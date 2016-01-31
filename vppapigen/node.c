/* 
 *------------------------------------------------------------------
 * node.c - the api generator's semantic back-end
 *
 * Copyright (c) 2004-2009 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>

#include "lex.h"
#include "node.h"

#define YYSTYPE void *

FILE *ofp;
FILE *javafp;
FILE *jnifp;
char *java_class;
time_t starttime;
char *vlib_app_name;
char *input_filename;
node_vft_t *the_vft[NODE_N_TYPES];
static int indent;
static int dont_output_version;
int dump_tree;
static char *fixed_name;
static char tmpbuf [MAXNAME];
static char *current_def_name;
static char *current_union_name;
static char *current_type_fmt;
static char *current_type_cast;
static char current_id;
static char current_is_complex;
static char *current_endianfun;
static char *current_type_name;
static int current_java_parameter_number;
static int current_java_emitted_parameter;
static int current_java_parameter_need_comma_space;
void *current_java_methodfun;
void *current_java_jnifun;

void indent_me(FILE *ofp)
{
    int i;

    for (i = 0; i < indent; i++)
        putc(' ', ofp);
}

char *uppercase (char *s)
{
    char *cp;

    cp = tmpbuf;

    while (*s && (cp < tmpbuf + (sizeof(tmpbuf)-1))) {
        if (*s >= 'a' && *s <= 'z')
            *cp++ = *s++ - ('a' - 'A');
        else
            *cp++ = *s++;
    }
    *cp = 0;
    return(tmpbuf);
}

char *lowercase (char *s)
{
    char *cp;

    cp = tmpbuf;

    while (*s && (cp < tmpbuf + (sizeof(tmpbuf)-1))) {
        if (*s >= 'A' && *s <= 'Z')
            *cp++ = *s++ + ('a' - 'A');
        else
            *cp++ = *s++;
    }
    *cp = 0;
    return(tmpbuf);
}

/* 
 * javah maps foo_bar to foo_1bar for whatever freakin' reason
 * So, adjust java names accordingly.
 */
char *java_name_mangle (void * name_arg)
{
    char * name = name_arg;
    static u8 * s;
    int i;

    vec_reset_length (s);

    s = format (s, "%s%c", name, 0);

    for (i = 0; i < vec_len(s); i++)
        if (s[i] == '_') {
            vec_delete (s, 1, i);
            if (s[i] >= 'a' && s[i] <= 'z')
                s[i] -= ('a' - 'A');
        }
    vec_add1 (s, 0);
    
    return ((char *) s);
}

void primtype_recursive_print(node_t *this, i8 *fmt)
{
    fputs((char *)fmt, stdout);

    if (this->deeper) {
        node_vft_t *vftp = the_vft[this->deeper->type];
        vftp->print(this->deeper);
    }
}

void primtype_recursive_generate(node_t *this, enum passid which, FILE *ofp,
                                 i8 *type_name, i8 *type_fmt, i8 *type_cast)
{
    node_vft_t *vftp;

    current_type_name = (char *)type_name;
    current_type_cast = (char *)type_cast;

    switch(which) {
    case TYPEDEF_PASS:
        fputs((char *)type_name, ofp);
        fputs(" ", ofp);
        break;

    case PRINTFUN_PASS:
        current_type_fmt = (char *)type_fmt;
        break;

    case ENDIANFUN_PASS:
        vftp = the_vft[this->type];
        current_endianfun = vftp->endian_converter;
        break;

    case JAVA_METHOD_PASS:
        vftp = the_vft[this->type];
        current_java_methodfun = vftp->java_method_function;
        break;

    default:
        fprintf(stderr, "primtype_recursive_generate: unimp pass %d\n", which);
        break;
    }

    if (this->deeper) {
        vftp = the_vft[this->deeper->type];
        vftp->generate(this->deeper, which, ofp);
    }
}

static int hidden_from_java(const node_t * deeper)
{
    if (current_java_parameter_number++ < 3) {
        if (!strncmp ((char *)(deeper->data[0]), "client_index", 12))
            return 1;
        else if (!strncmp ((char *)(deeper->data[0]), "context", 7))
            return 1;
        else if (!strncmp ((char *)(deeper->data[0]), "_vl_msg_id", 10))
            return 1;
    }

    return 0;
}

void primtype_java_method (node_t * this, enum passid which, FILE *ofp, 
                           char *java_type_name)
{
    node_t * deeper;

    deeper = this->deeper;

    /* We'll take care of _msg_id, client_index, and context ourselves */
    if (hidden_from_java(deeper)) {
        return;
    }

    if (deeper->type == NODE_SCALAR)
        fprintf (ofp, "%s %s", java_type_name, 
                 java_name_mangle(deeper->data[0]));
    else
        fprintf (ofp, "%s [] %s", java_type_name, 
                 java_name_mangle(deeper->data[0]));

    current_java_emitted_parameter = 1;
}

void primtype_java_parameter (node_t * this, enum passid which, FILE *ofp, 
                              char *java_type_name)
{
    node_t * deeper;

    deeper = this->deeper;

    /* We'll take care of _msg_id, client_index, and context ourselves */
    if (hidden_from_java(deeper)) {
        return;
    }
    if (current_java_parameter_need_comma_space) {
        current_java_parameter_need_comma_space = 0;
        fputs (", ", ofp);
    }

    if (deeper->type == NODE_SCALAR)
        fprintf (ofp, "%s %s", java_type_name, (char *)(deeper->data[0]));
    else
        fprintf (ofp, "%sArray %s", java_type_name, (char *)(deeper->data[0]));

    current_java_emitted_parameter = 1;
}

void primtype_java_setup (node_t * this, enum passid which, FILE *ofp, 
                          char *java_type_name, char *array_element_name)
{
    node_t * deeper;

    deeper = this->deeper;

    /* We'll take care of _msg_id, client_index, and context ourselves */
    if (hidden_from_java(deeper)) {
        return;
    }

    if (deeper->type == NODE_VECTOR) {
        indent_me(ofp);
        fprintf (ofp, 
                 "%s * %sP = (*env)->Get%sArrayElements (env, %s, NULL);\n",
                 java_type_name, (char *)(deeper->data[0]),
                 array_element_name, (char *)(deeper->data[0]));
    }
                 
    current_java_emitted_parameter = 1;
}

void primtype_java_code (node_t * this, enum passid which, FILE *ofp, 
                         char *java_type_name, char * swapper)
{
    node_t * deeper;
    char * s;

    deeper = this->deeper;

    /* We'll take care of _msg_id, client_index, and context ourselves */
    if (hidden_from_java(deeper)) {
        return;
    }

    indent_me(ofp);

    s = (char *)(deeper->data[0]);

    if (swapper == 0) {
        if (deeper->type == NODE_VECTOR)
            fprintf (ofp, "memcpy (mp->%s, %sP, sizeof (mp->%s));\n",
                     s, s, s);
        else
            fprintf (ofp, "mp->%s = %s;\n", s, s);
    } else {
        if (deeper->type == NODE_VECTOR) {
            fprintf(ofp, "{\n");
            indent += 4;
            indent_me(ofp);
            fprintf(ofp, "int _i;\n");
            indent_me(ofp);
            fprintf(ofp, "for (_i = 0; _i < %d; _i++) {\n", 
                    (int)(u64)(deeper->data[1]));
            indent += 4;
            indent_me(ofp);
            fprintf(ofp, "mp->%s[_i] = %s(%sP[_i]);\n",
                    s, swapper, s);
            indent -= 4;
            indent_me(ofp);
            fprintf(ofp, "}\n");
            indent -= 4;
            indent_me(ofp);
            fprintf(ofp, "}\n");
        } else {
            fprintf (ofp, "mp->%s = %s(%s);\n", s, swapper, s);
        }
    }

    current_java_emitted_parameter = 1;
}

void primtype_java_teardown (node_t * this, enum passid which, FILE *ofp, 
                             char * array_element_name)
{
    node_t * deeper;

    deeper = this->deeper;

    /* We'll take care of _msg_id, client_index, and context ourselves */
    if (hidden_from_java(deeper)) {
        return;
    }

    if (deeper->type == NODE_VECTOR) {
        indent_me(ofp);
        fprintf (ofp, 
                 "(*env)->Release%sArrayElements (env, %s, %sP, 0);\n",
                 array_element_name, 
                 (char *)(deeper->data[0]), 
                 (char *)(deeper->data[0]));
    }

    current_java_emitted_parameter = 1;
}

void node_illegal_print (node_t *this)
{
    fprintf(stderr, "node_illegal_print called\n");
    exit(0);
}

void node_illegal_generate (node_t *this, enum passid notused, FILE *ofp)
{
    fprintf(stderr, "node_illegal_generate called\n");
    exit(0);
}

void node_illegal_java_method (node_t *this, enum passid notused, FILE *ofp)
{
    fprintf(stderr, "node_illegal_java_method called\n");
    exit(0);
}

void node_illegal_java_jni (node_t *this, enum passid notused, FILE *ofp)
{
    fprintf(stderr, "node_illegal_java_jni called\n");
    exit(0);
}

node_vft_t node_illegal_vft = {
    node_illegal_print,
    node_illegal_generate,
    "illegal",
    node_illegal_java_method,
    node_illegal_java_jni,
};

void node_u8_print (node_t *this)
{
    primtype_recursive_print(this, "u8 ");
}

void node_u8_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "u8", "%u", "(unsigned)");
}

void node_u8_java_method (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_method (this, which, ofp, "byte");
}

void node_u8_java_parameter (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_parameter (this, which, ofp, "jbyte");
}

void node_u8_java_setup (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_setup (this, which, ofp, "jbyte", "Byte");
}

void node_u8_java_code (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_code (this, which, ofp, "jbyte", 0 /* swapper */);
}

void node_u8_java_teardown (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_teardown (this, which, ofp, "Byte");
}

node_vft_t node_u8_vft = {
    node_u8_print,
    node_u8_generate,
    "", 
    node_u8_java_method,
    node_u8_java_parameter,
    node_u8_java_setup,
    node_u8_java_code,
    node_u8_java_teardown,
};

void node_u16_print (node_t *this)
{
    primtype_recursive_print(this, "u16 ");
}

void node_u16_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "u16", "%u", "(unsigned)");
}

void node_u16_java_method (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_method (this, which, ofp, "short");
}

void node_u16_java_parameter (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_parameter (this, which, ofp, "jshort");
}

void node_u16_java_setup (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_setup (this, which, ofp, "jshort", "Short");
}

void node_u16_java_code (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_code (this, which, ofp, "jshort", "clib_host_to_net_u16");
}

void node_u16_java_teardown (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_teardown (this, which, ofp, "Short");
}

node_vft_t node_u16_vft = {
    node_u16_print,
    node_u16_generate,
    "clib_net_to_host_u16",
    node_u16_java_method,
    node_u16_java_parameter,
    node_u16_java_setup,
    node_u16_java_code,
    node_u16_java_teardown,
};

void node_u32_print (node_t *this)
{
    primtype_recursive_print(this, "u32 ");
}

void node_u32_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "u32", "%u", "(unsigned)");
}

void node_u32_java_method (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_method (this, which, ofp, "int");
}

void node_u32_java_parameter (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_parameter (this, which, ofp, "jint");
}

void node_u32_java_setup (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_setup (this, which, ofp, "jint", "Int");
}

void node_u32_java_code (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_code (this, which, ofp, "jint", "clib_host_to_net_u32");
}

void node_u32_java_teardown (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_teardown (this, which, ofp, "Int");
}

node_vft_t node_u32_vft = {
    node_u32_print,
    node_u32_generate,
    "clib_net_to_host_u32",
    node_u32_java_method,
    node_u32_java_parameter,
    node_u32_java_setup,
    node_u32_java_code,
    node_u32_java_teardown,
};

void node_u64_print (node_t *this)
{
    primtype_recursive_print(this, "u64 ");
}

void node_u64_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "u64", "%llu", 
                                "(long long)");
}

void node_u64_java_method (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_method (this, which, ofp, "long");
}

void node_u64_java_parameter (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_parameter (this, which, ofp, "jlong");
}

void node_u64_java_setup (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_setup (this, which, ofp, "jlong", "Long");
}

void node_u64_java_code (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_code (this, which, ofp, "jlong", "clib_host_to_net_u64");
}

void node_u64_java_teardown (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_teardown (this, which, ofp, "Long");
}

node_vft_t node_u64_vft = {
    node_u64_print,
    node_u64_generate,
    "clib_net_to_host_u64",
    node_u64_java_method,
    node_u64_java_parameter,
    node_u64_java_setup,
    node_u64_java_code,
    node_u64_java_teardown,
};

void node_i8_print (node_t *this)
{
    primtype_recursive_print(this, "i8 ");
}

void node_i8_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "i8", "%d", "(int)");
}

node_vft_t node_i8_vft = {
    node_i8_print,
    node_i8_generate,
    "",
    node_u8_java_method,
    node_u8_java_parameter,
    node_u8_java_setup,
    node_u8_java_code,
    node_u8_java_teardown,
};

void node_i16_print (node_t *this)
{
    primtype_recursive_print(this, "i16 ");
}

void node_i16_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "i16", "%d", "(int)");
}

node_vft_t node_i16_vft = {
    node_i16_print,
    node_i16_generate,
    "clib_net_to_host_u16",
    node_u16_java_method,
    node_u16_java_parameter,
    node_u16_java_setup,
    node_u16_java_code,
    node_u16_java_teardown,
};

void node_i32_print (node_t *this)
{
    primtype_recursive_print(this, "i32 ");
}

void node_i32_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "i32", "%ld", "(long)");
}

node_vft_t node_i32_vft = {
    node_i32_print,
    node_i32_generate,
    "clib_net_to_host_u32",
    node_u32_java_method,
    node_u32_java_parameter,
    node_u32_java_setup,
    node_u32_java_code,
    node_u32_java_teardown,
};

void node_i64_print (node_t *this)
{
    primtype_recursive_print(this, "i64 ");
}

void node_i64_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "i64", "%lld", 
                                "(long long)");
}

node_vft_t node_i64_vft = {
    node_i64_print,
    node_i64_generate,
    "clib_net_to_host_u64",
    node_u64_java_method,
    node_u64_java_parameter,
    node_u64_java_setup,
    node_u64_java_code,
    node_u64_java_teardown,
};

void node_f64_print (node_t *this)
{
    primtype_recursive_print(this, "f64 ");
}

void node_f64_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "f64", "%.2f", 
                                "(double)");
}
void node_f64_java_method (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_method (this, which, ofp, "double");
}

void node_f64_java_parameter (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_parameter (this, which, ofp, "jdouble");
}

void node_f64_java_setup (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_setup (this, which, ofp, "jdouble", "Double");
}

void node_f64_java_code (node_t *this, enum passid which, FILE *ofp)
{
    /* 
     * Current API code doesn't try to endian-swap doubles
     * FP formats aren't portable yadda yadda yadda
     */
    primtype_java_code (this, which, ofp, "jdouble", 0 /* $$$ */);
}

void node_f64_java_teardown (node_t *this, enum passid which, FILE *ofp)
{
    primtype_java_teardown (this, which, ofp, "Double");
}

node_vft_t node_f64_vft = {
    node_f64_print,
    node_f64_generate,
    " ",                        /* FP numbers are sent in host byte order */
    node_f64_java_method,
    node_f64_java_parameter,
    node_f64_java_setup,
    node_f64_java_code,
    node_f64_java_teardown,
};


void node_packed_print (node_t *this)
{
    primtype_recursive_print (this, "packed ");
}

void node_packed_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "PACKED", "", "");
}

node_vft_t node_packed_vft = {
    node_packed_print,
    node_packed_generate,
    0,
};

void node_define_print (node_t *this)
{
    fprintf(stdout, "define %s {\n", CDATA0);
    if (this->deeper) {
        node_vft_t *vftp = the_vft[this->deeper->type];
        fprintf(stdout, "    ");
        vftp->print(this->deeper);
    }
    fprintf(stdout, "};\n");
}

static void emit_java_arg_declaration(node_t *child, FILE *fp) {
    current_java_parameter_number = 0;
    while (child) {
        node_vft_t *vftp = the_vft[child->type];
        current_java_emitted_parameter = 0;
        vftp->java_method_function(child, JAVA_METHOD_PASS, fp);
        child = child->peer;
        if (child && current_java_emitted_parameter)
            fputs (", ", fp);
    }
}

void node_define_generate (node_t *this, enum passid which, FILE *fp)
{
    node_t *child, *save_child;

    switch(which) {
    case TYPEDEF_PASS:
        fprintf(fp, "typedef VL_API_PACKED(struct _vl_api_%s {\n", CDATA0);
        child = this->deeper;
        indent += 4;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            indent_me(fp);
            vftp->generate(child, which, fp);
            child = child->peer;
        }
        indent -= 4;
        fprintf(fp, "}) vl_api_%s_t;\n\n", CDATA0);
        break;

    case ENDIANFUN_PASS:
    case PRINTFUN_PASS:
        child = this->deeper;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            vftp->generate(child, which, fp);
            child = child->peer;
        }
        break;

    case JAVA_METHOD_PASS:
        indent += 4;
        indent_me(fp);

        /* Generate private native declaration */
        fprintf (fp, "private static native int %s0(", java_name_mangle(CDATA0));
        emit_java_arg_declaration(this->deeper, fp);
        fputs (");\n", fp);

        /* Generate public Java method */
        indent_me(fp);
        fprintf (fp, "public final int %s(", java_name_mangle(CDATA0));
        emit_java_arg_declaration(this->deeper, fp);
        fputs (") {\n", fp);

        indent += 4;
        indent_me(fp);
        fputs ("checkConnected();\n", fp);
        indent_me(fp);
        fprintf (fp, "return %s.%s0(", java_class, java_name_mangle(CDATA0));

        child = this->deeper;
        current_java_parameter_number = 0;
        while (child && hidden_from_java(child->deeper)) {
            child = child->peer;
        }
        while (child) {
            fputs(java_name_mangle((char *)(child->deeper->data[0])), fp);
            child = child->peer;
            if (child)
                fputs (", ", fp);
        }

        fputs (");\n", fp);
        indent -= 4;
        indent_me(fp);
        fputs ("}\n\n", fp);
        indent -= 4;
        break;

    case JAVA_JNI_PASS:
        /* Generate function prototype */
        fprintf (fp, "JNIEXPORT jint JNICALL Java_org_openvpp_vppjapi_%s_%s0\n", 
                 java_class, java_name_mangle(CDATA0));

        fprintf (fp, "(JNIEnv * env, jclass clazz");
        current_java_parameter_need_comma_space = 1;
        child = this->deeper;
        save_child = child;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            current_java_emitted_parameter = 0;
            vftp->java_jni_parameter(child, which, fp);
            child = child->peer;
            if (child && current_java_emitted_parameter)
                fputs (", ", fp);
        }
        fprintf (fp, ")\n{\n");
        indent += 4;

        /* define the api message pointer */
        indent_me(fp);
        fprintf (fp, "vppjni_main_t *jm = &vppjni_main;\n");
        indent_me(fp);
        fprintf (fp, "vl_api_%s_t * mp;\n", current_def_name);
        indent_me(fp);
        fprintf (fp, "u32 my_context_id;\n");
        indent_me(fp);
        fprintf (fp, "int rv;\n");

        indent_me(fp);
        fprintf (fp, "rv = vppjni_sanity_check (jm);\n");
        indent_me(fp);
        fprintf (fp, "if (rv) return rv;\n");

        indent_me(fp);
        fprintf (fp, "my_context_id = vppjni_get_context_id (jm);\n");

        /* Generate array setups, if any */
        child = save_child;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            current_java_parameter_number = 0;
            current_java_emitted_parameter = 0;
            vftp->java_jni_setup(child, which, fp);
            child = child->peer;
        }

        /* Setup the API message */
        indent_me(fp);
        fprintf (fp, "M(%s, %s);\n", uppercase(current_def_name),
                 current_def_name);
        indent_me(fp);
        fprintf (fp, "mp->context = clib_host_to_net_u32 (my_context_id);\n");
        /* $$$ Set up context hash table or some such... */

        /* Generate code */
        child = save_child;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            current_java_parameter_number = 0;
            current_java_emitted_parameter = 0;
            vftp->java_jni_code(child, which, fp);
            child = child->peer;
        }

        /* Generate array teardowns */
        child = save_child;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            current_java_parameter_number = 0;
            current_java_emitted_parameter = 0;
            vftp->java_jni_teardown(child, which, fp);
            child = child->peer;
        }

        /* Send the message, return context_id */
        indent_me (fp);
        fprintf (fp, "S;\n");
        indent_me (fp);
        fprintf (fp, "return my_context_id;\n");
        
        indent -= 4;
        fprintf (fp, "}\n\n");
        break;

    default:
        fprintf(stderr, "node_define_generate: unimp pass %d\n", which);
        break;
    }
}

node_vft_t node_define_vft = {
    node_define_print,
    node_define_generate,
    0,
};

void node_union_print (node_t *this)
{
    primtype_recursive_print (this, "union ");
}

void node_union_generate (node_t *this, enum passid which, FILE *fp)
{
    node_t *child;
    node_t *uelem;
    int case_id=1;

    switch(which) {
    case TYPEDEF_PASS:
        fprintf(fp, "u8 _%s_which;\n", CDATA0);
        indent_me(fp);
        fprintf(fp, "union _%s {\n", CDATA0);
        child = this->deeper;
        indent += 4;
    
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            indent_me(fp);
            vftp->generate(child, which, fp);
            child = child->peer;
        }
        indent -= 4;
        indent_me(fp);
        fprintf(fp, "} %s;\n", CDATA0);
        break;

    case PRINTFUN_PASS:
    case ENDIANFUN_PASS:
        uelem = this->deeper;
        
        indent_me(fp);
        fprintf(fp, "switch(a->_%s_which) {\n",
                CDATA0);
        indent += 4;
        current_union_name = CDATA0;

        /* Walk the list of objects in this union */
        while (uelem) {
            node_vft_t *vftp = the_vft[uelem->type];
            indent -= 4;
            indent_me(fp);
            fprintf(fp, "case %d:\n", case_id);
            case_id++;
            indent += 4;
            /* Drill down on each element */
            vftp->generate(uelem, which, fp);
            indent_me(fp);
            fprintf(fp, "break;\n");
            uelem = uelem->peer;
        }
        current_union_name = 0;
        indent -= 4;
        indent_me(fp);
        fprintf(fp, "default:\n");
        indent += 4;
        indent_me(fp);                 
        if (which == PRINTFUN_PASS) {
            fprintf(fp, 
                    "vl_print(handle, \"WARNING: _%s_which not set.\\n\");\n",
                    CDATA0);
        }
        indent_me(fp);
        fprintf(fp, "break;\n");
        indent -= 4;
        indent_me(fp);
        fprintf(fp, "}\n");
        break;

    default:
        fprintf(stderr, "node_union_generate: unimp pass %d\n", which);
        break;
    }
}


node_vft_t node_union_vft = {
    node_union_print,
    node_union_generate,
    0,
};

void node_scalar_print (node_t *this)
{
    fprintf(stdout, "%s", CDATA0);
    primtype_recursive_print (this, "");
}

void node_scalar_generate (node_t *this, enum passid which, FILE *fp)
{
    char *union_prefix = "";

    if (current_union_name) {
        sprintf(tmpbuf, "%s.", current_union_name);
        union_prefix = tmpbuf;
    }

    switch(which) {
    case TYPEDEF_PASS:
        fprintf(fp, "%s;\n", CDATA0);
        break;

    case PRINTFUN_PASS:
        indent_me(fp);
        if (current_is_complex) {
            fprintf(fp, "vl_api_%s_t_print(a->%s%s, handle);\n", 
                    current_type_name, union_prefix, CDATA0);
        } else {
            if (!strcmp(current_type_fmt, "uword")) {
                fprintf(fp, 
           "vl_print(handle, \"%s%s: \" _uword_fmt \"\\n\", %s a->%s%s);\n", 
                        union_prefix, CDATA0, "(_uword_cast)",
                        union_prefix, CDATA0);
            } else {
                fprintf(fp, 
                        "vl_print(handle, \"%s%s: %s\\n\", %s a->%s%s);\n", 
                        union_prefix, CDATA0, 
                        current_type_fmt, current_type_cast,
                        union_prefix, CDATA0);
            }
        }
        break;

    case ENDIANFUN_PASS:
        indent_me(fp);
        if (current_is_complex) {
            fprintf(fp, "vl_api%s_t_endian(a->%s%s);\n", 
                    current_type_name, union_prefix, CDATA0);
        } else {
            /* Current_endianfun == NULL means e.g. it's a u8... */
            if (current_endianfun) {
                fprintf(fp, "a->%s%s = %s(a->%s%s);\n", union_prefix,
                        CDATA0, current_endianfun, 
                        union_prefix, CDATA0);
            } else {
                fprintf(fp, "/* a->%s%s = a->%s%s */\n",
                        union_prefix, CDATA0, 
                        union_prefix, CDATA0);
            }
        }
        break;

    default:
        fprintf(stderr, "node_scalar_generate: unimp pass %d\n", which);
    }
    if (this->deeper) {
        fprintf(stderr, "broken recursion in node_scalar_generate\n");
    }
}


node_vft_t node_scalar_vft = {
    node_scalar_print,
    node_scalar_generate,
    0,
};

void node_vector_print (node_t *this)
{
    primtype_recursive_print (this, "vector ");
}

void node_vector_generate (node_t *this, enum passid which, FILE *fp)
{
    char *union_prefix = "";

    if (current_union_name) {
        sprintf(tmpbuf, "%s.", current_union_name);
        union_prefix = tmpbuf;
    }

    switch(which) {
    case TYPEDEF_PASS:
        fprintf(fp, "%s[%d];\n", CDATA0, IDATA1);
        break;

    case PRINTFUN_PASS:
        /* Don't bother about "u8 data [0];" et al. */
        if (IDATA1 == 0)
            break;

        indent_me(fp);
        fprintf(fp, "{\n");
        indent += 4;
        indent_me(fp);
        fprintf(fp, "int _i;\n");
        indent_me(fp);
        fprintf(fp, "for (_i = 0; _i < %d; _i++) {\n", 
                IDATA1);
        indent += 4;
        indent_me(fp);
        if (current_is_complex) {
            fprintf(fp, "vl_print(handle, \"%s%s[%%d]: ",
                    union_prefix, CDATA0);
            fprintf(fp, 
                    "vl_print_%s (handle, a->%s%s[_i]);\n", 
                    CDATA0, union_prefix, CDATA0);
        } else {
            fprintf(fp, 
         "vl_print(handle, \"%s%s[%%d]: %s\\n\", _i, a->%s%s[_i]);\n",
                    union_prefix, CDATA0, 
                    current_type_fmt, 
                    union_prefix, CDATA0);
        }
        indent -= 4;
        indent_me(fp);
        fprintf(fp, "}\n");
        indent -= 4;
        indent_me(fp);
        fprintf(fp, "}\n");
        break;

    case ENDIANFUN_PASS:
        /* Don't bother about "u8 data [0];" et al. */
        if (IDATA1 == 0)
            break;

        indent_me(fp);
        fprintf(fp, "{\n");
        indent += 4;
        indent_me(fp);
        fprintf(fp, "int _i;\n");
        indent_me(fp);
        fprintf(fp, "for (_i = 0; _i < %d; _i++) {\n", 
                IDATA1);
        indent += 4;
        indent_me(fp);
        if (current_is_complex) {
            fprintf(fp, 
                    "vl_api_%s_t_endian (a->%s%s[_i]);\n", 
                    current_type_name, union_prefix, CDATA0);
        } else {
            fprintf(fp, 
                    "a->%s%s[_i] = %s(a->%s%s[_i]);\n", 
                    union_prefix, CDATA0, 
                    current_endianfun, 
                    union_prefix, CDATA0);
        }
        indent -= 4;
        indent_me(fp);
        fprintf(fp, "}\n");
        indent -= 4;
        indent_me(fp);
        fprintf(fp, "}\n");
        break;

    default:
        fprintf(stderr, "node_vector_generate: unimp pass %d\n", which);
    }
    if (this->deeper) {
        fprintf(stderr, "broken recursion in node_vector_generate\n");
    }
}

node_vft_t node_vector_vft = {
    node_vector_print,
    node_vector_generate,
    0,
};

void node_complex_print (node_t *this)
{
    primtype_recursive_print (this, "complex ");
}

void node_complex_generate (node_t *this, enum passid which, FILE *fp)
{
    node_t *deeper;
    node_vft_t *vftp;
    char *member_name = "broken!";
    char *union_prefix = "";

    if (current_union_name) {
        sprintf(tmpbuf, "%s.", current_union_name);
        union_prefix = tmpbuf;
    }

    current_is_complex++;
    
    switch(which) {
    case TYPEDEF_PASS:
        fprintf(fp, "%s ", CDATA0);
        deeper = this->deeper;
        if (deeper) {
            vftp = the_vft[deeper->type];
            vftp->generate(deeper, which, fp);
        }
        break;

    case PRINTFUN_PASS:
        deeper = this->deeper;
        while (deeper) {
            if (deeper->type == NODE_SCALAR ||
                deeper->type == NODE_VECTOR) {
                member_name = deeper->data[0];
                break;
            }
            deeper = deeper->deeper;
        }
        indent_me(fp);
        fprintf(fp, "vl_print(handle, \"%s%s ----- \\n\");\n", 
                union_prefix, member_name);
        indent_me(fp);
        fprintf(fp, "%s_print(&a->%s%s, handle);\n", 
                CDATA0, union_prefix, member_name);
        indent_me(fp);
        fprintf(fp, "vl_print(handle, \"%s%s ----- END \\n\");\n", 
                union_prefix, member_name);
        break;

    case ENDIANFUN_PASS:
        deeper = this->deeper;
        while (deeper) {
            if (deeper->type == NODE_SCALAR ||
                deeper->type == NODE_VECTOR) {
                member_name = deeper->data[0];
                break;
            }
            deeper = deeper->deeper;
        }

        indent_me(fp);
        fprintf(fp, "%s_endian(&a->%s%s);\n", 
                CDATA0, union_prefix, member_name);
        break;

    default:
        fprintf(stderr, "node_complex_generate unimp pass %d...\n", which);
        break;
    }
    current_is_complex--;
}

node_vft_t node_complex_vft = {
    node_complex_print,
    node_complex_generate,
    0,
};

void node_noversion_print (node_t *this)
{
    primtype_recursive_print (this, "noversion ");
}

void node_noversion_generate (node_t *this, enum passid which, FILE *ofp)
{
    fprintf(stderr, "node_noversion_generate called...\n");
}

node_vft_t node_noversion_vft = {
    node_noversion_print,
    node_noversion_generate,
    0,
};

void node_uword_print (node_t *this)
{
    primtype_recursive_print(this, "uword ");
}

void node_uword_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "uword", "uword", "");
}

node_vft_t node_uword_vft = {
    node_uword_print,
    node_uword_generate,
    "clib_net_to_host_uword",
};

node_vft_t *the_vft[NODE_N_TYPES] = {
    &node_illegal_vft,
    &node_u8_vft,
    &node_u16_vft,
    &node_u32_vft,
    &node_u64_vft,
    &node_i8_vft,
    &node_i16_vft,
    &node_i32_vft,
    &node_i64_vft,
    &node_f64_vft,
    &node_packed_vft,
    &node_define_vft,
    &node_union_vft,
    &node_scalar_vft,
    &node_vector_vft,
    &node_complex_vft,
    &node_noversion_vft,
    &node_uword_vft,
};

void *make_node (enum node_subclass type)
{
    node_t *rv;

    rv = (node_t *) malloc (sizeof (*rv));
    if (rv == 0) {
        fprintf (stderr, "fatal: make_node out of memory\n");
        exit (1);
    }
    bzero (rv, sizeof (*rv));
    rv->type = type;
    return ((void *) rv);
}

YYSTYPE deeper (YYSTYPE arg1, YYSTYPE arg2)
{
    node_t *np1 = (node_t *) arg1;
    node_t *np2 = (node_t *) arg2;
    node_t *hook_point;
    
    hook_point = np1;

    while (hook_point->deeper)
        hook_point = hook_point->deeper;

    hook_point->deeper = np2;
    return (arg1);
}

YYSTYPE addpeer (YYSTYPE arg1, YYSTYPE arg2)
{
    node_t *np1 = (node_t *) arg1;
    node_t *np2 = (node_t *) arg2;
    node_t *hook_point;
    
    hook_point = np1;

    while (hook_point->peer)
        hook_point = hook_point->peer;

    hook_point->peer = np2;
    return (arg1);
}

/*
 * add_slist (stmt_list, stmt)
 */

YYSTYPE add_slist (YYSTYPE a1, YYSTYPE a2)
{
    if (a1 && a2)
        return (addpeer(a1, a2));
    else if(a1)
        return(a1);
    else 
        return(a2);
}

/*
 * add_define (char *name, defn_list);
 */
YYSTYPE add_define (YYSTYPE a1, YYSTYPE a2)
{
    node_t *np;

    np = make_node(NODE_DEFINE);
    np->data[0] = a1;
    deeper((YYSTYPE)np, a2);
    return ((YYSTYPE) np);
}

/*
 * add_defbody (defn_list, new_defn)
 */
YYSTYPE add_defbody (YYSTYPE a1, YYSTYPE a2)
{
    return (addpeer(a1, a2));
}

/*
 * add_primtype ([packed], primitive type, instance)
 */ 

YYSTYPE add_primtype (YYSTYPE a1, YYSTYPE a2, YYSTYPE a3)
{
    node_t *np1;

    np1 = (node_t *)a1;
    
    /* Hook instance to type node */
    deeper (a1, a2);
    if (a3) {
        deeper(a1, a3);
    }
    return (a1);
}

/*
 * add_complex(char *type_name, instance)
 */

YYSTYPE add_complex (YYSTYPE a1, YYSTYPE a2)
{
    node_t *np;

    np = make_node(NODE_COMPLEX);
    np->data[0] = (void *) a1;

    deeper((YYSTYPE)np, a2);
    return ((YYSTYPE) np);
}

/*
 * add_union(char *type_name, definition)
 */

YYSTYPE add_union (YYSTYPE a1, YYSTYPE a2)
{
    node_t *np;

    np = make_node(NODE_UNION);
    np->data[0] = (void *) a1;

    deeper((YYSTYPE)np, a2);
    return ((YYSTYPE) np);
}


/*
 * add_vector_vbl (node_t *variable, YYSTYPE size)
 */

YYSTYPE add_vector_vbl (YYSTYPE a1, YYSTYPE a2)
{
    node_t *np;

    np = make_node(NODE_VECTOR);
    np->data[0] = (void *) a1;
    np->data[1] = (void *) a2;
    return ((YYSTYPE) np);
}

/*
 * add_scalar_vbl (char *name)
 */
YYSTYPE add_scalar_vbl (YYSTYPE a1)
{
    node_t *np;

    np = make_node(NODE_SCALAR);
    np->data[0] = (void *) a1;
    return ((YYSTYPE) np);
}

/*
 * set_flags (int flags, msg(=0?))
 */ 
YYSTYPE set_flags(YYSTYPE a1, YYSTYPE a2)
{
    node_t *np;
    int flags;

    np = (node_t *)a2;
    if (!np)
        return(0);

    flags = (int)(uword) a1;

    np->flags |= flags;
    return (a2);
}
/*
 * suppress_version
 */
YYSTYPE suppress_version (void)
{
    dont_output_version = 1;
    return (0);
}

void dump(node_t *np)
{
    node_vft_t *vftp;

    while (np) {
        vftp = the_vft[np->type];
        vftp->print(np);
        np = np->peer;
    }
}

char *fixup_input_filename(void)
{
    char *cp;

    cp = (char *)input_filename;

    while (*cp)
        cp++;

    cp--;

    while (cp > input_filename && *cp != '/')
        cp--;
    if (*cp == '/')
        cp++;

    strcpy (tmpbuf, cp);

    cp = tmpbuf;

    while (*cp)
        cp++;

    cp--;

    while (cp > tmpbuf && *cp != '.')
        cp--;
    
    if (*cp == '.')
        *cp = 0;

    return (sxerox(tmpbuf));
}

void generate_top_boilerplate(FILE *fp)

{
    char *datestring = ctime(&starttime);
    fixed_name = fixup_input_filename();

    datestring[24] = 0;

    fprintf (fp, "/*\n");
    fprintf (fp, " * VLIB API definitions %s\n", datestring);
    fprintf (fp, " * Input file: %s\n", input_filename);
    fprintf (fp, " * Automatically generated: please edit the input file ");
    fprintf (fp, "NOT this file!\n");

    /* Moron Acme trigger workaround */
    fprintf (fp, " * %syright (c) %s by Cisco Systems, Inc.\n", "Cop", 
             &datestring[20]);
    fprintf (fp, " */\n\n");
    fprintf (fp, "#if defined(vl_msg_id)||defined(vl_union_id)||");
    fprintf (fp, "defined(vl_printfun) \\\n ||defined(vl_endianfun)||");
    fprintf (fp, " defined(vl_api_version)||defined(vl_typedefs) \\\n");
    fprintf (fp, " ||defined(vl_msg_name)\n");
    fprintf (fp, "/* ok, something was selected */\n");
    fprintf (fp, "#else\n");
    fprintf (fp, "#warning no content included from %s\n", input_filename);
    fprintf (fp, "#endif\n\n");
    fprintf (fp, "#define VL_API_PACKED(x) x __attribute__ ((packed))\n\n");
}

void generate_bottom_boilerplate(FILE *fp)

{
    fprintf (fp, "\n#ifdef vl_api_version\n");

    if (dont_output_version) {
        fprintf (fp, "/* WARNING: API FILE VERSION CHECK DISABLED */\n");
        input_crc = 0;
    }

    fprintf (fp, "vl_api_version(%s, 0x%08x)\n\n", 
             fixed_name, (unsigned int)input_crc);
    fprintf (fp, "#endif\n\n");
}

void generate_msg_ids(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;

    fprintf (fp, "\n/****** Message ID / handler enum ******/\n\n");
    fprintf (fp, "#ifdef vl_msg_id\n");

    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & NODE_FLAG_TYPEONLY)) {
                fprintf (fp, "vl_msg_id(VL_API_%s, vl_api_%s_t_handler)\n", 
                         uppercase(np->data[0]), (i8 *)np->data[0]);
            } else {
                fprintf (fp, "/* typeonly: %s */\n", (i8 *)np->data[0]);
            }
        }
        np = np->peer;
    }
    fprintf (fp, "#endif\n");

}

void generate_msg_names(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;

    fprintf (fp, "\n/****** Message names ******/\n\n");

    fprintf (fp, "#ifdef vl_msg_name\n");

    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & NODE_FLAG_TYPEONLY)) {
                fprintf (fp, "vl_msg_name(vl_api_%s_t, %d)\n",
                         (i8 *) np->data[0], 
                         (np->flags & NODE_FLAG_DONT_TRACE ? 0 : 1));
            } else {
                fprintf (fp, "/* typeonly: %s */\n", (i8 *)np->data[0]);
            }
        }
        np = np->peer;
    }
    fprintf (fp, "#endif\n\n");
}

void generate_typedefs(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;

    fprintf(fp, "\n/****** Typedefs *****/\n\n");
    fprintf(fp, "#ifdef vl_typedefs\n\n");

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            /* Yeah, this is pedantic */
            vftp = the_vft[np->type];
            vftp->generate(np, TYPEDEF_PASS, fp);
        }
        np = np->peer;
    }
    fprintf(fp, "#endif /* vl_typedefs */\n\n");
}

void union_walk_one_defn(node_t *np, FILE *fp)
{
    node_t *vblp;
    node_t *uelem;

    /* Walk the list of typed objects in this msg def */
    while (np) {
        if (np->type == NODE_UNION) {
            current_union_name = np->data[0];
            uelem = np->deeper;

            /* Walk the list of objects in this union */
            while (uelem) {
                vblp = uelem->deeper;
                /* Drill down on each element, find the variable name */
                while(vblp) {
                    if (vblp->type == NODE_SCALAR ||
                        vblp->type == NODE_VECTOR ||
                        vblp->type == NODE_COMPLEX) {
                        fprintf(ofp, "#define %s_", 
                                uppercase(current_def_name));
                        fprintf(ofp, "%s_", uppercase(current_union_name));
                        fprintf(ofp, "%s %d\n",uppercase(vblp->data[0]),
                                current_id);
                        current_id++;
                        break;
                    }
                    vblp = vblp->deeper;
                }
                uelem = uelem->peer;
            }
            current_union_name = 0;
            current_id = 1;
        }
        np = np->peer;
    }
}

void generate_uniondefs(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;

    fprintf(fp, "/****** Discriminated Union Definitions *****/\n\n");
    fprintf(fp, "#ifdef vl_union_id\n\n");

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            current_id = 1;
            current_def_name = np->data[0];
            union_walk_one_defn(np->deeper, fp);
        }
        np = np->peer;
    }
    fprintf(fp, "\n#endif /* vl_union_id */\n\n");
}

void generate_printfun(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;

    fprintf(fp, "/****** Print functions *****/\n\n");
    fprintf(fp, "#ifdef vl_printfun\n\n");

    fprintf(fp, "#ifdef LP64\n");
    fputs ("#define _uword_fmt \"%lld\"\n", fp);
    fputs ("#define _uword_cast (long long)\n", fp);
    fprintf(fp, "#else\n");
    fputs("#define _uword_fmt \"%ld\"\n", fp);
    fputs ("#define _uword_cast long\n", fp);
    fprintf(fp, "#endif\n\n");

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & NODE_FLAG_MANUAL_PRINT)) {
                fprintf(fp, 
       "static inline void *vl_api_%s_t_print (vl_api_%s_t *a,",
                        (i8 *)np->data[0], (i8 *) np->data[0]);
                fprintf(fp, "void *handle)\n{\n");
                /* output the message name */
                fprintf(fp, 
                    "    vl_print(handle, \"vl_api_%s_t:\\n\");\n",
                        (i8 *)np->data[0]);

                indent += 4;
                /* Yeah, this is pedantic */
                vftp = the_vft[np->type];
                vftp->generate(np, PRINTFUN_PASS, fp);
                fprintf(fp, "    return handle;\n");
                fprintf(fp, "}\n\n");
                indent -= 4;
            } else {
                fprintf(fp, "/***** manual: vl_api_%s_t_print  *****/\n\n",
                        (i8 *) np->data[0]);
            }
        }
        np = np->peer;
    }
    fprintf(fp, "#endif /* vl_printfun */\n\n");
}

void generate_endianfun(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;

    fprintf(fp, "\n/****** Endian swap functions *****/\n\n");
    fprintf(fp, "#ifdef vl_endianfun\n\n");
    fprintf(fp, "#undef clib_net_to_host_uword\n");
    fprintf(fp, "#ifdef LP64\n");
    fprintf(fp, "#define clib_net_to_host_uword clib_net_to_host_u64\n");
    fprintf(fp, "#else\n");
    fprintf(fp, "#define clib_net_to_host_uword clib_net_to_host_u32\n");
    fprintf(fp, "#endif\n\n");

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & NODE_FLAG_MANUAL_ENDIAN)) {
                fprintf(fp, 
               "static inline void vl_api_%s_t_endian (vl_api_%s_t *a)\n{\n",
                        (i8 *) np->data[0], (i8 *) np->data[0]);
                indent += 4;
                /* Yeah, this is pedantic */
                vftp = the_vft[np->type];
                vftp->generate(np, ENDIANFUN_PASS, fp);
                fprintf(fp, "}\n\n");
                indent -= 4;
            } else {
                fprintf(fp, "/***** manual: vl_api_%s_t_endian  *****/\n\n",
                        (i8 *) np->data[0]);
            }
        }
        np = np->peer;
    }
    fprintf(fp, "#endif /* vl_endianfun */\n\n");
}

void add_msg_ids(YYSTYPE a1)
{
    node_t *np = (node_t *)a1;
    node_t *new_u16;
    node_t *new_vbl;

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & NODE_FLAG_TYPEONLY)) {
                /* add the parse tree for "u16 _vl_msg_id" */
                new_u16 = make_node(NODE_U16);
                new_u16->peer = np->deeper;
                np->deeper = new_u16;
                new_vbl = make_node(NODE_SCALAR);
                new_vbl->data[0] = sxerox("_vl_msg_id");
                new_u16->deeper = new_vbl;
            }
        }
        np = np->peer;
    }
}

void generate_java_top_boilerplate(FILE *fp)

{
    char *datestring = ctime(&starttime);
    fixed_name = fixup_input_filename();

    datestring[24] = 0;

    fprintf (fp, "/*\n");
    fprintf (fp, " * VLIB API java binding %s\n", datestring);
    fprintf (fp, " * Input file: %s\n", input_filename);
    fprintf (fp, " * Automatically generated: please edit the input file ");
    fprintf (fp, "NOT this file!\n");
    fprintf (fp, " */\n\n");

    fprintf (fp, "package org.openvpp.vppjapi;\n\n");
    fprintf (fp, "import java.io.IOException;\n\n");
    fprintf (fp, "public class %s extends vppConn {\n",
             java_class);
    fprintf (fp, "    public %s(String clientName) throws IOException {\n", java_class);
    fprintf (fp, "        super(clientName);\n");
    fprintf (fp, "    }\n\n");
}

void generate_java_bottom_boilerplate(FILE *fp)
{
    fprintf (fp, "}\n");
}


void generate_java_class_definition (YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;

    fprintf(fp, "/****** API methods *****/\n\n");

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & (NODE_FLAG_MANUAL_JAVA | NODE_FLAG_TYPEONLY))) {
                /* Suppress messages named "xyz_reply" */
                char * cp = (char *) np->data[0];
                while (*cp)
                    cp++;
                cp -= 6;
                if (strncmp (cp, "_reply", 6)) {
                    current_java_parameter_number = 0;
                    vftp = the_vft[np->type];
                    vftp->generate(np, JAVA_METHOD_PASS, fp);
                }
            }
        }
        np = np->peer;
    }

    fprintf(fp, "\n/****** end of API methods *****/\n");
}

void generate_jni_reply_handler_list (YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;

    fprintf (fp, "#define foreach_api_reply_handler \\\n");

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & (NODE_FLAG_MANUAL_JAVA | NODE_FLAG_TYPEONLY))) {
                /* emit messages named "xyz_reply" */
                char * cp = (char *) np->data[0];
                while (*cp)
                    cp++;
                cp -= 6;
                if (!strncmp (cp, "_reply", 6)) {
                    fprintf (fp, "_(%s, %s) \\\n", 
                             uppercase(np->data[0]), (char *)(np->data[0]));
                }
            }
        }
        np = np->peer;
    }

    fprintf (fp, "\n\n");
}

char * m_macro_boilerplate =     
"#define M(T,t)                                      \\\n"
"do {                                                \\\n"
"    api_result_ready = 0;                           \\\n"
"    mp = vl_msg_api_alloc(sizeof(*mp));             \\\n"
"    memset (mp, 0, sizeof (*mp));                   \\\n"
"    mp->_vl_msg_id = ntohs (VL_API_##T);            \\\n"
"    mp->client_index = api_main.my_client_index;    \\\n"
"} while(0);\n\n"
"#define M2(T,t,n)                                   \\\n"
"do {                                                \\\n"
"    api_result_ready = 0;                           \\\n"
"    mp = vl_msg_api_alloc(sizeof(*mp)+(n));         \\\n"
"    memset (mp, 0, sizeof (*mp));                   \\\n"
"    mp->_vl_msg_id = ntohs (VL_API_##T);            \\\n"
"    mp->client_index = api_main.my_client_index;    \\\n"
"} while(0);\n\n";

char * s_macro_boilerplate = 
"#define S (vl_msg_api_send_shmem (api_main.shmem_hdr->vl_input_queue, \\\n"
"(u8 *)&mp));\n\n";

char * w_macro_boilerplate = 
"#define W                                               \\\n"
"do {                                                    \\\n"
"    timeout = clib_time_now (&clib_time) + 1.0;         \\\n"
"                                                        \\\n"
"    while (clib_time_now (&clib_time) < timeout) {      \\\n"
"        if (api_result_ready == 1) {                    \\\n"
"            return ((jint) api_result);                 \\\n"    
"        }                                               \\\n"
"    }                                                   \\\n"
"    return -99;                                         \\\n"   
"} while(0);\n\n";

void generate_jni_top_boilerplate(FILE *fp)

{
    char *datestring = ctime(&starttime);
    fixed_name = fixup_input_filename();

    datestring[24] = 0;

    fprintf (fp, "/*\n");
    fprintf (fp, " * VLIB Java native code %s\n", datestring);
    fprintf (fp, " * Input file: %s\n", input_filename);
    fprintf (fp, " * Automatically generated: please edit the input file ");
    fprintf (fp, "NOT this file!\n");
    fprintf (fp, " */\n\n");

    fprintf (fp, "#include <japi/vppjni.h>\n");

    fprintf (fp, 
             "#define vl_api_version(n,v) static u32 %s_api_version %s = v;\n",
	     vlib_app_name, "__attribute__((unused))");
    fprintf (fp, "#include <api/%s.api.h>\n", vlib_app_name);
    fprintf (fp, "#undef vl_api_version\n\n");

    fprintf (fp, "#include <japi/org_openvpp_vppjapi_vppConn.h>\n");
    fprintf (fp, "#include <japi/org_openvpp_vppjapi_%s.h>\n\n", java_class);

    fprintf (fp, "#include <api/%s_msg_enum.h>\n", vlib_app_name);
    fprintf (fp, "#define vl_typedefs /* define message structures */\n");
    fprintf (fp, "#include <api/%s_all_api_h.h> \n", vlib_app_name);
    fprintf (fp, "#undef vl_typedefs\n\n");

    fprintf (fp, "#define vl_endianfun \n");
    fprintf (fp, "#include <api/%s_all_api_h.h> \n", vlib_app_name);
    fprintf (fp, "#undef vl_endianfun\n\n");

    fprintf (fp, "#define vl_print(handle, ...)\n");
    fprintf (fp, "#define vl_printfun\n");
    fprintf (fp, "#include <api/%s_all_api_h.h>\n", vlib_app_name);
    fprintf (fp, "#undef vl_printfun\n\n");
}

void generate_jni_code (YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;

    /* Walk the top-level node-list */
    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & (NODE_FLAG_MANUAL_JAVA | NODE_FLAG_TYPEONLY))) {
                /* Suppress messages named "xyz_reply" */
                char * cp = (char *) np->data[0];
                while (*cp)
                    cp++;
                cp -= 6;
                if (strncmp (cp, "_reply", 6)) {
                    current_def_name = np->data[0];
                    current_java_parameter_number = 0;
                    vftp = the_vft[np->type];
                    vftp->generate(np, JAVA_JNI_PASS, fp);
                }
            }
        }
        np = np->peer;
    }
}

char *hookup_boilerplate = 
"void vl_msg_reply_handler_hookup (void)\n"
"{\n"
"#define _(N,n)	\\\n"
"    vl_msg_api_set_handlers (VL_API_##N, #n, \\\n"
"        vl_api_generic_reply_handler, \\\n"
"        vl_noop_handler, \\\n"
"        vl_api_##n##_t_endian, \\\n"
"        vl_api_##n##_t_print, \\\n"
"        sizeof(vl_api_##n##_t), 1); \n"
"    foreach_api_reply_handler;\n"
"#undef _\n\n"
"}\n\n";
    
void generate_jni_bottom_boilerplate(FILE *fp)
{
    fputs (hookup_boilerplate, fp);
}

void generate(YYSTYPE a1)
{
    if (dump_tree) {
        dump((node_t *)a1);
    }

    add_msg_ids(a1);

    if (ofp) {
        generate_top_boilerplate(ofp);

        generate_msg_ids(a1, ofp);
        generate_msg_names(a1, ofp);
        generate_typedefs(a1, ofp);
        generate_uniondefs(a1, ofp);
        generate_printfun(a1, ofp);
        generate_endianfun(a1, ofp);
        
        generate_bottom_boilerplate(ofp);
    }

    if (javafp) {
        generate_java_top_boilerplate(javafp);
        generate_java_class_definition(a1, javafp);
        generate_java_bottom_boilerplate(javafp);
    }
    if (jnifp) {
        generate_jni_top_boilerplate(jnifp);
        generate_jni_reply_handler_list (a1, jnifp);
        generate_jni_code(a1, jnifp);
        generate_jni_bottom_boilerplate(jnifp);
    }
}
