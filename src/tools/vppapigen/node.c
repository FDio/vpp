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
#include <stdbool.h>
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
FILE *pythonfp;
FILE *jsonfp;
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

    case PYTHON_PASS:
        fputs("('", pythonfp);
        fputs((char *)type_name, pythonfp);
        fputs("', ", pythonfp);
        break;

    case JSON_PASS:
        fputs("[\"", jsonfp);
        fputs((char *)type_name, jsonfp);
        fputs("\", ", jsonfp);
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

node_vft_t node_illegal_vft = {
    node_illegal_print,
    node_illegal_generate,
    "illegal"
};

void node_u8_print (node_t *this)
{
    primtype_recursive_print(this, "u8 ");
}

void node_u8_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "u8", "%u", "(unsigned)");
}

node_vft_t node_u8_vft = {
    node_u8_print,
    node_u8_generate,
    NULL
};

void node_u16_print (node_t *this)
{
    primtype_recursive_print(this, "u16 ");
}

void node_u16_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "u16", "%u", "(unsigned)");
}

node_vft_t node_u16_vft = {
    node_u16_print,
    node_u16_generate,
    "clib_net_to_host_u16"
};

void node_u32_print (node_t *this)
{
    primtype_recursive_print(this, "u32 ");
}

void node_u32_generate (node_t *this, enum passid which, FILE *ofp)
{
    primtype_recursive_generate(this, which, ofp, "u32", "%u", "(unsigned)");
}

node_vft_t node_u32_vft = {
    node_u32_print,
    node_u32_generate,
    "clib_net_to_host_u32",
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

node_vft_t node_u64_vft = {
    node_u64_print,
    node_u64_generate,
    "clib_net_to_host_u64"
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
    ""
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
    "clib_net_to_host_u16"
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
    "clib_net_to_host_u32"
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
    "clib_net_to_host_u64"
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

node_vft_t node_f64_vft = {
    node_f64_print,
    node_f64_generate,
    " ",                        /* FP numbers are sent in host byte order */
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

void node_define_generate (node_t *this, enum passid which, FILE *fp)
{
    node_t *child;

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

    case PYTHON_PASS:
      fprintf(fp, "('%s',\n", CDATA0);
        child = this->deeper;
        indent += 4;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            indent_me(fp);
            vftp->generate(child, which, fp);
            child = child->peer;
        }
        indent -= 4;
        fprintf(fp, "),\n\n");
        break;

    case JSON_PASS:
        fprintf(fp, "[\"%s\",\n", CDATA0);
        child = this->deeper;
        indent += 4;
        while (child) {
            node_vft_t *vftp = the_vft[child->type];
            indent_me(fp);
            vftp->generate(child, which, fp);
            child = child->peer;
	    fprintf(fp, ",\n");
        }
	indent_me(fp);
	fprintf (fp, "{\"crc\" : \"0x%08x\"}\n", (u32)(uword)CDATA3);
        indent -= 4;
	indent_me(fp);
        fprintf(fp, "]");
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
                fprintf(fp, "/* a->%s%s = a->%s%s (no-op) */\n",
                        union_prefix, CDATA0, 
                        union_prefix, CDATA0);
            }
        }
        break;
    case PYTHON_PASS:
        fprintf(fp, "'%s'),\n", CDATA0);
        break;

    case JSON_PASS:
        fprintf(fp, "\"%s\"]", CDATA0);
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
        /* If this is a simple endian swap, but the endian swap method is a no-op,
         * then indicate this is a no-op in a comment.
         */
	if (!current_is_complex && current_endianfun == NULL) {
            indent_me(fp);
            fprintf(fp, "/* a->%s%s[0..%d] = a->%s%s[0..%d] (no-op) */\n",
                    union_prefix, CDATA0, IDATA1 - 1,
                    union_prefix, CDATA0, IDATA1 - 1);
            break;
        }

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
    case PYTHON_PASS:
        if (CDATA2 != 0) { // variable length vector
            fprintf(fp, "'%s', '%d', '%s'),\n", CDATA0, IDATA1, CDATA2);
        } else {
            fprintf(fp, "'%s', '%d'),\n", CDATA0, IDATA1);
        }
        break;

    case JSON_PASS:
      if (CDATA2 != 0) { /* variable length vector */
            fprintf(fp, "\"%s\", %d, \"%s\"]", CDATA0, IDATA1, CDATA2);
        } else {
            fprintf(fp, "\"%s\", %d]", CDATA0, IDATA1);
        }
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

        if (deeper && deeper->type == NODE_VECTOR)
            fprintf(fp, "%s_print(a->%s%s, handle);\n", 
                    CDATA0, union_prefix, member_name);
        else
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
        if (deeper && deeper->type == NODE_VECTOR)
            fprintf(fp, "%s_endian(a->%s%s);\n", 
                    CDATA0, union_prefix, member_name);
        else
            fprintf(fp, "%s_endian(&a->%s%s);\n", 
                    CDATA0, union_prefix, member_name);
        break;
    case PYTHON_PASS:
        fprintf(fp, "('%s',", CDATA0);
        deeper = this->deeper;
        if (deeper) {
            vftp = the_vft[deeper->type];
            vftp->generate(deeper, which, fp);
        }
        break;

    case JSON_PASS:
        fprintf(fp, "[\"%s\", ", CDATA0);
        deeper = this->deeper;
        if (deeper) {
            vftp = the_vft[deeper->type];
            vftp->generate(deeper, which, fp);
        }
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
    np->data[3] = (void *) message_crc;
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
 * add_vector_vbl (char *vector_name, char *vector_length_var)
 */

YYSTYPE add_variable_length_vector_vbl (YYSTYPE vector_name, YYSTYPE vector_length_var)
{
    node_t *np;

    np = make_node(NODE_VECTOR);
    np->data[0] = (void *) vector_name;
    np->data[1] = (void *) 0; // vector size used for vpe.api.h generation (array of length zero)
    np->data[2] = (void *) vector_length_var; // name of the variable that stores vector length
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

    /* Generate a foo_reply_t right here */
    if (flags & NODE_FLAG_AUTOREPLY) 
        autoreply(np);

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

    strncpy (tmpbuf, cp, sizeof(tmpbuf)-1);

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
    time_t curtime;
    char *datestring;
    char *source_date_epoch;
    if ((source_date_epoch = getenv("SOURCE_DATE_EPOCH")) == NULL || (curtime = (time_t)strtol(source_date_epoch, NULL, 10)) <= 0)
        curtime = starttime;
    datestring = asctime(gmtime(&curtime));
    fixed_name = fixup_input_filename();

    datestring[24] = 0;

    fprintf (fp, "/*\n");
    fprintf (fp, " * VLIB API definitions %s\n", datestring);
    fprintf (fp, " * Input file: %s\n", input_filename);
    fprintf (fp, " * Automatically generated: please edit the input file ");
    fprintf (fp, "NOT this file!\n");
    fprintf (fp, " */\n\n");
    fprintf (fp, "#if defined(vl_msg_id)||defined(vl_union_id)||");
    fprintf (fp, "defined(vl_printfun) \\\n ||defined(vl_endianfun)||");
    fprintf (fp, " defined(vl_api_version)||defined(vl_typedefs) \\\n");
    fprintf (fp, " ||defined(vl_msg_name)||defined(vl_msg_name_crc_list)\n");
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

void generate_msg_name_crc_list (YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    char *unique_suffix, *cp;

    unique_suffix = sxerox(fixed_name);

    cp = unique_suffix;
    while (*cp && (*cp != '.'))
        cp++;
    if (*cp == '.')
        *cp = 0;

    fprintf (fp, "\n/****** Message name, crc list ******/\n\n");

    fprintf (fp, "#ifdef vl_msg_name_crc_list\n");
    fprintf (fp, "#define foreach_vl_msg_name_crc_%s ", unique_suffix);

    while (np) {
        if (np->type == NODE_DEFINE) {
            if (!(np->flags & NODE_FLAG_TYPEONLY)) {
                fprintf (fp, "\\\n_(VL_API_%s, %s, %08x) ",
                         uppercase (np->data[0]), (i8 *) np->data[0],
                         (u32)(uword)np->data[3]);
            }
        }
        np = np->peer;
    }
    fprintf (fp, "\n#endif\n\n");
    free (unique_suffix);
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

void generate_python_msg_definitions(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;
    fprintf (fp, "messages = [\n");
    /* Walk the top-level node-list */
    while (np) {
      if (np->type == NODE_DEFINE && !(np->flags & NODE_FLAG_TYPEONLY)) {
        /* Yeah, this is pedantic */
        vftp = the_vft[np->type];
        vftp->generate(np, PYTHON_PASS, fp);
      }
      np = np->peer;
    }
    fprintf (fp, "\n]\n");
}

static bool
is_typeonly_check(node_t *np, bool typeonly)
{
  bool is_typeonly = (np->flags & NODE_FLAG_TYPEONLY);
  return (is_typeonly == typeonly);
}

static void
generate_json_definitions(YYSTYPE a1, FILE *fp, bool typeonly)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;
    indent_me(fp);
    if (typeonly)
      fprintf (fp, "\"types\" : [\n");
    else
      fprintf (fp, "\"messages\" : [\n");

    /* Walk the top-level node-list */
    bool comma = false;
    indent += 4;
    while (np) {
      if (np->type == NODE_DEFINE && is_typeonly_check(np, typeonly)) {
        /* Yeah, this is pedantic */
        vftp = the_vft[np->type];
	indent_me(fp);
        vftp->generate(np, JSON_PASS, fp);
	comma = true;
      }
      np = np->peer;
      if (comma && np &&
	  np->type == NODE_DEFINE && is_typeonly_check(np, typeonly))
	fprintf (fp, ",\n");

    }
    indent -= 4;
    fprintf (fp, "\n");
    indent_me(fp);
    fprintf(fp, "]");
}

void generate_python_typeonly_definitions(YYSTYPE a1, FILE *fp)
{
    node_t *np = (node_t *)a1;
    node_vft_t *vftp;
    fprintf (fp, "types = [\n");
    /* Walk the top-level node-list */
    while (np) {
      if (np->type == NODE_DEFINE && (np->flags & NODE_FLAG_TYPEONLY)) {
        vftp = the_vft[np->type];
        vftp->generate(np, PYTHON_PASS, fp);
      }
      np = np->peer;
    }
    fprintf (fp, "\n]\n");
}

void generate_python(YYSTYPE a1, FILE *fp)
{
    generate_python_typeonly_definitions(a1, fp);
    generate_python_msg_definitions(a1, fp);

    /*
     * API CRC signature
     */
    fprintf (fp, "vl_api_version = 0x%08x\n\n", (unsigned int)input_crc);
}

void generate_json(YYSTYPE a1, FILE *fp)
{
    fprintf (fp, "{\n");
    indent += 4;
    generate_json_definitions(a1, fp, true);
    fprintf (fp, ",\n");
    generate_json_definitions(a1, fp, false);

    /*
     * API CRC signature
     */
    fprintf (fp, ",\n\"vl_api_version\" :\"0x%08x\"\n",
	     (unsigned int)input_crc);
    fprintf (fp, "}\n");
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
        generate_msg_name_crc_list(a1, ofp);
        generate_typedefs(a1, ofp);
        generate_uniondefs(a1, ofp);
        generate_printfun(a1, ofp);
        generate_endianfun(a1, ofp);
        
        generate_bottom_boilerplate(ofp);
    }
    if (pythonfp) {
      generate_python(a1, pythonfp);
    }
    if (jsonfp) {
      generate_json(a1, jsonfp);
    }
}
