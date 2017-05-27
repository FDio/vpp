#!/usr/bin/env python3
#
# Copyright (c) 2017 Pantheon Technologies, s.r.o.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from abc import ABCMeta, abstractmethod
from collections import namedtuple
from itertools import chain
from typing import List

from vapi_parse_json import Parameter
from model import CachedField, CachedMethod, GeneratedAccessibleClass, GeneratedInstantiableClass, MessageClass, PluginModel

def _c_typedef(class_: GeneratedAccessibleClass) -> str:
    return 'vl_api_%s_t' % (class_.type_.name)

def _jni_fqcn(class_: GeneratedAccessibleClass) -> str:
    return class_.fqcn.replace(".", "/")

class Generator():
    __metaclass__ = ABCMeta

    def __init__(self, vlib_type: str, jni_type: str, jni_arr_type: str) -> None:
        self.vlib_type = vlib_type
        self.jni_type = jni_type
        self.jni_arr_type = jni_arr_type

    @abstractmethod
    def to_object(self, f: CachedField) -> str:
        return None

    @abstractmethod
    def to_object_arr(self, f: CachedField) -> str:
        return None

    @abstractmethod
    def to_object_vararr(self, f: CachedField) -> str:
        return None

    @abstractmethod
    def to_struct(self, f: CachedField) -> str:
        return None

    @abstractmethod
    def to_struct_arr(self, f: CachedField) -> str:
        return None

    @abstractmethod
    def to_struct_vararr_prologue(self, f: CachedField) -> str:
        return None

    @abstractmethod
    def to_struct_vararr_epilogue(self, f: CachedField) -> str:
        return None


class PrimitiveGenerator(Generator):
    def __init__(self, vlib_type: str, jni_type: str, jni_arr_type: str) -> None:
        Generator.__init__(self, vlib_type, jni_type, jni_arr_type)

    def to_object(self, f: CachedField) -> str:
        return """
    (*env)->Set{field_type}Field(env, obj, {field_var}, ptr->{c_field});""".format(
            field_type=self.jni_arr_type,
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            )

    def to_object_arr(self, f: CachedField) -> str:
        return """
    {{
        {jni_type}Array arr = (*env)->New{field_type}Array(env, {length});
        (*env)->Set{field_type}ArrayRegion(env, arr, 0, {length}, ptr->{c_field});
        (*env)->SetObjectField(env, obj, {field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }}""".format(
            jni_type=self.jni_type,
            field_type=self.jni_arr_type,
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            length=f.type_.len,
            )

    def to_object_vararr(self, f: CachedField) -> str:
        return """
    {{
        const u32 len = {length_convert}(ptr->{length_field});
        {jni_type}Array arr = (*env)->New{field_type}Array(env, length);
        (*env)->Set{field_type}ArrayRegion(env, arr, 0, length, ptr->{c_field})
        (*env)->SetObjectField(env, obj, {field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }}""".format(
            length_field='FIXME_LENGTH_C_FIELD',
            length_convert='FIXME_LENGTH_CONVERT',
            jni_type=self.jni_type,
            field_type=self.jni_arr_type,
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            )

    def to_struct(self, f: CachedField) -> str:
        return """
    ptr->{c_field} = (*env)->Get{field_type}Field(env, obj, {field_var});""".format(
            field_type=self.jni_arr_type,
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            )

    def to_struct_arr(self, f: CachedField) -> str:
        return """
    {{
        {jni_type}Array arr = ({jni_type}Array)(*env)->GetObjectField(env, {field_var});
        if (arr) {{
            jsize len = (*env)->GetArrayLength(arr);
            if (len > {length}) {{
                len = {length};
            }}

            (*env)->Get{field_type}ArrayRegion(env, arr, 0, len, ptr->{c_field});
        }}
    }}""".format(
            jni_type=self.jni_type,
            field_type=self.jni_arr_type,
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            length=f.type_.len
            )

    def to_struct_vararr_prologue(self, f: CachedField) -> str:
        return """
    {jni_type}Array vararr = ({jni_type}Array)(*env)->GetObjectField(env, {field_var});
    const size_t vararr_length = vararr ? (*env)->GetArrayLength(vararr) : 0;
""".format(
        jni_type=self.jni_type,
        field_var=f.cache_var_name,
        )

    def to_struct_vararr_epilogue(self, f: CachedField) -> str:
        return """
    (*env)->Get{field_type}ArrayRegion(env, vararr, 0, length, ptr->{c_field});""".format(
            field_type=self.jni_arr_type,
            c_field=f.type_.name,)


class ByteswapGenerator(Generator):

    def __init__(self, vlib_type: str, jni_type: str, jni_arr_type: str, width: str) -> None:
        Generator.__init__(self, vlib_type, jni_type, jni_arr_type)
        self._width = width

    def to_object(self, f: CachedField) -> str:
        return """
    (*env)->Set{field_type}Field(env, obj, {field_var}, be2le{width}(ptr->{c_field}));""".format(
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                width=self._width,
                c_field=f.type_.name,
                )

    def to_object_arr(self, f: CachedField) -> str:
        return """
    {{
        {c_typedef} converted[{length}];
        for (int _i = 0; i < {length}; ++i) {{
            converted[_i] = {convert}(ptr->{c_field}[_i]);
        }}

        {jni_type}Array arr = (*env)->New{field_type}Array(env, {length});
        (*env)->Set{field_type}ArrayRegion(env, arr, 0, {length}, converted);
        (*env)->SetObjectField(env, obj, {field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }}""".format(
                jni_type=self.jni_type,
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                c_field=f.type_.name,
                length=f.type_.len,
                )

    def to_object_vararr(self, f: CachedField) -> str:
        return """
    {{
        const u32 len = {length_convert}(ptr->{length_field});
        {c_typedef} converted[len];
        for (int _i = 0; i < len; ++i) {{
            converted[_i] = be2le(ptr->{c_field}[_i]);
        }}

        {jni_type}Array arr = (*env)->New{field_type}Array(env, len);
        (*env)->Set{field_type}ArrayRegion(env, arr, 0, len, converted)
        (*env)->SetObjectField(env, obj, {field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }}""".format(
                length_field='FIXME_LENGTH_C_FIELD',
                length_convert='FIXME_LENGTH_CONVERT',
                jni_type=self.jni_type,
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                c_typedef=self.vlib_type,
                c_field=f.type_.name,
                )

    def to_struct(self, f: CachedField) -> str:
        return """
    ptr->{c_field} = le2be{width}((*env)->Get{field_type}Field(env, obj, {field_var}));""".format(
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                width=self._width,
                c_field=f.type_.name)

    def to_struct_arr(self, f: CachedField) -> str:
        return """
    {{
        {jni_type}Array arr = ({jni_type}Array)(*env)->GetObjectField(env, {field_var});
        if (arr) {{
            jsize len = (*env)->GetArrayLength(arr);
            if (len > {length}) {
                len = {length};
            }

            {c_typedef} tmp[len];
            (*env)->Get{field_type}ArrayRegion(env, arr, 0, len, tmp);

            for (int _i = 0; i < len; ++i) {{
                ptr->{c_field}[_i]) = le2be{width}(tmp[_i]);
            }}
        }}
    }}""".format(
                jni_type=self.jni_type,
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                c_field=f.type_.name,
                length=f.type_.len,
                width=self._width,
                )

    def to_struct_vararr_prologue(self, f: CachedField) -> str:
        return """
    {jni_type}Array vararr = ({jni_type}Array)(*env)->GetObjectField(env, {field_var});
    const size_t len = vararr ? (*env)->GetArrayLength(vararr) : 0;
""".format(
        jni_type=self.jni_type,
        field_var=f.cache_var_name,
        )

    def to_struct_vararr_epilogue(self, f: CachedField) -> str:
        return """
    {{
        {c_typedef} tmp[len];
        (*env)->Get{field_type}ArrayRegion(env, arr, 0, len, tmp);

        for (int _i = 0; i < len; ++i) {{
            ptr->{c_field}[_i]) = le2be{width}(tmp[_i]);
        }}
    }}""".format(
                field_type=self.jni_arr_type,
                c_typedef=self.vlib_type,
                c_field=f.type_.name,
                width=self._width,
                )


_primitive_generators = {
    'u8' : PrimitiveGenerator('u8',  'jbyte',   'Byte'),
    'i8' : PrimitiveGenerator('i8',  'jbyte',   'Byte'),
    'f64': PrimitiveGenerator('f64', 'jdouble', 'Double'),
    'u16': ByteswapGenerator( 'u16', 'jshort',  'Short', '16'),
    'i16': ByteswapGenerator( 'i16', 'jshort',  'Short', '16'),
    'u32': ByteswapGenerator( 'u32', 'jint',    'Int',   '32'),
    'i32': ByteswapGenerator( 'i32', 'jint',    'Int',   '32'),
    'u64': ByteswapGenerator( 'u64', 'jlong',   'Long',  '64'),
    'i64': ByteswapGenerator( 'i64', 'jlong',   'Long',  '64'),
}

class ObjectGenerator(Generator):
    def __init__(self, ctype: Parameter) -> None:
        pass

    def to_object(self, f: CachedField) -> str:
        return """
    {{
        jobject tmp = jvpp_alloc_obj_{type_name}(env, ptr->{c_field});
        (*env)->SetObjectField(env, obj, {field_var}, tmp));
        (*env)->DeleteLocalRef(env, arr);
    }}""".format(
            type_name='FIXME_TARGET_CLASS_NAME',
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            )

    def to_object_arr(self, f: CachedField) -> str:
        return """
    {{
        jobjectArray arr = (*env)->NewObjectArray(env, {length}, {class_var}, NULL);
        for (u32 _i = 0; _i < {length}; _i++) {{
            jobject tmp = jvpp_alloc_obj_{type_name}(env, ptr->{c_field});
            (*env)->SetObjectArrayElement(env, arr, _i, tmp);
            (*env)->DeleteLocalRef(env, tmp);
        }}

        (*env)->SetObjectField(env, obj, {field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }}""".format(
            class_var='FIXME_TARGET_CLASS_VAR',
            type_name='FIXME_TARGET_CLASS_NAME',
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            length=f.type_.len,
            )

    def to_object_vararr(self, f: CachedField) -> str:
        return """
    {{
        const u32 len = {length_convert}(ptr->{length_field});
        jobjectArray arr = (*env)->NewObjectArray(env, length, {class_var});

        for (u32 _i = 0; _i < length; _i++) {{
            jobject elem = jvpp_alloc_obj_{type_name}(env, ptr->{c_field} + _i);
            (*env)->SetObjectArrayElement(env, arr, _i, elem);
            (*env)->DeleteLocalRef(env, elem);
        }}

        (*env)->SetObjectField(env, obj, {field_var}, arr);
        (*env)->DeleteLocalRef(env, arr, {field_var});
    }}""".format(
            class_var='FIXME_TARGET_CLASS_VAR',
            type_name='FIXME_TARGET_CLASS_NAME',
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            length_field='FIXME_LENGTH_C_FIELD',
            length_convert='FIXME_LENGTH_CONVERT',
            )

    def to_struct(self, f: CachedField) -> str:
        return """
    {{
        jobject tmp = (*env)->GetObjectField(env, {field_var});
        jvpp_fill_struct_{type_name}(env, tmp, &ptr->{c_field});
    }}""".format(
            type_name='FIXME_TARGET_CLASS_NAME',
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            )

    def to_struct_arr(self, f: CachedField) -> str:
        return """
    {{
        jobjectArray arr = (jobjectArray)(*env)->GetObjectField(env, {field_var});
        if (arr) {{
            jsize len = (*env)->GetArrayLength(arr);
            if (len > {length}) {{
                len = {length};
            }}

            for (u32 _i = 0; _i < {length}; _i++) {{
                jobject tmp = (*env)->GetObjectArrayElement(env, arr, _i);
                jvpp_fill_struct_{type_name}(env, tmp, ptr->{c_field} + _i);
            }}

            // FIXME: set length field
        }}
    }}""".format(
            type_name='FIXME_TARGET_CLASS_NAME',
            field_var=f.cache_var_name,
            c_field=f.type_.name,
            length=f.type_.len,
            )

    def to_struct_vararr_prologue(self, f: CachedField) -> str:
        return """
    jobjectArray vararr = (jobjectArray)(*env)->GetObjectField(env, {field_var});
    const jsize length = vararr ? (*env)->GetArrayLength(vararr) : 0;
""".format(
        field_var=f.cache_var_name,
        )

    def to_struct_vararr_epilogue(self, f: CachedField) -> str:
        return """
    for (u32 _i = 0; _i < length; _i++) {{
        jobject tmp = (*env)->GetObjectArrayElement(env, arr, _i);
        jvpp_fill_struct_{type_name}(env, tmp, ptr->{c_field} + _i);
    }}
""".format(
        type_name='FIXME_TARGET_CLASS_NAME',
        c_field=f.type_.name,
        )

def _get_generator(type_: Parameter) -> Generator:
    gen = _primitive_generators.get(type_.type)
    if gen == None:
        return ObjectGenerator(type_)
    return gen


def _generate_to_object_decl(class_: GeneratedAccessibleClass) -> str:
    return """
/*
 * Convert a C structure into a java object. Returns a local reference, which needs
 * to be taken care of by the caller, or null if a failure occurs.
 */
static jobject jvpp_alloc_obj_{type_name}(JNIEnv *env, const {c_typedef} *ptr);""".format(
        type_name=class_.type_.name,
        c_typedef=_c_typedef(class_),
        )

def _generate_to_object(class_: GeneratedInstantiableClass) -> str:
    field_setters = [ ]
    for f in class_.fields:
        generator = _get_generator(f.type_)
        if f.type_.len == None:
            s = generator.to_object(f)
        elif f.type_.len == 0:
            s = generator.to_object_vararr(f)
        else:
            s = generator.to_object_arr(f)
        field_setters.append(s)

    return """
static jobject jvpp_alloc_obj_{type_name}(JNIEnv *env, const {c_typedef} *ptr)
{{
    jobject obj = (*env)->NewObject(env, {class_var}, {ctor_var});
    {field_setters}

    return obj;
}}""".format(
        type_name=class_.type_.name,
        c_typedef=_c_typedef(class_),
        class_var=class_.cache_var_name,
        ctor_var=class_.cache_var_name + "_NoargCtor", # FIXME: this is a slight hack
        field_setters="".join(field_setters),
        )


def _generate_fill_struct_decl(class_: GeneratedAccessibleClass) -> str:
    return """
static jboolean jvpp_fill_struct_{type_name}(JNIEnv *env, jobject obj, {c_typedef} *ptr);""".format(
        type_name=class_.type_.name,
        c_typedef=_c_typedef(class_),
        )

def _generate_fill_struct(class_: GeneratedAccessibleClass) -> str:
    field_setters=[ ]
    vararr_prologue=""
    vararr_epilogue=""
    for f in class_.fields:
        generator = _get_generator(f.type_)
        if f.type_.len == None:
            field_setters.append(generator.to_struct(f))
        elif f.type_.len == 0:
            vararr_prologue = generator.to_struct_vararr_prologue(f)
            vararr_epilogue = generator.to_struct_vararr_epilogue(f)
        else:
            field_setters.append(generator.to_struct_arr(f))

    return """
static jboolean jvpp_fill_struct_{type_name}(JNIEnv *env, jobject obj, {c_typedef} *ptr)
{{
    {field_setters}
    {vararr_prologue}
    {vararr_epilogue}
    return vpp_check_exception(env);
}}""".format(
        type_name=class_.type_.name,
        c_typedef=_c_typedef(class_),
        field_setters="".join(field_setters),
        vararr_prologue=vararr_prologue,
        vararr_epilogue=vararr_epilogue,
        )


def _generate_alloc_struct(class_: GeneratedAccessibleClass) -> str:
    field_setters=[ ]
    vararr_prologue="const size_t vararr_length = 0;"
    vararr_epilogue=""
    for f in class_.fields:
        generator = _get_generator(f.type_)
        if f.type_.len == None:
            field_setters.append(generator.to_struct(f))
        elif f.type_.len == 0:
            vararr_prologue = generator.to_struct_vararr_prologue(f)
            vararr_epilogue = generator.to_struct_vararr_epilogue(f)
        else:
            field_setters.append(generator.to_object_arr(f))

    return """
static {c_typedef} *jvpp_alloc_struct_{c_typedef}(JNIEnv *env, jobject obj)
{{
    {vararr_prologue}

    // Calculate the size of message, allocate space for it and clear it
    const size_t msglen = sizeof(c_typedef) + (vararr_length * sizeof({c_typedef}));
    {c_typedef} *ptr = vl_msg_api_alloc(msglen);
    memset(ptr, 0, msglen);

    {field_setters}
    {vararr_epilogue}

    if (jvpp_check_exception(env)) {{
        vl_msg_api_free(ptr);
        return NULL;
    }}

    // Fill out the message header
    ptr->_vl_msg_id = ntohs(get_message_id(env, "acl_interface_set_acl_list_7562419c"));
    return ptr;
}}""".format(
        type_name=class_.type_.name,
        c_typedef=_c_typedef(class_),
        field_setters="".join(field_setters),
        vararr_prologue=vararr_prologue,
        vararr_epilogue=vararr_epilogue,
        )

"""
// FIXME: proper declaration, this should be for {type_name}
JNIEXPORT jint JNICALL Java_io_fd_vpp_jvpp_acl_JVppAclImpl_macipAclAdd0
(JNIEnv * env, jclass clazz, jobject request)
{{
    u32 my_context_id = vppjni_get_context_id(&jvpp_main);
    acl_main_t *plugin_main = &acl_main;


    // Fill out the message header
    ptr->_vl_msg_id = ntohs(get_message_id(env, "acl_interface_set_acl_list_7562419c"));
    ptr->client_index = plugin_main->my_client_index;
    ptr->context = clib_host_to_net_u32(my_context_id);

    // Sent the message out
    vl_msg_api_send_shmem(plugin_main->vl_input_queue, (u8 *)&mp);
    JVPP_CHECK_EXCEPTION;

    return my_context_id;
}}"""

def _generate_translators(model: PluginModel) -> str:
    return "\n".join(chain(
        [_generate_fill_struct_decl(c) for c in model.types],
        [_generate_fill_struct(c) for c in model.types],
        [_generate_alloc_struct(c) for c in model.requests],
        [_generate_to_object_decl(c) for c in chain(model.types, model.replies)],
        [_generate_to_object(c) for c in chain(model.types, model.replies)],
        ))

# generate all cache variables
def _generate_cache_vars_decl(classes: List[GeneratedAccessibleClass]) -> str:
    return "\n".join(['static %s %s;' % (obj.jni_type, obj.cache_var_name)
        for obj in chain(classes, sum([c.cached_members for c in classes], [ ]))])

# generate cache variable initializer body
def _generate_cache_vars_ctor(classes: List[GeneratedAccessibleClass]) -> str:
    minit = [ ]
    for c in classes:
        minit.extend(["""
    JVPP_ACQUIRE_METHOD({var}, {class_var}, "{name}", "{sig}");""".format(
        var=m.cache_var_name,
        class_var=m.parent.cache_var_name,
        name=m.jni_name,
        sig=m.signature
        ) for m in c.cached_members if isinstance(m, CachedMethod)])
        minit.extend(["""
    JVPP_ACQUIRE_FIELD({var}, {class_var}, "{name}", "{sig}");""".format(
        var=f.cache_var_name,
        class_var=f.parent.cache_var_name,
        name=f.name,
        sig=f.signature
        ) for f in c.cached_members if isinstance(f, CachedField)])
    return "".join(chain(
        ["""
    JVPP_ACQUIRE_CLASS({var}, "{fqcn}");""".format(
        var=c.cache_var_name,
        fqcn=_jni_fqcn(c)
        ) for c in classes],
        minit))

# generate cache variable destructor body
def _generate_cache_vars_dtor(classes: List[GeneratedAccessibleClass]) -> str:
    mdest = [ ]
    for c in classes:
        mdest.extend(["""
    {var} = NULL;""".format(
        var=m.cache_var_name,
        ) for m in c.cached_members])
    return "".join(chain(mdest, ["""
    JVPP_RELEASE_CLASS({var});""".format(
        var=c.cache_var_name,
        ) for c in classes]))

# generate API messages observed at runtime

def _generate_api_messages(classes: List[GeneratedAccessibleClass]) -> str:
    return "\n".join(['_({name}_{crc}) \\'.format(
        name=c.type_.name,
        crc=c.crc[2:],
        ) for c in classes if isinstance(c, MessageClass)])

# Generate class initialization prologue
def generate_jni(model: PluginModel) -> str:
    classes = [x for x in chain(model.types, model.requests, model.replies)]

    return """

#import <endian.h>

static jboolean jvpp_check_exception(JNIEnv *env)
{{
    if ((*env)->ExceptionCheck(env)) {{
        (*env)->ExceptionDescribe(env);
        return JNI_TRUE;
    }}
    return JNI_FALSE;
}}

/*
 * Load and verify a class identified by its Fully-Qualified Class Name,
 * verify it and acquire a global reference to it.
 */
static jboolean jvpp_load_class(JNIEnv *env, const char *fqcn, jclass *var)
{{
    jclass local = (*env)->FindClass(env, fqcn);
    if (jvpp_check_exception(env)) {{
        return JNI_TRUE;
    }}

    // FIXME: check class CRC once we generate it

    jclass global = (jclass)(*env)->NewGlobalRef(env, local);
    if (jvpp_check_exception(env)) {{
        return JNI_TRUE;
    }}

    *var = global;
    return JNI_FALSE;
}}

#define JVPP_CHECK_EXCEPTION \\
    do {{ \\
        if (jvpp_check_exception(env)) {{ \\
            return JNI_ERR; \\
        }} \\
    }} while (0)

/*
 * List of all supported API messages along with their CRCs, used to verify
 * that the run-time API version matches the API version observed when this
 * code was generated.
 */
#define foreach_supported_api_message \\
{api_messages}

/*
 * Cached JVM handles to classes, fields and methods. These are populated
 * when the JNI library is loaded and freed just before it unloads.
 */
{cache_vars}

static jint cache_class_references(JNIEnv* env)
{{
#define JVPP_ACQUIRE_CLASS(_var, _fqcn) \\
    do {{ \\
        if (jvpp_load_class(env, _fqcn, &_var)) {{ \\
            return JNI_ERR; \\
        }} \\
    }} while (0)
#define JVPP_ACQUIRE_FIELD(_var, _cvar, _name, _sig) \\
    do {{ \\
        _var = (*env)->GetFieldID(env, _cvar, _name, _sig); \\
        JVPP_CHECK_EXCEPTION; \\
    }} while (0)
#define JVPP_ACQUIRE_METHOD(_var, _cvar, _name, _sig) \\
    do {{ \\
        _var = (*env)->GetMethodID(env, _cvar, _name, _sig); \\
        JVPP_CHECK_EXCEPTION; \\
    }} while (0)

{cache_var_ctors}

#undef JVPP_ACQUIRE_CLASS
#undef JVPP_ACQUIRE_FIELD
#undef JVPP_ACQUIRE_METHOD
}}

static void delete_class_references(JNIEnv* env)
{{
#define JVPP_RELEASE_CLASS(_var) \\
    do {{ \\
        if (_var) {{ \\
            (*env)->DeleteGlobalRef(env, _var); \\
            _var = NULL; \\
        }} \\
    }} while (0)

    {cache_var_dtors}

    return 0;

#undef JVPP_RELEASE_CLASS
}}

#define be2le16(x) htole16(be16toh(x))
#define be2le32(x) htole32(be32toh(x))
#define be2le64(x) htole64(be64toh(x))
#define le2be16(x) htobe16(le16toh(x))
#define le2be32(x) htobe32(le32toh(x))
#define le2be64(x) htobe64(le64toh(x))

{object_translators}

#undef be2le16
#undef be2le32
#undef be2le64
#undef le2be16
#undef le2be32
#undef le2be64

""".format(
            api_messages=_generate_api_messages(classes),
            cache_vars=_generate_cache_vars_decl(classes),
            cache_var_ctors=_generate_cache_vars_ctor(classes),
            cache_var_dtors=_generate_cache_vars_dtor(classes),
            object_translators=_generate_translators(model),
            )

