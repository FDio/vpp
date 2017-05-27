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
from string import Template
from typing import List

from generate import Parameter
from model import CachedField, CachedMethod, GeneratedAccessibleClass, GeneratedInstantiableClass, MessageClass, PluginModel

def _c_typedef(class_: GeneratedAccessibleClass) -> str:
    return 'vl_api_%s_t' % (class_.type_.name)

def _jni_fqcn(class_: GeneratedAccessibleClass) -> str:
    return class_.fqcn.replace(".", "/")

class Generator():
    __metaclass__ = ABCMeta

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


_primitive_to_object_template = Template("""
    (*env)->Set${field_type}Field(env, obj, ${field_var}, ${convert}(ptr->${c_field}));""")

_primitive_to_struct_template = Template("""
    ptr->${c_field} = ${convert}((*env)->Get${field_type}Field(env, obj, ${field_var}));""")

_primitive_arr_to_object_template = Template("""
    {
        ${jni_type}Array arr = (*env)->New${field_type}Array(env, ${length});
        (*env)->Set${field_type}ArrayRegion(env, arr, 0, ${length}, ptr->${c_field});
        (*env)->SetObjectField(env, obj, ${field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }""")

_primitive_arr_to_struct_template = Template("""
    {
        ${jni_type}Array arr = (${jni_type}Array)(*env)->GetObjectField(env, ${field_var});
        if (arr) {
            jsize len = (*env)->GetArrayLength(arr);
            if (len > ${length} {
                len = ${length};
            }

            (*env)->Get${field_type}ArrayRegion(env, arr, 0, len, ptr->${c_field});
        }
    }""")

_primitive_vararr_to_object_template = Template("""
    {
        const u32 len = ${length_convert}(ptr->${length_field});
        ${jni_type}Array arr = (*env)->New${field_type}Array(env, length);
        (*env)->Set{field_type}ArrayRegion(env, arr, 0, length, ptr->${c_field})
        (*env)->SetObjectField(env, obj, ${field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }""")

_primitive_vararr_to_struct_prologue = Template("""
    ${jni_type}Array vararr = (${jni_type}Array)(*env)->GetObjectField(env, ${field_var});
    const size_t vararr_length = vararr ? (*env)->GetArrayLength(vararr) : 0;
""")

_primitive_vararr_to_struct_epilogue = Template("""
    (*env)->Get${field_type}ArrayRegion(env, vararr, 0, length, ptr->${c_field});""")

class PrimitiveGenerator(Generator):
    def __init__(self, vlib_type: str, jni_type: str, jni_arr_type: str, convert: str) -> None:
        self.vlib_type = vlib_type
        self.jni_type = jni_type
        self.jni_arr_type = jni_arr_type
        self.convert = convert

    def to_object(self, f: CachedField) -> str:
        return _primitive_to_object_template.substitute(
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                convert=self.convert,
                c_field=f.type_.name)

    def to_object_arr(self, f: CachedField) -> str:
        return _primitive_arr_to_object_template.substitute(
                jni_type=self.jni_type,
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                c_field=f.type_.name,
                length=f.type_.len)

    def to_object_vararr(self, f: CachedField) -> str:
        return _primitive_vararr_to_object_template.substitute(
                length_field='FIXME_LENGTH_C_FIELD',
                length_convert='FIXME_LENGTH_CONVERT',
                jni_type=self.jni_type,
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                c_field=f.type_.name)

    def to_struct(self, f: CachedField) -> str:
        return _primitive_to_struct_template.substitute(
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                convert=self.convert,
                c_field=f.type_.name)

    def to_struct_arr(self, f: CachedField) -> str:
        return _primitive_arr_to_struct_template.substitute(
                jni_type=self.jni_type,
                field_type=self.jni_arr_type,
                field_var=f.cache_var_name,
                c_field=f.type_.name,
                length=f.type_.len)

    def to_struct_vararr_prologue(self, f: CachedField) -> str:
        return _primitive_vararr_to_struct_prologue.substitute(
                jni_type=self.jni_type,
                field_var=f.cache_var_name)

    def to_struct_vararr_epilogue(self, f: CachedField) -> str:
        return _primitive_vararr_to_struct_epilogue.substitute(
                field_type=self.jni_arr_type,
                c_field=f.type_.name)


_primitive_generators = {
    'u8' : PrimitiveGenerator('u8',  'jbyte',   'Byte',   ''),
    'i8' : PrimitiveGenerator('i8',  'jbyte',   'Byte',   ''),
    'u16': PrimitiveGenerator('u16', 'jshort',  'Short',  'htobe16'),
    'i16': PrimitiveGenerator('i16', 'jshort',  'Short',  'htobe16'),
    'u32': PrimitiveGenerator('u32', 'jint',    'Int',    'htobe32'),
    'i32': PrimitiveGenerator('i32', 'jint',    'Int',    'htobe32'),
    'u64': PrimitiveGenerator('u64', 'jlong',   'Long',   'htobe64'),
    'i64': PrimitiveGenerator('i64', 'jlong',   'Long',   'htobe64'),
    'f64': PrimitiveGenerator('f64', 'jdouble', 'Double', ''),
}

_jobject_to_object_template = Template("""
    {
        jobject tmp = jvpp_c_to_java_${type_name}(env, ptr->${c_field});
        (*env)->SetObjectField(env, obj, ${field_var}, tmp));
        (*env)->DeleteLocalRef(env, arr);
    }""")

_jobject_to_struct_template = Template("""
    {
        jobject tmp = (*env)->GetObjectField(env, ${field_var});
        jvpp_fill_struct_${type_name}(env, tmp, &ptr->${c_field});
    }""")

_jobject_arr_to_object_template = Template("""
    {
        jobjectArray arr = (*env)->NewObjectArray(env, ${length}, ${class_var}, NULL);
        for (u32 _i = 0; _i < ${length}; _i++) {
            jobject tmp = jvpp_c_to_java_${type_name}(env, ptr->${c_field});
            (*env)->SetObjectArrayElement(env, arr, _i, tmp);
            (*env)->DeleteLocalRef(env, tmp);
        }

        (*env)->SetObjectField(env, obj, ${field_var}, arr);
        (*env)->DeleteLocalRef(env, arr);
    }""")

_jobject_arr_to_struct_template = Template("""
    {
        jobjectArray arr = (jobjectArray)(*env)->GetObjectField(env, ${field_var});
        if (arr) {
            jsize len = (*env)->GetArrayLength(arr);
            if (len > ${length} {
                len = ${length};
            }

            for (u32 _i = 0; _i < ${length}; _i++) {
                jobject tmp = (*env)->GetObjectArrayElement(env, arr, _i);
                jvpp_fill_struct_${type_name}(env, tmp, ptr->${c_field} + _i);
            }

            // FIXME: set length field
        }
    }""")

_jobject_vararr_to_object_template = Template("""
    {
        const u32 len = ${length_convert}(ptr->${length_field});
        jobjectArray arr = (*env)->NewObjectArray(env, length, ${class_var});

        for (u32 _i = 0; _i < length; _i++) {
            jobject elem = jvpp_c_to_java_${type_name}(env, ptr->${c_field} + _i);
            (*env)->SetObjectArrayElement(env, arr, _i, elem);
            (*env)->DeleteLocalRef(env, elem);
        }

        (*env)->SetObjectField(env, obj, ${field_var}, arr);
        (*env)->DeleteLocalRef(env, arr, ${field_var});
    }""")

_jobject_vararr_to_struct_prologue = Template("""
    jobjectArray vararr = (jobjectArray)(*env)->GetObjectField(env, ${field_var});
    const jsize length = vararr ? (*env)->GetArrayLength(vararr) : 0;
""")

_jobject_vararr_to_struct_epilogue = Template("""
    for (u32 _i = 0; _i < length; _i++) {
        jobject tmp = (*env)->GetObjectArrayElement(env, arr, _i);
        jvpp_fill_struct_${type_name}(env, tmp, ptr->${c_field} + _i);
    }
""")

class ObjectGenerator(Generator):
    def __init__(self, ctype: Parameter) -> None:
        pass

    def to_object(self, f: CachedField) -> str:
        return _jobject_to_object_template.substitute(
                type_name='FIXME_TARGET_CLASS_NAME',
                field_var=f.cache_var_name,
                c_field=f.type_.name)

    def to_object_arr(self, f: CachedField) -> str:
        return _jobject_arr_to_object_template.substitute(
                class_var='FIXME_TARGET_CLASS_VAR',
                type_name='FIXME_TARGET_CLASS_NAME',
                field_var=f.cache_var_name,
                c_field=f.type_.name,
                length=f.type_.len)

    def to_object_vararr(self, f: CachedField) -> str:
        return _jobject_vararr_to_object_template.substitute(
                class_var='FIXME_TARGET_CLASS_VAR',
                type_name='FIXME_TARGET_CLASS_NAME',
                field_var=f.cache_var_name,
                c_field=f.type_.name,
                length_field='FIXME_LENGTH_C_FIELD',
                length_convert='FIXME_LENGTH_CONVERT',
                )

    def to_struct(self, f: CachedField) -> str:
        return _jobject_to_struct_template.substitute(
                type_name='FIXME_TARGET_CLASS_NAME',
                field_var=f.cache_var_name,
                c_field=f.type_.name)

    def to_struct_arr(self, f: CachedField) -> str:
        return _jobject_arr_to_struct_template.substitute(
                type_name='FIXME_TARGET_CLASS_NAME',
                field_var=f.cache_var_name,
                c_field=f.type_.name,
                length=f.type_.len)

    def to_struct_vararr_prologue(self, f: CachedField) -> str:
        return _jobject_vararr_to_struct_prologue.substitute(
                field_var=f.cache_var_name)

    def to_struct_vararr_epilogue(self, f: CachedField) -> str:
        return _jobject_vararr_to_struct_epilogue.substitute(
                type_name='FIXME_TARGET_CLASS_NAME',
                c_field=f.type_.name)

def _get_generator(type_: Parameter) -> Generator:
    gen = _primitive_generators.get(type_.type)
    if gen == None:
        return ObjectGenerator(type_)
    return gen

_struct_to_object_decl_template = Template("""
/*
 * Convert a C structure into a java object. Returns a local reference, which needs
 * to be taken care of by the caller, or null if a failure occurs.
 */
static jobject jvpp_c_to_java_${type_name}(JNIEnv *env, const ${c_typedef} *ptr);
""")

def _generate_to_object_decl(class_: GeneratedAccessibleClass) -> str:
    return _struct_to_object_decl_template.substitute(
            type_name=class_.type_.name,
            c_typedef=_c_typedef(class_))

_struct_to_object_template = Template("""
static jobject jvpp_c_to_java_${type_name}(JNIEnv *env, const ${c_typedef} *ptr)
{
    jobject obj = (*env)->NewObject(env, ${class_var}, ${ctor_var});
    ${field_setters}

    return obj;
}
""")

def _generate_to_object(class_: GeneratedInstantiableClass) -> str:
    print("gen class %s" % (class_))
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

    return _struct_to_object_template.substitute(
            type_name=class_.type_.name,
            c_typedef=_c_typedef(class_),
            class_var=class_.cache_var_name,
            ctor_var=class_.cache_var_name + "_NoargCtor", # FIXME: this is a slight hack
            field_setters="".join(field_setters))

_object_send_request_template = Template("""
// FIXME: proper declaration, this should be for ${type_name}
JNIEXPORT jint JNICALL Java_io_fd_vpp_jvpp_acl_JVppAclImpl_macipAclAdd0
(JNIEnv * env, jclass clazz, jobject request) {
    u32 my_context_id = vppjni_get_context_id(&jvpp_main);
    acl_main_t *plugin_main = &acl_main;

    ${vararr_prologue}

    // Calculate the size of message, allocate space for it and clear it
    const size_t msglen = sizeof(*ptr) + vararr_length;
    vl_api_macip_acl_add_t *ptr = vl_msg_api_alloc(msglen);
    memset(ptr, 0, msglen);

    ${field_setters}
    ${vararr_epilogue}

    // Fill out the message header
    ptr->_vl_msg_id = ntohs(get_message_id(env, "acl_interface_set_acl_list_7562419c"));
    ptr->client_index = plugin_main->my_client_index;
    ptr->context = clib_host_to_net_u32(my_context_id);

    // Sent the message out
    vl_msg_api_send_shmem(plugin_main->vl_input_queue, (u8 *)&mp);
    JVPP_CHECK_EXCEPTION;

    return my_context_id;
}""")

def _generate_send_request(class_: GeneratedAccessibleClass) -> str:
    field_setters=[ ]
    vararr_prologue="const size_t vararr_lenth = 0;"
    vararr_epilogue=""
    for f in class_.fields:
        generator = _get_generator(f.type_)
        if f.type_.len == None:
            field_setters.append(generator.to_object(f))
        elif f.type_.len == 0:
            vararr_prologue = generator.to_struct_vararr_prologue(f)
            vararr_epilogue = generator.to_struct_vararr_epilogue(f)
        else:
            field_setters.append(generator.to_object_arr(f))

    return _object_send_request_template.substitute(
            type_name=class_.type_.name,
            c_typedef=_c_typedef(class_),
            field_setters="".join(field_setters),
            vararr_prologue=vararr_prologue,
            vararr_epilogue=vararr_epilogue)

_object_fill_struct_decl_template = Template("""
static jboolean jvpp_fill_struct_${type_name}(JNIEnv *env, jobject obj, ${c_typedef} *ptr);
""")

def _generate_fill_struct_decl(class_: GeneratedAccessibleClass) -> str:
    return _object_fill_struct_decl_template.substitute(
            type_name=class_.type_.name,
            c_typedef=_c_typedef(class_))

_object_fill_struct_template = Template("""
static jboolean jvpp_fill_struct_${type_name}(JNIEnv *env, jobject obj, ${c_typedef} *ptr)
{
    ${field_setters}
    ${vararr_prologue}
    ${vararr_epilogue}
    return vpp_check_exception(env);
}
""")

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

    return _object_fill_struct_template.substitute(
            type_name=class_.type_.name,
            c_typedef=_c_typedef(class_),
            field_setters="".join(field_setters),
            vararr_prologue=vararr_prologue,
            vararr_epilogue=vararr_epilogue)

def _generate_translators(model: PluginModel) -> str:
    return "".join(chain(
        [_generate_fill_struct_decl(c) for c in model.types],
        [_generate_fill_struct(c) for c in model.types],
        [_generate_send_request(c) for c in model.requests],
        [_generate_to_object_decl(c) for c in chain(model.types, model.replies)],
        [_generate_to_object(c) for c in chain(model.types, model.replies)],
        ))

# generate all cache variables
def _generate_cache_vars_decl(classes: List[GeneratedAccessibleClass]) -> str:
    return "\n".join(['static %s %s;' % (obj.jni_type, obj.cache_var_name)
        for obj in chain(classes, sum([c.cached_members for c in classes], [ ]))])

# generate cache variable initializer body
_class_ctor_template = Template("""
    JVPP_ACQUIRE_CLASS(${var}, "${fqcn}");""")
_field_ctor_template = Template("""
    JVPP_ACQUIRE_FIELD(${var}, ${class_var}, "${name}", "${sig}");""")
_method_ctor_template = Template("""
    JVPP_ACQUIRE_METHOD(${var}, ${class_var}, "${name}", "${sig}");""")

def _generate_cache_vars_ctor(classes: List[GeneratedAccessibleClass]) -> str:
    minit = [ ]
    for c in classes:
        minit.extend([_method_ctor_template.substitute(
            var=m.cache_var_name, class_var=m.parent.cache_var_name, name=m.jni_name, sig=m.signature)
            for m in c.cached_members if isinstance(m, CachedMethod)])
        minit.extend([_field_ctor_template.substitute(
            var=f.cache_var_name, class_var=f.parent.cache_var_name, name=f.name, sig=f.signature)
            for f in c.cached_members if isinstance(f, CachedField)])
    return "".join(chain(
        [_class_ctor_template.substitute(var=c.cache_var_name, fqcn=_jni_fqcn(c)) for c in classes],
        minit))

# generate cache variable destructor body
_class_dtor_template = Template("""
    JVPP_RELEASE_CLASS(${var});""")
_member_dtor_template = Template("""
    ${var} = NULL;""")

def _generate_cache_vars_dtor(classes: List[GeneratedAccessibleClass]) -> str:
    mdest = [ ]
    for c in classes:
        mdest.extend([_member_dtor_template.substitute(var=m.cache_var_name) for m in c.cached_members])
    return "".join(chain(mdest, [_class_dtor_template.substitute(var=c.cache_var_name) for c in classes]))

# generate API messages observed at runtime
_api_message_template = Template("""_(${name}_${crc}) \\
""")

def _generate_api_messages(classes: List[GeneratedAccessibleClass]) -> str:
    return "".join([_api_message_template.substitute(name=c.type_.name, crc=c.crc[2:])
        for c in classes if isinstance(c, MessageClass)])

_jni_file_template = Template("""
static jboolean jvpp_check_exception(JNIEnv *env)
{
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

/*
 * Load and verify a class identified by its Fully-Qualified Class Name,
 * verify it and acquire a global reference to it.
 */
static jboolean jvpp_load_class(JNIEnv *env, const char *fqcn, jclass *var)
{
    jclass local = (*env)->FindClass(env, fqcn);
    if (jvpp_check_exception(env)) {
        return JNI_TRUE;
    }

    // FIXME: check class CRC once we generate it

    jclass global = (jclass)(*env)->NewGlobalRef(env, local);
    if (jvpp_check_exception(env)) {
        return JNI_TRUE;
    }

    *var = global;
    return JNI_FALSE;
}

#define JVPP_CHECK_EXCEPTION \\
    do { \\
        if (jvpp_check_exception(env)) { \\
            return JNI_ERR; \\
        } \\
    } while (0)

/*
 * List of all supported API messages along with their CRCs, used to verify
 * that the run-time API version matches the API version observed when this
 * code was generated.
 */
#define foreach_supported_api_message \\
${api_messages}

/*
 * Cached JVM handles to classes, fields and methods. These are populated
 * when the JNI library is loaded and freed just before it unloads.
 */
${cache_vars}

static jint cache_class_references(JNIEnv* env) {

#define JVPP_ACQUIRE_CLASS(_var, _fqcn) \\
    do { \\
        if (jvpp_load_class(env, _fqcn, &_var)) { \\
            return JNI_ERR; \\
        } \\
    } while (0)
#define JVPP_ACQUIRE_FIELD(_var, _cvar, _name, _sig) \\
    do { \\
        _var = (*env)->GetFieldID(env, _cvar, _name, _sig); \\
        JVPP_CHECK_EXCEPTION; \\
    } while (0)
#define JVPP_ACQUIRE_METHOD(_var, _cvar, _name, _sig) \\
    do { \\
        _var = (*env)->GetMethodID(env, _cvar, _name, _sig); \\
        JVPP_CHECK_EXCEPTION; \\
    } while (0)

${cache_var_ctors}

#undef JVPP_ACQUIRE_CLASS
#undef JVPP_ACQUIRE_FIELD
#undef JVPP_ACQUIRE_METHOD
}

static void delete_class_references(JNIEnv* env)
{

#define JVPP_RELEASE_CLASS(_var) \\
    do { \\
       if (_var) { \\
            (*env)->DeleteGlobalRef(env, _var); \\
            _var = NULL; \\
        } \\
    } while (0)

    ${cache_var_dtors}

    return 0;

#undef JVPP_RELEASE_CLASS
}

${object_translators}

""")

# Generate class initialization prologue
def generate_jni(model: PluginModel) -> str:
    classes = [x for x in chain(model.types, model.requests, model.replies)]

    return _jni_file_template.substitute(
            api_messages=_generate_api_messages(classes),
            cache_vars=_generate_cache_vars_decl(classes),
            cache_var_ctors=_generate_cache_vars_ctor(classes),
            cache_var_dtors=_generate_cache_vars_dtor(classes),
            object_translators=_generate_translators(model),
            )

