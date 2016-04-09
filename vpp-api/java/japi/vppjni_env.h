/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

/*
 * Utilities for accessing Java classes/method/fields in an efficient
 * manner.
 */

/*
 * A potentially-uninitialized reference to a Java class
 */
typedef struct vppjni_class {
    // Fully-Qualified Class Name
    const char          *fqcn;
    // Constructor signature
    const char          *init_sig;
    // Global reference to class handle
    jclass              jclass;
    // Constructor method handle
    jmethodID           jinit;
    // Next item in linked list
    struct vppjni_class *next;
} vppjni_class_t;

typedef struct jenv_field {
    // Field name
    const char           *name;
    // Field type
    const char           *type;
    // Defining class reference
    const vppjni_class_t *clsref;
    // Field handle
    jfieldID             jfield;
    // Next item in linked list
    struct jenv_field    *next;
} vppjni_field_t;

#define VPPJNI_CLASS_SYMBOL(name) vppjni_class_##name
#define VPPJNI_CLASS_INIT(name) vppjni_class_##name##_init
#define BIND_JAPI_CLASS(name, sig) \
    static vppjni_class_t VPPJNI_CLASS_SYMBOL(name); \
    static void VPPJNI_CLASS_INIT(name)(void) __attribute__((__constructor__)); \
    static void VPPJNI_CLASS_INIT(name)() \
    { \
        VPPJNI_CLASS_SYMBOL(name).fqcn = "org/openvpp/vppjapi/" #name; \
        VPPJNI_CLASS_SYMBOL(name).init_sig = sig; \
        vppjni_register_class(&VPPJNI_CLASS_SYMBOL(name)); \
    } \
    static __attribute__((unused)) jobject name##Array(JNIEnv *env, jsize length) \
    { \
        return (*env)->NewObjectArray(env, length, VPPJNI_CLASS_SYMBOL(name).jclass, NULL); \
    } \
    static jobject name##Object(JNIEnv *env, ...) \
    { \
        va_list ap; \
        va_start(ap, env); \
        jobject obj = vppjni_new_object(env, &VPPJNI_CLASS_SYMBOL(name), ap); \
        va_end(ap); \
        return obj; \
    }

#define VPPJNI_FIELD_SYMBOL(cls, name) vppjni_field_##cls##_##name
#define VPPJNI_FIELD_INIT(cls, name) vppjni_field_##cls##_##name##_init
#define BIND_JAPI_FIELD(cls, field, sig) \
    static vppjni_field_t VPPJNI_FIELD_SYMBOL(cls, field); \
        static void VPPJNI_FIELD_INIT(cls, field)(void) __attribute__((__constructor__)); \
    static void VPPJNI_FIELD_INIT(cls, field)() \
    { \
        VPPJNI_FIELD_SYMBOL(cls, field).name = #field; \
        VPPJNI_FIELD_SYMBOL(cls, field).type = sig; \
        VPPJNI_FIELD_SYMBOL(cls, field).clsref = &VPPJNI_CLASS_SYMBOL(cls); \
        vppjni_register_field(&VPPJNI_FIELD_SYMBOL(cls, field)); \
    }
#define BIND_JAPI_BOOL_FIELD(cls, field) \
    BIND_JAPI_FIELD(cls, field, "Z"); \
    static void set_##cls##_##field(JNIEnv *env, jobject obj, jboolean value) \
    { \
        (*env)->SetBooleanField(env, obj, VPPJNI_FIELD_SYMBOL(cls, field).jfield, value); \
    }
#define BIND_JAPI_BYTE_FIELD(cls, field) \
    BIND_JAPI_FIELD(cls, field, "B"); \
    static void set_##cls##_##field(JNIEnv *env, jobject obj, jbyte value) \
    { \
        (*env)->SetByteField(env, obj, VPPJNI_FIELD_SYMBOL(cls, field).jfield, value); \
    }
#define BIND_JAPI_INT_FIELD(cls, field) \
    BIND_JAPI_FIELD(cls, field, "I"); \
    static void set_##cls##_##field(JNIEnv *env, jobject obj, jint value) \
    { \
        (*env)->SetIntField(env, obj, VPPJNI_FIELD_SYMBOL(cls, field).jfield, value); \
    }
#define BIND_JAPI_OBJ_FIELD(cls, field, sig) \
    BIND_JAPI_FIELD(cls, field, sig); \
    static void set_##cls##_##field(JNIEnv *env, jobject obj, jobject value) \
    { \
        (*env)->SetObjectField(env, obj, VPPJNI_FIELD_SYMBOL(cls, field).jfield, value); \
    }
#define BIND_JAPI_STRING_FIELD(cls, field) \
    BIND_JAPI_OBJ_FIELD(cls, field, "Ljava/lang/String;")

jobject vppjni_new_object(JNIEnv *env, const vppjni_class_t *ptr, va_list ap) __attribute__ ((visibility ("hidden")));
void vppjni_register_class(vppjni_class_t *ptr) __attribute__ ((visibility ("hidden")));
void vppjni_register_field(vppjni_field_t *ptr) __attribute__ ((visibility ("hidden")));
int vppjni_init(JNIEnv *env) __attribute__ ((visibility ("hidden")));
void vppjni_uninit(JNIEnv *env) __attribute__ ((visibility ("hidden")));

