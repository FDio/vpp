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
#include <jni.h>

#include "vppjni_env.h"

// Head of the class registration list.
static vppjni_class_t *class_head;
// Head of the class registration list.
static vppjni_field_t *field_head;

void vppjni_init_register_class(vppjni_class_t *ptr)
{
    vppjni_class_t **where = &class_head;
    while (*where != NULL) {
        where = &((*where)->next);
    }
    *where = ptr;
}

void vppjni_register_field(vppjni_field_t *ptr) {
    vppjni_field_t **where = &field_head;
    while (*where != NULL) {
        where = &((*where)->next);
    }
    *where = ptr;
}

jobject vppjni_init_new_object(JNIEnv *env, const vppjni_class_t *ptr, va_list ap) {
    jobject obj = (*env)->NewObjectV(env, ptr->jclass, ptr->jinit, ap);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        return NULL;
    }

    return obj;
}

int vppjni_env_init(JNIEnv *env)
{
    vppjni_class_t *cwlk;
    vppjni_field_t *fwlk;

    for (cwlk = class_head; cwlk != NULL; cwlk = cwlk->next) {
        jclass cls;
        jmethodID method;

        cls = (*env)->FindClass(env, cwlk->fqcn);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            vppjni_uninit(env);
            return JNI_ERR;
        }

        method = (*env)->GetMethodID(env, cls, "<init>", cwlk->init_sig);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            vppjni_uninit(env);
            return JNI_ERR;
        }

        cwlk->jclass = (*env)->NewGlobalRef(env, cls);
        if (cwlk->jclass == NULL) {
            vppjni_uninit(env);
            return JNI_ERR;
        }
        cwlk->jinit = method;
    }

    for (fwlk = field_head; fwlk != NULL; fwlk = fwlk->next) {
        fwlk->jfield = (*env)->GetFieldID(env, fwlk->clsref->jclass, fwlk->name, fwlk->type);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            vppjni_uninit(env);
            return JNI_ERR;
        }
    }

    return 0;
}

void vppjni_env_uninit(JNIEnv *env) {
    vppjni_class_t *cwlk;
    vppjni_field_t *fwlk;

    for (fwlk = field_head; fwlk != NULL; fwlk = fwlk->next) {
        fwlk->jfield = NULL;
    }

    for (cwlk = class_head; cwlk != NULL; cwlk = cwlk->next) {
        if (cwlk->jclass != NULL ) {
            (*env)->DeleteGlobalRef(env, cwlk->jclass);
        }

        cwlk->jclass = NULL;
        cwlk->jinit = NULL;
    }
}

