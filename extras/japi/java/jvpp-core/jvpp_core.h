/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef VPP_JVPP_CORE_H
#define VPP_JVPP_CORE_H

#include <vlibapi/api_types.h>

#endif //VPP_JVPP_CORE_H

// /**
// * Host to network byte order conversion for string type. Converts String in Java to VPP string type.
// * typedef struct
// * {
// *   u32 length;
// *   u8 buf[0];
// * } __attribute__ ((packed)) vl_api_string_t;
// */
static  void _host_to_net_string(JNIEnv * env, jstring javaString, vl_api_string_t * vl_api_string);


//
// /**
// * Network to host byte order conversion for string type. Converts VPP string type to String in Java
// * typedef struct
// * {
// *   u32 length;
// *   u8 buf[0];
// * } __attribute__ ((packed)) vl_api_string_t;
// */
static jstring _net_to_host_string(JNIEnv * env, const vl_api_string_t * _net);


//
// /**
// * Returns the length of jstring as size_t
// */
static size_t jstr_length(JNIEnv *env, jstring string);
