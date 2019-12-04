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

#ifndef __FIB_API_H__
#define __FIB_API_H__

#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/ip/ip.api_types.h>

/**
 * Forward declare the API type, no need to include the generated api headers
 */
struct _vl_api_fib_path;
struct _vl_api_fib_prefix;

/**
 * Encode and decode functions from the API types to internal types
 */
extern void fib_api_path_encode(const fib_route_path_t * api_rpath,
                                vl_api_fib_path_t *out);
extern int fib_api_path_decode(vl_api_fib_path_t *in,
                               fib_route_path_t *out);

extern int fib_api_table_id_decode(fib_protocol_t fproto,
                                   u32 table_id,
                                   u32 *fib_index);

/**
 * Adding routes from the API
 */
extern int fib_api_route_add_del (u8 is_add,
                                  u8 is_multipath,
                                  u32 fib_index,
                                  const fib_prefix_t * prefix,
                                  fib_source_t src,
                                  fib_entry_flag_t entry_flags,
                                  fib_route_path_t *rpaths);

extern u8* format_vl_api_fib_path(u8 * s, va_list * args);


extern int fib_proto_from_api_address_family (vl_api_address_family_t af, fib_protocol_t *out);
extern vl_api_address_family_t fib_proto_to_api_address_family (fib_protocol_t fproto);

#endif /* __FIB_API_H__ */
