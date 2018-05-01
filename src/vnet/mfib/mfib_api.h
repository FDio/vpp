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

#ifndef __MFIB_API_H__
#define __MFIB_API_H__

#include <vnet/mfib/mfib_types.h>

/**
 * Forward declare the API type, no need to include the generated api headers
 */
struct _vl_api_mfib_path;

/**
 * Encode and decode functions from the API types to internal types
 */
extern void mfib_api_path_encode(const fib_route_path_t *in,
                                 struct _vl_api_mfib_path *out);
extern int mfib_api_path_decode(struct _vl_api_mfib_path *in,
                                fib_route_path_t *out);

extern int mfib_api_table_id_decode(fib_protocol_t fproto,
                                    u32 table_id,
                                    u32 *fib_index);

#endif /* __MFIB_API_H__ */
