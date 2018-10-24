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

/**
 * ACL Base Tracing
 *
 * Define a set of ACLs that a packet must match if it is to be traced
 * Run as a device input feature
 */
#ifndef __ABT_H__
#define __ABT_H__

#include <vnet/fib/fib_types.h>

extern int abt_attach(u32 sw_if_index,
                      fib_protocol_t fproto,
                      u32 *acl_indices);
extern int abt_detach(u32 sw_if_index,
                      fib_protocol_t fproto);

#endif
