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

#ifndef included_manual_fns_h
#define included_manual_fns_h

#include <vnet/ip/format.h>
#include <vnet/ethernet/ethernet.h>

#define vl_endianfun            /* define message structures */
#include <acl/acl_types.api.h>
#undef vl_endianfun

/* Macro to finish up custom dump fns */
#define PRINT_S \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);

static inline void
vl_api_acl_rule_t_array_endian(vl_api_acl_rule_t *rules, u32 count)
{
  u32 i;
  for(i=0; i<count; i++) {
    vl_api_acl_rule_t_endian (&rules[i]);
  }
}

static inline void
vl_api_macip_acl_rule_t_array_endian(vl_api_macip_acl_rule_t *rules, u32 count)
{
  u32 i;
  for(i=0; i<count; i++) {
    vl_api_macip_acl_rule_t_endian (&rules[i]);
  }
}

#endif /* included_manual_fns_h */
