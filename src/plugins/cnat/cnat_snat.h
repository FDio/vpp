/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __CNAT_SNAT_H__
#define __CNAT_SNAT_H__

#include <cnat/cnat_types.h>
#include <cnat/cnat_session.h>

/* function to use to decide whether to snat connections in the output
   feature */
typedef void (*cnat_snat_policy_t) (vlib_main_t *vm, vlib_buffer_t *b,
				    cnat_session_t *session,
				    cnat_node_ctx_t *ctx, u8 *do_snat);

typedef struct cnat_snat_policy_main_t_
{
  /* SNAT policy for the output feature node */
  cnat_snat_policy_t snat_policy;

} cnat_snat_policy_main_t;

extern cnat_snat_policy_main_t cnat_snat_policy_main;

extern void cnat_set_snat (ip4_address_t * ip4, ip6_address_t * ip6,
			   u32 sw_if_index);
extern int cnat_add_snat_prefix (ip_prefix_t * pfx);
extern int cnat_del_snat_prefix (ip_prefix_t * pfx);
extern void cnat_set_snat_policy (cnat_snat_policy_t fp);

int cnat_search_snat_prefix (ip46_address_t * addr, ip_address_family_t af);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
