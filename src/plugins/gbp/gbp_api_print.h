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

#ifndef __GBP_API_PRINT_H__
#define __GBP_API_PRINT_H__

/* Macro to finish up custom dump fns */
#define PRINT_S \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);

static inline void *
vl_api_gbp_bridge_domain_add_t_print (vl_api_gbp_bridge_domain_add_t * a,
				      void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_bridge_domain_add ");
  s = format (s, "flags %d", ntohl (a->bd.flags));
  s = format (s, "uu-fwd %d", ntohl (a->bd.uu_fwd_sw_if_index));
  s = format (s, "bvi %d", ntohl (a->bd.bvi_sw_if_index));
  s = format (s, "bm-flood %d", ntohl (a->bd.bm_flood_sw_if_index));

  s = format (0, "\n");

  PRINT_S;

  return handle;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __GBP_API_PRINT_H__ */
