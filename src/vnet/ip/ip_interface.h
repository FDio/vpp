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

/**
 * @file
 * @brief IP prefix management on interfaces
 */

#ifndef included_ip_interface_h
#define included_ip_interface_h

#include <vnet/ip/lookup.h>

clib_error_t *ip_interface_address_add (ip_lookup_main_t * lm,
					u32 sw_if_index,
					void *address,
					u32 address_length,
					u32 * result_index);
clib_error_t *ip_interface_address_del (ip_lookup_main_t * lm,
					vnet_main_t * vnm,
					u32 addr_index, void *address,
					u32 address_length, u32 sw_if_index);
void *ip_interface_get_first_ip (u32 sw_if_index, u8 is_ip4);
void ip_interface_address_mark (void);
void ip_interface_address_sweep (void);
u32 ip_interface_address_find (ip_lookup_main_t * lm,
			       void *addr_fib, u32 address_length);
u8 ip_interface_has_address (u32 sw_if_index, ip46_address_t * ip, u8 is_ip4);

always_inline void *
ip_interface_address_get_address (ip_lookup_main_t * lm,
				  ip_interface_address_t * a)
{
  return mhash_key_to_mem (&lm->address_to_if_address_index, a->address_key);
}

always_inline ip_interface_prefix_t *
ip_get_interface_prefix (ip_lookup_main_t * lm, ip_interface_prefix_key_t * k)
{
  uword *p = mhash_get (&lm->prefix_to_if_prefix_index, k);
  return p ? pool_elt_at_index (lm->if_prefix_pool, p[0]) : 0;
}

/* *INDENT-OFF* */
#define foreach_ip_interface_address(lm,a,sw_if_index,loop,body)        \
do {                                                                    \
    vnet_main_t *_vnm = vnet_get_main();                                \
    u32 _sw_if_index = sw_if_index;                                     \
    vnet_sw_interface_t *_swif;                                         \
    _swif = vnet_get_sw_interface (_vnm, _sw_if_index);                 \
                                                                        \
    /*                                                                  \
     * Loop => honor unnumbered interface addressing.                   \
     */                                                                 \
    if (_swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)               \
      {                                                                 \
        if (loop)                                                       \
          _sw_if_index = _swif->unnumbered_sw_if_index;                 \
        else                                                            \
          /* the interface is unnumbered, by the caller does not want   \
           * unnumbered interfaces considered/honoured */               \
          break;                                                        \
      }                                                                 \
    u32 _ia = ((vec_len((lm)->if_address_pool_index_by_sw_if_index)     \
                > (_sw_if_index)) ?                                     \
               vec_elt ((lm)->if_address_pool_index_by_sw_if_index,     \
                        (_sw_if_index)) :                               \
               (u32)~0);                                                \
    ip_interface_address_t * _a;                                        \
    while (_ia != ~0)                                                   \
    {                                                                   \
        _a = pool_elt_at_index ((lm)->if_address_pool, _ia);            \
        _ia = _a->next_this_sw_interface;                               \
        (a) = _a;                                                       \
        body;                                                           \
    }                                                                   \
} while (0)
/* *INDENT-ON* */

#endif /* included_ip_interface_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
