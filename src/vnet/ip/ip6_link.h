/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>

/**
 * IPv6 Configuration on an interface
 */

extern int ip6_link_enable (u32 sw_if_index,
			    const ip6_address_t * link_local_addr);
extern bool ip6_link_is_enabled (u32 sw_if_index);
extern int ip6_link_disable (u32 sw_if_index);

extern const ip6_address_t *ip6_get_link_local_address (u32 sw_if_index);

extern int ip6_link_set_local_address (u32 sw_if_index,
				       const ip6_address_t * address);
extern adj_index_t ip6_link_get_mcast_adj (u32 sw_if_index);

/**
 * Delegates for the interfaces
 *
 * delegates are a means for a external component to 'extend' the config
 * object by adding their own objects (aka delegates).
 */

/**
 * Callback functions for handling actions on the link
 */
typedef void (*ip6_link_enable_fn_t) (u32 sw_if_index);
typedef void (*ip6_link_disable_fn_t) (index_t ildi);
typedef void (*ip6_link_ll_change_fn_t) (u32 ildi, const ip6_address_t * a);
typedef void (*ip6_link_address_change_fn_t) (u32 ildi,
					      const ip6_address_t * a,
					      u8 address_oength);

typedef struct ip6_link_delegate_vft_t_
{
  ip6_link_enable_fn_t ildv_enable;
  ip6_link_disable_fn_t ildv_disable;
  ip6_link_ll_change_fn_t ildv_ll_change;
  ip6_link_address_change_fn_t ildv_addr_add;
  ip6_link_address_change_fn_t ildv_addr_del;
  format_function_t *ildv_format;
} ip6_link_delegate_vft_t;

typedef u32 ip6_link_delegate_id_t;


extern ip6_link_delegate_id_t ip6_link_delegate_register (const
							  ip6_link_delegate_vft_t
							  * vft);
extern index_t ip6_link_delegate_get (u32 sw_if_index,
				      ip6_link_delegate_id_t id);
extern bool ip6_link_delegate_update (u32 sw_if_index,
				      ip6_link_delegate_id_t id, index_t ii);
extern void ip6_link_delegate_remove (u32 sw_if_index,
				      ip6_link_delegate_id_t id, index_t ii);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
