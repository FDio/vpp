/*
 * ip_neighboor.h: ip neighbor generic services
 *
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

#include <vnet/ip-neighbor/ip_neighbor_types.h>

u8 *
format_ip_neighbor_flags (u8 * s, va_list * args)
{
  ip_neighbor_flags_t flags = va_arg (*args, int);

  if (flags & IP_NEIGHBOR_FLAG_STATIC)
    s = format (s, "S");

  if (flags & IP_NEIGHBOR_FLAG_DYNAMIC)
    s = format (s, "D");

  if (flags & IP_NEIGHBOR_FLAG_NO_FIB_ENTRY)
    s = format (s, "N");

  return s;
}


u8 *
format_ip_neighbor_key (u8 * s, va_list * va)
{
  ip_neighbor_key_t *key = va_arg (*va, ip_neighbor_key_t *);

  return (format (s, "[%U, %U]",
		  format_vnet_sw_if_index_name, vnet_get_main (),
		  key->ipnk_sw_if_index,
		  format_ip46_address, &key->ipnk_ip, key->ipnk_type));
}

u8 *
format_ip_neighbor_watcher (u8 * s, va_list * va)
{
  ip_neighbor_watcher_t *watcher = va_arg (*va, ip_neighbor_watcher_t *);

  return (format (s, "[pid:%d, client:%d]",
		  clib_host_to_net_u32 (watcher->ipw_pid),
		  clib_host_to_net_u32 (watcher->ipw_client)));
}

u8 *
format_ip_neighbor (u8 * s, va_list * va)
{
  index_t ipni = va_arg (*va, index_t);
  ip_neighbor_t *ipn;

  ipn = ip_neighbor_get (ipni);

  return (format (s, "%=12U%=40U%=6U%=20U%U",
		  format_vlib_time, vlib_get_main (),
		  ipn->ipn_time_last_updated,
		  format_ip46_address, &ipn->ipn_key->ipnk_ip, IP46_TYPE_ANY,
		  format_ip_neighbor_flags, ipn->ipn_flags,
		  format_mac_address_t, &ipn->ipn_mac,
		  format_vnet_sw_if_index_name, vnet_get_main (),
		  ipn->ipn_key->ipnk_sw_if_index));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
