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

void
ip_neighbor_clone (const ip_neighbor_t * ipn, ip_neighbor_t * clone)
{
  clib_memcpy (clone, ipn, sizeof (*ipn));

  clone->ipn_key = clib_mem_alloc (sizeof (ip_neighbor_key_t));
  clib_memcpy (clone->ipn_key, ipn->ipn_key, sizeof (ip_neighbor_key_t));
}

void
ip_neighbor_free (ip_neighbor_t * ipn)
{
  clib_mem_free (ipn->ipn_key);
}

u8 *
format_ip_neighbor_flags (u8 * s, va_list * args)
{
  ip_neighbor_flags_t flags = va_arg (*args, int);

#define _(a,b,c,d)                              \
  if (flags & IP_NEIGHBOR_FLAG_##a)             \
    s = format (s, "%s", d);
  foreach_ip_neighbor_flag
#undef _
    return s;
}

u8 *
format_ip_neighbor_key (u8 * s, va_list * va)
{
  ip_neighbor_key_t *key = va_arg (*va, ip_neighbor_key_t *);

  return (format (s, "[%U, %U]",
		  format_vnet_sw_if_index_name, vnet_get_main (),
		  key->ipnk_sw_if_index, format_ip_address, &key->ipnk_ip));
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
  f64 now = va_arg (*va, f64);
  index_t ipni = va_arg (*va, index_t);
  ip_neighbor_t *ipn;

  ipn = ip_neighbor_get (ipni);

  return (
    format (s, "%=12U%=40U%=6U%=20U%U", format_vlib_time, vlib_get_main (),
	    now - ipn->ipn_time_last_updated, format_ip_address,
	    &ipn->ipn_key->ipnk_ip, format_ip_neighbor_flags, ipn->ipn_flags,
	    format_mac_address_t, &ipn->ipn_mac, format_vnet_sw_if_index_name,
	    vnet_get_main (), ipn->ipn_key->ipnk_sw_if_index));
}

static void
ip_neighbor_alloc_one_ctr (ip_neighbor_counters_t *ctr, vlib_dir_t dir,
			   ip_neighbor_counter_type_t type, u32 sw_if_index)
{
  vlib_validate_simple_counter (&(ctr->ipnc[dir][type]), sw_if_index);
  vlib_zero_simple_counter (&(ctr->ipnc[dir][type]), sw_if_index);
}

void
ip_neighbor_alloc_ctr (ip_neighbor_counters_t *ctr, u32 sw_if_index)
{
  ip_neighbor_counter_type_t type;
  vlib_dir_t dir;

  FOREACH_VLIB_DIR (dir)
  {
    FOREACH_IP_NEIGHBOR_CTR (type)
    {
      ip_neighbor_alloc_one_ctr (ctr, dir, type, sw_if_index);
    }
  }
}

u8 *
format_ip_neighbor_counters (u8 *s, va_list *args)
{
  ip_neighbor_counters_t *ctr = va_arg (*args, ip_neighbor_counters_t *);
  u32 sw_if_index = va_arg (*args, u32);
  vlib_dir_t dir;

  FOREACH_VLIB_DIR (dir)
  {
    s = format (s, " %U:[", format_vlib_rx_tx, dir);

#define _(a, b)                                                               \
  s = format (s, "%s:%lld ", b,                                               \
	      vlib_get_simple_counter (&ctr->ipnc[dir][IP_NEIGHBOR_CTR_##a],  \
				       sw_if_index));
    foreach_ip_neighbor_counter_type
#undef _

      s = format (s, "]");
  }

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
