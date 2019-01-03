/*
 *------------------------------------------------------------------
 * map_api.c - vnet map api
 *
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
 *------------------------------------------------------------------
 */

#include <map/map.h>
#include <map/map_msg_enum.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>

#define vl_typedefs		/* define message structures */
#include <map/map_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <map/map_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <map/map_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <map/map_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE mm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_map_add_domain_t_handler (vl_api_map_add_domain_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_add_domain_reply_t *rmp;
  int rv = 0;
  u32 index;
  u8 flags = 0;

  rv =
    map_create_domain ((ip4_address_t *) & mp->ip4_prefix.prefix,
		       mp->ip4_prefix.len,
		       (ip6_address_t *) & mp->ip6_prefix.prefix,
		       mp->ip6_prefix.len,
		       (ip6_address_t *) & mp->ip6_src.prefix,
		       mp->ip6_src.len, mp->ea_bits_len, mp->psid_offset,
		       mp->psid_length, &index, ntohs (mp->mtu), flags);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MAP_ADD_DOMAIN_REPLY,
  ({
    rmp->index = ntohl(index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_del_domain_t_handler (vl_api_map_del_domain_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv = map_delete_domain (ntohl (mp->index));

  REPLY_MACRO (VL_API_MAP_DEL_DOMAIN_REPLY);
}

static void
vl_api_map_add_del_rule_t_handler (vl_api_map_add_del_rule_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv =
    map_add_del_psid (ntohl (mp->index), ntohs (mp->psid),
		      (ip6_address_t *) & mp->ip6_dst, mp->is_add);

  REPLY_MACRO (VL_API_MAP_ADD_DEL_RULE_REPLY);
}

static void
vl_api_map_domain_dump_t_handler (vl_api_map_domain_dump_t * mp)
{
  vl_api_map_domain_details_t *rmp;
  map_main_t *mm = &map_main;
  map_domain_t *d;
  vl_api_registration_t *reg;

  if (pool_elts (mm->domains) == 0)
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach(d, mm->domains,
  ({
    /* Make sure every field is initiated (or don't skip the clib_memset()) */
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = htons(VL_API_MAP_DOMAIN_DETAILS + mm->msg_id_base);
    rmp->context = mp->context;
    rmp->domain_index = htonl(d - mm->domains);
    clib_memcpy(&rmp->ip6_prefix.prefix, &d->ip6_prefix, sizeof(rmp->ip6_prefix.prefix));
    clib_memcpy(&rmp->ip4_prefix.prefix, &d->ip4_prefix, sizeof(rmp->ip4_prefix.prefix));
    clib_memcpy(&rmp->ip6_src.prefix, &d->ip6_src, sizeof(rmp->ip6_src.prefix));
    rmp->ip6_prefix.len = d->ip6_prefix_len;
    rmp->ip4_prefix.len = d->ip4_prefix_len;
    rmp->ip6_src.len = d->ip6_src_len;
    rmp->ea_bits_len = d->ea_bits_len;
    rmp->psid_offset = d->psid_offset;
    rmp->psid_length = d->psid_length;
    rmp->flags = d->flags;
    rmp->mtu = htons(d->mtu);

    vl_api_send_msg (reg, (u8 *) rmp);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_rule_dump_t_handler (vl_api_map_rule_dump_t * mp)
{
  vl_api_registration_t *reg;
  u16 i;
  ip6_address_t dst;
  vl_api_map_rule_details_t *rmp;
  map_main_t *mm = &map_main;
  u32 domain_index = ntohl (mp->domain_index);
  map_domain_t *d;

  if (pool_elts (mm->domains) == 0)
    return;

  d = pool_elt_at_index (mm->domains, domain_index);
  if (!d || !d->rules)
    {
      return;
    }

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  for (i = 0; i < (0x1 << d->psid_length); i++)
    {
      dst = d->rules[i];
      if (dst.as_u64[0] == 0 && dst.as_u64[1] == 0)
	{
	  continue;
	}
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = ntohs (VL_API_MAP_RULE_DETAILS + mm->msg_id_base);
      rmp->psid = htons (i);
      clib_memcpy (&rmp->ip6_dst, &dst, sizeof (rmp->ip6_dst));
      rmp->context = mp->context;
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_map_summary_stats_t_handler (vl_api_map_summary_stats_t * mp)
{
  vl_api_map_summary_stats_reply_t *rmp;
  vlib_combined_counter_main_t *cm;
  vlib_counter_t v;
  int i, which;
  u64 total_pkts[VLIB_N_RX_TX];
  u64 total_bytes[VLIB_N_RX_TX];
  map_main_t *mm = &map_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_MAP_SUMMARY_STATS_REPLY + mm->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = 0;

  if (pool_elts (mm->domains) == 0)
    {
      rmp->retval = -1;
      goto out;
    }

  clib_memset (total_pkts, 0, sizeof (total_pkts));
  clib_memset (total_bytes, 0, sizeof (total_bytes));

  map_domain_counter_lock (mm);
  vec_foreach (cm, mm->domain_counters)
  {
    which = cm - mm->domain_counters;

    for (i = 0; i < vlib_combined_counter_n_counters (cm); i++)
      {
	vlib_get_combined_counter (cm, i, &v);
	total_pkts[which] += v.packets;
	total_bytes[which] += v.bytes;
      }
  }

  map_domain_counter_unlock (mm);

  /* Note: in network byte order! */
  rmp->total_pkts[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (total_pkts[MAP_DOMAIN_COUNTER_RX]);
  rmp->total_bytes[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (total_bytes[MAP_DOMAIN_COUNTER_RX]);
  rmp->total_pkts[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (total_pkts[MAP_DOMAIN_COUNTER_TX]);
  rmp->total_bytes[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (total_bytes[MAP_DOMAIN_COUNTER_TX]);
  rmp->total_bindings = clib_host_to_net_u64 (pool_elts (mm->domains));
  rmp->total_ip4_fragments = 0;	// Not yet implemented. Should be a simple counter.
  rmp->total_security_check[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (map_error_counter_get
			  (ip4_map_node.index, MAP_ERROR_ENCAP_SEC_CHECK));
  rmp->total_security_check[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (map_error_counter_get
			  (ip4_map_node.index, MAP_ERROR_DECAP_SEC_CHECK));

out:
  vl_api_send_msg (reg, (u8 *) rmp);
}


int
map_param_set_fragmentation (bool inner, bool ignore_df)
{
  map_main_t *mm = &map_main;

  mm->frag_inner = ! !inner;
  mm->frag_ignore_df = ! !ignore_df;

  return 0;
}

static void
  vl_api_map_param_set_fragmentation_t_handler
  (vl_api_map_param_set_fragmentation_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_set_fragmentation_reply_t *rmp;
  int rv = 0;

  rv = map_param_set_fragmentation (mp->inner, mp->ignore_df);

  REPLY_MACRO (VL_API_MAP_PARAM_SET_FRAGMENTATION_REPLY);
}


int
map_param_set_icmp (ip4_address_t * icmp_src_address)
{
  map_main_t *mm = &map_main;

  if (icmp_src_address == 0)
    return -1;

  mm->icmp4_src_address = *icmp_src_address;

  return 0;
}


static void
vl_api_map_param_set_icmp_t_handler (vl_api_map_param_set_icmp_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_set_icmp_reply_t *rmp;
  int rv;

  rv = map_param_set_icmp ((ip4_address_t *) & mp->ip4_err_relay_src);

  REPLY_MACRO (VL_API_MAP_PARAM_SET_ICMP_REPLY);
}


int
map_param_set_icmp6 (u8 enable_unreachable)
{
  map_main_t *mm = &map_main;

  mm->icmp6_enabled = ! !enable_unreachable;

  return 0;
}

static void
vl_api_map_param_set_icmp6_t_handler (vl_api_map_param_set_icmp6_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_set_icmp6_reply_t *rmp;
  int rv;

  rv = map_param_set_icmp6 (mp->enable_unreachable);

  REPLY_MACRO (VL_API_MAP_PARAM_SET_ICMP6_REPLY);
}


static void
  vl_api_map_param_add_del_pre_resolve_t_handler
  (vl_api_map_param_add_del_pre_resolve_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_add_del_pre_resolve_reply_t *rmp;
  int rv = 0;

  map_pre_resolve ((ip4_address_t *) & mp->ip4_nh_address,
		   (ip6_address_t *) & mp->ip6_nh_address, !mp->is_add);

  REPLY_MACRO (VL_API_MAP_PARAM_ADD_DEL_PRE_RESOLVE_REPLY);
}


int
map_param_set_reassembly (bool is_ipv6,
			  u16 lifetime_ms,
			  u16 pool_size,
			  u32 buffers,
			  f64 ht_ratio, u32 * reass, u32 * packets)
{
  u32 ps_reass = 0, ps_packets = 0;
  u32 ht_reass = 0, ht_packets = 0;

  if (is_ipv6)
    {
      if (pool_size != (u16) ~ 0)
	{
	  if (pool_size > MAP_IP6_REASS_CONF_POOL_SIZE_MAX)
	    return MAP_ERR_BAD_POOL_SIZE;
	  if (map_ip6_reass_conf_pool_size
	      (pool_size, &ps_reass, &ps_packets))
	    return MAP_ERR_BAD_POOL_SIZE;
	}

      if (ht_ratio != (MAP_IP6_REASS_CONF_HT_RATIO_MAX + 1))
	{
	  if (ht_ratio > MAP_IP6_REASS_CONF_HT_RATIO_MAX)
	    return MAP_ERR_BAD_HT_RATIO;
	  if (map_ip6_reass_conf_ht_ratio (ht_ratio, &ht_reass, &ht_packets))
	    return MAP_ERR_BAD_HT_RATIO;
	}

      if (lifetime_ms != (u16) ~ 0)
	{
	  if (lifetime_ms > MAP_IP6_REASS_CONF_LIFETIME_MAX)
	    return MAP_ERR_BAD_LIFETIME;
	  if (map_ip6_reass_conf_lifetime (lifetime_ms))
	    return MAP_ERR_BAD_LIFETIME;
	}

      if (buffers != ~0)
	{
	  if (buffers > MAP_IP6_REASS_CONF_BUFFERS_MAX)
	    return MAP_ERR_BAD_BUFFERS;
	  if (map_ip6_reass_conf_buffers (buffers))
	    return MAP_ERR_BAD_BUFFERS;
	}

      if (map_main.ip6_reass_conf_buffers >
	  map_main.ip6_reass_conf_pool_size *
	  MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY)
	{
	  return MAP_ERR_BAD_BUFFERS_TOO_LARGE;
	}
    }
  else
    {
      if (pool_size != (u16) ~ 0)
	{
	  if (pool_size > MAP_IP4_REASS_CONF_POOL_SIZE_MAX)
	    return MAP_ERR_BAD_POOL_SIZE;
	  if (map_ip4_reass_conf_pool_size
	      (pool_size, &ps_reass, &ps_packets))
	    return MAP_ERR_BAD_POOL_SIZE;
	}

      if (ht_ratio != (MAP_IP4_REASS_CONF_HT_RATIO_MAX + 1))
	{
	  if (ht_ratio > MAP_IP4_REASS_CONF_HT_RATIO_MAX)
	    return MAP_ERR_BAD_HT_RATIO;
	  if (map_ip4_reass_conf_ht_ratio (ht_ratio, &ht_reass, &ht_packets))
	    return MAP_ERR_BAD_HT_RATIO;
	}

      if (lifetime_ms != (u16) ~ 0)
	{
	  if (lifetime_ms > MAP_IP4_REASS_CONF_LIFETIME_MAX)
	    return MAP_ERR_BAD_LIFETIME;
	  if (map_ip4_reass_conf_lifetime (lifetime_ms))
	    return MAP_ERR_BAD_LIFETIME;
	}

      if (buffers != ~0)
	{
	  if (buffers > MAP_IP4_REASS_CONF_BUFFERS_MAX)
	    return MAP_ERR_BAD_BUFFERS;
	  if (map_ip4_reass_conf_buffers (buffers))
	    return MAP_ERR_BAD_BUFFERS;
	}

      if (map_main.ip4_reass_conf_buffers >
	  map_main.ip4_reass_conf_pool_size *
	  MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY)
	{
	  return MAP_ERR_BAD_BUFFERS_TOO_LARGE;
	}
    }

  if (reass)
    *reass = ps_reass + ht_reass;

  if (packets)
    *packets = ps_packets + ht_packets;

  return 0;
}


static void
  vl_api_map_param_set_reassembly_t_handler
  (vl_api_map_param_set_reassembly_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_set_reassembly_reply_t *rmp;
  u32 reass = 0, packets = 0;
  int rv;
  f64 ht_ratio;

  ht_ratio = (f64) clib_net_to_host_u64 (mp->ht_ratio);
  if (ht_ratio == ~0)
    ht_ratio = MAP_IP6_REASS_CONF_HT_RATIO_MAX + 1;

  rv = map_param_set_reassembly (mp->is_ip6,
				 clib_net_to_host_u16 (mp->lifetime_ms),
				 clib_net_to_host_u16 (mp->pool_size),
				 clib_net_to_host_u32 (mp->buffers),
				 ht_ratio, &reass, &packets);

  /*
   * FIXME: Should the lost reass and packet counts be returned in the API?
   */

  REPLY_MACRO (VL_API_MAP_PARAM_SET_REASSEMBLY_REPLY);
}


int
map_param_set_security_check (bool enable, bool fragments)
{
  map_main_t *mm = &map_main;

  mm->sec_check = ! !enable;
  mm->sec_check_frag = ! !fragments;

  return 0;
}

static void
  vl_api_map_param_set_security_check_t_handler
  (vl_api_map_param_set_security_check_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_set_security_check_reply_t *rmp;
  int rv;

  rv = map_param_set_security_check (mp->enable, mp->fragments);

  REPLY_MACRO (VL_API_MAP_PARAM_SET_SECURITY_CHECK_REPLY);
}


int
map_param_set_traffic_class (bool copy, u8 tc)
{
  map_main_t *mm = &map_main;

  mm->tc_copy = ! !copy;
  mm->tc = tc;

  return 0;
}

static void
  vl_api_map_param_set_traffic_class_t_handler
  (vl_api_map_param_set_traffic_class_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_set_traffic_class_reply_t *rmp;
  int rv;

  rv = map_param_set_traffic_class (mp->copy, mp->class);

  REPLY_MACRO (VL_API_MAP_PARAM_SET_TRAFFIC_CLASS_REPLY);
}


int
map_param_set_tcp (u16 tcp_mss)
{
  map_main_t *mm = &map_main;

  mm->tcp_mss = tcp_mss;

  return 0;
}


static void
vl_api_map_param_set_tcp_t_handler (vl_api_map_param_set_tcp_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_set_tcp_reply_t *rmp;
  int rv = 0;

  map_param_set_tcp (ntohs (mp->tcp_mss));
  REPLY_MACRO (VL_API_MAP_PARAM_SET_TCP_REPLY);
}


static void
vl_api_map_param_get_t_handler (vl_api_map_param_get_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_param_get_reply_t *rmp;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_MAP_PARAM_GET_REPLY + mm->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = 0;

  rmp->frag_inner = mm->frag_inner;
  rmp->frag_ignore_df = mm->frag_ignore_df;

  clib_memcpy (&rmp->icmp_ip4_err_relay_src,
	       &mm->icmp4_src_address, sizeof (rmp->icmp_ip4_err_relay_src));

  rmp->icmp6_enable_unreachable = mm->icmp6_enabled;

  /*
   * FIXME: How are these addresses re-extracted from the FIB?
   * Or should a local map_main copy be kept?
   */
  clib_memset (&rmp->ip4_nh_address, 0, sizeof (rmp->ip4_nh_address));
  clib_memset (&rmp->ip6_nh_address, 0, sizeof (rmp->ip6_nh_address));

  rmp->ip4_lifetime_ms =
    clib_net_to_host_u16 (mm->ip4_reass_conf_lifetime_ms);
  rmp->ip4_pool_size = clib_net_to_host_u16 (mm->ip4_reass_conf_pool_size);
  rmp->ip4_buffers = clib_net_to_host_u32 (mm->ip4_reass_conf_buffers);
  rmp->ip4_ht_ratio =
    clib_net_to_host_u64 ((u64) mm->ip4_reass_conf_ht_ratio);

  rmp->ip6_lifetime_ms =
    clib_net_to_host_u16 (mm->ip6_reass_conf_lifetime_ms);
  rmp->ip6_pool_size = clib_net_to_host_u16 (mm->ip6_reass_conf_pool_size);
  rmp->ip6_buffers = clib_net_to_host_u32 (mm->ip6_reass_conf_buffers);
  rmp->ip6_ht_ratio =
    clib_net_to_host_u64 ((u64) mm->ip6_reass_conf_ht_ratio);

  rmp->sec_check_enable = mm->sec_check;
  rmp->sec_check_fragments = mm->sec_check_frag;

  rmp->tc_copy = mm->tc_copy;
  rmp->tc_class = mm->tc;

  vl_api_send_msg (reg, (u8 *) rmp);
}


int
map_if_enable_disable (bool is_enable, u32 sw_if_index, bool is_translation)
{
  map_main_t *mm = &map_main;

  is_enable = ! !is_enable;

  if (is_translation == false)
    {
      if (mm->is_encap_enabled != is_enable)
	{
	  vnet_feature_enable_disable ("ip4-unicast", "ip4-map", sw_if_index,
				       is_enable ? 1 : 0, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast", "ip6-map", sw_if_index,
				       is_enable ? 1 : 0, 0, 0);
	  mm->is_encap_enabled = is_enable;
	}
    }
  else
    {
      if (mm->is_translation_enabled != is_enable)
	{
	  vnet_feature_enable_disable ("ip4-unicast", "ip4-map-t",
				       sw_if_index, is_enable ? 1 : 0, 0, 0);
	  vnet_feature_enable_disable ("ip6-unicast", "ip6-map-t",
				       sw_if_index, is_enable ? 1 : 0, 0, 0);
	  mm->is_translation_enabled = is_enable;
	}
    }
  return 0;
}


static void
vl_api_map_if_enable_disable_t_handler (vl_api_map_if_enable_disable_t * mp)
{
  map_main_t *mm = &map_main;
  vl_api_map_if_enable_disable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    map_if_enable_disable (mp->is_enable, htonl (mp->sw_if_index),
			   mp->is_translation);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_MAP_IF_ENABLE_DISABLE_REPLY);
}


#define foreach_map_plugin_api_msg		\
_(MAP_ADD_DOMAIN, map_add_domain)		\
_(MAP_DEL_DOMAIN, map_del_domain)		\
_(MAP_ADD_DEL_RULE, map_add_del_rule)		\
_(MAP_DOMAIN_DUMP, map_domain_dump)		\
_(MAP_RULE_DUMP, map_rule_dump)			\
_(MAP_IF_ENABLE_DISABLE, map_if_enable_disable)	\
_(MAP_SUMMARY_STATS, map_summary_stats)		\
_(MAP_PARAM_SET_FRAGMENTATION, map_param_set_fragmentation)	\
_(MAP_PARAM_SET_ICMP, map_param_set_icmp)	\
_(MAP_PARAM_SET_ICMP6, map_param_set_icmp6)	\
_(MAP_PARAM_ADD_DEL_PRE_RESOLVE, map_param_add_del_pre_resolve)	\
_(MAP_PARAM_SET_REASSEMBLY, map_param_set_reassembly)		\
_(MAP_PARAM_SET_SECURITY_CHECK, map_param_set_security_check)	\
_(MAP_PARAM_SET_TRAFFIC_CLASS, map_param_set_traffic_class)	\
_(MAP_PARAM_SET_TCP, map_param_set_tcp)	\
_(MAP_PARAM_GET, map_param_get)

#define vl_msg_name_crc_list
#include <map/map_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (map_main_t * mm, api_main_t * am)
{
#define _(id,n,crc)							\
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_map;
#undef _
}

/* Set up the API message handling tables */
clib_error_t *
map_plugin_api_hookup (vlib_main_t * vm)
{
  map_main_t *mm = &map_main;
  u8 *name = format (0, "map_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base =
    vl_msg_api_get_msg_ids ((char *) name, VL_MSG_FIRST_AVAILABLE);
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_map_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (mm, &api_main);

  vec_free (name);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
