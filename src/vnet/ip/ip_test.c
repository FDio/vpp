/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp/api/types.h>
#include <vnet/mpls/packet.h>
#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base ip_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip.api_types.h>
#include <vlibmemory/vlib.api_types.h>

#define vl_endianfun /* define message structures */
#include <vnet/ip/ip.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <vnet/ip/ip.api.h>
#undef vl_calcsizefun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} ip_test_main_t;

static ip_test_main_t ip_test_main;

static int
api_ip_route_add_del_v2 (vat_main_t *vam)
{
  return -1;
}

static void
set_ip4_address (vl_api_address_t *a, u32 v)
{
  if (a->af == ADDRESS_IP4)
    {
      ip4_address_t *i = (ip4_address_t *) &a->un.ip4;
      i->as_u32 = v;
    }
}

static void
increment_v4_address (vl_api_ip4_address_t *i)
{
  ip4_address_t *a = (ip4_address_t *) i;
  u32 v;

  v = ntohl (a->as_u32) + 1;
  a->as_u32 = ntohl (v);
}

static void
increment_v6_address (vl_api_ip6_address_t *i)
{
  ip6_address_t *a = (ip6_address_t *) i;
  u64 v0, v1;

  v0 = clib_net_to_host_u64 (a->as_u64[0]);
  v1 = clib_net_to_host_u64 (a->as_u64[1]);

  v1 += 1;
  if (v1 == 0)
    v0 += 1;
  a->as_u64[0] = clib_net_to_host_u64 (v0);
  a->as_u64[1] = clib_net_to_host_u64 (v1);
}

static void
increment_address (vl_api_address_t *a)
{
  if (a->af == ADDRESS_IP4)
    increment_v4_address (&a->un.ip4);
  else if (a->af == ADDRESS_IP6)
    increment_v6_address (&a->un.ip6);
}

static uword
unformat_fib_path (unformat_input_t *input, va_list *args)
{
  vat_main_t *vam = va_arg (*args, vat_main_t *);
  vl_api_fib_path_t *path = va_arg (*args, vl_api_fib_path_t *);
  u32 weight, preference;
  mpls_label_t out_label;

  clib_memset (path, 0, sizeof (*path));
  path->weight = 1;
  path->sw_if_index = ~0;
  path->rpf_id = ~0;
  path->n_labels = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U %U", unformat_vl_api_ip4_address,
		    &path->nh.address.ip4, api_unformat_sw_if_index, vam,
		    &path->sw_if_index))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "%U %U", unformat_vl_api_ip6_address,
			 &path->nh.address.ip6, api_unformat_sw_if_index, vam,
			 &path->sw_if_index))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "weight %u", &weight))
	{
	  path->weight = weight;
	}
      else if (unformat (input, "preference %u", &preference))
	{
	  path->preference = preference;
	}
      else if (unformat (input, "%U next-hop-table %d",
			 unformat_vl_api_ip4_address, &path->nh.address.ip4,
			 &path->table_id))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "%U next-hop-table %d",
			 unformat_vl_api_ip6_address, &path->nh.address.ip6,
			 &path->table_id))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "%U", unformat_vl_api_ip4_address,
			 &path->nh.address.ip4))
	{
	  /*
	   * the recursive next-hops are by default in the default table
	   */
	  path->table_id = 0;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "%U", unformat_vl_api_ip6_address,
			 &path->nh.address.ip6))
	{
	  /*
	   * the recursive next-hops are by default in the default table
	   */
	  path->table_id = 0;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "resolve-via-host"))
	{
	  path->flags |= FIB_API_PATH_FLAG_RESOLVE_VIA_HOST;
	}
      else if (unformat (input, "resolve-via-attached"))
	{
	  path->flags |= FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED;
	}
      else if (unformat (input, "ip4-lookup-in-table %d", &path->table_id))
	{
	  path->type = FIB_API_PATH_TYPE_LOCAL;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP4;
	}
      else if (unformat (input, "ip6-lookup-in-table %d", &path->table_id))
	{
	  path->type = FIB_API_PATH_TYPE_LOCAL;
	  path->sw_if_index = ~0;
	  path->proto = FIB_API_PATH_NH_PROTO_IP6;
	}
      else if (unformat (input, "sw_if_index %d", &path->sw_if_index))
	;
      else if (unformat (input, "via-label %d", &path->nh.via_label))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_MPLS;
	  path->sw_if_index = ~0;
	}
      else if (unformat (input, "l2-input-on %d", &path->sw_if_index))
	{
	  path->proto = FIB_API_PATH_NH_PROTO_ETHERNET;
	  path->type = FIB_API_PATH_TYPE_INTERFACE_RX;
	}
      else if (unformat (input, "local"))
	{
	  path->type = FIB_API_PATH_TYPE_LOCAL;
	}
      else if (unformat (input, "out-labels"))
	{
	  while (unformat (input, "%d", &out_label))
	    {
	      path->label_stack[path->n_labels].label = out_label;
	      path->label_stack[path->n_labels].is_uniform = 0;
	      path->label_stack[path->n_labels].ttl = 64;
	      path->n_labels++;
	    }
	}
      else if (unformat (input, "via"))
	{
	  /* new path, back up and return */
	  unformat_put_input (input);
	  unformat_put_input (input);
	  unformat_put_input (input);
	  unformat_put_input (input);
	  break;
	}
      else
	{
	  return (0);
	}
    }

  path->proto = ntohl (path->proto);
  path->type = ntohl (path->type);
  path->flags = ntohl (path->flags);
  path->table_id = ntohl (path->table_id);
  path->sw_if_index = ntohl (path->sw_if_index);

  return (1);
}

static int
api_ip_route_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_route_add_del_t *mp;
  u32 vrf_id = 0;
  u8 is_add = 1;
  u8 is_multipath = 0;
  u8 prefix_set = 0;
  u8 path_count = 0;
  vl_api_prefix_t pfx = {};
  vl_api_fib_path_t paths[8];
  int count = 1;
  int j;
  f64 before = 0;
  u32 random_add_del = 0;
  u32 *random_vector = 0;
  u32 random_seed = 0xdeaddabe;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vl_api_prefix, &pfx))
	prefix_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "count %d", &count))
	;
      else if (unformat (i, "random"))
	random_add_del = 1;
      else if (unformat (i, "multipath"))
	is_multipath = 1;
      else if (unformat (i, "seed %d", &random_seed))
	;
      else if (unformat (i, "via %U", unformat_fib_path, vam,
			 &paths[path_count]))
	{
	  path_count++;
	  if (8 == path_count)
	    {
	      errmsg ("max 8 paths");
	      return -99;
	    }
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!path_count)
    {
      errmsg ("specify a path; via ...");
      return -99;
    }
  if (prefix_set == 0)
    {
      errmsg ("missing prefix");
      return -99;
    }

  /* Generate a pile of unique, random routes */
  if (random_add_del)
    {
      ip4_address_t *i = (ip4_address_t *) &paths[0].nh.address.ip4;
      u32 this_random_address;
      uword *random_hash;

      random_hash = hash_create (count, sizeof (uword));

      hash_set (random_hash, i->as_u32, 1);
      for (j = 0; j <= count; j++)
	{
	  do
	    {
	      this_random_address = random_u32 (&random_seed);
	      this_random_address = clib_host_to_net_u32 (this_random_address);
	    }
	  while (hash_get (random_hash, this_random_address));
	  vec_add1 (random_vector, this_random_address);
	  hash_set (random_hash, this_random_address, 1);
	}
      hash_free (random_hash);
      set_ip4_address (&pfx.address, random_vector[0]);
    }

  if (count > 1)
    {
      /* Turn on async mode */
      vam->async_mode = 1;
      vam->async_errors = 0;
      before = vat_time_now (vam);
    }

  for (j = 0; j < count; j++)
    {
      /* Construct the API message */
      M2 (IP_ROUTE_ADD_DEL, mp, sizeof (vl_api_fib_path_t) * path_count);

      mp->is_add = is_add;
      mp->is_multipath = is_multipath;

      clib_memcpy (&mp->route.prefix, &pfx, sizeof (pfx));
      mp->route.table_id = ntohl (vrf_id);
      mp->route.n_paths = path_count;

      clib_memcpy (&mp->route.paths, &paths, sizeof (paths[0]) * path_count);

      if (random_add_del)
	set_ip4_address (&pfx.address, random_vector[j + 1]);
      else
	increment_address (&pfx.address);
      /* send it... */
      S (mp);
      /* If we receive SIGTERM, stop now... */
      if (vam->do_exit)
	break;
    }

  /* When testing multiple add/del ops, use a control-ping to sync */
  if (count > 1)
    {
      vl_api_control_ping_t *mp_ping;
      f64 after;
      f64 timeout;

      /* Shut off async mode */
      vam->async_mode = 0;

      PING (&ip_test_main, mp_ping);
      S (mp_ping);

      timeout = vat_time_now (vam) + 1.0;
      while (vat_time_now (vam) < timeout)
	if (vam->result_ready == 1)
	  goto out;
      vam->retval = -99;

    out:
      if (vam->retval == -99)
	errmsg ("timeout");

      if (vam->async_errors > 0)
	{
	  errmsg ("%d asynchronous errors", vam->async_errors);
	  vam->retval = -98;
	}
      vam->async_errors = 0;
      after = vat_time_now (vam);

      /* slim chance, but we might have eaten SIGTERM on the first iteration */
      if (j > 0)
	count = j;

      print (vam->ofp, "%d routes in %.6f secs, %.2f routes/sec", count,
	     after - before, count / (after - before));
    }
  else
    {
      int ret;

      /* Wait for a reply... */
      W (ret);
      return ret;
    }

  /* Return the good/bad news */
  return (vam->retval);
}

static int
api_ip_table_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_add_del_t *mp;
  u32 table_id = ~0;
  u8 is_ipv6 = 0;
  u8 is_add = 1;
  int ret = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "table %d", &table_id))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (~0 == table_id)
    {
      errmsg ("missing table-ID");
      return -99;
    }

  /* Construct the API message */
  M (IP_TABLE_ADD_DEL, mp);

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;
  mp->is_add = is_add;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static int
api_ip_table_replace_begin (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_replace_begin_t *mp;
  u32 table_id = 0;
  u8 is_ipv6 = 0;

  int ret;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "table %d", &table_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IP_TABLE_REPLACE_BEGIN, mp);

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_table_flush (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_flush_t *mp;
  u32 table_id = 0;
  u8 is_ipv6 = 0;

  int ret;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "table %d", &table_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IP_TABLE_FLUSH, mp);

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_table_allocate (vat_main_t *vam)
{
  return -1;
}

static void
vl_api_ip_table_allocate_reply_t_handler (vl_api_ip_table_allocate_reply_t *mp)
{
}

static void
vl_api_ip_route_add_del_v2_reply_t_handler (
  vl_api_ip_route_add_del_v2_reply_t *mp)
{
}

static void
vl_api_ip_route_details_t_handler (vl_api_ip_route_details_t *mp)
{
}

static void
vl_api_ip_route_v2_details_t_handler (vl_api_ip_route_v2_details_t *mp)
{
}

static void
vl_api_ip_route_add_del_reply_t_handler (vl_api_ip_route_add_del_reply_t *mp)
{
  vat_main_t *vam = ip_test_main.vat_main;
  vam->result_ready = 1;
}

static void
vl_api_ip_route_lookup_reply_t_handler (vl_api_ip_route_lookup_reply_t *mp)
{
}

static void
vl_api_ip_route_lookup_v2_reply_t_handler (
  vl_api_ip_route_lookup_v2_reply_t *mp)
{
}

static int
api_set_ip_flow_hash_router_id (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_route_lookup (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_route_lookup_v2 (vat_main_t *vat)
{
  return -1;
}

static int
api_set_ip_flow_hash (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_set_ip_flow_hash_t *mp;
  u32 vrf_id = 0;
  u8 is_ipv6 = 0;
  u8 vrf_id_set = 0;
  u8 src = 0;
  u8 dst = 0;
  u8 sport = 0;
  u8 dport = 0;
  u8 proto = 0;
  u8 reverse = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vrf %d", &vrf_id))
	vrf_id_set = 1;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "src"))
	src = 1;
      else if (unformat (i, "dst"))
	dst = 1;
      else if (unformat (i, "sport"))
	sport = 1;
      else if (unformat (i, "dport"))
	dport = 1;
      else if (unformat (i, "proto"))
	proto = 1;
      else if (unformat (i, "reverse"))
	reverse = 1;

      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (vrf_id_set == 0)
    {
      errmsg ("missing vrf id");
      return -99;
    }

  M (SET_IP_FLOW_HASH, mp);
  mp->src = src;
  mp->dst = dst;
  mp->sport = sport;
  mp->dport = dport;
  mp->proto = proto;
  mp->reverse = reverse;
  mp->vrf_id = ntohl (vrf_id);
  mp->is_ipv6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_mfib_signal_dump (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_punt_police (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_punt_redirect (vat_main_t *vat)
{
  return -1;
}

static int
api_add_del_ip_punt_redirect_v2 (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_punt_redirect_dump (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ip_punt_redirect_details_t_handler (
  vl_api_ip_punt_redirect_details_t *mp)
{
  /**/
}

static int
api_ip_punt_redirect_v2_dump (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ip_punt_redirect_v2_details_t_handler (
  vl_api_ip_punt_redirect_v2_details_t *mp)
{
  /**/
}

static int
api_ip_address_dump (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_address_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "ipv4"))
	ipv4_set = 1;
      else if (unformat (i, "ipv6"))
	ipv6_set = 1;
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("ipv4 and ipv6 flags cannot be both set");
      return -99;
    }

  if ((!ipv4_set) && (!ipv6_set))
    {
      errmsg ("no ipv4 nor ipv6 flag set");
      return -99;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  vam->current_sw_if_index = sw_if_index;
  vam->is_ipv6 = ipv6_set;

  M (IP_ADDRESS_DUMP, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_ipv6 = ipv6_set;
  S (mp);

  /* Use a control ping for synchronization */
  PING (&ip_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_sw_interface_ip6_get_link_local_address_reply_t_handler (
  vl_api_sw_interface_ip6_get_link_local_address_reply_t *mp)
{
}

static int
api_sw_interface_ip6_set_link_local_address (vat_main_t *vam)
{
  return -1;
}

static int
api_sw_interface_ip6_get_link_local_address (vat_main_t *vam)
{
  return -1;
}

static int
api_ip_path_mtu_replace_end (vat_main_t *vam)
{
  return -1;
}

static int
api_ioam_enable (vat_main_t *vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ioam_enable_t *mp;
  u32 id = 0;
  int has_trace_option = 0;
  int has_pot_option = 0;
  int has_seqno_option = 0;
  int has_analyse_option = 0;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace"))
	has_trace_option = 1;
      else if (unformat (input, "pot"))
	has_pot_option = 1;
      else if (unformat (input, "seqno"))
	has_seqno_option = 1;
      else if (unformat (input, "analyse"))
	has_analyse_option = 1;
      else
	break;
    }
  M (IOAM_ENABLE, mp);
  mp->id = htons (id);
  mp->seqno = has_seqno_option;
  mp->analyse = has_analyse_option;
  mp->pot_enable = has_pot_option;
  mp->trace_enable = has_trace_option;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_reassembly_get (vat_main_t *vam)
{
  return -1;
}

static int
api_ip_path_mtu_replace_begin (vat_main_t *vam)
{
  return -1;
}

static int
api_ip_path_mtu_update (vat_main_t *vam)
{
  return -1;
}

static int
api_ioam_disable (vat_main_t *vam)
{
  vl_api_ioam_disable_t *mp;
  int ret;

  M (IOAM_DISABLE, mp);
  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_source_and_port_range_check_add_del (vat_main_t *vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ip_source_and_port_range_check_add_del_t *mp;

  u16 *low_ports = 0;
  u16 *high_ports = 0;
  u16 this_low;
  u16 this_hi;
  vl_api_prefix_t prefix;
  u32 tmp, tmp2;
  u8 prefix_set = 0;
  u32 vrf_id = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vl_api_prefix, &prefix))
	prefix_set = 1;
      else if (unformat (input, "vrf %d", &vrf_id))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "port %d", &tmp))
	{
	  if (tmp == 0 || tmp > 65535)
	    {
	      errmsg ("port %d out of range", tmp);
	      return -99;
	    }
	  this_low = tmp;
	  this_hi = this_low + 1;
	  vec_add1 (low_ports, this_low);
	  vec_add1 (high_ports, this_hi);
	}
      else if (unformat (input, "range %d - %d", &tmp, &tmp2))
	{
	  if ((tmp > tmp2) || (tmp == 0) || (tmp2 > 65535))
	    {
	      errmsg ("incorrect range parameters");
	      return -99;
	    }
	  this_low = tmp;
	  /* Note: in debug CLI +1 is added to high before
	     passing to real fn that does "the work"
	     (ip_source_and_port_range_check_add_del).
	     This fn is a wrapper around the binary API fn a
	     control plane will call, which expects this increment
	     to have occurred. Hence letting the binary API control
	     plane fn do the increment for consistency between VAT
	     and other control planes.
	   */
	  this_hi = tmp2;
	  vec_add1 (low_ports, this_low);
	  vec_add1 (high_ports, this_hi);
	}
      else
	break;
    }

  if (prefix_set == 0)
    {
      errmsg ("<address>/<mask> not specified");
      return -99;
    }

  if (vrf_id == ~0)
    {
      errmsg ("VRF ID required, not specified");
      return -99;
    }

  if (vrf_id == 0)
    {
      errmsg ("VRF ID should not be default. Should be distinct VRF for this "
	      "purpose.");
      return -99;
    }

  if (vec_len (low_ports) == 0)
    {
      errmsg ("At least one port or port range required");
      return -99;
    }

  M (IP_SOURCE_AND_PORT_RANGE_CHECK_ADD_DEL, mp);

  mp->is_add = is_add;

  clib_memcpy (&mp->prefix, &prefix, sizeof (prefix));

  mp->number_of_ranges = vec_len (low_ports);

  clib_memcpy (mp->low_ports, low_ports, vec_len (low_ports));
  vec_free (low_ports);

  clib_memcpy (mp->high_ports, high_ports, vec_len (high_ports));
  vec_free (high_ports);

  mp->vrf_id = ntohl (vrf_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_reassembly_set (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_container_proxy_add_del (vat_main_t *vam)
{
  vl_api_ip_container_proxy_add_del_t *mp;
  unformat_input_t *i = vam->input;
  u32 sw_if_index = ~0;
  vl_api_prefix_t pfx = {};
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	;
      if (unformat (i, "%U", unformat_vl_api_prefix, &pfx))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else
	break;
    }
  if (sw_if_index == ~0 || pfx.len == 0)
    {
      errmsg ("address and sw_if_index must be set");
      return -99;
    }

  M (IP_CONTAINER_PROXY_ADD_DEL, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
  mp->is_add = is_add;
  clib_memcpy (&mp->pfx, &pfx, sizeof (pfx));

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_reassembly_enable_disable (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_reass_forus_enable_disable (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_reass_forus_get (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ip_reass_forus_get_reply_t_handler (
  vl_api_ip_reass_forus_get_reply_t *mp)
{
}

static void
vl_api_ip_reassembly_get_reply_t_handler (vl_api_ip_reassembly_get_reply_t *mp)
{
}

int
api_ip_source_and_port_range_check_interface_add_del (vat_main_t *vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ip_source_and_port_range_check_interface_add_del_t *mp;
  u32 sw_if_index = ~0;
  int vrf_set = 0;
  u32 tcp_out_vrf_id = ~0, udp_out_vrf_id = ~0;
  u32 tcp_in_vrf_id = ~0, udp_in_vrf_id = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (input, "tcp-out-vrf %d", &tcp_out_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "udp-out-vrf %d", &udp_out_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "tcp-in-vrf %d", &tcp_in_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "udp-in-vrf %d", &udp_in_vrf_id))
	vrf_set = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("Interface required but not specified");
      return -99;
    }

  if (vrf_set == 0)
    {
      errmsg ("VRF ID required but not specified");
      return -99;
    }

  if (tcp_out_vrf_id == 0 || udp_out_vrf_id == 0 || tcp_in_vrf_id == 0 ||
      udp_in_vrf_id == 0)
    {
      errmsg ("VRF ID should not be default. Should be distinct VRF for this "
	      "purpose.");
      return -99;
    }

  /* Construct the API message */
  M (IP_SOURCE_AND_PORT_RANGE_CHECK_INTERFACE_ADD_DEL, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;
  mp->tcp_out_vrf_id = ntohl (tcp_out_vrf_id);
  mp->udp_out_vrf_id = ntohl (udp_out_vrf_id);
  mp->tcp_in_vrf_id = ntohl (tcp_in_vrf_id);
  mp->udp_in_vrf_id = ntohl (udp_in_vrf_id);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_ip_container_proxy_details_t_handler (
  vl_api_ip_container_proxy_details_t *mp)
{
}

static int
api_ip_container_proxy_dump (vat_main_t *vam)
{
  return -1;
}

static int
api_ip_dump (vat_main_t *vam)
{
  vl_api_ip_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  unformat_input_t *in = vam->input;
  int ipv4_set = 0;
  int ipv6_set = 0;
  int is_ipv6;
  int i;
  int ret;

  while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (in, "ipv4"))
	ipv4_set = 1;
      else if (unformat (in, "ipv6"))
	ipv6_set = 1;
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("ipv4 and ipv6 flags cannot be both set");
      return -99;
    }

  if ((!ipv4_set) && (!ipv6_set))
    {
      errmsg ("no ipv4 nor ipv6 flag set");
      return -99;
    }

  is_ipv6 = ipv6_set;
  vam->is_ipv6 = is_ipv6;

  /* free old data */
  for (i = 0; i < vec_len (vam->ip_details_by_sw_if_index[is_ipv6]); i++)
    {
      vec_free (vam->ip_details_by_sw_if_index[is_ipv6][i].addr);
    }
  vec_free (vam->ip_details_by_sw_if_index[is_ipv6]);

  M (IP_DUMP, mp);
  mp->is_ipv6 = ipv6_set;
  S (mp);

  /* Use a control ping for synchronization */
  PING (&ip_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_mfib_signal_details_t_handler (vl_api_mfib_signal_details_t *mp)
{
}

static void
vl_api_ip_mroute_details_t_handler (vl_api_ip_mroute_details_t *mp)
{
  vat_main_t *vam = ip_test_main.vat_main;
  vam->result_ready = 1;
}

static int
api_ip_mroute_dump (vat_main_t *vam)
{
  unformat_input_t *input = vam->input;
  vl_api_control_ping_t *mp_ping;
  vl_api_ip_mroute_dump_t *mp;
  int ret, is_ip6;
  u32 table_id;

  is_ip6 = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table_id %d", &table_id))
	;
      else if (unformat (input, "ip6"))
	is_ip6 = 1;
      else if (unformat (input, "ip4"))
	is_ip6 = 0;
      else
	break;
    }
  if (table_id == ~0)
    {
      errmsg ("missing table id");
      return -99;
    }

  M (IP_MROUTE_DUMP, mp);
  mp->table.table_id = table_id;
  mp->table.is_ip6 = is_ip6;
  S (mp);

  /* Use a control ping for synchronization */
  PING (&ip_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_sw_interface_ip6_enable_disable (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_ip6_enable_disable_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 enable = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (SW_INTERFACE_IP6_ENABLE_DISABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_set_ip_flow_hash_v2 (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_mroute_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u8 path_set = 0, prefix_set = 0, is_add = 1;
  vl_api_ip_mroute_add_del_t *mp;
  mfib_entry_flags_t eflags = 0;
  vl_api_mfib_path_t path;
  vl_api_mprefix_t pfx = {};
  u32 vrf_id = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vl_api_mprefix, &pfx))
	{
	  prefix_set = 1;
	  pfx.grp_address_length = htons (pfx.grp_address_length);
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "%U", unformat_mfib_itf_flags, &path.itf_flags))
	path.itf_flags = htonl (path.itf_flags);
      else if (unformat (i, "%U", unformat_mfib_entry_flags, &eflags))
	;
      else if (unformat (i, "via %U", unformat_fib_path, vam, &path.path))
	path_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (prefix_set == 0)
    {
      errmsg ("missing addresses\n");
      return -99;
    }
  if (path_set == 0)
    {
      errmsg ("missing path\n");
      return -99;
    }

  /* Construct the API message */
  M (IP_MROUTE_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->is_multipath = 1;

  clib_memcpy (&mp->route.prefix, &pfx, sizeof (pfx));
  mp->route.table_id = htonl (vrf_id);
  mp->route.n_paths = 1;
  mp->route.entry_flags = htonl (eflags);

  clib_memcpy (&mp->route.paths, &path, sizeof (path));

  /* send it... */
  S (mp);
  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_ip_mroute_add_del_reply_t_handler (vl_api_ip_mroute_add_del_reply_t *mp)
{
  vat_main_t *vam = ip_test_main.vat_main;
  vam->result_ready = 1;
}

static int
api_ip_mtable_dump (vat_main_t *vam)
{
  vl_api_ip_mtable_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP_MTABLE_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  PING (&ip_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_ip_mtable_details_t_handler (vl_api_ip_mtable_details_t *mp)
{
  vat_main_t *vam = ip_test_main.vat_main;
  vam->result_ready = 1;
}

static int
api_ip_table_replace_end (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ip_table_replace_end_t *mp;
  u32 table_id = 0;
  u8 is_ipv6 = 0;

  int ret;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "table %d", &table_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IP_TABLE_REPLACE_END, mp);

  mp->table.table_id = ntohl (table_id);
  mp->table.is_ip6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ip_table_dump (vat_main_t *vam)
{
  vl_api_ip_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  M (IP_TABLE_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  PING (&ip_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_ip_table_details_t_handler (vl_api_ip_table_details_t *mp)
{
  vat_main_t *vam = ip_test_main.vat_main;

  fformat (vam->ofp, "%s; table-id %d, prefix %U/%d", mp->table.name,
	   ntohl (mp->table.table_id));
  vam->result_ready = 1;
}

static int
api_ip_path_mtu_get (vat_main_t *vat)
{
  return -1;
}

static int
api_ip_route_v2_dump (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ip_path_mtu_get_reply_t_handler (vl_api_ip_path_mtu_get_reply_t *mp)
{
}

static int
api_ip_route_dump (vat_main_t *vam)
{
  unformat_input_t *input = vam->input;
  vl_api_ip_route_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 table_id;
  u8 is_ip6;
  int ret;

  is_ip6 = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table_id %d", &table_id))
	;
      else if (unformat (input, "ip6"))
	is_ip6 = 1;
      else if (unformat (input, "ip4"))
	is_ip6 = 0;
      else
	break;
    }
  if (table_id == ~0)
    {
      errmsg ("missing table id");
      return -99;
    }

  M (IP_ROUTE_DUMP, mp);

  mp->table.table_id = table_id;
  mp->table.is_ip6 = is_ip6;

  S (mp);

  /* Use a control ping for synchronization */
  PING (&ip_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_ip_address_details_t_handler (vl_api_ip_address_details_t *mp)
{
  vat_main_t *vam = ip_test_main.vat_main;
  static ip_address_details_t empty_ip_address_details = { { 0 } };
  ip_address_details_t *address = NULL;
  ip_details_t *current_ip_details = NULL;
  ip_details_t *details = NULL;

  details = vam->ip_details_by_sw_if_index[vam->is_ipv6];

  if (!details || vam->current_sw_if_index >= vec_len (details) ||
      !details[vam->current_sw_if_index].present)
    {
      errmsg ("ip address details arrived but not stored");
      errmsg ("ip_dump should be called first");
      return;
    }

  current_ip_details = vec_elt_at_index (details, vam->current_sw_if_index);

#define addresses (current_ip_details->addr)

  vec_validate_init_empty (addresses, vec_len (addresses),
			   empty_ip_address_details);

  address = vec_elt_at_index (addresses, vec_len (addresses) - 1);

  clib_memcpy (&address->ip, &mp->prefix.address.un, sizeof (address->ip));
  address->prefix_length = mp->prefix.len;
#undef addresses
}

static int
api_ip_unnumbered_dump (vat_main_t *vam)
{
  return -1;
}

static void
vl_api_ip_unnumbered_details_t_handler (vl_api_ip_unnumbered_details_t *mp)
{
}

static void
vl_api_ip_details_t_handler (vl_api_ip_details_t *mp)
{
  vat_main_t *vam = &vat_main;
  static ip_details_t empty_ip_details = { 0 };
  ip_details_t *ip = NULL;
  u32 sw_if_index = ~0;

  sw_if_index = ntohl (mp->sw_if_index);

  vec_validate_init_empty (vam->ip_details_by_sw_if_index[vam->is_ipv6],
			   sw_if_index, empty_ip_details);

  ip = vec_elt_at_index (vam->ip_details_by_sw_if_index[vam->is_ipv6],
			 sw_if_index);

  ip->present = 1;
}

#include <vnet/ip/ip.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
