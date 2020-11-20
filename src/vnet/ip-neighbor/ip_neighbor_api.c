/*
 *------------------------------------------------------------------
 * ip_api.c - vnet ip api
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

#include <stddef.h>

#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip-neighbor/ip_neighbor_watch.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vnet/ip-neighbor/ip_neighbor.api_enum.h>
#include <vnet/ip-neighbor/ip_neighbor.api_types.h>

static u16 msg_id_base;
#define REPLY_MSG_ID_BASE msg_id_base

#include <vlibapi/api_helper_macros.h>

#include <vnet/format_fns.h>


static ip46_type_t
ip46_type_from_af (ip_address_family_t af)
{
  return (AF_IP4 == af ? IP46_TYPE_IP4 : IP46_TYPE_IP6);
}

static vl_api_ip_neighbor_flags_t
ip_neighbor_flags_encode (ip_neighbor_flags_t f)
{
  vl_api_ip_neighbor_flags_t v = IP_API_NEIGHBOR_FLAG_NONE;

  if (f & IP_NEIGHBOR_FLAG_STATIC)
    v |= IP_API_NEIGHBOR_FLAG_STATIC;
  if (f & IP_NEIGHBOR_FLAG_NO_FIB_ENTRY)
    v |= IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY;

  return (v);
}

static void
ip_neighbor_encode (vl_api_ip_neighbor_t * api, const ip_neighbor_t * ipn)
{
  api->sw_if_index = htonl (ipn->ipn_key->ipnk_sw_if_index);
  api->flags = ip_neighbor_flags_encode (ipn->ipn_flags);

  ip_address_encode (&ipn->ipn_key->ipnk_ip,
		     ipn->ipn_key->ipnk_type, &api->ip_address);
  mac_address_encode (&ipn->ipn_mac, api->mac_address);
}

void
ip_neighbor_handle_event (ip_neighbor_event_t * ipne)
{
  vl_api_registration_t *reg;
  ip_neighbor_t *ipn;

  ipn = &ipne->ipne_nbr;

  if (NULL == ipn)
    /* Client can cancel, die, etc. */
    return;

  /* Customer(s) requesting event for this neighbor */
  reg = vl_api_client_index_to_registration (ipne->ipne_watch.ipw_client);
  if (!reg)
    return;

  if (vl_api_can_send_msg (reg))
    {
      if (1 == ipne->ipne_watch.ipw_api_version)
	{
	  vl_api_ip_neighbor_event_t *mp;

	  mp = vl_msg_api_alloc (sizeof (*mp));
	  clib_memset (mp, 0, sizeof (*mp));
	  mp->_vl_msg_id =
	    ntohs (VL_API_IP_NEIGHBOR_EVENT + REPLY_MSG_ID_BASE);
	  mp->client_index = ipne->ipne_watch.ipw_client;
	  mp->pid = ipne->ipne_watch.ipw_pid;

	  ip_neighbor_encode (&mp->neighbor, ipn);

	  vl_api_send_msg (reg, (u8 *) mp);
	}
      else if (2 == ipne->ipne_watch.ipw_api_version)
	{
	  vl_api_ip_neighbor_event_v2_t *mp;

	  mp = vl_msg_api_alloc (sizeof (*mp));
	  clib_memset (mp, 0, sizeof (*mp));
	  mp->_vl_msg_id =
	    ntohs (VL_API_IP_NEIGHBOR_EVENT_V2 + REPLY_MSG_ID_BASE);
	  mp->client_index = ipne->ipne_watch.ipw_client;
	  mp->pid = ipne->ipne_watch.ipw_pid;
	  mp->flags = clib_host_to_net_u32 (ipne->ipne_flags);

	  ip_neighbor_encode (&mp->neighbor, ipn);

	  vl_api_send_msg (reg, (u8 *) mp);
	}
    }
  else
    {
      static f64 last_time;
      /*
       * Throttle syslog msgs.
       * It's pretty tempting to just revoke the registration...
       */
      if (vlib_time_now (vlib_get_main ()) > last_time + 10.0)
	{
	  clib_warning ("neighbor event for %U to pid %d: queue stuffed!",
			format_ip46_address, &ipn->ipn_key->ipnk_ip,
			IP46_TYPE_ANY, ipne->ipne_watch.ipw_pid);
	  last_time = vlib_time_now (vlib_get_main ());
	}
    }

  ip_neighbor_free (ipn);
}

typedef struct ip_neighbor_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} ip_neighbor_dump_ctx_t;

static walk_rc_t
send_ip_neighbor_details (index_t ipni, void *arg)
{
  ip_neighbor_dump_ctx_t *ctx = arg;
  vl_api_ip_neighbor_details_t *mp;
  ip_neighbor_t *ipn;

  ipn = ip_neighbor_get (ipni);
  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP_NEIGHBOR_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = ctx->context;
  mp->age =
    clib_host_to_net_f64 ((vlib_time_now (vlib_get_main ()) -
			   ipn->ipn_time_last_updated));
  ip_neighbor_encode (&mp->neighbor, ipn);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_ip_neighbor_dump_t_handler (vl_api_ip_neighbor_dump_t * mp)
{
  vl_api_registration_t *reg;
  ip_address_family_t af;
  int rv;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = ip_address_family_decode (mp->af, &af);

  if (rv)
    return;

  ip_neighbor_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  // walk all neighbours on all interfaces
  ip_neighbor_walk ((af == AF_IP4 ?
		     IP46_TYPE_IP4 :
		     IP46_TYPE_IP6),
		    sw_if_index, send_ip_neighbor_details, &ctx);
}

static ip_neighbor_flags_t
ip_neighbor_flags_decode (vl_api_ip_neighbor_flags_t v)
{
  ip_neighbor_flags_t f = IP_NEIGHBOR_FLAG_NONE;

  if (v & IP_API_NEIGHBOR_FLAG_STATIC)
    f |= IP_NEIGHBOR_FLAG_STATIC;
  if (v & IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY)
    f |= IP_NEIGHBOR_FLAG_NO_FIB_ENTRY;

  return (f);
}

static void
vl_api_ip_neighbor_add_del_t_handler (vl_api_ip_neighbor_add_del_t * mp,
				      vlib_main_t * vm)
{
  vl_api_ip_neighbor_add_del_reply_t *rmp;
  ip_neighbor_flags_t flags;
  u32 stats_index = ~0;
  ip46_address_t ip = ip46_address_initializer;
  mac_address_t mac;
  ip46_type_t type;
  int rv;

  VALIDATE_SW_IF_INDEX ((&mp->neighbor));

  flags = ip_neighbor_flags_decode (mp->neighbor.flags);
  type = ip_address_decode (&mp->neighbor.ip_address, &ip);
  mac_address_decode (mp->neighbor.mac_address, &mac);

  /* must be static or dynamic, default to dynamic */
  if (!(flags & IP_NEIGHBOR_FLAG_STATIC) &&
      !(flags & IP_NEIGHBOR_FLAG_DYNAMIC))
    flags |= IP_NEIGHBOR_FLAG_DYNAMIC;

  /*
   * there's no validation here of the ND/ARP entry being added.
   * The expectation is that the FIB will ensure that nothing bad
   * will come of adding bogus entries.
   */
  if (mp->is_add)
    rv = ip_neighbor_add (&ip, type, &mac,
			  ntohl (mp->neighbor.sw_if_index),
			  flags, &stats_index);
  else
    rv = ip_neighbor_del (&ip, type, ntohl (mp->neighbor.sw_if_index));

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IP_NEIGHBOR_ADD_DEL_REPLY,
  ({
    rmp->stats_index = htonl (stats_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_want_ip_neighbor_events_t_handler (vl_api_want_ip_neighbor_events_t *
					  mp)
{
  vl_api_want_ip_neighbor_events_reply_t *rmp;
  ip46_address_t ip;
  ip46_type_t itype;
  int rv = 0;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);
  itype = ip_address_decode (&mp->ip, &ip);

  ip_neighbor_watcher_t watch = {
    .ipw_client = mp->client_index,
    .ipw_pid = mp->pid,
    .ipw_api_version = 1,
  };

  if (mp->enable)
    ip_neighbor_watch (&ip, itype, ntohl (mp->sw_if_index), &watch);
  else
    ip_neighbor_unwatch (&ip, itype, ntohl (mp->sw_if_index), &watch);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_WANT_IP_NEIGHBOR_EVENTS_REPLY);
}

static void
  vl_api_want_ip_neighbor_events_v2_t_handler
  (vl_api_want_ip_neighbor_events_v2_t * mp)
{
  vl_api_want_ip_neighbor_events_reply_t *rmp;
  ip46_address_t ip;
  ip46_type_t itype;
  int rv = 0;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);
  itype = ip_address_decode (&mp->ip, &ip);

  ip_neighbor_watcher_t watch = {
    .ipw_client = mp->client_index,
    .ipw_pid = mp->pid,
    .ipw_api_version = 2,
  };

  if (mp->enable)
    ip_neighbor_watch (&ip, itype, ntohl (mp->sw_if_index), &watch);
  else
    ip_neighbor_unwatch (&ip, itype, ntohl (mp->sw_if_index), &watch);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_WANT_IP_NEIGHBOR_EVENTS_V2_REPLY);
}

static void
vl_api_ip_neighbor_config_t_handler (vl_api_ip_neighbor_config_t * mp)
{
  vl_api_ip_neighbor_config_reply_t *rmp;
  ip_address_family_t af;
  int rv;

  rv = ip_address_family_decode (mp->af, &af);

  if (!rv)
    rv = ip_neighbor_config (ip46_type_from_af (af),
			     ntohl (mp->max_number),
			     ntohl (mp->max_age), mp->recycle);

  REPLY_MACRO (VL_API_IP_NEIGHBOR_CONFIG_REPLY);
}

static void
vl_api_ip_neighbor_replace_begin_t_handler (vl_api_ip_neighbor_replace_begin_t
					    * mp)
{
  vl_api_ip_neighbor_replace_begin_reply_t *rmp;
  int rv = 0;

  ip_neighbor_mark (IP46_TYPE_IP4);
  ip_neighbor_mark (IP46_TYPE_IP6);

  REPLY_MACRO (VL_API_IP_NEIGHBOR_REPLACE_BEGIN_REPLY);
}

static void
vl_api_ip_neighbor_replace_end_t_handler (vl_api_ip_neighbor_replace_end_t *
					  mp)
{
  vl_api_ip_neighbor_replace_end_reply_t *rmp;
  int rv = 0;

  ip_neighbor_sweep (IP46_TYPE_IP4);
  ip_neighbor_sweep (IP46_TYPE_IP6);

  REPLY_MACRO (VL_API_IP_NEIGHBOR_REPLACE_END_REPLY);
}

static void
vl_api_ip_neighbor_flush_t_handler (vl_api_ip_neighbor_flush_t * mp)
{
  vl_api_ip_neighbor_flush_reply_t *rmp;
  ip_address_family_t af;
  int rv;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);

  rv = ip_address_family_decode (mp->af, &af);

  if (!rv)
    ip_neighbor_del_all (ip46_type_from_af (af), ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IP_NEIGHBOR_FLUSH_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/ip-neighbor/ip_neighbor.api.h>
#undef vl_msg_name_crc_list

#include <vnet/ip-neighbor/ip_neighbor.api.c>

static clib_error_t *
ip_neighbor_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (ip_neighbor_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
