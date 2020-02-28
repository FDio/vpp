/*
 * vrrp.c - VRRP vpp-api-test plug-in
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vrrp/vrrp.api_enum.h>
#include <vrrp/vrrp.api_types.h>
#include <vpp/api/vpe.api_types.h>


typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} vrrp_test_main_t;

vrrp_test_main_t vrrp_test_main;

#define __plugin_msg_base vrrp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_vrrp_vr_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  u32 sw_if_index = ~0;
  u32 vr_id, priority, interval;
  u8 is_ipv6, no_preempt, accept_mode, vr_unicast, is_add, is_del;
  u8 n_addrs4, n_addrs6;
  vl_api_vrrp_vr_add_del_t *mp;
  vl_api_address_t *api_addr;
  ip46_address_t *ip_addr, *ip_addrs = 0;
  ip46_address_t addr;
  int ret = 0;

  interval = priority = 100;
  n_addrs4 = n_addrs6 = 0;
  vr_id = is_ipv6 = no_preempt = accept_mode = vr_unicast = 0;
  is_add = is_del = 0;

  clib_memset (&addr, 0, sizeof (addr));

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (i, "vr_id %u", &vr_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "priority %u", &priority))
	;
      else if (unformat (i, "interval %u", &interval))
	;
      else if (unformat (i, "no_preempt"))
	no_preempt = 1;
      else if (unformat (i, "accept_mode"))
	accept_mode = 1;
      else if (unformat (i, "unicast"))
	vr_unicast = 1;
      else if (unformat (i, "%U", unformat_ip4_address, &addr.ip4))
	{
	  vec_add1 (ip_addrs, addr);
	  n_addrs4++;
	  clib_memset (&addr, 0, sizeof (addr));
	}
      else if (unformat (i, "%U", unformat_ip6_address, &addr.ip6))
	{
	  vec_add1 (ip_addrs, addr);
	  n_addrs6++;
	  clib_memset (&addr, 0, sizeof (addr));
	}
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "del"))
	is_del = 1;
      else
	break;
    }

  if (is_add == is_del)
    {
      errmsg ("One of add or del must be specified\n");
      ret = -99;
    }
  else if (sw_if_index == ~0)
    {
      errmsg ("Interface not set\n");
      ret = -99;
    }
  else if (n_addrs4 && (n_addrs6 || is_ipv6))
    {
      errmsg ("Address family mismatch\n");
      ret = -99;
    }

  if (ret)
    goto done;

  /* Construct the API message */
  M2 (VRRP_VR_ADD_DEL, mp, vec_len (ip_addrs) * sizeof (*api_addr));

  mp->is_add = is_add;
  mp->sw_if_index = ntohl (sw_if_index);
  mp->vr_id = vr_id;
  mp->priority = priority;
  mp->interval = htons (interval);
  mp->flags = VRRP_API_VR_PREEMPT;	/* preempt by default */

  if (no_preempt)
    mp->flags &= ~VRRP_API_VR_PREEMPT;

  if (accept_mode)
    mp->flags |= VRRP_API_VR_ACCEPT;

  if (vr_unicast)
    mp->flags |= VRRP_API_VR_UNICAST;

  if (is_ipv6)
    mp->flags |= VRRP_API_VR_IPV6;

  mp->flags = htonl (mp->flags);

  mp->n_addrs = n_addrs4 + n_addrs6;
  api_addr = mp->addrs;

  vec_foreach (ip_addr, ip_addrs)
  {
    void *src, *dst;
    int len;

    if (is_ipv6)
      {
	api_addr->af = ADDRESS_IP6;
	src = &ip_addr->ip6;
	dst = &api_addr->un.ip6;
	len = sizeof (api_addr->un.ip6);
      }
    else
      {
	api_addr->af = ADDRESS_IP4;
	src = &ip_addr->ip4;
	dst = &api_addr->un.ip4;
	len = sizeof (api_addr->un.ip4);
      }
    clib_memcpy (dst, src, len);
    api_addr++;
  }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

done:
  vec_free (ip_addrs);

  return ret;
}

static int
api_vrrp_vr_dump (vat_main_t * vam)
{
  vrrp_test_main_t *vtm = &vrrp_test_main;
  unformat_input_t *i = vam->input;
  vl_api_vrrp_vr_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index = ~0;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for vrrp_vr_dump");
      return -99;
    }

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else
	break;
    }

  M (VRRP_VR_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (vtm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_vrrp_vr_details_t_handler (vl_api_vrrp_vr_details_t * mp)
{
  vat_main_t *vam = vrrp_test_main.vat_main;
  u32 api_flags = ntohl (mp->config.flags);
  int i;
  u32 state;
  char *states[] = {
    "VRRP_API_VR_STATE_INIT",
    "VRRP_API_VR_STATE_BACKUP",
    "VRRP_API_VR_STATE_MASTER",
    "BAD STATE!",
  };

  state = ntohl (mp->runtime.state);

  if (state > ARRAY_LEN (states) - 2)
    state = ARRAY_LEN (states) - 1;

  fformat (vam->ofp, "sw_if_index %u vr_id %u IPv%d: "
	   "priority %u interval %u preempt %s accept %s unicast %s "
	   "state %s master_adv_interval %u skew %u master_down_interval %u "
	   "mac %U ",
	   ntohl (mp->config.sw_if_index), mp->config.vr_id,
	   (mp->config.flags & VRRP_API_VR_IPV6) ? 6 : 4,
	   mp->config.priority, htons (mp->config.interval),
	   (api_flags & VRRP_API_VR_PREEMPT) ? "yes" : "no",
	   (api_flags & VRRP_API_VR_ACCEPT) ? "yes" : "no",
	   (api_flags & VRRP_API_VR_UNICAST) ? "yes" : "no",
	   states[state],
	   ntohs (mp->runtime.master_adv_int), ntohs (mp->runtime.skew),
	   ntohs (mp->runtime.master_down_int),
	   format_ethernet_address, &mp->runtime.mac);

  fformat (vam->ofp, "addresses: ");

  for (i = 0; i < mp->n_addrs; i++)
    {
      vl_api_address_t *addr = mp->addrs + i;

      fformat (vam->ofp, "%U ",
	       (addr->af) ? format_ip6_address : format_ip4_address,
	       (u8 *) & addr->un);
    }

  fformat (vam->ofp, "\n");
}

static int
api_vrrp_vr_start_stop (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_vrrp_vr_start_stop_t *mp;
  u32 sw_if_index = ~0, vr_id;
  u8 is_ipv6, is_start, is_stop;
  int ret;

  vr_id = is_ipv6 = is_start = is_stop = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (i, "vr_id %u", &vr_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "start"))
	is_start = 1;
      else if (unformat (i, "stop"))
	is_stop = 1;
      else
	break;
    }

  if (is_start == is_stop)
    {
      errmsg ("One of add or del must be specified\n");
      return -99;
    }
  else if (sw_if_index == ~0)
    {
      errmsg ("Interface not set\n");
      return -99;
    }
  else if (!vr_id)
    {
      errmsg ("VR ID must be between 1 and 255");
      return -99;
    }

  M (VRRP_VR_START_STOP, mp);

  mp->sw_if_index = htonl (sw_if_index);
  mp->vr_id = vr_id;
  mp->is_ipv6 = (is_ipv6 != 0);
  mp->is_start = (is_start != 0);

  S (mp);

  W (ret);
  return ret;
}

static int
api_vrrp_vr_track_if_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_vrrp_vr_track_if_add_del_t *mp;
  vl_api_vrrp_vr_track_if_t *track_ifs = 0, *track_if;
  u32 sw_if_index = ~0, track_sw_if_index = ~0, vr_id, priority;
  u8 is_ipv6, is_add, is_del;
  int ret;

  is_ipv6 = is_add = is_del = 0;
  vr_id = priority = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (i, "vr_id %u", &vr_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "track-index %u priority %u", &track_sw_if_index,
			 &priority))
	{
	  vec_add2 (track_ifs, track_if, 1);
	  track_if->sw_if_index = ntohl (track_sw_if_index);
	  track_if->priority = priority;
	}
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "del"))
	is_del = 1;
      else
	break;
    }

  if (is_add == is_del)
    {
      errmsg ("One of add or del must be specified\n");
      ret = -99;
    }
  else if (sw_if_index == ~0)
    {
      errmsg ("VR interface not specified\n");
      return -99;
    }
  else if (!vr_id)
    {
      errmsg ("Invalid VR ID - must be between 1 and 255");
      return -99;
    }
  else if (vec_len (track_ifs) == 0)
    {
      errmsg ("No tracked interfaces specified for VR\n");
      return -99;
    }

  vec_foreach (track_if, track_ifs)
  {
    if (!track_if->priority)
      {
	errmsg ("Priority must be nonzero");
	vec_free (track_ifs);
	return -99;
      }
  }


  M2 (VRRP_VR_TRACK_IF_ADD_DEL, mp, vec_len (track_ifs) * sizeof (*track_if));

  mp->sw_if_index = htonl (sw_if_index);
  mp->vr_id = vr_id;
  mp->is_ipv6 = (is_ipv6 != 0);
  mp->is_add = is_add;
  mp->n_ifs = vec_len (track_ifs);
  clib_memcpy (mp->ifs, track_ifs, mp->n_ifs * sizeof (*track_if));

  S (mp);

  W (ret);
  return ret;
}

static int
api_vrrp_vr_track_if_dump (vat_main_t * vam)
{
  vrrp_test_main_t *vtm = &vrrp_test_main;
  unformat_input_t *i = vam->input;
  vl_api_vrrp_vr_track_if_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index = ~0, vr_id = 0;
  u8 is_ipv6 = 0, dump_all = 0;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for vrrp_vr_track_if_dump");
      return -99;
    }

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (i, "vr_id %u", &vr_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	break;
    }

  /* If no arguments were provided, dump all VRs */
  if ((sw_if_index == ~0) && !vr_id && !is_ipv6)
    dump_all = 1;

  /* If any arguments provided, sw_if_index and vr_id must be valid */
  else if (sw_if_index == ~0)
    {
      errmsg ("VR interface not specified\n");
      return -99;
    }
  else if (!vr_id)
    {
      errmsg ("Invalid VR ID - must be between 1 and 255");
      return -99;
    }

  M (VRRP_VR_TRACK_IF_DUMP, mp);

  mp->dump_all = dump_all;
  if (!dump_all)
    {
      mp->sw_if_index = htonl (sw_if_index);
      mp->vr_id = vr_id;
      mp->is_ipv6 = is_ipv6;
    }

  S (mp);

  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (vtm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

static void
  vl_api_vrrp_vr_track_if_details_t_handler
  (vl_api_vrrp_vr_track_if_details_t * mp)
{
  vat_main_t *vam = vrrp_test_main.vat_main;
  int i;

  for (i = 0; i < mp->n_ifs; i++)
    {
      fformat (vam->ofp, "VR sw_if_index %u vr_id %u IPv%d - "
	       "track sw_if_index %u priority %u\n",
	       ntohl (mp->sw_if_index), mp->vr_id, (mp->is_ipv6) ? 6 : 4,
	       ntohl (mp->ifs[i].sw_if_index), mp->ifs[i].priority);
    }

  fformat (vam->ofp, "\n");
}

static int
api_vrrp_vr_set_peers (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  u32 sw_if_index = ~0;
  u32 vr_id;
  u8 is_ipv6;
  u8 n_addrs4, n_addrs6;
  vl_api_vrrp_vr_set_peers_t *mp;
  vl_api_address_t *api_addr;
  ip46_address_t *ip_addr, *ip_addrs = 0;
  ip46_address_t addr;
  int ret = 0;

  n_addrs4 = n_addrs6 = 0;
  vr_id = is_ipv6 = 0;

  clib_memset (&addr, 0, sizeof (addr));

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (i, "vr_id %u", &vr_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (i, "%U", unformat_ip4_address, &addr.ip4))
	{
	  vec_add1 (ip_addrs, addr);
	  n_addrs4++;
	  clib_memset (&addr, 0, sizeof (addr));
	}
      else if (unformat (i, "%U", unformat_ip6_address, &addr.ip6))
	{
	  vec_add1 (ip_addrs, addr);
	  n_addrs6++;
	  clib_memset (&addr, 0, sizeof (addr));
	}
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("Interface not set\n");
      ret = -99;
    }
  else if (n_addrs4 && (n_addrs6 || is_ipv6))
    {
      errmsg ("Address family mismatch\n");
      ret = -99;
    }

  if (ret)
    goto done;

  /* Construct the API message */
  M2 (VRRP_VR_SET_PEERS, mp, vec_len (ip_addrs) * sizeof (*api_addr));

  mp->sw_if_index = ntohl (sw_if_index);
  mp->vr_id = vr_id;
  mp->is_ipv6 = (is_ipv6 != 0);

  mp->n_addrs = n_addrs4 + n_addrs6;
  api_addr = mp->addrs;

  vec_foreach (ip_addr, ip_addrs)
  {
    void *src, *dst;
    int len;

    if (is_ipv6)
      {
	api_addr->af = ADDRESS_IP6;
	src = &ip_addr->ip6;
	dst = &api_addr->un.ip6;
	len = sizeof (api_addr->un.ip6);
      }
    else
      {
	api_addr->af = ADDRESS_IP4;
	src = &ip_addr->ip4;
	dst = &api_addr->un.ip4;
	len = sizeof (api_addr->un.ip4);
      }
    clib_memcpy (dst, src, len);
    api_addr++;
  }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

done:
  vec_free (ip_addrs);

  return ret;
}

static int
api_vrrp_vr_peer_dump (vat_main_t * vam)
{
  vrrp_test_main_t *vtm = &vrrp_test_main;
  unformat_input_t *i = vam->input;
  vl_api_vrrp_vr_peer_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index = ~0, vr_id = 0;
  u8 is_ipv6 = 0;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for vrrp_vr_track_if_dump");
      return -99;
    }

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (i, "vr_id %u", &vr_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	break;
    }

  /* sw_if_index and vr_id must be valid */
  if (sw_if_index == ~0)
    {
      errmsg ("VR interface not specified\n");
      return -99;
    }
  else if (!vr_id)
    {
      errmsg ("Invalid VR ID - must be between 1 and 255");
      return -99;
    }

  M (VRRP_VR_PEER_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);
  mp->vr_id = vr_id;
  mp->is_ipv6 = is_ipv6;

  S (mp);

  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (vtm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_vrrp_vr_peer_details_t_handler (vl_api_vrrp_vr_peer_details_t * mp)
{
  vat_main_t *vam = vrrp_test_main.vat_main;
  int i;

  fformat (vam->ofp, "sw_if_index %u vr_id %u IPv%d ",
	   ntohl (mp->sw_if_index), mp->vr_id, (mp->is_ipv6) ? 6 : 4);

  fformat (vam->ofp, "peer addresses: ");

  for (i = 0; i < mp->n_peer_addrs; i++)
    {
      vl_api_address_t *addr = mp->peer_addrs + i;

      fformat (vam->ofp, "%U ",
	       (addr->af) ? format_ip6_address : format_ip4_address,
	       (u8 *) & addr->un);
    }

  fformat (vam->ofp, "\n");
}

#include <vrrp/vrrp.api_test.c>
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
