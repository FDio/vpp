/*
 * vrrp.c - vpp vrrp plug-in
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vrrp/vrrp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <vrrp/vrrp.api_enum.h>
#include <vrrp/vrrp.api_types.h>

#define REPLY_MSG_ID_BASE vrrp_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handlers */
static void
vl_api_vrrp_vr_update_t_handler (vl_api_vrrp_vr_update_t *mp)
{
  vl_api_vrrp_vr_update_reply_t *rmp;
  vrrp_vr_config_t vr_conf;
  u32 api_flags;
  u32 vrrp_index = INDEX_INVALID;
  ip46_address_t *addrs = 0;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  api_flags = htonl (mp->flags);

  clib_memset (&vr_conf, 0, sizeof (vr_conf));

  vr_conf.sw_if_index = ntohl (mp->sw_if_index);
  vr_conf.vr_id = mp->vr_id;
  vr_conf.priority = mp->priority;
  vr_conf.adv_interval = ntohs (mp->interval);

  if (api_flags & VRRP_API_VR_PREEMPT)
    vr_conf.flags |= VRRP_VR_PREEMPT;

  if (api_flags & VRRP_API_VR_ACCEPT)
    vr_conf.flags |= VRRP_VR_ACCEPT;

  if (api_flags & VRRP_API_VR_UNICAST)
    vr_conf.flags |= VRRP_VR_UNICAST;

  if (api_flags & VRRP_API_VR_IPV6)
    vr_conf.flags |= VRRP_VR_IPV6;

  int i;
  for (i = 0; i < mp->n_addrs; i++)
    {
      ip46_address_t *addr;
      void *src, *dst;
      int len;

      vec_add2 (addrs, addr, 1);

      if (ntohl (mp->addrs[i].af) == ADDRESS_IP4)
	{
	  src = &mp->addrs[i].un.ip4;
	  dst = &addr->ip4;
	  len = sizeof (addr->ip4);
	}
      else
	{
	  src = &mp->addrs[i].un.ip6;
	  dst = &addr->ip6;
	  len = sizeof (addr->ip6);
	}

      clib_memcpy (dst, src, len);
    }

  vr_conf.vr_addrs = addrs;

  if (vr_conf.priority == 0)
    {
      clib_warning ("VR priority must be > 0");
      rv = VNET_API_ERROR_INVALID_VALUE;
    }
  else if (vr_conf.adv_interval == 0)
    {
      clib_warning ("VR advertisement interval must be > 0");
      rv = VNET_API_ERROR_INVALID_VALUE;
    }
  else if (vr_conf.vr_id == 0)
    {
      clib_warning ("VR ID must be > 0");
      rv = VNET_API_ERROR_INVALID_VALUE;
    }
  else
    {
      vrrp_index = ntohl (mp->vrrp_index);
      rv = vrrp_vr_update (&vrrp_index, &vr_conf);
    }

  vec_free (addrs);

  BAD_SW_IF_INDEX_LABEL;
  // clang-format off
  REPLY_MACRO2 (VL_API_VRRP_VR_UPDATE_REPLY,
  ({
    rmp->vrrp_index = htonl (vrrp_index);
  }));
  // clang-format on
}

static void
vl_api_vrrp_vr_del_t_handler (vl_api_vrrp_vr_del_t *mp)
{
  vl_api_vrrp_vr_del_reply_t *rmp;
  int rv;

  rv = vrrp_vr_del (ntohl (mp->vrrp_index));

  REPLY_MACRO (VL_API_VRRP_VR_DEL_REPLY);
}

static void
vl_api_vrrp_vr_add_del_t_handler (vl_api_vrrp_vr_add_del_t * mp)
{
  vl_api_vrrp_vr_add_del_reply_t *rmp;
  vrrp_vr_config_t vr_conf;
  u32 api_flags;
  ip46_address_t *addrs = 0;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  api_flags = htonl (mp->flags);

  clib_memset (&vr_conf, 0, sizeof (vr_conf));

  vr_conf.sw_if_index = ntohl (mp->sw_if_index);
  vr_conf.vr_id = mp->vr_id;
  vr_conf.priority = mp->priority;
  vr_conf.adv_interval = ntohs (mp->interval);

  if (api_flags & VRRP_API_VR_PREEMPT)
    vr_conf.flags |= VRRP_VR_PREEMPT;

  if (api_flags & VRRP_API_VR_ACCEPT)
    vr_conf.flags |= VRRP_VR_ACCEPT;

  if (api_flags & VRRP_API_VR_UNICAST)
    vr_conf.flags |= VRRP_VR_UNICAST;

  if (api_flags & VRRP_API_VR_IPV6)
    vr_conf.flags |= VRRP_VR_IPV6;

  if (mp->is_add)
    {
      int i;

      for (i = 0; i < mp->n_addrs; i++)
	{
	  ip46_address_t *addr;
	  void *src, *dst;
	  int len;

	  vec_add2 (addrs, addr, 1);

	  if (ntohl (mp->addrs[i].af) == ADDRESS_IP4)
	    {
	      src = &mp->addrs[i].un.ip4;
	      dst = &addr->ip4;
	      len = sizeof (addr->ip4);
	    }
	  else
	    {
	      src = &mp->addrs[i].un.ip6;
	      dst = &addr->ip6;
	      len = sizeof (addr->ip6);
	    }

	  clib_memcpy (dst, src, len);
	}

      vr_conf.vr_addrs = addrs;
    }

  if (vr_conf.priority == 0)
    {
      clib_warning ("VR priority must be > 0");
      rv = VNET_API_ERROR_INVALID_VALUE;
    }
  else if (vr_conf.adv_interval == 0)
    {
      clib_warning ("VR advertisement interval must be > 0");
      rv = VNET_API_ERROR_INVALID_VALUE;
    }
  else if (vr_conf.vr_id == 0)
    {
      clib_warning ("VR ID must be > 0");
      rv = VNET_API_ERROR_INVALID_VALUE;
    }
  else
    rv = vrrp_vr_add_del (mp->is_add, &vr_conf, NULL);

  vec_free (addrs);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_VRRP_VR_ADD_DEL_REPLY);
}

static vl_api_vrrp_vr_state_t
vrrp_vr_state_encode (vrrp_vr_state_t vr_state)
{
  if (vr_state == VRRP_VR_STATE_BACKUP)
    return VRRP_API_VR_STATE_BACKUP;
  if (vr_state == VRRP_VR_STATE_MASTER)
    return VRRP_API_VR_STATE_MASTER;
  if (vr_state == VRRP_VR_STATE_INTF_DOWN)
    return VRRP_API_VR_STATE_INTF_DOWN;

  return VRRP_API_VR_STATE_INIT;
}

static void
send_vrrp_vr_details (vrrp_vr_t * vr, vl_api_registration_t * reg,
		      u32 context)
{
  vrrp_main_t *vmp = &vrrp_main;
  vl_api_vrrp_vr_details_t *mp;
  int n_addrs, msg_size;
  ip46_address_t *addr;
  vl_api_address_t *api_addr;
  u32 api_flags = 0;

  n_addrs = vec_len (vr->config.vr_addrs);
  msg_size = sizeof (*mp) + n_addrs * sizeof (*api_addr);
  mp = vl_msg_api_alloc (msg_size);
  if (!mp)
    return;
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id = htons (VL_API_VRRP_VR_DETAILS + vmp->msg_id_base);
  mp->context = context;

  /* config */
  mp->config.sw_if_index = htonl (vr->config.sw_if_index);
  mp->config.vr_id = vr->config.vr_id;
  mp->config.priority = vr->config.priority;
  mp->config.interval = htons (vr->config.adv_interval);

  if (vr->config.flags & VRRP_VR_PREEMPT)
    api_flags |= VRRP_API_VR_PREEMPT;
  if (vr->config.flags & VRRP_VR_ACCEPT)
    api_flags |= VRRP_API_VR_ACCEPT;
  if (vrrp_vr_is_unicast (vr))
    api_flags |= VRRP_API_VR_UNICAST;
  if (vrrp_vr_is_ipv6 (vr))
    api_flags |= VRRP_API_VR_IPV6;

  mp->config.flags = htonl (api_flags);

  /* runtime */
  mp->runtime.state = htonl (vrrp_vr_state_encode (vr->runtime.state));

  mp->runtime.master_adv_int = htons (vr->runtime.master_adv_int);
  mp->runtime.skew = htons (vr->runtime.skew);
  mp->runtime.master_down_int = htons (vr->runtime.master_down_int);
  clib_memcpy (&mp->runtime.mac, &vr->runtime.mac, sizeof (vr->runtime.mac));

  mp->runtime.tracking.interfaces_dec = htonl (vr->tracking.interfaces_dec);
  mp->runtime.tracking.priority = vrrp_vr_priority (vr);

  /* addrs */
  mp->n_addrs = vec_len (vr->config.vr_addrs);
  api_addr = mp->addrs;
  vec_foreach (addr, vr->config.vr_addrs)
  {
    void *src, *dst;
    size_t len;

    if (vrrp_vr_is_ipv6 (vr))
      {
	api_addr->af = ADDRESS_IP6;
	dst = &api_addr->un.ip6;
	src = &addr->ip6;
	len = sizeof (addr->ip6);
      }
    else
      {
	api_addr->af = ADDRESS_IP4;
	dst = &api_addr->un.ip4;
	src = &addr->ip4;
	len = sizeof (addr->ip4);
      }
    clib_memcpy (dst, src, len);
    api_addr++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_vrrp_vr_dump_t_handler (vl_api_vrrp_vr_dump_t * mp)
{
  vrrp_main_t *vmp = &vrrp_main;
  vl_api_registration_t *reg;
  vrrp_vr_t *vr;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = htonl (mp->sw_if_index);

  /* *INDENT-OFF* */
  pool_foreach (vr, vmp->vrs)  {

    if (sw_if_index && (sw_if_index != ~0) &&
	(sw_if_index != vr->config.sw_if_index))
      continue;

    send_vrrp_vr_details (vr, reg, mp->context);
  }
  /* *INDENT-ON* */
}

static void
vl_api_vrrp_vr_start_stop_t_handler (vl_api_vrrp_vr_start_stop_t * mp)
{
  vl_api_vrrp_vr_start_stop_reply_t *rmp;
  vrrp_vr_key_t vr_key;
  int rv;

  clib_memset (&vr_key, 0, sizeof (vr_key));

  vr_key.sw_if_index = ntohl (mp->sw_if_index);
  vr_key.vr_id = mp->vr_id;
  vr_key.is_ipv6 = (mp->is_ipv6 != 0);

  rv = vrrp_vr_start_stop ((mp->is_start != 0), &vr_key);

  REPLY_MACRO (VL_API_VRRP_VR_START_STOP_REPLY);
}

static void
vl_api_vrrp_vr_set_peers_t_handler (vl_api_vrrp_vr_set_peers_t * mp)
{
  vl_api_vrrp_vr_set_peers_reply_t *rmp;
  vrrp_vr_key_t vr_key;
  ip46_address_t *peer_addrs = 0;
  int i;
  int rv;

  clib_memset (&vr_key, 0, sizeof (vr_key));

  vr_key.sw_if_index = ntohl (mp->sw_if_index);
  vr_key.vr_id = mp->vr_id;
  vr_key.is_ipv6 = (mp->is_ipv6 != 0);

  for (i = 0; i < mp->n_addrs; i++)
    {
      ip46_address_t *peer;

      vec_add2 (peer_addrs, peer, 1);

      if (mp->is_ipv6)
	clib_memcpy (&peer->ip6, mp->addrs[i].un.ip6, 16);
      else
	clib_memcpy (&peer->ip4, mp->addrs[i].un.ip4, 4);
    }

  rv = vrrp_vr_set_peers (&vr_key, peer_addrs);

  vec_free (peer_addrs);
  REPLY_MACRO (VL_API_VRRP_VR_SET_PEERS_REPLY);
}

static void
send_vrrp_vr_peer_details (vrrp_vr_t * vr, vl_api_registration_t * reg,
			   u32 context)
{
  vrrp_main_t *vmp = &vrrp_main;
  vl_api_vrrp_vr_peer_details_t *mp;
  int n_addrs, msg_size;
  ip46_address_t *addr;
  vl_api_address_t *api_addr;

  n_addrs = vec_len (vr->config.peer_addrs);
  msg_size = sizeof (*mp) + n_addrs * sizeof (*api_addr);
  mp = vl_msg_api_alloc (msg_size);
  if (!mp)
    return;
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id = htons (VL_API_VRRP_VR_PEER_DETAILS + vmp->msg_id_base);
  mp->context = context;

  mp->sw_if_index = htonl (vr->config.sw_if_index);
  mp->vr_id = vr->config.vr_id;
  mp->is_ipv6 = vrrp_vr_is_ipv6 (vr);

  /* addrs */
  mp->n_peer_addrs = n_addrs;
  api_addr = mp->peer_addrs;
  vec_foreach (addr, vr->config.peer_addrs)
  {
    void *src, *dst;
    size_t len;

    if (vrrp_vr_is_ipv6 (vr))
      {
	api_addr->af = ADDRESS_IP6;
	dst = &api_addr->un.ip6;
	src = &addr->ip6;
	len = sizeof (addr->ip6);
      }
    else
      {
	api_addr->af = ADDRESS_IP4;
	dst = &api_addr->un.ip4;
	src = &addr->ip4;
	len = sizeof (addr->ip4);
      }
    clib_memcpy (dst, src, len);
    api_addr++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_vrrp_vr_peer_dump_t_handler (vl_api_vrrp_vr_peer_dump_t * mp)
{
  vrrp_main_t *vmp = &vrrp_main;
  vl_api_registration_t *reg;
  vrrp_vr_t *vr;
  vrrp_vr_key_t vr_key;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vr_key.sw_if_index = ntohl (mp->sw_if_index);

  if (vr_key.sw_if_index && (vr_key.sw_if_index != ~0))
    {
      uword *p;
      u32 vr_index = ~0;

      vr_key.vr_id = mp->vr_id;
      vr_key.is_ipv6 = mp->is_ipv6;

      p = mhash_get (&vmp->vr_index_by_key, &vr_key);
      if (!p)
	return;

      vr_index = p[0];
      vr = pool_elt_at_index (vmp->vrs, vr_index);
      send_vrrp_vr_peer_details (vr, reg, mp->context);

      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (vr, vmp->vrs)  {

    if (!vec_len (vr->config.peer_addrs))
      continue;

    send_vrrp_vr_peer_details (vr, reg, mp->context);

  }
  /* *INDENT-ON* */
}

static void
  vl_api_vrrp_vr_track_if_add_del_t_handler
  (vl_api_vrrp_vr_track_if_add_del_t * mp)
{
  vl_api_vrrp_vr_track_if_add_del_reply_t *rmp;
  vrrp_vr_t *vr;
  vrrp_vr_tracking_if_t *track_if, *track_ifs = 0;
  int rv = 0, i;

  /* lookup VR and return error if it does not exist */
  vr =
    vrrp_vr_lookup (ntohl (mp->sw_if_index), mp->vr_id, (mp->is_ipv6 != 0));
  if (!vr)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  for (i = 0; i < mp->n_ifs; i++)
    {
      vl_api_vrrp_vr_track_if_t *api_track_if = &mp->ifs[i];

      vec_add2 (track_ifs, track_if, 1);
      track_if->sw_if_index = ntohl (api_track_if->sw_if_index);
      track_if->priority = api_track_if->priority;
    }

  rv = vrrp_vr_tracking_ifs_add_del (vr, track_ifs, mp->is_add != 0);

done:
  vec_free (track_ifs);
  REPLY_MACRO (VL_API_VRRP_VR_TRACK_IF_ADD_DEL_REPLY);
}

static void
send_vrrp_vr_track_if_details (vrrp_vr_t * vr, vl_api_registration_t * reg,
			       u32 context)
{
  vrrp_main_t *vmp = &vrrp_main;
  vl_api_vrrp_vr_track_if_details_t *mp;
  int n_ifs, msg_size;
  vl_api_vrrp_vr_track_if_t *api_track_if;
  vrrp_vr_tracking_if_t *track_if;

  if (!vr)
    return;

  n_ifs = vec_len (vr->tracking.interfaces);
  msg_size = sizeof (*mp) + n_ifs * sizeof (*api_track_if);
  mp = vl_msg_api_alloc (msg_size);
  if (!mp)
    return;
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id = htons (VL_API_VRRP_VR_TRACK_IF_DETAILS + vmp->msg_id_base);
  mp->context = context;

  mp->sw_if_index = htonl (vr->config.sw_if_index);
  mp->vr_id = vr->config.vr_id;
  mp->is_ipv6 = vrrp_vr_is_ipv6 (vr);

  /* tracked interfaces */
  mp->n_ifs = n_ifs;
  api_track_if = mp->ifs;
  vec_foreach (track_if, vr->tracking.interfaces)
  {
    api_track_if->sw_if_index = htonl (track_if->sw_if_index);
    api_track_if->priority = track_if->priority;
    api_track_if += 1;
  }

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_vrrp_vr_track_if_dump_t_handler (vl_api_vrrp_vr_track_if_dump_t * mp)
{
  vrrp_main_t *vmp = &vrrp_main;
  vl_api_registration_t *reg;
  vrrp_vr_t *vr;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (!mp->dump_all)
    {
      vr = vrrp_vr_lookup (ntohl (mp->sw_if_index), mp->vr_id, mp->is_ipv6);
      send_vrrp_vr_track_if_details (vr, reg, mp->context);

      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (vr, vmp->vrs)  {

    if (!vec_len (vr->tracking.interfaces))
      continue;

    send_vrrp_vr_track_if_details (vr, reg, mp->context);

  }
  /* *INDENT-ON* */
}

static void
send_vrrp_vr_event (vpe_client_registration_t * reg,
		    vl_api_registration_t * vl_reg,
		    vrrp_vr_t * vr, vrrp_vr_state_t new_state)
{
  vrrp_main_t *vmp = &vrrp_main;
  vl_api_vrrp_vr_event_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_VRRP_VR_EVENT + vmp->msg_id_base);
  mp->client_index = reg->client_index;
  mp->pid = reg->client_pid;
  mp->vr.sw_if_index = ntohl (vr->config.sw_if_index);
  mp->vr.vr_id = vr->config.vr_id;
  mp->vr.is_ipv6 = ((vr->config.flags & VRRP_VR_IPV6) != 0);

  mp->old_state = htonl (vrrp_vr_state_encode (vr->runtime.state));
  mp->new_state = htonl (vrrp_vr_state_encode (new_state));

  vl_api_send_msg (vl_reg, (u8 *) mp);
}

void
vrrp_vr_event (vrrp_vr_t * vr, vrrp_vr_state_t new_state)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vpe_client_registration_t *reg;
  vl_api_registration_t *vl_reg;

  /* *INDENT-OFF* */
  pool_foreach (reg, vam->vrrp_vr_events_registrations)
   {
    vl_reg = vl_api_client_index_to_registration (reg->client_index);
    if (vl_reg)
      send_vrrp_vr_event (reg, vl_reg, vr, new_state);
  }
  /* *INDENT-ON* */
}

pub_sub_handler (vrrp_vr_events, VRRP_VR_EVENTS);

/* Set up the API message handling tables */
#include <vrrp/vrrp.api.c>
clib_error_t *
vrrp_plugin_api_hookup (vlib_main_t * vm)
{
  vrrp_main_t *vmp = &vrrp_main;

  /* Ask for a correctly-sized block of API message decode slots */
  vmp->msg_id_base = setup_message_id_table ();

  return 0;
}

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
