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

#include <vnet/ip6-nd/ip6_nd.h>
#include <vnet/ip6-nd/ip6_ra.h>

#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <vnet/ip6-nd/ip6_nd.api_enum.h>
#include <vnet/ip6-nd/ip6_nd.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 ip6_nd_base_msg_id;
#define REPLY_MSG_ID_BASE ip6_nd_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
send_ip6nd_proxy_details (vl_api_registration_t * reg,
			  u32 context,
			  const ip46_address_t * addr, u32 sw_if_index)
{
  vl_api_ip6nd_proxy_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_IP6ND_PROXY_DETAILS);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);

  ip6_address_encode (&addr->ip6, mp->ip);

  vl_api_send_msg (reg, (u8 *) mp);
}

typedef struct api_ip6nd_proxy_fib_table_walk_ctx_t_
{
  u32 *indices;
} api_ip6nd_proxy_fib_table_walk_ctx_t;

static fib_table_walk_rc_t
api_ip6nd_proxy_fib_table_walk (fib_node_index_t fei, void *arg)
{
  api_ip6nd_proxy_fib_table_walk_ctx_t *ctx = arg;

  if (fib_entry_is_sourced (fei, FIB_SOURCE_IP6_ND_PROXY))
    {
      vec_add1 (ctx->indices, fei);
    }

  return (FIB_TABLE_WALK_CONTINUE);
}

static void
vl_api_ip6nd_proxy_dump_t_handler (vl_api_ip6nd_proxy_dump_t * mp)
{
  ip6_main_t *im6 = &ip6_main;
  u32 fib_index;
  api_ip6nd_proxy_fib_table_walk_ctx_t ctx = {
    .indices = NULL,
  };
  fib_node_index_t *feip;
  const fib_prefix_t *pfx;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach_index (fib_index, im6->fibs)
    {
      fib_table_walk (fib_index, FIB_PROTOCOL_IP6,
		      api_ip6nd_proxy_fib_table_walk, &ctx);
    }
  /* *INDENT-ON* */

  vec_sort_with_function (ctx.indices, fib_entry_cmp_for_sort);

  vec_foreach (feip, ctx.indices)
  {
    pfx = fib_entry_get_prefix (*feip);

    send_ip6nd_proxy_details (reg,
			      mp->context,
			      &pfx->fp_addr,
			      fib_entry_get_resolving_interface (*feip));
  }

  vec_free (ctx.indices);
}

static void
vl_api_ip6nd_proxy_enable_disable_t_handler (
  vl_api_ip6nd_proxy_enable_disable_t *mp)
{
  vl_api_ip6nd_proxy_enable_disable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_enable)
    rv = ip6_nd_proxy_enable_disable (ntohl (mp->sw_if_index), 1);
  else
    rv = ip6_nd_proxy_enable_disable (ntohl (mp->sw_if_index), 0);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IP6ND_PROXY_ENABLE_DISABLE_REPLY);
}

static void
vl_api_ip6nd_proxy_add_del_t_handler (vl_api_ip6nd_proxy_add_del_t * mp)
{
  vl_api_ip6nd_proxy_add_del_reply_t *rmp;
  ip6_address_t ip6;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  ip6_address_decode (mp->ip, &ip6);
  if (mp->is_add)
    rv = ip6_nd_proxy_add (ntohl (mp->sw_if_index), &ip6);
  else
    rv = ip6_nd_proxy_del (ntohl (mp->sw_if_index), &ip6);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IP6ND_PROXY_ADD_DEL_REPLY);
}

static void
  vl_api_sw_interface_ip6nd_ra_config_t_handler
  (vl_api_sw_interface_ip6nd_ra_config_t * mp)
{
  vl_api_sw_interface_ip6nd_ra_config_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;
  u8 is_no, suppress, managed, other, ll_option, send_unicast, cease,
    default_router;

  is_no = mp->is_no == 1;
  suppress = mp->suppress == 1;
  managed = mp->managed == 1;
  other = mp->other == 1;
  ll_option = mp->ll_option == 1;
  send_unicast = mp->send_unicast == 1;
  cease = mp->cease == 1;
  default_router = mp->default_router == 1;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ip6_ra_config (vm, ntohl (mp->sw_if_index),
		      suppress, managed, other,
		      ll_option, send_unicast, cease,
		      default_router, ntohl (mp->lifetime),
		      ntohl (mp->initial_count),
		      ntohl (mp->initial_interval),
		      ntohl (mp->max_interval),
		      ntohl (mp->min_interval), is_no);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_IP6ND_RA_CONFIG_REPLY);
}

static void
  vl_api_sw_interface_ip6nd_ra_prefix_t_handler
  (vl_api_sw_interface_ip6nd_ra_prefix_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sw_interface_ip6nd_ra_prefix_reply_t *rmp;
  fib_prefix_t pfx;
  int rv = 0;
  u8 is_no, use_default, no_advertise, off_link, no_autoconfig, no_onlink;

  VALIDATE_SW_IF_INDEX (mp);

  ip_prefix_decode (&mp->prefix, &pfx);
  is_no = mp->is_no == 1;
  use_default = mp->use_default == 1;
  no_advertise = mp->no_advertise == 1;
  off_link = mp->off_link == 1;
  no_autoconfig = mp->no_autoconfig == 1;
  no_onlink = mp->no_onlink == 1;

  rv = ip6_ra_prefix (vm, ntohl (mp->sw_if_index),
		      &pfx.fp_addr.ip6,
		      pfx.fp_len, use_default,
		      ntohl (mp->val_lifetime),
		      ntohl (mp->pref_lifetime), no_advertise,
		      off_link, no_autoconfig, no_onlink, is_no);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_IP6ND_RA_PREFIX_REPLY);
}

static void
ip6_radv_prefix_encode (f64 now, const ip6_radv_prefix_t *in,
			vl_api_ip6nd_ra_prefix_t *out)
{
  fib_prefix_t in_ip6_pfx = {
    .fp_addr = {
      .ip6 = in->prefix,
    },
    .fp_len = in->prefix_len,
    .fp_proto = FIB_PROTOCOL_IP6,
  };

  ip_prefix_encode (&in_ip6_pfx, &out->prefix);

  out->onlink_flag = in->adv_on_link_flag;
  out->autonomous_flag = in->adv_autonomous_flag;
  out->val_lifetime = htonl (in->adv_valid_lifetime_in_secs);
  out->pref_lifetime = htonl (in->adv_pref_lifetime_in_secs);

  if (in->adv_valid_lifetime_in_secs != ~0)
    {
      out->valid_lifetime_expires =
	clib_host_to_net_f64 (in->valid_lifetime_expires - now);
    }

  if (in->adv_pref_lifetime_in_secs != ~0)
    {
      out->pref_lifetime_expires =
	clib_host_to_net_f64 (in->pref_lifetime_expires - now);
    }

  out->decrement_lifetime_flag = in->decrement_lifetime_flag;
  out->no_advertise = (in->enabled == 0);
}

static void
send_sw_interface_ip6nd_ra_details (vl_api_registration_t *reg, u32 context,
				    ip6_ra_t *radv_info)
{
  vl_api_sw_interface_ip6nd_ra_details_t *rmp = 0;
  vl_api_ip6nd_ra_prefix_t *api_radv_pfx;
  u32 n_prefixes = pool_elts (radv_info->adv_prefixes_pool);
  ip6_radv_prefix_t *radv_pfx;
  u32 msg_size = sizeof (*rmp) + n_prefixes * sizeof (*api_radv_pfx);
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);

  rmp = vl_msg_api_alloc (msg_size);
  if (!rmp)
    return;
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_SW_INTERFACE_IP6ND_RA_DETAILS + REPLY_MSG_ID_BASE);
  rmp->context = context;

  rmp->sw_if_index = htonl (radv_info->sw_if_index);
  rmp->cur_hop_limit = radv_info->curr_hop_limit;
  rmp->adv_managed_flag = radv_info->adv_managed_flag;
  rmp->adv_other_flag = radv_info->adv_other_flag;
  rmp->adv_router_lifetime = htons (radv_info->adv_router_lifetime_in_sec);
  rmp->adv_neighbor_reachable_time =
    htonl (radv_info->adv_neighbor_reachable_time_in_msec);
  rmp->adv_retransmit_interval = htonl (
    radv_info->adv_time_in_msec_between_retransmitted_neighbor_solicitations);
  rmp->adv_link_mtu = htonl (radv_info->adv_link_mtu);
  rmp->send_radv = radv_info->send_radv;
  rmp->cease_radv = radv_info->cease_radv;
  rmp->send_unicast = radv_info->send_unicast;
  rmp->adv_link_layer_address = radv_info->adv_link_layer_address;
  rmp->max_radv_interval = clib_host_to_net_f64 (radv_info->max_radv_interval);
  rmp->min_radv_interval = clib_host_to_net_f64 (radv_info->min_radv_interval);

  if (radv_info->last_radv_time > 0.0)
    {
      rmp->last_radv_time =
	clib_host_to_net_f64 (now - radv_info->last_radv_time);
    }

  if ((radv_info->next_multicast_time - radv_info->last_multicast_time) > 0.0)
    {
      rmp->last_multicast_time =
	clib_host_to_net_f64 (now - radv_info->last_multicast_time);
      rmp->next_multicast_time =
	clib_host_to_net_f64 (radv_info->next_multicast_time - now);
    }

  rmp->initial_adverts_count = htonl (radv_info->initial_adverts_count);
  rmp->initial_adverts_interval =
    clib_host_to_net_f64 (radv_info->initial_adverts_interval);
  rmp->initial_adverts_sent = (radv_info->initial_adverts_sent == 0);
  rmp->n_advertisements_sent = htonl (radv_info->n_advertisements_sent);
  rmp->n_solicitations_rcvd = htonl (radv_info->n_solicitations_rcvd);
  rmp->n_solicitations_dropped = htonl (radv_info->n_solicitations_dropped);
  rmp->n_prefixes = htonl (n_prefixes);

  api_radv_pfx = rmp->prefixes;
  pool_foreach (radv_pfx, radv_info->adv_prefixes_pool)
    {
      ip6_radv_prefix_encode (now, radv_pfx, api_radv_pfx);

      api_radv_pfx++;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

typedef struct
{
  u32 *sw_if_indices;
} api_dump_ip6_ra_itf_walk_ctx_t;

static walk_rc_t
api_dump_ip6_ra_itf_walk_fn (u32 sw_if_index, void *arg)
{
  api_dump_ip6_ra_itf_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->sw_if_indices, sw_if_index);

  return (WALK_CONTINUE);
}

static void
vl_api_sw_interface_ip6nd_ra_dump_t_handler (
  vl_api_sw_interface_ip6nd_ra_dump_t *mp)
{
  vl_api_registration_t *reg;
  u32 sw_if_index;
  ip6_ra_t *radv_info;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (sw_if_index == INDEX_INVALID)
    {
      /* dump all interfaces */

      api_dump_ip6_ra_itf_walk_ctx_t ctx = {
	.sw_if_indices = NULL,
      };
      u32 *sw_if_i;

      ip6_ra_itf_walk (api_dump_ip6_ra_itf_walk_fn, &ctx);

      vec_foreach (sw_if_i, ctx.sw_if_indices)
	{
	  radv_info = ip6_ra_get_itf (*sw_if_i);
	  if (radv_info != NULL)
	    {
	      send_sw_interface_ip6nd_ra_details (reg, mp->context, radv_info);
	    }
	}

      vec_free (ctx.sw_if_indices);
    }
  else
    {
      /* dump a single interface */

      radv_info = ip6_ra_get_itf (sw_if_index);
      if (radv_info != NULL)
	{
	  send_sw_interface_ip6nd_ra_details (reg, mp->context, radv_info);
	}
    }
}

static void
  vl_api_ip6nd_send_router_solicitation_t_handler
  (vl_api_ip6nd_send_router_solicitation_t * mp)
{
  vl_api_ip6nd_send_router_solicitation_reply_t *rmp;
  icmp6_send_router_solicitation_params_t params;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_IP6ND_SEND_ROUTER_SOLICITATION_REPLY);

  if (rv != 0)
    return;

  params.irt = ntohl (mp->irt);
  params.mrt = ntohl (mp->mrt);
  params.mrc = ntohl (mp->mrc);
  params.mrd = ntohl (mp->mrd);

  icmp6_send_router_solicitation (vm, ntohl (mp->sw_if_index), mp->stop,
				  &params);
}

static void
ip6_ra_handle_report (const ip6_ra_report_t * rap)
{
  /* *INDENT-OFF* */
  vpe_client_registration_t *rp;

  pool_foreach (rp, vpe_api_main.ip6_ra_events_registrations)
   {
    vl_api_registration_t *vl_reg;

    vl_reg = vl_api_client_index_to_registration (rp->client_index);

    if (vl_reg && vl_api_can_send_msg (vl_reg))
      {
        vl_api_ip6_ra_prefix_info_t *prefix;
        vl_api_ip6_ra_event_t *event;

        u32 event_size = (sizeof (vl_api_ip6_ra_event_t) +
                          vec_len (rap->prefixes) *
                          sizeof (vl_api_ip6_ra_prefix_info_t));
        event = vl_msg_api_alloc_zero (event_size);

        event->_vl_msg_id = htons (VL_API_IP6_RA_EVENT + REPLY_MSG_ID_BASE);
        event->client_index = rp->client_index;
        event->pid = rp->client_pid;
        event->sw_if_index = clib_host_to_net_u32 (rap->sw_if_index);

        ip6_address_encode (&rap->router_address,
                            event->router_addr);

        event->current_hop_limit = rap->current_hop_limit;
        event->flags = rap->flags;
        event->router_lifetime_in_sec =
          clib_host_to_net_u16 (rap->router_lifetime_in_sec);
        event->neighbor_reachable_time_in_msec =
          clib_host_to_net_u32 (rap->neighbor_reachable_time_in_msec);
        event->time_in_msec_between_retransmitted_neighbor_solicitations =
          clib_host_to_net_u32 (rap->time_in_msec_between_retransmitted_neighbor_solicitations);
        event->n_prefixes = clib_host_to_net_u32 (vec_len (rap->prefixes));

        prefix = event->prefixes;
          // (typeof (prefix)) event->prefixes;
        u32 j;
        for (j = 0; j < vec_len (rap->prefixes); j++)
          {
            ra_report_prefix_info_t *info = &rap->prefixes[j];
            ip_prefix_encode(&info->prefix, &prefix->prefix);
            prefix->flags = info->flags;
            prefix->valid_time = clib_host_to_net_u32 (info->valid_time);
            prefix->preferred_time =
              clib_host_to_net_u32 (info->preferred_time);
            prefix++;
          }

        vl_api_send_msg (vl_reg, (u8 *) event);
      }
  }
  /* *INDENT-ON* */
}

static void
vl_api_want_ip6_ra_events_t_handler (vl_api_want_ip6_ra_events_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_want_ip6_ra_events_reply_t *rmp;
  int rv = 0, had_reg, have_reg;

  had_reg = hash_elts (am->ip6_ra_events_registration_hash);
  uword *p = hash_get (am->ip6_ra_events_registration_hash, mp->client_index);
  vpe_client_registration_t *rp;
  if (p)
    {
      if (mp->enable)
	{
	  clib_warning ("pid %d: already enabled...", ntohl (mp->pid));
	  rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  goto reply;
	}
      else
	{
	  rp = pool_elt_at_index (am->ip6_ra_events_registrations, p[0]);
	  pool_put (am->ip6_ra_events_registrations, rp);
	  hash_unset (am->ip6_ra_events_registration_hash, mp->client_index);
	  goto reply;
	}
    }
  if (mp->enable == 0)
    {
      clib_warning ("pid %d: already disabled...", ntohl (mp->pid));
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto reply;
    }
  pool_get (am->ip6_ra_events_registrations, rp);
  rp->client_index = mp->client_index;
  rp->client_pid = ntohl (mp->pid);
  hash_set (am->ip6_ra_events_registration_hash, rp->client_index,
	    rp - am->ip6_ra_events_registrations);

reply:
  have_reg = hash_elts (am->ip6_ra_events_registration_hash);

  if (!had_reg && have_reg)
    ip6_ra_report_register (ip6_ra_handle_report);
  else if (had_reg && !have_reg)
    ip6_ra_report_unregister (ip6_ra_handle_report);

  REPLY_MACRO (VL_API_WANT_IP6_RA_EVENTS_REPLY);
}

static clib_error_t *
want_ip6_ra_events_reaper (u32 client_index)
{
  vpe_api_main_t *am = &vpe_api_main;
  vpe_client_registration_t *rp;
  uword *p;

  p = hash_get (am->ip6_ra_events_registration_hash, client_index);

  if (p)
    {
      rp = pool_elt_at_index (am->ip6_ra_events_registrations, p[0]);
      pool_put (am->ip6_ra_events_registrations, rp);
      hash_unset (am->ip6_ra_events_registration_hash, client_index);
    }
  return (NULL);
}

VL_MSG_API_REAPER_FUNCTION (want_ip6_ra_events_reaper);

#include <vnet/ip6-nd/ip6_nd.api.c>

static clib_error_t *
ip6_nd_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  ip6_nd_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (ip6_nd_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
