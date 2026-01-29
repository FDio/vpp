/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/session_stats/session_stats.h>
#include <vlib/stats/stats.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <sfdp_services/session_stats/session_stats.api_enum.h>
#include <sfdp_services/session_stats/session_stats.api_types.h>
#include <vnet/sfdp/sfdp_types_funcs.h>

#define REPLY_MSG_ID_BASE ssm->msg_id_base
#include <vlibapi/api_helper_macros.h>

extern void sfdp_session_stats_periodic_export_enable (vlib_main_t *vm, f64 interval);
extern void sfdp_session_stats_periodic_export_disable (vlib_main_t *vm);
extern void sfdp_session_stats_export_now (vlib_main_t *vm);

/* TODO - can some of these API be established as mp-safe ? */
static void
vl_api_sfdp_session_stats_ring_enable_t_handler (vl_api_sfdp_session_stats_ring_enable_t *mp)
{
  vl_api_sfdp_session_stats_ring_enable_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  if (mp->enable)
    {
      u32 ring_size = clib_net_to_host_u32 (mp->ring_size);
      if (ring_size == 0)
	ring_size = SFDP_SESSION_STATS_DEFAULT_RING_SIZE;
      rv = sfdp_session_stats_ring_init (vm, ring_size);
    }
  else
    {
      if (ssm->ring_buffer_enabled)
	{
	  vlib_stats_remove_entry (ssm->ring_buffer_index);
	  ssm->ring_buffer_index = CLIB_U32_MAX;
	  ssm->ring_buffer_size = 0;
	  ssm->ring_buffer_enabled = 0;
	}
    }

  REPLY_MACRO (VL_API_SFDP_SESSION_STATS_RING_ENABLE_REPLY);
}

static void
vl_api_sfdp_session_stats_periodic_export_t_handler (
  vl_api_sfdp_session_stats_periodic_export_t *mp)
{
  vl_api_sfdp_session_stats_periodic_export_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  if (mp->enable)
    {
      f64 interval = mp->interval;
      if (interval <= 0)
	interval = 30.0; /* default */
      sfdp_session_stats_periodic_export_enable (vm, interval);
    }
  else
    {
      sfdp_session_stats_periodic_export_disable (vm);
    }

  REPLY_MACRO (VL_API_SFDP_SESSION_STATS_PERIODIC_EXPORT_REPLY);
}

static void
vl_api_sfdp_session_stats_export_now_t_handler (vl_api_sfdp_session_stats_export_now_t *mp)
{
  vl_api_sfdp_session_stats_export_now_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  sfdp_session_stats_export_now (vm);

  REPLY_MACRO (VL_API_SFDP_SESSION_STATS_EXPORT_NOW_REPLY);
}

static void
sfdp_session_stats_send_details (vl_api_registration_t *rp, u32 context, sfdp_session_t *session,
				 sfdp_session_stats_entry_t *stats)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  vl_api_sfdp_session_stats_details_t *mp;
  sfdp_session_ip46_key_t skey;

  mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SFDP_SESSION_STATS_DETAILS + ssm->msg_id_base);

  mp->context = context;
  mp->session_id = clib_host_to_net_u64 (session->session_id);
  mp->session_version = clib_host_to_net_u32 (session->session_version);
  mp->tenant_idx = clib_host_to_net_u32 (session->tenant_idx);
  mp->proto = session->proto;

  /* Set addresses from session key using normalise functions */
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      ip4_address_t src_ip4, dst_ip4;
      mp->is_ip6 = 0;
      sfdp_normalise_ip4_key (session, &skey.key4, 0);
      /* After normalisation: ip_addr_lo = src, ip_addr_hi = dst */
      src_ip4.as_u32 = skey.key4.ip4_key.ip_addr_lo;
      dst_ip4.as_u32 = skey.key4.ip4_key.ip_addr_hi;
      ip4_address_encode (&src_ip4, mp->src_addr.un.ip4);
      ip4_address_encode (&dst_ip4, mp->dst_addr.un.ip4);
      mp->src_port = clib_host_to_net_u16 (skey.key4.ip4_key.port_lo);
      mp->dst_port = clib_host_to_net_u16 (skey.key4.ip4_key.port_hi);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      mp->is_ip6 = 1;
      sfdp_normalise_ip6_key (session, &skey.key6, 0);
      /* After normalisation: ip6_addr_lo = src, ip6_addr_hi = dst */
      ip6_address_encode (&skey.key6.ip6_key.ip6_addr_lo, mp->src_addr.un.ip6);
      ip6_address_encode (&skey.key6.ip6_key.ip6_addr_hi, mp->dst_addr.un.ip6);
      mp->src_port = clib_host_to_net_u16 (skey.key6.ip6_key.port_lo);
      mp->dst_port = clib_host_to_net_u16 (skey.key6.ip6_key.port_hi);
    }

  /* Stats counters */
  mp->packets_fwd = clib_host_to_net_u64 (stats->packets[SFDP_FLOW_FORWARD]);
  mp->packets_rev = clib_host_to_net_u64 (stats->packets[SFDP_FLOW_REVERSE]);
  mp->bytes_fwd = clib_host_to_net_u64 (stats->bytes[SFDP_FLOW_FORWARD]);
  mp->bytes_rev = clib_host_to_net_u64 (stats->bytes[SFDP_FLOW_REVERSE]);

  /* Timestamps - send as f64 */
  mp->first_seen = stats->first_seen;
  mp->last_seen = stats->last_seen;
  mp->duration =
    (stats->last_seen > stats->first_seen) ? (stats->last_seen - stats->first_seen) : 0.0;

  /* TTL statistics */
  mp->ttl_min_fwd = stats->ttl[SFDP_FLOW_FORWARD].min_ttl;
  mp->ttl_max_fwd = stats->ttl[SFDP_FLOW_FORWARD].max_ttl;
  mp->ttl_mean_fwd = stats->ttl[SFDP_FLOW_FORWARD].mean;
  mp->ttl_stddev_fwd = sfdp_session_stats_compute_stddev (stats->ttl[SFDP_FLOW_FORWARD].m2,
							  stats->ttl[SFDP_FLOW_FORWARD].count);
  mp->ttl_min_rev = stats->ttl[SFDP_FLOW_REVERSE].min_ttl;
  mp->ttl_max_rev = stats->ttl[SFDP_FLOW_REVERSE].max_ttl;
  mp->ttl_mean_rev = stats->ttl[SFDP_FLOW_REVERSE].mean;
  mp->ttl_stddev_rev = sfdp_session_stats_compute_stddev (stats->ttl[SFDP_FLOW_REVERSE].m2,
							  stats->ttl[SFDP_FLOW_REVERSE].count);

  /* RTT statistics */
  mp->rtt_mean_fwd = stats->rtt[SFDP_FLOW_FORWARD].mean;
  mp->rtt_stddev_fwd = sfdp_session_stats_compute_stddev (stats->rtt[SFDP_FLOW_FORWARD].m2,
							  stats->rtt[SFDP_FLOW_FORWARD].count);
  mp->rtt_mean_rev = stats->rtt[SFDP_FLOW_REVERSE].mean;
  mp->rtt_stddev_rev = sfdp_session_stats_compute_stddev (stats->rtt[SFDP_FLOW_REVERSE].m2,
							  stats->rtt[SFDP_FLOW_REVERSE].count);

  /* TCP-specific statistics */
  mp->tcp_mss = clib_host_to_net_u16 (stats->tcp.mss);
  mp->tcp_handshake_complete = stats->tcp.handshake_complete;
  mp->tcp_syn_packets = clib_host_to_net_u32 (stats->tcp.syn_packets);
  mp->tcp_fin_packets = clib_host_to_net_u32 (stats->tcp.fin_packets);
  mp->tcp_rst_packets = clib_host_to_net_u32 (stats->tcp.rst_packets);
  /* ECN/CWR metrics */
  mp->tcp_ecn_ect_packets = clib_host_to_net_u32 (stats->tcp.ecn_ect_packets);
  mp->tcp_ecn_ce_packets = clib_host_to_net_u32 (stats->tcp.ecn_ce_packets);
  mp->tcp_ece_packets = clib_host_to_net_u32 (stats->tcp.ece_packets);
  mp->tcp_cwr_packets = clib_host_to_net_u32 (stats->tcp.cwr_packets);
  mp->tcp_retransmissions_fwd =
    clib_host_to_net_u32 (stats->tcp.retransmissions[SFDP_FLOW_FORWARD]);
  mp->tcp_retransmissions_rev =
    clib_host_to_net_u32 (stats->tcp.retransmissions[SFDP_FLOW_REVERSE]);
  mp->tcp_zero_window_events_fwd =
    clib_host_to_net_u32 (stats->tcp.zero_window_events[SFDP_FLOW_FORWARD]);
  mp->tcp_zero_window_events_rev =
    clib_host_to_net_u32 (stats->tcp.zero_window_events[SFDP_FLOW_REVERSE]);
  mp->tcp_dupack_events_fwd = clib_host_to_net_u32 (stats->tcp.dupack_like[SFDP_FLOW_FORWARD]);
  mp->tcp_dupack_events_rev = clib_host_to_net_u32 (stats->tcp.dupack_like[SFDP_FLOW_REVERSE]);
  mp->tcp_partial_overlap_events_fwd =
    clib_host_to_net_u32 (stats->tcp.partial_overlaps[SFDP_FLOW_FORWARD]);
  mp->tcp_partial_overlap_events_rev =
    clib_host_to_net_u32 (stats->tcp.partial_overlaps[SFDP_FLOW_REVERSE]);
  mp->tcp_out_of_order_events_fwd =
    clib_host_to_net_u32 (stats->tcp.out_of_order[SFDP_FLOW_FORWARD]);
  mp->tcp_out_of_order_events_rev =
    clib_host_to_net_u32 (stats->tcp.out_of_order[SFDP_FLOW_REVERSE]);
  mp->tcp_last_seq_fwd = clib_host_to_net_u32 (stats->tcp.last_seq[SFDP_FLOW_FORWARD]);
  mp->tcp_last_ack_fwd = clib_host_to_net_u32 (stats->tcp.last_ack[SFDP_FLOW_FORWARD]);
  mp->tcp_last_seq_rev = clib_host_to_net_u32 (stats->tcp.last_seq[SFDP_FLOW_REVERSE]);
  mp->tcp_last_ack_rev = clib_host_to_net_u32 (stats->tcp.last_ack[SFDP_FLOW_REVERSE]);

  vl_api_send_msg (rp, (u8 *) mp);
}

static void
vl_api_sfdp_session_stats_dump_t_handler (vl_api_sfdp_session_stats_dump_t *mp)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  sfdp_session_t *session;
  sfdp_session_stats_entry_t *stats;
  uword session_index;
  vl_api_registration_t *rp;
  u64 session_id_filter = clib_net_to_host_u64 (mp->session_id);
  u32 tenant_filter = clib_net_to_host_u32 (mp->tenant_idx);

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  sfdp_foreach_session (sfdp, session_index, session)
  {
    /* Filter by session ID if specified */
    if (session_id_filter != 0 && session->session_id != session_id_filter)
      continue;

    /* Filter by tenant if specified (skip if all tenants requested) */
    if (tenant_filter != SFDP_SESSION_STATS_ALL_TENANTS && session->tenant_idx != tenant_filter)
      continue;

    /* Check we have stats for this session */
    if (session_index >= vec_len (ssm->stats))
      continue;

    stats = vec_elt_at_index (ssm->stats, session_index);

    /* Only send if session has seen traffic */
    // if (stats->packets[SFDP_FLOW_FORWARD] == 0 && stats->packets[SFDP_FLOW_REVERSE] == 0)
    // continue;

    sfdp_session_stats_send_details (rp, mp->context, session, stats);
  }
}

static void
vl_api_sfdp_session_stats_get_config_t_handler (vl_api_sfdp_session_stats_get_config_t *mp)
{
  vl_api_sfdp_session_stats_get_config_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  int rv = 0;
  u32 active_sessions = 0;

  /* TODO - do we really need to re-compute active sessions here for each dump ? */
  /* Can't a counter be kept up and incremented/decremented on session stats creation/deletion */

  /* Count active sessions */
  for (u32 i = 0; i < vec_len (ssm->stats); i++)
    {
      // sfdp_session_stats_entry_t *s = vec_elt_at_index (ssm->stats, i);
      // if (s->packets[SFDP_FLOW_FORWARD] > 0 || s->packets[SFDP_FLOW_REVERSE] > 0)
      active_sessions++;
    }

  REPLY_MACRO2 (VL_API_SFDP_SESSION_STATS_GET_CONFIG_REPLY, ({
		  rmp->ring_buffer_enabled = ssm->ring_buffer_enabled;
		  rmp->periodic_export_enabled = ssm->periodic_export_enabled;
		  rmp->export_interval = ssm->export_interval;
		  rmp->ring_size = clib_host_to_net_u32 (ssm->ring_buffer_size);
		  rmp->total_exports = clib_host_to_net_u64 (ssm->total_exports);
		  rmp->active_sessions = clib_host_to_net_u32 (active_sessions);
		}));
}

static void
vl_api_sfdp_session_stats_clear_t_handler (vl_api_sfdp_session_stats_clear_t *mp)
{
  vl_api_sfdp_session_stats_clear_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  u64 session_id = clib_net_to_host_u64 (mp->session_id);
  int rv = 0;

  sfdp_session_stats_clear_sessions (session_id);

  REPLY_MACRO (VL_API_SFDP_SESSION_STATS_CLEAR_REPLY);
}

static void
vl_api_sfdp_session_stats_set_custom_api_data_t_handler (
  vl_api_sfdp_session_stats_set_custom_api_data_t *mp)
{
  vl_api_sfdp_session_stats_set_custom_api_data_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  int rv = 0;

  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u64 data = clib_net_to_host_u64 (mp->value);
  rv = sfdp_session_stats_set_custom_api_data (tenant_id, data);

  REPLY_MACRO (VL_API_SFDP_SESSION_STATS_SET_CUSTOM_API_DATA_REPLY);
}

static void
vl_api_sfdp_session_stats_clear_custom_api_data_t_handler (
  vl_api_sfdp_session_stats_clear_custom_api_data_t *mp)
{
  vl_api_sfdp_session_stats_clear_custom_api_data_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  int rv = 0;

  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  sfdp_session_stats_clear_custom_api_data (tenant_id);

  REPLY_MACRO (VL_API_SFDP_SESSION_STATS_CLEAR_CUSTOM_API_DATA_REPLY);
}

static void
vl_api_sfdp_session_stats_get_tenant_custom_data_t_handler (
  vl_api_sfdp_session_stats_get_tenant_custom_data_t *mp)
{
  vl_api_sfdp_session_stats_get_tenant_custom_data_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  int rv = 0;

  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u8 has_api_data = 0;
  u64 api_data_value = sfdp_session_stats_get_custom_api_data (tenant_id, &has_api_data);

  REPLY_MACRO2 (VL_API_SFDP_SESSION_STATS_GET_TENANT_CUSTOM_DATA_REPLY, ({
		  rmp->tenant_id = clib_host_to_net_u32 (tenant_id);
		  rmp->has_api_data = has_api_data;
		  rmp->api_data_value = clib_host_to_net_u64 (api_data_value);
		}));
}

static void
vl_api_sfdp_session_stats_set_custom_api_data_name_t_handler (
  vl_api_sfdp_session_stats_set_custom_api_data_name_t *mp)
{
  vl_api_sfdp_session_stats_set_custom_api_data_name_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  int rv = 0;

  /* Extract name from API message */
  /* TODO - safer appoach required for strcpy ? */
  u8 *name = (u8 *) mp->name;
  u32 name_len = clib_strnlen ((char *) name, SFDP_SESSION_STATS_CUSTOM_API_DATA_NAME_MAX_LEN + 1);

  rv = sfdp_session_stats_set_custom_api_data_name (name, name_len);

  REPLY_MACRO (VL_API_SFDP_SESSION_STATS_SET_CUSTOM_API_DATA_NAME_REPLY);
}

static void
vl_api_sfdp_session_stats_get_custom_api_data_name_t_handler (
  vl_api_sfdp_session_stats_get_custom_api_data_name_t *mp)
{
  vl_api_sfdp_session_stats_get_custom_api_data_name_reply_t *rmp;
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  int rv = 0;

  /* TODO - safer appoach required for strcpy ? */
  REPLY_MACRO2 (VL_API_SFDP_SESSION_STATS_GET_CUSTOM_API_DATA_NAME_REPLY, ({
		  u32 name_len = clib_strnlen ((char *) ssm->custom_api_data_name,
					       SFDP_SESSION_STATS_CUSTOM_API_DATA_NAME_MAX_LEN);
		  clib_memcpy_fast (rmp->name, ssm->custom_api_data_name, name_len);
		  rmp->name[name_len] = '\0';
		}));
}

#include <sfdp_services/session_stats/session_stats.api.c>

static clib_error_t *
sfdp_session_stats_plugin_api_hookup (vlib_main_t *vm)
{
  sfdp_session_stats_main_t *ssm = &sfdp_session_stats_main;
  ssm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (sfdp_session_stats_plugin_api_hookup);
