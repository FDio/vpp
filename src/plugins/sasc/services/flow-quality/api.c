// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <sasc/sasc.h>
#include <sasc/services/flow-quality/packet_stats.h>
#include <sasc/services/flow-quality/flow_quality_tcp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <sasc/services/flow-quality/sasc_flow_quality.api_enum.h>
#include <sasc/services/flow-quality/sasc_flow_quality.api_types.h>

#define REPLY_MSG_ID_BASE sasc_packet_stats_main->msg_id_base
#include <vlibapi/api_helper_macros.h>

// TODO - Stats API currently dumps all available information
// We should explore splitting it into multiple APIs to expose
// different types of information (i.e. TCP session statistics,
// Protocol-agnostic statistics, quality scores)
static void
sasc_send_packet_stats_details(vl_api_registration_t *rp, u32 context, u32 session_index,
                               sasc_packet_stats_session_data_t *session_data) {

    sasc_packet_stats_main_t *packet_details = &sasc_packet_stats_main;
    vl_api_sasc_packet_stats_details_t *mp;

    mp = vl_msg_api_alloc_zero(sizeof(*mp));
    mp->_vl_msg_id = clib_host_to_net_u16(VL_API_SASC_PACKET_STATS_DETAILS + packet_details->msg_id_base);
    mp->context = context;

    /* Session identifier */
    mp->session_index = clib_host_to_net_u32(session_index);

    /* Main packet statistics */
    mp->last_packet_time = clib_host_to_net_f64(session_data->last_packet_time);
    mp->iat_mean = clib_host_to_net_f64(session_data->iat_mean);
    mp->iat_stddev = clib_host_to_net_f64(session_data->iat_stddev);
    mp->iat_cv = clib_host_to_net_f64(session_data->iat_cv);
    mp->iat_count = clib_host_to_net_u32(session_data->iat_count);
    mp->burst_count = clib_host_to_net_u32(session_data->burst_count);
    mp->idle_periods = clib_host_to_net_u32(session_data->idle_periods);
    mp->tiny_packets = clib_host_to_net_u32(session_data->tiny_packets);
    mp->frames_touched = clib_host_to_net_u32(session_data->frames_touched);
    mp->ecn_ect = clib_host_to_net_u32(session_data->ecn_ect);
    mp->ecn_ce = clib_host_to_net_u32(session_data->ecn_ce);

    /* TTL statistics - forward direction */
    mp->ttl_min_fwd = session_data->ttl_min[0];
    mp->ttl_max_fwd = session_data->ttl_max[0];
    mp->ttl_mean_fwd = clib_host_to_net_f64(session_data->ttl_mean[0]);
    mp->ttl_stddev_fwd = clib_host_to_net_f64(session_data->ttl_stddev[0]);
    mp->ttl_count_fwd = clib_host_to_net_u32(session_data->ttl_count[0]);

    /* TTL statistics - reverse direction */
    mp->ttl_min_rev = session_data->ttl_min[1];
    mp->ttl_max_rev = session_data->ttl_max[1];
    mp->ttl_mean_rev = clib_host_to_net_f64(session_data->ttl_mean[1]);
    mp->ttl_stddev_rev = clib_host_to_net_f64(session_data->ttl_stddev[1]);
    mp->ttl_count_rev = clib_host_to_net_u32(session_data->ttl_count[1]);

    /* DSCP metrics */
    mp->last_dscp = clib_host_to_net_u32(session_data->last_dscp);
    mp->dscp_changes = clib_host_to_net_u32(session_data->dscp_changes);

    /* Quality scores */
    mp->quality_score = clib_host_to_net_f64(session_data->quality_score);
    mp->q_stability = clib_host_to_net_f64(session_data->q_stability);
    mp->q_congestion = clib_host_to_net_f64(session_data->q_congestion);
    mp->q_continuity = clib_host_to_net_f64(session_data->q_continuity);
    mp->q_delivery = clib_host_to_net_f64(session_data->q_delivery);
    mp->q_packetization = clib_host_to_net_f64(session_data->q_packetization);

    /* TCP statistics - basic counters */
    sasc_tcp_quality_session_data_t *tcp = &session_data->tcp_session_data;
    mp->tcp_packets = clib_host_to_net_u32(tcp->packets);
    mp->tcp_data_packets = clib_host_to_net_u32(tcp->data_packets);
    mp->tcp_syn_packets = clib_host_to_net_u32(tcp->syn_packets);
    mp->tcp_syn_retx = clib_host_to_net_u32(tcp->syn_retx);
    mp->tcp_fin_packets = clib_host_to_net_u32(tcp->fin_packets);
    mp->tcp_rst_packets = clib_host_to_net_u32(tcp->rst_packets);

    /* TCP statistics - ECN tracking */
    mp->tcp_ce_mark_popcnt = tcp->ce_mark_popcnt;
    mp->tcp_ece_seen = clib_host_to_net_u32(tcp->ece_seen);
    mp->tcp_cwr_seen = clib_host_to_net_u32(tcp->cwr_seen);

    /* TCP statistics - loss/reorder */
    mp->tcp_retransmissions = clib_host_to_net_u32(tcp->retransmissions);
    mp->tcp_reorder_events = clib_host_to_net_u32(tcp->reorder_events);
    mp->tcp_dupack_like = clib_host_to_net_u32(tcp->dupack_like);
    mp->tcp_partial_overlaps = clib_host_to_net_u32(tcp->partial_overlaps);

    /* TCP statistics - window/stalls */
    mp->tcp_zero_window_events = clib_host_to_net_u32(tcp->zero_window_events);
    mp->tcp_stall_time_fwd = clib_host_to_net_f64(tcp->stall_time_accum[0]);
    mp->tcp_stall_time_rev = clib_host_to_net_f64(tcp->stall_time_accum[1]);

    /* TCP statistics - RTT per direction */
    mp->tcp_rtt_mean_fwd = clib_host_to_net_f64(tcp->rtt_mean[0]);
    mp->tcp_rtt_count_fwd = clib_host_to_net_u32(tcp->rtt_count[0]);
    mp->tcp_rtt_mean_rev = clib_host_to_net_f64(tcp->rtt_mean[1]);
    mp->tcp_rtt_count_rev = clib_host_to_net_u32(tcp->rtt_count[1]);

    /* TCP statistics - handshake/closure */
    mp->tcp_handshake_ok = tcp->handshake_ok;
    mp->tcp_syn_rtt = clib_host_to_net_f64(tcp->syn_rtt);
    mp->tcp_orderly_close = tcp->orderly_close;

    /* TCP statistics - MSS/segmentation */
    mp->tcp_mss = clib_host_to_net_u16(tcp->mss);
    mp->tcp_atypical_seg_sizes = clib_host_to_net_u32(tcp->atypical_seg_sizes);

    /* TCP statistics - EMA rates */
    mp->tcp_ema_retrans = clib_host_to_net_f64(tcp->ema_retrans);
    mp->tcp_ema_reorder = clib_host_to_net_f64(tcp->ema_reorder);
    mp->tcp_ema_overlap = clib_host_to_net_f64(tcp->ema_overlap);
    mp->tcp_ema_small_seg = clib_host_to_net_f64(tcp->ema_small_seg);
    mp->tcp_ema_ce_rate = clib_host_to_net_f64(tcp->ema_ce_rate);

    vl_api_send_msg(rp, (u8 *)mp);
}

static void
vl_api_sasc_packet_stats_dump_t_handler(vl_api_sasc_packet_stats_dump_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_session_t *session;
    vl_api_registration_t *rp;
    u32 filter_session_index;

    rp = vl_api_client_index_to_registration(mp->client_index);
    if (rp == 0)
        return;

    filter_session_index = clib_net_to_host_u32(mp->session_index);

    if (filter_session_index != ~0) {
        /* Dump specific session */
        session = sasc_session_at_index(sasc, filter_session_index);
        if (session && psm->session_data) {
            sasc_packet_stats_session_data_t *session_data = &psm->session_data[filter_session_index];
            sasc_quality_compute(session, session_data);
            sasc_send_packet_stats_details(rp, mp->context, filter_session_index, session_data);
        }
    } else {
        /* Dump all sessions */
        pool_foreach (session, sasc->sessions) {
            u32 session_index = session - sasc->sessions;
            if (psm->session_data) {
                sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
                sasc_quality_compute(session, session_data);
                sasc_send_packet_stats_details(rp, mp->context, session_index, session_data);
            }
        }
    }
}

#include <sasc/services/flow-quality/sasc_flow_quality.api.c>
static clib_error_t *
sasc_plugin_flow_quality_api_hookup(vlib_main_t *vm) {
    sasc_packet_stats_main_t *packet_stats = &sasc_packet_stats_main;
    packet_stats->msg_id_base = setup_message_id_table();
    return 0;
}
VLIB_API_INIT_FUNCTION(sasc_plugin_flow_quality_api_hookup);
