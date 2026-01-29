/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "internal.h"

static const char *
proto_to_string (u8 proto)
{
  /* format provided IP proto to string */
  switch (proto)
    {
    case 6:
      return "tcp";
    case 17:
      return "udp";
    case 1:
      return "icmp";
    case 58:
      return "icmpv6";
    case 132:
      return "sctp";
    default:
      return "other";
    }
}

static void
format_ip_address_text (char *buf, size_t buflen, u8 *ip, u8 is_ip4)
{
  /* format provided IP address to string */
  if (is_ip4)
    snprintf (buf, buflen, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  else
    inet_ntop (AF_INET6, ip, buf, buflen);
}

static void
emit_metric (FILE *stream, const session_exporter_main_t *em, const char *metric_name,
	     const char *labels, i64 timestamp_ms, const char *value_fmt, ...)
{
  /* format metric name and labels, and decorate with instance name if set */
  /* before emitting to prometheus sock */
  if (em->instance)
    fprintf (stream, "%s{instance=\"%s\",%s} ", metric_name, em->instance, labels);
  else
    fprintf (stream, "%s{%s} ", metric_name, labels);

  va_list ap;
  va_start (ap, value_fmt);
  vfprintf (stream, value_fmt, ap);
  va_end (ap);
  fprintf (stream, " %" PRId64, timestamp_ms);
  fputc ('\n', stream);
}

static void
emit_help_type (FILE *stream, const char *metric, const char *help_text, const char *metric_type)
{
  /* emit help and type for a specific metric */
  fprintf (stream, "# HELP %s %s\n", metric, help_text);
  fprintf (stream, "# TYPE %s %s\n", metric, metric_type);
}

static u8
session_is_silent (const session_exporter_main_t *em, const tracked_session_t *ts, f64 now)
{
  if (em->session_silence_timeout <= 0.0)
    return 0;

  if (ts->last_update <= 0.0)
    return 0;

  return (now - ts->last_update) > em->session_silence_timeout;
}

static void
build_base_labels (char *buf, size_t buflen, const vl_api_sfdp_session_stats_ring_entry_t *s,
		   const char *proto, const char *src_ip, const char *dst_ip,
		   const char *ip_version, const char *opaque_label, const char *opaque_value)
{
  /* base labels are apprended to each counter/gauge */
  snprintf (buf, buflen,
	    "session_id=\"%lu\",tenant_id=\"%u\",proto=\"%s\","
	    "src_ip=\"%s\",dst_ip=\"%s\",src_port=\"%u\",dst_port=\"%u\","
	    "ip_version=\"%s\",%s=\"%s\"",
	    s->session_id, s->tenant_id, proto, src_ip, dst_ip, s->src_port, s->dst_port,
	    ip_version, opaque_label, opaque_value);
}

void
dump_session_metrics (FILE *stream, stat_client_main_t *shm)
{
  session_exporter_main_t *em = &exporter_main;
  char src_ip[INET6_ADDRSTRLEN];
  char dst_ip[INET6_ADDRSTRLEN];

  /* consume ring buffer entries, and fill exportain main session table */
  consume_result_t rv = consume_ring_buffer_entries (shm);
  if (rv != CONSUME_OK)
    {
      if (rv == CONSUME_ERR_SCHEMA)
	fprintf (stream, "# SFDP session stats ring ABI ID is missing or unsupported\n");
      else if (rv == CONSUME_ERR_CONFIG)
	fprintf (stream, "# SFDP session stats ring config invalid\n");
      else
	{
	  fprintf (stream, "# SFDP session stats ring buffer not found or not enabled\n");
	  fprintf (stream, "# Enable with: sfdp session stats ring enable\n");
	}
      return;
    }

  /* Static ABI ID compatibility is already enforced in schema loading path. */
  emit_help_type (stream, "sfdp_session_packets_forward", "Total forward packets for session",
		  "counter");
  emit_help_type (stream, "sfdp_session_packets_reverse", "Total reverse packets for session",
		  "counter");
  emit_help_type (stream, "sfdp_session_bytes_forward", "Total forward bytes for session",
		  "counter");
  emit_help_type (stream, "sfdp_session_bytes_reverse", "Total reverse bytes for session",
		  "counter");
  emit_help_type (stream, "sfdp_session_duration_seconds", "Session duration in seconds", "gauge");

  fprintf (stream, "# HELP sfdp_session_info Session information (always 1)\n");
  fprintf (stream, "# TYPE sfdp_session_info gauge\n");

  emit_help_type (stream, "sfdp_session_ttl_min_forward", "Minimum TTL forward direction", "gauge");
  emit_help_type (stream, "sfdp_session_ttl_max_forward", "Maximum TTL forward direction", "gauge");
  emit_help_type (stream, "sfdp_session_ttl_min_reverse", "Minimum TTL reverse direction", "gauge");
  emit_help_type (stream, "sfdp_session_ttl_max_reverse", "Maximum TTL reverse direction", "gauge");
  emit_help_type (stream, "sfdp_session_ttl_mean_forward", "Mean TTL forward direction", "gauge");
  emit_help_type (stream, "sfdp_session_ttl_mean_reverse", "Mean TTL reverse direction", "gauge");
  emit_help_type (stream, "sfdp_session_ttl_stddev_forward", "TTL stddev forward direction",
		  "gauge");
  emit_help_type (stream, "sfdp_session_ttl_stddev_reverse", "TTL stddev reverse direction",
		  "gauge");

  emit_help_type (stream, "sfdp_session_rtt_mean_forward_seconds", "Mean RTT forward direction",
		  "gauge");
  emit_help_type (stream, "sfdp_session_rtt_mean_reverse_seconds", "Mean RTT reverse direction",
		  "gauge");
  emit_help_type (stream, "sfdp_session_rtt_stddev_forward_seconds", "RTT stddev forward direction",
		  "gauge");
  emit_help_type (stream, "sfdp_session_rtt_stddev_reverse_seconds", "RTT stddev reverse direction",
		  "gauge");

  emit_help_type (stream, "sfdp_session_tcp_mss", "TCP Maximum Segment Size", "gauge");
  emit_help_type (stream, "sfdp_session_tcp_handshake_complete", "TCP handshake completed (0 or 1)",
		  "gauge");
  emit_help_type (stream, "sfdp_session_tcp_syn_packets", "TCP SYN packets counter", "counter");
  emit_help_type (stream, "sfdp_session_tcp_fin_packets", "TCP FIN packets counter", "counter");
  emit_help_type (stream, "sfdp_session_tcp_rst_packets", "TCP RST packets counter", "counter");
  emit_help_type (stream, "sfdp_session_tcp_retransmissions_forward", "TCP retransmissions forward",
		  "counter");
  emit_help_type (stream, "sfdp_session_tcp_retransmissions_reverse", "TCP retransmissions reverse",
		  "counter");
  emit_help_type (stream, "sfdp_session_tcp_zero_window_forward", "TCP zero window events forward",
		  "counter");
  emit_help_type (stream, "sfdp_session_tcp_zero_window_reverse", "TCP zero window events reverse",
		  "counter");
  emit_help_type (stream, "sfdp_session_tcp_dupack_forward", "TCP duplicate ACK events forward",
		  "counter");
  emit_help_type (stream, "sfdp_session_tcp_dupack_reverse", "TCP duplicate ACK events reverse",
		  "counter");
  emit_help_type (stream, "sfdp_session_tcp_partial_overlap_forward",
		  "TCP partial overlap events forward", "counter");
  emit_help_type (stream, "sfdp_session_tcp_partial_overlap_reverse",
		  "TCP partial overlap events reverse", "counter");
  emit_help_type (stream, "sfdp_session_tcp_out_of_order_forward",
		  "TCP out-of-order events forward", "counter");
  emit_help_type (stream, "sfdp_session_tcp_out_of_order_reverse",
		  "TCP out-of-order events reverse", "counter");
  emit_help_type (stream, "sfdp_session_tcp_ecn_ect_packets",
		  "Packets with ECN ECT(0) or ECT(1) marks", "counter");
  emit_help_type (stream, "sfdp_session_tcp_ecn_ce_packets",
		  "Packets with ECN CE (Congestion Experienced)", "counter");
  emit_help_type (stream, "sfdp_session_tcp_ece_packets", "TCP packets with ECE flag", "counter");
  emit_help_type (stream, "sfdp_session_tcp_cwr_packets", "TCP packets with CWR flag", "counter");
  emit_help_type (stream, "sfdp_session_tcp_last_seq_forward", "Last TCP seq forward", "gauge");
  emit_help_type (stream, "sfdp_session_tcp_last_ack_forward", "Last TCP ack forward", "gauge");
  emit_help_type (stream, "sfdp_session_tcp_last_seq_reverse", "Last TCP seq reverse", "gauge");
  emit_help_type (stream, "sfdp_session_tcp_last_ack_reverse", "Last TCP ack reverse", "gauge");

  f64 now = unix_time_now ();

  /* Iterate over cached sessions, persisting values between scrape cycles. */
  for (u32 i = 0; i < vec_len (em->sessions); i++)
    {
      tracked_session_t *ts = &em->sessions[i];
      vl_api_sfdp_session_stats_ring_entry_t *s = &ts->stats;
      char base_labels[1024];

      if (session_is_silent (em, ts, now))
	continue;

      /* compute last unix timestamp in ms to expose with each session entry to prometheus */
      i64 timestamp_ms = (i64) (ts->last_update * 1000.0);

      format_ip_address_text (src_ip, sizeof (src_ip), s->src_ip, s->is_ip4);
      format_ip_address_text (dst_ip, sizeof (dst_ip), s->dst_ip, s->is_ip4);

      const char *proto = proto_to_string (s->proto);
      const char *ip_version = s->is_ip4 ? "4" : "6";

      const char *opaque_label =
	em->opaque_label ? (const char *) em->opaque_label : OPAQUE_LABEL_DEFAULT_NAME;
      char opaque_value_str[32] = { 0 };
      snprintf (opaque_value_str, sizeof (opaque_value_str), "%" PRIu64, s->opaque);

      build_base_labels (base_labels, sizeof (base_labels), s, proto, src_ip, dst_ip, ip_version,
			 opaque_label, opaque_value_str);

      emit_metric (stream, em, "sfdp_session_packets_forward", base_labels, timestamp_ms, "%lu",
		   s->packets_forward);
      emit_metric (stream, em, "sfdp_session_packets_reverse", base_labels, timestamp_ms, "%lu",
		   s->packets_reverse);
      emit_metric (stream, em, "sfdp_session_bytes_forward", base_labels, timestamp_ms, "%lu",
		   s->bytes_forward);
      emit_metric (stream, em, "sfdp_session_bytes_reverse", base_labels, timestamp_ms, "%lu",
		   s->bytes_reverse);
      emit_metric (stream, em, "sfdp_session_duration_seconds", base_labels, timestamp_ms, "%.6f",
		   s->duration);

      emit_metric (stream, em, "sfdp_session_ttl_min_forward", base_labels, timestamp_ms, "%u",
		   s->ttl_min_forward);
      emit_metric (stream, em, "sfdp_session_ttl_max_forward", base_labels, timestamp_ms, "%u",
		   s->ttl_max_forward);
      emit_metric (stream, em, "sfdp_session_ttl_min_reverse", base_labels, timestamp_ms, "%u",
		   s->ttl_min_reverse);
      emit_metric (stream, em, "sfdp_session_ttl_max_reverse", base_labels, timestamp_ms, "%u",
		   s->ttl_max_reverse);
      emit_metric (stream, em, "sfdp_session_ttl_mean_forward", base_labels, timestamp_ms, "%.2f",
		   s->ttl_mean_forward);
      emit_metric (stream, em, "sfdp_session_ttl_mean_reverse", base_labels, timestamp_ms, "%.2f",
		   s->ttl_mean_reverse);
      emit_metric (stream, em, "sfdp_session_ttl_stddev_forward", base_labels, timestamp_ms, "%.2f",
		   s->ttl_stddev_forward);
      emit_metric (stream, em, "sfdp_session_ttl_stddev_reverse", base_labels, timestamp_ms, "%.2f",
		   s->ttl_stddev_reverse);

      emit_metric (stream, em, "sfdp_session_rtt_mean_forward_seconds", base_labels, timestamp_ms,
		   "%.6f", s->rtt_mean_forward);
      emit_metric (stream, em, "sfdp_session_rtt_mean_reverse_seconds", base_labels, timestamp_ms,
		   "%.6f", s->rtt_mean_reverse);
      emit_metric (stream, em, "sfdp_session_rtt_stddev_forward_seconds", base_labels, timestamp_ms,
		   "%.6f", s->rtt_stddev_forward);
      emit_metric (stream, em, "sfdp_session_rtt_stddev_reverse_seconds", base_labels, timestamp_ms,
		   "%.6f", s->rtt_stddev_reverse);

      if (s->proto == 6)
	{
	  emit_metric (stream, em, "sfdp_session_tcp_mss", base_labels, timestamp_ms, "%u",
		       s->tcp_mss);
	  emit_metric (stream, em, "sfdp_session_tcp_handshake_complete", base_labels, timestamp_ms,
		       "%u", s->tcp_handshake_complete);
	  emit_metric (stream, em, "sfdp_session_tcp_syn_packets", base_labels, timestamp_ms, "%u",
		       s->tcp_syn_packets);
	  emit_metric (stream, em, "sfdp_session_tcp_fin_packets", base_labels, timestamp_ms, "%u",
		       s->tcp_fin_packets);
	  emit_metric (stream, em, "sfdp_session_tcp_rst_packets", base_labels, timestamp_ms, "%u",
		       s->tcp_rst_packets);
	  emit_metric (stream, em, "sfdp_session_tcp_retransmissions_forward", base_labels,
		       timestamp_ms, "%u", s->tcp_retransmissions_fwd);
	  emit_metric (stream, em, "sfdp_session_tcp_retransmissions_reverse", base_labels,
		       timestamp_ms, "%u", s->tcp_retransmissions_rev);
	  emit_metric (stream, em, "sfdp_session_tcp_zero_window_forward", base_labels,
		       timestamp_ms, "%u", s->tcp_zero_window_events_fwd);
	  emit_metric (stream, em, "sfdp_session_tcp_zero_window_reverse", base_labels,
		       timestamp_ms, "%u", s->tcp_zero_window_events_rev);
	  emit_metric (stream, em, "sfdp_session_tcp_dupack_forward", base_labels, timestamp_ms,
		       "%u", s->tcp_dupack_events_fwd);
	  emit_metric (stream, em, "sfdp_session_tcp_dupack_reverse", base_labels, timestamp_ms,
		       "%u", s->tcp_dupack_events_rev);
	  emit_metric (stream, em, "sfdp_session_tcp_partial_overlap_forward", base_labels,
		       timestamp_ms, "%u", s->tcp_partial_overlap_events_fwd);
	  emit_metric (stream, em, "sfdp_session_tcp_partial_overlap_reverse", base_labels,
		       timestamp_ms, "%u", s->tcp_partial_overlap_events_rev);
	  emit_metric (stream, em, "sfdp_session_tcp_out_of_order_forward", base_labels,
		       timestamp_ms, "%u", s->tcp_out_of_order_events_fwd);
	  emit_metric (stream, em, "sfdp_session_tcp_out_of_order_reverse", base_labels,
		       timestamp_ms, "%u", s->tcp_out_of_order_events_rev);
	  emit_metric (stream, em, "sfdp_session_tcp_ecn_ect_packets", base_labels, timestamp_ms,
		       "%u", s->tcp_ecn_ect_packets);
	  emit_metric (stream, em, "sfdp_session_tcp_ecn_ce_packets", base_labels, timestamp_ms,
		       "%u", s->tcp_ecn_ce_packets);
	  emit_metric (stream, em, "sfdp_session_tcp_ece_packets", base_labels, timestamp_ms, "%u",
		       s->tcp_ece_packets);
	  emit_metric (stream, em, "sfdp_session_tcp_cwr_packets", base_labels, timestamp_ms, "%u",
		       s->tcp_cwr_packets);
	  emit_metric (stream, em, "sfdp_session_tcp_last_seq_forward", base_labels, timestamp_ms,
		       "%u", s->tcp_last_seq_forward);
	  emit_metric (stream, em, "sfdp_session_tcp_last_ack_forward", base_labels, timestamp_ms,
		       "%u", s->tcp_last_ack_forward);
	  emit_metric (stream, em, "sfdp_session_tcp_last_seq_reverse", base_labels, timestamp_ms,
		       "%u", s->tcp_last_seq_reverse);
	  emit_metric (stream, em, "sfdp_session_tcp_last_ack_reverse", base_labels, timestamp_ms,
		       "%u", s->tcp_last_ack_reverse);
	}

      /* Export session identity labels only (no session_index label). */
      emit_metric (stream, em, "sfdp_session_info", base_labels, timestamp_ms, "1");
    }
}
