/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "internal.h"

#define HAS_FIELD(schema_ptr, id) ((schema_ptr)->fields[id].valid)
#define EMIT_HELP_TYPE(stream, schema_ptr, id, metric, help_text, metric_type)                     \
  do                                                                                               \
    {                                                                                              \
      if (HAS_FIELD (schema_ptr, id))                                                              \
	{                                                                                          \
	  fprintf (stream, "# HELP " metric " " help_text "\n");                                   \
	  fprintf (stream, "# TYPE " metric " " metric_type "\n");                                 \
	}                                                                                          \
    }                                                                                              \
  while (0)
#define EMIT_METRIC_IF(stream, em_ptr, schema_ptr, labels, id, metric, fmt, value)                 \
  do                                                                                               \
    {                                                                                              \
      if (HAS_FIELD (schema_ptr, id))                                                              \
	emit_metric (stream, em_ptr, metric, labels, fmt, value);                                  \
    }                                                                                              \
  while (0)

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
	     const char *labels, const char *value_fmt, ...)
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
  fputc ('\n', stream);
}

static u8
session_is_silent (const session_exporter_main_t *em, const tracked_session_t *ts, f64 now)
{
  /* check if the session has seen entries below the silence timeout threshold */
  /* do not export to prometheus otherwise */
  if (em->session_silence_timeout <= 0.0)
    return 0;

  if (ts->last_update <= 0.0)
    return 0;

  return (now - ts->last_update) > em->session_silence_timeout;
}

static void
build_base_labels (char *buf, size_t buflen, const sfdp_session_stats_ring_entry_t *s,
		   const char *proto, const char *src_ip, const char *dst_ip,
		   const char *ip_version, u8 include_opaque, const char *opaque_label,
		   const char *opaque_value)
{
  /* base labels are apprended to each counter/gauge */
  if (include_opaque)
    {
      snprintf (buf, buflen,
		"session_id=\"%lu\",tenant_id=\"%u\",proto=\"%s\","
		"src_ip=\"%s\",dst_ip=\"%s\",src_port=\"%u\",dst_port=\"%u\","
		"ip_version=\"%s\",%s=\"%s\"",
		s->session_id, s->tenant_id, proto, src_ip, dst_ip, s->src_port, s->dst_port,
		ip_version, opaque_label, opaque_value);
    }
  else
    {
      snprintf (buf, buflen,
		"session_id=\"%lu\",tenant_id=\"%u\",proto=\"%s\","
		"src_ip=\"%s\",dst_ip=\"%s\",src_port=\"%u\",dst_port=\"%u\","
		"ip_version=\"%s\"",
		s->session_id, s->tenant_id, proto, src_ip, dst_ip, s->src_port, s->dst_port,
		ip_version);
    }
}

void
dump_session_metrics (FILE *stream, stat_client_main_t *shm)
{
  session_exporter_main_t *em = &exporter_main;
  ring_schema_t *schema = &em->schema;
  char src_ip[INET6_ADDRSTRLEN];
  char dst_ip[INET6_ADDRSTRLEN];

  /* consume ring buffer entries, and fill exportain main session table */
  consume_result_t rv = consume_ring_buffer_entries (shm);
  if (rv != CONSUME_OK)
    {
      if (rv == CONSUME_ERR_SCHEMA)
	fprintf (stream, "# SFDP session stats schema missing required fields\n");
      else if (rv == CONSUME_ERR_CONFIG)
	fprintf (stream, "# SFDP session stats ring config invalid\n");
      else
	{
	  fprintf (stream, "# SFDP session stats ring buffer not found or not enabled\n");
	  fprintf (stream, "# Enable with: sfdp session stats ring enable\n");
	}
      return;
    }

  /* emit 'help' entry for each type that is valid / present ring buffer schema */
  EMIT_HELP_TYPE (stream, schema, FIELD_PACKETS_FORWARD, "sfdp_session_packets_forward",
		  "Total forward packets for session", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_PACKETS_REVERSE, "sfdp_session_packets_reverse",
		  "Total reverse packets for session", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_BYTES_FORWARD, "sfdp_session_bytes_forward",
		  "Total forward bytes for session", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_BYTES_REVERSE, "sfdp_session_bytes_reverse",
		  "Total reverse bytes for session", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_DURATION, "sfdp_session_duration_seconds",
		  "Session duration in seconds", "gauge");

  fprintf (stream, "# HELP sfdp_session_info Session information (always 1)\n");
  fprintf (stream, "# TYPE sfdp_session_info gauge\n");

  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_MIN_FORWARD, "sfdp_session_ttl_min_forward",
		  "Minimum TTL forward direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_MAX_FORWARD, "sfdp_session_ttl_max_forward",
		  "Maximum TTL forward direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_MIN_REVERSE, "sfdp_session_ttl_min_reverse",
		  "Minimum TTL reverse direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_MAX_REVERSE, "sfdp_session_ttl_max_reverse",
		  "Maximum TTL reverse direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_MEAN_FORWARD, "sfdp_session_ttl_mean_forward",
		  "Mean TTL forward direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_MEAN_REVERSE, "sfdp_session_ttl_mean_reverse",
		  "Mean TTL reverse direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_STDDEV_FORWARD, "sfdp_session_ttl_stddev_forward",
		  "TTL stddev forward direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TTL_STDDEV_REVERSE, "sfdp_session_ttl_stddev_reverse",
		  "TTL stddev reverse direction", "gauge");

  EMIT_HELP_TYPE (stream, schema, FIELD_RTT_MEAN_FORWARD, "sfdp_session_rtt_mean_forward_seconds",
		  "Mean RTT forward direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_RTT_MEAN_REVERSE, "sfdp_session_rtt_mean_reverse_seconds",
		  "Mean RTT reverse direction", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_RTT_STDDEV_FORWARD,
		  "sfdp_session_rtt_stddev_forward_seconds", "RTT stddev forward direction",
		  "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_RTT_STDDEV_REVERSE,
		  "sfdp_session_rtt_stddev_reverse_seconds", "RTT stddev reverse direction",
		  "gauge");

  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_MSS, "sfdp_session_tcp_mss", "TCP Maximum Segment Size",
		  "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_HANDSHAKE_COMPLETE,
		  "sfdp_session_tcp_handshake_complete", "TCP handshake completed (0 or 1)",
		  "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_SYN_PACKETS, "sfdp_session_tcp_syn_packets",
		  "TCP SYN packets counter", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_FIN_PACKETS, "sfdp_session_tcp_fin_packets",
		  "TCP FIN packets counter", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_RST_PACKETS, "sfdp_session_tcp_rst_packets",
		  "TCP RST packets counter", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_RETRANSMISSIONS_FWD,
		  "sfdp_session_tcp_retransmissions_forward", "TCP retransmissions forward",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_RETRANSMISSIONS_REV,
		  "sfdp_session_tcp_retransmissions_reverse", "TCP retransmissions reverse",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_ZERO_WINDOW_EVENTS_FWD,
		  "sfdp_session_tcp_zero_window_forward", "TCP zero window events forward",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_ZERO_WINDOW_EVENTS_REV,
		  "sfdp_session_tcp_zero_window_reverse", "TCP zero window events reverse",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_DUPACK_EVENTS_FWD, "sfdp_session_tcp_dupack_forward",
		  "TCP duplicate ACK events forward", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_DUPACK_EVENTS_REV, "sfdp_session_tcp_dupack_reverse",
		  "TCP duplicate ACK events reverse", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_PARTIAL_OVERLAP_EVENTS_FWD,
		  "sfdp_session_tcp_partial_overlap_forward", "TCP partial overlap events forward",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_PARTIAL_OVERLAP_EVENTS_REV,
		  "sfdp_session_tcp_partial_overlap_reverse", "TCP partial overlap events reverse",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_OUT_OF_ORDER_EVENTS_FWD,
		  "sfdp_session_tcp_out_of_order_forward", "TCP out-of-order events forward",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_OUT_OF_ORDER_EVENTS_REV,
		  "sfdp_session_tcp_out_of_order_reverse", "TCP out-of-order events reverse",
		  "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_ECN_ECT_PACKETS, "sfdp_session_tcp_ecn_ect_packets",
		  "Packets with ECN ECT(0) or ECT(1) marks", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_ECN_CE_PACKETS, "sfdp_session_tcp_ecn_ce_packets",
		  "Packets with ECN CE (Congestion Experienced)", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_ECE_PACKETS, "sfdp_session_tcp_ece_packets",
		  "TCP packets with ECE flag", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_CWR_PACKETS, "sfdp_session_tcp_cwr_packets",
		  "TCP packets with CWR flag", "counter");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_LAST_SEQ_FORWARD, "sfdp_session_tcp_last_seq_forward",
		  "Last TCP seq forward", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_LAST_ACK_FORWARD, "sfdp_session_tcp_last_ack_forward",
		  "Last TCP ack forward", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_LAST_SEQ_REVERSE, "sfdp_session_tcp_last_seq_reverse",
		  "Last TCP seq reverse", "gauge");
  EMIT_HELP_TYPE (stream, schema, FIELD_TCP_LAST_ACK_REVERSE, "sfdp_session_tcp_last_ack_reverse",
		  "Last TCP ack reverse", "gauge");

  f64 now = unix_time_now ();

  /* iterate over all sessions cached in the exporter main */
  for (u32 i = 0; i < vec_len (em->sessions); i++)
    {
      tracked_session_t *ts = &em->sessions[i];
      sfdp_session_stats_ring_entry_t *s = &ts->stats;
      char base_labels[1024];

      if (session_is_silent (em, ts, now))
	continue;

      format_ip_address_text (src_ip, sizeof (src_ip), s->src_ip, s->is_ip4);
      format_ip_address_text (dst_ip, sizeof (dst_ip), s->dst_ip, s->is_ip4);

      const char *proto = proto_to_string (s->proto);
      const char *ip_version = s->is_ip4 ? "4" : "6";

      const char *opaque_label =
	em->opaque_label ? (const char *) em->opaque_label : OPAQUE_LABEL_DEFAULT_NAME;
      char opaque_value_str[32] = { 0 };
      u8 include_opaque = 0;
      if (em->schema.has_opaque_label)
	{
	  snprintf (opaque_value_str, sizeof (opaque_value_str), "%" PRIu64, s->opaque.value);
	  include_opaque = 1;
	}

      build_base_labels (base_labels, sizeof (base_labels), s, proto, src_ip, dst_ip, ip_version,
			 include_opaque, opaque_label, opaque_value_str);

      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_PACKETS_FORWARD,
		      "sfdp_session_packets_forward", "%lu", s->packets_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_PACKETS_REVERSE,
		      "sfdp_session_packets_reverse", "%lu", s->packets_reverse);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_BYTES_FORWARD,
		      "sfdp_session_bytes_forward", "%lu", s->bytes_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_BYTES_REVERSE,
		      "sfdp_session_bytes_reverse", "%lu", s->bytes_reverse);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_DURATION,
		      "sfdp_session_duration_seconds", "%.6f", s->duration);

      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_MIN_FORWARD,
		      "sfdp_session_ttl_min_forward", "%u", s->ttl_min_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_MAX_FORWARD,
		      "sfdp_session_ttl_max_forward", "%u", s->ttl_max_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_MIN_REVERSE,
		      "sfdp_session_ttl_min_reverse", "%u", s->ttl_min_reverse);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_MAX_REVERSE,
		      "sfdp_session_ttl_max_reverse", "%u", s->ttl_max_reverse);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_MEAN_FORWARD,
		      "sfdp_session_ttl_mean_forward", "%.2f", s->ttl_mean_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_MEAN_REVERSE,
		      "sfdp_session_ttl_mean_reverse", "%.2f", s->ttl_mean_reverse);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_STDDEV_FORWARD,
		      "sfdp_session_ttl_stddev_forward", "%.2f", s->ttl_stddev_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TTL_STDDEV_REVERSE,
		      "sfdp_session_ttl_stddev_reverse", "%.2f", s->ttl_stddev_reverse);

      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_RTT_MEAN_FORWARD,
		      "sfdp_session_rtt_mean_forward_seconds", "%.6f", s->rtt_mean_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_RTT_MEAN_REVERSE,
		      "sfdp_session_rtt_mean_reverse_seconds", "%.6f", s->rtt_mean_reverse);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_RTT_STDDEV_FORWARD,
		      "sfdp_session_rtt_stddev_forward_seconds", "%.6f", s->rtt_stddev_forward);
      EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_RTT_STDDEV_REVERSE,
		      "sfdp_session_rtt_stddev_reverse_seconds", "%.6f", s->rtt_stddev_reverse);

      if (s->proto == 6)
	{
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_MSS, "sfdp_session_tcp_mss",
			  "%u", s->tcp_mss);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_HANDSHAKE_COMPLETE,
			  "sfdp_session_tcp_handshake_complete", "%u", s->tcp_handshake_complete);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_SYN_PACKETS,
			  "sfdp_session_tcp_syn_packets", "%u", s->tcp_syn_packets);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_FIN_PACKETS,
			  "sfdp_session_tcp_fin_packets", "%u", s->tcp_fin_packets);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_RST_PACKETS,
			  "sfdp_session_tcp_rst_packets", "%u", s->tcp_rst_packets);

	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_RETRANSMISSIONS_FWD,
			  "sfdp_session_tcp_retransmissions_forward", "%u",
			  s->tcp_retransmissions_fwd);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_RETRANSMISSIONS_REV,
			  "sfdp_session_tcp_retransmissions_reverse", "%u",
			  s->tcp_retransmissions_rev);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_ZERO_WINDOW_EVENTS_FWD,
			  "sfdp_session_tcp_zero_window_forward", "%u",
			  s->tcp_zero_window_events_fwd);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_ZERO_WINDOW_EVENTS_REV,
			  "sfdp_session_tcp_zero_window_reverse", "%u",
			  s->tcp_zero_window_events_rev);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_DUPACK_EVENTS_FWD,
			  "sfdp_session_tcp_dupack_forward", "%u", s->tcp_dupack_events_fwd);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_DUPACK_EVENTS_REV,
			  "sfdp_session_tcp_dupack_reverse", "%u", s->tcp_dupack_events_rev);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_PARTIAL_OVERLAP_EVENTS_FWD,
			  "sfdp_session_tcp_partial_overlap_forward", "%u",
			  s->tcp_partial_overlap_events_fwd);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_PARTIAL_OVERLAP_EVENTS_REV,
			  "sfdp_session_tcp_partial_overlap_reverse", "%u",
			  s->tcp_partial_overlap_events_rev);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_OUT_OF_ORDER_EVENTS_FWD,
			  "sfdp_session_tcp_out_of_order_forward", "%u",
			  s->tcp_out_of_order_events_fwd);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_OUT_OF_ORDER_EVENTS_REV,
			  "sfdp_session_tcp_out_of_order_reverse", "%u",
			  s->tcp_out_of_order_events_rev);

	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_ECN_ECT_PACKETS,
			  "sfdp_session_tcp_ecn_ect_packets", "%u", s->tcp_ecn_ect_packets);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_ECN_CE_PACKETS,
			  "sfdp_session_tcp_ecn_ce_packets", "%u", s->tcp_ecn_ce_packets);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_ECE_PACKETS,
			  "sfdp_session_tcp_ece_packets", "%u", s->tcp_ece_packets);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_CWR_PACKETS,
			  "sfdp_session_tcp_cwr_packets", "%u", s->tcp_cwr_packets);

	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_LAST_SEQ_FORWARD,
			  "sfdp_session_tcp_last_seq_forward", "%u", s->tcp_last_seq_forward);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_LAST_ACK_FORWARD,
			  "sfdp_session_tcp_last_ack_forward", "%u", s->tcp_last_ack_forward);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_LAST_SEQ_REVERSE,
			  "sfdp_session_tcp_last_seq_reverse", "%u", s->tcp_last_seq_reverse);
	  EMIT_METRIC_IF (stream, em, schema, base_labels, FIELD_TCP_LAST_ACK_REVERSE,
			  "sfdp_session_tcp_last_ack_reverse", "%u", s->tcp_last_ack_reverse);
	}

      /* Export session identity labels only (no session_index label). */
      emit_metric (stream, em, "sfdp_session_info", base_labels, "1");
    }
}
