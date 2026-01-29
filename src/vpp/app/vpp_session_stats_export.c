/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

/*
 * vpp_session_stats_export.c
 *
 * Prometheus exporter for SFDP session statistics ring buffer.
 * Reads session stats from the VPP stats segment ring buffer and
 * exposes them as Prometheus metrics with session-based labels.
 */

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#ifdef __FreeBSD__
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* __FreeBSD__ */
#include <sys/socket.h>
#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>
#include <vlib/stats/shared.h>
#include <ctype.h>

/* Default port - using 9483 (one after prometheus default 9482) */
#define SERVER_PORT 9482

/* Ring buffer name for SFDP session stats */
#define SFDP_SESSION_STATS_RING "/sfdp/session/stats"

/* Session stats ring entry size (must match session_stats.h) */
#define SESSION_STATS_ENTRY_SIZE 512

/* Maximum sessions to track for Prometheus (to limit memory) */
#define MAX_TRACKED_SESSIONS 10000

#define ROOTPAGE                                                                                   \
  "<html><head><title>SFDP Session Stats Exporter</title></head>"                                  \
  "<body><h1>SFDP Session Statistics Prometheus Exporter</h1>"                                     \
  "<ul><li><a href=\"/metrics\">metrics</a></li></ul></body></html>"

#define NOT_FOUND_ERROR                                                                            \
  "<html><head><title>Document not found</title></head>"                                           \
  "<body><h1>404 - Document not found</h1></body></html>"

/*
 * Session stats entry structure - must match sfdp_session_stats_ring_entry_t
 * from session_stats.h (512 bytes total, schema v3)
 */
typedef struct
{
  /* Core statistics - offset 0 */
  u64 session_id;
  u32 session_index;
  u32 tenant_id;
  u8 proto;
  u8 session_type;
  u8 export_reason;
  u8 is_ip4;
  u64 packets_forward;
  u64 packets_reverse;
  u64 bytes_forward;
  u64 bytes_reverse;
  f64 first_seen;
  f64 last_seen;
  f64 export_time;
  f64 duration;

  /* Forward five-tuple - offset 84 */
  u8 fwd_src_ip[16];
  u8 fwd_dst_ip[16];
  u16 fwd_src_port;
  u16 fwd_dst_port;

  /* Reverse five-tuple - offset 120 */
  u8 rev_src_ip[16];
  u8 rev_dst_ip[16];
  u16 rev_src_port;
  u16 rev_dst_port;

  /* TTL statistics per direction - offset 156 */
  u8 ttl_min_forward;
  u8 ttl_max_forward;
  u8 ttl_min_reverse;
  u8 ttl_max_reverse;
  f64 ttl_mean_forward;
  f64 ttl_mean_reverse;
  f64 ttl_stddev_forward;
  f64 ttl_stddev_reverse;

  /* RTT statistics per direction - offset 192 */
  f64 rtt_mean_forward;
  f64 rtt_mean_reverse;
  f64 rtt_stddev_forward;
  f64 rtt_stddev_reverse;

  /* TCP information - offset 224 */
  u16 tcp_mss;
  u8 tcp_handshake_complete;
  u8 reserved_tcp_info;

  /* TCP packet counters - offset 228 */
  u32 tcp_syn_packets;
  u32 tcp_fin_packets;
  u32 tcp_rst_packets;

  /* TCP events per direction - offset 240 */
  u32 tcp_retransmissions_fwd;
  u32 tcp_retransmissions_rev;
  u32 tcp_zero_window_events_fwd;
  u32 tcp_zero_window_events_rev;
  u32 tcp_dupack_events_fwd;
  u32 tcp_dupack_events_rev;
  u32 tcp_partial_overlap_events_fwd;
  u32 tcp_partial_overlap_events_rev;

  /* TCP sequence window - offset 272 */
  u32 tcp_last_seq_forward;
  u32 tcp_last_ack_forward;
  u32 tcp_last_seq_reverse;
  u32 tcp_last_ack_reverse;

  /* Decorator metadata - offset 288 */
  u8 decorator_type;
  u8 decorator_flags;
  u8 reserved_meta[6];

  /* Decorator data - offset 296, size 64 */
  u8 decorator[64];

  /* Padding to 512 bytes - offset 360, size 152 */
  u8 reserved_pad[152];
} __clib_packed session_stats_entry_t;

STATIC_ASSERT_SIZEOF (session_stats_entry_t, SESSION_STATS_ENTRY_SIZE);

/*
 * Session key for tracking unique sessions
 */
typedef struct
{
  u64 session_id;
  u32 tenant_id;
} session_key_t;

/*
 * Tracked session with latest stats
 */
typedef struct
{
  session_key_t key;
  session_stats_entry_t stats;
  f64 last_update;
} tracked_session_t;

/*
 * Global state
 */
typedef struct
{
  tracked_session_t *sessions; /* vec of tracked sessions */
  uword *session_index_by_id;  /* hash: session_id -> index in sessions vec */
  u64 local_tail;	       /* Local consumer position */
  u64 last_sequence;	       /* Last seen sequence number */
  u8 initialized;	       /* Whether we've started tracking */
  u8 *instance;		       /* Optional instance name for metrics */
} session_exporter_main_t;

static session_exporter_main_t exporter_main;

/*
 * Protocol number to name mapping
 */
static const char *
proto_to_string (u8 proto)
{
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

/*
 * Export reason to string
 */
static const char *
export_reason_to_string (u8 reason)
{
  switch (reason)
    {
    case 0:
      return "periodic";
    case 1:
      return "expiry";
    case 2:
      return "api_request";
    default:
      return "unknown";
    }
}

/*
 * Format IPv4/IPv6 address to string
 */
static void
format_ip_address (char *buf, size_t buflen, u8 *ip, u8 is_ip4)
{
  if (is_ip4)
    {
      snprintf (buf, buflen, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    }
  else
    {
      inet_ntop (AF_INET6, ip, buf, buflen);
    }
}

/*
 * Find ring buffer entry in stats segment by name
 */
static vlib_stats_entry_t *
find_ring_buffer_entry (stat_client_main_t *shm, const char *name)
{
  vlib_stats_entry_t *ep;
  vlib_stats_entry_t *entries = shm->directory_vector;

  for (u32 i = 0; i < vec_len (entries); i++)
    {
      ep = &entries[i];
      if (ep->type == STAT_DIR_TYPE_RING_BUFFER && strcmp (ep->name, name) == 0)
	return ep;
    }
  return NULL;
}

/*
 * Read ring buffer metadata
 */
typedef struct
{
  u32 head;
  u32 schema_version;
  u64 sequence;
  u32 schema_offset;
  u32 schema_size;
} ring_metadata_t;

typedef struct
{
  u32 entry_size;
  u32 ring_size;
  u32 n_threads;
  u32 schema_size;
  u32 schema_version;
  u32 metadata_offset;
  u32 data_offset;
} ring_config_t;

static void
read_ring_config (stat_client_main_t *shm, vlib_stats_entry_t *ep, ring_config_t *config)
{
  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    {
      memset (config, 0, sizeof (*config));
      return;
    }

  /* Read config structure */
  memcpy (&config->entry_size, ring_ptr, sizeof (u32));
  memcpy (&config->ring_size, ring_ptr + 4, sizeof (u32));
  memcpy (&config->n_threads, ring_ptr + 8, sizeof (u32));
  memcpy (&config->schema_size, ring_ptr + 12, sizeof (u32));
  memcpy (&config->schema_version, ring_ptr + 16, sizeof (u32));
  memcpy (&config->metadata_offset, ring_ptr + 20, sizeof (u32));
  memcpy (&config->data_offset, ring_ptr + 24, sizeof (u32));
}

static void
read_ring_metadata (stat_client_main_t *shm, vlib_stats_entry_t *ep, ring_config_t *config,
		    u32 thread_index, ring_metadata_t *metadata)
{
  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    {
      memset (metadata, 0, sizeof (*metadata));
      return;
    }
  u8 *metadata_ptr = ring_ptr + config->metadata_offset + (thread_index * 64);

  memcpy (&metadata->head, metadata_ptr, sizeof (u32));
  memcpy (&metadata->schema_version, metadata_ptr + 4, sizeof (u32));
  memcpy (&metadata->sequence, metadata_ptr + 8, sizeof (u64));
  memcpy (&metadata->schema_offset, metadata_ptr + 16, sizeof (u32));
  memcpy (&metadata->schema_size, metadata_ptr + 20, sizeof (u32));
}

/*
 * Consume entries from ring buffer and update tracked sessions
 */
static int
consume_ring_buffer_entries (stat_client_main_t *shm)
{
  session_exporter_main_t *em = &exporter_main;
  stat_segment_access_t sa;

  /* Start safe access to stats segment */
  if (stat_segment_access_start (&sa, shm))
    return -1;

  vlib_stats_entry_t *ep = find_ring_buffer_entry (shm, SFDP_SESSION_STATS_RING);
  if (!ep)
    {
      stat_segment_access_end (&sa, shm);
      return -1; /* Ring buffer not found */
    }

  ring_config_t config;
  read_ring_config (shm, ep, &config);

  if (config.entry_size != SESSION_STATS_ENTRY_SIZE)
    {
      fprintf (stderr, "Entry size mismatch: expected %d, got %d\n", SESSION_STATS_ENTRY_SIZE,
	       config.entry_size);
      stat_segment_access_end (&sa, shm);
      return -1;
    }

  /* Process thread 0 only for now */
  u32 thread_index = 0;
  ring_metadata_t metadata;
  read_ring_metadata (shm, ep, &config, thread_index, &metadata);

  u8 *ring_ptr = (u8 *) stat_segment_adjust (shm, ep->data);
  if (!ring_ptr)
    {
      stat_segment_access_end (&sa, shm);
      return -1;
    }
  u8 *data_ptr = ring_ptr + config.data_offset;

  /* Initialize on first run */
  if (!em->initialized)
    {
      em->local_tail = metadata.head;
      em->last_sequence = metadata.sequence;
      em->initialized = 1;
      stat_segment_access_end (&sa, shm);
      return 0;
    }

  /* Check for overwrite (producer lapped us) */
  u64 delta = metadata.sequence - em->last_sequence;
  if (delta > config.ring_size)
    {
      /* We were overwritten, reset to current head */
      fprintf (stderr, "Ring buffer overrun detected, resetting consumer\n");
      em->local_tail = metadata.head;
      em->last_sequence = metadata.sequence;
      stat_segment_access_end (&sa, shm);
      return 0;
    }

  /* Consume all available entries */
  while (em->local_tail != metadata.head)
    {
      u32 offset = em->local_tail * config.entry_size;
      session_stats_entry_t *entry = (session_stats_entry_t *) (data_ptr + offset);

      /* Look up or create tracked session */
      session_key_t key = { .session_id = entry->session_id, .tenant_id = entry->tenant_id };

      uword *p = hash_get (em->session_index_by_id, entry->session_id);
      if (p)
	{
	  /* Update existing session */
	  u32 idx = p[0];
	  if (idx < vec_len (em->sessions))
	    {
	      memcpy (&em->sessions[idx].stats, entry, sizeof (*entry));
	      em->sessions[idx].last_update = entry->export_time;
	    }
	}
      else
	{
	  /* Add new session if we have room */
	  if (vec_len (em->sessions) < MAX_TRACKED_SESSIONS)
	    {
	      tracked_session_t ts;
	      ts.key = key;
	      memcpy (&ts.stats, entry, sizeof (*entry));
	      ts.last_update = entry->export_time;

	      u32 idx = vec_len (em->sessions);
	      vec_add1 (em->sessions, ts);
	      hash_set (em->session_index_by_id, entry->session_id, idx);
	    }
	}

      em->local_tail = (em->local_tail + 1) % config.ring_size;
    }

  em->last_sequence = metadata.sequence;
  stat_segment_access_end (&sa, shm);
  return 0;
}

/*
 * Dump session stats as Prometheus metrics
 */
static void
dump_session_metrics (FILE *stream, stat_client_main_t *shm)
{
  session_exporter_main_t *em = &exporter_main;
  char src_ip[INET6_ADDRSTRLEN];
  char dst_ip[INET6_ADDRSTRLEN];

  /* First consume any new entries from ring buffer */
  if (consume_ring_buffer_entries (shm) < 0)
    {
      fprintf (stream, "# SFDP session stats ring buffer not found or not enabled\n");
      fprintf (stream, "# Enable with: sfdp session stats ring enable\n");
      return;
    }

  /* Output HELP and TYPE declarations */
  fprintf (stream, "# HELP sfdp_session_packets_forward Total forward packets for session\n");
  fprintf (stream, "# TYPE sfdp_session_packets_forward counter\n");

  fprintf (stream, "# HELP sfdp_session_packets_reverse Total reverse packets for session\n");
  fprintf (stream, "# TYPE sfdp_session_packets_reverse counter\n");

  fprintf (stream, "# HELP sfdp_session_bytes_forward Total forward bytes for session\n");
  fprintf (stream, "# TYPE sfdp_session_bytes_forward counter\n");

  fprintf (stream, "# HELP sfdp_session_bytes_reverse Total reverse bytes for session\n");
  fprintf (stream, "# TYPE sfdp_session_bytes_reverse counter\n");

  fprintf (stream, "# HELP sfdp_session_duration_seconds Session duration in seconds\n");
  fprintf (stream, "# TYPE sfdp_session_duration_seconds gauge\n");

  fprintf (stream, "# HELP sfdp_session_first_seen_timestamp Session first seen timestamp\n");
  fprintf (stream, "# TYPE sfdp_session_first_seen_timestamp gauge\n");

  fprintf (stream, "# HELP sfdp_session_last_seen_timestamp Session last seen timestamp\n");
  fprintf (stream, "# TYPE sfdp_session_last_seen_timestamp gauge\n");

  fprintf (stream, "# HELP sfdp_session_export_time_timestamp Session export timestamp\n");
  fprintf (stream, "# TYPE sfdp_session_export_time_timestamp gauge\n");

  fprintf (stream, "# HELP sfdp_session_info Session information (always 1)\n");
  fprintf (stream, "# TYPE sfdp_session_info gauge\n");

  /* TTL statistics */
  fprintf (stream, "# HELP sfdp_session_ttl_min_forward Minimum TTL forward direction\n");
  fprintf (stream, "# TYPE sfdp_session_ttl_min_forward gauge\n");
  fprintf (stream, "# HELP sfdp_session_ttl_max_forward Maximum TTL forward direction\n");
  fprintf (stream, "# TYPE sfdp_session_ttl_max_forward gauge\n");
  fprintf (stream, "# HELP sfdp_session_ttl_min_reverse Minimum TTL reverse direction\n");
  fprintf (stream, "# TYPE sfdp_session_ttl_min_reverse gauge\n");
  fprintf (stream, "# HELP sfdp_session_ttl_max_reverse Maximum TTL reverse direction\n");
  fprintf (stream, "# TYPE sfdp_session_ttl_max_reverse gauge\n");
  fprintf (stream, "# HELP sfdp_session_ttl_mean_forward Mean TTL forward direction\n");
  fprintf (stream, "# TYPE sfdp_session_ttl_mean_forward gauge\n");
  fprintf (stream, "# HELP sfdp_session_ttl_mean_reverse Mean TTL reverse direction\n");
  fprintf (stream, "# TYPE sfdp_session_ttl_mean_reverse gauge\n");

  /* RTT statistics */
  fprintf (stream, "# HELP sfdp_session_rtt_mean_forward_seconds Mean RTT forward direction\n");
  fprintf (stream, "# TYPE sfdp_session_rtt_mean_forward_seconds gauge\n");
  fprintf (stream, "# HELP sfdp_session_rtt_mean_reverse_seconds Mean RTT reverse direction\n");
  fprintf (stream, "# TYPE sfdp_session_rtt_mean_reverse_seconds gauge\n");

  /* TCP metrics */
  fprintf (stream, "# HELP sfdp_session_tcp_mss TCP Maximum Segment Size\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_mss gauge\n");
  fprintf (stream, "# HELP sfdp_session_tcp_handshake_complete TCP handshake completed (0 or 1)\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_handshake_complete gauge\n");
  fprintf (stream, "# HELP sfdp_session_tcp_syn_packets TCP SYN packets counter\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_syn_packets counter\n");
  fprintf (stream, "# HELP sfdp_session_tcp_fin_packets TCP FIN packets counter\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_fin_packets counter\n");
  fprintf (stream, "# HELP sfdp_session_tcp_rst_packets TCP RST packets counter\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_rst_packets counter\n");

  /* TCP events per direction */
  fprintf (stream, "# HELP sfdp_session_tcp_retransmissions_forward TCP retransmissions forward\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_retransmissions_forward counter\n");
  fprintf (stream, "# HELP sfdp_session_tcp_retransmissions_reverse TCP retransmissions reverse\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_retransmissions_reverse counter\n");
  fprintf (stream, "# HELP sfdp_session_tcp_zero_window_forward TCP zero window events forward\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_zero_window_forward counter\n");
  fprintf (stream, "# HELP sfdp_session_tcp_zero_window_reverse TCP zero window events reverse\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_zero_window_reverse counter\n");
  fprintf (stream, "# HELP sfdp_session_tcp_dupack_forward TCP duplicate ACK events forward\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_dupack_forward counter\n");
  fprintf (stream, "# HELP sfdp_session_tcp_dupack_reverse TCP duplicate ACK events reverse\n");
  fprintf (stream, "# TYPE sfdp_session_tcp_dupack_reverse counter\n");

  fprintf (stream, "# HELP sfdp_sessions_total Total number of tracked sessions\n");
  fprintf (stream, "# TYPE sfdp_sessions_total gauge\n");
  if (em->instance)
    fprintf (stream, "sfdp_sessions_total{instance=\"%s\"} %u\n", em->instance,
	     vec_len (em->sessions));
  else
    fprintf (stream, "sfdp_sessions_total %u\n", vec_len (em->sessions));

  /* Output per-session metrics */
  for (u32 i = 0; i < vec_len (em->sessions); i++)
    {
      tracked_session_t *ts = &em->sessions[i];
      session_stats_entry_t *s = &ts->stats;

      format_ip_address (src_ip, sizeof (src_ip), s->fwd_src_ip, s->is_ip4);
      format_ip_address (dst_ip, sizeof (dst_ip), s->fwd_dst_ip, s->is_ip4);

      const char *proto = proto_to_string (s->proto);
      const char *export_reason = export_reason_to_string (s->export_reason);
      const char *ip_version = s->is_ip4 ? "4" : "6";

/* Common label set - defined based on whether instance is set */
#define LABELS_WITH_INSTANCE                                                                       \
  "instance=\"%s\",session_id=\"%lu\",tenant_id=\"%u\",proto=\"%s\","                              \
  "src_ip=\"%s\",dst_ip=\"%s\",src_port=\"%u\",dst_port=\"%u\","                                   \
  "ip_version=\"%s\""

#define LABELS_WITHOUT_INSTANCE                                                                    \
  "session_id=\"%lu\",tenant_id=\"%u\",proto=\"%s\","                                              \
  "src_ip=\"%s\",dst_ip=\"%s\",src_port=\"%u\",dst_port=\"%u\","                                   \
  "ip_version=\"%s\""

#define EMIT_METRIC(metric_name, fmt, value)                                                       \
  do                                                                                               \
    {                                                                                              \
      if (em->instance)                                                                            \
	fprintf (stream, metric_name "{" LABELS_WITH_INSTANCE "} " fmt "\n", em->instance,         \
		 s->session_id, s->tenant_id, proto, src_ip, dst_ip, s->fwd_src_port,              \
		 s->fwd_dst_port, ip_version, value);                                              \
      else                                                                                         \
	fprintf (stream, metric_name "{" LABELS_WITHOUT_INSTANCE "} " fmt "\n", s->session_id,     \
		 s->tenant_id, proto, src_ip, dst_ip, s->fwd_src_port, s->fwd_dst_port,            \
		 ip_version, value);                                                               \
    }                                                                                              \
  while (0)

      /* Packet counters */

      EMIT_METRIC ("sfdp_session_packets_forward", "%lu", s->packets_forward);
      EMIT_METRIC ("sfdp_session_packets_reverse", "%lu", s->packets_reverse);

      /* Byte counters */
      EMIT_METRIC ("sfdp_session_bytes_forward", "%lu", s->bytes_forward);
      EMIT_METRIC ("sfdp_session_bytes_reverse", "%lu", s->bytes_reverse);

      /* Duration gauge */
      EMIT_METRIC ("sfdp_session_duration_seconds", "%.6f", s->duration);

      /* Timestamps */
      EMIT_METRIC ("sfdp_session_first_seen_timestamp", "%.6f", s->first_seen);
      EMIT_METRIC ("sfdp_session_last_seen_timestamp", "%.6f", s->last_seen);
      EMIT_METRIC ("sfdp_session_export_time_timestamp", "%.6f", s->export_time);

      /* TTL statistics */
      EMIT_METRIC ("sfdp_session_ttl_min_forward", "%u", s->ttl_min_forward);
      EMIT_METRIC ("sfdp_session_ttl_max_forward", "%u", s->ttl_max_forward);
      EMIT_METRIC ("sfdp_session_ttl_min_reverse", "%u", s->ttl_min_reverse);
      EMIT_METRIC ("sfdp_session_ttl_max_reverse", "%u", s->ttl_max_reverse);
      EMIT_METRIC ("sfdp_session_ttl_mean_forward", "%.2f", s->ttl_mean_forward);
      EMIT_METRIC ("sfdp_session_ttl_mean_reverse", "%.2f", s->ttl_mean_reverse);

      /* RTT statistics */
      EMIT_METRIC ("sfdp_session_rtt_mean_forward_seconds", "%.6f", s->rtt_mean_forward);
      EMIT_METRIC ("sfdp_session_rtt_mean_reverse_seconds", "%.6f", s->rtt_mean_reverse);

      /* TCP-specific metrics (only for TCP sessions) */
      if (s->proto == 6) /* TCP */
	{
	  EMIT_METRIC ("sfdp_session_tcp_mss", "%u", s->tcp_mss);
	  EMIT_METRIC ("sfdp_session_tcp_handshake_complete", "%u", s->tcp_handshake_complete);
	  EMIT_METRIC ("sfdp_session_tcp_syn_packets", "%u", s->tcp_syn_packets);
	  EMIT_METRIC ("sfdp_session_tcp_fin_packets", "%u", s->tcp_fin_packets);
	  EMIT_METRIC ("sfdp_session_tcp_rst_packets", "%u", s->tcp_rst_packets);

	  /* TCP events per direction */
	  EMIT_METRIC ("sfdp_session_tcp_retransmissions_forward", "%u",
		       s->tcp_retransmissions_fwd);
	  EMIT_METRIC ("sfdp_session_tcp_retransmissions_reverse", "%u",
		       s->tcp_retransmissions_rev);
	  EMIT_METRIC ("sfdp_session_tcp_zero_window_forward", "%u", s->tcp_zero_window_events_fwd);
	  EMIT_METRIC ("sfdp_session_tcp_zero_window_reverse", "%u", s->tcp_zero_window_events_rev);
	  EMIT_METRIC ("sfdp_session_tcp_dupack_forward", "%u", s->tcp_dupack_events_fwd);
	  EMIT_METRIC ("sfdp_session_tcp_dupack_reverse", "%u", s->tcp_dupack_events_rev);
	}

      /* Session info with additional labels */
      if (em->instance)
	fprintf (stream,
		 "sfdp_session_info{" LABELS_WITH_INSTANCE ",export_reason=\"%s\","
		 "session_index=\"%u\"} 1\n",
		 em->instance, s->session_id, s->tenant_id, proto, src_ip, dst_ip, s->fwd_src_port,
		 s->fwd_dst_port, ip_version, export_reason, s->session_index);
      else
	fprintf (stream,
		 "sfdp_session_info{" LABELS_WITHOUT_INSTANCE ",export_reason=\"%s\","
		 "session_index=\"%u\"} 1\n",
		 s->session_id, s->tenant_id, proto, src_ip, dst_ip, s->fwd_src_port,
		 s->fwd_dst_port, ip_version, export_reason, s->session_index);

#undef LABELS_WITH_INSTANCE
#undef LABELS_WITHOUT_INSTANCE
#undef EMIT_METRIC
    }
}

/*
 * HTTP request handler
 */
static void
http_handler (FILE *stream, u8 *stats_segment_name)
{
  char status[80] = { 0 };
  if (fgets (status, sizeof (status) - 1, stream) == 0)
    {
      fprintf (stderr, "fgets error: %s %s\n", status, strerror (errno));
      return;
    }

  char *saveptr;
  char *method = strtok_r (status, " \t\r\n", &saveptr);
  if (method == 0 || strncmp (method, "GET", 4) != 0)
    {
      fputs ("HTTP/1.0 405 Method Not Allowed\r\n", stream);
      return;
    }

  char *request_uri = strtok_r (NULL, " \t", &saveptr);
  char *protocol = strtok_r (NULL, " \t\r\n", &saveptr);
  if (protocol == 0 || strncmp (protocol, "HTTP/1.", 7) != 0)
    {
      fputs ("HTTP/1.0 400 Bad Request\r\n", stream);
      return;
    }

  /* Read the other headers */
  for (;;)
    {
      char header[1024];
      if (fgets (header, sizeof (header) - 1, stream) == 0)
	{
	  fprintf (stderr, "fgets error: %s\n", strerror (errno));
	  return;
	}
      if (header[0] == '\n' || header[1] == '\n')
	break;
    }

  if (strcmp (request_uri, "/") == 0)
    {
      fprintf (stream, "HTTP/1.0 200 OK\r\nContent-Length: %lu\r\n\r\n",
	       (unsigned long) strlen (ROOTPAGE));
      fputs (ROOTPAGE, stream);
      return;
    }

  if (strcmp (request_uri, "/metrics") != 0)
    {
      fprintf (stream, "HTTP/1.0 404 Not Found\r\nContent-Length: %lu\r\n\r\n",
	       (unsigned long) strlen (NOT_FOUND_ERROR));
      fputs (NOT_FOUND_ERROR, stream);
      return;
    }

  fputs ("HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", stream);

  stat_client_main_t shm;
  int rv = stat_segment_connect_r ((char *) stats_segment_name, &shm);
  if (rv)
    {
      fprintf (stream, "# ERROR: Couldn't connect to VPP stats segment\n");
      fprintf (stream, "# Check that VPP is running and %s exists\n", stats_segment_name);
      return;
    }

  dump_session_metrics (stream, &shm);
  stat_segment_disconnect_r (&shm);
}

/*
 * Start listening socket
 */
static int
start_listen (u16 port)
{
  struct sockaddr_in6 serveraddr;
  int addrlen = sizeof (serveraddr);
  int enable = 1;

  int listenfd = socket (AF_INET6, SOCK_STREAM, 0);
  if (listenfd == -1)
    {
      perror ("Failed opening socket");
      return -1;
    }

  int rv = setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof (int));
  if (rv < 0)
    {
      perror ("Failed setsockopt");
      close (listenfd);
      return -1;
    }

  clib_memset (&serveraddr, 0, sizeof (serveraddr));
  serveraddr.sin6_family = AF_INET6;
  serveraddr.sin6_port = htons (port);
  serveraddr.sin6_addr = in6addr_any;

  if (bind (listenfd, (struct sockaddr *) &serveraddr, addrlen) < 0)
    {
      fprintf (stderr, "bind() error %s\n", strerror (errno));
      close (listenfd);
      return -1;
    }

  if (listen (listenfd, 1000000) != 0)
    {
      fprintf (stderr, "listen() error for %s\n", strerror (errno));
      close (listenfd);
      return -1;
    }

  return listenfd;
}

int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  u8 *stat_segment_name;
  u16 port = SERVER_PORT;
  int rv;
  f64 session_timeout = 300.0; /* Default: remove sessions after 5 minutes */

  char *usage = "%s: usage [socket-name <name>] [port <0-65535>] "
		"[session-timeout <seconds>] [instance <name>]\n";

  /* Allocating 256MB heap */
  clib_mem_init (0, 256 << 20);

  unformat_init_command_line (a, argv);

  stat_segment_name = (u8 *) STAT_SEGMENT_SOCKET_FILE;

  /* Initialize exporter state */
  session_exporter_main_t *em = &exporter_main;
  em->sessions = 0;
  em->session_index_by_id = hash_create (0, sizeof (uword));
  em->local_tail = 0;
  em->last_sequence = 0;
  em->initialized = 0;
  em->instance = 0;

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "socket-name %s", &stat_segment_name))
	;
      else if (unformat (a, "port %d", &port))
	;
      else if (unformat (a, "session-timeout %f", &session_timeout))
	;
      else if (unformat (a, "instance %s", &em->instance))
	;
      else if (unformat (a, "help"))
	{
	  fformat (stderr, usage, argv[0]);
	  fformat (stderr, "\nOptions:\n");
	  fformat (stderr,
		   "  socket-name <name>  VPP stats socket path "
		   "(default: %s)\n",
		   STAT_SEGMENT_SOCKET_FILE);
	  fformat (stderr,
		   "  port <0-65535>      HTTP server port "
		   "(default: %d)\n",
		   SERVER_PORT);
	  fformat (stderr, "  session-timeout <s> Session expiry time "
			   "(default: 300s)\n");
	  fformat (stderr, "  instance <name>      Instance name for metrics "
			   "(optional)\n");
	  exit (0);
	}
      else
	{
	  fformat (stderr, usage, argv[0]);
	  exit (1);
	}
    }

  /* Verify we can connect to VPP */
  stat_client_main_t shm;
  rv = stat_segment_connect_r ((char *) stat_segment_name, &shm);
  if (rv)
    {
      fformat (stderr, "Couldn't connect to VPP, does %s exist?\n", stat_segment_name);
      exit (1);
    }
  stat_segment_disconnect_r (&shm);

  fprintf (stderr, "SFDP Session Stats Prometheus Exporter starting...\n");
  fprintf (stderr, "  Stats socket: %s\n", stat_segment_name);
  fprintf (stderr, "  HTTP port: %d\n", port);
  fprintf (stderr, "  Session timeout: %.0f seconds\n", session_timeout);
  if (em->instance)
    fprintf (stderr, "  Instance: %s\n", em->instance);
  fprintf (stderr, "  Metrics URL: http://localhost:%d/metrics\n", port);

  int fd = start_listen (port);
  if (fd < 0)
    {
      exit (1);
    }

  for (;;)
    {
      int conn_sock = accept (fd, NULL, NULL);
      if (conn_sock < 0)
	{
	  fprintf (stderr, "Accept failed: %s\n", strerror (errno));
	  continue;
	}
      else
	{
	  struct sockaddr_in6 clientaddr = { 0 };
	  char address[INET6_ADDRSTRLEN];
	  memset (address, 0, sizeof (address));
	  socklen_t addrlen = sizeof (clientaddr);
	  getpeername (conn_sock, (struct sockaddr *) &clientaddr, &addrlen);
	  if (inet_ntop (AF_INET6, &clientaddr.sin6_addr, address, sizeof (address)))
	    {
	      fprintf (stderr, "Client: [%s]:%d\n", address, ntohs (clientaddr.sin6_port));
	    }
	}

      FILE *stream = fdopen (conn_sock, "r+");
      if (stream == NULL)
	{
	  fprintf (stderr, "fdopen error: %s\n", strerror (errno));
	  close (conn_sock);
	  continue;
	}

      http_handler (stream, stat_segment_name);
      fclose (stream);
    }

  /* Cleanup */
  vec_free (em->sessions);
  hash_free (em->session_index_by_id);
  vec_free (em->instance);
  close (fd);

  exit (0);
}
