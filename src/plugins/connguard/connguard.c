/* SPDX-License-Identifier: Apache-2.0 */

/*
 * connguard.c — mighty_xddos Application Filter (VPP mode) control plane:
 * interface roles and feature attachment, protected services, settings,
 * the once-a-second scan process (Slow Connection Guard verdicts, resets,
 * per-source connection counts, each server's top new-connection
 * sources), and the `connguard` / `show connguard` CLI. See node.c's
 * package doc comment for the packet path. Behaviour mirrors
 * ebpf/xdp_bridge/xdp_bridge_daemon.c's app_filter_thread; the JSON the
 * `show connguard stats|events` commands print has exactly the shape of
 * that daemon's "app-filter-stats"/"app-filter-events" replies, so
 * virtserver parses both modes with the same code.
 *
 * Every mutating command is silent on success, like floodguard's —
 * virtserver's RunVppCtl treats any output as an anomaly.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/format.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/interface_funcs.h>
#include <vpp/app/version.h>

#include <connguard/connguard.h>

connguard_main_t connguard_main;

static const char *const connguard_reason_names[CONNGUARD_R_COUNT] = {
  "slow-request", "silent-hold", "slow-read", "conn-limit", "conn-rate"
};
static const char *const connguard_action_names[] = { "monitor", "reset",
						      "reset-failed",
						      "report" };

typedef struct
{
  u32 gen;
  u32 client;
  u32 server;
  u16 port; /* 0 = per-server total for this client */
  u16 pad;
  u32 conns;
  u32 news;
} connguard_agg_t;

typedef struct
{
  u64 ts;
  u32 client, server;
  u16 port;
  u8 reason;
  u8 used;
} connguard_dedup_t;

void
connguard_ensure_init (void)
{
  connguard_main_t *cm = &connguard_main;

  if (cm->initialized)
    return;

  clib_bihash_init_8_8 (&cm->svc_table, "connguard protected services",
			1024, 0);

  cm->s.mode = CONNGUARD_MODE_MONITOR;
  cm->s.req_timeout_sec = 10;
  cm->s.req_min_rate = 64;
  cm->s.silent_timeout_sec = 30;
  cm->s.read_timeout_sec = 30;
  cm->s.max_conn = 256;
  cm->s.max_rate = 100;

  cm->n_threads = vlib_get_n_threads ();
  cm->health = clib_mem_alloc_aligned (
    (uword) cm->n_threads * CONNGUARD_MAX_SERVERS * sizeof (connguard_health_t),
    CLIB_CACHE_LINE_BYTES);
  clib_memset (cm->health, 0,
	       (uword) cm->n_threads * CONNGUARD_MAX_SERVERS *
		 sizeof (connguard_health_t));

  cm->dropped_counters.name = "dropped";
  cm->dropped_counters.stat_segment_name = "/connguard/dropped";
  vlib_validate_simple_counter (&cm->dropped_counters, 0);
  vlib_zero_simple_counter (&cm->dropped_counters, 0);

  cm->rand_seed = (u32) clib_cpu_time_now ();
  cm->initialized = 1;
}

/* connguard_alloc_tables: the connection and half-open slots and the scan
 * tables, only once the feature is first enabled (~19MB + ~6MB + ~25MB of
 * main heap). */
static int
connguard_alloc_tables (connguard_main_t *cm)
{
  if (cm->conns)
    return 0;
  cm->conns = clib_mem_alloc_aligned_or_null (
    (uword) CONNGUARD_CONN_SLOTS * sizeof (connguard_conn_t),
    CLIB_CACHE_LINE_BYTES);
  cm->agg = clib_mem_alloc_aligned_or_null (
    (uword) CONNGUARD_AGG_SLOTS * sizeof (connguard_agg_t),
    CLIB_CACHE_LINE_BYTES);
  cm->dedup = clib_mem_alloc_aligned_or_null (
    (uword) CONNGUARD_DEDUP_SLOTS * sizeof (connguard_dedup_t),
    CLIB_CACHE_LINE_BYTES);
  cm->halfopen = clib_mem_alloc_aligned_or_null (
    (uword) CONNGUARD_HALFOPEN_SLOTS * sizeof (connguard_halfopen_t),
    CLIB_CACHE_LINE_BYTES);
  if (!cm->conns || !cm->agg || !cm->dedup || !cm->halfopen)
    {
      if (cm->halfopen)
	clib_mem_free (cm->halfopen);
      cm->halfopen = 0;
      if (cm->conns)
	clib_mem_free (cm->conns);
      if (cm->agg)
	clib_mem_free (cm->agg);
      if (cm->dedup)
	clib_mem_free (cm->dedup);
      cm->conns = 0;
      cm->agg = 0;
      cm->dedup = 0;
      return -1;
    }
  clib_memset (cm->conns, 0,
	       (uword) CONNGUARD_CONN_SLOTS * sizeof (connguard_conn_t));
  clib_memset (cm->agg, 0,
	       (uword) CONNGUARD_AGG_SLOTS * sizeof (connguard_agg_t));
  clib_memset (cm->dedup, 0,
	       (uword) CONNGUARD_DEDUP_SLOTS * sizeof (connguard_dedup_t));
  clib_memset (cm->halfopen, 0,
	       (uword) CONNGUARD_HALFOPEN_SLOTS * sizeof (connguard_halfopen_t));
  cm->agg_gen = 0;
  cm->prev_scan_ns = 0;
  return 0;
}

/* connguard_apply_features: attach both nodes to every LAN-role interface
 * while enabled, detach them everywhere otherwise. */
static void
connguard_apply_features (connguard_main_t *cm)
{
  u32 sw_if_index;

  vec_validate_init_empty (cm->feature_on_by_sw_if_index,
			   vec_len (cm->role_by_sw_if_index), 0);
  for (sw_if_index = 0; sw_if_index < vec_len (cm->feature_on_by_sw_if_index);
       sw_if_index++)
    {
      int want = cm->enabled && sw_if_index < vec_len (cm->role_by_sw_if_index) &&
		 cm->role_by_sw_if_index[sw_if_index] == CONNGUARD_ROLE_LAN;
      if (want == cm->feature_on_by_sw_if_index[sw_if_index])
	continue;
      vnet_feature_enable_disable ("device-input", "connguard-in",
				   sw_if_index, want, 0, 0);
      vnet_feature_enable_disable ("interface-output", "connguard-out",
				   sw_if_index, want, 0, 0);
      cm->feature_on_by_sw_if_index[sw_if_index] = want;
    }
}

static void
connguard_event_push (connguard_main_t *cm, u32 client, u32 server, u16 port,
		      int reason, int action, u32 value)
{
  connguard_event_t *e = &cm->events[cm->event_seq % CONNGUARD_EVENT_RING];
  e->seq = ++cm->event_seq;
  e->ts = (i64) unix_time_now ();
  e->client = client;
  e->server = server;
  e->port = port;
  e->reason = (u8) reason;
  e->action = (u8) action;
  e->value = value;
  cm->detected[reason]++;
}

static u16
connguard_csum (const u8 *p, uword len, u32 sum)
{
  uword i;
  for (i = 0; i + 1 < len; i += 2)
    sum += (u32) ((p[i] << 8) | p[i + 1]);
  if (len & 1)
    sum += (u32) (p[len - 1] << 8);
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return (u16) ~sum;
}

/* connguard_send_rst: a bare RST from the client to the server carrying
 * the server's rcv_nxt (RFC 5961 exact match), transmitted on the LAN
 * interface the server is behind — see xdp_bridge_daemon.c's af_send_rst
 * for the reasoning. Its RX interface is set to that same LAN interface,
 * so connguard-out (which only records packets received on a WAN
 * interface) lets it straight through. */
static int
connguard_send_rst (vlib_main_t *vm, connguard_main_t *cm,
		    const connguard_conn_t *c)
{
  vnet_main_t *vnm = cm->vnet_main;
  u32 sw_if_index = c->server_sw_if_index;
  u32 bi;

  if (sw_if_index == 0 || sw_if_index == ~0 ||
      pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return -1;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return -1;

  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  u8 *f = vlib_buffer_get_current (b);
  clib_memset (f, 0, 60);

  clib_memcpy_fast (f, c->dst_mac, 6);
  clib_memcpy_fast (f + 6, c->src_mac, 6);
  f[12] = 0x08;
  f[13] = 0x00;

  u8 *ip = f + 14;
  u16 id = (u16) random_u32 (&cm->rand_seed);
  ip[0] = 0x45;
  ip[3] = 40; /* total length */
  ip[4] = id >> 8;
  ip[5] = id & 0xff;
  ip[6] = 0x40; /* DF */
  ip[8] = 64;   /* TTL */
  ip[9] = IP_PROTOCOL_TCP;
  clib_memcpy_fast (ip + 12, &c->client_ip, 4);
  clib_memcpy_fast (ip + 16, &c->server_ip, 4);
  u16 ipc = connguard_csum (ip, 20, 0);
  ip[10] = ipc >> 8;
  ip[11] = ipc & 0xff;

  u8 *tcp = ip + 20;
  u32 seq = clib_host_to_net_u32 (c->rcv_nxt);
  tcp[0] = c->client_port >> 8;
  tcp[1] = c->client_port & 0xff;
  tcp[2] = c->server_port >> 8;
  tcp[3] = c->server_port & 0xff;
  clib_memcpy_fast (tcp + 4, &seq, 4);
  tcp[12] = 5 << 4;	  /* data offset: 20 bytes */
  tcp[13] = TCP_FLAG_RST;

  u8 pseudo[12];
  clib_memcpy_fast (pseudo, &c->client_ip, 4);
  clib_memcpy_fast (pseudo + 4, &c->server_ip, 4);
  pseudo[8] = 0;
  pseudo[9] = IP_PROTOCOL_TCP;
  pseudo[10] = 0;
  pseudo[11] = 20;
  u32 psum = 0;
  int i;
  for (i = 0; i < 12; i += 2)
    psum += (u32) ((pseudo[i] << 8) | pseudo[i + 1]);
  u16 tc = connguard_csum (tcp, 20, psum);
  tcp[16] = tc >> 8;
  tcp[17] = tc & 0xff;

  b->current_length = 60;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  vlib_frame_t *fr = vnet_get_frame_to_sw_interface (vnm, sw_if_index);
  u32 *to = vlib_frame_vector_args (fr);
  to[0] = bi;
  fr->n_vectors = 1;
  vnet_put_frame_to_sw_interface (vnm, sw_if_index, fr);
  return 0;
}

static connguard_agg_t *
connguard_agg_get (connguard_agg_t *tbl, u32 gen, u32 client, u32 server,
		   u16 port)
{
  u32 i = connguard_hash3 (client, server, port) & (CONNGUARD_AGG_SLOTS - 1);
  u32 n;
  for (n = 0; n < CONNGUARD_AGG_SLOTS;
       n++, i = (i + 1) & (CONNGUARD_AGG_SLOTS - 1))
    {
      connguard_agg_t *a = &tbl[i];
      if (a->gen != gen)
	{
	  a->gen = gen;
	  a->client = client;
	  a->server = server;
	  a->port = port;
	  a->conns = 0;
	  a->news = 0;
	  return a;
	}
      if (a->client == client && a->server == server && a->port == port)
	return a;
    }
  return 0;
}

/* connguard_dedup_hit: see xdp_bridge_daemon.c's af_dedup_hit. */
static int
connguard_dedup_hit (connguard_dedup_t *tbl, u64 now, u32 client, u32 server,
		     u16 port, u8 reason)
{
  u32 i = connguard_hash3 (client, server, ((u32) port << 8) | reason) &
	  (CONNGUARD_DEDUP_SLOTS - 1);
  connguard_dedup_t *d = &tbl[i];
  if (d->used && d->client == client && d->server == server &&
      d->port == port && d->reason == reason &&
      now - d->ts < CONNGUARD_DEDUP_NS)
    return 1;
  d->used = 1;
  d->ts = now;
  d->client = client;
  d->server = server;
  d->port = port;
  d->reason = reason;
  return 0;
}

/* connguard_judge: see xdp_bridge_daemon.c's af_judge — same rules. */
static int
connguard_judge (const connguard_settings_t *s, const connguard_conn_t *c,
		 u64 now, u32 *value)
{
  const u64 ns = 1000000000ULL;
  if (c->wait_start_ns && now > c->wait_start_ns)
    {
      u64 el = now - c->wait_start_ns;
      if (el >= (u64) s->req_timeout_sec * ns && c->wait_segs >= 2 &&
	  (u64) c->wait_bytes * ns < (u64) s->req_min_rate * el)
	{
	  *value = (u32) (el / ns);
	  return CONNGUARD_R_SLOW_REQUEST;
	}
    }
  if (!(c->flags & CONNGUARD_F_CLIENT_DATA) && now > c->start_ns &&
      now - c->start_ns >= (u64) s->silent_timeout_sec * ns)
    {
      *value = (u32) ((now - c->start_ns) / ns);
      return CONNGUARD_R_SILENT_HOLD;
    }
  if (c->zero_win_ns && now > c->zero_win_ns &&
      now - c->zero_win_ns >= (u64) s->read_timeout_sec * ns)
    {
      *value = (u32) ((now - c->zero_win_ns) / ns);
      return CONNGUARD_R_SLOW_READ;
    }
  return -1;
}

static void
connguard_scan (vlib_main_t *vm, connguard_main_t *cm)
{
  connguard_agg_t *agg = cm->agg;
  connguard_dedup_t *dedup = cm->dedup;
  connguard_settings_t s = cm->s;
  u32 servers[CONNGUARD_MAX_SERVERS];
  u32 nservers = cm->n_servers;
  u64 now = connguard_now_ns (vm);
  u64 prev = cm->prev_scan_ns;
  u64 dt = prev ? now - prev : 0;
  f64 last_start = vlib_time_now (vm);
  u32 tracked = 0, i;

  clib_memcpy_fast (servers, cm->servers, sizeof (servers));
  if (++cm->agg_gen == 0)
    {
      clib_memset (agg, 0,
		   (uword) CONNGUARD_AGG_SLOTS * sizeof (connguard_agg_t));
      cm->agg_gen = 1;
    }
  u32 gen = cm->agg_gen;

  for (i = 0; i < CONNGUARD_CONN_SLOTS; i++)
    {
      /* Time-budgeted: never hold the main thread for more than ~20us
       * at a time. */
      if ((i & 1023) == 0)
	{
	  f64 t = vlib_time_now (vm);
	  if (t - last_start > 20e-6)
	    {
	      vlib_process_suspend (vm, 100e-6);
	      last_start = vlib_time_now (vm);
	      if (!cm->enabled || !cm->conns)
		return;
	    }
	}

      connguard_conn_t *c = &cm->conns[i];
      u8 state = c->state;
      if (state == CONNGUARD_FREE)
	continue;
      int is_new = prev && c->start_ns > prev;

      if (state == CONNGUARD_CLOSED ||
	  (state == CONNGUARD_KILLED &&
	   now - c->wait_start_ns >= CONNGUARD_KILLED_KEEP_NS))
	c->state = CONNGUARD_FREE;
      else
	tracked++;

      int active = state == CONNGUARD_EST ||
		   (state == CONNGUARD_SYN &&
		    now - c->start_ns < CONNGUARD_SYN_STALE_NS);
      if (active || is_new)
	{
	  connguard_agg_t *a = connguard_agg_get (agg, gen, c->client_ip,
						  c->server_ip, c->server_port);
	  connguard_agg_t *as =
	    connguard_agg_get (agg, gen, c->client_ip, c->server_ip, 0);
	  if (a)
	    {
	      a->conns += active;
	      a->news += is_new;
	    }
	  if (as)
	    {
	      as->conns += active;
	      as->news += is_new;
	    }
	}

      if (!s.guard_enabled || state != CONNGUARD_EST ||
	  (c->flags & CONNGUARD_F_REPORTED))
	continue;
      u32 value = 0;
      int reason = connguard_judge (&s, c, now, &value);
      if (reason < 0)
	continue;

      int action = CONNGUARD_A_MONITOR;
      if (s.mode == CONNGUARD_MODE_RESET)
	{
	  if (connguard_send_rst (vm, cm, c) == 0)
	    {
	      c->wait_start_ns = now;
	      c->state = CONNGUARD_KILLED;
	      action = CONNGUARD_A_RESET;
	      cm->reset_total++;
	    }
	  else
	    {
	      c->flags |= CONNGUARD_F_REPORTED;
	      action = CONNGUARD_A_RESET_FAILED;
	      cm->reset_failed++;
	    }
	}
      else
	c->flags |= CONNGUARD_F_REPORTED;
      connguard_event_push (cm, c->client_ip, c->server_ip, c->server_port,
			    reason, action, value);
    }

  /* Per-source limits and each server's snapshot. */
  connguard_server_snap_t snap[CONNGUARD_MAX_SERVERS];
  clib_memset (snap, 0, sizeof (snap));
  for (i = 0; i < nservers; i++)
    snap[i].ip = servers[i];

  for (i = 0; i < CONNGUARD_AGG_SLOTS; i++)
    {
      connguard_agg_t *a = &agg[i];
      u32 j;
      if (a->gen != gen)
	continue;
      if (a->port != 0)
	{
	  if (!s.guard_enabled)
	    continue;
	  int reason = -1;
	  u32 value = 0;
	  if (s.max_conn > 0 && a->conns > (u32) s.max_conn)
	    {
	      reason = CONNGUARD_R_CONN_LIMIT;
	      value = a->conns;
	    }
	  else if (s.max_rate > 0 && dt > 0 &&
		   (u64) a->news * 1000000000ULL > (u64) s.max_rate * dt)
	    {
	      reason = CONNGUARD_R_CONN_RATE;
	      value = (u32) ((u64) a->news * 1000000000ULL / dt);
	    }
	  if (reason >= 0 && !connguard_dedup_hit (dedup, now, a->client,
						   a->server, a->port,
						   (u8) reason))
	    connguard_event_push (cm, a->client, a->server, a->port, reason,
				  CONNGUARD_A_REPORT, value);
	  continue;
	}
      for (j = 0; j < nservers; j++)
	{
	  connguard_server_snap_t *sv = &snap[j];
	  if (sv->ip != a->server)
	    continue;
	  sv->active += a->conns;
	  sv->news += a->news;
	  if (a->news == 0)
	    break;
	  int pos = sv->ntop;
	  while (pos > 0 && sv->top[pos - 1].news < a->news)
	    pos--;
	  if (pos < CONNGUARD_TOP_N)
	    {
	      int last =
		sv->ntop < CONNGUARD_TOP_N ? sv->ntop : CONNGUARD_TOP_N - 1;
	      int m;
	      for (m = last; m > pos; m--)
		sv->top[m] = sv->top[m - 1];
	      sv->top[pos].ip = a->client;
	      sv->top[pos].news = a->news;
	      if (sv->ntop < CONNGUARD_TOP_N)
		sv->ntop++;
	    }
	  break;
	}
    }

  clib_memcpy_fast (cm->snap, snap, sizeof (snap));
  cm->n_snap = nservers;
  cm->tracked = tracked;
  cm->interval_ms = dt / 1000000ULL;
  cm->prev_scan_ns = now;
}

static uword
connguard_scan_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
			vlib_frame_t *f)
{
  connguard_main_t *cm = &connguard_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      vlib_process_get_events (vm, 0);
      if (cm->enabled && cm->conns)
	connguard_scan (vm, cm);
    }
  return 0;
}

VLIB_REGISTER_NODE (connguard_scan_process_node, static) = {
  .function = connguard_scan_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "connguard-scan-process",
};

/* ── CLI ──────────────────────────────────────────────────────────────── */

/* connguard config enable <0|1> guard <0|1> mode <monitor|reset>
 *   req-timeout <s> req-min-rate <Bps> silent-timeout <s> read-timeout <s>
 *   max-conn <n> max-rate <n> — every keyword optional, unset ones keep
 *   their current value. */
static clib_error_t *
connguard_config_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  connguard_main_t *cm = &connguard_main;
  connguard_settings_t s;
  u32 enabled, v;

  connguard_ensure_init ();
  s = cm->s;
  enabled = cm->enabled;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable %u", &v))
	enabled = v != 0;
      else if (unformat (input, "guard %u", &v))
	s.guard_enabled = v != 0;
      else if (unformat (input, "mode monitor"))
	s.mode = CONNGUARD_MODE_MONITOR;
      else if (unformat (input, "mode reset"))
	s.mode = CONNGUARD_MODE_RESET;
      else if (unformat (input, "req-timeout %u", &v))
	s.req_timeout_sec = v;
      else if (unformat (input, "req-min-rate %u", &v))
	s.req_min_rate = v;
      else if (unformat (input, "silent-timeout %u", &v))
	s.silent_timeout_sec = v;
      else if (unformat (input, "read-timeout %u", &v))
	s.read_timeout_sec = v;
      else if (unformat (input, "max-conn %u", &v))
	s.max_conn = v;
      else if (unformat (input, "max-rate %u", &v))
	s.max_rate = v;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (s.req_timeout_sec <= 0 || s.silent_timeout_sec <= 0 ||
      s.read_timeout_sec <= 0)
    return clib_error_return (0, "timeouts must be greater than 0");
  if (enabled && connguard_alloc_tables (cm) != 0)
    return clib_error_return (0, "connguard: out of memory for the tables");

  cm->s = s;
  if (!enabled && cm->enabled)
    {
      cm->enabled = 0;
      connguard_apply_features (cm);
      /* Features detached: no worker touches the slots any more. */
      clib_memset (cm->conns, 0,
		   (uword) CONNGUARD_CONN_SLOTS * sizeof (connguard_conn_t));
      clib_memset (cm->halfopen, 0,
		   (uword) CONNGUARD_HALFOPEN_SLOTS *
		     sizeof (connguard_halfopen_t));
      cm->prev_scan_ns = 0;
      cm->n_snap = 0;
    }
  else if (enabled && !cm->enabled)
    {
      cm->prev_scan_ns = 0;
      cm->enabled = 1;
      connguard_apply_features (cm);
    }
  return 0;
}

/* connguard interface <interface> <wan|lan|none> */
static clib_error_t *
connguard_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  connguard_main_t *cm = &connguard_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int role = -1;

  connguard_ensure_init ();
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "wan"))
	role = CONNGUARD_ROLE_WAN;
      else if (unformat (input, "lan"))
	role = CONNGUARD_ROLE_LAN;
      else if (unformat (input, "none"))
	role = CONNGUARD_ROLE_NONE;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (sw_if_index == ~0 || role < 0)
    return clib_error_return (0, "specify an interface and wan|lan|none");

  vec_validate_init_empty (cm->role_by_sw_if_index, sw_if_index,
			   CONNGUARD_ROLE_NONE);
  cm->role_by_sw_if_index[sw_if_index] = (u8) role;
  connguard_apply_features (cm);
  return 0;
}

static int
connguard_collect_key (clib_bihash_kv_8_8_t *kv, void *arg)
{
  u64 **keys = arg;
  vec_add1 (*keys, kv->key);
  return BIHASH_WALK_CONTINUE;
}

/* connguard service clear
 * connguard service add <server-ip> port <n> [port <n> ...] */
static clib_error_t *
connguard_service_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  connguard_main_t *cm = &connguard_main;
  ip4_address_t server;
  u32 ports[CONNGUARD_MAX_PORTS], n_ports = 0, port, i;
  int is_clear = 0, is_add = 0, have_ip = 0;

  connguard_ensure_init ();
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "clear"))
	is_clear = 1;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "port %u", &port))
	{
	  if (port == 0 || port > 65535)
	    return clib_error_return (0, "invalid port %u", port);
	  if (n_ports >= CONNGUARD_MAX_PORTS)
	    return clib_error_return (0, "at most %d ports per server",
				      CONNGUARD_MAX_PORTS);
	  ports[n_ports++] = port;
	}
      else if (unformat (input, "%U", unformat_ip4_address, &server))
	have_ip = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (is_clear)
    {
      /* Delete entry by entry — never free the table: worker threads may
       * be searching it right now, and a bihash delete is safe against
       * concurrent searches. */
      u64 *keys = 0, *k;
      clib_bihash_foreach_key_value_pair_8_8 (&cm->svc_table,
					      connguard_collect_key, &keys);
      vec_foreach (k, keys)
	{
	  clib_bihash_kv_8_8_t kv = { .key = *k };
	  clib_bihash_add_del_8_8 (&cm->svc_table, &kv, 0);
	}
      vec_free (keys);
      cm->n_servers = 0;
      cm->n_snap = 0;
      clib_memset (cm->health, 0,
		   (uword) cm->n_threads * CONNGUARD_MAX_SERVERS *
		     sizeof (connguard_health_t));
      return 0;
    }
  if (!is_add || !have_ip || n_ports == 0)
    return clib_error_return (
      0, "usage: connguard service add <server-ip> port <n> [port <n> ...]");

  u32 idx = ~0;
  for (i = 0; i < cm->n_servers; i++)
    if (cm->servers[i] == server.as_u32)
      idx = i;
  if (idx == ~0)
    {
      if (cm->n_servers >= CONNGUARD_MAX_SERVERS)
	return clib_error_return (0, "too many protected servers (max %d)",
				  CONNGUARD_MAX_SERVERS);
      idx = cm->n_servers;
      cm->servers[idx] = server.as_u32;
      for (i = 0; i < cm->n_threads; i++)
	clib_memset (&cm->health[i * CONNGUARD_MAX_SERVERS + idx], 0,
		     sizeof (connguard_health_t));
      CLIB_MEMORY_STORE_BARRIER ();
      cm->n_servers++;
    }
  for (i = 0; i < n_ports; i++)
    {
      clib_bihash_kv_8_8_t kv;
      kv.key = ((u64) server.as_u32 << 32) | ports[i];
      kv.value = idx;
      clib_bihash_add_del_8_8 (&cm->svc_table, &kv, 1);
    }
  return 0;
}

static void
connguard_health_sum (connguard_main_t *cm, u32 idx, u64 *syn, u64 *synack,
		      u64 *rst)
{
  u32 t;
  *syn = *synack = *rst = 0;
  for (t = 0; t < cm->n_threads; t++)
    {
      connguard_health_t *h = &cm->health[t * CONNGUARD_MAX_SERVERS + idx];
      *syn += h->syn;
      *synack += h->synack;
      *rst += h->rst;
    }
}

/* show connguard [stats|events [since <n>]] — plain "show connguard" is
 * the human-readable summary; "stats"/"events" print one JSON line each
 * (see this file's package doc comment). */
static clib_error_t *
show_connguard_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  connguard_main_t *cm = &connguard_main;
  int want_stats = 0, want_events = 0;
  u64 since = 0;
  u32 i;
  int t;
  u8 *s = 0;

  connguard_ensure_init ();
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "stats"))
	want_stats = 1;
      else if (unformat (input, "events"))
	want_events = 1;
      else if (unformat (input, "since %llu", &since))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  u64 dropped = vlib_get_simple_counter (&cm->dropped_counters, 0);

  if (want_events)
    {
      u64 last = cm->event_seq;
      u64 first = last > CONNGUARD_EVENT_RING ?
		    last - CONNGUARD_EVENT_RING + 1 :
		    1;
      u64 q, out_seq = last;
      int n = 0;
      if (since + 1 > first)
	first = since + 1;
      s = format (s, "{\"events\":[");
      for (q = first; q <= last; q++)
	{
	  connguard_event_t *e = &cm->events[(q - 1) % CONNGUARD_EVENT_RING];
	  if (e->seq != q)
	    continue;
	  if (n == CONNGUARD_EVENTS_PER_READ)
	    {
	      out_seq = q - 1;
	      break;
	    }
	  s = format (s,
		      "%s{\"seq\":%llu,\"ts\":%lld,\"client\":\"%U\","
		      "\"server\":\"%U\",\"port\":%u,\"reason\":\"%s\","
		      "\"action\":\"%s\",\"value\":%u}",
		      n ? "," : "", e->seq, e->ts, format_ip4_address,
		      &e->client, format_ip4_address, &e->server, e->port,
		      connguard_reason_names[e->reason],
		      connguard_action_names[e->action], e->value);
	  n++;
	}
      s = format (s, "],\"seq\":%llu}", out_seq);
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
      return 0;
    }

  if (want_stats)
    {
      s = format (
	s,
	"{\"enabled\":%d,\"guard_enabled\":%d,\"mode\":\"%s\",\"tracked\":%u,"
	"\"dropped\":%llu,\"reset_total\":%llu,\"reset_failed\":%llu,"
	"\"slow_request\":%llu,\"silent_hold\":%llu,\"slow_read\":%llu,"
	"\"conn_limit\":%llu,\"conn_rate\":%llu,\"interval_ms\":%llu,"
	"\"servers\":[",
	cm->enabled ? 1 : 0, cm->s.guard_enabled ? 1 : 0,
	cm->s.mode == CONNGUARD_MODE_RESET ? "reset" : "monitor", cm->tracked,
	dropped, cm->reset_total, cm->reset_failed,
	cm->detected[CONNGUARD_R_SLOW_REQUEST],
	cm->detected[CONNGUARD_R_SILENT_HOLD],
	cm->detected[CONNGUARD_R_SLOW_READ],
	cm->detected[CONNGUARD_R_CONN_LIMIT],
	cm->detected[CONNGUARD_R_CONN_RATE], cm->interval_ms);
      for (i = 0; i < cm->n_servers; i++)
	{
	  u64 syn, synack, rst;
	  connguard_server_snap_t *sv = 0;
	  u32 j;
	  connguard_health_sum (cm, i, &syn, &synack, &rst);
	  for (j = 0; j < cm->n_snap; j++)
	    if (cm->snap[j].ip == cm->servers[i])
	      sv = &cm->snap[j];
	  s = format (s,
		      "%s{\"ip\":\"%U\",\"syn\":%llu,\"synack\":%llu,"
		      "\"rst\":%llu,\"active\":%u,\"new_conns\":%u,\"top\":[",
		      i ? "," : "", format_ip4_address, &cm->servers[i], syn,
		      synack, rst, sv ? sv->active : 0, sv ? sv->news : 0);
	  for (t = 0; sv && t < sv->ntop; t++)
	    s = format (s, "%s{\"ip\":\"%U\",\"new_conns\":%u}", t ? "," : "",
			format_ip4_address, &sv->top[t].ip, sv->top[t].news);
	  s = format (s, "]}");
	}
      s = format (s, "]}");
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
      return 0;
    }

  vlib_cli_output (vm, "Application Filter:");
  vlib_cli_output (vm, "  Recording:         %s",
		   cm->enabled ? "enabled" : "disabled");
  vlib_cli_output (vm, "  Slow Conn Guard:   %s (%s)",
		   cm->s.guard_enabled ? "enabled" : "disabled",
		   cm->s.mode == CONNGUARD_MODE_RESET ? "reset" : "monitor");
  vlib_cli_output (vm, "  Tracked conns:     %u", cm->tracked);
  vlib_cli_output (vm, "  Resets sent:       %llu (failed %llu)",
		   cm->reset_total, cm->reset_failed);
  vlib_cli_output (vm, "  Dropped (reset):   %llu", dropped);
  for (i = 0; i < CONNGUARD_R_COUNT; i++)
    vlib_cli_output (vm, "  %-18s %llu", connguard_reason_names[i],
		     cm->detected[i]);
  vlib_cli_output (vm, "  Interfaces:");
  for (i = 0; i < vec_len (cm->role_by_sw_if_index); i++)
    if (cm->role_by_sw_if_index[i] != CONNGUARD_ROLE_NONE)
      vlib_cli_output (
	vm, "    %U: %s%s", format_vnet_sw_if_index_name, cm->vnet_main, i,
	cm->role_by_sw_if_index[i] == CONNGUARD_ROLE_WAN ? "wan" : "lan",
	i < vec_len (cm->feature_on_by_sw_if_index) &&
	    cm->feature_on_by_sw_if_index[i] ?
	  " (attached)" :
	  "");
  vlib_cli_output (vm, "  Protected servers:");
  for (i = 0; i < cm->n_servers; i++)
    {
      u64 syn, synack, rst;
      connguard_health_sum (cm, i, &syn, &synack, &rst);
      vlib_cli_output (vm, "    %U  syn %llu synack %llu rst %llu",
		       format_ip4_address, &cm->servers[i], syn, synack, rst);
    }
  return 0;
}

VLIB_CLI_COMMAND (connguard_config_command, static) = {
  .path = "connguard config",
  .short_help = "connguard config [enable <0|1>] [guard <0|1>] "
		"[mode <monitor|reset>] [req-timeout <s>] [req-min-rate <Bps>] "
		"[silent-timeout <s>] [read-timeout <s>] [max-conn <n>] "
		"[max-rate <n>]",
  .function = connguard_config_command_fn,
};

VLIB_CLI_COMMAND (connguard_interface_command, static) = {
  .path = "connguard interface",
  .short_help = "connguard interface <interface> <wan|lan|none>",
  .function = connguard_interface_command_fn,
};

VLIB_CLI_COMMAND (connguard_service_command, static) = {
  .path = "connguard service",
  .short_help = "connguard service clear | connguard service add "
		"<server-ip> port <n> [port <n> ...]",
  .function = connguard_service_command_fn,
};

VLIB_CLI_COMMAND (show_connguard_command, static) = {
  .path = "show connguard",
  .short_help = "show connguard [stats | events [since <n>]]",
  .function = show_connguard_command_fn,
};

static clib_error_t *
connguard_init (vlib_main_t *vm)
{
  connguard_main_t *cm = &connguard_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();
  return 0;
}

VLIB_INIT_FUNCTION (connguard_init);

VNET_FEATURE_INIT (connguard_in_feature, static) = {
  .arc_name = "device-input",
  .node_name = "connguard-in",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (connguard_out_feature, static) = {
  .arc_name = "interface-output",
  .node_name = "connguard-out",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "mighty_xddos Application Filter",
};
