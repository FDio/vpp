/* SPDX-License-Identifier: Apache-2.0 */

/*
 * node.c — mighty_xddos Flood Guard (VPP mode) packet path.
 *
 * Replaces the earlier policer classify chain (removed 2026-10-04): every IPv4
 * unicast packet missed all of its tables (4 Broadcast Filter tables + 5
 * SYN/UDP/ICMP flood tables per interface), paying one serial hash lookup
 * per table — measured ~433 clocks/packet, empty tables included. Here the
 * same decisions take a MAC bit test, and a victim lookup only while a
 * victim is armed.
 *
 * Two nodes per interface, placed around the ACL input node so the order
 * follows the kernel mode's xdp_bridge (storm -> blocklist -> WAN Service
 * Port ACL -> flood victim protection):
 *
 *   floodguard-l2-ip4/-ip6/-nonip — L2 input arcs, BEFORE the ACL node:
 *     ARP (any destination)                 -> interface ARP policer
 *     dst ff:ff:ff:ff:ff:ff                 -> interface broadcast policer
 *     dst 01:80:c2:00:00:0x                 -> L2 control policer
 *     dst group bit                         -> interface multicast policer
 *   Storm frames are counted and limited whatever the ACL would decide
 *   about them, as in kernel mode.
 *
 *   floodguard-victim — l2-input-ip4 arc, AFTER the ACL node (attacker
 *   blocklist and WAN Service Port ACL already applied), IPv4 dst = armed
 *   victim:
 *     TCP SYN/RST, SYN Reset Challenge      -> challenge (see below)
 *     TCP with SYN (port-limited or all)    -> SYN policer
 *     UDP (port-limited or all)             -> UDP policer
 *     ICMP                                  -> ICMP policer
 *
 * SYN Reset Challenge (RFC 793 §3.4 case 2, same mechanism as the kernel
 * mode's handle_syn_reset_challenge and the earlier synchallenge plugin it
 * replaced): a bare SYN from an unverified source is answered with
 * a SYN-ACK whose ack is the client's own seq (not seq+1); a real TCP stack
 * answers it with a RST carrying that value, which whitelists the source,
 * and its retried SYN then passes untouched. Being after the ACL, a
 * blocklisted source or a closed port never gets a challenge, and the
 * original SYN has already gone through ethernet-input's rx pcap capture
 * and the device-input sampling. A SYN sent to a group MAC is left alone
 * (the storm node already policed it), and a SYN from a source that can
 * never answer (0/8, 224/4, 240/4) is dropped instead of reflected. The
 * reply is sent straight to interface-output: it is the victim's answer on
 * the ingress port, not bridged traffic, so it must not create an output
 * ACL session per spoofed source.
 *
 * Deliberate differences from the classify masks: the IPv4 header length
 * is honored (the masks assumed a 20-byte header, so IP options shifted
 * the L4 fields), and port/flag checks need the first fragment (the masks
 * read whatever bytes sat at those offsets).
 *
 * Policing reuses the policer plugin's objects by index — the same
 * conform/exceed/violate accounting the classify path produced, so the
 * existing policer statistics keep working. Only transmit/drop actions are
 * used by virtserver; mark actions are not applied here.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/l2/l2_input.h>
#include <vnet/feature/feature.h>

#include <floodguard/floodguard.h>

typedef enum
{
  FLOODGUARD_NEXT_DROP,
  FLOODGUARD_NEXT_REFLECT,
  FLOODGUARD_N_NEXT,
} floodguard_next_t;

#define foreach_floodguard_error _ (DROP, "flood guard drop")

typedef enum
{
#define _(sym, str) FLOODGUARD_ERROR_##sym,
  foreach_floodguard_error
#undef _
    FLOODGUARD_N_ERROR,
} floodguard_error_t;

static char *floodguard_error_strings[] = {
#define _(sym, string) string,
  foreach_floodguard_error
#undef _
};

/* What the node did with a packet (trace only). */
typedef enum
{
  FLOODGUARD_VERDICT_PASS,
  FLOODGUARD_VERDICT_DROP,
  FLOODGUARD_VERDICT_CHALLENGED,
  FLOODGUARD_VERDICT_VERIFIED,
  FLOODGUARD_VERDICT_PERMITTED,
} floodguard_verdict_t;

typedef struct
{
  u32 sw_if_index;
  u32 policer;
  u8 kind;
  u8 verdict;
} floodguard_trace_t;

static const char *const floodguard_kind_names[FLOODGUARD_N_KIND] = {
  [FLOODGUARD_KIND_NONE] = "none",
  [FLOODGUARD_KIND_ARP] = "arp",
  [FLOODGUARD_KIND_BROADCAST] = "broadcast",
  [FLOODGUARD_KIND_CTRL] = "l2-control",
  [FLOODGUARD_KIND_MULTICAST] = "multicast",
  [FLOODGUARD_KIND_SYN] = "syn",
  [FLOODGUARD_KIND_UDP] = "udp",
  [FLOODGUARD_KIND_ICMP] = "icmp",
  [FLOODGUARD_KIND_SYN_CHALLENGE] = "syn-challenge",
};

static const char *const floodguard_verdict_names[] = {
  [FLOODGUARD_VERDICT_PASS] = "pass",
  [FLOODGUARD_VERDICT_DROP] = "drop",
  [FLOODGUARD_VERDICT_CHALLENGED] = "challenged",
  [FLOODGUARD_VERDICT_VERIFIED] = "verified",
  [FLOODGUARD_VERDICT_PERMITTED] = "permitted",
};

static u8 *
format_floodguard_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  floodguard_trace_t *t = va_arg (*args, floodguard_trace_t *);

  s = format (s, "floodguard: sw_if_index %u kind %s %s", t->sw_if_index,
	      floodguard_kind_names[t->kind],
	      floodguard_verdict_names[t->verdict]);
  if (t->policer != ~0)
    s = format (s, " policer %u", t->policer);
  return s;
}

static_always_inline void
floodguard_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		  u32 sw_if_index, u32 pi, floodguard_kind_t kind,
		  floodguard_verdict_t verdict)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		     (b->flags & VLIB_BUFFER_IS_TRACED)))
    {
      floodguard_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->sw_if_index = sw_if_index;
      t->policer = pi;
      t->kind = kind;
      t->verdict = verdict;
    }
}

/* floodguard_police: run b through policer pi; nonzero = drop. */
static_always_inline int
floodguard_police (vlib_main_t *vm, floodguard_main_t *fm, vlib_buffer_t *b,
		   u32 pi, u64 now)
{
  policer_main_t *pm = fm->pm;

  if (PREDICT_FALSE (pool_is_free_index (pm->policers, pi)))
    return 0;
  policer_t *pol = pool_elt_at_index (pm->policers, pi);
  u32 len = vlib_buffer_length_in_chain (vm, b);
  policer_result_e col = vnet_police_packet (pol, len, POLICE_CONFORM, now);
  vlib_increment_combined_counter (&fm->policer_counters[col],
				   vm->thread_index, pi, 1, len);
  return pol->action[col] == QOS_ACTION_DROP;
}

static_always_inline void
floodguard_count_drops (vlib_main_t *vm, floodguard_main_t *fm, u32 *drops)
{
  int k;

  for (k = 0; k < FLOODGUARD_N_KIND; k++)
    if (drops[k])
      vlib_increment_simple_counter (&fm->drop_counters[k], vm->thread_index,
				     0, drops[k]);
}

/* ------------------------------------------------------------------------
 * Storm node
 * ------------------------------------------------------------------------ */

/* floodguard_l2_kind: Broadcast Filter classification by destination MAC
 * (ARP is decided by the caller from the ethertype). */
static_always_inline floodguard_kind_t
floodguard_l2_kind (const u8 *dst)
{
  if (PREDICT_TRUE (!(dst[0] & 1)))
    return FLOODGUARD_KIND_NONE;
  if ((clib_mem_unaligned (dst, u32) & clib_mem_unaligned (dst + 2, u32)) ==
      0xffffffff)
    return FLOODGUARD_KIND_BROADCAST;
  if (dst[0] == 0x01 && dst[1] == 0x80 && dst[2] == 0xc2 && dst[3] == 0 &&
      dst[4] == 0 && (dst[5] & 0xf0) == 0)
    return FLOODGUARD_KIND_CTRL;
  return FLOODGUARD_KIND_MULTICAST;
}

static_always_inline uword
floodguard_l2_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, int is_nonip)
{
  floodguard_main_t *fm = &floodguard_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 drops[FLOODGUARD_N_KIND] = { 0 };
  u32 n_dropped = 0;
  u64 now = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u8 *eth = vlib_buffer_get_current (b[0]);
      u32 sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      floodguard_kind_t kind;
      u32 pi = ~0;
      int drop = 0;

      if (n_left > 2)
	vlib_prefetch_buffer_header (b[2], LOAD);

      vnet_feature_next_u16 (next, b[0]);

      if (is_nonip && clib_mem_unaligned (eth + vnet_buffer (b[0])->l2.l2_len -
					    2, u16) ==
			clib_host_to_net_u16 (ETHERNET_TYPE_ARP))
	kind = FLOODGUARD_KIND_ARP;
      else
	kind = floodguard_l2_kind (eth);

      if (kind != FLOODGUARD_KIND_NONE && sw_if_index < vec_len (fm->ifs))
	pi = fm->ifs[sw_if_index].policer[kind - 1];

      if (pi != ~0)
	{
	  drop = floodguard_police (vm, fm, b[0], pi, now);
	  if (drop)
	    {
	      next[0] = FLOODGUARD_NEXT_DROP;
	      b[0]->error = node->errors[FLOODGUARD_ERROR_DROP];
	      drops[kind]++;
	      n_dropped++;
	    }
	}

      floodguard_trace (vm, node, b[0], sw_if_index, pi, kind,
			drop ? FLOODGUARD_VERDICT_DROP :
			       FLOODGUARD_VERDICT_PASS);

      b++;
      next++;
      n_left--;
    }

  if (n_dropped)
    floodguard_count_drops (vm, fm, drops);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (floodguard_l2_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return floodguard_l2_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (floodguard_l2_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return floodguard_l2_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (floodguard_l2_nonip_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return floodguard_l2_inline (vm, node, frame, 1);
}

/* ------------------------------------------------------------------------
 * Victim node
 * ------------------------------------------------------------------------ */

/* floodguard_challenge_pending_key: the client->victim 4-tuple, every
 * field as on the wire, so the original SYN and the client's RST (same
 * direction) produce the same key. */
static_always_inline void
floodguard_challenge_pending_key (u32 client_ip, u32 victim_ip,
				  u16 client_port, u16 victim_port,
				  clib_bihash_kv_16_8_t *kv)
{
  kv->key[0] = ((u64) victim_ip << 32) | (u64) client_ip;
  kv->key[1] = ((u64) victim_port << 16) | (u64) client_port;
}

/* floodguard_unanswerable_src: a source no TCP stack can answer from —
 * 0.0.0.0/8, multicast 224/4, reserved 240/4 and the limited broadcast. */
static_always_inline int
floodguard_unanswerable_src (u32 src_net)
{
  u8 first = ((u8 *) &src_net)[0];
  return first == 0 || first >= 224;
}

/* floodguard_challenge_reflect: rewrite the SYN in place into the
 * challenge SYN-ACK (ack = the client's own seq, deliberately not seq+1)
 * and send it back out the ingress port. */
static_always_inline void
floodguard_challenge_reflect (vlib_main_t *vm, vlib_buffer_t *b, u8 *eth,
			      ip4_header_t *ip, tcp_header_t *tcp)
{
  u32 client_ip = ip->src_address.as_u32;
  u32 victim_ip = ip->dst_address.as_u32;
  u16 client_port = tcp->src_port;
  u16 victim_port = tcp->dst_port;
  u32 client_seq = tcp->seq_number;
  u8 mac[6];

  clib_memcpy_fast (mac, eth, 6);
  clib_memcpy_fast (eth, eth + 6, 6);
  clib_memcpy_fast (eth + 6, mac, 6);

  clib_memset (ip, 0, sizeof (*ip) + sizeof (*tcp));
  tcp = (tcp_header_t *) (ip + 1);
  ip->ip_version_and_header_length = 0x45;
  ip->length = clib_host_to_net_u16 (sizeof (*ip) + sizeof (*tcp));
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_TCP;
  ip->src_address.as_u32 = victim_ip;
  ip->dst_address.as_u32 = client_ip;
  ip->checksum = ip4_header_checksum (ip);

  tcp->src_port = victim_port;
  tcp->dst_port = client_port;
  tcp->ack_number = client_seq;
  tcp->data_offset_and_reserved = 5 << 4;
  tcp->flags = TCP_FLAG_SYN | TCP_FLAG_ACK;

  b->current_length = ((u8 *) (tcp + 1)) - eth;
  b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  b->total_length_not_including_first_buffer = 0;
  tcp->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip);

  vnet_buffer (b)->sw_if_index[VLIB_TX] =
    vnet_buffer (b)->sw_if_index[VLIB_RX];
}

/* floodguard_challenge: SYN Reset Challenge for a bare SYN or a RST toward
 * a challenge victim (see the package doc comment). */
static_always_inline floodguard_verdict_t
floodguard_challenge (vlib_main_t *vm, floodguard_main_t *fm, vlib_buffer_t *b,
		      u8 *eth, ip4_header_t *ip, tcp_header_t *tcp, int is_syn)
{
  u32 thread = vm->thread_index;
  u32 client_ip = ip->src_address.as_u32;
  u64 now = (u64) vlib_time_now (vm);
  clib_bihash_kv_8_8_t wkv, wval;
  clib_bihash_kv_16_8_t pkv, pval;

  wkv.key = client_ip;
  if (!clib_bihash_search_8_8 (&fm->challenge_whitelist, &wkv, &wval) &&
      now < wval.value)
    {
      /* Verified: SYNs pass, and its RSTs are ordinary connection
       * teardown. An expired entry is left for the sweep process. */
      if (!is_syn)
	return FLOODGUARD_VERDICT_PASS;
      vlib_increment_simple_counter (
	&fm->challenge_counters[FLOODGUARD_CHALLENGE_PERMITTED], thread, 0, 1);
      return FLOODGUARD_VERDICT_PERMITTED;
    }

  floodguard_challenge_pending_key (client_ip, ip->dst_address.as_u32,
				    tcp->src_port, tcp->dst_port, &pkv);
  if (!is_syn)
    {
      /* Only the RST answering an outstanding challenge means anything;
       * every other unverified RST toward the victim is dropped. */
      if (!clib_bihash_search_16_8 (&fm->challenge_pending, &pkv, &pval) &&
	  now < (pval.value & 0xffffffff) &&
	  tcp->seq_number == (u32) (pval.value >> 32))
	{
	  wkv.value = now + fm->challenge_whitelist_ttl_sec;
	  clib_bihash_add_del_8_8 (&fm->challenge_whitelist, &wkv, 1);
	  clib_bihash_add_del_16_8 (&fm->challenge_pending, &pkv, 0);
	  vlib_increment_simple_counter (
	    &fm->challenge_counters[FLOODGUARD_CHALLENGE_VERIFIED], thread, 0,
	    1);
	  return FLOODGUARD_VERDICT_VERIFIED;
	}
      return FLOODGUARD_VERDICT_DROP;
    }

  /* A real client's SYN never goes to a group MAC; the storm node has
   * already policed it, and reflecting it would send a group source MAC. */
  if (eth[0] & 1)
    return FLOODGUARD_VERDICT_PASS;
  if (floodguard_unanswerable_src (client_ip))
    return FLOODGUARD_VERDICT_DROP;

  pkv.value = ((u64) tcp->seq_number << 32) |
	      (now + FLOODGUARD_CHALLENGE_PENDING_TTL_SEC);
  clib_bihash_add_del_16_8 (&fm->challenge_pending, &pkv, 1);
  floodguard_challenge_reflect (vm, b, eth, ip, tcp);
  vlib_increment_simple_counter (
    &fm->challenge_counters[FLOODGUARD_CHALLENGE_CHALLENGED], thread, 0, 1);
  return FLOODGUARD_VERDICT_CHALLENGED;
}

VLIB_NODE_FN (floodguard_victim_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  floodguard_main_t *fm = &floodguard_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 drops[FLOODGUARD_N_KIND] = { 0 };
  u32 n_dropped = 0;
  int check_victims = fm->n_victims != 0;
  u64 now = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u8 *eth = vlib_buffer_get_current (b[0]);
      u8 *end = eth + b[0]->current_length;
      ip4_header_t *ip =
	(ip4_header_t *) (eth + vnet_buffer (b[0])->l2.l2_len);
      floodguard_kind_t kind = FLOODGUARD_KIND_NONE;
      floodguard_verdict_t verdict = FLOODGUARD_VERDICT_PASS;
      clib_bihash_kv_8_8_t kv, val;
      u32 pi = ~0;

      if (n_left > 2)
	vlib_prefetch_buffer_header (b[2], LOAD);

      vnet_feature_next_u16 (next, b[0]);

      if (!check_victims || (u8 *) (ip + 1) > end)
	goto done;
      kv.key = ip->dst_address.as_u32;
      if (clib_bihash_search_8_8 (&fm->victims, &kv, &val))
	goto done;

      u64 v = val.value;
      int first = ip4_get_fragment_offset (ip) == 0;
      u8 *l4 = (u8 *) ip + ip4_header_bytes (ip);

      switch (ip->protocol)
	{
	case IP_PROTOCOL_TCP:
	  {
	    tcp_header_t *tcp = (tcp_header_t *) l4;
	    if (!first || (u8 *) (tcp + 1) > end)
	      break;
	    u8 flags = tcp->flags;
	    int is_syn = (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN;
	    if ((v & FLOODGUARD_V_SYN_CHALLENGE) &&
		(is_syn || (flags & TCP_FLAG_RST)))
	      {
		kind = FLOODGUARD_KIND_SYN_CHALLENGE;
		verdict = floodguard_challenge (vm, fm, b[0], eth, ip, tcp,
						is_syn);
		break;
	      }
	    if (!(v & FLOODGUARD_V_SYN) || !(flags & TCP_FLAG_SYN))
	      break;
	    u16 port = FLOODGUARD_V_SYN_PORT (v);
	    if (port && clib_net_to_host_u16 (tcp->dst_port) != port)
	      break;
	    kind = FLOODGUARD_KIND_SYN;
	    break;
	  }
	case IP_PROTOCOL_UDP:
	  {
	    if (!(v & FLOODGUARD_V_UDP))
	      break;
	    u16 port = FLOODGUARD_V_UDP_PORT (v);
	    if (port)
	      {
		udp_header_t *udp = (udp_header_t *) l4;
		if (!first || (u8 *) (udp + 1) > end ||
		    clib_net_to_host_u16 (udp->dst_port) != port)
		  break;
	      }
	    kind = FLOODGUARD_KIND_UDP;
	    break;
	  }
	case IP_PROTOCOL_ICMP:
	  if (v & FLOODGUARD_V_ICMP)
	    kind = FLOODGUARD_KIND_ICMP;
	  break;
	default:
	  break;
	}

      if (kind >= FLOODGUARD_KIND_SYN && kind <= FLOODGUARD_KIND_ICMP)
	{
	  pi = fm->flood_policer[kind - FLOODGUARD_KIND_SYN];
	  if (pi != ~0 && floodguard_police (vm, fm, b[0], pi, now))
	    verdict = FLOODGUARD_VERDICT_DROP;
	}

      if (verdict == FLOODGUARD_VERDICT_DROP)
	{
	  next[0] = FLOODGUARD_NEXT_DROP;
	  b[0]->error = node->errors[FLOODGUARD_ERROR_DROP];
	  drops[kind]++;
	  n_dropped++;
	}
      else if (verdict == FLOODGUARD_VERDICT_VERIFIED)
	{
	  /* The matched RST was only the challenge's answer (counted as
	   * verified, not as a drop); the client now retries its SYN. */
	  next[0] = FLOODGUARD_NEXT_DROP;
	  b[0]->error = node->errors[FLOODGUARD_ERROR_DROP];
	}
      else if (verdict == FLOODGUARD_VERDICT_CHALLENGED)
	next[0] = FLOODGUARD_NEXT_REFLECT;

    done:
      floodguard_trace (vm, node, b[0], vnet_buffer (b[0])->sw_if_index[VLIB_RX],
			pi, kind, verdict);
      b++;
      next++;
      n_left--;
    }

  if (n_dropped)
    floodguard_count_drops (vm, fm, drops);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

#define FLOODGUARD_NODE(sym, nm)                                              \
  VLIB_REGISTER_NODE (sym) = {                                                \
    .name = nm,                                                               \
    .vector_size = sizeof (u32),                                              \
    .format_trace = format_floodguard_trace,                                  \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .n_errors = ARRAY_LEN (floodguard_error_strings),                         \
    .error_strings = floodguard_error_strings,                                \
    .n_next_nodes = FLOODGUARD_N_NEXT,                                        \
    .next_nodes = { [FLOODGUARD_NEXT_DROP] = "error-drop",                    \
		    [FLOODGUARD_NEXT_REFLECT] = "interface-output" },         \
  }

FLOODGUARD_NODE (floodguard_l2_ip4_node, "floodguard-l2-ip4");
FLOODGUARD_NODE (floodguard_l2_ip6_node, "floodguard-l2-ip6");
FLOODGUARD_NODE (floodguard_l2_nonip_node, "floodguard-l2-nonip");
FLOODGUARD_NODE (floodguard_victim_node, "floodguard-victim");

VNET_FEATURE_INIT (floodguard_l2_ip4_feature, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "floodguard-l2-ip4",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip4-l2"),
};

VNET_FEATURE_INIT (floodguard_l2_ip6_feature, static) = {
  .arc_name = "l2-input-ip6",
  .node_name = "floodguard-l2-ip6",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip6-l2"),
};

VNET_FEATURE_INIT (floodguard_l2_nonip_feature, static) = {
  .arc_name = "l2-input-nonip",
  .node_name = "floodguard-l2-nonip",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VNET_FEATURE_INIT (floodguard_victim_feature, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "floodguard-victim",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-l2", "floodguard-l2-ip4"),
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};
