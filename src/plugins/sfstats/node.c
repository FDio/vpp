#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <sfstats/sfstats.h>
#include <ping/ping.h>

typedef enum
{
  SFSTATS_NEXT_IP4,
  SFSTATS_NEXT_IP6,
  SFSTATS_N_NEXT,
} sfstats_next_t;

#define SFSTATS_NEXT_NODES                                                    \
  {                                                                           \
    [SFSTATS_NEXT_IP4] = "ip4-lookup", [SFSTATS_NEXT_IP6] = "ip6-lookup",     \
  }

static inline uword
icmp6_echo_hash (ip6_address_t *src, ip6_address_t *dst, u16 id, u8 type)
{
  u64 hash = 5381;
  hash = ((hash << 5) + hash) + clib_net_to_host_u32 (src->as_u32[0]);
  hash = ((hash << 5) + hash) + clib_net_to_host_u32 (dst->as_u32[0]);
  hash = ((hash << 5) + hash) + id;
  hash = ((hash << 5) + hash) + type;
  return (uword) (hash % ICMP6_FLOWS);
}

static inline uword
tcp4_hash (ip4_address_t *src, ip4_address_t *dst, u16 src_port, u16 dst_port)
{
  u64 hash = 5381;
  hash = ((hash << 5) + hash) + clib_net_to_host_u32 (src->as_u32);
  hash = ((hash << 5) + hash) + clib_net_to_host_u32 (dst->as_u32);
  hash = ((hash << 5) + hash) + src_port;
  hash = ((hash << 5) + hash) + dst_port;
  return (uword) (hash % TCP6_FLOWS);
}

static inline uword
tcp6_hash (ip6_address_t *src, ip6_address_t *dst, u16 src_port, u16 dst_port)
{
  u64 hash = 5381;
  hash = ((hash << 5) + hash) + clib_net_to_host_u64 (src->as_u64[0]);
  hash = ((hash << 5) + hash) + clib_net_to_host_u64 (dst->as_u64[0]);
  hash = ((hash << 5) + hash) + src_port;
  hash = ((hash << 5) + hash) + dst_port;
  return (uword) (hash % TCP6_FLOWS);
}

static void
track_tcp46_flow (const tcp_header_t *tcp, tcp46_stats_t *tcp_stat, u16 len)
{
  len -= tcp_header_bytes ((void *) tcp);
  u32 seq = clib_net_to_host_u32 (tcp->seq_number);
  u32 next = seq + len;
  tcp_stat->pkts++;
  tcp_stat->bytes += len;

  if ((tcp_stat->next_seq == seq) || (tcp_stat->pkts == 1))
    {
      // Sequence number matches the expected next sequence
      tcp_stat->next_seq = next;
    }
  else if (seq < tcp_stat->next_seq)
    {
      // Packet is a duplicate, increment drop count
      tcp_stat->drop_count++;
      tcp_stat->drop_bytes += len;
    }
  else
    {
      // New sequence number, reset the next sequence
      tcp_stat->next_seq = next;
    }
}
static void
process_tcp4 (ip4_address_t *src, ip4_address_t *dst, tcp_header_t *tcp,
	      uword l4len)
{
  f64 now = vlib_time_now (vlib_get_main ());
  uword hash = tcp4_hash (src, dst, tcp->src_port, tcp->dst_port);
  tcp46_stats_t *tcp_stat = &tcp4_stats[hash];

  if (ip4_address_is_equal (&tcp_stat->src_address.ip4, src) &&
      ip4_address_is_equal (&tcp_stat->dst_address.ip4, dst) &&
      tcp_stat->src_port == tcp->src_port &&
      tcp_stat->dst_port == tcp->dst_port)
    {

      track_tcp46_flow (tcp, tcp_stat, l4len);
      tcp_stat->last_update = now;
    }
  else if ((tcp_stat->last_update == 0.0) ||
	   (now - tcp_stat->last_update > 60.0))
    {
      tcp_stat->src_address.ip4 = *src;
      tcp_stat->dst_address.ip4 = *dst;
      tcp_stat->src_port = tcp->src_port;
      tcp_stat->dst_port = tcp->dst_port;
      tcp_stat->pkts = 1;
      tcp_stat->drop_count = 0;
      tcp_stat->drop_bytes = 0;
      track_tcp46_flow (tcp, tcp_stat, l4len);
      tcp_stat->last_update = now;
    }
}

static void
process_tcp6 (ip6_address_t *src, ip6_address_t *dst, tcp_header_t *tcp,
	      uword l4len)
{
  f64 now = vlib_time_now (vlib_get_main ());
  uword hash = tcp6_hash (src, dst, tcp->src_port, tcp->dst_port);
  tcp46_stats_t *tcp_stat = &tcp6_stats[hash];

  if (ip6_address_is_equal (&tcp_stat->src_address.ip6, src) &&
      ip6_address_is_equal (&tcp_stat->dst_address.ip6, dst) &&
      tcp_stat->src_port == tcp->src_port &&
      tcp_stat->dst_port == tcp->dst_port)
    {

      track_tcp46_flow (tcp, tcp_stat, l4len);
      tcp_stat->last_update = now;
    }
  else if ((tcp_stat->last_update == 0.0) ||
	   (now - tcp_stat->last_update > 60.0))
    {
      tcp_stat->src_address.ip6 = *src;
      tcp_stat->dst_address.ip6 = *dst;
      tcp_stat->src_port = tcp->src_port;
      tcp_stat->dst_port = tcp->dst_port;
      tcp_stat->pkts = 1;
      tcp_stat->drop_count = 0;
      tcp_stat->drop_bytes = 0;
      track_tcp46_flow (tcp, tcp_stat, l4len);
      tcp_stat->last_update = now;
    }
}

static void
process_icmp6 (ip6_address_t *src, ip6_address_t *dst, u16 id, u16 seq,
	       icmp6_type_t type)
{
  f64 now = vlib_time_now (vlib_get_main ());
  uword hash = icmp6_echo_hash (src, dst, id, type);
  icmp6_stats_t *icmp6_stat = &icmp6_stats[hash];

  if (ip6_address_is_equal (&icmp6_stat->src_address, src) &&
      ip6_address_is_equal (&icmp6_stat->dst_address, dst) &&
      icmp6_stat->type == type && icmp6_stat->id == id)
    {

      if ((u16) (icmp6_stat->last_seq + 1) != seq)
	{
	  icmp6_stat->drop_count++;
	}

      icmp6_stat->last_seq = seq;
      icmp6_stat->count++;
      icmp6_stat->last_update = now;
    }
  else if ((icmp6_stat->last_update == 0.0) ||
	   (now - icmp6_stat->last_update > 60.0))
    {
      icmp6_stat->src_address = *src;
      icmp6_stat->dst_address = *dst;
      icmp6_stat->type = type;
      icmp6_stat->id = id;
      icmp6_stat->last_seq = seq;
      icmp6_stat->count = 1;
      icmp6_stat->drop_count = 0;
      icmp6_stat->last_update = now;
    }
}

static_always_inline uword
sfstats_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, u8 is_ip4)
{
  u32 n_left_from, *from, *f;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  sfstats_main_t *sm = &sfstats_main;
  ip4_header_t *ip40 = 0;
  ip6_header_t *ip60 = 0;

  next = nexts;

  from = vlib_frame_vector_args (frame);
  f = from;
  n_left_from = frame->n_vectors;
  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      vnet_feature_next_u16 (next, b0);

      if (is_ip4)
	{
	  sm->ipv4_count++;
	  ip40 = (ip4_header_t *) vlib_buffer_get_current (b0);
	  if (ip40->protocol == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *tcp0;
	      tcp0 = ip4_next_header (ip40);
	      process_tcp4 (&ip40->src_address, &ip40->dst_address, tcp0,
			    clib_net_to_host_u16 (ip40->length) -
			      sizeof (ip4_header_t));
	    }
	}
      else
	{
	  sm->ipv6_count++;
	  ip60 = (ip6_header_t *) vlib_buffer_get_current (b0);
	  if (ip60->protocol == IP_PROTOCOL_ICMP6)
	    {
	      icmp46_header_t *icmp0;
	      icmp6_type_t type0;
	      icmp0 = ip6_next_header (ip60);
	      type0 = icmp0->type;
	      if (type0 == ICMP6_echo_request || type0 == ICMP6_echo_reply)
		{
		  // Process ICMPv6 echo request/reply
		  icmp46_echo_request_t *echo =
		    (icmp46_echo_request_t *) (icmp0 + 1);
		  process_icmp6 (&ip60->src_address, &ip60->dst_address,
				 echo->id, clib_net_to_host_u16 (echo->seq),
				 type0);
		}
	    }
	  else if (ip60->protocol == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *tcp0;
	      tcp0 = ip6_next_header (ip60);
	      process_tcp6 (&ip60->src_address, &ip60->dst_address, tcp0,
			    clib_net_to_host_u16 (ip60->payload_length));
	      // printf("%d %lu\n", clib_net_to_host_u16(ip60->payload_length),
	      // sizeof(ip6_header_t));
	    }
	}

      from += 1;
      n_left_from -= 1;
      next += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, f, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (sfstats6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfstats_node_inline (vm, node, frame, 0 /* is_ip4 */);
}

// Enregistrement du nœud
VLIB_REGISTER_NODE (sfstats6_node) = {
  .name = "sfstats6-node",
  .vector_size = sizeof (u32),
  .format_trace = NULL,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SFSTATS_N_NEXT,
  .next_nodes = SFSTATS_NEXT_NODES,
};

VLIB_NODE_FN (sfstats4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  // Appel de la fonction principale du nœud
  return sfstats_node_inline (vm, node, frame, 1 /* is_ip4 */);
}

VLIB_REGISTER_NODE (sfstats4_node) = {
  .name = "sfstats4-node",
  .vector_size = sizeof (u32),
  .format_trace = NULL,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SFSTATS_N_NEXT,
  .next_nodes = SFSTATS_NEXT_NODES,
};

VNET_FEATURE_INIT (sfstats6_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "sfstats6-node",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

VNET_FEATURE_INIT (sfstats4_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "sfstats4-node",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
