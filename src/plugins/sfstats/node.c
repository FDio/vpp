#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <sfstats/sfstats.h>
#include <ping/ping.h>

typedef enum {
    SFSTATS_NEXT_IP4,
    SFSTATS_NEXT_IP6,
    SFSTATS_N_NEXT,
} sfstats_next_t;

#define SFSTATS_NEXT_NODES { \
    [SFSTATS_NEXT_IP4] = "ip4-lookup", \
    [SFSTATS_NEXT_IP6] = "ip6-lookup", \
}

static inline uword icmp6_echo_hash(ip6_address_t *src, ip6_address_t *dst, u16 id, u8 type) {
    u64 hash = 5381;
    hash = ((hash << 5) + hash) + clib_net_to_host_u32(src->as_u32[0]);
    hash = ((hash << 5) + hash) + clib_net_to_host_u32(dst->as_u32[0]);
    hash = ((hash << 5) + hash) + id;
    hash = ((hash << 5) + hash) + type;
    return (uword)(hash % ICMP6_FLOWS); 
}

static_always_inline uword
sfstats_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_ip4) {
    u32 n_left_from, *from, *f;
    u16 nexts[VLIB_FRAME_SIZE], *next;
    sfstats_main_t *sm = &sfstats_main;
    ip6_header_t *ip60 = 0;
    
    next = nexts;

    from = vlib_frame_vector_args(frame);
    f = from;
    n_left_from = frame->n_vectors;
    while (n_left_from > 0) {
        u32 bi0;
        vlib_buffer_t *b0;

        bi0 = from[0];
        b0 = vlib_get_buffer(vm, bi0);
        vnet_feature_next_u16(next, b0);

        if (is_ip4) {
            sm->ipv4_count++;
        } else {
            sm->ipv6_count++;
            ip60 = (ip6_header_t *) vlib_buffer_get_current(b0);
            if (ip60->protocol == IP_PROTOCOL_ICMP6) {
                icmp46_header_t *icmp0;
                icmp6_type_t type0;
                icmp0 = ip6_next_header (ip60);
                type0 = icmp0->type;
                if (type0 == ICMP6_echo_request || type0 == ICMP6_echo_reply) {
                  f64 now = vlib_time_now(vm);
                  icmp46_echo_request_t *echo = (icmp46_echo_request_t *) (icmp0 + 1);
                  uword hash = icmp6_echo_hash(&ip60->src_address, &ip60->dst_address, echo->id, type0);
                  icmp6_stats_t *icmp6_stat = &icmp6_stats[hash];
                  if(ip6_address_is_equal(&icmp6_stat->src_address, &ip60->src_address) &&
                     ip6_address_is_equal(&icmp6_stat->dst_address, &ip60->dst_address) &&
                     icmp6_stat->type == type0 &&
                     icmp6_stat->id == echo->id) {

                      u16 seq = clib_net_to_host_u16(echo->seq);
                      if (icmp6_stat->last_seq+1 != seq) 
                        icmp6_stat->drop_count++;

                      icmp6_stat->last_seq = seq;
                      icmp6_stat->count++;
                      icmp6_stat->last_update = now;
                  } else if ((icmp6_stat->last_update == 0.0) || (now - icmp6_stat->last_update > 60.0)) {
                      icmp6_stat->src_address = ip60->src_address;
                      icmp6_stat->dst_address = ip60->dst_address;
                      icmp6_stat->type = type0;
                      icmp6_stat->id = echo->id;
                      icmp6_stat->last_seq = clib_net_to_host_u16(echo->seq);
                      icmp6_stat->count = 1;
                      icmp6_stat->drop_count = 0;
                      icmp6_stat->last_update = now;
                  }
                }
            }
        }

        from += 1;
        n_left_from -= 1;
        next += 1;
    }
    
    vlib_buffer_enqueue_to_next (vm, node, f, nexts, frame->n_vectors);
    return frame->n_vectors;
}

VLIB_NODE_FN(sfstats6_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    // Appel de la fonction principale du nœud
    return sfstats_node_inline(vm, node, frame, 0 /* is_ip4 */);
}

// Enregistrement du nœud
VLIB_REGISTER_NODE(sfstats6_node) = {
    .name = "sfstats6-node",
    .vector_size = sizeof(u32),
    .format_trace = NULL,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_next_nodes = SFSTATS_N_NEXT,
    .next_nodes = SFSTATS_NEXT_NODES,
};


VLIB_NODE_FN(sfstats4_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    // Appel de la fonction principale du nœud
    return sfstats_node_inline(vm, node, frame, 1 /* is_ip4 */);
}

// Enregistrement du nœud
VLIB_REGISTER_NODE(sfstats4_node) = {
    .name = "sfstats4-node",
    .vector_size = sizeof(u32),
    .format_trace = NULL,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_next_nodes = SFSTATS_N_NEXT,
    .next_nodes = SFSTATS_NEXT_NODES,
};

VNET_FEATURE_INIT(sfstats6_feature, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "sfstats6-node",
    .runs_before = VNET_FEATURES("ip6-lookup"),
};


VNET_FEATURE_INIT(sfstats4_feature, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "sfstats4-node",
    .runs_before = VNET_FEATURES("ip4-lookup"),
};


