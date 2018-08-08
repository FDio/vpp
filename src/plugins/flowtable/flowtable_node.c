#include <vppinfra/dlist.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip4_packet.h>

#include "flowtable.h"

vlib_node_registration_t flowtable_node;


typedef struct {
    u32 sw_if_index;
    u32 next_index;
    u32 offloaded;
} flow_trace_t;

static u8 *
format_get_flowinfo(u8 * s, va_list * args)
{
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    flow_trace_t * t = va_arg(*args, flow_trace_t *);

    s = format(s, "FlowInfo - sw_if_index %d, next_index = %d, offload = %d",
            t->sw_if_index, t->next_index, t->offloaded);
    return s;
}

/* TODO find a better hash function */
static inline u64
hash_signature(u8 is_ip4, signature const * sig)
{
    if (is_ip4) {
        return sig->ip4.src.as_u32 ^ sig->ip4.dst.as_u32 ^ sig->ip4.proto
            ^ sig->ip4.port_src ^ sig->ip4.port_dst;
    } else {
        return sig->ip6.dst.as_u64[0] ^ sig->ip6.dst.as_u64[1]
            ^ sig->ip6.src.as_u64[0] ^ sig->ip6.src.as_u64[1]
            ^ sig->ip4.port_src ^ sig->ip4.port_dst;
    }
}

static inline u64
parse_ip4_packet(ip4_header_t * ip0, uword * is_reverse, struct ip4_sig *sig)
{
    sig->proto = ip0->protocol;

    if (ip4_address_compare(&ip0->src_address, &ip0->dst_address) < 0) {
        sig->src = ip0->src_address;
        sig->dst = ip0->dst_address;
        *is_reverse = 1;
    } else {
        sig->src = ip0->dst_address;
        sig->dst = ip0->src_address;
    }

    if (sig->proto == IP_PROTOCOL_UDP || sig->proto == IP_PROTOCOL_TCP) {
        /* tcp and udp ports have the same offset */
        udp_header_t * udp0 = (udp_header_t *) ip4_next_header(ip0);
        if (is_reverse == 0) {
            sig->port_src = udp0->src_port;
            sig->port_dst = udp0->dst_port;
        } else {
            sig->port_src = udp0->dst_port;
            sig->port_dst = udp0->src_port;
        }
    } else {
        sig->port_src = 0;
        sig->port_dst = 0;
    }

    return hash_signature(1 /* is_ip4 */, (signature *) sig);
}

static inline u64
parse_ip6_packet(ip6_header_t * ip60, uword * is_reverse, struct ip6_sig * sig)
{
    sig->proto = ip60->protocol;

    if (ip6_address_compare(&ip60->src_address, &ip60->dst_address) < 0) {
        sig->src = ip60->src_address;
        sig->dst = ip60->dst_address;
        *is_reverse = 1;
    } else {
        sig->src = ip60->dst_address;
        sig->dst = ip60->src_address;
    }

    if (sig->proto == IP_PROTOCOL_UDP || sig->proto == IP_PROTOCOL_TCP) {
        /* tcp and udp ports have the same offset */
        udp_header_t *udp0 = (udp_header_t *) ip6_next_header(ip60);
        if (is_reverse == 0) {
            sig->port_src = udp0->src_port;
            sig->port_dst = udp0->dst_port;
        } else {
            sig->port_src = udp0->dst_port;
            sig->port_dst = udp0->src_port;
        }
    } else {
        sig->port_src = 0;
        sig->port_dst = 0;
    }

    return hash_signature(0 /* is_ip4 */, (signature *) sig);
}

int
flowtable_update(u8 is_ip4, u8 ip_src[16], u8 ip_dst[16], u8 ip_upper_proto,
        u16 port_src, u16 port_dst, u16 lifetime, u8 offloaded, u8 infos[27])
{
    flowtable_main_t * fm = &flowtable_main;
    u32 sig_len;
    signature sig;
    flow_entry_t *flow;
    BVT(clib_bihash_kv) kv;

    if (is_ip4) {
        sig_len = sizeof(sig.ip4);
        clib_memcpy (&sig.ip4.src, ip_src, 4);
        clib_memcpy (&sig.ip4.dst, ip_dst, 4);
        sig.ip4.proto = ip_upper_proto;
        sig.ip4.port_src = port_src;
        sig.ip4.port_dst = port_dst;

    } else {
        sig_len = sizeof(sig.ip6);
        clib_memcpy (&sig.ip6.src, ip_src, 16);
        clib_memcpy (&sig.ip6.dst, ip_dst, 16);
        sig.ip6.proto = ip_upper_proto;
        sig.ip6.port_src = port_src;
        sig.ip6.port_dst = port_dst;
    }

    flow = NULL;
    kv.key = hash_signature(is_ip4, &sig);
    if (PREDICT_FALSE(BV(clib_bihash_search) (&fm->flows_ht, &kv, &kv))) {
        return -1; /* flow not found */
    } else {
        dlist_elt_t * ht_line;
        dlist_elt_t * e;
        u32 ht_line_head_index;

        flow = NULL;
        ht_line_head_index = (u32) kv.value;
        if (dlist_is_empty(fm->ht_lines, ht_line_head_index))
            return -1; /* flow not found */

        ht_line = pool_elt_at_index(fm->ht_lines, ht_line_head_index);
        e = pool_elt_at_index(fm->ht_lines, ht_line->next);
        while (!dlist_is_head(e)) {
            flow = pool_elt_at_index(fm->flows, e->value);
            if (PREDICT_TRUE(memcmp(&flow->sig, &sig, sig_len) == 0)) {
                break;
            }
            e = pool_elt_at_index(fm->ht_lines, e->next);
        }
    }

    if (PREDICT_FALSE(flow == NULL))
        return -1; /* flow not found */

    if (lifetime != (u16) ~0) {
        ASSERT(lifetime < TIMER_MAX_LIFETIME);
        flow->lifetime = lifetime;
    }
    flow->infos.data.offloaded = offloaded;
    clib_memcpy(flow->infos.data.opaque, infos, sizeof(flow->infos.data.opaque));

    return 0;
}

static inline void
flowtable_entry_remove(flowtable_main_t *fm, flow_entry_t * f)
{
    /* remove node from hashtable */
    clib_dlist_remove(fm->ht_lines, f->ht_index);
    pool_put_index(fm->ht_lines, f->ht_index);

    /* if list is empty, free it and delete hashtable entry */
    if (dlist_is_empty(fm->ht_lines, f->ht_line_index)) {
        pool_put_index(fm->ht_lines, f->ht_line_index);

        BVT(clib_bihash_kv) kv = {.key = f->sig_hash};
        BV(clib_bihash_add_del) (&fm->flows_ht, &kv, 0 /* is_add */);
    }

    /* release flow to pool */
    pool_put(fm->flows, f);
    ASSERT(fm->flows_cpt > 1);
    fm->flows_cpt--;
}

static u64
flowtable_timer_expire(flowtable_main_t *fm, u32 now)
{
    u64 expire_cpt;
    flow_entry_t * f;
    u32 * time_slot_curr_index;
    dlist_elt_t * time_slot_curr;
    dlist_elt_t * e;

    time_slot_curr_index = vec_elt_at_index(fm->timer_wheel, fm->time_index);

    if (PREDICT_FALSE(dlist_is_empty(fm->timers, *time_slot_curr_index)))
        return 0;

    expire_cpt = 0;
    time_slot_curr = pool_elt_at_index(fm->timers, *time_slot_curr_index);

    e = pool_elt_at_index(fm->timers, time_slot_curr->next);
    while (!dlist_is_head(e) && expire_cpt < TIMER_MAX_EXPIRE) {
        u32 next_index;
        f = pool_elt_at_index(fm->flows, e->value);

        ASSERT(f->timer_index == (e - fm->timers));
        ASSERT(f->expire >= now);
        flowtable_entry_remove(fm, f);

        next_index = e->next;
        clib_dlist_remove(fm->timers, e - fm->timers);
        pool_put(fm->timers, e);

        expire_cpt++;
        e = pool_elt_at_index(fm->timers, next_index);
    }

    return expire_cpt;
}

static inline void
timer_wheel_insert_flow(flowtable_main_t *fm, flow_entry_t *f)
{
    u32 timer_slot_head_index;

    timer_slot_head_index = (fm->time_index + f->lifetime) % TIMER_MAX_LIFETIME;
    clib_dlist_addtail(fm->timers, timer_slot_head_index, f->timer_index);
}

static void
timer_wheel_resched_flow(flowtable_main_t *fm, flow_entry_t *f, u64 now)
{
    clib_dlist_remove(fm->timers, f->timer_index);
    f->expire = now + f->lifetime;
    timer_wheel_insert_flow(fm, f);

    return;
}

/* TODO: replace with a more appropriate hashtable */
static inline flow_entry_t *
flowtable_entry_lookup_create(flowtable_main_t *fm, BVT(clib_bihash_kv) *kv,
        signature const *sig, u32 const sig_len, u32 const now, int *created)
{
    flow_entry_t * f;
    dlist_elt_t * ht_line;
    dlist_elt_t * timer_entry;
    dlist_elt_t * flow_entry;
    u32 ht_line_head_index;

    ht_line = NULL;

    /* get hashtable line */
    if (PREDICT_TRUE(BV(clib_bihash_search) (&fm->flows_ht, kv, kv) == 0)) {
        dlist_elt_t * e;
        ht_line_head_index = (u32) kv->value;
        ht_line = pool_elt_at_index(fm->ht_lines, ht_line_head_index);

        /* The list CANNOT be a singleton */
        e = pool_elt_at_index(fm->ht_lines, ht_line->next);
        while (!dlist_is_head(e)) {
            f = pool_elt_at_index(fm->flows, e->value);
            if (PREDICT_TRUE(memcmp(&f->sig, &sig, sig_len) == 0)) {
                return f;
            }
            e = pool_elt_at_index(fm->ht_lines, e->next);
        }

        vlib_node_increment_counter(fm->vlib_main, flowtable_node.index,
                FLOWTABLE_ERROR_COLLISION , 1);
    } else {
        /* create a new line */
        pool_get(fm->ht_lines, ht_line);

        ht_line_head_index = ht_line - fm->ht_lines;
        clib_dlist_init (fm->ht_lines, ht_line_head_index);
        kv->value = ht_line_head_index;
        BV(clib_bihash_add_del) (&fm->flows_ht, kv, 1 /* is_add */);
    }

    /* assume the flowtable has been configured correctly */
    ASSERT(fm->flows_cpt <= FM_POOL_COUNT);
    if (PREDICT_FALSE(fm->flows_cpt > FM_POOL_COUNT)) {
        return NULL;
    }

    /* create new flow */
    *created = 1;
    pool_get_aligned(fm->flows, f, CLIB_CACHE_LINE_BYTES);
    fm->flows_cpt++;

    memset(f, 0, sizeof(*f));
    f->sig_len = sig_len;
    clib_memcpy(&f->sig, &sig, sig_len);
     f->sig_hash = kv->key;
    f->lifetime = TIMER_DEFAULT_LIFETIME;
    f->expire = now + TIMER_DEFAULT_LIFETIME;

    /* insert in timer list */
    pool_get(fm->timers, timer_entry);
    timer_entry->value = f - fm->flows; /* index within the flow pool */
    f->timer_index = timer_entry - fm->timers; /* index within the timer pool */
    timer_wheel_insert_flow(fm, f);

    /* insert in ht line */
    pool_get(fm->ht_lines, flow_entry);
    f->ht_index = flow_entry - fm->ht_lines; /* index within the ht line pool */
    flow_entry->value = f - fm->flows; /* index within the flow pool */
    f->ht_line_index = ht_line_head_index;
    clib_dlist_addhead(fm->ht_lines, ht_line_head_index, f->ht_index);

    return f;
}

static inline void
timer_wheel_index_update(flowtable_main_t * fm, u32 now)
{
    u32 new_index = now % TIMER_MAX_LIFETIME;

    if (PREDICT_FALSE(fm->time_index == ~0)) {
        fm->time_index = new_index;
        return;
    }

    if (new_index != fm->time_index) {
        /* reschedule all remaining flows on current time index
         * at the begining of the next one */

        u32 * curr_slot_index = vec_elt_at_index(fm->timer_wheel, fm->time_index);
        dlist_elt_t * curr_head = pool_elt_at_index(fm->timers, *curr_slot_index);

        u32 * next_slot_index = vec_elt_at_index(fm->timer_wheel, new_index);
        dlist_elt_t * next_head = pool_elt_at_index(fm->timers, *next_slot_index);

        if (PREDICT_FALSE(dlist_is_empty(fm->timers, *curr_slot_index))) {
            fm->time_index = new_index;
            return;
        }

        dlist_elt_t * curr_prev = pool_elt_at_index (fm->timers, curr_head->prev);
        dlist_elt_t * curr_next = pool_elt_at_index (fm->timers, curr_head->next);

        /* insert timer list of current time slot at the begining of the next slot */
        if (PREDICT_FALSE(dlist_is_empty(fm->timers, *next_slot_index))) {
            next_head->next = curr_head->next;
            next_head->prev = curr_head->prev;
            curr_prev->next = *next_slot_index;
            curr_next->prev = *next_slot_index;
        } else {
            dlist_elt_t * next_next = pool_elt_at_index (fm->timers, next_head->next);
            curr_prev->next = next_head->next;
            next_head->next = curr_head->next;
            next_next->prev = curr_head->prev;
            curr_next->prev = *next_slot_index;
        }

        /* reset current time slot as an empty list */
        memset (curr_head, 0xff, sizeof (*curr_head));

        fm->time_index = new_index;
    }
}

static uword
flowtable_process(vlib_main_t * vm,
    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, * from, next_index, * to_next;
    flowtable_main_t * fm = &flowtable_main;

#define _(sym, str) u32 CPT_##sym = 0;
    foreach_flowtable_error
#undef _

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    u32 current_time = (u32) ((u64) fm->vlib_main->cpu_time_last_node_dispatch / fm->vlib_main->clib_time.clocks_per_second);
    timer_wheel_index_update(fm, current_time);

    while (n_left_from > 0)
    {
        u32 pi0;
        u32 next0;
        u32 n_left_to_next;

        vlib_buffer_t * b0;
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        /* Single loop */
        while (n_left_from > 0 && n_left_to_next > 0)
        {
            int created = 0;
            flow_entry_t * flow = NULL;
            uword is_reverse = 0;
            u64 sig_hash;
            BVT(clib_bihash_kv) kv;

            u16 type;
            pi0 = to_next[0] = from[0];
            b0 = vlib_get_buffer(vm, pi0);
            u32 sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

            /* Get Flow & copy metadatas into opaque1 or opaque2 */
            ethernet_header_t * eth0 = (void *) (b0->data + b0->current_data);
            type = clib_net_to_host_u16(eth0->type);
            if (PREDICT_TRUE
                    (type == ETHERNET_TYPE_IP6 || type == ETHERNET_TYPE_IP4))
            {
                u32 sig_len;
                signature sig;
                vlib_buffer_advance(b0, sizeof(ethernet_header_t));

                /* compute 5 tuple key so that 2 half connections
                 * get into the same flow */
                if (type == ETHERNET_TYPE_IP4)
                {
                    sig_len = sizeof(struct ip4_sig);
                    sig_hash = parse_ip4_packet(vlib_buffer_get_current(b0),
                            &is_reverse, (struct ip4_sig *) &sig);
                } else {
                    sig_len = sizeof(struct ip6_sig);
                    sig_hash = parse_ip6_packet(vlib_buffer_get_current(b0),
                            &is_reverse, (struct ip6_sig *) &sig);
                }

                /* lookup flow */
                kv.key = sig_hash;
                flow = flowtable_entry_lookup_create(fm, &kv, &sig, sig_len,
                        current_time, &created);

                if (PREDICT_FALSE(flow == NULL)) {
                    CPT_ALLOC_ERROR++;
                    next0 = FT_NEXT_ETHERNET_INPUT;
                    goto get_flowinfo_error;
                }

                if (created) {
                    CPT_CREATED++;
                } else {
                    timer_wheel_resched_flow(fm, flow, current_time);
                    CPT_HIT++;
                }

                if (is_reverse)
                    flow->stats.reverse++;
                else
                    flow->stats.straight++;


                if (flow_is_offloaded(flow)) {
                    next0 = FT_NEXT_ETHERNET_INPUT;
                    clib_memcpy(b0->opaque, &flow->infos, sizeof(flow->infos));
                    vnet_buffer (b0)->sw_if_index[VLIB_RX] = flow->infos.data.sw_if_index_current;

                    CPT_OFFLOADED++;
                } else {
                    flow->infos.data.sw_if_index_current = sw_if_index0;
                    clib_memcpy(b0->opaque, &flow->infos, sizeof(flow->infos));
                    next0 = fm->next_node_index;
                }
            } else {
                next0 = FT_NEXT_ETHERNET_INPUT;
            }
            vlib_buffer_reset(b0);

            /* stats */
            CPT_THRU++;

            /* frame mgmt */
            from++;
            to_next++;
            n_left_from--;
            n_left_to_next--;

            if (b0->flags & VLIB_BUFFER_IS_TRACED)
            {
                flow_trace_t * t = vlib_add_trace(vm, node, b0, sizeof(*t));
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                if (flow)
                    t->offloaded = flow->infos.data.offloaded;
                else
                    t->offloaded = 0;
            }

get_flowinfo_error:
            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                n_left_to_next, pi0, next0);
        }
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }

    /* handle expirations */
    CPT_TIMER_EXPIRE += flowtable_timer_expire(fm, current_time);

#define _(sym, str) \
    vlib_node_increment_counter(vm, flowtable_node.index, \
            FLOWTABLE_ERROR_##sym , CPT_##sym);
    foreach_flowtable_error
#undef _

    return frame->n_vectors;
}

static char * flowtable_error_strings[] = {
#define _(sym, string) string,
    foreach_flowtable_error
#undef _
};

VLIB_REGISTER_NODE(flowtable_node) = {
    .function = flowtable_process,
    .name = "flowtable-process",
    .vector_size = sizeof(u32),
    .format_trace = format_get_flowinfo,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = FLOWTABLE_N_ERROR,
    .error_strings = flowtable_error_strings,
    .n_next_nodes = FT_NEXT_N_NEXT,
    .next_nodes = {
        [FT_NEXT_DROP] = "error-drop",
        [FT_NEXT_ETHERNET_INPUT] = "ethernet-input"
    }
};
