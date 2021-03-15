/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_pnat_node_h
#define included_pnat_node_h

#include "pnat.h"
#include <pnat/pnat.api_enum.h>
#include <vnet/feature/feature.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/format.h>

#define foreach_pnat_errors                                         \
  _ (NONE, none, INFO, "rewritten")                                 \
  _ (TOOSHORT, tooshort, ERROR, "rewrite is longer than packet")    \
  _ (REWRITE, rewrite, ERROR, "rewrite failed")                     \
  _ (FRAGMENT, fragment, ERROR, "can't rewrite fragmented packet")  \
  _ (OPTIONS, options, ERROR, "IP4 options not supported")

typedef enum
{
#define _(f, n, s, d) PNAT_ERROR_##f,
  foreach_pnat_errors
#undef _
    PNAT_N_ERROR,
} pnat_error_t;
static vl_counter_t pnat_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_pnat_errors
#undef _
};

/* PNAT next-nodes */
typedef enum { PNAT_NEXT_DROP, PNAT_N_NEXT } pnat_next_t;

u8 *format_pnat_match_tuple(u8 *s, va_list *args);
u8 *format_pnat_rewrite_tuple(u8 *s, va_list *args);
static inline u8 *format_pnat_trace(u8 *s, va_list *args) {
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    pnat_trace_t *t = va_arg(*args, pnat_trace_t *);

    s = format(s, "pnat: index %d\n", t->pool_index);
    if (t->pool_index != ~0) {
        s = format(s, "        match: %U\n", format_pnat_match_tuple,
                   &t->match);
        s = format(s, "        rewrite: %U", format_pnat_rewrite_tuple,
                   &t->rewrite);
    }
    return s;
}

/*
 * Rewrite u64x3 starting with IP4 header source address.
 * SA/DA in IP4 header and first 16 octets of L4 header.
 */
static u32 pnat_rewrite_ip4(pnat_translation_t *t, ip4_header_t *ip) {
    /* Validity checks */
    if (ip->ip_version_and_header_length != 0x45)
        return PNAT_ERROR_OPTIONS;
    if (t->max_rewrite > clib_net_to_host_u16(ip->length))
        return PNAT_ERROR_TOOSHORT;
    if (ip4_is_fragment(ip) && t->max_rewrite > 20)
        return PNAT_ERROR_FRAGMENT;

    int i;
    pnat_u64x3_t *p = (pnat_u64x3_t *)(&ip->src_address);
    pnat_u64x3_t old = {0};

    /* Special handling for the copy instructions */
    u8 *q = (u8 *)ip;
    if (t->instructions & PNAT_INSTR_COPY_BYTE)
        t->post.as_u8[t->to_offset - 12] = q[t->from_offset];

    /* Copy out the old values given the mask and overwrite with new */
    for (i = 0; i < 3; i++) {
        old.as_u64[i] = p->as_u64[i] & t->pre_mask.as_u64[i];
        p->as_u64[i] &= ~t->post_mask.as_u64[i];
        p->as_u64[i] |= t->post.as_u64[i];
    }

    /* Adjust IP checksum */
    ip_csum_t csumd = 0;
    csumd = ip_csum_sub_even(csumd, old.as_u64[0]);
    csumd = ip_csum_add_even(csumd, t->post.as_u64[0]);
    ip_csum_t csum = ip->checksum;
    csum = ip_csum_sub_even(csum, csumd);
    ip->checksum = ip_csum_fold(csum);
    if (ip->checksum == 0xffff)
        ip->checksum = 0;
    ASSERT(ip->checksum == ip4_header_checksum(ip));

    /* Adjust L4 checksum */
    if (t->l4_checksum_offset) {
        u16 *l4csum_p = (u16 *)((char *)ip + t->l4_checksum_offset);
        ip_csum_t l4csum = *l4csum_p;
        if (l4csum) {
            l4csum = ip_csum_sub_even(l4csum, old.as_u64[1]);
            l4csum = ip_csum_sub_even(l4csum, old.as_u64[2]);
            l4csum = ip_csum_add_even(l4csum, t->post.as_u64[1]);
            l4csum = ip_csum_add_even(l4csum, t->post.as_u64[2]);

            l4csum = ip_csum_sub_even(l4csum, csumd);
            *l4csum_p = ip_csum_fold(l4csum);
        }
    }
    return PNAT_ERROR_NONE;
}

/*
 * Lookup the packet tuple in the flow cache, given the lookup mask.
 * If a binding is found, rewrite the packet according to instructions,
 * otherwise follow configured default action (forward, punt or drop)
 */
static_always_inline uword pnat_node_inline(vlib_main_t *vm,
                                            vlib_node_runtime_t *node,
                                            vlib_frame_t *frame,
                                            pnat_attachment_point_t attachment,
                                            int dir) {
    pnat_main_t *pm = &pnat_main;
    u32 n_left_from, *from;
    u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;
    u32 pool_indicies[VLIB_FRAME_SIZE], *pi = pool_indicies;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    clib_bihash_kv_16_8_t kv, value;
    ip4_header_t *ip0;

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    vlib_get_buffers(vm, from, b, n_left_from);
    pnat_interface_t *interface;

    /* Stage 1: build vector of flow hash (based on lookup mask) */
    while (n_left_from > 0) {
        u32 sw_if_index0 = vnet_buffer(b[0])->sw_if_index[dir];
        u16 sport0 = vnet_buffer(b[0])->ip.reass.l4_src_port;
        u16 dport0 = vnet_buffer(b[0])->ip.reass.l4_dst_port;
        u32 iph_offset =
            dir == VLIB_TX ? vnet_buffer(b[0])->ip.save_rewrite_length : 0;
        ip0 = (ip4_header_t *)(vlib_buffer_get_current(b[0]) + iph_offset);
        interface = pnat_interface_by_sw_if_index(sw_if_index0);
        ASSERT(interface);
        pnat_mask_fast_t mask = interface->lookup_mask_fast[attachment];
        pnat_calc_key(sw_if_index0, attachment, ip0->src_address,
                      ip0->dst_address, ip0->protocol, sport0, dport0, mask,
                      &kv);
        /* By default pass packet to next node in the feature chain */
        vnet_feature_next_u16(next, b[0]);

        if (clib_bihash_search_16_8(&pm->flowhash, &kv, &value) == 0) {
            /* Cache hit */
            *pi = value.value;
            if (pool_is_free_index(pm->translations, value.value)) {
                next[0] = PNAT_NEXT_DROP;
                b[0]->error = node->errors[PNAT_ERROR_REWRITE];
            } else {
                u32 errno0 = 0;
                pnat_translation_t *t = pool_elt_at_index(pm->translations, value.value);
                errno0 = pnat_rewrite_ip4(t, ip0);
                if (errno0) {
                    next[0] = PNAT_NEXT_DROP;
                    b[0]->error = node->errors[errno0];
                }
            }
        } else {
            /* Cache miss */
            *pi = ~0;
        }

        /*next: */
        next += 1;
        n_left_from -= 1;
        b += 1;
        pi += 1;
    }

    /* Packet trace */
    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        u32 i;
        b = bufs;
        pi = pool_indicies;
        for (i = 0; i < frame->n_vectors; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                pnat_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                if (*pi != ~0) {
                    if (!pool_is_free_index(pm->translations, *pi)) {
                        pnat_translation_t *tr =
                            pool_elt_at_index(pm->translations, *pi);
                        t->match = tr->match;
                        t->rewrite = tr->rewrite;
                    }
                }
                t->pool_index = *pi;
                b += 1;
                pi += 1;
            } else
                break;
        }
    }

    vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

    return frame->n_vectors;
}
#endif
