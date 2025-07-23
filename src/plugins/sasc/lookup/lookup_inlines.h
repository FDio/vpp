// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_lookup_inlines_h
#define included_lookup_inlines_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <arpa/inet.h> // TODO: remove
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/format.h>
#include <vppinfra/bihash_40_8.h>
#include <sasc/sasc_funcs.h>

static inline int
sasc_header_offset(void *start, void *end, int header_size) {
    return (end - start) + header_size;
}

static inline void
sasc_calc_key_v4(vlib_buffer_t *b, u32 context_id, enum sasc_lookup_mode_e lookup_mode,
                 sasc_session_key_t *skey) {
    ip4_header_t *ip = sasc_get_ip4_header(b);
    udp_header_t *udp = (udp_header_t *)(ip + 1);
    b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
    vnet_buffer(b)->l4_hdr_offset = (u8 *)udp - b->data;

    skey->proto = ip->protocol;
    skey->context_id = context_id;
    ip46_address_set_ip4(&skey->src, &ip->src_address);
    ip46_address_set_ip4(&skey->dst, &ip->dst_address);
    if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
        skey->sport = udp->src_port;
        skey->dport = udp->dst_port;
    } else if (ip->protocol == IP_PROTOCOL_ICMP) {
        icmp46_header_t *icmp = (icmp46_header_t *)ip4_next_header(ip);
        // Treat anything but echo as an ICMP error packet
        bool is_echo = icmp->type == 8 || icmp->type == 0;
        if (is_echo) {
            icmp_echo_header_t *echo = (icmp_echo_header_t *)(icmp + 1);
            skey->sport = skey->dport = echo->identifier;
        } else {
            // ICMP error packet - use custom protocol number
            skey->proto = SASC_IP_PROTOCOL_ICMP_ERROR;
            skey->sport = icmp->type;
            skey->dport = icmp->code;
        }
    } else {
        skey->sport = skey->dport = 0;
    }
    switch (lookup_mode) {
    case SASC_LOOKUP_MODE_DEFAULT:
        break;
    case SASC_LOOKUP_MODE_4TUPLE:
        skey->sport = 0;
        break;
    case SASC_LOOKUP_MODE_3TUPLE:
        skey->sport = 0;
        skey->src = (ip46_address_t){0};
        break;
    case SASC_LOOKUP_MODE_1TUPLE:
        skey->sport = 0;
        skey->dport = 0;
        skey->proto = 0;
        skey->src = (ip46_address_t){0};
        break;
    default:
        ASSERT(0);
    }
}

static inline void
sasc_calc_key_v6(vlib_buffer_t *b, u32 context_id, enum sasc_lookup_mode_e lookup_mode,
                 sasc_session_key_t *skey) {
    ip6_header_t *ip = sasc_get_ip6_header(b);
    udp_header_t *udp = (udp_header_t *)(ip + 1);
    b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
    vnet_buffer(b)->l4_hdr_offset = (u8 *)udp - b->data;

    skey->proto = ip->protocol;
    skey->context_id = context_id;
    ip46_address_set_ip6(&skey->src, &ip->src_address);
    ip46_address_set_ip6(&skey->dst, &ip->dst_address);

    if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
        skey->sport = udp->src_port;
        skey->dport = udp->dst_port;
    } else if (ip->protocol == IP_PROTOCOL_ICMP6) {
        icmp46_header_t *icmp = (icmp46_header_t *)ip6_next_header(ip);
        icmp_echo_header_t *echo = (icmp_echo_header_t *)(icmp + 1);
        skey->sport = skey->dport = echo->identifier;
    } else {
        skey->sport = skey->dport = 0;
    }
    switch (lookup_mode) {
    case SASC_LOOKUP_MODE_DEFAULT:
        break;
    case SASC_LOOKUP_MODE_4TUPLE:
        skey->sport = 0;
        break;
    case SASC_LOOKUP_MODE_3TUPLE:
        skey->sport = 0;
        skey->src.as_u64[0] = 0;
        skey->src.as_u64[1] = 0;
        break;
    case SASC_LOOKUP_MODE_1TUPLE:
        skey->sport = 0;
        skey->dport = 0;
        skey->proto = 0;
        skey->src.as_u64[0] = 0;
        skey->src.as_u64[1] = 0;
        break;
    default:
        ASSERT(0);
    }
}

static inline void
sasc_calc_key(vlib_buffer_t *b, u32 context_id, sasc_session_key_t *k, u64 *h, bool is_ip6,
              enum sasc_lookup_mode_e lookup_mode) {
    if (is_ip6) {
        sasc_calc_key_v6(b, context_id, lookup_mode, k);

    } else {
        sasc_calc_key_v4(b, context_id, lookup_mode, k);
    }
    /* calculate hash */
    h[0] = clib_bihash_hash_40_8((clib_bihash_kv_40_8_t *)(k));
}

/*
 * Find the 5-tuple key. In case of an ICMP error use the inner IP packet.
 */
static inline int
sasc_calc_key_slow(vlib_buffer_t *b, u32 context_id, sasc_session_key_t *k, u64 *h, bool is_ip6) {
    int offset = 0;
    udp_header_t *udp;
    icmp46_header_t *icmp;
    icmp_echo_header_t *echo;

    if (is_ip6) {
        ip6_header_t *ip = sasc_get_ip6_header(b);
        // if (ip6_is_fragment(ip)) {
        //   return -1;
        // }

        ip46_address_set_ip6(&k->src, &ip->src_address);
        ip46_address_set_ip6(&k->dst, &ip->dst_address);

        k->proto = ip->protocol;
        k->context_id = context_id;

        if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
            udp = (udp_header_t *)(ip + 1);
            offset = sasc_header_offset(ip, udp, sizeof(*udp));
            k->sport = udp->src_port;
            k->dport = udp->dst_port;
        } else if (ip->protocol == IP_PROTOCOL_ICMP6) {
            icmp = (icmp46_header_t *)ip6_next_header(ip);
            echo = (icmp_echo_header_t *)(icmp + 1);
            offset = sasc_header_offset(ip, echo, sizeof(*echo));
            k->sport = k->dport = 0; // default
            if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply) {
                k->sport = k->dport = echo->identifier;
            } else if (icmp->type < 128) {
                /* Do the same thing for the inner packet */
                ip6_header_t *inner_ip = (ip6_header_t *)(echo + 1);
                offset = sasc_header_offset(ip, inner_ip, sizeof(*inner_ip));
                // Swap lookup key for ICMP error
                ip46_address_set_ip6(&k->dst, &inner_ip->dst_address);
                ip46_address_set_ip6(&k->src, &inner_ip->src_address);
                k->proto = inner_ip->protocol;
                if (inner_ip->protocol == IP_PROTOCOL_TCP ||
                    inner_ip->protocol == IP_PROTOCOL_UDP) {
                    udp = (udp_header_t *)ip6_next_header(inner_ip);
                    offset = sasc_header_offset(ip, udp, sizeof(*udp));
                    k->dport = udp->dst_port;
                    k->sport = udp->src_port;
                } else if (inner_ip->protocol == IP_PROTOCOL_ICMP) {
                    icmp = (icmp46_header_t *)ip6_next_header(inner_ip);
                    echo = (icmp_echo_header_t *)(icmp + 1);
                    offset = sasc_header_offset(ip, echo, sizeof(*echo));
                    if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply) {
                        k->sport = k->dport = echo->identifier;
                    } else {
                        sasc_log_info("Failed dealing with ICMP error %U", format_ip6_header, ip,
                                      40);
                        return -1;
                    }
                }
            }
        } else {
            k->sport = k->dport = 0;
        }
    } else {
        ip4_header_t *ip = sasc_get_ip4_header(b);

        /* Do not support fragmentation for now */
        if (ip4_get_fragment_offset(ip) > 0) {
            return -2;
        }
        ip46_address_set_ip4(&k->src, &ip->src_address);
        ip46_address_set_ip4(&k->dst, &ip->dst_address);
        k->proto = ip->protocol;
        k->context_id = context_id;

        if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
            udp = (udp_header_t *)(ip + 1);
            offset = sasc_header_offset(ip, udp, sizeof(*udp));
            k->sport = udp->src_port;
            k->dport = udp->dst_port;
        } else if (ip->protocol == IP_PROTOCOL_ICMP) {
            icmp = (icmp46_header_t *)ip4_next_header(ip);
            echo = (icmp_echo_header_t *)(icmp + 1);
            offset = sasc_header_offset(ip, echo, sizeof(*echo));
            k->sport = k->dport = 0; // default

            if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
                k->sport = k->dport = echo->identifier;
            } else {
                /* Do the same thing for the inner packet */
                ip4_header_t *inner_ip = (ip4_header_t *)(echo + 1);
                offset = sasc_header_offset(ip, inner_ip, sizeof(*inner_ip));
                // Swap lookup key for ICMP error
                ip46_address_set_ip4(&k->dst, &inner_ip->src_address);
                ip46_address_set_ip4(&k->src, &inner_ip->dst_address);
                k->proto = inner_ip->protocol;
                if (inner_ip->protocol == IP_PROTOCOL_TCP ||
                    inner_ip->protocol == IP_PROTOCOL_UDP) {
                    udp = (udp_header_t *)ip4_next_header(inner_ip);
                    offset = sasc_header_offset(ip, udp, sizeof(*udp));
                    k->dport = udp->src_port;
                    k->sport = udp->dst_port;
                } else if (inner_ip->protocol == IP_PROTOCOL_ICMP) {
                    icmp = (icmp46_header_t *)ip4_next_header(inner_ip);
                    echo = (icmp_echo_header_t *)(icmp + 1);
                    offset = sasc_header_offset(ip, echo, sizeof(*echo));
                    if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
                        k->sport = k->dport = echo->identifier;
                    } else {
                        sasc_log_info("Failed dealing with ICMP error %U", format_ip4_header, ip,
                                      20);
                        return -1;
                    }
                }
            }
        } else {
            k->sport = k->dport = 0;
        }
    }
    /* calculate hash */
    h[0] = clib_bihash_hash_40_8((clib_bihash_kv_40_8_t *)(k));
    if (offset > b->current_length) {
        return -3;
    }
    return 0;
}

#endif