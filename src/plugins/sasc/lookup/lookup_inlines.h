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

enum sasc_lookup_next_e { SASC_LOOKUP_NEXT_BYPASS, SASC_LOOKUP_NEXT_ICMP_ERROR, SASC_LOOKUP_N_NEXT };

static inline int
sasc_lookup_with_hash(u64 hash, sasc_session_key_t *k, u64 *v) {
    sasc_main_t *sasc = &sasc_main;
    clib_bihash_kv_40_8_t kv;
    clib_memcpy_fast(&kv, k, 40);
    kv.value = 0;
    if (clib_bihash_search_inline_with_hash_40_8(&sasc->session_hash, hash, &kv) == 0) {
        *v = kv.value;
        return 0;
    }
    return -1;
}

static inline int
sasc_header_offset(void *start, void *end, int header_size) {
    return (end - start) + header_size;
}

static inline bool
is_icmp_error_message(u8 type) {
    return (type == 3 ||  // Destination Unreachable
            type == 4 ||  // Source Quench
            type == 5 ||  // Redirect
            type == 11 || // Time Exceeded
            type == 12);  // Parameter Problem
}
/* Extract session key from inner packet of ICMP error message */
static inline int
sasc_extract_inner_packet_key(vlib_buffer_t *b, ip4_header_t *ip, icmp46_header_t *icmp, sasc_session_key_t *skey,
                              bool *is_icmp_error) {
    u32 offset = 0;

    // Start from ICMP header
    offset = (u8 *)icmp - b->data;

    // Skip ICMP header
    offset += sizeof(*icmp);

    // Skip ICMP echo header (4 bytes of data)
    offset += sizeof(icmp_echo_header_t);

    // Extract inner IP header
    ip4_header_t *inner_ip = (ip4_header_t *)(b->data + offset);
    offset += sizeof(*inner_ip);

    // XXX: Swap addresses for ICMP error (inner packet's src becomes dst)
    ip46_address_set_ip4(&skey->dst, &inner_ip->dst_address);
    ip46_address_set_ip4(&skey->src, &inner_ip->src_address);
    skey->proto = inner_ip->protocol;
    *is_icmp_error = true;

    // Extract ports from inner packet's L4 header
    if (inner_ip->protocol == IP_PROTOCOL_TCP || inner_ip->protocol == IP_PROTOCOL_UDP) {
        udp_header_t *inner_udp = (udp_header_t *)(b->data + offset);
        offset += sizeof(*inner_udp);
        skey->sport = inner_udp->src_port;
        skey->dport = inner_udp->dst_port;
    } else if (inner_ip->protocol == IP_PROTOCOL_ICMP) {
        icmp46_header_t *inner_icmp = (icmp46_header_t *)(b->data + offset);
        offset += sizeof(*inner_icmp);
        icmp_echo_header_t *inner_echo = (icmp_echo_header_t *)(b->data + offset);
        offset += sizeof(*inner_echo);

        if (inner_icmp->type == ICMP4_echo_request || inner_icmp->type == ICMP4_echo_reply) {
            skey->sport = skey->dport = inner_echo->identifier;
        } else {
            skey->sport = skey->dport = 0;
            return -1;
        }
    } else {
        skey->sport = skey->dport = 0;
    }

    // Final validation: check if we've read beyond the packet
    if (offset > b->current_length) {
        skey->sport = skey->dport = 0;
        return -1;
    }

    return 0;
}

static inline int
sasc_calc_key_v4(vlib_buffer_t *b, u32 context_id, enum sasc_lookup_mode_e lookup_mode, sasc_session_key_t *skey,
                 bool *is_icmp_error) {
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
        } else if (is_icmp_error_message(icmp->type)) {
            // ICMP error packet - extract inner packet and set key to it
            if (sasc_extract_inner_packet_key(b, ip, icmp, skey, is_icmp_error) != 0) {
                // Failed to extract inner packet key
                return -1;
            }
        } else {
            return -1;
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
    return 0;
}

static inline int
sasc_calc_key_v6(vlib_buffer_t *b, u32 context_id, enum sasc_lookup_mode_e lookup_mode, sasc_session_key_t *skey,
                 bool *is_icmp_error) {
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
    return 0;
}

static inline int
sasc_calc_key(vlib_buffer_t *b, u32 context_id, sasc_session_key_t *k, u64 *h, bool is_ip6,
              enum sasc_lookup_mode_e lookup_mode, bool *is_icmp_error) {
    int rv;
    if (is_ip6) {
        rv = sasc_calc_key_v6(b, context_id, lookup_mode, k, is_icmp_error);

    } else {
        rv = sasc_calc_key_v4(b, context_id, lookup_mode, k, is_icmp_error);
    }
    /* calculate hash */
    h[0] = clib_bihash_hash_40_8((clib_bihash_kv_40_8_t *)(k));
    return rv;
}

#if 0
/*
 * Find the 5-tuple key. In case of an ICMP error use the inner IP packet.
 */
static inline int
sasc_calc_key_slow(vlib_buffer_t *b, u32 context_id, sasc_session_key_t *k, u64 *h, bool is_ip6, bool *is_icmp_error) {
    int offset = 0;
    udp_header_t *udp;
    icmp46_header_t *icmp;
    icmp_echo_header_t *echo;
    *is_icmp_error = false;
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
                *is_icmp_error = true;
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
            } else if (is_icmp_error_message(icmp->type)) {
                /* Do the same thing for the inner packet */
                ip4_header_t *inner_ip = (ip4_header_t *)(echo + 1);
                offset = sasc_header_offset(ip, inner_ip, sizeof(*inner_ip));
                // Swap lookup key for ICMP error
                ip46_address_set_ip4(&k->dst, &inner_ip->src_address);
                ip46_address_set_ip4(&k->src, &inner_ip->dst_address);
                k->proto = inner_ip->protocol;
                *is_icmp_error = true;
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
            } else {
                return -1;
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

#endif