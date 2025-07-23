// SPDX-License-Identifier: Apache-2.0
#include "sasc_packet_factory.h"
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h>

/* Minimal IPv4 + TCP/UDP/ICMPv4 builder. Ethernet header omitted: inject into appropriate node. */

static void
ip4_finalize_checksums(ip4_header_t *ip) {
    ip->checksum = 0;
    ip->checksum = ip4_header_checksum(ip);
}

static u16
csum_fold(u32 sum) {
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    return (u16)~sum;
}

static u16
csum_add(u32 sum, u16 x) {
    return sum + x;
}

static u16
ip4_pseudo_csum(ip4_header_t *ip, u8 proto, u16 l4_len) {
    u32 sum = 0;
    sum = csum_add(sum, ip->src_address.as_u16[0]);
    sum = csum_add(sum, ip->src_address.as_u16[1]);
    sum = csum_add(sum, ip->dst_address.as_u16[0]);
    sum = csum_add(sum, ip->dst_address.as_u16[1]);
    sum = csum_add(sum, clib_host_to_net_u16(proto));
    sum = csum_add(sum, clib_host_to_net_u16(l4_len));
    return (u16)sum;
}

static u16
tcp_checksum(ip4_header_t *ip, tcp_header_t *th, u16 tcp_len) {
    u32 sum = ip4_pseudo_csum(ip, IP_PROTOCOL_TCP, tcp_len);
    u16 *u = (u16 *)th;
    for (u32 i = 0; i < (tcp_len / 2); i++)
        sum += clib_net_to_host_u16(u[i]);
    if (tcp_len & 1)
        sum += ((u8 *)th)[tcp_len - 1] << 8;
    return csum_fold(sum);
}

static u16
udp_checksum(ip4_header_t *ip, udp_header_t *uh, u16 udp_len) {
    u32 sum = ip4_pseudo_csum(ip, IP_PROTOCOL_UDP, udp_len);
    u16 *u = (u16 *)uh;
    for (u32 i = 0; i < (udp_len / 2); i++)
        sum += clib_net_to_host_u16(u[i]);
    if (udp_len & 1)
        sum += ((u8 *)uh)[udp_len - 1] << 8;
    return csum_fold(sum);
}

static u16
icmp_checksum(u16 *data, u16 len) {
    u32 sum = 0;
    for (u32 i = 0; i < len / 2; i++)
        sum += clib_net_to_host_u16(data[i]);
    if (len & 1)
        sum += ((u8 *)data)[len - 1] << 8;
    return csum_fold(sum);
}

/* Encode a minimal TCP options block. Returns options length (multiple of 4). */
static u8
tcp_encode_opts(u8 *dst, const sasc_packet_desc_t *d) {
    u8 *p = dst;
    if (d->tcp.mss_present) {
        *p++ = 2;
        *p++ = 4; /* MSS */
        *(u16 *)p = clib_host_to_net_u16(d->tcp.mss);
        p += 2;
    }
    if (d->tcp.wscale_present) {
        *p++ = 3;
        *p++ = 3;
        *p++ = d->tcp.wscale;
    }
    if (d->tcp.sack_ok) {
        *p++ = 4;
        *p++ = 2;
    }
    if (d->tcp.ts_present) {
        *p++ = 8;
        *p++ = 10;
        *(u32 *)p = clib_host_to_net_u32(d->tcp.tsval);
        p += 4;
        *(u32 *)p = clib_host_to_net_u32(d->tcp.tsecr);
        p += 4;
    }
    /* pad to 4-byte boundary with NOP (1) */
    while (((p - dst) & 3) != 0)
        *p++ = 1;
    return (u8)(p - dst);
}

vlib_buffer_t *
sasc_pkt_build(vlib_main_t *vm, const sasc_packet_desc_t *d) {
    /* Allocate a buffer */
    u32 bi = ~0u;
    if (vlib_buffer_alloc(vm, &bi, 1) != 1)
        return 0;
    vlib_buffer_t *b = vlib_get_buffer(vm, bi);
    u8 *cur = b->data;
    u8 *start = cur;

    /* IPv4 header */
    ip4_header_t *ip = (ip4_header_t *)cur;
    cur += sizeof(*ip);
    ip->ip_version_and_header_length = 0x45;
    ip->tos = 0;
    ip->fragment_id = 0;
    ip->flags_and_fragment_offset = 0;
    ip->ttl = 64;
    ip->protocol = d->l4_proto;
    ip->src_address.as_u32 = d->src.ip4.as_u32;
    ip->dst_address.as_u32 = d->dst.ip4.as_u32;

    if (d->l4_proto == IP_PROTOCOL_TCP) {
        tcp_header_t *th = (tcp_header_t *)cur;
        u8 *opt_ptr = (u8 *)(th + 1);
        u8 opt_len = tcp_encode_opts(opt_ptr, d);
        cur = opt_ptr + opt_len;

        th->src_port = clib_host_to_net_u16(d->sport);
        th->dst_port = clib_host_to_net_u16(d->dport);
        th->seq_number = clib_host_to_net_u32(d->tcp.seq);
        th->ack_number = clib_host_to_net_u32(d->tcp.ack);
        th->data_offset_and_reserved = (u8)(((sizeof(*th) + opt_len) >> 2) << 4);
        th->flags = d->tcp.flags;
        th->window = clib_host_to_net_u16(d->tcp.win);
        th->checksum = 0;
        th->urgent_pointer = 0;

        /* payload (if any) */
        if (d->tcp.data_len) {
            clib_memset_u8(cur, 0x42, d->tcp.data_len);
            cur += d->tcp.data_len;
        }

        u16 tcp_len = (u16)(cur - (u8 *)th);
        ip->length = clib_host_to_net_u16((u16)(sizeof(*ip) + tcp_len));
        ip4_finalize_checksums(ip);
        th->checksum = tcp_checksum(ip, th, tcp_len);

    } else if (d->l4_proto == IP_PROTOCOL_UDP) {
        udp_header_t *uh = (udp_header_t *)cur;
        cur += sizeof(*uh);
        uh->src_port = clib_host_to_net_u16(d->sport);
        uh->dst_port = clib_host_to_net_u16(d->dport);
        u16 udp_len = (u16)(sizeof(*uh) + d->payload_len);
        uh->length = clib_host_to_net_u16(udp_len);
        uh->checksum = 0;
        if (d->payload_len) {
            clib_memset_u8(cur, 0x24, d->payload_len);
            cur += d->payload_len;
        }
        ip->length = clib_host_to_net_u16((u16)(sizeof(*ip) + udp_len));
        ip4_finalize_checksums(ip);
        uh->checksum = udp_checksum(ip, uh, udp_len);

    } else if (d->l4_proto == IP_PROTOCOL_ICMP) {
        /* ICMP Echo or ICMP Error (Destination Unreachable) */
        typedef struct {
            u8 type, code;
            u16 csum;
            u32 rest; /* varies: for dest-unreach this is unused */
        } icmp4_header_min_t;

        icmp4_header_min_t *ih = (icmp4_header_min_t *)cur;
        cur += sizeof(*ih);
        ih->type = d->icmp.type;
        ih->code = d->icmp.code;
        ih->csum = 0;
        ih->rest = 0;

        if (d->icmp.type == 3 /* dest unreach */ && d->icmp.inner.present) {
            /* Per RFC 792/1812: include original IP header + 8 bytes L4 */
            ip4_header_t *inner_ip = (ip4_header_t *)cur;
            cur += sizeof(*inner_ip);
            inner_ip->ip_version_and_header_length = 0x45;
            inner_ip->tos = 0;
            inner_ip->length = clib_host_to_net_u16(sizeof(ip4_header_t) + 8); /* header + 8 bytes of L4 */
            inner_ip->fragment_id = 0;
            inner_ip->flags_and_fragment_offset = 0;
            inner_ip->ttl = 64;
            inner_ip->protocol = d->icmp.inner.l4_proto;
            inner_ip->src_address.as_u32 = d->icmp.inner.src.ip4.as_u32;
            inner_ip->dst_address.as_u32 = d->icmp.inner.dst.ip4.as_u32;
            inner_ip->checksum = 0;
            inner_ip->checksum = ip4_header_checksum(inner_ip);

            if (d->icmp.inner.l4_proto == IP_PROTOCOL_TCP) {
                tcp_header_t *th = (tcp_header_t *)cur;
                cur += 8; /* only first 8 bytes copied */
                th->src_port = clib_host_to_net_u16(d->icmp.inner.sport);
                th->dst_port = clib_host_to_net_u16(d->icmp.inner.dport);
                th->seq_number = clib_host_to_net_u32(d->icmp.inner.seq);
                th->ack_number = clib_host_to_net_u32(d->icmp.inner.ack);
            } else if (d->icmp.inner.l4_proto == IP_PROTOCOL_UDP) {
                udp_header_t *uh = (udp_header_t *)cur;
                cur += 8;
                uh->src_port = clib_host_to_net_u16(d->icmp.inner.sport);
                uh->dst_port = clib_host_to_net_u16(d->icmp.inner.dport);
                uh->length = 0;
                uh->checksum = 0; /* not fully set: only 8 bytes copied */
            } else {
                cur += 8; /* generic 8 bytes */
            }
        } else {
            /* ICMP Echo (not used in these scenarios), synthesize minimal payload */
            clib_memset_u8(cur, 0, 8);
            cur += 8;
        }

        u16 icmp_len = (u16)((u8 *)cur - (u8 *)ih);
        ip->length = clib_host_to_net_u16((u16)(sizeof(*ip) + icmp_len));
        ip4_finalize_checksums(ip);
        ih->csum = icmp_checksum((u16 *)ih, icmp_len);
    }

    b->current_data = 0;
    b->current_length = (u16)(cur - start);
    return b;
}
