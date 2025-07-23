// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "sasc_test_framework.h"
#include <vnet/tcp/tcp_packet.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Convenience constructors for packet descriptions */

static inline sasc_packet_desc_t
sasc_pkt_tcp_base(sasc_5tuple_t key, u32 seq, u32 ack, u8 flags, u16 win, u16 data_len) {
    sasc_packet_desc_t d = {0};
    d.is_ip6 = 0;
    d.l4_proto = IP_PROTOCOL_TCP;
    d.src = key.src;
    d.dst = key.dst;
    d.sport = key.sport;
    d.dport = key.dport;
    d.tcp.seq = seq;
    d.tcp.ack = ack;
    d.tcp.flags = flags;
    d.tcp.win = win;
    d.tcp.data_len = data_len;
    return d;
}
static inline sasc_packet_desc_t
sasc_pkt_tcp_syn(sasc_5tuple_t key, u32 isn, u16 win, u16 mss, u8 wscale, bool sack_ok) {
    sasc_packet_desc_t d = sasc_pkt_tcp_base(key, isn, 0, TCP_FLAG_SYN, win, 0);
    d.tcp.mss_present = 1;
    d.tcp.mss = mss;
    d.tcp.wscale_present = 1;
    d.tcp.wscale = wscale;
    d.tcp.sack_ok = sack_ok;
    return d;
}
static inline sasc_packet_desc_t
sasc_pkt_icmp_unreach_port_embed_tcp(const sasc_5tuple_t *inner_key, u32 seq, u32 ack, u8 tcp_flags) {
    sasc_packet_desc_t d = {0};
    d.is_ip6 = 0;
    d.l4_proto = IP_PROTOCOL_ICMP;
    d.icmp.type = 3;
    d.icmp.code = 3; /* dest unreach: port */
    d.icmp.inner.present = 1;
    d.icmp.inner.l4_proto = IP_PROTOCOL_TCP;
    d.icmp.inner.seq = seq;
    d.icmp.inner.ack = ack;
    d.icmp.inner.tcp_flags = tcp_flags;
    d.icmp.inner.sport = inner_key->sport;
    d.icmp.inner.dport = inner_key->dport;
    d.icmp.inner.src = inner_key->src;
    d.icmp.inner.dst = inner_key->dst;
    return d;
}

/* Build vlib_buffer_t for a description */
vlib_buffer_t *sasc_pkt_build(vlib_main_t *vm, const sasc_packet_desc_t *d);

#ifdef __cplusplus
}
#endif
