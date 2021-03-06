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

#ifndef included_pnat_test_stubs_h
#define included_pnat_test_stubs_h

void os_panic(void) {}
void os_exit(int code) {}
u32 ip4_fib_table_get_index_for_sw_if_index(u32 sw_if_index) { return 0; }
#include <vpp/stats/stat_segment.h>
clib_error_t *stat_segment_register_gauge(u8 *names,
                                          stat_segment_update_fn update_fn,
                                          u32 index) {
    return 0;
};
#include <vnet/feature/feature.h>
vnet_feature_main_t feature_main;
void classify_get_trace_chain(void){};

/* Format an IP4 address. */
u8 *format_ip4_address(u8 *s, va_list *args) {
    u8 *a = va_arg(*args, u8 *);
    return format(s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 *format_pnat_5tuple(u8 *s, va_list *args) { return 0; }

vl_counter_t pnat_error_counters[10];

int ip4_sv_reass_enable_disable_with_refcnt(u32 sw_if_index, int is_enable) {
    return 0;
}
int ip4_sv_reass_output_enable_disable_with_refcnt(u32 sw_if_index,
                                                   int is_enable) {
    return 0;
}
int vnet_feature_enable_disable(const char *arc_name, const char *node_name,
                                u32 sw_if_index, int enable_disable,
                                void *feature_config,
                                u32 n_feature_config_bytes) {
    return 0;
}
vnet_main_t *vnet_get_main(void) { return 0; }

vlib_main_t **vlib_mains = 0;

/* Compute TCP/UDP/ICMP4 checksum in software. */
u16 ip4_tcp_udp_compute_checksum(vlib_main_t *vm, vlib_buffer_t *p0,
                                 ip4_header_t *ip0) {
    ip_csum_t sum0;
    u32 ip_header_length, payload_length_host_byte_order;

    /* Initialize checksum with ip header. */
    ip_header_length = ip4_header_bytes(ip0);
    payload_length_host_byte_order =
        clib_net_to_host_u16(ip0->length) - ip_header_length;
    sum0 = clib_host_to_net_u32(payload_length_host_byte_order +
                                (ip0->protocol << 16));

    if (BITS(uword) == 32) {
        sum0 = ip_csum_with_carry(sum0,
                                  clib_mem_unaligned(&ip0->src_address, u32));
        sum0 = ip_csum_with_carry(sum0,
                                  clib_mem_unaligned(&ip0->dst_address, u32));
    } else
        sum0 = ip_csum_with_carry(sum0,
                                  clib_mem_unaligned(&ip0->src_address, u64));
    return ip_calculate_l4_checksum(vm, p0, sum0,
                                    payload_length_host_byte_order, (u8 *)ip0,
                                    ip_header_length, NULL);
}

u32 ip4_tcp_udp_validate_checksum(vlib_main_t *vm, vlib_buffer_t *p0) {
    ip4_header_t *ip0 = vlib_buffer_get_current(p0);
    udp_header_t *udp0;
    u16 sum16;

    ASSERT(ip0->protocol == IP_PROTOCOL_TCP ||
           ip0->protocol == IP_PROTOCOL_UDP);

    udp0 = (void *)(ip0 + 1);
    if (ip0->protocol == IP_PROTOCOL_UDP && udp0->checksum == 0) {
        p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
                      VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
        return p0->flags;
    }

    sum16 = ip4_tcp_udp_compute_checksum(vm, p0, ip0);

    p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
                  ((sum16 == 0) << VNET_BUFFER_F_LOG2_L4_CHECKSUM_CORRECT));

    return p0->flags;
}
u8 *format_tcp_header(u8 *s, va_list *args) {
    tcp_header_t *tcp = va_arg(*args, tcp_header_t *);
    u32 max_header_bytes = va_arg(*args, u32);
    u32 header_bytes;
    u32 indent;

    /* Nothing to do. */
    if (max_header_bytes < sizeof(tcp[0]))
        return format(s, "TCP header truncated");

    indent = format_get_indent(s);
    indent += 2;
    header_bytes = tcp_header_bytes(tcp);

    s = format(s, "TCP: %d -> %d", clib_net_to_host_u16(tcp->src),
               clib_net_to_host_u16(tcp->dst));

    s = format(s, "\n%Useq. 0x%08x ack 0x%08x", format_white_space, indent,
               clib_net_to_host_u32(tcp->seq_number),
               clib_net_to_host_u32(tcp->ack_number));

    s = format(s, "\n%Utcp header: %d bytes", format_white_space, indent,
               tcp->flags, header_bytes);

    s = format(s, "\n%Uwindow %d, checksum 0x%04x", format_white_space, indent,
               clib_net_to_host_u16(tcp->window),
               clib_net_to_host_u16(tcp->checksum));
    return s;
}

/* Format an IP4 header. */
u8 *format_ip4_header(u8 *s, va_list *args) {
    ip4_header_t *ip = va_arg(*args, ip4_header_t *);
    u32 max_header_bytes = va_arg(*args, u32);
    u32 ip_version, header_bytes;
    u32 indent;

    /* Nothing to do. */
    if (max_header_bytes < sizeof(ip[0]))
        return format(s, "IP header truncated");

    indent = format_get_indent(s);
    indent += 2;

    ip_version = (ip->ip_version_and_header_length >> 4);
    header_bytes = (ip->ip_version_and_header_length & 0xf) * sizeof(u32);

    s = format(s, "%d: %U -> %U", ip->protocol, format_ip4_address,
               ip->src_address.data, format_ip4_address, ip->dst_address.data);

    /* Show IP version and header length only with unexpected values. */
    if (ip_version != 4 || header_bytes != sizeof(ip4_header_t))
        s = format(s, "\n%Uversion %d, header length %d", format_white_space,
                   indent, ip_version, header_bytes);

    s = format(s, "\n%Utos 0x%02x, ttl %d, length %d, checksum 0x%04x",
               format_white_space, indent, ip->tos, ip->ttl,
               clib_net_to_host_u16(ip->length),
               clib_net_to_host_u16(ip->checksum));

    /* Check and report invalid checksums. */
    {
        if (!ip4_header_checksum_is_valid(ip))
            s = format(s, " (should be 0x%04x)",
                       clib_net_to_host_u16(ip4_header_checksum(ip)));
    }

    {
        u32 f = clib_net_to_host_u16(ip->flags_and_fragment_offset);
        u32 o;

        s = format(s, "\n%Ufragment id 0x%04x", format_white_space, indent,
                   clib_net_to_host_u16(ip->fragment_id));

        /* Fragment offset. */
        o = 8 * (f & 0x1fff);
        f ^= f & 0x1fff;
        if (o != 0)
            s = format(s, " offset %d", o);

        if (f != 0) {
            s = format(s, ", flags ");
#define _(l)                                                                   \
    if (f & IP4_HEADER_FLAG_##l)                                               \
        s = format(s, #l);
            _(MORE_FRAGMENTS);
            _(DONT_FRAGMENT);
            _(CONGESTION);
#undef _
        }
        /* Fragment packet but not the first. */
        if (o != 0)
            return s;
    }

    return s;
}

#endif
