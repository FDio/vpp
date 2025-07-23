#ifndef included_ipv4_5tuple_h
#define included_ipv4_5tuple_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

// 13-byte 5-tuple as a byte array
typedef u8 ipv4_5tuple_t[13];

#if defined(__x86_64__) || defined(__i386__)
// AVX-512 optimized 5-tuple extraction
static_always_inline void
extract_ipv4_5tuple_avx512(vlib_buffer_t *b, ipv4_5tuple_t tuple) {
    ip4_header_t *ip = sasc_get_ip4_header(b);

    // Load IP header into AVX-512 register
    __m512i ip_header = _mm512_loadu_si512((__m512i *)ip);

    // Extract protocol (at offset 9)
    u8 protocol = _mm512_extract_epi8(ip_header, 9);

    // Create mask for protocol type
    __mmask16 protocol_mask = _mm512_cmpeq_epi8_mask(ip_header, _mm512_set1_epi8(protocol));

    // Extract source and destination IPs (at offsets 12 and 16)
    __m128i src_dst_ips = _mm512_extracti32x4_epi32(ip_header, 0);

    // Store IPs and protocol
    _mm_storeu_si64(tuple, src_dst_ips);                        // src_ip (4 bytes)
    _mm_storeu_si64(tuple + 4, _mm_srli_si128(src_dst_ips, 4)); // dst_ip (4 bytes)
    tuple[8] = protocol;                                        // protocol (1 byte)

    // Handle different protocols
    if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP) {
        // TCP/UDP case - extract ports
        udp_header_t *udp = (udp_header_t *)(ip + 1);
        __m128i ports = _mm_loadu_si128((__m128i *)udp);
        _mm_storeu_si32(tuple + 9, ports);                     // src_port (2 bytes)
        _mm_storeu_si32(tuple + 11, _mm_srli_si128(ports, 2)); // dst_port (2 bytes)
    } else if (protocol == IP_PROTOCOL_ICMP) {
        // ICMP case - check type and use identifier if echo request/reply
        icmp46_header_t *icmp = (icmp46_header_t *)ip4_next_header(ip);
        u8 icmp_type = icmp->type;

        if (icmp_type == ICMP4_echo_request || icmp_type == ICMP4_echo_reply) {
            icmp_echo_header_t *echo = (icmp_echo_header_t *)(icmp + 1);
            u16 identifier = echo->identifier;
            _mm_storeu_si32(tuple + 9, _mm_set1_epi16(identifier)); // both ports = identifier
        } else {
            _mm_storeu_si32(tuple + 9, _mm_setzero_si128()); // zero ports
        }
    } else {
        // Other protocols - zero ports
        _mm_storeu_si32(tuple + 9, _mm_setzero_si128());
    }
}

// Vectorized version for multiple packets
static_always_inline void
extract_ipv4_5tuple_avx512_vec4(vlib_buffer_t **b, ipv4_5tuple_t *tuples) {
    // Load 4 IP headers
    __m512i ip_headers[4];
    for (int i = 0; i < 4; i++) {
        ip_headers[i] = _mm512_loadu_si512((__m512i *)sasc_get_ip4_header(b[i]));
    }

    // Extract protocols
    u8 protocols[4];
    for (int i = 0; i < 4; i++) {
        protocols[i] = _mm512_extract_epi8(ip_headers[i], 9);
    }

    // Process each packet
    for (int i = 0; i < 4; i++) {
        // Extract source and destination IPs
        __m128i src_dst_ips = _mm512_extracti32x4_epi32(ip_headers[i], 0);

        // Store IPs and protocol
        _mm_storeu_si64(tuples[i], src_dst_ips);
        _mm_storeu_si64(tuples[i] + 4, _mm_srli_si128(src_dst_ips, 4));
        tuples[i][8] = protocols[i];

        // Handle different protocols
        if (protocols[i] == IP_PROTOCOL_TCP || protocols[i] == IP_PROTOCOL_UDP) {
            udp_header_t *udp = (udp_header_t *)(sasc_get_ip4_header(b[i]) + 1);
            __m128i ports = _mm_loadu_si128((__m128i *)udp);
            _mm_storeu_si32(tuples[i] + 9, ports);
            _mm_storeu_si32(tuples[i] + 11, _mm_srli_si128(ports, 2));
        } else if (protocols[i] == IP_PROTOCOL_ICMP) {
            icmp46_header_t *icmp = (icmp46_header_t *)ip4_next_header(sasc_get_ip4_header(b[i]));
            if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
                icmp_echo_header_t *echo = (icmp_echo_header_t *)(icmp + 1);
                u16 identifier = echo->identifier;
                _mm_storeu_si32(tuples[i] + 9, _mm_set1_epi16(identifier));
            } else {
                _mm_storeu_si32(tuples[i] + 9, _mm_setzero_si128());
            }
        } else {
            _mm_storeu_si32(tuples[i] + 9, _mm_setzero_si128());
        }
    }
}

#elif defined(__aarch64__)
// ARM NEON optimized 5-tuple extraction
static_always_inline void
extract_ipv4_5tuple_neon(vlib_buffer_t *b, ipv4_5tuple_t tuple) {
    ip4_header_t *ip = sasc_get_ip4_header(b);

    // Load IP header into NEON register
    uint8x16_t ip_header = vld1q_u8((uint8_t *)ip);

    // Extract protocol (at offset 9)
    u8 protocol = vgetq_lane_u8(ip_header, 9);

    // Extract source and destination IPs (at offsets 12 and 16)
    uint32x2_t src_dst_ips = vget_low_u32(vreinterpretq_u32_u8(ip_header));

    // Store IPs and protocol
    vst1_lane_u32((uint32_t *)tuple, vreinterpret_u32_u8(vreinterpret_u8_u32(src_dst_ips)),
                  0); // src_ip
    vst1_lane_u32((uint32_t *)(tuple + 4), vreinterpret_u32_u8(vreinterpret_u8_u32(src_dst_ips)),
                  1); // dst_ip
    tuple[8] = protocol;

    // Handle different protocols
    if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP) {
        // TCP/UDP case - extract ports
        udp_header_t *udp = (udp_header_t *)(ip + 1);
        uint16x4_t ports = vld1_u16((uint16_t *)udp);
        vst1_lane_u16((uint16_t *)(tuple + 9), ports, 0);  // src_port
        vst1_lane_u16((uint16_t *)(tuple + 11), ports, 1); // dst_port
    } else if (protocol == IP_PROTOCOL_ICMP) {
        // ICMP case - check type and use identifier if echo request/reply
        icmp46_header_t *icmp = (icmp46_header_t *)ip4_next_header(ip);
        u8 icmp_type = icmp->type;

        if (icmp_type == ICMP4_echo_request || icmp_type == ICMP4_echo_reply) {
            icmp_echo_header_t *echo = (icmp_echo_header_t *)(icmp + 1);
            u16 identifier = echo->identifier;
            uint16x4_t id_vec = vdup_n_u16(identifier);
            vst1_u16((uint16_t *)(tuple + 9), id_vec); // both ports = identifier
        } else {
            vst1_u16((uint16_t *)(tuple + 9), vdup_n_u16(0)); // zero ports
        }
    } else {
        // Other protocols - zero ports
        vst1_u16((uint16_t *)(tuple + 9), vdup_n_u16(0));
    }
}
#endif

// Runtime detection and fallback
static_always_inline void
extract_ipv4_5tuple(vlib_buffer_t *b, ipv4_5tuple_t tuple) {
#if defined(__x86_64__) || defined(__i386__)
    if (clib_cpu_supports_avx512()) {
        extract_ipv4_5tuple_avx512(b, tuple);
    } else {
#elif defined(__aarch64__)
    if (clib_cpu_supports_neon()) {
        extract_ipv4_5tuple_neon(b, tuple);
    } else {
#endif
        // Fallback to scalar version
        ip4_header_t *ip = sasc_get_ip4_header(b);
        u8 protocol = ip->protocol;

        // Copy IPs
        clib_memcpy_fast(tuple, &ip->src_address, 4);
        clib_memcpy_fast(tuple + 4, &ip->dst_address, 4);
        tuple[8] = protocol;

        // Handle ports based on protocol
        if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP) {
            udp_header_t *udp = (udp_header_t *)(ip + 1);
            clib_memcpy_fast(tuple + 9, &udp->src_port, 2);
            clib_memcpy_fast(tuple + 11, &udp->dst_port, 2);
        } else if (protocol == IP_PROTOCOL_ICMP) {
            icmp46_header_t *icmp = (icmp46_header_t *)ip4_next_header(ip);
            if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
                icmp_echo_header_t *echo = (icmp_echo_header_t *)(icmp + 1);
                u16 identifier = echo->identifier;
                clib_memcpy_fast(tuple + 9, &identifier, 2);
                clib_memcpy_fast(tuple + 11, &identifier, 2);
            } else {
                clib_memset(tuple + 9, 0, 4);
            }
        } else {
            clib_memset(tuple + 9, 0, 4);
        }
    }
}

#endif /* included_ipv4_5tuple_h */