#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vppinfra/time.h>
#include "ipv4_5tuple.h"

#define BENCH_ITERATIONS        1000000
#define BENCH_WARMUP_ITERATIONS 1000

typedef struct {
    u8 packet_data[128]; // Buffer for packet data
    vlib_buffer_t buffer;
} bench_packet_t;

static void
init_bench_packet(bench_packet_t *pkt, u8 protocol, u8 is_icmp_error) {
    ip4_header_t *ip;
    udp_header_t *udp;
    icmp46_header_t *icmp;
    icmp_echo_header_t *echo;
    ip4_header_t *inner_ip;
    udp_header_t *inner_udp;

    // Initialize buffer
    clib_memset(pkt, 0, sizeof(*pkt));
    pkt->buffer.data = pkt->packet_data;
    pkt->buffer.current_data = pkt->packet_data;
    pkt->buffer.total_length_not_including_first_buffer = 0;
    pkt->buffer.current_length = 128;

    // Setup IP header
    ip = (ip4_header_t *)pkt->packet_data;
    ip->ip_version_and_header_length = 0x45;
    ip->protocol = protocol;
    ip->src_address.as_u32 = 0x0a000001; // 10.0.0.1
    ip->dst_address.as_u32 = 0x0a000002; // 10.0.0.2

    if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP) {
        udp = (udp_header_t *)(ip + 1);
        udp->src_port = clib_host_to_net_u16(12345);
        udp->dst_port = clib_host_to_net_u16(80);
    } else if (protocol == IP_PROTOCOL_ICMP) {
        icmp = (icmp46_header_t *)(ip + 1);
        if (is_icmp_error) {
            icmp->type = ICMP4_destination_unreachable;
            echo = (icmp_echo_header_t *)(icmp + 1);

            // Setup inner IP header
            inner_ip = (ip4_header_t *)(echo + 1);
            inner_ip->ip_version_and_header_length = 0x45;
            inner_ip->protocol = IP_PROTOCOL_UDP;
            inner_ip->src_address.as_u32 = 0x0a000003; // 10.0.0.3
            inner_ip->dst_address.as_u32 = 0x0a000004; // 10.0.0.4

            // Setup inner UDP header
            inner_udp = (udp_header_t *)(inner_ip + 1);
            inner_udp->src_port = clib_host_to_net_u16(54321);
            inner_udp->dst_port = clib_host_to_net_u16(443);
        } else {
            icmp->type = ICMP4_echo_request;
            echo = (icmp_echo_header_t *)(icmp + 1);
            echo->identifier = clib_host_to_net_u16(12345);
        }
    }
}

static void
run_benchmark(void) {
    bench_packet_t pkt;
    ipv4_5tuple_t tuple;
    f64 start_time, end_time;
    u32 i;
    f64 total_time = 0;
    f64 min_time = 1e9;
    f64 max_time = 0;

    // Warmup
    for (i = 0; i < BENCH_WARMUP_ITERATIONS; i++) {
        init_bench_packet(&pkt, IP_PROTOCOL_UDP, 0);
        extract_ipv4_5tuple(&pkt.buffer, tuple);
    }

    // Benchmark UDP packets
    clib_warning("Benchmarking UDP packets...");
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        init_bench_packet(&pkt, IP_PROTOCOL_UDP, 0);
        start_time = vlib_time_now(vlib_get_main());
        extract_ipv4_5tuple(&pkt.buffer, tuple);
        end_time = vlib_time_now(vlib_get_main());

        f64 iter_time = (end_time - start_time) * 1e9; // Convert to nanoseconds
        total_time += iter_time;
        min_time = clib_min(min_time, iter_time);
        max_time = clib_max(max_time, iter_time);
    }

    clib_warning("UDP Results:");
    clib_warning("  Avg time: %.2f ns", total_time / BENCH_ITERATIONS);
    clib_warning("  Min time: %.2f ns", min_time);
    clib_warning("  Max time: %.2f ns", max_time);

    // Reset stats
    total_time = 0;
    min_time = 1e9;
    max_time = 0;

    // Benchmark ICMP echo packets
    clib_warning("\nBenchmarking ICMP echo packets...");
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        init_bench_packet(&pkt, IP_PROTOCOL_ICMP, 0);
        start_time = vlib_time_now(vlib_get_main());
        extract_ipv4_5tuple(&pkt.buffer, tuple);
        end_time = vlib_time_now(vlib_get_main());

        f64 iter_time = (end_time - start_time) * 1e9;
        total_time += iter_time;
        min_time = clib_min(min_time, iter_time);
        max_time = clib_max(max_time, iter_time);
    }

    clib_warning("ICMP Echo Results:");
    clib_warning("  Avg time: %.2f ns", total_time / BENCH_ITERATIONS);
    clib_warning("  Min time: %.2f ns", min_time);
    clib_warning("  Max time: %.2f ns", max_time);

    // Reset stats
    total_time = 0;
    min_time = 1e9;
    max_time = 0;

    // Benchmark ICMP error packets
    clib_warning("\nBenchmarking ICMP error packets...");
    for (i = 0; i < BENCH_ITERATIONS; i++) {
        init_bench_packet(&pkt, IP_PROTOCOL_ICMP, 1);
        start_time = vlib_time_now(vlib_get_main());
        extract_ipv4_5tuple(&pkt.buffer, tuple);
        end_time = vlib_time_now(vlib_get_main());

        f64 iter_time = (end_time - start_time) * 1e9;
        total_time += iter_time;
        min_time = clib_min(min_time, iter_time);
        max_time = clib_max(max_time, iter_time);
    }

    clib_warning("ICMP Error Results:");
    clib_warning("  Avg time: %.2f ns", total_time / BENCH_ITERATIONS);
    clib_warning("  Min time: %.2f ns", min_time);
    clib_warning("  Max time: %.2f ns", max_time);
}

static clib_error_t *
ipv4_5tuple_bench_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    run_benchmark();
    return 0;
}

VLIB_CLI_COMMAND(ipv4_5tuple_bench_command, static) = {
    .path = "test ipv4-5tuple-bench",
    .short_help = "Run IPv4 5-tuple extraction benchmarks",
    .function = ipv4_5tuple_bench_command_fn,
};