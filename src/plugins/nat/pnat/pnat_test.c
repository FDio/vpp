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

#include <stdbool.h>
#include <assert.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.c>
#include <vnet/fib/ip4_fib.h>

#include "pnat.h"
#include <pnat/pnat.api_enum.h>  /* For error counters */
#include <arpa/inet.h>

u32 *bi = 0;			/* global vector of buffers */
u32 *results_bi = 0;	/* global vector of result buffers */
u16 *results_next = 0;

/*
 * Always return the frame of generated packets
 */
#define vlib_frame_vector_args test_vlib_frame_vector_args
always_inline void *
test_vlib_frame_vector_args (vlib_frame_t * f)
{
    f->n_vectors = vec_len(bi);
    return bi;
}

/* Synthetic value for vnet_feature_next  */
#define NEXT_PASSTHROUGH 4242

#define vnet_feature_next_u16 test_vnet_feature_next_u16
static_always_inline void
vnet_feature_next_u16 (u16 * next0, vlib_buffer_t * b0)
{
  *next0 = NEXT_PASSTHROUGH;
}

/* Gather output packets */
#define vlib_buffer_enqueue_to_next test_vlib_buffer_enqueue_to_next
static_always_inline void
test_vlib_buffer_enqueue_to_next (vlib_main_t * vm, vlib_node_runtime_t * node,
                                  u32 * buffers, u16 * nexts, uword count)
{
    vec_add(results_next, nexts, count);
    vec_add(results_bi, buffers, count);
}

pnat_trace_t trace = {0};
#define vlib_add_trace test_vlib_add_trace
void *
test_vlib_add_trace (vlib_main_t * vm,
                     vlib_node_runtime_t * r, vlib_buffer_t * b, u32 n_data_bytes)
{
    return &trace;
}

#include "pnat_node.h"

/*** STUBS ***/
void os_panic (void) {}
void os_exit (int code) {}
u32 ip4_fib_table_get_index_for_sw_if_index(u32 sw_if_index) { return 0;}
#include <vpp/stats/stat_segment.h>
clib_error_t *stat_segment_register_gauge (u8 *names, stat_segment_update_fn update_fn, u32 index) { return 0;};
#include <vnet/feature/feature.h>
vnet_feature_main_t feature_main;
void classify_get_trace_chain (void) {};

/* Format an IP4 address. */
u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

u8 *format_pnat_5tuple (u8 * s, va_list * args) {return 0;}

vl_counter_t pnat_error_counters[10];

int ip4_sv_reass_enable_disable_with_refcnt (u32 sw_if_index, int is_enable) { return 0; }
int ip4_sv_reass_output_enable_disable_with_refcnt (u32 sw_if_index, int is_enable) { return 0; }
int vnet_feature_enable_disable (const char *arc_name, const char *node_name,
                                 u32 sw_if_index, int enable_disable,
                                 void *feature_config, u32 n_feature_config_bytes) { return 0; }

vlib_main_t vlib_global_main;

static struct
{
  vec_header_t h;
  vlib_main_t *vm;
} __attribute__ ((packed)) __bootstrap_vlib_main_vector
__attribute__ ((aligned (CLIB_CACHE_LINE_BYTES))) =
{
  .h.len = 1,
  .vm = &vlib_global_main,
};

vlib_main_t **vlib_mains = &__bootstrap_vlib_main_vector.vm;

/* Compute TCP/UDP/ICMP4 checksum in software. */
u16
ip4_tcp_udp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
                              ip4_header_t * ip0)
{
  ip_csum_t sum0;
  u32 ip_header_length, payload_length_host_byte_order;

  /* Initialize checksum with ip header. */
  ip_header_length = ip4_header_bytes (ip0);
  payload_length_host_byte_order = clib_net_to_host_u16 (ip0->length) - ip_header_length;
  sum0 = clib_host_to_net_u32 (payload_length_host_byte_order + (ip0->protocol << 16));

  if (BITS (uword) == 32) {
      sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->src_address, u32));
      sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->dst_address, u32));
  } else
      sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->src_address, u64));
  return ip_calculate_l4_checksum (vm, p0, sum0,
                                   payload_length_host_byte_order, (u8 *) ip0,
                                   ip_header_length, NULL);
}

u32
ip4_tcp_udp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0)
{
  ip4_header_t *ip0 = vlib_buffer_get_current (p0);
  udp_header_t *udp0;
  u16 sum16;

  ASSERT (ip0->protocol == IP_PROTOCOL_TCP
          || ip0->protocol == IP_PROTOCOL_UDP);

  udp0 = (void *) (ip0 + 1);
  if (ip0->protocol == IP_PROTOCOL_UDP && udp0->checksum == 0)
    {
      p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
                    | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
      return p0->flags;
    }

  sum16 = ip4_tcp_udp_compute_checksum (vm, p0, ip0);

  p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
                | ((sum16 == 0) << VNET_BUFFER_F_LOG2_L4_CHECKSUM_CORRECT));

  return p0->flags;
}

/*** TESTS ***/

/*
 * Test ideas:
 * Forwarding node:
 * - L3 checksum
 * - L4 checksum
 * - UDP checksum 0
 * - fragmented packet
 * - buffer shorter than UDP header
 * - IPv4 options
 * - input/output path
 * - trace
 * - rule/cache miss
 * - UDP, TCP, ICMP, other traffic
 * - dual/quad loop (At least 16 here)
 *
 * API:
 * CLI:
 * STATS:
 *
 * PERFORMANCE:
 * COVERAGE:
 *
 */


typedef struct {
    char *src;
    char *dst;
    u8 proto;
    u16 sport;
    u16 dport;
} test_5tuple_t;

typedef struct {
    char *name;
    test_5tuple_t send;
    test_5tuple_t expect;
    u32 expect_next_index;
} test_t;

test_t tests[] = {
    {
        .name = "da rewritten",
        .send = {"1.1.1.1", "2.2.2.2", 17, 80, 6871},
        .expect = {"1.1.1.1", "1.2.3.4", 17, 80, 6871},
        .expect_next_index = NEXT_PASSTHROUGH,
    },
    {
        .name = "unchanged",
        .send = {"1.1.1.1", "2.2.2.2", 17, 80, 8080},
        .expect = {"1.1.1.1", "2.2.2.2", 17, 80, 8080},
        .expect_next_index = NEXT_PASSTHROUGH,
    },
    {
        .name = "tcp da",
        .send = {"1.1.1.1", "2.2.2.2", 6, 80, 6871},
        .expect = {"1.1.1.1", "1.2.3.4", 6, 80, 6871},
        .expect_next_index = NEXT_PASSTHROUGH,
    },
    {
        .name = "tcp da ports",
        .send = {"1.1.1.1", "2.2.2.2", 6, 80, 6872},
        .expect = {"1.1.1.1", "1.2.3.4", 6, 53, 8000},
        .expect_next_index = NEXT_PASSTHROUGH,
    },
};

/* Rules */
typedef struct {
    test_5tuple_t match;
    test_5tuple_t rewrite;
    bool in;
    u32 index;
} rule_t;

rule_t rules[] = {
    {
        .match = {.dst = "2.2.2.2", .proto = 17, .dport = 6871},
        .rewrite = {.dst = "1.2.3.4"},
        .in = true,
    },
    {
        .match = {.dst = "2.2.2.2", .proto = 6, .dport = 6871},
        .rewrite = {.dst = "1.2.3.4"},
        .in = true,
    },
    {
        .match = {.dst = "2.2.2.2", .proto = 6, .dport = 6872},
        .rewrite = {.dst = "1.2.3.4", .sport=53, .dport=8000},
        .in = true,
    },
    {
        .match = {.dst = "2.2.2.2", .proto = 6, .dport = 6873},
        .rewrite = {.dst = "1.2.3.4", .sport=53, .dport=8000},
        .in = true,
    },
};

u8 *
format_tcp_header (u8 * s, va_list * args)
{
  tcp_header_t *tcp = va_arg (*args, tcp_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 header_bytes;
  u32 indent;

  /* Nothing to do. */
  if (max_header_bytes < sizeof (tcp[0]))
    return format (s, "TCP header truncated");

  indent = format_get_indent (s);
  indent += 2;
  header_bytes = tcp_header_bytes (tcp);

  s = format (s, "TCP: %d -> %d", clib_net_to_host_u16 (tcp->src),
	      clib_net_to_host_u16 (tcp->dst));

  s = format (s, "\n%Useq. 0x%08x ack 0x%08x", format_white_space, indent,
	      clib_net_to_host_u32 (tcp->seq_number),
	      clib_net_to_host_u32 (tcp->ack_number));

  s = format (s, "\n%Utcp header: %d bytes", format_white_space,
	      indent, tcp->flags, header_bytes);

  s = format (s, "\n%Uwindow %d, checksum 0x%04x", format_white_space, indent,
	      clib_net_to_host_u16 (tcp->window),
              clib_net_to_host_u16 (tcp->checksum));
  return s;
}

/* Format an IP4 header. */
u8 *
format_ip4_header (u8 * s, va_list * args)
{
    ip4_header_t *ip = va_arg (*args, ip4_header_t *);
    u32 max_header_bytes = va_arg (*args, u32);
    u32 ip_version, header_bytes;
    u32 indent;

    /* Nothing to do. */
    if (max_header_bytes < sizeof (ip[0]))
        return format (s, "IP header truncated");

    indent = format_get_indent (s);
    indent += 2;

    ip_version = (ip->ip_version_and_header_length >> 4);
    header_bytes = (ip->ip_version_and_header_length & 0xf) * sizeof (u32);

    s = format (s, "%d: %U -> %U",
                ip->protocol,
                format_ip4_address, ip->src_address.data,
                format_ip4_address, ip->dst_address.data);

    /* Show IP version and header length only with unexpected values. */
    if (ip_version != 4 || header_bytes != sizeof (ip4_header_t))
        s = format (s, "\n%Uversion %d, header length %d",
                    format_white_space, indent, ip_version, header_bytes);

    s = format (s, "\n%Utos 0x%02x, ttl %d, length %d, checksum 0x%04x",
                format_white_space, indent,
                ip->tos, ip->ttl,
                clib_net_to_host_u16 (ip->length),
                clib_net_to_host_u16 (ip->checksum));

    /* Check and report invalid checksums. */
    {
        if (!ip4_header_checksum_is_valid (ip))
            s =
                format (s, " (should be 0x%04x)",
                        clib_net_to_host_u16 (ip4_header_checksum (ip)));
    }


    {
        u32 f = clib_net_to_host_u16 (ip->flags_and_fragment_offset);
        u32 o;

        s = format (s, "\n%Ufragment id 0x%04x",
                    format_white_space, indent,
                    clib_net_to_host_u16 (ip->fragment_id));

        /* Fragment offset. */
        o = 8 * (f & 0x1fff);
        f ^= f & 0x1fff;
        if (o != 0)
            s = format (s, " offset %d", o);

        if (f != 0)
        {
            s = format (s, ", flags ");
#define _(l) if (f & IP4_HEADER_FLAG_##l) s = format (s, #l);
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

static int
fill_packets2 (vlib_main_t *vm, u32 bi, test_5tuple_t *test)
{
  vlib_buffer_t *b = vlib_get_buffer(vm, bi);
  assert(b);

  b->flags |= VLIB_BUFFER_IS_TRACED;

  ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current (b);
  memset(ip, 0, sizeof(*ip));
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 64;
  inet_pton(AF_INET, test->src, &ip->src_address.as_u32);
  inet_pton(AF_INET, test->dst, &ip->dst_address.as_u32);
  ip->protocol = test->proto;

  if (test->proto == IP_PROTOCOL_UDP) {
      udp_header_t *udp = ip4_next_header(ip);
      memset(udp, 0, sizeof(*udp));
      udp->dst_port = htons(test->dport);
      udp->src_port = htons(test->sport);
      udp->length = htons(8);
      vnet_buffer (b)->ip.reass.l4_src_port = udp->src_port;
      vnet_buffer (b)->ip.reass.l4_dst_port = udp->dst_port;
      b->current_length = 28;
      ip->length = htons(b->current_length);
      ip->checksum = ip4_header_checksum(ip);
      udp->checksum = ip4_tcp_udp_compute_checksum(vm, b, ip);
  } else if (test->proto == IP_PROTOCOL_TCP) {
      tcp_header_t *tcp = ip4_next_header(ip);
      memset(tcp, 0, sizeof(*tcp));
      tcp->dst_port = htons(test->dport);
      tcp->src_port = htons(test->sport);
      vnet_buffer (b)->ip.reass.l4_src_port = tcp->src_port;
      vnet_buffer (b)->ip.reass.l4_dst_port = tcp->dst_port;
      b->current_length = sizeof(ip4_header_t) + sizeof(tcp_header_t);
      ip->length = htons(b->current_length);
      ip->checksum = ip4_header_checksum(ip);
      tcp->checksum = ip4_tcp_udp_compute_checksum(vm, b, ip);
  } else {
      b->current_length = sizeof(ip4_header_t);
      ip->length = htons(b->current_length);
      ip->checksum = ip4_header_checksum(ip);
      vnet_buffer (b)->ip.reass.l4_src_port = 0;
      vnet_buffer (b)->ip.reass.l4_dst_port = 0;
  }
  return 0;
}

int pnat_add_translation(u32 sw_if_index, pnat_5tuple_t *match,
                         pnat_5tuple_t *rewrite, bool input, u32 *index);
int pnat_del_translation(u32 index, u32 sw_if_index);
u8 *format_pnat_translation(u8 * s, va_list * args);

static void
ruleto5tuple (test_5tuple_t *r, pnat_5tuple_t *t)
{
    if (r->src) {
        inet_pton(AF_INET, r->src, &t->src);
        t->mask |= PNAT_SA;
    }
    if (r->dst) {
        inet_pton(AF_INET, r->dst, &t->dst);
        t->mask |= PNAT_DA;
    }
    if (r->dport) {
        t->dport = r->dport;
        t->mask |= PNAT_DPORT;
    }
    if (r->sport) {
        t->sport = r->sport;
        t->mask |= PNAT_SPORT;
    }
    t->proto = r->proto;
}

static void
add_translation (rule_t *r)
{
    pnat_5tuple_t match = {0};
    pnat_5tuple_t rewrite = {0};

    ruleto5tuple(&r->match, &match);
    ruleto5tuple(&r->rewrite, &rewrite);

    int rv = pnat_add_translation(0, &match, &rewrite, r->in, &r->index);
    assert(rv == 0);
}

static void
del_translation (rule_t *r)
{
    int rv = pnat_del_translation(r->index, 0);
    assert(rv == 0);
}

#define log_info(M, ...) fprintf(stderr, "\033[32;1m[OK] " M "\033[0m\n", ##__VA_ARGS__)
#define log_error(M, ...) fprintf(stderr, "\033[31;1m[ERROR] (%s:%d:) " M "\033[0m\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define test_assert(A, M, ...) if(!(A)) {log_error(M, ##__VA_ARGS__); assert(A); } else {log_info(M, ##__VA_ARGS__);}
static void
validate_packet(vlib_main_t *vm, char *name, u32 bi, u32 expected_bi)
{
    vlib_buffer_t *b = vlib_get_buffer(vm, bi);
    assert(b);
    vlib_buffer_t *expected_b = vlib_get_buffer(vm, expected_bi);
    assert(expected_b);

    ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current (b);
    ip4_header_t *expected_ip = (ip4_header_t *) vlib_buffer_get_current (expected_b);
#if 0
    clib_warning("Received packet: %U", format_ip4_header, ip);
    clib_warning("Expected packet: %U", format_ip4_header, expected_ip);
#endif

    tcp_header_t *tcp = ip4_next_header(ip);
    clib_warning("IP: %U TCP: %U", format_ip4_header, ip, sizeof(*ip), format_tcp_header, tcp, sizeof(*tcp));

    u32 flags = ip4_tcp_udp_validate_checksum(vm, b);
    assert((flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0);
    flags = ip4_tcp_udp_validate_checksum(vm, expected_b);
    assert((flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0);
    assert(b->current_length == expected_b->current_length);
    test_assert(memcmp(ip, expected_ip, b->current_length) == 0, "%s", name);
}

extern vlib_node_registration_t pnat_input_node;

static void
test_table (vlib_main_t *vm, vlib_node_runtime_t *node)
{
    // walk through table of tests
    int i;
    int no_tests = sizeof(tests) / sizeof(test_t);

    /* Allocate send buffers */
    vec_validate(bi, no_tests-1);
    u32 n_bufs = vlib_buffer_alloc(vm, bi, no_tests);
    assert(n_bufs == no_tests);

    /* Allocate expected buffers */
    u32 *expected_bi = 0;
    vec_validate(expected_bi, no_tests-1);
    n_bufs = vlib_buffer_alloc(vm, expected_bi, no_tests);
    assert(n_bufs == no_tests);

    /* Generate packet data */
    for (i = 0; i < no_tests; i++) {
        // create input buffer(s)
        fill_packets2(vm, bi[i], &tests[i].send);
        fill_packets2(vm, expected_bi[i], &tests[i].expect);
    }

    /* send packets through graph node */
    vlib_frame_t frame = {0};
    node->flags |= VLIB_NODE_FLAG_TRACE;
    pnat_node_inline(vm, node, &frame, true);
    /* verify tests */
    for (i = 0; i < no_tests; i++) {
        assert(tests[i].expect_next_index == results_next[i]);
        validate_packet(vm, tests[i].name, results_bi[i], expected_bi[i]);
        //clib_warning("Trace: %U", format_pnat_trace, vm, node, &trace);
    }
    vlib_buffer_free(vm, bi, no_tests);
    vlib_buffer_free(vm, expected_bi, no_tests);
    vec_free(bi);
    vec_free(expected_bi);
}

/*
 * Unit testing:
 * 1) Table of packets and expected outcomes. Run through
 * 2) Performance tests. Measure instructions, cache behaviour etc.
 */
clib_error_t *ip_checksum_init (vlib_main_t * vm);

int main (int argc, char **argv)
{
    pnat_main_t *pm = &pnat_main;

    clib_mem_init (0, 3ULL << 30);

    vlib_main_t *vm = &vlib_global_main;

    assert(vlib_physmem_init(vm) == 0);
    assert(vlib_buffer_main_init(vm) == 0);

    assert(vlib_node_main_init(vm) == 0);

    ip_checksum_init(vm);

    u32 node_index = vlib_register_node(vm, &pnat_input_node);
    vlib_node_runtime_t *node = vlib_node_get_runtime (vm, node_index);
    assert(node);

    //clib_mem_trace(1);
    int i;
    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        add_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == sizeof(rules) / sizeof(rules[0]));

    test_table(vm, node);

    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        del_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == 0);
    assert(pool_elts(pm->interfaces) == 0);
}
