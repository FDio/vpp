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
#include <pnat/pnat.api_enum.h> /* For error counters */
#include <arpa/inet.h>
#include "pnat_test_stubs.h"

/*
** Buffer management in test setup
** Allocate buffers return vector of buffer indicies.
**
** Setup frame with buffers when calling function.
** Global vector of all buffers with their indicies?
** Convert buffer index to pointer?
*/
struct buffers {
    u8 data[2048];
};
struct buffers buffers[256];
struct buffers expected[256];
u32 *buffers_vector = 0;

static u32 *buffer_init(u32 *vector, int count) {
    int i;
    for (i = 0; i < count; i++) {
        vec_add1(vector, i);
    }
    return vector;
}
#define PNAT_TEST_DEBUG 0

u32 *results_bi = 0; /* global vector of result buffers */
u16 *results_next = 0;
vlib_node_runtime_t *node;

#define log_info(M, ...)                                                       \
    fprintf(stderr, "\033[32;1m[OK] " M "\033[0m\n", ##__VA_ARGS__)
#define log_error(M, ...)                                                      \
    fprintf(stderr, "\033[31;1m[ERROR] (%s:%d:) " M "\033[0m\n", __FILE__,     \
            __LINE__, ##__VA_ARGS__)
#define test_assert(A, M, ...)                                                 \
    if (!(A)) {                                                                \
        log_error(M, ##__VA_ARGS__);                                           \
        assert(A);                                                             \
    } else {                                                                   \
        log_info(M, ##__VA_ARGS__);                                            \
    }

/*
 * Always return the frame of generated packets
 */
#define vlib_frame_vector_args test_vlib_frame_vector_args
void *test_vlib_frame_vector_args(vlib_frame_t *f) { return buffers_vector; }

/* Synthetic value for vnet_feature_next  */
#define NEXT_PASSTHROUGH 4242

#define vnet_feature_next_u16 test_vnet_feature_next_u16
void vnet_feature_next_u16(u16 *next0, vlib_buffer_t *b0) {
    *next0 = NEXT_PASSTHROUGH;
}

/* Gather output packets */
#define vlib_buffer_enqueue_to_next test_vlib_buffer_enqueue_to_next
void test_vlib_buffer_enqueue_to_next(vlib_main_t *vm,
                                      vlib_node_runtime_t *node, u32 *buffers,
                                      u16 *nexts, uword count) {
    vec_add(results_next, nexts, count);
    vec_add(results_bi, buffers, count);
}

pnat_trace_t trace = {0};
#define vlib_add_trace test_vlib_add_trace
void *test_vlib_add_trace(vlib_main_t *vm, vlib_node_runtime_t *r,
                          vlib_buffer_t *b, u32 n_data_bytes) {
    return &trace;
}

#define vlib_get_buffers test_vlib_get_buffers
void test_vlib_get_buffers(vlib_main_t *vm, u32 *bi, vlib_buffer_t **b,
                           int count) {
    int i;
    for (i = 0; i < count; i++) {
        b[i] = (vlib_buffer_t *)&buffers[bi[i]];
    }
}

vlib_buffer_t *test_vlib_get_buffer(u32 bi) {
    return (vlib_buffer_t *)&buffers[bi];
}

/* Must be included here to allow the above functions to override */
#include "pnat_node.h"

/*** TESTS ***/

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
        .rewrite = {.dst = "1.2.3.4", .sport = 53, .dport = 8000},
        .in = true,
    },
    {
        .match = {.dst = "2.2.2.2", .proto = 6, .dport = 6873},
        .rewrite = {.dst = "1.2.3.4", .sport = 53, .dport = 8000},
        .in = true,
    },
};

static int fill_packets(vlib_main_t *vm, vlib_buffer_t *b,
                        test_5tuple_t *test) {
    b->flags |= VLIB_BUFFER_IS_TRACED;

    ip4_header_t *ip = (ip4_header_t *)vlib_buffer_get_current(b);
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
        vnet_buffer(b)->ip.reass.l4_src_port = udp->src_port;
        vnet_buffer(b)->ip.reass.l4_dst_port = udp->dst_port;
        b->current_length = 28;
        ip->length = htons(b->current_length);
        ip->checksum = ip4_header_checksum(ip);
        udp->checksum = ip4_tcp_udp_compute_checksum(vm, b, ip);
    } else if (test->proto == IP_PROTOCOL_TCP) {
        tcp_header_t *tcp = ip4_next_header(ip);
        memset(tcp, 0, sizeof(*tcp));
        tcp->dst_port = htons(test->dport);
        tcp->src_port = htons(test->sport);
        vnet_buffer(b)->ip.reass.l4_src_port = tcp->src_port;
        vnet_buffer(b)->ip.reass.l4_dst_port = tcp->dst_port;
        b->current_length = sizeof(ip4_header_t) + sizeof(tcp_header_t);
        ip->length = htons(b->current_length);
        ip->checksum = ip4_header_checksum(ip);
        tcp->checksum = ip4_tcp_udp_compute_checksum(vm, b, ip);
    } else {
        b->current_length = sizeof(ip4_header_t);
        ip->length = htons(b->current_length);
        ip->checksum = ip4_header_checksum(ip);
        vnet_buffer(b)->ip.reass.l4_src_port = 0;
        vnet_buffer(b)->ip.reass.l4_dst_port = 0;
    }

    return 0;
}

static void ruleto5tuple(test_5tuple_t *r, pnat_5tuple_t *t) {
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

static void add_translation(rule_t *r) {
    pnat_5tuple_t match = {0};
    pnat_5tuple_t rewrite = {0};

    ruleto5tuple(&r->match, &match);
    ruleto5tuple(&r->rewrite, &rewrite);

    int rv = pnat_binding_add(&match, &rewrite, &r->index);
    assert(rv == 0);

    rv = pnat_binding_attach(0, PNAT_IP4_INPUT, r->index);
    assert(rv == 0);
}

static void del_translation(rule_t *r) {
    int rv = pnat_binding_detach(0, PNAT_IP4_INPUT, r->index);
    assert(rv == 0);

    rv = pnat_binding_del(r->index);
    assert(rv == 0);
}

static void validate_packet(vlib_main_t *vm, char *name, u32 bi,
                            vlib_buffer_t *expected_b) {
    vlib_buffer_t *b = test_vlib_get_buffer(bi);
    assert(b);

    ip4_header_t *ip = (ip4_header_t *)vlib_buffer_get_current(b);
    ip4_header_t *expected_ip =
        (ip4_header_t *)vlib_buffer_get_current(expected_b);

#if PNAT_TEST_DEBUG
    clib_warning("Received packet: %U", format_ip4_header, ip, 20);
    clib_warning("Expected packet: %U", format_ip4_header, expected_ip, 20);
    tcp_header_t *tcp = ip4_next_header(ip);
    clib_warning("IP: %U TCP: %U", format_ip4_header, ip, sizeof(*ip),
                 format_tcp_header, tcp, sizeof(*tcp));
    tcp = ip4_next_header(expected_ip);
    clib_warning("IP: %U TCP: %U", format_ip4_header, expected_ip, sizeof(*ip),
                 format_tcp_header, tcp, sizeof(*tcp));
#endif

    u32 flags = ip4_tcp_udp_validate_checksum(vm, b);
    assert((flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0);
    flags = ip4_tcp_udp_validate_checksum(vm, expected_b);
    assert((flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0);
    assert(b->current_length == expected_b->current_length);

    test_assert(memcmp(ip, expected_ip, b->current_length) == 0, "%s", name);
}

extern vlib_node_registration_t pnat_input_node;

static void test_table(test_t *t, int no_tests) {
    // walk through table of tests
    int i;
    vlib_main_t *vm = vlib_mains[0];

    /* Generate packet data */
    for (i = 0; i < no_tests; i++) {
        // create input buffer(s)
        fill_packets(vm, (vlib_buffer_t *)&buffers[i], &t[i].send);
        fill_packets(vm, (vlib_buffer_t *)&expected[i], &t[i].expect);
    }

    /* send packets through graph node */
    vlib_frame_t frame = {.n_vectors = no_tests};
    node->flags |= VLIB_NODE_FLAG_TRACE;

    pnat_node_inline(vm, node, &frame, PNAT_IP4_INPUT, VLIB_RX);

    /* verify tests */
    for (i = 0; i < no_tests; i++) {
        assert(t[i].expect_next_index == results_next[i]);
        validate_packet(vm, t[i].name, results_bi[i],
                        (vlib_buffer_t *)&expected[i]);
    }
    vec_free(results_next);
    vec_free(results_bi);
}

static void test_performance(void) {
    pnat_main_t *pm = &pnat_main;
    int i;
    vlib_main_t *vm = vlib_mains[0];

    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        add_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == sizeof(rules) / sizeof(rules[0]));

    int no_tests = sizeof(tests) / sizeof(tests[0]);
    /* Generate packet data */
    for (i = 0; i < VLIB_FRAME_SIZE; i++) {
        // create input buffer(s)
        fill_packets(vm, (vlib_buffer_t *)&buffers[i],
                     &tests[i % no_tests].send);
        // fill_packets(vm, (vlib_buffer_t *)&expected[i], &tests[i %
        // no_tests].expect);
    }

    /* send packets through graph node */
    vlib_frame_t frame = {.n_vectors = VLIB_FRAME_SIZE};
    node->flags &= ~VLIB_NODE_FLAG_TRACE;

    int j;
    for (j = 0; j < 10000; j++) {
        pnat_node_inline(vm, node, &frame, PNAT_IP4_INPUT, VLIB_RX);

#if 0
    for (i = 0; i < VLIB_FRAME_SIZE; i++) {
        assert(tests[i % no_tests].expect_next_index == results_next[i]);
        validate_packet(vm, tests[i % no_tests].name, results_bi[i], (vlib_buffer_t *)&expected[i]);
    }
#endif
        vec_free(results_next);
        vec_free(results_bi);
    }

    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        del_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == 0);
    assert(pool_elts(pm->interfaces) == 0);
}

static void test_packets(void) {
    pnat_main_t *pm = &pnat_main;
    int i;
    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        add_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == sizeof(rules) / sizeof(rules[0]));

    test_table(tests, sizeof(tests) / sizeof(tests[0]));

    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        del_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == 0);
    assert(pool_elts(pm->interfaces) == 0);
}
static void test_attach(void) {
    pnat_attachment_point_t attachment = PNAT_IP4_INPUT;
    u32 binding_index = 0;
    u32 sw_if_index = 0;
    int rv = pnat_binding_attach(sw_if_index, attachment, binding_index);
    test_assert(rv == -1, "binding_attach - nothing to attach");

    rv = pnat_binding_detach(sw_if_index, attachment, 1234);
    test_assert(rv == -1, "binding_detach - nothing to detach");

    pnat_5tuple_t match = {.mask = PNAT_SA};
    pnat_5tuple_t rewrite = {.mask = PNAT_SA};
    rv = pnat_binding_add(&match, &rewrite, &binding_index);
    assert(rv == 0);

    rv = pnat_binding_attach(sw_if_index, attachment, binding_index);
    test_assert(rv == 0, "binding_attach - rule");

    rv = pnat_binding_detach(sw_if_index, attachment, binding_index);
    test_assert(rv == 0, "binding_detach - rule");

    rv = pnat_binding_del(binding_index);
    assert(rv == 0);
}

static void test_del_before_detach(void) {
    pnat_attachment_point_t attachment = PNAT_IP4_INPUT;
    u32 binding_index = 0;
    u32 sw_if_index = 0;

    /* Ensure 5-tuple here will not duplicate with other tests cause this will
     * not be removed from flow cache */
    rule_t rule = {
        .match = {.dst = "123.123.123.123", .proto = 17, .dport = 6871},
        .rewrite = {.dst = "1.2.3.4"},
        .in = true,
    };

    add_translation(&rule);

    int rv = pnat_binding_del(binding_index);
    assert(rv == 0);

    test_t test = {
        .name = "hit missing rule",
        .send = {"1.1.1.1", "123.123.123.123", 17, 80, 6871},
        .expect = {"1.1.1.1", "123.123.123.123", 17, 80, 6871},
        .expect_next_index = PNAT_NEXT_DROP,
    };

    test_table(&test, 1);

    /* For now if you have deleted before detach, can't find key */
    rv = pnat_binding_detach(sw_if_index, attachment, binding_index);
    test_assert(rv == -1, "binding_detach - failure");

    /* Re-add the rule and try again */
    pnat_5tuple_t match = {0};
    pnat_5tuple_t rewrite = {0};
    ruleto5tuple(&rule.match, &match);
    ruleto5tuple(&rule.rewrite, &rewrite);
    rv = pnat_binding_add(&match, &rewrite, &binding_index);
    assert(rv == 0);
    rv = pnat_binding_detach(sw_if_index, attachment, binding_index);
    test_assert(rv == 0, "binding_detach - pass");
    rv = pnat_binding_del(binding_index);
    assert(rv == 0);
}

static void test_api(void) {
    test_attach();
    test_del_before_detach();
}

/*
 * Unit testing:
 * 1) Table of packets and expected outcomes. Run through
 * 2) Performance tests. Measure instructions, cache behaviour etc.
 */
clib_error_t *ip_checksum_init(vlib_main_t *vm);

int main(int argc, char **argv) {

    clib_mem_init(0, 3ULL << 30);

    vlib_main_t *vm = vlib_mains[0];

    buffers_vector = buffer_init(buffers_vector, 256);

    assert(vlib_node_main_init(vm) == 0);

    ip_checksum_init(vm);

    u32 node_index = vlib_register_node(vm, &pnat_input_node);
    node = vlib_node_get_runtime(vm, node_index);
    assert(node);

    /* Test API */
    test_api();

    test_packets();

    test_performance();
}
