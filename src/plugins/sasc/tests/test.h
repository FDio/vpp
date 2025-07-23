// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#ifndef SASC_TEST_H
#define SASC_TEST_H

#include <vlib/vlib.h>
#include <stdbool.h>
#include <sasc/sasc.h>

typedef enum {
    SASC_TEST_CATEGORY_BASIC,
    SASC_TEST_CATEGORY_TCP_LIFECYCLE,
    SASC_TEST_CATEGORY_RETRANSMIT,
    SASC_TEST_CATEGORY_REORDER,
    SASC_TEST_CATEGORY_ADVANCED,
    SASC_TEST_CATEGORY_UDP,
} sasc_test_category_t;

typedef struct {
    const char *name;              /* Test name for display */
    const char *description;       /* Test description */
    sasc_test_category_t category; /* Test category */
    int (*test_fn)(void);          /* Test function pointer */
    int (*post_fn)(void);          /* Optional post-test verification */
    bool enabled;                  /* Whether test is enabled */
    const char *expected_behavior; /* What the test is supposed to verify */
} sasc_test_t;

/* Test registry - will be populated by test registration macros */
extern sasc_test_t **sasc_test_registry;
extern u32 sasc_test_registry_size;

/* TCP Session Lifetime Test Structures */
typedef struct {
    u32 seq_num;
    u32 ack_num;
    u8 flags;
    u16 sport;
    u16 dport;
    ip4_address_t src_ip;
    ip4_address_t dst_ip;
    const char *options_str; /* Optional Scapy TCP options string */
} tcp_packet_info_t;

typedef struct {
    u32 session_id;
    u8 expected_state; /* Use u8 instead of sasc_session_state_t */
    u32 expected_flags;
    bool should_exist;
} session_verification_t;

/* Structure to define a single packet in a test sequence template */
typedef struct {
    u32 src_ip;
    u32 dst_ip;
    u16 sport;
    u16 dport;
    u32 seq_num;
    u32 ack_num;
    u8 flags;
    const char *options_str; /* Optional Scapy TCP options string */
} test_packet_template_t;

typedef struct {
    tcp_packet_info_t *packets;
    u32 n_packets;
    const char *test_name;
    bool expect_success;
} tcp_test_sequence_t;

vlib_buffer_t *
build_packet(char *packetdef, u32 *bi);
vlib_buffer_t *
build_tcp_packet_with_flags(u32 *bi, tcp_packet_info_t *info);

/* Test registration macros */
#define SASC_TEST_REGISTER(_name, _desc, _category, _test_fn, _post_fn, _behavior)                 \
    static sasc_test_t sasc_test_##_name = {.name = #_name,                                        \
                                            .description = _desc,                                  \
                                            .category = _category,                                 \
                                            .test_fn = _test_fn,                                   \
                                            .post_fn = _post_fn,                                   \
                                            .enabled = true,                                       \
                                            .expected_behavior = _behavior};                       \
    __attribute__((section("sasc_tests"))) sasc_test_t *sasc_test_##_name##_ptr =                  \
        &sasc_test_##_name;

/* Convenience macros for common test types */
#define SASC_TEST_REGISTER_TCP(name, desc, packets, post_fn)                                       \
    static int sasc_test_##name##_fn(void) {                                                       \
        return run_tcp_test(#name, packets, ARRAY_LEN(packets), post_fn);                          \
    }                                                                                              \
    SASC_TEST_REGISTER(name, desc, SASC_TEST_CATEGORY_TCP_LIFECYCLE, sasc_test_##name##_fn,        \
                       post_fn, "TCP session behavior")

#define SASC_TEST_REGISTER_RETRANSMIT(name, desc, packets, expect_retransmit, post_fn)             \
    static int sasc_test_##name##_fn(void) {                                                       \
        return run_retransmit_test(#name, packets, ARRAY_LEN(packets), expect_retransmit,          \
                                   post_fn);                                                       \
    }                                                                                              \
    SASC_TEST_REGISTER(name, desc, SASC_TEST_CATEGORY_RETRANSMIT, sasc_test_##name##_fn, post_fn,  \
                       "TCP retransmit detection")

#define SASC_TEST_REGISTER_REORDER(name, desc, packets, expect_reorder, post_fn)                   \
    static int sasc_test_##name##_fn(void) {                                                       \
        return run_reorder_test(#name, packets, ARRAY_LEN(packets), expect_reorder, post_fn);      \
    }                                                                                              \
    SASC_TEST_REGISTER(name, desc, SASC_TEST_CATEGORY_REORDER, sasc_test_##name##_fn, post_fn,     \
                       "TCP reorder detection")

#define SASC_TEST_REGISTER_BASIC(name, desc, packets, post_fn)                                     \
    static int sasc_test_##name##_fn(void) {                                                       \
        return run_tcp_test(#name, packets, ARRAY_LEN(packets), post_fn);                          \
    }                                                                                              \
    SASC_TEST_REGISTER(name, desc, SASC_TEST_CATEGORY_BASIC, sasc_test_##name##_fn, post_fn,       \
                       "Basic SASC functionality")

#define SASC_TEST_REGISTER_UDP(name, desc, packets, post_fn)                                       \
    static int sasc_test_##name##_fn(void) {                                                       \
        return run_udp_test(#name, packets, ARRAY_LEN(packets), post_fn);                          \
    }                                                                                              \
    SASC_TEST_REGISTER(name, desc, SASC_TEST_CATEGORY_UDP, sasc_test_##name##_fn, post_fn,         \
                       "UDP functionality")

int
run_tcp_test(const char *name, const test_packet_template_t *pkts, int len, int (*post_fn)(void));
int
run_retransmit_test(const char *name, const test_packet_template_t *pkts, int len,
                    bool expect_retransmit, int (*post_fn)(void));
int
run_reorder_test(const char *name, const test_packet_template_t *pkts, int len, bool expect_reorder,
                 int (*post_fn)(void));
int
run_udp_test(const char *name, const test_packet_template_t *pkts, int len, int (*post_fn)(void));

#endif // TEST_H