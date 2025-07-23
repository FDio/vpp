// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#include <vlib/vlib.h>
#include "scapy.h"
#include "test.h"
#include <vnet/tcp/tcp_packet.h>
#include <sasc/session.h>
#include <sasc/sasc_funcs.h>
#include <sasc/services/tcp-check/tcp_check.h>
#include <vppinfra/pcap.h>

sasc_test_t **sasc_test_registry = 0;
u32 sasc_test_registry_size = 0;

vlib_buffer_t *
build_packet(char *packetdef, u32 *bi) {
    vlib_main_t *vm = vlib_get_main();
    ASSERT(vlib_buffer_alloc(vm, bi, 1) == 1);
    vlib_buffer_t *b = vlib_get_buffer(vm, bi[0]);
    size_t len;
    u8 *pkt = scapy_build_packet(packetdef, &len);
    ASSERT(pkt);
    clib_memcpy(b->data, pkt, len);
    b->current_length = len;
    b->total_length_not_including_first_buffer = 0;

    vnet_buffer(b)->l2_hdr_offset = 0;
    vnet_buffer(b)->l3_hdr_offset = sizeof(ethernet_header_t);
    vnet_buffer(b)->l4_hdr_offset = sizeof(ethernet_header_t) + sizeof(ip4_header_t);

    b->flags |= (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
                 VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
    vlib_buffer_advance(b, sizeof(ethernet_header_t));
    free(pkt);

    return b;
}

/* Helper function to build TCP packets with specific flags and sequence numbers */
vlib_buffer_t *
build_tcp_packet_with_flags(u32 *bi, tcp_packet_info_t *info) {
    u8 *packet_def = 0;
    u8 *flags_str = 0;
    /* Scapy expects flags in the order 'FSRPAU' */
    if (info->flags & TCP_FLAG_FIN)
        flags_str = format(flags_str, "%s", "F");
    if (info->flags & TCP_FLAG_SYN)
        flags_str = format(flags_str, "%s", "S");
    if (info->flags & TCP_FLAG_RST)
        flags_str = format(flags_str, "%s", "R");
    if (info->flags & TCP_FLAG_PSH)
        flags_str = format(flags_str, "%s", "P");
    if (info->flags & TCP_FLAG_ACK)
        flags_str = format(flags_str, "%s", "A");
    if (info->flags & TCP_FLAG_URG)
        flags_str = format(flags_str, "%s", "U");
    if (vec_len(flags_str) == 0)
        flags_str = format(flags_str, "%s", "");

    u8 *options_part = 0;
    if (info->options_str) {
        options_part = format(0, ", options=[%s]", info->options_str);
    }

    /* Build base packet definition */
    packet_def = format(
        0, "Ether()/IP(src='%U', dst='%U')/TCP(sport=%d, dport=%d, seq=%u, ack=%u, flags='%s'%s",
        format_ip4_address, &info->src_ip, format_ip4_address, &info->dst_ip, info->sport,
        info->dport, info->seq_num, info->ack_num, flags_str,
        options_part ? (char *)options_part : "");
    /* Add payload for PSH packets */
    if (info->flags & TCP_FLAG_PSH) {
        packet_def = format(packet_def, ")/Raw(load='x' * 10)");
    } else {
        packet_def = format(packet_def, ")");
    }
    vec_add1(packet_def, 0);
    vlib_buffer_t *b = build_packet((char *)packet_def, bi);
    vec_free(packet_def);
    vec_free(flags_str);
    vec_free(options_part);
    return b;
}

/* Helper function to create TCP packet info with common defaults */
void
tcp_packet_info_init(tcp_packet_info_t *pkt, u32 src_ip, u32 dst_ip, u16 sport, u16 dport,
                     u32 seq_num, u32 ack_num, u8 flags, const char *options_str) {
    pkt->src_ip.as_u32 = clib_host_to_net_u32(src_ip);
    pkt->dst_ip.as_u32 = clib_host_to_net_u32(dst_ip);
    pkt->sport = sport;
    pkt->dport = dport;
    pkt->seq_num = seq_num;
    pkt->ack_num = ack_num;
    pkt->flags = flags;
    pkt->options_str = options_str;
}

/* Helper function to verify session state */
int
verify_session_state(u32 session_id, session_verification_t *expected) {
    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session;

    if (session_id >= pool_elts(sasc->sessions)) {
        if (!expected->should_exist)
            return 0; /* Expected not to exist */
        return -1;    /* Should exist but doesn't */
    }

    session = pool_elt_at_index(sasc->sessions, session_id);
    if (!session) {
        if (!expected->should_exist)
            return 0; /* Expected not to exist */
        return -1;    /* Should exist but doesn't */
    }

    if (session->state != expected->expected_state) {
        clib_warning("Session %u state mismatch: expected %U, got %U", session_id,
                     format_sasc_session_state, expected->expected_state, format_sasc_session_state,
                     session->state);
        return -1;
    }

    return 0;
}

/* Helper function to check retransmit detection in TCP session state */
static int
verify_retransmit_detection(u32 session_id, bool expect_retransmit) {
    sasc_main_t *sasc = &sasc_main;
    sasc_tcp_check_main_t *tcm = &sasc_tcp_check_main;

    sasc_session_t *session = sasc_session_at_index(sasc, session_id);
    if (!session) {
        clib_warning("Session %u is NULL", session_id);
        return -1;
    }

    sasc_tcp_check_session_state_t *tcp_session = &tcm->state[session_id];
    bool has_retransmit_flag = tcp_session->retransmit_count[SASC_FLOW_FORWARD] > 0 ||
                               tcp_session->retransmit_count[SASC_FLOW_REVERSE] > 0;

    /* Debug: Print retransmit state */
    clib_warning("Retransmit debug - Session %u: expect=%d, forward_count=%u, reverse_count=%u",
                 session_id, expect_retransmit, tcp_session->retransmit_count[SASC_FLOW_FORWARD],
                 tcp_session->retransmit_count[SASC_FLOW_REVERSE]);

    if (expect_retransmit && !has_retransmit_flag) {
        clib_warning("Expected retransmit detection but flag not set for session %u", session_id);
        return -1;
    }

    if (!expect_retransmit && has_retransmit_flag) {
        clib_warning("Unexpected retransmit detection flag set for session %u", session_id);
        return -1;
    }

    if (expect_retransmit) {
        clib_warning("✓ Retransmit detection verified for session %u", session_id);
    } else {
        clib_warning("✓ No retransmit detection verified for session %u", session_id);
    }

    return 0;
}

/* Helper function to check reorder detection in TCP session state */
static int
verify_reorder_detection(u32 session_id, bool expect_reorder) {
    sasc_main_t *sasc = &sasc_main;
    sasc_tcp_check_main_t *tcm = &sasc_tcp_check_main;

    sasc_session_t *session = sasc_session_at_index(sasc, session_id);
    if (!session) {
        clib_warning("Session %u is NULL", session_id);
        return -1;
    }

    sasc_tcp_check_session_state_t *tcp_session = &tcm->state[session_id];
    bool has_reorder_flag = tcp_session->reorder_count[SASC_FLOW_FORWARD] > 0 ||
                            tcp_session->reorder_count[SASC_FLOW_REVERSE] > 0;

    /* Debug: Print reorder state */
    clib_warning(
        "Reorder debug - Session %u: flag=%d, expect=%d, forward_count=%u, reverse_count=%u",
        session_id, has_reorder_flag, expect_reorder, tcp_session->reorder_count[SASC_FLOW_FORWARD],
        tcp_session->reorder_count[SASC_FLOW_REVERSE]);

    if (expect_reorder && !has_reorder_flag) {
        clib_warning("Expected reorder detection but flag not set for session %u", session_id);
        return -1;
    }

    if (!expect_reorder && has_reorder_flag) {
        clib_warning("Unexpected reorder detection flag set for session %u", session_id);
        return -1;
    }

    if (expect_reorder) {
        clib_warning("✓ Reorder detection verified for session %u", session_id);
    } else {
        clib_warning("✓ No reorder detection verified for session %u", session_id);
    }

    return 0;
}

/* Comprehensive helper function for TCP packet injection and processing */
int
sasc_test_tcp_sequence(tcp_test_sequence_t *sequence) {
    vlib_main_t *vm = vlib_get_main();
    u32 *bi_array = 0;
    vlib_buffer_t **buffer_array = 0;
    int rv = 0;

    /* Allocate arrays for buffer indices and buffer pointers */
    vec_validate(bi_array, sequence->n_packets - 1);
    vec_validate(buffer_array, sequence->n_packets - 1);

    clib_warning("Running TCP test sequence: %s (%u packets)", sequence->test_name,
                 sequence->n_packets);

    /* Get the lookup node once */
    vlib_node_t *lookup_node = vlib_get_node_by_name(vm, (u8 *)"sasc-lookup-ip4");
    if (!lookup_node) {
        clib_warning("SASC lookup node not found");
        rv = -1;
        goto cleanup;
    }

    /* Process each packet in the sequence */
    for (u32 i = 0; i < sequence->n_packets; i++) {
        tcp_packet_info_t *pkt_info = &sequence->packets[i];

        /* Build the TCP packet */
        buffer_array[i] = build_tcp_packet_with_flags(&bi_array[i], pkt_info);
        if (!buffer_array[i]) {
            clib_warning("Failed to build packet %u", i);
            rv = -1;
            goto cleanup;
        }

        /* Initialize buffer for SASC processing */
        vnet_buffer(buffer_array[i])->sw_if_index[VLIB_RX] = 0;
        vnet_buffer(buffer_array[i])->sw_if_index[VLIB_TX] = 0;

        /* Set SASC buffer metadata for test */
        sasc_buffer(buffer_array[i])->tenant_index = 0; // Use tenant 0
        sasc_buffer(buffer_array[i])->context_id = 0;   // Use context 0

        /* Create frame and enqueue to SASC input node */
        vlib_frame_t *f = vlib_get_frame_to_node(vm, lookup_node->index);
        u32 *to_next = vlib_frame_vector_args(f);
        to_next[0] = bi_array[i];
        f->n_vectors = 1;
        vlib_put_frame_to_node(vm, lookup_node->index, f);

        /* Allow processing time */
        vlib_process_suspend(vm, 0.1);

        /* Check for errors */
        if (buffer_array[i]->error) {
            clib_warning("Packet %u processing failed with error", i);
            if (sequence->expect_success) {
                rv = -1;
                goto cleanup;
            }
        }
    }

    /* Verify overall test result */
    if (sequence->expect_success) {
        clib_warning("TCP test sequence '%s' completed successfully", sequence->test_name);
    } else {
        clib_warning("TCP test sequence '%s' completed as expected", sequence->test_name);
    }

cleanup:
    /* Cleanup all buffers */
    // for (u32 i = 0; i < sequence->n_packets; i++) {
    //     if (i < vec_len(bi_array) && bi_array[i] != ~0) {
    //         vlib_buffer_free_one(vm, bi_array[i]);
    //     }
    // }

    /* Free arrays */
    vec_free(bi_array);
    vec_free(buffer_array);

    return rv;
}

int
run_tcp_test(const char *name, const test_packet_template_t *pkts, int len, int (*post_fn)(void)) {
    tcp_packet_info_t packets[len];
    for (int i = 0; i < len; i++) {
        tcp_packet_info_init(&packets[i], pkts[i].src_ip, pkts[i].dst_ip, pkts[i].sport,
                             pkts[i].dport, pkts[i].seq_num, pkts[i].ack_num, pkts[i].flags,
                             pkts[i].options_str);
    }
    tcp_test_sequence_t sequence = {
        .packets = packets,
        .n_packets = len,
        .test_name = name,
        .expect_success = true,
    };
    int rv = sasc_test_tcp_sequence(&sequence);
    if (rv == 0 && post_fn && post_fn() != 0)
        rv = -1;
    return rv;
}

int
run_udp_test(const char *name, const test_packet_template_t *pkts, int len, int (*post_fn)(void)) {
    vlib_main_t *vm = vlib_get_main();
    u32 *bi_array = 0;
    vlib_buffer_t **buffer_array = 0;
    int rv = 0;

    /* Allocate arrays for buffer indices and buffer pointers */
    vec_validate(bi_array, len - 1);
    vec_validate(buffer_array, len - 1);

    clib_warning("Running UDP test: %s (%d packets)", name, len);

    /* Get the lookup node once */
    vlib_node_t *lookup_node = vlib_get_node_by_name(vm, (u8 *)"sasc-lookup-ip4");
    if (!lookup_node) {
        clib_warning("SASC lookup node not found");
        rv = -1;
        goto cleanup;
    }

    /* Process each packet in the sequence */
    for (int i = 0; i < len; i++) {
        const test_packet_template_t *pkt_info = &pkts[i];

        /* Build UDP packet definition */
        u8 *packet_def = 0;
        packet_def = format(
            0, "Ether()/IP(src='%U', dst='%U')/UDP(sport=%d, dport=%d)", format_ip4_address,
            &(ip4_address_t){.as_u32 = clib_host_to_net_u32(pkt_info->src_ip)}, format_ip4_address,
            &(ip4_address_t){.as_u32 = clib_host_to_net_u32(pkt_info->dst_ip)}, pkt_info->sport,
            pkt_info->dport);

        /* Add payload if specified */
        if (pkt_info->flags & 0x01) { /* Use a flag bit to indicate payload */
            packet_def = format(packet_def, "/Raw(load='x' * 10)");
        }
        vec_add1(packet_def, 0);

        /* Build the UDP packet */
        buffer_array[i] = build_packet((char *)packet_def, &bi_array[i]);
        if (!buffer_array[i]) {
            clib_warning("Failed to build UDP packet %d", i);
            rv = -1;
            vec_free(packet_def);
            goto cleanup;
        }

        /* Initialize buffer for SASC processing */
        vnet_buffer(buffer_array[i])->sw_if_index[VLIB_RX] = 0;
        vnet_buffer(buffer_array[i])->sw_if_index[VLIB_TX] = 0;

        /* Create frame and enqueue to lookup node */
        vlib_frame_t *f = vlib_get_frame_to_node(vm, lookup_node->index);
        u32 *to_next = vlib_frame_vector_args(f);
        to_next[0] = bi_array[i];
        f->n_vectors = 1;
        vlib_put_frame_to_node(vm, lookup_node->index, f);

        /* Allow processing time */
        vlib_process_suspend(vm, 0.1);

        /* Check for errors */
        if (buffer_array[i]->error) {
            clib_warning("UDP packet %d processing failed with error", i);
            rv = -1;
            vec_free(packet_def);
            goto cleanup;
        }

        vec_free(packet_def);
    }

    /* Verify overall test result */
    clib_warning("UDP test '%s' completed successfully", name);

cleanup:
    /* Free arrays */
    vec_free(bi_array);
    vec_free(buffer_array);

    if (rv == 0 && post_fn && post_fn() != 0)
        rv = -1;
    return rv;
}

/* Special retransmit test function that also verifies retransmit detection */
int
run_retransmit_test(const char *name, const test_packet_template_t *pkts, int len,
                    bool expect_retransmit, int (*post_fn)(void)) {
    tcp_packet_info_t packets[len];
    for (int i = 0; i < len; i++) {
        tcp_packet_info_init(&packets[i], pkts[i].src_ip, pkts[i].dst_ip, pkts[i].sport,
                             pkts[i].dport, pkts[i].seq_num, pkts[i].ack_num, pkts[i].flags,
                             pkts[i].options_str);
    }
    tcp_test_sequence_t sequence = {
        .packets = packets,
        .n_packets = len,
        .test_name = name,
        .expect_success = true,
    };
    int rv = sasc_test_tcp_sequence(&sequence);
    if (rv == 0 && post_fn && post_fn() != 0)
        rv = -1;

    /* Verify retransmit detection if test succeeded */
    if (rv == 0) {
        /* Find the session ID using sasc_lookup_session */
        sasc_main_t *sasc = &sasc_main;
        u32 session_id = ~0;

        /* Get the source port from the first packet in the test */
        u16 test_sport = pkts[0].sport;

        /* Convert session key to individual parameters for sasc_lookup_session */
        ip_address_t src_addr = {.ip = {.ip4.as_u32 = clib_host_to_net_u32(pkts[0].src_ip)},
                                 .version = AF_IP4};
        ip_address_t dst_addr = {.ip = {.ip4.as_u32 = clib_host_to_net_u32(pkts[0].dst_ip)},
                                 .version = AF_IP4};

        /* Look up the session */
        sasc_session_t *session =
            sasc_lookup_session(0, &src_addr, clib_net_to_host_u16(test_sport), IP_PROTOCOL_TCP,
                                &dst_addr, clib_net_to_host_u16(pkts[0].dport));
        if (session) {
            session_id = session - sasc->sessions;
            clib_warning("DEBUG: Found session %u using sasc_lookup_session", session_id);
        } else {
            clib_warning(
                "Could not find session for retransmit verification using sasc_lookup_session");
            return -1;
        }

        /* Verify retransmit detection */
        if (verify_retransmit_detection(session_id, expect_retransmit) != 0) {
            clib_warning("Retransmit detection verification failed for session %u", session_id);
            return -1;
        }
    }

    return rv;
}

/* Special reorder test function that also verifies reorder detection */
int
run_reorder_test(const char *name, const test_packet_template_t *pkts, int len, bool expect_reorder,
                 int (*post_fn)(void)) {
    tcp_packet_info_t packets[len];
    for (int i = 0; i < len; i++) {
        tcp_packet_info_init(&packets[i], pkts[i].src_ip, pkts[i].dst_ip, pkts[i].sport,
                             pkts[i].dport, pkts[i].seq_num, pkts[i].ack_num, pkts[i].flags,
                             pkts[i].options_str);
    }
    tcp_test_sequence_t sequence = {
        .packets = packets,
        .n_packets = len,
        .test_name = name,
        .expect_success = true,
    };
    int rv = sasc_test_tcp_sequence(&sequence);
    if (rv == 0 && post_fn && post_fn() != 0)
        rv = -1;

    /* Verify reorder detection if test succeeded */
    if (rv == 0) {
        /* Find the session ID using sasc_lookup_session */
        sasc_main_t *sasc = &sasc_main;
        u32 session_id = ~0;

        /* Get the source port from the first packet in the test */
        u16 test_sport = pkts[0].sport;

        /* Create a session key to look up the session */
        ip_address_t src_addr = {.ip = {.ip4.as_u32 = clib_host_to_net_u32(pkts[0].src_ip)},
                                 .version = AF_IP4};
        ip_address_t dst_addr = {.ip = {.ip4.as_u32 = clib_host_to_net_u32(pkts[0].dst_ip)},
                                 .version = AF_IP4};

        /* Look up the session */
        sasc_session_t *session =
            sasc_lookup_session(0, &src_addr, clib_net_to_host_u16(test_sport), IP_PROTOCOL_TCP,
                                &dst_addr, clib_net_to_host_u16(pkts[0].dport));
        if (session) {
            session_id = session - sasc->sessions;
            clib_warning("DEBUG: Found session %u using sasc_lookup_session", session_id);
        } else {
            clib_warning(
                "Could not find session for reorder verification using sasc_lookup_session");
            return -1;
        }

        /* Verify reorder detection */
        if (verify_reorder_detection(session_id, expect_reorder) != 0) {
            clib_warning("Reorder detection verification failed for session %u", session_id);
            return -1;
        }
    }

    return rv;
}

int
run_icmp_test(const char *name, const test_packet_template_t *pkts, int len, int (*post_fn)(void)) {
    vlib_main_t *vm = vlib_get_main();
    u32 *bi_array = 0;
    vlib_buffer_t **buffer_array = 0;
    int rv = 0;

    /* Allocate arrays for buffer indices and buffer pointers */
    vec_validate(bi_array, len - 1);
    vec_validate(buffer_array, len - 1);

    clib_warning("Running ICMP test: %s (%d packets)", name, len);

    /* Get the lookup node once */
    vlib_node_t *lookup_node = vlib_get_node_by_name(vm, (u8 *)"sasc-lookup-ip4");
    if (!lookup_node) {
        clib_warning("SASC lookup node not found");
        rv = -1;
        goto cleanup;
    }

    /* Process each packet in the sequence */
    for (int i = 0; i < len; i++) {
        const test_packet_template_t *pkt_info = &pkts[i];

        /* Build ICMP packet definition */
        u8 *packet_def = 0;
        u8 icmp_type = (pkt_info->flags >> 8) & 0xFF; /* ICMP type from upper byte of flags */
        u8 icmp_code = pkt_info->flags & 0xFF;        /* ICMP code from lower byte of flags */

        clib_warning(
            "Building ICMP packet %d: type=%d, code=%d, src=%U, dst=%U", i, icmp_type, icmp_code,
            format_ip4_address, &(ip4_address_t){.as_u32 = clib_host_to_net_u32(pkt_info->src_ip)},
            format_ip4_address, &(ip4_address_t){.as_u32 = clib_host_to_net_u32(pkt_info->dst_ip)});

        packet_def = format(
            0, "Ether()/IP(src='%U', dst='%U')/ICMP(type=%d, code=%d)", format_ip4_address,
            &(ip4_address_t){.as_u32 = clib_host_to_net_u32(pkt_info->src_ip)}, format_ip4_address,
            &(ip4_address_t){.as_u32 = clib_host_to_net_u32(pkt_info->dst_ip)}, icmp_type,
            icmp_code);

        /* Add appropriate payload based on ICMP type */
        if (icmp_type == 8 || icmp_type == 0) {
            /* Echo Request/Reply - add identifier and sequence */
            if (pkt_info->sport != 0 || pkt_info->dport != 0) {
                packet_def = format(packet_def, "/Raw(load='x' * 10)");
            }
        } else if (icmp_type == 3 || icmp_type == 4 || icmp_type == 5 || icmp_type == 11 ||
                   icmp_type == 12) {
            /* ICMP Error messages - include original packet as payload */
            /* This simulates the original packet that caused the error */
            packet_def = format(
                packet_def, "/Raw(load='"
                            "\\x45\\x00\\x00\\x28\\x00\\x01\\x00\\x00\\x40\\x06\\x00\\x00\\x0a\\x00"
                            "\\x00\\x01\\x0a\\x00\\x00\\x02\\x04\\xd2\\x00\\x50\\x00\\x00\\x00\\x01"
                            "\\x00\\x00\\x00\\x00\\x50\\x02\\x20\\x00\\x00\\x00\\x00\\x00')");
        }
        vec_add1(packet_def, 0);

        /* Build the ICMP packet */
        buffer_array[i] = build_packet((char *)packet_def, &bi_array[i]);
        if (!buffer_array[i]) {
            clib_warning("Failed to build ICMP packet %d", i);
            rv = -1;
            vec_free(packet_def);
            goto cleanup;
        }

        /* Initialize buffer for SASC processing */
        vnet_buffer(buffer_array[i])->sw_if_index[VLIB_RX] = 0;
        vnet_buffer(buffer_array[i])->sw_if_index[VLIB_TX] = 0;

        /* Create frame and enqueue to lookup node */
        vlib_frame_t *f = vlib_get_frame_to_node(vm, lookup_node->index);
        u32 *to_next = vlib_frame_vector_args(f);
        to_next[0] = bi_array[i];
        f->n_vectors = 1;
        vlib_put_frame_to_node(vm, lookup_node->index, f);

        /* Allow processing time */
        vlib_process_suspend(vm, 0.1);

        /* Check for errors */
        if (buffer_array[i]->error) {
            clib_warning("ICMP packet %d processing failed with error", i);
            rv = -1;
            vec_free(packet_def);
            goto cleanup;
        }

        vec_free(packet_def);
    }

    /* Verify overall test result */
    clib_warning("ICMP test '%s' completed successfully", name);

cleanup:
    /* Free arrays */
    vec_free(bi_array);
    vec_free(buffer_array);

    if (rv == 0 && post_fn && post_fn() != 0)
        rv = -1;
    return rv;
}

/* Test runner functions */
static int
sasc_run_test_by_name(const char *test_name) {
    for (u32 i = 0; i < sasc_test_registry_size; i++) {
        if (strcmp(sasc_test_registry[i]->name, test_name) == 0) {
            if (!sasc_test_registry[i]->enabled) {
                clib_warning("Test '%s' is disabled", test_name);
                return -1;
            }

            clib_warning("Running test: %s", sasc_test_registry[i]->description);
            int rv = sasc_test_registry[i]->test_fn();

            if (rv == 0 && sasc_test_registry[i]->post_fn) {
                rv = sasc_test_registry[i]->post_fn();
            }

            if (rv == 0) {
                clib_warning("✓ Test '%s' PASSED", test_name);
            } else {
                clib_warning("✗ Test '%s' FAILED", test_name);
            }

            return rv;
        }
    }

    clib_warning("Test '%s' not found in registry", test_name);
    return -1;
}

static int
sasc_run_all_tests(void) {
    int test_count = 0;
    int passed_count = 0;
    int failed_count = 0;

    clib_warning("=== Running All SASC Tests ===");

    for (u32 i = 0; i < sasc_test_registry_size; i++) {
        if (sasc_test_registry[i]->enabled) {
            test_count++;
            if (sasc_run_test_by_name(sasc_test_registry[i]->name) == 0) {
                passed_count++;
            } else {
                failed_count++;
            }
        }
    }

    clib_warning("=== Test Summary ===");
    clib_warning("Total tests run: %d", test_count);
    clib_warning("Tests passed: %d", passed_count);
    clib_warning("Tests failed: %d", failed_count);

    return (failed_count > 0) ? -1 : 0;
}

static void
sasc_list_tests(void) {
    clib_warning("=== Available SASC Tests ===");

    const char *category_names[] = {"Basic",    "TCP Lifecycle", "Retransmit", "Reorder",
                                    "Advanced", "UDP",           "ICMP"};

    for (u32 i = 0; i < sasc_test_registry_size; i++) {
        sasc_test_t *test = sasc_test_registry[i];
        clib_warning("[%s] %s: %s (%s)", category_names[test->category], test->name,
                     test->description, test->enabled ? "enabled" : "disabled");
    }
}

/* CLI command to list all tests */
static clib_error_t *
sasc_test_list_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_list_tests();
    return 0;
}

VLIB_CLI_COMMAND(sasc_test_list_command, static) = {
    .path = "test sasc list",
    .short_help = "test sasc list - List all available SASC tests",
    .function = sasc_test_list_command_fn,
};

/* CLI command to run a specific test */
static clib_error_t *
sasc_test_run_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    u8 *test_name = 0;

    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "%s", &test_name))
            ;
        else {
            err = unformat_parse_error(line_input);
            goto done;
        }
    }

    if (!test_name) {
        err = clib_error_return(0, "missing test name");
        goto done;
    }

    if (sasc_run_test_by_name((char *)test_name) != 0) {
        err = clib_error_return(0, "Test '%s' failed", test_name);
    }

done:
    unformat_free(line_input);
    vec_free(test_name);
    return err;
}

VLIB_CLI_COMMAND(sasc_test_run_command, static) = {
    .path = "test sasc run",
    .short_help = "test sasc run <test-name> - Run a specific SASC test",
    .function = sasc_test_run_command_fn,
};

static int
sasc_run_category(sasc_test_category_t category) {
    int passed_count = 0;
    int failed_count = 0;

    const char *category_names[] = {"Basic",   "TCP Lifecycle", "Retransmit",
                                    "Reorder", "Advanced",      "ICMP"};

    clib_warning("Running %s tests...", category_names[category]);

    for (u32 i = 0; i < sasc_test_registry_size; i++) {
        if (sasc_test_registry[i]->category == category && sasc_test_registry[i]->enabled) {
            if (sasc_run_test_by_name(sasc_test_registry[i]->name) == 0) {
                passed_count++;
            } else {
                failed_count++;
            }
        }
    }

    clib_warning("%s tests: %d passed, %d failed", category_names[category], passed_count,
                 failed_count);
    return (failed_count > 0) ? -1 : 0;
}

/* CLI command to run tests by category */
static clib_error_t *
sasc_test_category_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    u8 *category_name = 0;

    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "%s", &category_name))
            ;
        else {
            err = unformat_parse_error(line_input);
            goto done;
        }
    }

    if (!category_name) {
        err = clib_error_return(
            0, "missing category name (basic, tcp-lifecycle, retransmit, reorder, advanced, icmp)");
        goto done;
    }

    sasc_test_category_t category = SASC_TEST_CATEGORY_BASIC; // default
    bool category_found = false;

    if (strcmp((char *)category_name, "basic") == 0) {
        category = SASC_TEST_CATEGORY_BASIC;
        category_found = true;
    } else if (strcmp((char *)category_name, "tcp-lifecycle") == 0) {
        category = SASC_TEST_CATEGORY_TCP_LIFECYCLE;
        category_found = true;
    } else if (strcmp((char *)category_name, "retransmit") == 0) {
        category = SASC_TEST_CATEGORY_RETRANSMIT;
        category_found = true;
    } else if (strcmp((char *)category_name, "reorder") == 0) {
        category = SASC_TEST_CATEGORY_REORDER;
        category_found = true;
    } else if (strcmp((char *)category_name, "advanced") == 0) {
        category = SASC_TEST_CATEGORY_ADVANCED;
        category_found = true;
    } else if (strcmp((char *)category_name, "icmp") == 0) {
        category = SASC_TEST_CATEGORY_ICMP;
        category_found = true;
    }

    if (!category_found) {
        err = clib_error_return(
            0,
            "unknown category '%s'. Use: basic, tcp-lifecycle, retransmit, reorder, advanced, icmp",
            category_name);
        goto done;
    }

    if (sasc_run_category(category) != 0) {
        err = clib_error_return(0, "Some tests in category '%s' failed", category_name);
    }

done:
    unformat_free(line_input);
    vec_free(category_name);
    return err;
}

VLIB_CLI_COMMAND(sasc_test_category_command, static) = {
    .path = "test sasc category",
    .short_help = "test sasc category <category> - Run all tests in a category (basic, "
                  "tcp-lifecycle, retransmit, reorder, advanced, icmp)",
    .function = sasc_test_category_command_fn,
};

/* Comprehensive test runner that executes all SASC tests */
static clib_error_t *
sasc_test_all_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    if (sasc_run_all_tests() != 0) {
        return clib_error_return(0, "Some SASC tests failed");
    }
    return 0;
}

VLIB_CLI_COMMAND(sasc_test_all_command, static) = {
    .path = "test sasc all",
    .short_help = "test sasc all - Run all SASC tests",
    .function = sasc_test_all_command_fn,
};

static clib_error_t *
sasc_test_pcap_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    pcap_main_t pcap_main = {0};
    clib_error_t *err = 0;
    char *pcap_filename = 0;
    u32 rate_pps = 0; // packets per second, 0 means default
    u32 min_batch = 1, max_batch = 64;

    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "%s", &pcap_filename))
            ;
        else if (unformat(line_input, "rate %d", &rate_pps))
            ;
        else {
            err = unformat_parse_error(line_input);
            return err;
        }
    }

    pcap_main.file_name = pcap_filename;
    err = pcap_read(&pcap_main);
    if (err) {
        return err;
    }

    u32 n_packets = vec_len(pcap_main.packets_read);
    clib_warning("Packets read: %d", n_packets);

    /* Get the lookup node once */
    vlib_node_t *lookup_node = vlib_get_node_by_name(vm, (u8 *)"sasc-lookup-ip4");
    if (!lookup_node) {
        clib_warning("SASC lookup node not found");
        err = clib_error_return(0, "SASC lookup node not found");
        goto done;
    }
    f64 start_time_all = vlib_time_now(vm);

    u32 batch_start = 0;
    while (batch_start < n_packets) {
        f64 start_time = vlib_time_now(vm);
        /* Semi-random batch size between min_batch and max_batch (uniform distribution) */
        static u32 seed = 123456789;
        u32 batch_size = min_batch + (random_u32(&seed) % (max_batch - min_batch + 1));
        if (batch_size > max_batch)
            batch_size = max_batch;
        if (batch_size > (n_packets - batch_start))
            batch_size = n_packets - batch_start;
        // clib_warning("Processing batch %u-%u (%u packets)", batch_start,
        //              batch_start + batch_size - 1, batch_size);

        /* Allocate buffers for this batch */
        u32 *bi = 0;
        vec_validate(bi, batch_size - 1);
        u32 n_buffers = vlib_buffer_alloc(vm, bi, batch_size);
        if (n_buffers != batch_size) {
            clib_warning("Failed to allocate %u buffers, got %u", batch_size, n_buffers);
            vec_free(bi);
            err = clib_error_return(0, "Buffer allocation failed");
            goto done;
        }

        /* Create frame for this batch */
        vlib_frame_t *f = vlib_get_frame_to_node(vm, lookup_node->index);
        u32 *to_next = vlib_frame_vector_args(f);
        f->n_vectors = batch_size;

        /* Process each packet in the batch */
        for (u32 i = 0; i < batch_size; i++) {
            u32 packet_idx = batch_start + i;
            vlib_buffer_t *b = vlib_get_buffer(vm, bi[i]);
            u8 *pkt = pcap_main.packets_read[packet_idx];

            /* Copy packet data */
            clib_memcpy(b->data, pkt, vec_len(pkt));
            b->current_length = vec_len(pkt);
            b->total_length_not_including_first_buffer = 0;

            /* Set up buffer metadata for IP4 processing */
            vnet_buffer(b)->sw_if_index[VLIB_RX] = 0;
            vnet_buffer(b)->sw_if_index[VLIB_TX] = 0;
            vnet_buffer(b)->l2_hdr_offset = 0;
            vnet_buffer(b)->l3_hdr_offset = sizeof(ethernet_header_t);
            vnet_buffer(b)->l4_hdr_offset = sizeof(ethernet_header_t) + sizeof(ip4_header_t);

            b->flags |= (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
                         VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID);

            /* Advance buffer past ethernet header */
            vlib_buffer_advance(b, sizeof(ethernet_header_t));

            /* Add to frame */
            to_next[i] = bi[i];
        }

        /* Send frame to lookup node */
        vlib_put_frame_to_node(vm, lookup_node->index, f);

        /* Always yield to the scheduler at least once */
        vlib_process_suspend(vm, 0);
        /* Free buffer indices for this batch */
        vec_free(bi);

        f64 end_time = vlib_time_now(vm);
        f64 processing_time = end_time - start_time;
        f64 delay = 0.1; // default
        if (rate_pps > 0) {
            delay = (f64)batch_size / rate_pps;
        }
        f64 sleep_time = delay - processing_time;

        if (sleep_time > 0)
            vlib_process_suspend(vm, sleep_time);

        batch_start += batch_size;
    }
    f64 end_time_all = vlib_time_now(vm);
    f64 processing_time_all = end_time_all - start_time_all;
    clib_warning(
        "PCAP processing completed: %u packets processed in %f seconds. Achieved rate: %f pps",
        n_packets, processing_time_all, (f64)n_packets / processing_time_all);

done:
    unformat_free(line_input);
    vec_free(pcap_filename);
    return err;
}
VLIB_CLI_COMMAND(sasc_test_pcap_command, static) = {
    .path = "test sasc pcap",
    .short_help = "test sasc pcap <filename> [rate <packets-per-second>] - Run SASC tests with "
                  "pcap capture at optional rate",
    .function = sasc_test_pcap_command_fn,
};