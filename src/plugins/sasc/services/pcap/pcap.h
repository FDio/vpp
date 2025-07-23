// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#ifndef included_sasc_pcap_h
#define included_sasc_pcap_h

#include <vlib/vlib.h>
#include <vppinfra/pcap.h>
#include <sasc/sasc.h>

typedef struct {
    session_version_t version;
    u16 sampled_packets;
} sasc_pcap_session_data_t;

typedef struct {
    /* PCAP configuration */
    pcap_main_t pcap_main;
    sasc_pcap_session_data_t *session_data;

    /* Service state */
    bool enabled;
    char *filename;
    u32 max_packets;
    u32 packets_captured;

    /* Statistics */
    u32 packets_processed;
    u32 packets_captured_total;
    u32 bytes_captured_total;

    /* Message ID base for API */
    u16 msg_id_base;
} sasc_pcap_main_t;

extern sasc_pcap_main_t sasc_pcap_main;

#endif /* included_sasc_pcap_h */