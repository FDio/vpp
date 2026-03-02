/*
 * SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
 * Dual-licensed under GPL version 2.0 or Apache License version 2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#define XDP_METADATA_SECTION "xdp_metadata"
#define XSK_PROG_VERSION     1

#define DEFAULT_QUEUE_IDS 64

struct
{
  __uint (type, BPF_MAP_TYPE_XSKMAP);
  __uint (key_size, sizeof (int));
  __uint (value_size, sizeof (int));
  __uint (max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC (".maps");

struct
{
  __uint (priority, 10);
  __uint (XDP_PASS, 1);
} XDP_RUN_CONFIG (xdp_sock_prog_frags);

SEC ("xdp.frags")
int
xdp_sock_prog_frags (struct xdp_md *ctx)
{
  return bpf_redirect_map (&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC ("license") = "GPL";
__uint (xsk_prog_version, XSK_PROG_VERSION) SEC (XDP_METADATA_SECTION);
