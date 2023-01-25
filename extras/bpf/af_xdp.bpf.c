/*
 * SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
 * Dual-licensed under GPL version 2.0 or Apache License version 2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define XDP_METADATA_SECTION "xdp_metadata"
#define XSK_PROG_VERSION     1

/*
 * when compiled, debug print can be viewed with eg.
 * sudo cat /sys/kernel/debug/tracing/trace_pipe
 */
#ifdef DEBUG
#define s__(n)   # n
#define s_(n)    s__(n)
#define x_(fmt)  __FILE__ ":" s_(__LINE__) ": " fmt "\n"
#define DEBUG_PRINT_(fmt, ...) do { \
    const char fmt__[] = fmt; \
    bpf_trace_printk(fmt__, sizeof(fmt), ## __VA_ARGS__); } while(0)
#define DEBUG_PRINT(fmt, ...)   DEBUG_PRINT_ (x_(fmt), ## __VA_ARGS__)
#else   /* DEBUG */
#define DEBUG_PRINT(fmt, ...)
#endif  /* DEBUG */

#define ntohs(x) __constant_ntohs (x)

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
} XDP_RUN_CONFIG (xdp_sock_prog);

SEC ("xdp")
int
xdp_sock_prog (struct xdp_md *ctx)
{
  const void *data = (void *) (long) ctx->data;
  const void *data_end = (void *) (long) ctx->data_end;

  DEBUG_PRINT ("rx %ld bytes packet", (long) data_end - (long) data);

  /* smallest packet we are interesting in is ip-ip */
  if (data + sizeof (struct ethhdr) + 2 * sizeof (struct iphdr) > data_end)
    {
      DEBUG_PRINT ("packet too small");
      return XDP_PASS;
    }

  const struct ethhdr *eth = data;
  if (eth->h_proto != ntohs (ETH_P_IP))
    {
      DEBUG_PRINT ("unsupported eth proto %x", (int) eth->h_proto);
      return XDP_PASS;
    }

  const struct iphdr *ip = (void *) (eth + 1);
  switch (ip->protocol)
    {
    case IPPROTO_UDP:
      {
	const struct udphdr *udp = (void *) (ip + 1);
	if (udp->dest != ntohs (4789)) /* VxLAN dest port */
	  {
	    DEBUG_PRINT ("unsupported udp dst port %x", (int) udp->dest);
	    return XDP_PASS;
	  }
      }
    case IPPROTO_IPIP:
    case IPPROTO_ESP:
      break;
    default:
      DEBUG_PRINT ("unsupported ip proto %x", (int) ip->protocol);
      return XDP_PASS;
    }

  return bpf_redirect_map (&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

/* actually Dual GPLv2/Apache2, but GPLv2 as far as kernel is concerned */
char _license[] SEC ("license") = "GPL";
__uint (xsk_prog_version, XSK_PROG_VERSION) SEC (XDP_METADATA_SECTION);
