/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2026 Cisco Systems, Inc.
 */
#pragma once

#include <linux/ioctl.h>
#include <linux/types.h>

#define KDI_DEVICE_NAME_LEN	64
#define KDI_RESOURCE_NAME_LEN	64
#define KDI_CONTROL_DEVICE_NAME "vpp-kdi"
#define KDI_DEVICE_PATH		"/dev/" KDI_CONTROL_DEVICE_NAME

enum kdi_resource_kind
{
  KDI_RESOURCE_CLOCK,
  KDI_RESOURCE_RESET,
  KDI_RESOURCE_INTERCONNECT,
  KDI_RESOURCE_ETHERNET_PHY,
  KDI_RESOURCE_CLOCK_PROVIDER,
};

/* Resource open */
struct kdi_resource_open
{
  enum kdi_resource_kind type;
  char device_name[KDI_DEVICE_NAME_LEN];
  char node_name[KDI_RESOURCE_NAME_LEN];
  char resource_name[KDI_RESOURCE_NAME_LEN];
  /* KDI_RESOURCE_CLOCK_PROVIDER: number of clock outputs to register for
   * the node (its #clock-cells indices 0..arg-1). Unused otherwise. */
  __u32 arg;
};

#define KDI_IOC_MAGIC	      'K'
#define KDI_IOC_OPEN_RESOURCE _IOW (KDI_IOC_MAGIC, 0, struct kdi_resource_open)

/* Clock operations */
#define KDI_IOC_CLOCK_ENABLE   _IO (KDI_IOC_MAGIC, 1)
#define KDI_IOC_CLOCK_DISABLE  _IO (KDI_IOC_MAGIC, 2)
#define KDI_IOC_CLOCK_SET_RATE _IOW (KDI_IOC_MAGIC, 3, __u64)

/* Reset operations */
#define KDI_IOC_RESET_ASSERT   _IO (KDI_IOC_MAGIC, 4)
#define KDI_IOC_RESET_DEASSERT _IO (KDI_IOC_MAGIC, 5)
#define KDI_IOC_RESET_PULSE    _IO (KDI_IOC_MAGIC, 6)

/* Interconnect operations */
struct kdi_interconnect_op
{
  __aligned_u64 average_bw;
  __aligned_u64 peak_bw;
};

#define KDI_IOC_INTERCONNECT_SET_BW _IOW (KDI_IOC_MAGIC, 7, struct kdi_interconnect_op)

/* Ethernet PHY operations */
struct kdi_ethernet_phy_state
{
  __u32 link;
  __u32 speed;
  __u32 duplex;
  __u32 autoneg;
};

#define KDI_IOC_ETHERNET_PHY_START_ANEG _IO (KDI_IOC_MAGIC, 10)
#define KDI_IOC_ETHERNET_PHY_GET_STATE	_IOR (KDI_IOC_MAGIC, 11, struct kdi_ethernet_phy_state)
#define KDI_IOC_ETHERNET_PHY_STOP	_IO (KDI_IOC_MAGIC, 12)

/* Clock provider operations: kdi registers as the Linux clk-framework
 * provider for an arbitrary device_node (one with #clock-cells) and proxies
 * every prepare/unprepare/set_rate call it receives from in-kernel consumers
 * out to whichever userspace process holds this resource open. kdi carries
 * no knowledge of what the node represents or what rate makes sense for
 * it; that logic lives entirely on the userspace side of this interface. */
enum kdi_clock_provider_op
{
  KDI_CLOCK_PROVIDER_OP_PREPARE,
  KDI_CLOCK_PROVIDER_OP_UNPREPARE,
  KDI_CLOCK_PROVIDER_OP_SET_RATE,
};

struct kdi_clock_provider_request
{
  __u32 index;	      /* which output clock, 0..n_outputs-1 */
  __u32 op;	      /* enum kdi_clock_provider_op */
  __aligned_u64 rate; /* requested rate, for KDI_CLOCK_PROVIDER_OP_SET_RATE */
};

struct kdi_clock_provider_response
{
  __s32 result;	      /* 0 or -errno */
  __aligned_u64 rate; /* rate actually set, for PREPARE/SET_RATE */
};

#define KDI_IOC_CLOCK_PROVIDER_WAIT_REQUEST                                                        \
  _IOR (KDI_IOC_MAGIC, 14, struct kdi_clock_provider_request)
#define KDI_IOC_CLOCK_PROVIDER_COMPLETE _IOW (KDI_IOC_MAGIC, 15, struct kdi_clock_provider_response)

/* Unprompted rate push: lets userspace drive the provider clock's own
 * clk_set_rate() from the kernel side, on its own initiative, instead of
 * only ever answering a consumer-initiated SET_RATE request. Some
 * consumers (e.g. a clock-rate notifier registered on this clock) only
 * react when the provider calls clk_set_rate() on itself at the point
 * its own hardware state actually changed - not when some unrelated
 * downstream consumer happens to ask for a rate. kdi still carries no
 * knowledge of why; it just forwards the push into the clk framework. */
struct kdi_clock_provider_notify_rate
{
  __u32 index; /* which output clock, 0..n_outputs-1 */
  __u32 pad;
  __aligned_u64 rate;
};

#define KDI_IOC_CLOCK_PROVIDER_NOTIFY_RATE                                                         \
  _IOW (KDI_IOC_MAGIC, 16, struct kdi_clock_provider_notify_rate)

/* DMA memory operations */
struct kdi_dma_mem_map
{
  __aligned_u64 addr;	   /* in: userspace VA to remap */
  __aligned_u64 size;	   /* in: size of the range */
  __aligned_u64 phys_addr; /* out: physical address backing addr */
};

#define KDI_IOC_MAP_DMA_MEM_UNCACHED _IOWR (KDI_IOC_MAGIC, 13, struct kdi_dma_mem_map)
