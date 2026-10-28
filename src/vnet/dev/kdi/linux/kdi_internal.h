/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/interconnect.h>
#include <linux/mutex.h>
#include <linux/phy.h>
#include <linux/phylink.h>
#include <linux/reset.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "../kdi.h"

extern bool kdi_debug;

#define kdi_dbg(dev, fmt, ...)                                                                     \
  do                                                                                               \
    {                                                                                              \
      if (kdi_debug)                                                                               \
	dev_info (dev, fmt, ##__VA_ARGS__);                                                        \
    }                                                                                              \
  while (0)

struct kdi_resource
{
  struct device *dev;
  struct device_node *node;
  enum kdi_resource_kind type;
  char name[KDI_RESOURCE_NAME_LEN];
  __u32 arg;
  struct mutex lock;
  bool enabled;
  union
  {
    struct clk *clock;
    struct reset_control *reset;
    struct icc_path *interconnect;
    struct kdi_ethernet_phy *ethernet_phy;
    struct kdi_clock_provider *clock_provider;
  } resource;
};

struct kdi_ethernet_phy
{
  struct device *dev;
  struct net_device *netdev;
  struct phylink_config config;
  struct phylink *phylink;
  spinlock_t state_lock;
  struct kdi_ethernet_phy_state state;
  bool started;
};

/* One registered clock output. Each in-kernel consumer sees a normal
 * struct clk; every operation on it is forwarded by kdi_clock_provider to
 * whichever userspace process holds the resource open. */
struct kdi_clk
{
  struct clk_hw hw;
  struct kdi_clock_provider *provider;
  unsigned int index;
  unsigned long rate;
  bool prepared;
  /* set around a self-initiated clk_set_rate() from
   * KDI_IOC_CLOCK_PROVIDER_NOTIFY_RATE, so kdi_clk_set_rate() takes the
   * rate it was just given instead of round-tripping to userspace to
   * ask for the rate userspace itself just pushed. */
  bool self_push;
};

struct kdi_clock_provider
{
  struct kdi_resource *resource;
  struct device_node *node;
  unsigned int n_clks;
  struct kdi_clk *clks;
  struct clk_hw_onecell_data *onecell;
  wait_queue_head_t response_wq; /* a kernel clk_ops call sleeps here */
  bool request_pending;	  /* a request exists, answered or not */
  bool request_delivered;	  /* WAIT_REQUEST already returned it once */
  bool response_ready;
  struct kdi_clock_provider_request request;
  struct kdi_clock_provider_response response;
};

struct kdi_resource_type
{
  int (*open) (struct kdi_resource *resource);
  void (*release) (struct kdi_resource *resource);
  const struct file_operations *fops;
};

extern const struct kdi_resource_type kdi_clock_resource_type;
extern const struct kdi_resource_type kdi_reset_resource_type;
extern const struct kdi_resource_type kdi_interconnect_resource_type;
extern const struct kdi_resource_type kdi_ethernet_phy_resource_type;
extern const struct kdi_resource_type kdi_clock_provider_resource_type;

void kdi_resource_put (struct kdi_resource *resource);
