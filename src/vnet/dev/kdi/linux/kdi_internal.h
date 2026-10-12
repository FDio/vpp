/* SPDX-License-Identifier: GPL-2.0-only */

#pragma once

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/interconnect.h>
#include <linux/mutex.h>
#include <linux/phy/phy.h>
#include <linux/phy.h>
#include <linux/phylink.h>
#include <linux/reset.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

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
  struct mutex lock;
  bool enabled;
  union
  {
    struct clk *clock;
    struct reset_control *reset;
    struct icc_path *interconnect;
    struct phy *phy;
    struct kdi_ethernet_phy *ethernet_phy;
  } resource;
};

struct kdi_ethernet_phy
{
  struct phylink_config config;
  struct phylink *phylink;
  struct phylink_pcs *pcs;
  spinlock_t state_lock;
  struct kdi_ethernet_phy_state state;
  bool started;
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
extern const struct kdi_resource_type kdi_phy_resource_type;
extern const struct kdi_resource_type kdi_ethernet_phy_resource_type;

void kdi_resource_put (struct kdi_resource *resource);
