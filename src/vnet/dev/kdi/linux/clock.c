/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/module.h>

#include "kdi_internal.h"

static void
kdi_clock_log_state (struct kdi_resource *resource, const char *operation)
{
  struct clk *parent;
  unsigned long rate;
  bool enabled;

  if (IS_ERR_OR_NULL (resource->resource.clock))
    return;

  parent = clk_get_parent (resource->resource.clock);
  rate = clk_get_rate (resource->resource.clock);
  enabled = __clk_is_enabled (resource->resource.clock);

  if (parent)
    kdi_dbg (resource->dev,
	     "clock %s '%s': rate=%lu Hz, enabled=%u, KDI-owned=%u, parent='%s' at %lu Hz\n",
	     operation, resource->name, rate, enabled, resource->enabled, __clk_get_name (parent),
	     clk_get_rate (parent));
  else
    kdi_dbg (resource->dev, "clock %s '%s': rate=%lu Hz, enabled=%u, KDI-owned=%u, no parent\n",
	     operation, resource->name, rate, enabled, resource->enabled);
}

static int
kdi_clock_open (struct kdi_resource *resource)
{
  if (resource->node == resource->dev->of_node)
    resource->resource.clock = clk_get (resource->dev, resource->name);
  else
    resource->resource.clock = of_clk_get_by_name (resource->node, resource->name);
  if (IS_ERR (resource->resource.clock))
    return PTR_ERR (resource->resource.clock);
  kdi_clock_log_state (resource, "opened");
  return 0;
}

static void
kdi_clock_release (struct kdi_resource *resource)
{
  kdi_clock_log_state (resource, "release before");
  if (resource->enabled)
    {
      clk_disable_unprepare (resource->resource.clock);
      resource->enabled = false;
    }
  else if (__clk_is_enabled (resource->resource.clock))
    kdi_dbg (resource->dev,
	     "clock '%s' is enabled by the provider but not owned by this KDI handle\n",
	     resource->name);
  kdi_clock_log_state (resource, "release after");
  if (resource->resource.clock)
    clk_put (resource->resource.clock);
  kdi_dbg (resource->dev, "released clock '%s'\n", resource->name);
}

static long
kdi_clock_ioctl (struct kdi_resource *resource, unsigned int cmd, void __user *argp)
{
  __u64 rate;
  int ret = 0;

  switch (cmd)
    {
    case KDI_IOC_CLOCK_ENABLE:
      mutex_lock (&resource->lock);
      kdi_clock_log_state (resource, "enable before");
      if (!resource->enabled)
	{
	  ret = clk_prepare_enable (resource->resource.clock);
	  if (!ret)
	    resource->enabled = true;
	}
      kdi_dbg (resource->dev, "clock enable '%s': result %d\n", resource->name, ret);
      kdi_clock_log_state (resource, "enable after");
      mutex_unlock (&resource->lock);
      return ret;
    case KDI_IOC_CLOCK_DISABLE:
      mutex_lock (&resource->lock);
      kdi_clock_log_state (resource, "disable before");
      if (resource->enabled)
	{
	  clk_disable_unprepare (resource->resource.clock);
	  resource->enabled = false;
	}
      kdi_dbg (resource->dev, "clock disable '%s': result %d\n", resource->name, ret);
      kdi_clock_log_state (resource, "disable after");
      mutex_unlock (&resource->lock);
      return ret;
    case KDI_IOC_CLOCK_SET_RATE:
      if (copy_from_user (&rate, argp, sizeof (rate)))
	return -EFAULT;
      kdi_clock_log_state (resource, "set-rate before");
      ret = clk_set_rate (resource->resource.clock, rate);
      kdi_dbg (resource->dev, "clock set rate '%s' to %llu Hz: result %d\n", resource->name, rate,
	       ret);
      kdi_clock_log_state (resource, "set-rate after");
      return ret;
    default:
      return -ENOTTY;
    }
}

static long
kdi_clock_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  return kdi_clock_ioctl (file->private_data, cmd, (void __user *) arg);
}

static int
kdi_clock_file_release (struct inode *inode, struct file *file)
{
  struct kdi_resource *resource = file->private_data;

  kdi_clock_release (resource);
  kdi_resource_put (resource);
  return 0;
}

static const struct file_operations kdi_clock_fops = {
  .owner = THIS_MODULE,
  .release = kdi_clock_file_release,
  .unlocked_ioctl = kdi_clock_file_ioctl,
  .compat_ioctl = compat_ptr_ioctl,
};

const struct kdi_resource_type kdi_clock_resource_type = {
  .open = kdi_clock_open,
  .release = kdi_clock_release,
  .fops = &kdi_clock_fops,
};
