/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <linux/reset.h>
#include <linux/module.h>

#include "kdi_internal.h"

static int
kdi_reset_open (struct kdi_resource *resource)
{
  resource->resource.reset = of_reset_control_get_exclusive (resource->node, resource->name);
  if (IS_ERR (resource->resource.reset))
    return PTR_ERR (resource->resource.reset);
  kdi_dbg (resource->dev, "opened reset '%s'\n", resource->name);
  return 0;
}

static void
kdi_reset_release (struct kdi_resource *resource)
{
  if (resource->resource.reset)
    reset_control_put (resource->resource.reset);
  kdi_dbg (resource->dev, "released reset handle '%s' without changing its state\n",
	   resource->name);
}

static long
kdi_reset_ioctl (struct kdi_resource *resource, unsigned int cmd)
{
  int ret;

  mutex_lock (&resource->lock);
  switch (cmd)
    {
    case KDI_IOC_RESET_ASSERT:
      ret = reset_control_assert (resource->resource.reset);
      kdi_dbg (resource->dev, "reset assert '%s': result %d\n", resource->name, ret);
      break;
    case KDI_IOC_RESET_DEASSERT:
      ret = reset_control_deassert (resource->resource.reset);
      kdi_dbg (resource->dev, "reset deassert '%s': result %d\n", resource->name, ret);
      break;
    case KDI_IOC_RESET_PULSE:
      ret = reset_control_reset (resource->resource.reset);
      kdi_dbg (resource->dev, "reset pulse '%s': result %d\n", resource->name, ret);
      break;
    default:
      ret = -ENOTTY;
      break;
    }
  mutex_unlock (&resource->lock);
  return ret;
}

static long
kdi_reset_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  return kdi_reset_ioctl (file->private_data, cmd);
}

static int
kdi_reset_file_release (struct inode *inode, struct file *file)
{
  struct kdi_resource *resource = file->private_data;

  kdi_reset_release (resource);
  kdi_resource_put (resource);
  return 0;
}

static const struct file_operations kdi_reset_fops = {
  .owner = THIS_MODULE,
  .release = kdi_reset_file_release,
  .unlocked_ioctl = kdi_reset_file_ioctl,
  .compat_ioctl = compat_ptr_ioctl,
};

const struct kdi_resource_type kdi_reset_resource_type = {
  .open = kdi_reset_open,
  .release = kdi_reset_release,
  .fops = &kdi_reset_fops,
};
