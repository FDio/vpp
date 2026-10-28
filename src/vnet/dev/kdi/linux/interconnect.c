/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <linux/interconnect.h>
#include <linux/module.h>

#include "kdi_internal.h"

static int
kdi_interconnect_open (struct kdi_resource *resource)
{
  resource->resource.interconnect = of_icc_get (resource->dev, resource->name);
  if (IS_ERR (resource->resource.interconnect))
    return PTR_ERR (resource->resource.interconnect);
  kdi_dbg (resource->dev, "opened interconnect '%s'\n", resource->name);
  return 0;
}

static void
kdi_interconnect_release (struct kdi_resource *resource)
{
  if (resource->resource.interconnect)
    icc_put (resource->resource.interconnect);
  kdi_dbg (resource->dev, "released interconnect '%s'\n", resource->name);
}

static long
kdi_interconnect_ioctl (struct kdi_resource *resource, unsigned int cmd, void __user *argp)
{
  struct kdi_interconnect_op op;
  int ret;

  switch (cmd)
    {
    case KDI_IOC_INTERCONNECT_SET_BW:
      if (copy_from_user (&op, argp, sizeof (op)))
	return -EFAULT;
      ret = icc_set_bw (resource->resource.interconnect, op.average_bw, op.peak_bw);
      kdi_dbg (resource->dev,
	       "interconnect set bandwidth '%s': average %llu, peak %llu, result %d\n",
	       resource->name, op.average_bw, op.peak_bw, ret);
      return ret;
    default:
      return -ENOTTY;
    }
}

static long
kdi_interconnect_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  return kdi_interconnect_ioctl (file->private_data, cmd, (void __user *) arg);
}

static int
kdi_interconnect_file_release (struct inode *inode, struct file *file)
{
  struct kdi_resource *resource = file->private_data;

  kdi_interconnect_release (resource);
  kdi_resource_put (resource);
  return 0;
}

static const struct file_operations kdi_interconnect_fops = {
  .owner = THIS_MODULE,
  .release = kdi_interconnect_file_release,
  .unlocked_ioctl = kdi_interconnect_file_ioctl,
  .compat_ioctl = compat_ptr_ioctl,
};

const struct kdi_resource_type kdi_interconnect_resource_type = {
  .open = kdi_interconnect_open,
  .release = kdi_interconnect_release,
  .fops = &kdi_interconnect_fops,
};
