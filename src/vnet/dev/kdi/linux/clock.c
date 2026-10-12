/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/clk.h>
#include <linux/module.h>

#include "kdi_internal.h"

static int
kdi_clock_open (struct kdi_resource *resource)
{
  resource->resource.clock = clk_get (resource->dev, resource->name);
  if (IS_ERR (resource->resource.clock))
    return PTR_ERR (resource->resource.clock);
  kdi_dbg (resource->dev, "opened clock '%s' at %lu Hz\n", resource->name,
	   clk_get_rate (resource->resource.clock));
  return 0;
}

static void
kdi_clock_release (struct kdi_resource *resource)
{
  if (resource->enabled)
    clk_disable_unprepare (resource->resource.clock);
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
      if (!resource->enabled)
	{
	  ret = clk_prepare_enable (resource->resource.clock);
	  if (!ret)
	    resource->enabled = true;
	}
      kdi_dbg (resource->dev, "clock enable '%s': result %d\n", resource->name, ret);
      mutex_unlock (&resource->lock);
      return ret;
    case KDI_IOC_CLOCK_DISABLE:
      mutex_lock (&resource->lock);
      if (resource->enabled)
	{
	  clk_disable_unprepare (resource->resource.clock);
	  resource->enabled = false;
	}
      kdi_dbg (resource->dev, "clock disable '%s': result %d\n", resource->name, ret);
      mutex_unlock (&resource->lock);
      return ret;
    case KDI_IOC_CLOCK_SET_RATE:
      if (copy_from_user (&rate, argp, sizeof (rate)))
	return -EFAULT;
      ret = clk_set_rate (resource->resource.clock, rate);
      kdi_dbg (resource->dev, "clock set rate '%s' to %llu Hz: result %d\n", resource->name, rate,
	       ret);
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
