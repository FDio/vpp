/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/phy/phy.h>
#include <linux/module.h>

#include "kdi_internal.h"

static int
kdi_phy_open (struct kdi_resource *resource)
{
  resource->resource.phy = of_phy_get (resource->node, resource->name);
  if (IS_ERR (resource->resource.phy))
    return PTR_ERR (resource->resource.phy);
  kdi_dbg (resource->dev, "opened PHY '%s'\n", resource->name);
  return 0;
}

static void
kdi_phy_release (struct kdi_resource *resource)
{
  if (resource->enabled)
    phy_power_off (resource->resource.phy);
  if (resource->resource.phy)
    of_phy_put (resource->resource.phy);
  kdi_dbg (resource->dev, "released PHY '%s'\n", resource->name);
}

static long
kdi_phy_ioctl (struct kdi_resource *resource, unsigned int cmd)
{
  int ret;

  mutex_lock (&resource->lock);
  switch (cmd)
    {
    case KDI_IOC_PHY_POWER_ON:
      ret = resource->enabled ? 0 : phy_power_on (resource->resource.phy);
      if (!ret)
	resource->enabled = true;
      kdi_dbg (resource->dev, "PHY power on '%s': result %d\n", resource->name, ret);
      break;
    case KDI_IOC_PHY_POWER_OFF:
      ret = resource->enabled ? phy_power_off (resource->resource.phy) : 0;
      if (!ret)
	resource->enabled = false;
      kdi_dbg (resource->dev, "PHY power off '%s': result %d\n", resource->name, ret);
      break;
    default:
      ret = -ENOTTY;
      break;
    }
  mutex_unlock (&resource->lock);
  return ret;
}

static long
kdi_phy_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  return kdi_phy_ioctl (file->private_data, cmd);
}

static int
kdi_phy_file_release (struct inode *inode, struct file *file)
{
  struct kdi_resource *resource = file->private_data;

  kdi_phy_release (resource);
  kdi_resource_put (resource);
  return 0;
}

static const struct file_operations kdi_phy_fops = {
  .owner = THIS_MODULE,
  .release = kdi_phy_file_release,
  .unlocked_ioctl = kdi_phy_file_ioctl,
  .compat_ioctl = compat_ptr_ioctl,
};

const struct kdi_resource_type kdi_phy_resource_type = {
  .open = kdi_phy_open,
  .release = kdi_phy_release,
  .fops = &kdi_phy_fops,
};
