/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kdi_internal.h"

bool kdi_debug;
module_param_named (debug, kdi_debug, bool, 0600);
MODULE_PARM_DESC (debug, "Enable detailed KDI operation logging");

static const struct kdi_resource_type *kdi_resource_types[] = {
  [KDI_RESOURCE_CLOCK] = &kdi_clock_resource_type,
  [KDI_RESOURCE_RESET] = &kdi_reset_resource_type,
  [KDI_RESOURCE_INTERCONNECT] = &kdi_interconnect_resource_type,
  [KDI_RESOURCE_PHY] = &kdi_phy_resource_type,
};

void
kdi_resource_put (struct kdi_resource *resource)
{
  of_node_put (resource->node);
  put_device (resource->dev);
  kfree (resource);
}

static long
kdi_open_resource (unsigned long arg)
{
  struct kdi_resource_open request;
  struct kdi_resource *resource;
  struct device *dev;
  struct device_node *node;
  int ret;

  if (copy_from_user (&request, (void __user *) arg, sizeof (request)))
    return -EFAULT;
  if (!memchr (request.device_name, 0, sizeof (request.device_name)) || !request.device_name[0] ||
      !memchr (request.node_name, 0, sizeof (request.node_name)) ||
      !memchr (request.resource_name, 0, sizeof (request.resource_name)) ||
      !request.resource_name[0] || (u32) request.type >= ARRAY_SIZE (kdi_resource_types))
    return -EINVAL;
  dev = bus_find_device_by_name (&platform_bus_type, NULL, request.device_name);
  if (!dev)
    return -ENODEV;
  if (!dev->driver || strncmp (dev->driver->name, "uio", 3))
    {
      put_device (dev);
      return -EBUSY;
    }
  if (request.node_name[0])
    node = of_get_child_by_name (dev->of_node, request.node_name);
  else
    node = of_node_get (dev->of_node);
  if (!node)
    {
      put_device (dev);
      return -ENOENT;
    }
  if (request.node_name[0] && request.type == KDI_RESOURCE_INTERCONNECT)
    {
      of_node_put (node);
      put_device (dev);
      return -EOPNOTSUPP;
    }
  resource = kzalloc (sizeof (*resource), GFP_KERNEL);
  if (!resource)
    {
      of_node_put (node);
      put_device (dev);
      return -ENOMEM;
    }
  resource->dev = dev;
  resource->node = node;
  resource->type = request.type;
  strscpy (resource->name, request.resource_name, sizeof (resource->name));
  mutex_init (&resource->lock);
  ret = kdi_resource_types[resource->type]->open (resource);
  if (ret)
    {
      kdi_dbg (dev, "open device '%s' node '%pOF' resource type %u name '%s' failed: %d\n",
	       request.device_name, resource->node, request.type, request.resource_name, ret);
      of_node_put (resource->node);
      put_device (dev);
      kfree (resource);
      return ret;
    }
  ret = anon_inode_getfd ("vpp-kdi-resource", kdi_resource_types[resource->type]->fops, resource,
			  O_RDWR | O_CLOEXEC);
  if (ret < 0)
    {
      kdi_resource_types[resource->type]->release (resource);
      kdi_resource_put (resource);
      return ret;
    }
  kdi_dbg (dev, "opened device '%s' node '%pOF' resource fd %d type %u name '%s'\n",
	   request.device_name, resource->node, ret, request.type, request.resource_name);
  return ret;
}

static long
kdi_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  if (cmd != KDI_IOC_OPEN_RESOURCE)
    return -ENOTTY;
  return kdi_open_resource (arg);
}

static const struct file_operations kdi_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = kdi_ioctl,
  .compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice kdi_miscdev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = KDI_CONTROL_DEVICE_NAME,
  .fops = &kdi_fops,
  .mode = 0600,
};

module_misc_device (kdi_miscdev);

MODULE_DESCRIPTION ("Generic VPP device kernel interface");
MODULE_LICENSE ("GPL");
