/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <linux/anon_inodes.h>
#include <linux/cacheflush.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pfn.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#ifdef CONFIG_ARM64
#include <asm/cache.h>
#endif

#include "kdi_internal.h"

bool kdi_debug;
module_param_named (debug, kdi_debug, bool, 0600);
MODULE_PARM_DESC (debug, "Enable detailed KDI operation logging");

static const struct kdi_resource_type *kdi_resource_types[] = {
  [KDI_RESOURCE_CLOCK] = &kdi_clock_resource_type,
  [KDI_RESOURCE_RESET] = &kdi_reset_resource_type,
  [KDI_RESOURCE_INTERCONNECT] = &kdi_interconnect_resource_type,
  [KDI_RESOURCE_ETHERNET_PHY] = &kdi_ethernet_phy_resource_type,
  [KDI_RESOURCE_CLOCK_PROVIDER] = &kdi_clock_provider_resource_type,
};

void
kdi_resource_put (struct kdi_resource *resource)
{
  of_node_put (resource->node);
  put_device (resource->dev);
  kfree (resource);
}

static struct device_node *
kdi_of_get_node_by_path (struct device_node *parent, const char *path)
{
  struct device_node *node = of_node_get (parent);
  char *path_copy, *cursor, *component;

  path_copy = kstrdup (path, GFP_KERNEL);
  if (!path_copy)
    {
      of_node_put (node);
      return NULL;
    }

  cursor = path_copy;
  while ((component = strsep (&cursor, "/")) != NULL)
    {
      struct device_node *child;

      if (!component[0] || !strcmp (component, ".") || !strcmp (component, ".."))
	{
	  of_node_put (node);
	  node = NULL;
	  break;
	}

      child = of_get_child_by_name (node, component);
      if (!child)
	for_each_child_of_node (node, child)
	{
	  const char *child_name = strrchr (child->full_name, '/');

	  child_name = child_name ? child_name + 1 : child->full_name;
	  if (!strcmp (child_name, component))
	    break;
	}
      of_node_put (node);
      node = child;
      if (!node)
	break;
    }
  kfree (path_copy);
  return node;
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
    node = kdi_of_get_node_by_path (dev->of_node, request.node_name);
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
  resource->arg = request.arg;
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

struct kdi_dma_mem
{
  struct page **pages;
  unsigned long n_pages;
};

static int
kdi_dma_mem_mmap (struct file *file, struct vm_area_struct *vma)
{
  struct kdi_dma_mem *m = file->private_data;
  unsigned long size = vma->vm_end - vma->vm_start;
  int ret;

  if (size != (m->n_pages << PAGE_SHIFT))
    return -EINVAL;

  /* This is ordinary RAM being remapped for a non-coherent DMA engine, not
   * an MMIO register window: pgprot_noncached () selects Device memory
   * (MT_DEVICE_nGnRnE), which also forbids unaligned/vector accesses.
   * pgprot_dmacoherent () selects Normal Non-cacheable (MT_NORMAL_NC),
   * which is what the DMA API itself uses for this exact purpose. */
  vma->vm_page_prot = pgprot_dmacoherent (vma->vm_page_prot);

  for (unsigned long i = 0; i < m->n_pages; i++)
    {
      ret = remap_pfn_range (vma, vma->vm_start + (i << PAGE_SHIFT), page_to_pfn (m->pages[i]),
			     PAGE_SIZE, vma->vm_page_prot);
      if (ret)
	return ret;
    }

  return 0;
}

static int
kdi_dma_mem_release (struct inode *inode, struct file *file)
{
  struct kdi_dma_mem *m = file->private_data;

  unpin_user_pages (m->pages, m->n_pages);
  kfree (m->pages);
  kfree (m);
  return 0;
}

static const struct file_operations kdi_dma_mem_fops = {
  .owner = THIS_MODULE,
  .mmap = kdi_dma_mem_mmap,
  .release = kdi_dma_mem_release,
};

static void
kdi_dma_mem_flush_page (struct page *page)
{
#ifdef CONFIG_ARM64
  unsigned long addr = (unsigned long) page_address (page);
  unsigned long end = addr + PAGE_SIZE;
  unsigned long line_size;

  /* flush_dcache_page() only updates page flags on ARM64. Clean and
   * invalidate to PoC before installing the non-cacheable mapping.
   * Prevent migration while using the current CPU's cache line size. */
  preempt_disable ();
  line_size = 4UL << SYS_FIELD_GET (CTR_EL0, DminLine, read_cpuid_cachetype ());
  for (; addr < end; addr += line_size)
    asm volatile ("dc civac, %0" : : "r"(addr) : "memory");
  asm volatile ("dsb sy" : : : "memory");
  preempt_enable ();
#else
  flush_dcache_page (page);
#endif
}

static long
kdi_map_dma_mem_uncached (unsigned long arg)
{
  struct kdi_dma_mem_map request;
  struct kdi_dma_mem *m;
  unsigned long n_pages;
  long n_pinned;
  int ret;

  if (copy_from_user (&request, (void __user *) arg, sizeof (request)))
    return -EFAULT;
  if (!request.size || (request.addr & ~PAGE_MASK) || (request.size & ~PAGE_MASK))
    return -EINVAL;

  n_pages = request.size >> PAGE_SHIFT;

  m = kzalloc (sizeof (*m), GFP_KERNEL);
  if (!m)
    return -ENOMEM;

  m->pages = kcalloc (n_pages, sizeof (*m->pages), GFP_KERNEL);
  if (!m->pages)
    {
      kfree (m);
      return -ENOMEM;
    }

  /* FOLL_LONGTERM: these pages stay pinned for as long as the coherent
   * mapping exists, not just for one transient DMA transfer. */
  n_pinned = pin_user_pages_fast (request.addr, n_pages, FOLL_WRITE | FOLL_LONGTERM, m->pages);
  if (n_pinned < 0 || (unsigned long) n_pinned != n_pages)
    {
      if (n_pinned > 0)
	unpin_user_pages (m->pages, n_pinned);
      kfree (m->pages);
      kfree (m);
      return n_pinned < 0 ? n_pinned : -EFAULT;
    }
  m->n_pages = n_pages;

  /* Whatever the caller last wrote via its ordinary cacheable mapping of
   * these pages may still be dirty in the CPU cache. Changing the PTE's
   * memory type to non-cacheable does not itself flush anything, so clean
   * each page now or that write could be lost (or, worse, written back
   * later and clobber whatever the device subsequently DMAs in). */
  for (unsigned long i = 0; i < n_pages; i++)
    kdi_dma_mem_flush_page (m->pages[i]);

  /* page_to_pfn () gives the real physical frame regardless of how the
   * caller's own VA happens to be mapped; /proc/pid/pagemap-based lookups
   * (which is how userspace normally resolves this) cannot be trusted
   * once we hand back a remap_pfn_range ()-installed mapping for it. */
  request.phys_addr = (u64) page_to_pfn (m->pages[0]) << PAGE_SHIFT;
  if (copy_to_user ((void __user *) arg, &request, sizeof (request)))
    {
      unpin_user_pages (m->pages, m->n_pages);
      kfree (m->pages);
      kfree (m);
      return -EFAULT;
    }

  ret = anon_inode_getfd ("vpp-kdi-dma-mem", &kdi_dma_mem_fops, m, O_RDWR | O_CLOEXEC);
  if (ret < 0)
    {
      unpin_user_pages (m->pages, m->n_pages);
      kfree (m->pages);
      kfree (m);
      return ret;
    }

  pr_info ("vpp-kdi: mapping va [0x%llx-0x%llx] (phys 0x%llx) uncached\n",
	   (unsigned long long) request.addr,
	   (unsigned long long) (request.addr + request.size - 1),
	   (unsigned long long) request.phys_addr);
  return ret;
}

static long
kdi_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
  if (cmd == KDI_IOC_OPEN_RESOURCE)
    return kdi_open_resource (arg);
  if (cmd == KDI_IOC_MAP_DMA_MEM_UNCACHED)
    return kdi_map_dma_mem_uncached (arg);
  return -ENOTTY;
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
