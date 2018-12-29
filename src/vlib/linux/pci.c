/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * pci.c: Linux user space PCI bus management.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vppinfra/linux/sysfs.h>

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>
#include <vlib/linux/vfio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>

static const char *sysfs_pci_dev_path = "/sys/bus/pci/devices";
static const char *sysfs_pci_drv_path = "/sys/bus/pci/drivers";
static char *sysfs_mod_vfio_noiommu =
  "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode";

#define pci_log_debug(vm, dev, f, ...) \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, pci_main.log_default, "%U: " f, \
           format_vlib_pci_addr, vlib_pci_get_addr(vm, dev->handle), ## __VA_ARGS__)
#define pci_log_err(vm, dev, f, ...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, pci_main.log_default, "%U: " f, \
           format_vlib_pci_addr, vlib_pci_get_addr(vm, dev->handle), ## __VA_ARGS__)

typedef struct
{
  int fd;
  void *addr;
  size_t size;
} linux_pci_region_t;

typedef struct
{
  int fd;
  u32 clib_file_index;
  union
  {
    pci_intx_handler_function_t *intx_handler;
    pci_msix_handler_function_t *msix_handler;
  };
} linux_pci_irq_t;

typedef enum
{
  LINUX_PCI_DEVICE_TYPE_UNKNOWN,
  LINUX_PCI_DEVICE_TYPE_UIO,
  LINUX_PCI_DEVICE_TYPE_VFIO,
} linux_pci_device_type_t;

typedef struct
{
  linux_pci_device_type_t type;
  vlib_pci_dev_handle_t handle;
  vlib_pci_addr_t addr;

  /* Resource file descriptors. */
  linux_pci_region_t *regions;

  /* File descriptor for config space read/write. */
  int config_fd;
  u64 config_offset;

  /* Device File descriptor */
  int fd;

  /* read/write file descriptor for io bar */
  int io_fd;
  u64 io_offset;

  /* Minor device for uio device. */
  u32 uio_minor;

  /* Interrupt handlers */
  linux_pci_irq_t intx_irq;
  linux_pci_irq_t *msix_irqs;

  /* private data */
  uword private_data;

  u8 supports_va_dma;

} linux_pci_device_t;

/* Pool of PCI devices. */
typedef struct
{
  vlib_main_t *vlib_main;
  linux_pci_device_t *linux_pci_devices;

} linux_pci_main_t;

extern linux_pci_main_t linux_pci_main;

static linux_pci_device_t *
linux_pci_get_device (vlib_pci_dev_handle_t h)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  return pool_elt_at_index (lpm->linux_pci_devices, h);
}

uword
vlib_pci_get_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  linux_pci_device_t *d = linux_pci_get_device (h);
  return d->private_data;
}

void
vlib_pci_set_private_data (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   uword private_data)
{
  linux_pci_device_t *d = linux_pci_get_device (h);
  d->private_data = private_data;
}

vlib_pci_addr_t *
vlib_pci_get_addr (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  linux_pci_device_t *d = linux_pci_get_device (h);
  return &d->addr;
}

/* Call to allocate/initialize the pci subsystem.
   This is not an init function so that users can explicitly enable
   pci only when it's needed. */
clib_error_t *pci_bus_init (vlib_main_t * vm);

linux_pci_main_t linux_pci_main;

vlib_pci_device_info_t *
vlib_pci_get_device_info (vlib_main_t * vm, vlib_pci_addr_t * addr,
			  clib_error_t ** error)
{
  linux_vfio_main_t *lvm = &vfio_main;
  clib_error_t *err;
  vlib_pci_device_info_t *di;
  u8 *f = 0;
  u32 tmp;
  int fd;

  di = clib_mem_alloc (sizeof (vlib_pci_device_info_t));
  clib_memset (di, 0, sizeof (vlib_pci_device_info_t));
  di->addr.as_u32 = addr->as_u32;

  u8 *dev_dir_name = format (0, "%s/%U", sysfs_pci_dev_path,
			     format_vlib_pci_addr, addr);

  f = format (0, "%v/config%c", dev_dir_name, 0);
  fd = open ((char *) f, O_RDWR);

  /* Try read-only access if write fails. */
  if (fd < 0)
    fd = open ((char *) f, O_RDONLY);

  if (fd < 0)
    {
      err = clib_error_return_unix (0, "open `%s'", f);
      goto error;
    }

  /* You can only read more that 64 bytes of config space as root; so we try to
     read the full space but fall back to just the first 64 bytes. */
  if (read (fd, &di->config_data, sizeof (di->config_data)) <
      sizeof (di->config0))
    {
      err = clib_error_return_unix (0, "read `%s'", f);
      close (fd);
      goto error;
    }

  {
    static pci_config_header_t all_ones;
    if (all_ones.vendor_id == 0)
      clib_memset (&all_ones, ~0, sizeof (all_ones));

    if (!memcmp (&di->config0.header, &all_ones, sizeof (all_ones)))
      {
	err = clib_error_return (0, "invalid PCI config for `%s'", f);
	close (fd);
	goto error;
      }
  }

  if (di->config0.header.header_type == 0)
    pci_config_type0_little_to_host (&di->config0);
  else
    pci_config_type1_little_to_host (&di->config1);

  di->numa_node = -1;
  vec_reset_length (f);
  f = format (f, "%v/numa_node%c", dev_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%u", &di->numa_node);
  if (err)
    {
      di->numa_node = -1;
      clib_error_free (err);
    }

  vec_reset_length (f);
  f = format (f, "%v/class%c", dev_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "0x%x", &tmp);
  if (err)
    goto error;
  di->device_class = tmp >> 8;

  vec_reset_length (f);
  f = format (f, "%v/vendor%c", dev_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "0x%x", &tmp);
  if (err)
    goto error;
  di->vendor_id = tmp;

  vec_reset_length (f);
  f = format (f, "%v/device%c", dev_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "0x%x", &tmp);
  if (err)
    goto error;
  di->device_id = tmp;

  vec_reset_length (f);
  f = format (f, "%v/driver%c", dev_dir_name, 0);
  di->driver_name = clib_sysfs_link_to_name ((char *) f);

  di->iommu_group = -1;
  if (lvm->container_fd == -1)
    {
      linux_vfio_get_container_fd ();
    }

  if (lvm->container_fd != -1)
    {
      u8 *tmpstr;
      vec_reset_length (f);
      f = format (f, "%v/iommu_group%c", dev_dir_name, 0);
      tmpstr = clib_sysfs_link_to_name ((char *) f);
      if (tmpstr)
	{
	  di->iommu_group = atoi ((char *) tmpstr);
	  vec_free (tmpstr);
	}
      vec_reset_length (f);
      f = format (f, "%v/iommu_group/name%c", dev_dir_name, 0);
      err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
      if (err == 0)
	{
	  if (strncmp ((char *) tmpstr, "vfio-noiommu", 12) == 0)
	    di->flags |= VLIB_PCI_DEVICE_INFO_F_NOIOMMU;
	  vec_free (tmpstr);
	}
      else
	clib_error_free (err);
    }

  close (fd);

  vec_reset_length (f);
  f = format (f, "%v/vpd%c", dev_dir_name, 0);
  fd = open ((char *) f, O_RDONLY);
  if (fd >= 0)
    {
      while (1)
	{
	  u8 tag[3];
	  u8 *data = 0;
	  uword len;

	  if (read (fd, &tag, 3) != 3)
	    break;

	  if (tag[0] != 0x82 && tag[0] != 0x90 && tag[0] != 0x91)
	    break;

	  len = (tag[2] << 8) | tag[1];
	  vec_validate (data, len);

	  if (read (fd, data, len) != len)
	    {
	      vec_free (data);
	      break;
	    }
	  if (tag[0] == 0x82)
	    di->product_name = data;
	  else if (tag[0] == 0x90)
	    di->vpd_r = data;
	  else if (tag[0] == 0x91)
	    di->vpd_w = data;

	  data = 0;
	}
      close (fd);
    }

  goto done;

error:
  vlib_pci_free_device_info (di);
  di = 0;

done:
  vec_free (f);
  vec_free (dev_dir_name);
  if (error)
    *error = err;
  else
    clib_error_free (err);
  return di;
}

static int
directory_exists (char *path)
{
  struct stat s = { 0 };
  if (stat (path, &s) == -1)
    return 0;

  return S_ISDIR (s.st_mode);
}

clib_error_t *
vlib_pci_bind_to_uio (vlib_main_t * vm, vlib_pci_addr_t * addr,
		      char *uio_drv_name)
{
  clib_error_t *error = 0;
  u8 *s = 0, *driver_name = 0;
  DIR *dir = 0;
  struct dirent *e;
  vlib_pci_device_info_t *di;
  int fd, clear_driver_override = 0;
  u8 *dev_dir_name = format (0, "%s/%U", sysfs_pci_dev_path,
			     format_vlib_pci_addr, addr);

  di = vlib_pci_get_device_info (vm, addr, &error);

  if (error)
    return error;

  if (strncmp ("auto", uio_drv_name, 5) == 0)
    {
      int vfio_pci_loaded = 0;

      if (directory_exists ("/sys/module/vfio_pci"))
	vfio_pci_loaded = 1;

      if (di->iommu_group != -1)
	{
	  /* device is bound to IOMMU group */
	  if (!vfio_pci_loaded)
	    {
	      error = clib_error_return (0, "Skipping PCI device %U: device "
					 "is bound to IOMMU group and "
					 "vfio-pci driver is not loaded",
					 format_vlib_pci_addr, addr);
	      goto done;
	    }
	  else
	    uio_drv_name = "vfio-pci";
	}
      else
	{
	  /* device is not bound to IOMMU group so we have multiple options */
	  if (vfio_pci_loaded &&
	      (error = clib_sysfs_write (sysfs_mod_vfio_noiommu, "Y")) == 0)
	    uio_drv_name = "vfio-pci";
	  else if (directory_exists ("/sys/module/uio_pci_generic"))
	    uio_drv_name = "uio_pci_generic";
	  else if (directory_exists ("/sys/module/igb_uio"))
	    uio_drv_name = "igb_uio";
	  else
	    {
	      clib_error_free (error);
	      error = clib_error_return (0, "Skipping PCI device %U: missing "
					 "kernel VFIO or UIO driver",
					 format_vlib_pci_addr, addr);
	      goto done;
	    }
	  clib_error_free (error);
	}
    }

  s = format (s, "%v/driver%c", dev_dir_name, 0);
  driver_name = clib_sysfs_link_to_name ((char *) s);
  vec_reset_length (s);

  if (driver_name &&
      ((strcmp ("vfio-pci", (char *) driver_name) == 0) ||
       (strcmp ("uio_pci_generic", (char *) driver_name) == 0) ||
       (strcmp ("igb_uio", (char *) driver_name) == 0)))
    goto done;

  /* walk trough all linux interfaces and if interface belonging to
     this device is founf check if interface is admin up  */
  dir = opendir ("/sys/class/net");
  s = format (s, "%U%c", format_vlib_pci_addr, addr, 0);

  if (!dir)
    {
      error = clib_error_return (0, "Skipping PCI device %U: failed to "
				 "read /sys/class/net",
				 format_vlib_pci_addr, addr);
      goto done;
    }

  fd = socket (PF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "socket");
      goto done;
    }

  while ((e = readdir (dir)))
    {
      struct ifreq ifr;
      struct ethtool_drvinfo drvinfo;

      if (e->d_name[0] == '.')	/* skip . and .. */
	continue;

      clib_memset (&ifr, 0, sizeof ifr);
      clib_memset (&drvinfo, 0, sizeof drvinfo);
      ifr.ifr_data = (char *) &drvinfo;
      strncpy (ifr.ifr_name, e->d_name, sizeof (ifr.ifr_name));
      ifr.ifr_name[ARRAY_LEN (ifr.ifr_name) - 1] = '\0';
      drvinfo.cmd = ETHTOOL_GDRVINFO;
      if (ioctl (fd, SIOCETHTOOL, &ifr) < 0)
	{
	  /* Some interfaces (eg "lo") don't support this ioctl */
	  if ((errno != ENOTSUP) && (errno != ENODEV))
	    clib_unix_warning ("ioctl fetch intf %s bus info error",
			       e->d_name);
	  continue;
	}

      if (strcmp ((char *) s, drvinfo.bus_info))
	continue;

      clib_memset (&ifr, 0, sizeof (ifr));
      strncpy (ifr.ifr_name, e->d_name, sizeof (ifr.ifr_name));
      ifr.ifr_name[ARRAY_LEN (ifr.ifr_name) - 1] = '\0';
      if (ioctl (fd, SIOCGIFFLAGS, &ifr) < 0)
	{
	  error = clib_error_return_unix (0, "ioctl fetch intf %s flags",
					  e->d_name);
	  close (fd);
	  goto done;
	}

      if (ifr.ifr_flags & IFF_UP)
	{
	  error = clib_error_return (0, "Skipping PCI device %U as host "
				     "interface %s is up",
				     format_vlib_pci_addr, addr, e->d_name);
	  close (fd);
	  goto done;
	}
    }

  close (fd);
  vec_reset_length (s);

  s = format (s, "%v/driver/unbind%c", dev_dir_name, 0);
  clib_sysfs_write ((char *) s, "%U", format_vlib_pci_addr, addr);
  vec_reset_length (s);

  s = format (s, "%v/driver_override%c", dev_dir_name, 0);
  if (access ((char *) s, F_OK) == 0)
    {
      clib_sysfs_write ((char *) s, "%s", uio_drv_name);
      clear_driver_override = 1;
    }
  else
    {
      vec_reset_length (s);
      s = format (s, "%s/%s/new_id%c", sysfs_pci_drv_path, uio_drv_name, 0);
      clib_sysfs_write ((char *) s, "0x%04x 0x%04x", di->vendor_id,
			di->device_id);
    }
  vec_reset_length (s);

  s = format (s, "%s/%s/bind%c", sysfs_pci_drv_path, uio_drv_name, 0);
  clib_sysfs_write ((char *) s, "%U", format_vlib_pci_addr, addr);
  vec_reset_length (s);

  if (clear_driver_override)
    {
      s = format (s, "%v/driver_override%c", dev_dir_name, 0);
      clib_sysfs_write ((char *) s, "%c", 0);
      vec_reset_length (s);
    }

done:
  closedir (dir);
  vec_free (s);
  vec_free (dev_dir_name);
  vec_free (driver_name);
  return error;
}


static clib_error_t *
scan_uio_dir (void *arg, u8 * path_name, u8 * file_name)
{
  linux_pci_device_t *l = arg;
  unformat_input_t input;

  unformat_init_string (&input, (char *) file_name, vec_len (file_name));

  if (!unformat (&input, "uio%d", &l->uio_minor))
    abort ();

  unformat_free (&input);
  return 0;
}

static clib_error_t *
vfio_set_irqs (vlib_main_t * vm, linux_pci_device_t * p, u32 index, u32 start,
	       u32 count, u32 flags, int *efds)
{
  int data_len = efds ? count * sizeof (int) : 0;
  u8 buf[sizeof (struct vfio_irq_set) + data_len];
  struct vfio_irq_info ii = { 0 };
  struct vfio_irq_set *irq_set = (struct vfio_irq_set *) buf;


  ii.argsz = sizeof (struct vfio_irq_info);
  ii.index = index;

  if (ioctl (p->fd, VFIO_DEVICE_GET_IRQ_INFO, &ii) < 0)
    return clib_error_return_unix (0, "ioctl(VFIO_DEVICE_GET_IRQ_INFO) "
				   "'%U'", format_vlib_pci_addr, &p->addr);

  pci_log_debug (vm, p, "%s index:%u count:%u flags: %s%s%s%s(0x%x)",
		 __func__, ii.index, ii.count,
		 ii.flags & VFIO_IRQ_INFO_EVENTFD ? "eventfd " : "",
		 ii.flags & VFIO_IRQ_INFO_MASKABLE ? "maskable " : "",
		 ii.flags & VFIO_IRQ_INFO_AUTOMASKED ? "automasked " : "",
		 ii.flags & VFIO_IRQ_INFO_NORESIZE ? "noresize " : "",
		 ii.flags);

  if (ii.count < start + count)
    return clib_error_return_unix (0, "vfio_set_irq: unexistng interrupt on "
				   "'%U'", format_vlib_pci_addr, &p->addr);


  if (efds)
    {
      flags |= VFIO_IRQ_SET_DATA_EVENTFD;
      clib_memcpy_fast (&irq_set->data, efds, data_len);
    }
  else
    flags |= VFIO_IRQ_SET_DATA_NONE;

  ASSERT ((flags & (VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_DATA_EVENTFD)) !=
	  (VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_DATA_EVENTFD));

  irq_set->argsz = sizeof (struct vfio_irq_set) + data_len;
  irq_set->index = index;
  irq_set->start = start;
  irq_set->count = count;
  irq_set->flags = flags;

  if (ioctl (p->fd, VFIO_DEVICE_SET_IRQS, irq_set) < 0)
    return clib_error_return_unix (0, "%U:ioctl(VFIO_DEVICE_SET_IRQS) "
				   "[index = %u, start = %u, count = %u, "
				   "flags = 0x%x]",
				   format_vlib_pci_addr, &p->addr,
				   index, start, count, flags);
  return 0;
}

static clib_error_t *
linux_pci_uio_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  int __attribute__ ((unused)) rv;
  vlib_pci_dev_handle_t h = uf->private_data;
  linux_pci_device_t *p = linux_pci_get_device (h);
  linux_pci_irq_t *irq = &p->intx_irq;

  u32 icount;
  rv = read (uf->file_descriptor, &icount, 4);

  if (irq->intx_handler)
    irq->intx_handler (vm, h);

  vlib_pci_intr_enable (vm, h);

  return /* no error */ 0;
}

static clib_error_t *
linux_pci_vfio_unmask_intx (vlib_main_t * vm, linux_pci_device_t * d)
{
  return vfio_set_irqs (vm, d, VFIO_PCI_INTX_IRQ_INDEX, 0, 1,
			VFIO_IRQ_SET_ACTION_UNMASK, 0);
}

static clib_error_t *
linux_pci_uio_error_ready (clib_file_t * uf)
{
  u32 error_index = (u32) uf->private_data;

  return clib_error_return (0, "pci device %d: error", error_index);
}

static clib_error_t *
linux_pci_vfio_msix_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  int __attribute__ ((unused)) rv;
  vlib_pci_dev_handle_t h = uf->private_data >> 16;
  u16 line = uf->private_data & 0xffff;
  linux_pci_device_t *p = linux_pci_get_device (h);
  linux_pci_irq_t *irq = vec_elt_at_index (p->msix_irqs, line);

  u64 icount;
  rv = read (uf->file_descriptor, &icount, sizeof (icount));

  if (irq->msix_handler)
    irq->msix_handler (vm, h, line);

  return /* no error */ 0;
}

static clib_error_t *
linux_pci_vfio_intx_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  int __attribute__ ((unused)) rv;
  vlib_pci_dev_handle_t h = uf->private_data;
  linux_pci_device_t *p = linux_pci_get_device (h);
  linux_pci_irq_t *irq = &p->intx_irq;

  u64 icount;
  rv = read (uf->file_descriptor, &icount, sizeof (icount));

  if (irq->intx_handler)
    irq->intx_handler (vm, h);

  linux_pci_vfio_unmask_intx (vm, p);

  return /* no error */ 0;
}

static clib_error_t *
linux_pci_vfio_error_ready (clib_file_t * uf)
{
  u32 error_index = (u32) uf->private_data;

  return clib_error_return (0, "pci device %d: error", error_index);
}

static clib_error_t *
add_device_uio (vlib_main_t * vm, linux_pci_device_t * p,
		vlib_pci_device_info_t * di, pci_device_registration_t * r)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  clib_error_t *err = 0;
  u8 *s = 0;

  p->fd = -1;
  p->type = LINUX_PCI_DEVICE_TYPE_UIO;

  s = format (s, "%s/%U/config%c", sysfs_pci_dev_path,
	      format_vlib_pci_addr, &di->addr, 0);

  p->config_fd = open ((char *) s, O_RDWR);
  p->config_offset = 0;
  vec_reset_length (s);

  if (p->config_fd == -1)
    {
      err = clib_error_return_unix (0, "open '%s'", s);
      goto error;
    }

  s = format (0, "%s/%U/uio", sysfs_pci_dev_path,
	      format_vlib_pci_addr, &di->addr);
  foreach_directory_file ((char *) s, scan_uio_dir, p,	/* scan_dirs */
			  1);
  vec_reset_length (s);

  s = format (s, "/dev/uio%d%c", p->uio_minor, 0);
  p->fd = open ((char *) s, O_RDWR);
  if (p->fd < 0)
    {
      err = clib_error_return_unix (0, "open '%s'", s);
      goto error;
    }

  if (r && r->interrupt_handler)
    vlib_pci_register_intx_handler (vm, p->handle, r->interrupt_handler);

  if (r && r->init_function)
    err = r->init_function (lpm->vlib_main, p->handle);

error:
  vec_free (s);
  if (err)
    {
      if (p->config_fd != -1)
	close (p->config_fd);
      if (p->fd != -1)
	close (p->fd);
    }
  return err;
}

clib_error_t *
vlib_pci_register_intx_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				pci_intx_handler_function_t * intx_handler)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  clib_file_t t = { 0 };
  linux_pci_irq_t *irq = &p->intx_irq;
  ASSERT (irq->fd == -1);

  if (p->type == LINUX_PCI_DEVICE_TYPE_VFIO)
    {
      struct vfio_irq_info ii = { 0 };
      ii.argsz = sizeof (struct vfio_irq_info);
      ii.index = VFIO_PCI_INTX_IRQ_INDEX;
      if (ioctl (p->fd, VFIO_DEVICE_GET_IRQ_INFO, &ii) < 0)
	return clib_error_return_unix (0, "ioctl(VFIO_DEVICE_GET_IRQ_INFO) '"
				       "%U'", format_vlib_pci_addr, &p->addr);
      pci_log_debug (vm, p, "%s index:%u count:%u flags: %s%s%s%s(0x%x)",
		     __func__, ii.index, ii.count,
		     ii.flags & VFIO_IRQ_INFO_EVENTFD ? "eventfd " : "",
		     ii.flags & VFIO_IRQ_INFO_MASKABLE ? "maskable " : "",
		     ii.flags & VFIO_IRQ_INFO_AUTOMASKED ? "automasked " : "",
		     ii.flags & VFIO_IRQ_INFO_NORESIZE ? "noresize " : "",
		     ii.flags);
      if (ii.count != 1)
	return clib_error_return (0, "INTx interrupt does not exist on device"
				  "'%U'", format_vlib_pci_addr, &p->addr);

      irq->fd = eventfd (0, EFD_NONBLOCK);
      if (irq->fd == -1)
	return clib_error_return_unix (0, "eventfd");

      t.file_descriptor = irq->fd;
      t.read_function = linux_pci_vfio_intx_read_ready;
    }
  else if (p->type == LINUX_PCI_DEVICE_TYPE_UIO)
    {
      t.file_descriptor = p->fd;
      t.read_function = linux_pci_uio_read_ready;
    }
  else
    return 0;

  t.error_function = linux_pci_uio_error_ready;
  t.private_data = p->handle;
  t.description = format (0, "PCI %U INTx", format_vlib_pci_addr, &p->addr);
  irq->clib_file_index = clib_file_add (&file_main, &t);
  irq->intx_handler = intx_handler;
  return 0;
}

clib_error_t *
vlib_pci_register_msix_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
				u32 start, u32 count,
				pci_msix_handler_function_t * msix_handler)
{
  clib_error_t *err = 0;
  linux_pci_device_t *p = linux_pci_get_device (h);
  u32 i;

  if (p->type != LINUX_PCI_DEVICE_TYPE_VFIO)
    return clib_error_return (0, "vfio driver is needed for MSI-X interrupt "
			      "support");

  /* *INDENT-OFF* */
  vec_validate_init_empty (p->msix_irqs, start + count - 1, (linux_pci_irq_t)
			   { .fd = -1});
  /* *INDENT-ON* */

  for (i = start; i < start + count; i++)
    {
      clib_file_t t = { 0 };
      linux_pci_irq_t *irq = vec_elt_at_index (p->msix_irqs, i);
      ASSERT (irq->fd == -1);

      irq->fd = eventfd (0, EFD_NONBLOCK);
      if (irq->fd == -1)
	{
	  err = clib_error_return_unix (0, "eventfd");
	  goto error;
	}

      t.read_function = linux_pci_vfio_msix_read_ready;
      t.file_descriptor = irq->fd;
      t.error_function = linux_pci_vfio_error_ready;
      t.private_data = p->handle << 16 | i;
      t.description = format (0, "PCI %U MSI-X #%u", format_vlib_pci_addr,
			      &p->addr, i);
      irq->clib_file_index = clib_file_add (&file_main, &t);
      irq->msix_handler = msix_handler;
    }

  return 0;

error:
  while (i-- > start)
    {
      linux_pci_irq_t *irq = vec_elt_at_index (p->msix_irqs, i);
      if (irq->fd != -1)
	{
	  clib_file_del_by_index (&file_main, irq->clib_file_index);
	  close (irq->fd);
	  irq->fd = -1;
	}
    }
  return err;
}

clib_error_t *
vlib_pci_enable_msix_irq (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			  u16 start, u16 count)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  int fds[count];
  int i;

  if (p->type != LINUX_PCI_DEVICE_TYPE_VFIO)
    return clib_error_return (0, "vfio driver is needed for MSI-X interrupt "
			      "support");

  for (i = start; i < start + count; i++)
    {
      linux_pci_irq_t *irq = vec_elt_at_index (p->msix_irqs, i);
      fds[i] = irq->fd;
    }

  return vfio_set_irqs (vm, p, VFIO_PCI_MSIX_IRQ_INDEX, start, count,
			VFIO_IRQ_SET_ACTION_TRIGGER, fds);
}

clib_error_t *
vlib_pci_disable_msix_irq (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   u16 start, u16 count)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  int i, fds[count];

  if (p->type != LINUX_PCI_DEVICE_TYPE_VFIO)
    return clib_error_return (0, "vfio driver is needed for MSI-X interrupt "
			      "support");

  for (i = start; i < start + count; i++)
    fds[i] = -1;

  return vfio_set_irqs (vm, p, VFIO_PCI_MSIX_IRQ_INDEX, start, count,
			VFIO_IRQ_SET_ACTION_TRIGGER, fds);
}

static clib_error_t *
add_device_vfio (vlib_main_t * vm, linux_pci_device_t * p,
		 vlib_pci_device_info_t * di, pci_device_registration_t * r)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  struct vfio_device_info device_info = { 0 };
  struct vfio_region_info reg = { 0 };
  clib_error_t *err = 0;
  u8 *s = 0;
  int is_noiommu;

  p->type = LINUX_PCI_DEVICE_TYPE_VFIO;

  if ((err = linux_vfio_group_get_device_fd (&p->addr, &p->fd, &is_noiommu)))
    return err;

  if (is_noiommu == 0)
    p->supports_va_dma = 1;

  device_info.argsz = sizeof (device_info);
  if (ioctl (p->fd, VFIO_DEVICE_GET_INFO, &device_info) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_GET_INFO) '%U'",
				    format_vlib_pci_addr, &di->addr);
      goto error;
    }

  reg.argsz = sizeof (struct vfio_region_info);
  reg.index = VFIO_PCI_CONFIG_REGION_INDEX;
  if (ioctl (p->fd, VFIO_DEVICE_GET_REGION_INFO, &reg) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_GET_INFO) '%U'",
				    format_vlib_pci_addr, &di->addr);
      goto error;
    }

  pci_log_debug (vm, p, "%s region_info index:%u size:0x%lx offset:0x%lx "
		 "flags: %s%s%s(0x%x)", __func__,
		 reg.index, reg.size, reg.offset,
		 reg.flags & VFIO_REGION_INFO_FLAG_READ ? "rd " : "",
		 reg.flags & VFIO_REGION_INFO_FLAG_WRITE ? "wr " : "",
		 reg.flags & VFIO_REGION_INFO_FLAG_MMAP ? "mmap " : "",
		 reg.flags);

  p->config_offset = reg.offset;
  p->config_fd = p->fd;

  /* reset if device supports it */
  if (device_info.flags & VFIO_DEVICE_FLAGS_RESET)
    if (ioctl (p->fd, VFIO_DEVICE_RESET) < 0)
      {
	err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_RESET) '%U'",
				      format_vlib_pci_addr, &di->addr);
	goto error;
      }

  if (r && r->interrupt_handler)
    {
      vlib_pci_register_intx_handler (vm, p->handle, r->interrupt_handler);
      linux_pci_vfio_unmask_intx (vm, p);
    }

  if (p->supports_va_dma)
    {
      vlib_buffer_pool_t *bp;
      /* *INDENT-OFF* */
      vec_foreach (bp, buffer_main.buffer_pools)
	{
	  u32 i;
	  vlib_physmem_map_t *pm;
	  pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
	  for (i = 0; i < pm->n_pages; i++)
	    vfio_map_physmem_page (vm, pm->base + (i << pm->log2_page_size));
	}
      /* *INDENT-ON* */
    }

  if (r && r->init_function)
    err = r->init_function (lpm->vlib_main, p->handle);

error:
  vec_free (s);
  if (err)
    {
      if (p->fd != -1)
	close (p->fd);
      if (p->config_fd != -1 && p->config_fd != p->fd)
	close (p->config_fd);
      p->config_fd = p->fd = -1;
    }
  return err;
}

/* Configuration space read/write. */
clib_error_t *
vlib_pci_read_write_config (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			    vlib_read_or_write_t read_or_write,
			    uword address, void *data, u32 n_bytes)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  int n;

  if (read_or_write == VLIB_READ)
    n = pread (p->config_fd, data, n_bytes, p->config_offset + address);
  else
    n = pwrite (p->config_fd, data, n_bytes, p->config_offset + address);

  if (n != n_bytes)
    return clib_error_return_unix (0, "%s",
				   read_or_write == VLIB_READ
				   ? "read" : "write");

  return 0;
}

static clib_error_t *
vlib_pci_region (vlib_main_t * vm, vlib_pci_dev_handle_t h, u32 bar, int *fd,
		 u64 * size, u64 * offset)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  clib_error_t *error = 0;
  int _fd = -1;
  u64 _size = 0, _offset = 0;

  ASSERT (bar <= 5);

  error = 0;

  if (p->type == LINUX_PCI_DEVICE_TYPE_UIO)
    {
      u8 *file_name;
      struct stat stat_buf;
      file_name = format (0, "%s/%U/resource%d%c", sysfs_pci_dev_path,
			  format_vlib_pci_addr, &p->addr, bar, 0);

      _fd = open ((char *) file_name, O_RDWR);
      if (_fd < 0)
	{
	  error = clib_error_return_unix (0, "open `%s'", file_name);
	  vec_free (file_name);
	  return error;
	}

      if (fstat (_fd, &stat_buf) < 0)
	{
	  error = clib_error_return_unix (0, "fstat `%s'", file_name);
	  vec_free (file_name);
	  close (_fd);
	  return error;
	}

      vec_free (file_name);
      _size = stat_buf.st_size;
      _offset = 0;
    }
  else if (p->type == LINUX_PCI_DEVICE_TYPE_VFIO)
    {
      struct vfio_region_info reg = { 0 };
      reg.argsz = sizeof (struct vfio_region_info);
      reg.index = bar;
      if (ioctl (p->fd, VFIO_DEVICE_GET_REGION_INFO, &reg) < 0)
	return clib_error_return_unix (0, "ioctl(VFIO_DEVICE_GET_INFO) "
				       "'%U'", format_vlib_pci_addr,
				       &p->addr);
      _fd = p->fd;
      _size = reg.size;
      _offset = reg.offset;
      pci_log_debug (vm, p, "%s region_info index:%u size:0x%lx offset:0x%lx "
		     "flags: %s%s%s(0x%x)", __func__,
		     reg.index, reg.size, reg.offset,
		     reg.flags & VFIO_REGION_INFO_FLAG_READ ? "rd " : "",
		     reg.flags & VFIO_REGION_INFO_FLAG_WRITE ? "wr " : "",
		     reg.flags & VFIO_REGION_INFO_FLAG_MMAP ? "mmap " : "",
		     reg.flags);
    }
  else
    ASSERT (0);

  *fd = _fd;
  *size = _size;
  *offset = _offset;

  return error;
}

static clib_error_t *
vlib_pci_map_region_int (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			 u32 bar, u8 * addr, void **result)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  int fd = -1;
  clib_error_t *error;
  int flags = MAP_SHARED;
  u64 size = 0, offset = 0;

  pci_log_debug (vm, p, "map region %u to va %p", bar, addr);

  if ((error = vlib_pci_region (vm, h, bar, &fd, &size, &offset)))
    return error;

  if (p->type == LINUX_PCI_DEVICE_TYPE_UIO && addr != 0)
    flags |= MAP_FIXED;

  *result = mmap (addr, size, PROT_READ | PROT_WRITE, flags, fd, offset);
  if (*result == (void *) -1)
    {
      error = clib_error_return_unix (0, "mmap `BAR%u'", bar);
      if (p->type == LINUX_PCI_DEVICE_TYPE_UIO)
	close (fd);
      return error;
    }

  /* *INDENT-OFF* */
  vec_validate_init_empty (p->regions, bar,
			   (linux_pci_region_t) { .fd = -1});
  /* *INDENT-ON* */
  if (p->type == LINUX_PCI_DEVICE_TYPE_UIO)
    p->regions[bar].fd = fd;
  p->regions[bar].addr = *result;
  p->regions[bar].size = size;
  return 0;
}

clib_error_t *
vlib_pci_map_region (vlib_main_t * vm, vlib_pci_dev_handle_t h, u32 resource,
		     void **result)
{
  return (vlib_pci_map_region_int (vm, h, resource, 0 /* addr */ , result));
}

clib_error_t *
vlib_pci_map_region_fixed (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			   u32 resource, u8 * addr, void **result)
{
  return (vlib_pci_map_region_int (vm, h, resource, addr, result));
}

clib_error_t *
vlib_pci_io_region (vlib_main_t * vm, vlib_pci_dev_handle_t h, u32 resource)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  clib_error_t *error = 0;
  int fd = -1;
  u64 size = 0, offset = 0;

  if ((error = vlib_pci_region (vm, h, resource, &fd, &size, &offset)))
    return error;

  p->io_fd = fd;
  p->io_offset = offset;
  return error;
}

clib_error_t *
vlib_pci_read_write_io (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			vlib_read_or_write_t read_or_write,
			uword offset, void *data, u32 length)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  int n = 0;

  if (read_or_write == VLIB_READ)
    n = pread (p->io_fd, data, length, p->io_offset + offset);
  else
    n = pwrite (p->io_fd, data, length, p->io_offset + offset);

  if (n != length)
    return clib_error_return_unix (0, "%s",
				   read_or_write == VLIB_READ
				   ? "read" : "write");
  return 0;
}

clib_error_t *
vlib_pci_map_dma (vlib_main_t * vm, vlib_pci_dev_handle_t h, void *ptr)
{
  linux_pci_device_t *p = linux_pci_get_device (h);

  if (!p->supports_va_dma)
    return 0;

  return vfio_map_physmem_page (vm, ptr);
}

int
vlib_pci_supports_virtual_addr_dma (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  linux_pci_device_t *p = linux_pci_get_device (h);

  return p->supports_va_dma != 0;
}

clib_error_t *
vlib_pci_device_open (vlib_main_t * vm, vlib_pci_addr_t * addr,
		      pci_device_id_t ids[], vlib_pci_dev_handle_t * handle)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  vlib_pci_device_info_t *di;
  linux_pci_device_t *p;
  clib_error_t *err = 0;
  pci_device_id_t *i;

  di = vlib_pci_get_device_info (vm, addr, &err);

  if (err)
    return err;
  for (i = ids; i->vendor_id != 0; i++)
    if (i->vendor_id == di->vendor_id && i->device_id == di->device_id)
      break;

  if (i->vendor_id == 0)
    return clib_error_return (0, "Wrong vendor or device id");

  pool_get (lpm->linux_pci_devices, p);
  p->handle = p - lpm->linux_pci_devices;
  p->addr.as_u32 = di->addr.as_u32;
  p->intx_irq.fd = -1;
  /*
   * pci io bar read/write fd
   */
  p->io_fd = -1;

  pci_log_debug (vm, p, "open vid:0x%04x did:0x%04x driver:%s iommu_group:%d",
		 di->vendor_id, di->device_id, di->driver_name,
		 di->iommu_group);

  if (strncmp ("vfio-pci", (char *) di->driver_name, 8) == 0)
    err = add_device_vfio (vm, p, di, 0);
  else if (strncmp ("uio_pci_generic", (char *) di->driver_name, 8) == 0)
    err = add_device_uio (vm, p, di, 0);
  else
    err = clib_error_create ("device not bound to 'vfio-pci' or "
			     "'uio_pci_generic' kernel module");
  if (err)
    goto error;

  *handle = p->handle;

error:
  vlib_pci_free_device_info (di);
  if (err)
    {
      pci_log_err (vm, p, "%U", format_clib_error, err);
      clib_memset (p, 0, sizeof (linux_pci_device_t));
      pool_put (lpm->linux_pci_devices, p);
    }

  return err;
}

void
vlib_pci_device_close (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  linux_pci_device_t *p = linux_pci_get_device (h);
  linux_pci_irq_t *irq;
  linux_pci_region_t *res;
  clib_error_t *err = 0;

  if (p->type == LINUX_PCI_DEVICE_TYPE_UIO)
    {
      irq = &p->intx_irq;
      clib_file_del_by_index (&file_main, irq->clib_file_index);
      close (p->config_fd);
      if (p->io_fd != -1)
	close (p->io_fd);
    }
  else if (p->type == LINUX_PCI_DEVICE_TYPE_VFIO)
    {
      irq = &p->intx_irq;
      /* close INTx irqs */
      if (irq->fd != -1)
	{
	  err = vfio_set_irqs (vm, p, VFIO_PCI_INTX_IRQ_INDEX, 0, 0,
			       VFIO_IRQ_SET_ACTION_TRIGGER, 0);
	  clib_error_free (err);
	  clib_file_del_by_index (&file_main, irq->clib_file_index);
	  close (irq->fd);
	}

      /* close MSI-X irqs */
      if (vec_len (p->msix_irqs))
	{
	  err = vfio_set_irqs (vm, p, VFIO_PCI_MSIX_IRQ_INDEX, 0, 0,
			       VFIO_IRQ_SET_ACTION_TRIGGER, 0);
	  clib_error_free (err);
          /* *INDENT-OFF* */
	  vec_foreach (irq, p->msix_irqs)
	    {
	      if (irq->fd == -1)
		continue;
	      clib_file_del_by_index (&file_main, irq->clib_file_index);
	      close (irq->fd);
	    }
          /* *INDENT-ON* */
	  vec_free (p->msix_irqs);
	}
    }

  /* *INDENT-OFF* */
  vec_foreach (res, p->regions)
    {
      if (res->size == 0)
	continue;
      munmap (res->addr, res->size);
      if (res->fd != -1)
        close (res->fd);
    }
  /* *INDENT-ON* */
  vec_free (p->regions);

  close (p->fd);
  clib_memset (p, 0, sizeof (linux_pci_device_t));
  pool_put (lpm->linux_pci_devices, p);
}

void
init_device_from_registered (vlib_main_t * vm, vlib_pci_device_info_t * di)
{
  vlib_pci_main_t *pm = &pci_main;
  linux_pci_main_t *lpm = &linux_pci_main;
  pci_device_registration_t *r;
  pci_device_id_t *i;
  clib_error_t *err = 0;
  linux_pci_device_t *p;

  pool_get (lpm->linux_pci_devices, p);
  p->handle = p - lpm->linux_pci_devices;
  p->intx_irq.fd = -1;

  r = pm->pci_device_registrations;

  while (r)
    {
      for (i = r->supported_devices; i->vendor_id != 0; i++)
	if (i->vendor_id == di->vendor_id && i->device_id == di->device_id)
	  {
	    if (di->iommu_group != -1)
	      err = add_device_vfio (vm, p, di, r);
	    else
	      err = add_device_uio (vm, p, di, r);

	    if (err)
	      clib_error_report (err);
	    else
	      return;
	  }
      r = r->next_registration;
    }

  /* No driver, close the PCI config-space FD */
  clib_memset (p, 0, sizeof (linux_pci_device_t));
  pool_put (lpm->linux_pci_devices, p);
}

static clib_error_t *
scan_pci_addr (void *arg, u8 * dev_dir_name, u8 * ignored)
{
  vlib_pci_addr_t addr, **addrv = arg;
  unformat_input_t input;
  clib_error_t *err = 0;

  unformat_init_string (&input, (char *) dev_dir_name,
			vec_len (dev_dir_name));

  if (!unformat (&input, "/sys/bus/pci/devices/%U",
		 unformat_vlib_pci_addr, &addr))
    err = clib_error_return (0, "unformat error `%v`", dev_dir_name);

  unformat_free (&input);

  if (err)
    return err;

  vec_add1 (*addrv, addr);
  return 0;
}

static int
pci_addr_cmp (void *v1, void *v2)
{
  vlib_pci_addr_t *a1 = v1;
  vlib_pci_addr_t *a2 = v2;

  if (a1->domain > a2->domain)
    return 1;
  if (a1->domain < a2->domain)
    return -1;
  if (a1->bus > a2->bus)
    return 1;
  if (a1->bus < a2->bus)
    return -1;
  if (a1->slot > a2->slot)
    return 1;
  if (a1->slot < a2->slot)
    return -1;
  if (a1->function > a2->function)
    return 1;
  if (a1->function < a2->function)
    return -1;
  return 0;
}

vlib_pci_addr_t *
vlib_pci_get_all_dev_addrs ()
{
  vlib_pci_addr_t *addrs = 0;
  clib_error_t *err;
  err = foreach_directory_file ((char *) sysfs_pci_dev_path, scan_pci_addr,
				&addrs, /* scan_dirs */ 0);
  if (err)
    {
      vec_free (addrs);
      return 0;
    }

  vec_sort_with_function (addrs, pci_addr_cmp);

  return addrs;
}

clib_error_t *
linux_pci_init (vlib_main_t * vm)
{
  vlib_pci_main_t *pm = &pci_main;
  vlib_pci_addr_t *addr = 0, *addrs;
  clib_error_t *error;

  pm->vlib_main = vm;

  if ((error = vlib_call_init_function (vm, unix_input_init)))
    return error;

  ASSERT (sizeof (vlib_pci_addr_t) == sizeof (u32));

  addrs = vlib_pci_get_all_dev_addrs ();
  /* *INDENT-OFF* */
  vec_foreach (addr, addrs)
    {
      vlib_pci_device_info_t *d;
      if ((d = vlib_pci_get_device_info (vm, addr, 0)))
	{
	  init_device_from_registered (vm, d);
	  vlib_pci_free_device_info (d);
	}
    }
  /* *INDENT-ON* */

  return error;
}

VLIB_INIT_FUNCTION (linux_pci_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
