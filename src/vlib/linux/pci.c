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

typedef struct
{
  vlib_pci_dev_handle_t handle;
  vlib_pci_addr_t addr;

  /* Resource file descriptors. */
  int *resource_fds;

  /* File descriptor for config space read/write. */
  int config_fd;

  /* File descriptor for /dev/uio%d */
  int uio_fd;

  /* Minor device for uio device. */
  u32 uio_minor;

  /* vfio */
  int vfio_device_fd;

  /* Index given by clib_file_add. */
  u32 clib_file_index;

  /* Interrupt handler */
  void (*interrupt_handler) (vlib_pci_dev_handle_t h);

  /* private data */
  uword private_data;

} linux_pci_device_t;

typedef struct
{
  int group;
  int fd;
  int refcnt;
} linux_pci_vfio_iommu_group_t;

/* Pool of PCI devices. */
typedef struct
{
  vlib_main_t *vlib_main;
  linux_pci_device_t *linux_pci_devices;

  /* VFIO */
  int vfio_container_fd;
  int vfio_iommu_mode;

  /* pool of IOMMU groups */
  linux_pci_vfio_iommu_group_t *iommu_groups;

  /* iommu group pool index by group id  hash */
  uword *iommu_pool_index_by_group;

} linux_pci_main_t;

extern linux_pci_main_t linux_pci_main;

linux_pci_device_t *
linux_pci_get_device (vlib_pci_dev_handle_t h)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  return pool_elt_at_index (lpm->linux_pci_devices, h);
}

uword
vlib_pci_get_private_data (vlib_pci_dev_handle_t h)
{
  linux_pci_device_t *d = linux_pci_get_device (h);
  return d->private_data;
}

void
vlib_pci_set_private_data (vlib_pci_dev_handle_t h, uword private_data)
{
  linux_pci_device_t *d = linux_pci_get_device (h);
  d->private_data = private_data;
}

vlib_pci_addr_t *
vlib_pci_get_addr (vlib_pci_dev_handle_t h)
{
  linux_pci_device_t *lpm = linux_pci_get_device (h);
  return &lpm->addr;
}

/* Call to allocate/initialize the pci subsystem.
   This is not an init function so that users can explicitly enable
   pci only when it's needed. */
clib_error_t *pci_bus_init (vlib_main_t * vm);

linux_pci_main_t linux_pci_main;

vlib_pci_device_info_t *
vlib_pci_get_device_info (vlib_pci_addr_t * addr, clib_error_t ** error)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  clib_error_t *err;
  vlib_pci_device_info_t *di;
  u8 *f = 0;
  u32 tmp;
  int fd;

  di = clib_mem_alloc (sizeof (vlib_pci_device_info_t));
  memset (di, 0, sizeof (vlib_pci_device_info_t));
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
  if (read (fd, &di->config_data, sizeof (di->config_data)) !=
      sizeof (di->config_data)
      && read (fd, &di->config0,
	       sizeof (di->config0)) != sizeof (di->config0))
    {
      err = clib_error_return_unix (0, "read `%s'", f);
      close (fd);
      goto error;
    }

  {
    static pci_config_header_t all_ones;
    if (all_ones.vendor_id == 0)
      memset (&all_ones, ~0, sizeof (all_ones));

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
  if (lpm->vfio_container_fd != -1)
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
vlib_pci_bind_to_uio (vlib_pci_addr_t * addr, char *uio_drv_name)
{
  clib_error_t *error = 0;
  u8 *s = 0, *driver_name = 0;
  DIR *dir = 0;
  struct dirent *e;
  vlib_pci_device_info_t *di;
  int fd, clear_driver_override = 0;
  u8 *dev_dir_name = format (0, "%s/%U", sysfs_pci_dev_path,
			     format_vlib_pci_addr, addr);

  di = vlib_pci_get_device_info (addr, &error);

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

      memset (&ifr, 0, sizeof ifr);
      memset (&drvinfo, 0, sizeof drvinfo);
      ifr.ifr_data = (char *) &drvinfo;
      strncpy (ifr.ifr_name, e->d_name, IFNAMSIZ - 1);
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

      memset (&ifr, 0, sizeof (ifr));
      strncpy (ifr.ifr_name, e->d_name, IFNAMSIZ - 1);
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
linux_pci_uio_read_ready (clib_file_t * uf)
{
  int __attribute__ ((unused)) rv;
  vlib_pci_dev_handle_t h = uf->private_data;
  linux_pci_device_t *p = linux_pci_get_device (h);

  u32 icount;
  rv = read (uf->file_descriptor, &icount, 4);

  if (p->interrupt_handler)
    p->interrupt_handler (h);

  vlib_pci_intr_enable (h);

  return /* no error */ 0;
}

static clib_error_t *
linux_pci_vfio_unmask_intx (linux_pci_device_t * d)
{
  clib_error_t *err = 0;
  struct vfio_irq_set i = {
    .argsz = sizeof (struct vfio_irq_set),
    .start = 0,
    .count = 1,
    .index = VFIO_PCI_INTX_IRQ_INDEX,
    .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK,
  };

  if (ioctl (d->vfio_device_fd, VFIO_DEVICE_SET_IRQS, &i) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_SET_IRQS) '%U'",
				    format_vlib_pci_addr, &d->addr);
    }
  return err;
}

static clib_error_t *
linux_pci_uio_error_ready (clib_file_t * uf)
{
  u32 error_index = (u32) uf->private_data;

  return clib_error_return (0, "pci device %d: error", error_index);
}

static clib_error_t *
linux_pci_vfio_read_ready (clib_file_t * uf)
{
  int __attribute__ ((unused)) rv;
  vlib_pci_dev_handle_t h = uf->private_data;
  linux_pci_device_t *p = linux_pci_get_device (h);

  u64 icount;
  rv = read (uf->file_descriptor, &icount, sizeof (icount));

  if (p->interrupt_handler)
    p->interrupt_handler (h);

  linux_pci_vfio_unmask_intx (p);

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
  clib_error_t *err = 0;
  clib_file_t t = { 0 };
  u8 *s = 0;

  p->addr.as_u32 = di->addr.as_u32;
  p->uio_fd = -1;

  s = format (s, "%s/%U/config%c", sysfs_pci_dev_path,
	      format_vlib_pci_addr, &di->addr, 0);

  p->config_fd = open ((char *) s, O_RDWR);
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
  p->uio_fd = open ((char *) s, O_RDWR);
  if (p->uio_fd < 0)
    {
      err = clib_error_return_unix (0, "open '%s'", s);
      goto error;
    }

  t.read_function = linux_pci_uio_read_ready;
  t.file_descriptor = p->uio_fd;
  t.error_function = linux_pci_uio_error_ready;
  t.private_data = p->handle;

  p->clib_file_index = clib_file_add (&file_main, &t);
  p->interrupt_handler = r->interrupt_handler;
  err = r->init_function (vm, p->handle);

error:
  free (s);
  if (err)
    {
      if (p->config_fd != -1)
	close (p->config_fd);
      if (p->uio_fd != -1)
	close (p->uio_fd);
    }
  return err;
}

static linux_pci_vfio_iommu_group_t *
get_vfio_iommu_group (int group)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  uword *p;

  p = hash_get (lpm->iommu_pool_index_by_group, group);

  return p ? pool_elt_at_index (lpm->iommu_groups, p[0]) : 0;
}

static clib_error_t *
open_vfio_iommu_group (int group)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  linux_pci_vfio_iommu_group_t *g;
  clib_error_t *err = 0;
  struct vfio_group_status group_status;
  u8 *s = 0;
  int fd;

  g = get_vfio_iommu_group (group);
  if (g)
    {
      g->refcnt++;
      return 0;
    }
  s = format (s, "/dev/vfio/%u%c", group, 0);
  fd = open ((char *) s, O_RDWR);
  if (fd < 0)
    return clib_error_return_unix (0, "open '%s'", s);

  group_status.argsz = sizeof (group_status);
  if (ioctl (fd, VFIO_GROUP_GET_STATUS, &group_status) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_GROUP_GET_STATUS) '%s'",
				    s);
      goto error;
    }

  if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE))
    {
      err = clib_error_return (0, "iommu group %d is not viable (not all "
			       "devices in this group bound to vfio-pci)",
			       group);
      goto error;
    }

  if (ioctl (fd, VFIO_GROUP_SET_CONTAINER, &lpm->vfio_container_fd) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_GROUP_SET_CONTAINER) '%s'",
				    s);
      goto error;
    }

  if (lpm->vfio_iommu_mode == 0)
    {
      if (ioctl (lpm->vfio_container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) <
	  0)
	{
	  err = clib_error_return_unix (0, "ioctl(VFIO_SET_IOMMU) "
					"'/dev/vfio/vfio'");
	  goto error;
	}
      lpm->vfio_iommu_mode = VFIO_TYPE1_IOMMU;
    }


  pool_get (lpm->iommu_groups, g);
  g->fd = fd;
  g->refcnt = 1;
  hash_set (lpm->iommu_pool_index_by_group, group, g - lpm->iommu_groups);
  vec_free (s);
  return 0;
error:
  close (fd);
  return err;
}

static clib_error_t *
add_device_vfio (vlib_main_t * vm, linux_pci_device_t * p,
		 vlib_pci_device_info_t * di, pci_device_registration_t * r)
{
  linux_pci_vfio_iommu_group_t *g;
  struct vfio_device_info device_info;
  struct vfio_irq_info irq_info = { 0 };
  clib_error_t *err = 0;
  u8 *s = 0;
  int dfd;

  p->addr.as_u32 = di->addr.as_u32;

  if (di->driver_name == 0 ||
      (strcmp ("vfio-pci", (char *) di->driver_name) != 0))
    return clib_error_return (0, "Device '%U' (iommu group %d) not bound to "
			      "vfio-pci", format_vlib_pci_addr, &di->addr,
			      di->iommu_group);

  if ((err = open_vfio_iommu_group (di->iommu_group)))
    return err;

  g = get_vfio_iommu_group (di->iommu_group);

  s = format (s, "%U%c", format_vlib_pci_addr, &di->addr, 0);
  if ((dfd = ioctl (g->fd, VFIO_GROUP_GET_DEVICE_FD, (char *) s)) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_GROUP_GET_DEVICE_FD) '%U'",
				    format_vlib_pci_addr, &di->addr);
      goto error;
    }
  vec_reset_length (s);
  p->vfio_device_fd = dfd;

  device_info.argsz = sizeof (device_info);
  if (ioctl (dfd, VFIO_DEVICE_GET_INFO, &device_info) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_GET_INFO) '%U'",
				    format_vlib_pci_addr, &di->addr);
      goto error;
    }

  irq_info.argsz = sizeof (struct vfio_irq_info);
  irq_info.index = VFIO_PCI_INTX_IRQ_INDEX;
  if (ioctl (dfd, VFIO_DEVICE_GET_IRQ_INFO, &irq_info) < 0)
    {
      err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_GET_IRQ_INFO) "
				    "'%U'", format_vlib_pci_addr, &di->addr);
      goto error;
    }

  /* reset if device supports it */
  if (device_info.flags & VFIO_DEVICE_FLAGS_RESET)
    if (ioctl (dfd, VFIO_DEVICE_RESET) < 0)
      {
	err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_RESET) '%U'",
				      format_vlib_pci_addr, &di->addr);
	goto error;
      }

  if ((irq_info.flags & VFIO_IRQ_INFO_EVENTFD) && irq_info.count == 1)
    {
      u8 buf[sizeof (struct vfio_irq_set) + sizeof (int)] = { 0 };
      struct vfio_irq_set *irq_set = (struct vfio_irq_set *) buf;
      clib_file_t t = { 0 };
      int efd = eventfd (0, EFD_NONBLOCK);

      irq_set->argsz = sizeof (buf);
      irq_set->count = 1;
      irq_set->index = VFIO_PCI_INTX_IRQ_INDEX;
      irq_set->flags =
	VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
      clib_memcpy (&irq_set->data, &efd, sizeof (int));

      if (ioctl (dfd, VFIO_DEVICE_SET_IRQS, irq_set) < 0)
	{
	  err = clib_error_return_unix (0, "ioctl(VFIO_DEVICE_SET_IRQS) '%U'",
					format_vlib_pci_addr, &di->addr);
	  goto error;
	}

      t.read_function = linux_pci_vfio_read_ready;
      t.file_descriptor = efd;
      t.error_function = linux_pci_vfio_error_ready;
      t.private_data = p->handle;
      p->clib_file_index = clib_file_add (&file_main, &t);

      /* unmask the interrupt */
      linux_pci_vfio_unmask_intx (p);
    }

  p->interrupt_handler = r->interrupt_handler;

  s = format (s, "%s/%U/config%c", sysfs_pci_dev_path,
	      format_vlib_pci_addr, &di->addr, 0);

  p->config_fd = open ((char *) s, O_RDWR);
  vec_reset_length (s);

  if (p->config_fd == -1)
    {
      err = clib_error_return_unix (0, "open '%s'", s);
      goto error;
    }

  err = r->init_function (vm, p->handle);

error:
  vec_free (s);
  if (err)
    {
      if (dfd != -1)
	close (dfd);
      if (p->config_fd != -1)
	close (p->config_fd);
    }
  return err;
}

/* Configuration space read/write. */
clib_error_t *
vlib_pci_read_write_config (vlib_pci_dev_handle_t h,
			    vlib_read_or_write_t read_or_write,
			    uword address, void *data, u32 n_bytes)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  int n;

  if (read_or_write == VLIB_READ)
    n = pread (p->config_fd, data, n_bytes, address);
  else
    n = pwrite (p->config_fd, data, n_bytes, address);

  if (n != n_bytes)
    return clib_error_return_unix (0, "%s",
				   read_or_write == VLIB_READ
				   ? "read" : "write");

  return 0;
}

static clib_error_t *
vlib_pci_map_resource_int (vlib_pci_dev_handle_t h,
			   u32 resource, u8 * addr, void **result)
{
  linux_pci_device_t *p = linux_pci_get_device (h);
  struct stat stat_buf;
  u8 *file_name;
  int fd;
  clib_error_t *error;
  int flags = MAP_SHARED;

  error = 0;

  file_name = format (0, "%s/%U/resource%d%c", sysfs_pci_dev_path,
		      format_vlib_pci_addr, &p->addr, resource, 0);

  fd = open ((char *) file_name, O_RDWR);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "open `%s'", file_name);
      goto done;
    }

  if (fstat (fd, &stat_buf) < 0)
    {
      error = clib_error_return_unix (0, "fstat `%s'", file_name);
      goto done;
    }

  vec_validate (p->resource_fds, resource);
  p->resource_fds[resource] = fd;
  if (addr != 0)
    flags |= MAP_FIXED;

  *result = mmap (addr,
		  /* size */ stat_buf.st_size,
		  PROT_READ | PROT_WRITE, flags,
		  /* file */ fd,
		  /* offset */ 0);
  if (*result == (void *) -1)
    {
      error = clib_error_return_unix (0, "mmap `%s'", file_name);
      goto done;
    }

done:
  if (error)
    {
      if (fd >= 0)
	close (fd);
    }
  vec_free (file_name);
  return error;
}

clib_error_t *
vlib_pci_map_resource (vlib_pci_dev_handle_t h, u32 resource, void **result)
{
  return (vlib_pci_map_resource_int (h, resource, 0 /* addr */ , result));
}

clib_error_t *
vlib_pci_map_resource_fixed (vlib_pci_dev_handle_t h,
			     u32 resource, u8 * addr, void **result)
{
  return (vlib_pci_map_resource_int (h, resource, addr, result));
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
  memset (p, 0, sizeof (linux_pci_device_t));
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
  linux_pci_main_t *lpm = &linux_pci_main;
  vlib_pci_addr_t *addr = 0, *addrs;
  clib_error_t *error;
  int fd;

  pm->vlib_main = vm;

  if ((error = vlib_call_init_function (vm, unix_input_init)))
    return error;

  ASSERT (sizeof (vlib_pci_addr_t) == sizeof (u32));

  fd = open ("/dev/vfio/vfio", O_RDWR);

  if ((fd != -1) && (ioctl (fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION))
    {
      close (fd);
      fd = -1;
    }

  if ((fd != -1) && (ioctl (fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU) == 0))
    {
      close (fd);
      fd = -1;
    }

  lpm->vfio_container_fd = fd;
  lpm->iommu_pool_index_by_group = hash_create (0, sizeof (uword));

  addrs = vlib_pci_get_all_dev_addrs ();
  /* *INDENT-OFF* */
  vec_foreach (addr, addrs)
    {
      vlib_pci_device_info_t *d;
      if ((d = vlib_pci_get_device_info (addr, 0)))
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
