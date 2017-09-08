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

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>
#include <vlib/linux/sysfs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

typedef struct
{
  /* /sys/bus/pci/devices/... directory name for this device. */
  u8 *dev_dir_name;

  /* Resource file descriptors. */
  int *resource_fds;

  /* File descriptor for config space read/write. */
  int config_fd;

  /* File descriptor for /dev/uio%d */
  int uio_fd;

  /* Minor device for uio device. */
  u32 uio_minor;

  /* Index given by clib_file_add. */
  u32 clib_file_index;

} linux_pci_device_t;

/* Pool of PCI devices. */
typedef struct
{
  vlib_main_t *vlib_main;
  linux_pci_device_t *linux_pci_devices;
} linux_pci_main_t;

extern linux_pci_main_t linux_pci_main;

/* Call to allocate/initialize the pci subsystem.
   This is not an init function so that users can explicitly enable
   pci only when it's needed. */
clib_error_t *pci_bus_init (vlib_main_t * vm);

clib_error_t *vlib_pci_bind_to_uio (vlib_pci_device_t * d,
				    char *uio_driver_name);

linux_pci_main_t linux_pci_main;

clib_error_t *
vlib_pci_bind_to_uio (vlib_pci_device_t * d, char *uio_driver_name)
{
  clib_error_t *error = 0;
  u8 *s = 0, *driver_name = 0;
  DIR *dir = 0;
  struct dirent *e;
  int fd, clear_driver_override = 0;
  u8 *dev_dir_name = format (0, "/sys/bus/pci/devices/%U",
			     format_vlib_pci_addr, &d->bus_address);

  s = format (s, "%v/driver%c", dev_dir_name, 0);
  driver_name = vlib_sysfs_link_to_name ((char *) s);
  vec_reset_length (s);

  if (driver_name &&
      ((strcmp ("vfio-pci", (char *) driver_name) == 0) ||
       (strcmp ("uio_pci_generic", (char *) driver_name) == 0) ||
       (strcmp ("igb_uio", (char *) driver_name) == 0)))
    goto done;

  /* walk trough all linux interfaces and if interface belonging to
     this device is founf check if interface is admin up  */
  dir = opendir ("/sys/class/net");
  s = format (s, "%U%c", format_vlib_pci_addr, &d->bus_address, 0);

  if (!dir)
    {
      error = clib_error_return (0, "Skipping PCI device %U: failed to "
				 "read /sys/class/net",
				 format_vlib_pci_addr, &d->bus_address);
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
				     format_vlib_pci_addr, &d->bus_address,
				     e->d_name);
	  close (fd);
	  goto done;
	}
    }

  close (fd);
  vec_reset_length (s);

  s = format (s, "%v/driver/unbind%c", dev_dir_name, 0);
  vlib_sysfs_write ((char *) s, "%U", format_vlib_pci_addr, &d->bus_address);
  vec_reset_length (s);

  s = format (s, "%v/driver_override%c", dev_dir_name, 0);
  if (access ((char *) s, F_OK) == 0)
    {
      vlib_sysfs_write ((char *) s, "%s", uio_driver_name);
      clear_driver_override = 1;
    }
  else
    {
      vec_reset_length (s);
      s = format (s, "/sys/bus/pci/drivers/%s/new_id%c", uio_driver_name, 0);
      vlib_sysfs_write ((char *) s, "0x%04x 0x%04x", d->vendor_id,
			d->device_id);
    }
  vec_reset_length (s);

  s = format (s, "/sys/bus/pci/drivers/%s/bind%c", uio_driver_name, 0);
  vlib_sysfs_write ((char *) s, "%U", format_vlib_pci_addr, &d->bus_address);
  vec_reset_length (s);

  if (clear_driver_override)
    {
      s = format (s, "%v/driver_override%c", dev_dir_name, 0);
      vlib_sysfs_write ((char *) s, "%c", 0);
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
  vlib_pci_main_t *pm = &pci_main;
  vlib_pci_device_t *d;
  int __attribute__ ((unused)) rv;

  u32 icount;
  rv = read (uf->file_descriptor, &icount, 4);

  d = pool_elt_at_index (pm->pci_devs, uf->private_data);

  if (d->interrupt_handler)
    d->interrupt_handler (d);

  vlib_pci_intr_enable (d);

  return /* no error */ 0;
}

static clib_error_t *
linux_pci_uio_error_ready (clib_file_t * uf)
{
  u32 error_index = (u32) uf->private_data;

  return clib_error_return (0, "pci device %d: error", error_index);
}

static void
add_device (vlib_pci_device_t * dev, linux_pci_device_t * pdev)
{
  vlib_pci_main_t *pm = &pci_main;
  linux_pci_main_t *lpm = &linux_pci_main;
  linux_pci_device_t *l;

  pool_get (lpm->linux_pci_devices, l);
  l[0] = pdev[0];

  l->dev_dir_name = vec_dup (l->dev_dir_name);

  dev->os_handle = l - lpm->linux_pci_devices;

  {
    u8 *uio_dir = format (0, "%s/uio", l->dev_dir_name);
    foreach_directory_file ((char *) uio_dir, scan_uio_dir, l,	/* scan_dirs */
			    1);
    vec_free (uio_dir);
  }

  {
    char *uio_name = (char *) format (0, "/dev/uio%d%c", l->uio_minor, 0);
    l->uio_fd = open (uio_name, O_RDWR);
    if (l->uio_fd < 0)
      clib_unix_error ("open `%s'", uio_name);
    vec_free (uio_name);
  }

  {
    clib_file_t template = { 0 };

    template.read_function = linux_pci_uio_read_ready;
    template.file_descriptor = l->uio_fd;
    template.error_function = linux_pci_uio_error_ready;
    template.private_data = dev - pm->pci_devs;

    l->clib_file_index = clib_file_add (&file_main, &template);
  }
}

static void
linux_pci_device_free (linux_pci_device_t * l)
{
  int i;
  for (i = 0; i < vec_len (l->resource_fds); i++)
    if (l->resource_fds[i] > 0)
      close (l->resource_fds[i]);
  if (l->config_fd > 0)
    close (l->config_fd);
  if (l->uio_fd > 0)
    close (l->uio_fd);
  vec_free (l->resource_fds);
  vec_free (l->dev_dir_name);
}

/* Configuration space read/write. */
clib_error_t *
vlib_pci_read_write_config (vlib_pci_device_t * dev,
			    vlib_read_or_write_t read_or_write,
			    uword address, void *data, u32 n_bytes)
{
  linux_pci_main_t *lpm = &linux_pci_main;
  linux_pci_device_t *p;
  int n;

  p = pool_elt_at_index (lpm->linux_pci_devices, dev->os_handle);

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
os_map_pci_resource_internal (uword os_handle,
			      u32 resource, u8 * addr, void **result)
{
  linux_pci_main_t *pm = &linux_pci_main;
  linux_pci_device_t *p;
  struct stat stat_buf;
  u8 *file_name;
  int fd;
  clib_error_t *error;
  int flags = MAP_SHARED;

  error = 0;
  p = pool_elt_at_index (pm->linux_pci_devices, os_handle);

  file_name = format (0, "%v/resource%d%c", p->dev_dir_name, resource, 0);
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
vlib_pci_map_resource (vlib_pci_device_t * dev, u32 resource, void **result)
{
  return (os_map_pci_resource_internal
	  (dev->os_handle, resource, 0 /* addr */ ,
	   result));
}

clib_error_t *
vlib_pci_map_resource_fixed (vlib_pci_device_t * dev,
			     u32 resource, u8 * addr, void **result)
{
  return (os_map_pci_resource_internal
	  (dev->os_handle, resource, addr, result));
}

void
vlib_pci_free_device (vlib_pci_device_t * dev)
{
  linux_pci_main_t *pm = &linux_pci_main;
  linux_pci_device_t *l;

  l = pool_elt_at_index (pm->linux_pci_devices, dev->os_handle);
  linux_pci_device_free (l);
  pool_put (pm->linux_pci_devices, l);
}

pci_device_registration_t * __attribute__ ((unused))
pci_device_next_registered (pci_device_registration_t * r)
{
  uword i;

  /* Null vendor id marks end of initialized list. */
  for (i = 0; r->supported_devices[i].vendor_id != 0; i++)
    ;

  return clib_elf_section_data_next (r, i * sizeof (r->supported_devices[0]));
}

static clib_error_t *
init_device_from_registered (vlib_main_t * vm,
			     vlib_pci_device_t * dev,
			     linux_pci_device_t * pdev)
{
  vlib_pci_main_t *pm = &pci_main;
  pci_device_registration_t *r;
  pci_device_id_t *i;
  clib_error_t *error;

  r = pm->pci_device_registrations;

  while (r)
    {
      for (i = r->supported_devices; i->vendor_id != 0; i++)
	if (i->vendor_id == dev->vendor_id && i->device_id == dev->device_id)
	  {
	    error = vlib_pci_bind_to_uio (dev, "uio_pci_generic");
	    if (error)
	      {
		clib_error_report (error);
		continue;
	      }

	    add_device (dev, pdev);
	    dev->interrupt_handler = r->interrupt_handler;
	    return r->init_function (vm, dev);
	  }
      r = r->next_registration;
    }
  /* No driver, close the PCI config-space FD */
  close (pdev->config_fd);
  return 0;
}

static clib_error_t *
init_device (vlib_main_t * vm,
	     vlib_pci_device_t * dev, linux_pci_device_t * pdev)
{
  return init_device_from_registered (vm, dev, pdev);
}

static clib_error_t *
scan_device (void *arg, u8 * dev_dir_name, u8 * ignored)
{
  vlib_main_t *vm = arg;
  vlib_pci_main_t *pm = &pci_main;
  int fd;
  u8 *f;
  clib_error_t *error = 0;
  vlib_pci_device_t *dev;
  linux_pci_device_t pdev = { 0 };
  u32 tmp;

  f = format (0, "%v/config%c", dev_dir_name, 0);
  fd = open ((char *) f, O_RDWR);

  /* Try read-only access if write fails. */
  if (fd < 0)
    fd = open ((char *) f, O_RDONLY);

  if (fd < 0)
    {
      error = clib_error_return_unix (0, "open `%s'", f);
      goto done;
    }

  pool_get (pm->pci_devs, dev);

  /* You can only read more that 64 bytes of config space as root; so we try to
     read the full space but fall back to just the first 64 bytes. */
  if (read (fd, &dev->config_data, sizeof (dev->config_data)) !=
      sizeof (dev->config_data)
      && read (fd, &dev->config0,
	       sizeof (dev->config0)) != sizeof (dev->config0))
    {
      pool_put (pm->pci_devs, dev);
      error = clib_error_return_unix (0, "read `%s'", f);
      close (fd);
      goto done;
    }

  {
    static pci_config_header_t all_ones;
    if (all_ones.vendor_id == 0)
      memset (&all_ones, ~0, sizeof (all_ones));

    if (!memcmp (&dev->config0.header, &all_ones, sizeof (all_ones)))
      {
	pool_put (pm->pci_devs, dev);
	error = clib_error_return (0, "invalid PCI config for `%s'", f);
	close (fd);
	goto done;
      }
  }

  if (dev->config0.header.header_type == 0)
    pci_config_type0_little_to_host (&dev->config0);
  else
    pci_config_type1_little_to_host (&dev->config1);

  /* Parse bus, dev, function from directory name. */
  {
    unformat_input_t input;

    unformat_init_string (&input, (char *) dev_dir_name,
			  vec_len (dev_dir_name));

    if (!unformat (&input, "/sys/bus/pci/devices/%U",
		   unformat_vlib_pci_addr, &dev->bus_address))
      abort ();

    unformat_free (&input);

  }


  pdev.config_fd = fd;
  pdev.dev_dir_name = dev_dir_name;

  hash_set (pm->pci_dev_index_by_pci_addr, dev->bus_address.as_u32,
	    dev - pm->pci_devs);

  vec_reset_length (f);
  f = format (f, "%v/vpd%c", dev_dir_name, 0);
  fd = open ((char *) f, O_RDONLY);
  if (fd >= 0)
    {
      while (1)
	{
	  u8 tag[3];
	  u8 *data = 0;
	  int len;

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
	    dev->product_name = data;
	  else if (tag[0] == 0x90)
	    dev->vpd_r = data;
	  else if (tag[0] == 0x91)
	    dev->vpd_w = data;

	  data = 0;
	}
      close (fd);
    }

  dev->numa_node = -1;
  vec_reset_length (f);
  f = format (f, "%v/numa_node%c", dev_dir_name, 0);
  vlib_sysfs_read ((char *) f, "%u", &dev->numa_node);

  vec_reset_length (f);
  f = format (f, "%v/class%c", dev_dir_name, 0);
  vlib_sysfs_read ((char *) f, "0x%x", &tmp);
  dev->device_class = tmp >> 8;

  vec_reset_length (f);
  f = format (f, "%v/vendor%c", dev_dir_name, 0);
  vlib_sysfs_read ((char *) f, "0x%x", &tmp);
  dev->vendor_id = tmp;

  vec_reset_length (f);
  f = format (f, "%v/device%c", dev_dir_name, 0);
  vlib_sysfs_read ((char *) f, "0x%x", &tmp);
  dev->device_id = tmp;

  error = init_device (vm, dev, &pdev);

  vec_reset_length (f);
  f = format (f, "%v/driver%c", dev_dir_name, 0);
  dev->driver_name = vlib_sysfs_link_to_name ((char *) f);

done:
  vec_free (f);
  return error;
}

clib_error_t *
linux_pci_init (vlib_main_t * vm)
{
  vlib_pci_main_t *pm = &pci_main;
  clib_error_t *error;

  pm->vlib_main = vm;

  if ((error = vlib_call_init_function (vm, unix_input_init)))
    return error;

  ASSERT (sizeof (vlib_pci_addr_t) == sizeof (u32));
  pm->pci_dev_index_by_pci_addr = hash_create (0, sizeof (uword));

  error = foreach_directory_file ("/sys/bus/pci/devices", scan_device, vm,
				  /* scan_dirs */ 0);

  /* Complain and continue. might not be root, etc. */
  if (error)
    clib_error_report (error);

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
