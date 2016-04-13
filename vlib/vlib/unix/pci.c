/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vlib/unix/pci.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>


linux_pci_main_t linux_pci_main;

clib_error_t *
vlib_pci_bind_to_uio (vlib_pci_device_t * d, char * uio_driver_name)
{
  clib_error_t * error = 0;
  u8 *s = 0;
  DIR *dir = 0;
  struct dirent *e;
  int fd;
  pci_config_header_t * c;
  u8 * dev_dir_name = format(0, "/sys/bus/pci/devices/%U",
			     format_vlib_pci_addr, &d->bus_address);

  c = &d->config0.header;

  /* if uio sub-directory exists, we are fine, device is
     already bound to UIO driver */
  s = format (s, "%v/uio%c", dev_dir_name, 0);
  if (access ( (char *) s, F_OK) == 0)
    goto done;
  vec_reset_length (s);

  /* walk trough all linux interfaces and if interface belonging to
     this device is founf check if interface is admin up  */
  dir = opendir ("/sys/class/net");
  s = format(s, "%U%c", format_vlib_pci_addr, &d->bus_address, 0);

  if (!dir)
    {
      error = clib_error_return (0, "Skipping PCI device %U: failed to "
				 "read /sys/class/net",
				 format_vlib_pci_addr, &d->bus_address);
      goto done;
    }

  fd = socket(PF_INET, SOCK_DGRAM, 0);

  while((e = readdir (dir)))
    {
      struct ifreq ifr;
      struct ethtool_drvinfo drvinfo;

      if (e->d_name[0] == '.') /* skip . and .. */
	continue;

      memset(&ifr, 0, sizeof ifr);
      memset(&drvinfo, 0, sizeof drvinfo);
      ifr.ifr_data = (char *) &drvinfo;
      strncpy(ifr.ifr_name, e->d_name, IFNAMSIZ);
      drvinfo.cmd = ETHTOOL_GDRVINFO;
      ioctl (fd, SIOCETHTOOL, &ifr);

      if (strcmp ((char *) s, drvinfo.bus_info))
	continue;

      memset (&ifr, 0, sizeof(ifr));
      strncpy (ifr.ifr_name, e->d_name, IFNAMSIZ);
      ioctl (fd, SIOCGIFFLAGS, &ifr);
      close (fd);

      if (ifr.ifr_flags & IFF_UP)
	{
	  error = clib_error_return (0, "Skipping PCI device %U as host "
				     "interface %s is up",
				     format_vlib_pci_addr, &d->bus_address,
				     e->d_name);
	  goto done;
	}
    }

  close (fd);
  vec_reset_length (s);

  s = format (s, "%v/driver/unbind%c", dev_dir_name, 0);
  write_sys_fs ((char *) s, "%U", format_vlib_pci_addr, &d->bus_address);
  vec_reset_length (s);

  s = format (s, "/sys/bus/pci/drivers/%s/new_id%c", uio_driver_name, 0);
  write_sys_fs ((char *) s, "0x%04x 0x%04x", c->vendor_id, c->device_id);
  vec_reset_length (s);

  s = format (s, "/sys/bus/pci/drivers/%s/bind%c", uio_driver_name, 0);
  write_sys_fs ((char *) s, "%U", format_vlib_pci_addr, &d->bus_address);

done:
  closedir (dir);
  vec_free (s);
  vec_free (dev_dir_name);
  return error;
}


static clib_error_t *
scan_uio_dir (void * arg, u8 * path_name, u8 * file_name)
{
  linux_pci_device_t * l = arg;
  unformat_input_t input;

  unformat_init_string (&input, (char *) file_name, vec_len (file_name));

  if (! unformat (&input, "uio%d", &l->uio_minor))
    abort ();

  unformat_free (&input);
  return 0;
}

static clib_error_t * linux_pci_uio_read_ready (unix_file_t * uf)
{
  linux_pci_main_t * pm = &linux_pci_main;
  vlib_main_t * vm = pm->vlib_main;
  linux_pci_device_t * l;
  u32 li = uf->private_data;

  l = pool_elt_at_index (pm->linux_pci_devices, li);
  vlib_node_set_interrupt_pending (vm, l->device_input_node_index);

  /* Let node know which device is interrupting. */
  {
    vlib_node_runtime_t * rt = vlib_node_get_runtime (vm, l->device_input_node_index);
    rt->runtime_data[0] |= 1 << l->device_index;
  }

  return /* no error */ 0;
}

static clib_error_t *linux_pci_uio_error_ready (unix_file_t *uf)
{
  u32 error_index = (u32) uf->private_data;

  return clib_error_return (0, "pci device %d: error", error_index);
}

static uword pci_resource_size (uword os_handle, uword resource)
{
  linux_pci_main_t * pm = &linux_pci_main;
  linux_pci_device_t * p;
  u8 * file_name;
  struct stat b;
  uword result = 0;

  p = pool_elt_at_index (pm->linux_pci_devices, os_handle);

  file_name = format (0, "%v/resource%d%c", p->dev_dir_name, resource, 0);
  if (stat ((char *) file_name, &b) >= 0)
    result = b.st_size;
  vec_free (file_name);
  return result;
}

void os_add_pci_disable_interrupts_reg (uword os_handle, u32 resource,
					u32 reg_offset, u32 reg_value)
{
  linux_pci_main_t * pm = &linux_pci_main;
  linux_pci_device_t * l;
  char * file_name;
  clib_error_t * error;

  l = pool_elt_at_index (pm->linux_pci_devices, os_handle);
  ASSERT (resource == 0);
  ASSERT (reg_offset < pci_resource_size (os_handle, resource));
  file_name = (char *) format (0, "%s/disable_interrupt_regs%c", l->dev_dir_name, 0);
  error = write_sys_fs (file_name, "%x %x", reg_offset, reg_value);
  if (error)
    clib_error_report (error);
  vec_free (file_name);
}

static void add_device (vlib_pci_device_t * dev, linux_pci_device_t * pdev)
{
  linux_pci_main_t * pm = &linux_pci_main;
  linux_pci_device_t * l;
  pci_config_header_t * c;
  u32 x[4];
  clib_error_t * error;

  c = &dev->config0.header;

  pool_get (pm->linux_pci_devices, l);
  l[0] = pdev[0];

  l->dev_dir_name = vec_dup (l->dev_dir_name);

  dev->os_handle = l - pm->linux_pci_devices;

  error = write_sys_fs ("/sys/bus/pci/drivers/uio_pci_dma/new_id",
			"%x %x", c->vendor_id, c->device_id);
  if (error)
    clib_error_report (error);
  error = write_sys_fs ("/sys/bus/pci/drivers/uio_pci_dma/bind",
			"%04x:%02x:%02x.%x", x[0], x[1], x[2], x[3]);
  /* Errors happen when re-binding so just ignore them. */
  if (error)
    clib_error_free (error);

  {
    u8 * uio_dir = format (0, "%s/uio", l->dev_dir_name);
    foreach_directory_file ((char *) uio_dir, scan_uio_dir, l, /* scan_dirs */ 1);
    vec_free (uio_dir);
  }

  {
    char * uio_name = (char *) format (0, "/dev/uio%d%c", l->uio_minor, 0);
    l->uio_fd = open (uio_name, O_RDWR);
    if (l->uio_fd < 0)
      clib_unix_error ("open `%s'", uio_name);
    vec_free (uio_name);
  }

  {
    unix_file_t template = {0};
    unix_main_t * um = &unix_main;

    template.read_function = linux_pci_uio_read_ready;
    template.file_descriptor = l->uio_fd;
    template.error_function = linux_pci_uio_error_ready;
    template.private_data = l - pm->linux_pci_devices;

    /* To be filled in by driver. */
    l->device_input_node_index = ~0;
    l->device_index = 0;

    l->unix_file_index = unix_file_add (um, &template);
  }
}

static void linux_pci_device_free (linux_pci_device_t * l)
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
os_read_write_pci_config (uword os_handle,
			  vlib_read_or_write_t read_or_write,
			  uword address,
			  void * data,
			  u32 n_bytes)
{
  linux_pci_main_t * pm = &linux_pci_main;
  linux_pci_device_t * p;
  int n;

  p = pool_elt_at_index (pm->linux_pci_devices, os_handle);

  if (address != lseek (p->config_fd, address, SEEK_SET))
    return clib_error_return_unix (0, "seek offset %d", address);

  if (read_or_write == VLIB_READ)
    n = read (p->config_fd, data, n_bytes);
  else
    n = write (p->config_fd, data, n_bytes);

  if (n != n_bytes)
    return clib_error_return_unix (0, "%s",
				   read_or_write == VLIB_READ
				   ? "read" : "write");

  return 0;
}

static clib_error_t *
os_map_pci_resource_internal (uword os_handle,
                              u32 resource,
                              u8 *addr,
                              void ** result)
{
  linux_pci_main_t * pm = &linux_pci_main;
  linux_pci_device_t * p;
  struct stat stat_buf;
  u8 * file_name;
  int fd;
  clib_error_t * error;
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
		  PROT_READ | PROT_WRITE,
                  flags,
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
      if (fd > 0)
	close (fd);
    }
  vec_free (file_name);
  return error;
}

clib_error_t *
os_map_pci_resource (uword os_handle,
		     u32 resource,
		     void ** result)
{
  return (os_map_pci_resource_internal (os_handle, resource, 0 /* addr */,
                                        result));
}

clib_error_t *
os_map_pci_resource_fixed (uword os_handle,
                           u32 resource,
                           u8 *addr,
                           void ** result)
{
  return (os_map_pci_resource_internal (os_handle, resource, addr, result));
}

void os_free_pci_device (uword os_handle)
{
  linux_pci_main_t * pm = &linux_pci_main;
  linux_pci_device_t * l;

  l = pool_elt_at_index (pm->linux_pci_devices, os_handle);
  linux_pci_device_free (l);
  pool_put (pm->linux_pci_devices, l);
}

u8 * format_os_pci_handle (u8 * s, va_list * va)
{
  linux_pci_main_t * pm = &linux_pci_main;
  uword os_pci_handle = va_arg (*va, uword);
  linux_pci_device_t * l;

  l = pool_elt_at_index (pm->linux_pci_devices, os_pci_handle);
  return format (s, "%x/%x/%x", l->bus_address.bus,
		 l->bus_address.slot, l->bus_address.function);
}

static inline pci_device_registration_t *
pci_device_next_registered (pci_device_registration_t * r)
{
  uword i;

  /* Null vendor id marks end of initialized list. */
  for (i = 0; r->supported_devices[i].vendor_id != 0; i++)
    ;

  return clib_elf_section_data_next (r, i * sizeof (r->supported_devices[0]));
}

static inline u8 kernel_driver_installed (pci_device_registration_t *r)
{
  u8 * link_name;
  struct stat b;

  link_name = format (0, "/sys/bus/pci/drivers/%s", r->kernel_driver);
  if (stat ((char *)link_name, &b) >= 0)
    r->kernel_driver_running++;
  else
    r->kernel_driver_running=0;

  vec_free (link_name);
  return r->kernel_driver_running;
}

static clib_error_t *
init_device_from_registered (vlib_main_t * vm,
			     vlib_pci_device_t * dev,
			     linux_pci_device_t * pdev)
{
  linux_pci_main_t * lpm = &linux_pci_main;
  pci_device_registration_t * r;
  pci_device_id_t * i;
  pci_config_header_t * c;

  c = &dev->config0.header;

  r = lpm->pci_device_registrations;

  while (r)
    {
      for (i = r->supported_devices; i->vendor_id != 0; i++)
        if (i->vendor_id == c->vendor_id && i->device_id == c->device_id)
          {
            if (r->kernel_driver && kernel_driver_installed(r))
              {
                if (r->kernel_driver_running == 1)
                  {
                    clib_warning("PCI device type [%04x:%04x] is busy!\n"
                                 "\tUninstall the associated linux kernel "
                                 "driver:  sudo rmmod %s",
                                 c->vendor_id, c->device_id, r->kernel_driver);
                  }
                continue;
              }
            add_device (dev, pdev);
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
	     vlib_pci_device_t * dev,
	     linux_pci_device_t * pdev)
{
  return init_device_from_registered (vm, dev, pdev);
}

static clib_error_t *
scan_device (void * arg, u8 * dev_dir_name, u8 * ignored)
{
  vlib_main_t * vm = arg;
  linux_pci_main_t * pm = &linux_pci_main;
  int fd;
  u8 * f;
  clib_error_t * error = 0;
  vlib_pci_device_t * dev;
  linux_pci_device_t pdev = {0};

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
  if (read (fd, &dev->config_data, sizeof (dev->config_data)) != sizeof (dev->config_data)
      && read (fd, &dev->config0, sizeof (dev->config0)) != sizeof (dev->config0))
    {
      pool_put (pm->pci_devs, dev);
      error = clib_error_return_unix (0, "read `%s'", f);
      goto done;
    }

  {
    static pci_config_header_t all_ones;
    if (all_ones.vendor_id == 0)
      memset (&all_ones, ~0, sizeof (all_ones));

    if (! memcmp (&dev->config0.header, &all_ones, sizeof (all_ones)))
      {
        pool_put (pm->pci_devs, dev);
	error = clib_error_return (0, "invalid PCI config for `%s'", f);
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

    if (! unformat (&input, "/sys/bus/pci/devices/%U",
		    unformat_vlib_pci_addr, &dev->bus_address))
      abort ();

    unformat_free (&input);

    pdev.bus_address = dev->bus_address;
  }


  pdev.config_fd = fd;
  pdev.dev_dir_name = dev_dir_name;

  hash_set(pm->pci_dev_index_by_pci_addr, dev->bus_address.as_u32,
	   dev - pm->pci_devs);

  error = init_device (vm, dev, &pdev);

 done:
  vec_free (f);
  return error;
}

clib_error_t * pci_bus_init (vlib_main_t * vm)
{
  linux_pci_main_t * pm = &linux_pci_main;
  clib_error_t * error;

  pm->vlib_main = vm;

  if ((error = vlib_call_init_function (vm, unix_input_init)))
    return error;

  ASSERT(sizeof(vlib_pci_addr_t) == sizeof(u32));
  pm->pci_dev_index_by_pci_addr = hash_create (0, sizeof (uword));

  error = foreach_directory_file ("/sys/bus/pci/devices", scan_device, vm, /* scan_dirs */ 0);

  /* Complain and continue. might not be root, etc. */
  if (error)
    clib_error_report (error);

  return error;
}

VLIB_INIT_FUNCTION (pci_bus_init);
