/*
 * Copyright (c) 2018, Microsoft Corporation.
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
 * vmbus.c: Linux user space VMBus bus management.
 */

#include <vppinfra/linux/sysfs.h>

#include <vlib/vlib.h>
#include <vlib/vmbus/vmbus.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

static const char sysfs_vmbus_dev_path[] = "/sys/bus/vmbus/devices";
static const char sysfs_vmbus_drv_path[] = "/sys/bus/vmbus/drivers";
static const char sysfs_class_net_path[] = "/sys/class/net";
static const char uio_drv_name[] = "uio_hv_generic";
static const char vmbus_netvsc_uuid[] =
  "f8615163-df3e-46c5-913f-f2d2f965ed0e";

typedef struct
{
  int fd;
  void *addr;
  size_t size;
} linux_vmbus_region_t;

typedef struct
{
  int fd;
  u32 clib_file_index;
} linux_vmbus_irq_t;

typedef struct
{
  vlib_vmbus_dev_handle_t handle;
  vlib_vmbus_addr_t addr;

  /* Device File descriptor */
  int fd;

  /* Minor device for uio device. */
  u32 uio_minor;

  /* private data */
  uword private_data;

} linux_vmbus_device_t;

/* Pool of VMBUS devices. */
typedef struct
{
  vlib_main_t *vlib_main;
  linux_vmbus_device_t *linux_vmbus_devices;

} linux_vmbus_main_t;

linux_vmbus_main_t linux_vmbus_main;

static linux_vmbus_device_t *
linux_vmbus_get_device (vlib_vmbus_dev_handle_t h)
{
  linux_vmbus_main_t *lpm = &linux_vmbus_main;
  return pool_elt_at_index (lpm->linux_vmbus_devices, h);
}

uword
vlib_vmbus_get_private_data (vlib_vmbus_dev_handle_t h)
{
  linux_vmbus_device_t *d = linux_vmbus_get_device (h);
  return d->private_data;
}

void
vlib_vmbus_set_private_data (vlib_vmbus_dev_handle_t h, uword private_data)
{
  linux_vmbus_device_t *d = linux_vmbus_get_device (h);
  d->private_data = private_data;
}

vlib_vmbus_addr_t *
vlib_vmbus_get_addr (vlib_vmbus_dev_handle_t h)
{
  linux_vmbus_device_t *d = linux_vmbus_get_device (h);
  return &d->addr;
}

/* Call to allocate/initialize the vmbus subsystem.
   This is not an init function so that users can explicitly enable
   vmbus only when it's needed. */
clib_error_t *vmbus_bus_init (vlib_main_t * vm);

linux_vmbus_main_t linux_vmbus_main;


clib_error_t *
vlib_vmbus_bind_to_uio (vlib_vmbus_addr_t * addr)
{
  clib_error_t *error = 0;
  static int uio_new_id_needed = 1;
  u8 *s, *driver_name;
  u8 *dev_dir_name;
  struct dirent *e;
  u8 *lnk = 0;
  DIR *dir;

  dev_dir_name = format (0, "%s/%U", sysfs_vmbus_dev_path,
			 format_vlib_vmbus_addr, addr);
  s = format (0, "%v/driver%c", dev_dir_name, 0);

  driver_name = clib_sysfs_link_to_name ((char *) s);
  vec_reset_length (s);

  /* skip if not using the Linux kernel netvsc driver */
  if (!driver_name || strcmp ("hv_netvsc", (char *) driver_name) != 0)
    goto done;

  /* walk through all linux interfaces and find the device */
  dir = opendir (sysfs_class_net_path);

  if (!dir)
    {
      error = clib_error_return (0,
				 "VMBUS device %U: failed to read %s",
				 format_vlib_vmbus_addr, addr,
				 sysfs_class_net_path);
      goto done;
    }

  /* expected symlink for the /sys/class/net/ethN/device */
  lnk = format (0, "../../../%U", format_vlib_vmbus_addr, addr);

  error = clib_error_return (0,
			     "VMBUS device %U not found",
			     format_vlib_vmbus_addr, addr);

  while ((e = readdir (dir)))
    {
      char path[PATH_MAX];
      u32 flags;
      int ret;

      if (e->d_name[0] == '.')	/* skip . and .. */
	continue;

      s = format (s, "%s/%s/device%c", sysfs_class_net_path, e->d_name, 0);

      /* skip non-physical devices */
      ret = readlink ((char *) s, path, PATH_MAX - 1);
      vec_reset_length (s);

      if (ret < 0)
	continue;

      if (strncmp (path, (char *) lnk, ret))
	continue;

      /* read up/down flags */
      s = format (s, "%s/%s/flags%c", sysfs_class_net_path, e->d_name, 0);
      error = clib_sysfs_read ((char *) s, "0x%x", &flags);
      vec_reset_length (s);

      if (error)
	break;

      if (flags & IFF_UP)
	{
	  error = clib_error_return (0,
				     "Skipping VMBUS device %U as host interface %s is up",
				     format_vlib_vmbus_addr, addr, e->d_name);
	  break;
	}
    }

  closedir (dir);
  if (error)
    goto done;

  /* tell uio_hv_generic about netvsc device type */
  if (uio_new_id_needed)
    {
      uio_new_id_needed = 0;

      s = format (s, "%s/%s/new_id%c", sysfs_vmbus_drv_path, uio_drv_name, 0);
      error = clib_sysfs_write ((char *) s, "%s", vmbus_netvsc_uuid);

      if (error)
	goto done;

      vec_reset_length (s);
    }


  /* prefer the simplier driver_override model */
  s = format (s, "%v/driver_override%c", dev_dir_name, 0);
  if (access ((char *) s, F_OK) == 0)
    {
      clib_sysfs_write ((char *) s, "%s", uio_drv_name);
    }
  else
    {
      vec_reset_length (s);

      s = format (s, "%v/driver/unbind%c", dev_dir_name, 0);
      error =
	clib_sysfs_write ((char *) s, "%U", format_vlib_vmbus_addr, addr);

      if (error)
	goto done;

      vec_reset_length (s);

      s = format (s, "%s/%s/bind%c", sysfs_vmbus_drv_path, uio_drv_name, 0);
      error =
	clib_sysfs_write ((char *) s, "%U", format_vlib_vmbus_addr, addr);
    }
  vec_reset_length (s);

done:
  vec_free (s);
  vec_free (lnk);
  vec_free (dev_dir_name);
  vec_free (driver_name);
  return error;
}

static clib_error_t *
scan_vmbus_addr (void *arg, u8 * dev_dir_name, u8 * ignored)
{
  vlib_vmbus_addr_t addr, **addrv = arg;
  unformat_input_t input;
  clib_error_t *err = 0;

  unformat_init_string (&input, (char *) dev_dir_name,
			vec_len (dev_dir_name));

  if (!unformat (&input, "/sys/bus/vmbus/devices/%U",
		 unformat_vlib_vmbus_addr, &addr))
    err = clib_error_return (0, "unformat error `%v`", dev_dir_name);

  unformat_free (&input);

  if (err)
    return err;

  vec_add1 (*addrv, addr);
  return 0;
}

static int
vmbus_addr_cmp (void *v1, void *v2)
{
  vlib_vmbus_addr_t *a1 = v1;
  vlib_vmbus_addr_t *a2 = v2;

  return uuid_compare (a1->guid, a2->guid);
}

vlib_vmbus_addr_t *
vlib_vmbus_get_all_dev_addrs ()
{
  vlib_vmbus_addr_t *addrs = 0;
  clib_error_t *err;

  err =
    foreach_directory_file ((char *) sysfs_vmbus_dev_path, scan_vmbus_addr,
			    &addrs, /* scan_dirs */ 0);
  if (err)
    {
      vec_free (addrs);
      return 0;
    }

  vec_sort_with_function (addrs, vmbus_addr_cmp);

  return addrs;
}

clib_error_t *
linux_vmbus_init (vlib_main_t * vm)
{
  linux_vmbus_main_t *pm = &linux_vmbus_main;

  pm->vlib_main = vm;

  return vlib_call_init_function (vm, unix_input_init);
}

VLIB_INIT_FUNCTION (linux_vmbus_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
