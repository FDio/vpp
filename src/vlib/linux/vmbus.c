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
static const char netvsc_uuid[] = "f8615163-df3e-46c5-913f-f2d2f965ed0e";

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

/*
 * Take VMBus address represented in standard form like:
 * "f2c086b2-ff2e-11e8-88de-7bad0a57de05" and convert
 * it to u8[16]
 */
uword
unformat_vlib_vmbus_addr (unformat_input_t *input, va_list *args)
{
  vlib_vmbus_addr_t *addr = va_arg (*args, vlib_vmbus_addr_t *);
  uword ret = 0;
  u8 *s = 0;

  if (!unformat (input, "%U", unformat_token, "a-zA-Z0-9-", &s))
    return 0;

  if (vec_len (s) != 36)
    goto fail;

  if (s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-')
    goto fail;

  clib_memmove (s + 8, s + 9, 4);
  clib_memmove (s + 12, s + 14, 4);
  clib_memmove (s + 16, s + 19, 4);
  clib_memmove (s + 20, s + 24, 12);

  for (int i = 0; i < 32; i++)
    if (s[i] >= '0' && s[i] <= '9')
      s[i] -= '0';
    else if (s[i] >= 'A' && s[i] <= 'F')
      s[i] -= 'A' - 10;
    else if (s[i] >= 'a' && s[i] <= 'f')
      s[i] -= 'a' - 10;
    else
      goto fail;

  for (int i = 0; i < 16; i++)
    addr->guid[i] = s[2 * i] * 16 + s[2 * i + 1];

  ret = 1;

fail:
  vec_free (s);
  return ret;
}

/* Convert bus address to standard UUID string */
u8 *
format_vlib_vmbus_addr (u8 *s, va_list *va)
{
  vlib_vmbus_addr_t *addr = va_arg (*va, vlib_vmbus_addr_t *);
  u8 *bytes = addr->guid;

  for (int i = 0; i < 4; i++)
    s = format (s, "%02X", bytes++[0]);
  vec_add1 (s, '-');
  for (int i = 0; i < 2; i++)
    s = format (s, "%02X", bytes++[0]);
  vec_add1 (s, '-');
  for (int i = 0; i < 2; i++)
    s = format (s, "%02X", bytes++[0]);
  vec_add1 (s, '-');
  for (int i = 0; i < 2; i++)
    s = format (s, "%02X", bytes++[0]);
  vec_add1 (s, '-');
  for (int i = 0; i < 6; i++)
    s = format (s, "%02X", bytes++[0]);

  return s;
}

/* workaround for mlx bug, bring lower device up before unbind */
static clib_error_t *
vlib_vmbus_raise_lower (int fd, const char *upper_name)
{
  clib_error_t *error = 0;
  struct dirent *e;
  struct ifreq ifr;
  u8 *dev_net_dir;
  DIR *dir;

  clib_memset (&ifr, 0, sizeof (ifr));

  dev_net_dir = format (0, "%s/%s%c", sysfs_class_net_path, upper_name, 0);

  dir = opendir ((char *) dev_net_dir);

  if (!dir)
    {
      error = clib_error_return (0, "VMBUS failed to open %s", dev_net_dir);
      goto done;
    }

  while ((e = readdir (dir)))
    {
      /* look for lower_enXXXX */
      if (strncmp (e->d_name, "lower_", 6))
	continue;

      strncpy (ifr.ifr_name, e->d_name + 6, IFNAMSIZ - 1);
      break;
    }
  closedir (dir);

  if (!e)
    goto done;			/* no lower device */

  if (ioctl (fd, SIOCGIFFLAGS, &ifr) < 0)
    error = clib_error_return_unix (0, "ioctl fetch intf %s flags",
				    ifr.ifr_name);
  else if (!(ifr.ifr_flags & IFF_UP))
    {
      ifr.ifr_flags |= IFF_UP;

      if (ioctl (fd, SIOCSIFFLAGS, &ifr) < 0)
	error = clib_error_return_unix (0, "ioctl set intf %s flags",
					ifr.ifr_name);
    }
done:
  vec_free (dev_net_dir);
  return error;
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
vlib_vmbus_bind_to_uio (vlib_vmbus_addr_t * addr)
{
  clib_error_t *error = 0;
  u8 *dev_dir_name;
  char *ifname = 0;
  static int uio_new_id_needed = 1;
  struct dirent *e;
  struct ifreq ifr;
  u8 *s = 0, *driver_name;
  DIR *dir;
  int fd;

  dev_dir_name = format (0, "%s/%U", sysfs_vmbus_dev_path,
			 format_vlib_vmbus_addr, addr);

  driver_name = clib_file_get_resolved_basename ("%v/driver", dev_dir_name);

  /* skip if not using the Linux kernel netvsc driver */
  if (!driver_name || strcmp ("hv_netvsc", (char *) driver_name) != 0)
    goto done;

  /* if uio_hv_generic is not loaded, then can't use native DPDK driver. */
  if (!directory_exists ("/sys/module/uio_hv_generic"))
    goto done;

  s = format (s, "%v/net%c", dev_dir_name, 0);
  dir = opendir ((char *) s);
  vec_reset_length (s);

  if (!dir)
    return clib_error_return (0, "VMBUS failed to open %s", s);

  while ((e = readdir (dir)))
    {
      if (e->d_name[0] == '.')	/* skip . and .. */
	continue;

      ifname = strdup (e->d_name);
      break;
    }
  closedir (dir);

  if (!ifname)
    {
      error = clib_error_return (0,
				 "VMBUS device %U eth not found",
				 format_vlib_vmbus_addr, addr);
      goto done;
    }


  clib_memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, ifname, IFNAMSIZ - 1);

  /* read up/down flags */
  fd = socket (PF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      error = clib_error_return_unix (0, "socket");
      goto done;
    }

  if (ioctl (fd, SIOCGIFFLAGS, &ifr) < 0)
    {
      error = clib_error_return_unix (0, "ioctl fetch intf %s flags",
				      ifr.ifr_name);
      close (fd);
      goto done;
    }

  if (ifr.ifr_flags & IFF_UP)
    {
      error = clib_error_return (
	0, "Skipping VMBUS device %U as host interface %s is up",
	format_vlib_vmbus_addr, addr, ifname);
      close (fd);
      goto done;
    }

  /* tell uio_hv_generic about netvsc device type */
  if (uio_new_id_needed)
    {
      vec_reset_length (s);
      s = format (s, "%s/%s/new_id%c", sysfs_vmbus_drv_path, uio_drv_name, 0);
      error = clib_sysfs_write ((char *) s, "%s", netvsc_uuid);
      /* If device already exists, we can bind/unbind/override driver */
      if (error)
	{
	  if (error->code == EEXIST)
	    {
	      clib_error_free (error);
	    }
	  else
	    {
	      close (fd);
	      goto done;
	    }
	}

      uio_new_id_needed = 0;
    }

  error = vlib_vmbus_raise_lower (fd, ifname);
  close (fd);

  if (error)
    goto done;

  /* prefer the simplier driver_override model */
  vec_reset_length (s);
  s = format (s, "%/driver_override%c", dev_dir_name, 0);
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
  free (ifname);
  vec_free (s);
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

  for (int i = 0; i < ARRAY_LEN (a1->guid); i++)
    if (a1->guid[i] > a2->guid[i])
      return 1;
    else if (a1->guid[i] < a2->guid[i])
      return -1;

  return 0;
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

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (linux_vmbus_init) =
{
  .runs_before = VLIB_INITS("unix_input_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
