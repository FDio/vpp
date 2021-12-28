/*
 * Copyright (c) 2021, Microsoft Corporation.
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
 * idxdbus.c: Linux user space idxd device management.
 */

#include <vppinfra/linux/sysfs.h>

#include <vlib/vlib.h>
#include <vlib/linux/idxd.h>
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

static const char *dsa_dev_path = "/dev/dsa";
static const char *sysfs_dsa_dev_path = "/sys/bus/dsa/devices";

vlib_dsa_main_t linux_dsa_main;

static clib_error_t *
scan_dsa_addr (void *arg, u8 *dev_dir_name, u8 *ignored)
{
  vlib_dsa_addr_t addr, **addrv = arg;
  unformat_input_t input;
  clib_error_t *err = 0;

  unformat_init_string (&input, (char *) dev_dir_name, vec_len (dev_dir_name));

  if (!unformat (&input, "/dev/dsa/wq%d.%d", &addr.device_id, &addr.wq_id))
    err = clib_error_return (0, "unformat error `%v`", dev_dir_name);

  if (err)
    return err;

  vec_add1 (*addrv, addr);
  return 0;
}

u8 *
format_vlib_dsa_addr (u8 *s, va_list *va)
{
  vlib_dsa_addr_t *addr = va_arg (*va, vlib_dsa_addr_t *);
  return format (s, "wq%d.%d", addr->device_id, addr->wq_id);
}

uword
unformat_vlib_dsa_addr (unformat_input_t *input, va_list *args)
{
  vlib_dsa_addr_t *addr = va_arg (*args, vlib_dsa_addr_t *);
  u16 x[2];

  if (!unformat (input, "wq%d.%d", &x[0], &x[1]))
    return 0;

  addr->device_id = x[0];
  addr->wq_id = x[1];
  return 1;
}

static int
dsa_addr_cmp (void *v1, void *v2)
{
  vlib_dsa_addr_t *a1 = v1;
  vlib_dsa_addr_t *a2 = v2;

  if (a1->device_id > a2->device_id)
    return 1;
  if (a1->device_id < a2->device_id)
    return -1;
  if (a1->wq_id > a2->wq_id)
    return 1;
  if (a1->wq_id < a2->wq_id)
    return -1;

  return 0;
}

void
vlib_dsa_get_all_dev_addrs (vlib_dsa_addr_t **addrs)
{
  clib_error_t *err;
  err = foreach_directory_file ((char *) dsa_dev_path, scan_dsa_addr, addrs,
				/* scan_dirs */ 0);
  if (err)
    {
      vec_free (*addrs);
      return;
    }

  vec_sort_with_function (*addrs, dsa_addr_cmp);

  return;
}

u8
dsa_sysfs_link_to_device (char *link, vlib_pci_addr_t *addr)
{
  char *p, *pend, buffer[128];
  unformat_input_t in;
  int r;

  r = readlink (link, buffer, sizeof (buffer) - 1);

  if (r < 0)
    return 0;

  buffer[r] = 0;

  p = strstr (buffer, "pci");
  if (!p)
    return 0;
  p = strchr (p, '/');
  pend = strchr (p + 1, '/');
  unformat_init_string (&in, p + 1, pend - p - 1);
  if (unformat (&in, "%U", unformat_vlib_pci_addr, addr) != 1)
    {
      clib_unix_warning ("no string?");
      unformat_free (&in);
      return 0;
    }
  unformat_free (&in);

  return 1;
}

static inline void
vlib_dsa_free_device_info (vlib_dsa_device_info_t *di)
{
  if (!di)
    return;
  vec_free (di->driver_name);
  vec_free (di->wq_name);
  clib_mem_free (di);
}

vlib_dsa_device_info_t *
vlib_dsa_get_device_info (vlib_main_t *vm, vlib_dsa_addr_t *addr,
			  clib_error_t **error)
{
  vlib_dsa_device_info_t *di;
  u8 *tmpstr;
  di = clib_mem_alloc (sizeof (vlib_dsa_device_info_t));
  clib_memset (di, 0, sizeof (vlib_dsa_device_info_t));

  u8 *f = 0;
  u8 *dev_dir_name =
    format (0, "%s/%U", sysfs_dsa_dev_path, format_vlib_dsa_addr, addr);

  f = format (f, "%v/driver%c", dev_dir_name, 0);

  di->driver_name = clib_sysfs_link_to_name ((char *) f);
  if (!di->driver_name)
    di->driver_name = format (0, "<NONE>%c", 0);

  vec_reset_length (f);
  f = format (f, "%v/name%c", dev_dir_name, 0);
  *error = clib_sysfs_read ((char *) f, "%s", &di->wq_name);
  if (*error)
    goto error;

  vec_reset_length (f);
  f = format (f, "%v/size%c", dev_dir_name, 0);
  *error = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (*error)
    goto error;
  di->size = atoi ((char *) tmpstr);

  vec_reset_length (f);
  f = format (f, "%v/type%c", dev_dir_name, 0);
  *error = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (*error)
    goto error;
  if (tmpstr)
    {
      if (!clib_strcmp ((char *) tmpstr, "kernel"))
	di->type = LINUX_DSA_DEVICE_TYPE_KERNEL;
      else if (!clib_strcmp ((char *) tmpstr, "user"))
	di->type = LINUX_DSA_DEVICE_TYPE_USER;
      else if (!clib_strcmp ((char *) tmpstr, "mdev"))
	di->type = LINUX_DSA_DEVICE_TYPE_KERNEL;
      else
	di->type = LINUX_DSA_DEVICE_TYPE_UNKNOWN;
      vec_free (tmpstr);
    }

  if (dsa_sysfs_link_to_device ((char *) dev_dir_name, &di->paddr) != 1)
    goto error;

  vec_free (f);
  vec_free (dev_dir_name);
  return di;

error:
  vec_free (f);
  vec_free (dev_dir_name);
  vlib_dsa_free_device_info (di);
  return NULL;
}

clib_error_t *
linux_dsa_init (vlib_main_t *vm)
{
  vlib_dsa_main_t *dm = &linux_dsa_main;
  linux_dsa_device_t dev;
  clib_memset (&dev, 0, sizeof (linux_dsa_device_t));

  dm->vlib_main = vm;
  ASSERT (sizeof (vlib_dsa_addr_t) == sizeof (u32));

  vlib_dsa_get_all_dev_addrs (&dm->addrs);

  return 0;
}

clib_error_t *
vlib_dsa_device_open (vlib_main_t *vm, vlib_dsa_addr_t *addr,
		      vlib_dsa_dev_handle_t *handle)
{
  clib_error_t *err = NULL;
  vlib_dsa_device_info_t *d;
  linux_dsa_device_t *p;
  vlib_dsa_main_t *ldm = &linux_dsa_main;

  d = vlib_dsa_get_device_info (vm, addr, &err);
  if (err)
    return err;

  pool_get (ldm->linux_dsa_devices, p);
  p->numa_node = d->numa_node;
  p->daddr.as_u32 = addr->as_u32;
  p->handle = p - ldm->linux_dsa_devices;
  p->paddr.as_u32 = d->paddr.as_u32;
  snprintf ((char *) p->wq_name, 32, "wq%d.%d", p->daddr.device_id,
	    p->daddr.wq_id);
  *handle = p->handle;
  return NULL;
}

clib_error_t *
vlib_dsa_device_map (vlib_main_t *vm, vlib_dsa_dev_handle_t h, void **result)
{
  clib_error_t *error = NULL;
  linux_dsa_device_t *p = linux_dsa_get_device (h);

  if (!p)
    return clib_error_return (0, "no dsa device");
  // map one page
  uword size = 0x1000;
  uword offset = 0;
  char path[256] = { 0 };

  snprintf (path, sizeof (path), "%s/%s", dsa_dev_path, p->wq_name);
  int fd = open (path, O_RDWR);
  if (fd < 0)
    return clib_error_return (0, "failed to open device");

  *result = clib_mem_vm_map_shared (0, size, fd, offset, "WQ %s", p->wq_name);
  if (*result == CLIB_MEM_VM_MAP_FAILED)
    {
      error = clib_error_return (0, "mmap %s failed", path);
      close (fd);
      return error;
    }
  p->fd = fd;
  return NULL;
}

clib_error_t *
vlib_dsa_device_unmap (vlib_dsa_dev_handle_t h, void *base)
{
  linux_dsa_device_t *p = linux_dsa_get_device (h);
  if (!p)
    return clib_error_return (0, "no dsa device");
  if (clib_mem_vm_unmap (base))
    {
      return clib_error_return (0, "unmap %llx failed", base);
    }
  close (p->fd);
  return NULL;
}

VLIB_INIT_FUNCTION (linux_dsa_init) = {
  .runs_after = VLIB_INITS ("unix_input_init"),
};
