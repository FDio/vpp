/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "platform",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log._class, "%U" f, format_vnet_dev_log, \
	    dev,                                                              \
	    clib_string_skip_prefix (__func__, "vnet_dev_bus_platform_dt_"),  \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log._class, "%U" f, format_vnet_dev_log,   \
	    dev, 0, ##__VA_ARGS__)

#define PLATFORM_DEV_PATH "/sys/bus/platform/devices"

clib_dt_main_t vnet_dev_bus_platform_dt_main;

vnet_dev_rv_t
vnet_dev_bus_platform_dt_node_from_device_id (clib_dt_node_t **nodep,
					      char *device_id)
{
  clib_dt_main_t *dm = &vnet_dev_bus_platform_dt_main;
  clib_dt_node_t *n;
  char *name = device_id + sizeof (PLATFORM_BUS_NAME);
  char path[PATH_MAX];
  int r;
  u8 *link;

  if (dm->root == 0)
    {
      clib_error_t *err;
      err = clib_dt_read_from_sysfs (&vnet_dev_bus_platform_dt_main);
      if (err)
	{
	  log_err (0, "cannot read devicetree: %U", format_clib_error, err);
	  clib_error_free (err);
	  return VNET_DEV_ERR_NOT_FOUND;
	}
    }

  link = format (0, PLATFORM_DEV_PATH "/%s/of_node%c", name, 0);
  r = readlink ((char *) link, path, sizeof (path) - 1);

  if (r < 1)
    {
      log_err (0, "of_node doesn't exist for '%s'", name);
      vec_free (link);
      return VNET_DEV_ERR_NOT_FOUND;
    }

  path[r] = 0;
  vec_reset_length (link);
  link = format (link, PLATFORM_DEV_PATH "/%s/%s%c", name, path, 0);
  if (!realpath ((char *) link, path))
    {
      log_err (0, "cannot find realpath for '%s'", link);
      vec_free (link);
      return VNET_DEV_ERR_NOT_FOUND;
    }

  vec_free (link);

  if (strncmp (CLIB_DT_LINUX_PREFIX, path,
	       sizeof (CLIB_DT_LINUX_PREFIX) - 1) != 0)
    return VNET_DEV_ERR_BUG;

  n = clib_dt_get_node_with_path (dm, "%s",
				  path + sizeof (CLIB_DT_LINUX_PREFIX) - 1);

  if (n)
    {
      *nodep = n;
      return VNET_DEV_OK;
    }

  return VNET_DEV_ERR_NOT_FOUND;
}

static void *
vnet_dev_bus_platform_get_device_info (vlib_main_t *vm, char *device_id)
{
  clib_dt_node_t *n = 0;
  vnet_dev_bus_platform_device_info_t *di;

  vnet_dev_bus_platform_dt_node_from_device_id (&n, device_id);

  if (n)
    {
      clib_dt_property_t *compatible;
      compatible = clib_dt_get_node_property_by_name (n, "compatible");
      log_debug (0, "node found, is compatible %U",
		 format_clib_dt_property_data, compatible);
      di = clib_mem_alloc (sizeof (*di));
      di->node = n;
      return di;
    }

  return 0;
}

static void
vnet_dev_bus_platform_free_device_info (vlib_main_t *vm, void *p)
{
  clib_mem_free (p);
}

static void
vnet_dev_bus_platform_close (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "");
}

static vnet_dev_rv_t
vnet_dev_bus_platform_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  clib_dt_node_t *n = 0;
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  vnet_dev_rv_t rv;

  log_debug (dev, "");

  rv = vnet_dev_bus_platform_dt_node_from_device_id (&n, dev->device_id);
  if (rv != VNET_DEV_OK)
    return rv;

  dd->node = n;
  return VNET_DEV_OK;
}

static u8 *
format_dev_bus_platform_device_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  return format (s, "device-tree path is '%v'", dd->node->path);
}

static u8 *
format_dev_bus_platform_device_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  return format (s, "%s", dev->device_id + sizeof (PLATFORM_BUS_NAME));
}

VNET_DEV_REGISTER_BUS (pp2) = {
  .name = PLATFORM_BUS_NAME,
  .device_data_size = sizeof (vnet_dev_bus_platform_device_info_t),
  .ops = {
    .get_device_info = vnet_dev_bus_platform_get_device_info,
    .free_device_info = vnet_dev_bus_platform_free_device_info,
    .device_open = vnet_dev_bus_platform_open,
    .device_close = vnet_dev_bus_platform_close,
    .format_device_info = format_dev_bus_platform_device_info,
    .format_device_addr = format_dev_bus_platform_device_addr,
  },
};
