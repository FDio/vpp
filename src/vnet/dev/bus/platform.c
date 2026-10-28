/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024-2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <vnet/dev/kdi/kdi.h>
#include <vlib/physmem_funcs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "platform",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U" f, format_vnet_dev_log, \
	    dev,                                                              \
	    clib_string_skip_prefix (__func__, "vnet_dev_bus_platform_dt_"),  \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U" f, format_vnet_dev_log,   \
	    dev, 0, ##__VA_ARGS__)

#define PLATFORM_DEV_PATH "/sys/bus/platform/devices"
#define PLATFORM_UIO_PATH "/sys/class/uio"

static const enum kdi_resource_kind kdi_resource_type_map[] = {
  [VNET_DEV_PLATFORM_RESOURCE_CLOCK] = KDI_RESOURCE_CLOCK,
  [VNET_DEV_PLATFORM_RESOURCE_RESET] = KDI_RESOURCE_RESET,
  [VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT] = KDI_RESOURCE_INTERCONNECT,
  [VNET_DEV_PLATFORM_RESOURCE_ETHERNET_PHY] = KDI_RESOURCE_ETHERNET_PHY,
  [VNET_DEV_PLATFORM_RESOURCE_CLOCK_PROVIDER] = KDI_RESOURCE_CLOCK_PROVIDER,
};

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
  /* coverity[fs_check_call] - sysfs link, not controlled by an unprivileged user */
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
  vnet_dev_platform_resource_close (dev);
  vnet_dev_platform_unmap_regions (dev);
}

void
vnet_dev_platform_unmap_regions (vnet_dev_t *dev)
{
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  vnet_dev_bus_platform_mapping_t *m;

  vec_foreach (m, dd->mappings)
    munmap (m->base, m->size);
  vec_free (dd->mappings);
}

/* Core resource-open primitive: device_name is explicit rather than
 * derived from dev->device_id, so it can address any platform device
 * sharing dev's kdi_fd connection to /dev/vpp-kdi, not just dev's own. */
static int
vnet_dev_platform_resource_open (vnet_dev_t *dev, char *device_name,
				 vnet_dev_platform_resource_type_t type, char *node_name,
				 char *resource_name, u32 arg)
{
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  struct kdi_resource_open request = {};
  int fd;

  if (dd->kdi_fd < 0)
    return -ENODEV;
  if (type < VNET_DEV_PLATFORM_RESOURCE_CLOCK || type > VNET_DEV_PLATFORM_RESOURCE_CLOCK_PROVIDER)
    return -EINVAL;
  if (strnlen (device_name, sizeof (request.device_name)) >= sizeof (request.device_name))
    return -ENAMETOOLONG;
  request.type = kdi_resource_type_map[type];
  request.arg = arg;
  snprintf (request.device_name, sizeof (request.device_name), "%s", device_name);
  snprintf (request.node_name, sizeof (request.node_name), "%s", node_name);
  snprintf (request.resource_name, sizeof (request.resource_name), "%s", resource_name);
  fd = ioctl (dd->kdi_fd, KDI_IOC_OPEN_RESOURCE, &request);
  if (fd < 0)
    return -errno;
  log_debug (dev, "opened KDI resource type %u on device '%s' '%s%s%s', fd %d", type, device_name,
	     node_name[0] ? node_name : "", node_name[0] ? "/" : "", resource_name, fd);
  return fd;
}

static int
vnet_dev_platform_resource_open_on_node (vnet_dev_t *dev, vnet_dev_platform_resource_type_t type,
					 char *node_name, char *resource_name)
{
  char *name = dev->device_id + sizeof (PLATFORM_BUS_NAME);

  return vnet_dev_platform_resource_open (dev, name, type, node_name, resource_name, 0);
}

static void
vnet_dev_platform_resource_close_fd (int fd)
{
  if (fd >= 0)
    close (fd);
}

void
vnet_dev_platform_resource_close (vnet_dev_t *dev)
{
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  vnet_dev_platform_resource_handle_t *resource;

  vec_foreach (resource, dd->resources)
    {
      vnet_dev_platform_resource_close_fd (resource->fd);
      vec_free (resource->node_name);
      vec_free (resource->resource_name);
    }
  vec_free (dd->resources);

  if (dd->kdi_fd >= 0)
    close (dd->kdi_fd);
  dd->kdi_fd = -1;
}

static int
vnet_dev_platform_resource_get_fd (vnet_dev_t *dev, vnet_dev_platform_resource_type_t type,
				   char *node_name, char *resource_name)
{
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  vnet_dev_platform_resource_handle_t *resource;
  int fd;

  if (!node_name || !resource_name)
    return -EINVAL;
  if (strnlen (node_name, VNET_DEV_PLATFORM_RESOURCE_NAME_LEN) >=
	VNET_DEV_PLATFORM_RESOURCE_NAME_LEN ||
      strnlen (resource_name, VNET_DEV_PLATFORM_RESOURCE_NAME_LEN) >=
	VNET_DEV_PLATFORM_RESOURCE_NAME_LEN)
    return -ENAMETOOLONG;

  vec_foreach (resource, dd->resources)
    if (resource->type == type && strcmp (resource->node_name, node_name) == 0 &&
	strcmp (resource->resource_name, resource_name) == 0)
      return resource->fd;

  fd = vnet_dev_platform_resource_open_on_node (dev, type, node_name, resource_name);
  if (fd < 0)
    return fd;

  vec_add2 (dd->resources, resource, 1);
  resource->type = type;
  resource->fd = fd;
  resource->node_name = (char *) format (0, "%s%c", node_name, 0);
  resource->resource_name = (char *) format (0, "%s%c", resource_name, 0);
  return fd;
}

static vnet_dev_rv_t
vnet_dev_platform_resource_ioctl (vnet_dev_t *dev, vnet_dev_platform_resource_type_t type,
				  char *node_name, char *resource_name, char *operation,
				  unsigned long request, void *arg)
{
  int fd = vnet_dev_platform_resource_get_fd (dev, type, node_name, resource_name);
  u8 *path = format (0, "%s%s%s%c", node_name, node_name[0] ? "/" : "", resource_name, 0);
  int rv;

  if (fd < 0)
    {
      log_err (dev, "%s failed for '%v': %s", operation, path, strerror (-fd));
      vec_free (path);
      return VNET_DEV_ERR_BUS;
    }

  rv = ioctl (fd, request, arg);
  if (rv < 0)
    {
      log_err (dev, "%s failed for '%v': %s", operation, path, strerror (errno));
      vec_free (path);
      return VNET_DEV_ERR_BUS;
    }
  log_debug (dev, "%s succeeded for '%v'", operation, path);
  vec_free (path);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_clock_enable (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_CLOCK, node_name,
					   resource_name, "clock enable", KDI_IOC_CLOCK_ENABLE, 0);
}

vnet_dev_rv_t
vnet_dev_platform_clock_disable (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_CLOCK, node_name,
					   resource_name, "clock disable", KDI_IOC_CLOCK_DISABLE,
					   0);
}

vnet_dev_rv_t
vnet_dev_platform_clock_set_rate (vnet_dev_t *dev, char *node_name, char *resource_name, u64 rate)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_CLOCK, node_name,
					   resource_name, "clock rate update",
					   KDI_IOC_CLOCK_SET_RATE, &rate);
}

vnet_dev_rv_t
vnet_dev_platform_reset_assert (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_RESET, node_name,
					   resource_name, "reset assertion", KDI_IOC_RESET_ASSERT,
					   0);
}

vnet_dev_rv_t
vnet_dev_platform_reset_deassert (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_RESET, node_name,
					   resource_name, "reset deassertion",
					   KDI_IOC_RESET_DEASSERT, 0);
}

vnet_dev_rv_t
vnet_dev_platform_reset_pulse (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_RESET, node_name,
					   resource_name, "reset pulse", KDI_IOC_RESET_PULSE, 0);
}

vnet_dev_rv_t
vnet_dev_platform_interconnect_set_bw (vnet_dev_t *dev, char *node_name, char *resource_name,
				       u64 average_bw, u64 peak_bw)
{
  int fd = vnet_dev_platform_resource_get_fd (dev, VNET_DEV_PLATFORM_RESOURCE_INTERCONNECT,
					      node_name, resource_name);
  struct kdi_interconnect_op request = {
    .average_bw = average_bw,
    .peak_bw = peak_bw,
  };
  if (fd < 0)
    {
      log_err (dev, "cannot open interconnect '%s': %s", resource_name, strerror (-fd));
      return VNET_DEV_ERR_BUS;
    }
  if (ioctl (fd, KDI_IOC_INTERCONNECT_SET_BW, &request) < 0)
    {
      log_err (dev, "cannot set interconnect '%s' bandwidth: %s", resource_name, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }
  log_debug (dev, "configured interconnect '%s%s%s' with average/peak bandwidth %llu/%llu",
	     node_name, node_name[0] ? "/" : "", resource_name, average_bw, peak_bw);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_ethernet_phy_open (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  int fd = vnet_dev_platform_resource_get_fd (dev, VNET_DEV_PLATFORM_RESOURCE_ETHERNET_PHY,
					      node_name, resource_name);
  if (fd < 0)
    {
      log_err (dev, "cannot open Ethernet PHY '%s%s%s': %s", node_name, node_name[0] ? "/" : "",
	       resource_name, strerror (-fd));
      return VNET_DEV_ERR_BUS;
    }
  log_debug (dev, "opened Ethernet PHY '%s%s%s'", node_name, node_name[0] ? "/" : "",
	     resource_name);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_ethernet_phy_start_aneg (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_ETHERNET_PHY, node_name,
					   resource_name, "Ethernet PHY autonegotiation start",
					   KDI_IOC_ETHERNET_PHY_START_ANEG, 0);
}

vnet_dev_rv_t
vnet_dev_platform_ethernet_phy_stop (vnet_dev_t *dev, char *node_name, char *resource_name)
{
  return vnet_dev_platform_resource_ioctl (dev, VNET_DEV_PLATFORM_RESOURCE_ETHERNET_PHY, node_name,
					   resource_name, "Ethernet PHY stop",
					   KDI_IOC_ETHERNET_PHY_STOP, 0);
}

vnet_dev_rv_t
vnet_dev_platform_ethernet_phy_get_state (vnet_dev_t *dev, char *node_name, char *resource_name,
					  vnet_dev_platform_ethernet_phy_state_t *state)
{
  struct kdi_ethernet_phy_state kdi_state;
  int fd = vnet_dev_platform_resource_get_fd (dev, VNET_DEV_PLATFORM_RESOURCE_ETHERNET_PHY,
					      node_name, resource_name);

  if (fd < 0)
    {
      log_err (dev, "cannot read Ethernet PHY state '%s%s%s': %s", node_name,
	       node_name[0] ? "/" : "", resource_name, strerror (-fd));
      return VNET_DEV_ERR_BUS;
    }

  if (ioctl (fd, KDI_IOC_ETHERNET_PHY_GET_STATE, &kdi_state) < 0)
    {
      log_err (dev, "cannot read Ethernet PHY state '%s%s%s': %s", node_name,
	       node_name[0] ? "/" : "", resource_name, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }
  state->link = kdi_state.link;
  state->speed_mbps = kdi_state.speed;
  state->full_duplex = kdi_state.duplex;
  state->autoneg = kdi_state.autoneg;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_dt_node_device_name (clib_dt_node_t *node, u8 **device_name)
{
  char *leaf = strrchr ((char *) node->path, '/');
  char *at;

  leaf = leaf ? leaf + 1 : (char *) node->path;
  at = strchr (leaf, '@');
  *device_name =
    at ? format (0, "%s.%.*s%c", at + 1, (int) (at - leaf), leaf, 0) : format (0, "%s%c", leaf, 0);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_open_resource_on_device (vnet_dev_t *dev, char *device_name,
					   vnet_dev_platform_resource_type_t type, char *node_name,
					   char *resource_name, u32 arg, int *fd)
{
  int rv = vnet_dev_platform_resource_open (dev, device_name, type, node_name, resource_name, arg);

  if (rv < 0)
    {
      log_err (dev, "cannot open resource type %u on device '%s' '%s%s%s': %s", type, device_name,
	       node_name[0] ? node_name : "", node_name[0] ? "/" : "", resource_name,
	       strerror (-rv));
      return VNET_DEV_ERR_BUS;
    }
  *fd = rv;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
vnet_dev_platform_resource_ioctl_fd (vnet_dev_t *dev, int fd, char *operation,
				     unsigned long request, void *arg)
{
  if (ioctl (fd, request, arg) < 0)
    {
      log_err (dev, "%s failed: %s", operation, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }
  log_debug (dev, "%s succeeded", operation);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_clock_enable_fd (vnet_dev_t *dev, int fd)
{
  return vnet_dev_platform_resource_ioctl_fd (dev, fd, "clock enable", KDI_IOC_CLOCK_ENABLE, 0);
}

vnet_dev_rv_t
vnet_dev_platform_clock_disable_fd (vnet_dev_t *dev, int fd)
{
  return vnet_dev_platform_resource_ioctl_fd (dev, fd, "clock disable", KDI_IOC_CLOCK_DISABLE, 0);
}

vnet_dev_rv_t
vnet_dev_platform_clock_set_rate_fd (vnet_dev_t *dev, int fd, u64 rate)
{
  return vnet_dev_platform_resource_ioctl_fd (dev, fd, "clock rate update", KDI_IOC_CLOCK_SET_RATE,
					      &rate);
}

vnet_dev_rv_t
vnet_dev_platform_reset_assert_fd (vnet_dev_t *dev, int fd)
{
  return vnet_dev_platform_resource_ioctl_fd (dev, fd, "reset assertion", KDI_IOC_RESET_ASSERT, 0);
}

vnet_dev_rv_t
vnet_dev_platform_reset_deassert_fd (vnet_dev_t *dev, int fd)
{
  return vnet_dev_platform_resource_ioctl_fd (dev, fd, "reset deassertion", KDI_IOC_RESET_DEASSERT,
					      0);
}

vnet_dev_rv_t
vnet_dev_platform_reset_pulse_fd (vnet_dev_t *dev, int fd)
{
  return vnet_dev_platform_resource_ioctl_fd (dev, fd, "reset pulse", KDI_IOC_RESET_PULSE, 0);
}

vnet_dev_rv_t
vnet_dev_platform_clock_provider_try_request (int fd,
					      vnet_dev_platform_clock_provider_request_t *req)
{
  struct kdi_clock_provider_request kreq;

  if (ioctl (fd, KDI_IOC_CLOCK_PROVIDER_WAIT_REQUEST, &kreq) < 0)
    return errno == EAGAIN ? VNET_DEV_ERR_NOT_READY : VNET_DEV_ERR_BUS;
  req->index = kreq.index;
  req->op = (vnet_dev_platform_clock_provider_op_t) kreq.op;
  req->rate = kreq.rate;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_clock_provider_complete (int fd, i32 result, u64 rate)
{
  struct kdi_clock_provider_response resp = {
    .result = result,
    .rate = rate,
  };

  if (ioctl (fd, KDI_IOC_CLOCK_PROVIDER_COMPLETE, &resp) < 0)
    return VNET_DEV_ERR_BUS;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_platform_clock_provider_notify_rate (vnet_dev_t *dev, int fd, u32 index, u64 rate)
{
  struct kdi_clock_provider_notify_rate req = {
    .index = index,
    .rate = rate,
  };

  return vnet_dev_platform_resource_ioctl_fd (dev, fd, "clock provider notify-rate",
					      KDI_IOC_CLOCK_PROVIDER_NOTIFY_RATE, &req);
}

static int
vnet_dev_bus_platform_read_u64 (char *path, u64 *value)
{
  FILE *f = fopen (path, "r");
  int rv;

  if (!f)
    return -1;
  rv = fscanf (f, "0x%lx", value);
  fclose (f);
  return rv == 1 ? 0 : -1;
}

static int
vnet_dev_bus_platform_read_string (char *path, char *value, uword size)
{
  FILE *f = fopen (path, "r");
  char *p;

  if (!f)
    return -1;
  p = fgets (value, size, f);
  fclose (f);
  if (!p)
    return -1;
  p = strchr (value, '\n');
  if (p)
    *p = 0;
  return 0;
}

static int
vnet_dev_bus_platform_uio_is_sibling (char *uio_name, char *parent_path)
{
  char path[PATH_MAX];
  char real_path[PATH_MAX];
  char *last;

  snprintf (path, sizeof (path), "%s/%s/device/of_node", PLATFORM_UIO_PATH, uio_name);
  if (!realpath (path, real_path))
    return 0;
  last = strrchr (real_path, '/');
  if (!last)
    return 0;
  *last = 0;
  return strcmp (real_path, parent_path) == 0;
}

static vnet_dev_rv_t
vnet_dev_bus_platform_find_uio_map (vnet_dev_bus_platform_device_data_t *dd, char *name,
				    u32 *uio_num, u32 *map_index, u64 *map_offset, u64 *map_size)
{
  char maps_path[PATH_MAX];
  struct dirent *uio_entry;
  DIR *uio_dir;
  u8 *path = 0;
  u8 *parent_path = format (0, CLIB_DT_LINUX_PREFIX "%v%c", dd->node->parent->path, 0);

  uio_dir = opendir (PLATFORM_UIO_PATH);
  if (!uio_dir)
    {
      vec_free (parent_path);
      return VNET_DEV_ERR_NOT_FOUND;
    }

  while ((uio_entry = readdir (uio_dir)))
    {
      struct dirent *map_entry;
      DIR *map_dir;
      char extra;
      int n;

      if (sscanf (uio_entry->d_name, "uio%d%c", &n, &extra) != 1)
	continue;
      if (!vnet_dev_bus_platform_uio_is_sibling (uio_entry->d_name, (char *) parent_path))
	continue;
      snprintf (maps_path, sizeof (maps_path), "%s/%s/maps", PLATFORM_UIO_PATH, uio_entry->d_name);
      map_dir = opendir (maps_path);
      if (!map_dir)
	continue;

      while ((map_entry = readdir (map_dir)))
	{
	  u64 uio_offset;
	  u64 uio_size;
	  char map_name[64];
	  int index;

	  if (sscanf (map_entry->d_name, "map%d%c", &index, &extra) != 1)
	    continue;
	  vec_reset_length (path);
	  path = format (path, "%s/%s/name%c", maps_path, map_entry->d_name, 0);
	  if (vnet_dev_bus_platform_read_string ((char *) path, map_name, sizeof (map_name)) ||
	      strcmp (name, map_name))
	    continue;
	  vec_reset_length (path);
	  path = format (path, "%s/%s/offset%c", maps_path, map_entry->d_name, 0);
	  if (vnet_dev_bus_platform_read_u64 ((char *) path, &uio_offset))
	    continue;
	  vec_reset_length (path);
	  path = format (path, "%s/%s/size%c", maps_path, map_entry->d_name, 0);
	  if (vnet_dev_bus_platform_read_u64 ((char *) path, &uio_size))
	    continue;

	  *uio_num = n;
	  *map_index = index;
	  *map_offset = uio_offset;
	  *map_size = uio_size;
	  closedir (map_dir);
	  closedir (uio_dir);
	  vec_free (path);
	  vec_free (parent_path);
	  return VNET_DEV_OK;
	}
      closedir (map_dir);
    }

  closedir (uio_dir);
  vec_free (path);
  vec_free (parent_path);
  return VNET_DEV_ERR_NOT_FOUND;
}

vnet_dev_rv_t
vnet_dev_platform_map_uio_region (vnet_dev_t *dev, char *name, void **va)
{
  vnet_dev_bus_platform_device_data_t *dd = vnet_dev_get_bus_data (dev);
  u64 uio_offset;
  u64 uio_size;
  u64 page_offset;
  u64 map_size;
  uword page_size = getpagesize ();
  char path[PATH_MAX];
  u32 map_index;
  u32 uio_num;
  int fd;
  void *base;
  vnet_dev_rv_t rv;

  rv = vnet_dev_bus_platform_find_uio_map (dd, name, &uio_num, &map_index, &uio_offset, &uio_size);
  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "cannot find UIO region '%s'", name);
      return rv;
    }

  snprintf (path, sizeof (path), "/dev/uio%u", uio_num);
  fd = open (path, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    {
      log_err (dev, "cannot open %s: %s", path, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }

  page_offset = uio_offset & (page_size - 1);
  map_size = round_pow2 (page_offset + uio_size, page_size);
  if (map_size > CLIB_UWORD_MAX)
    {
      /* coverity[dead_error_begin] - map_size can exceed uword on 32 bit */
      close (fd);
      return VNET_DEV_ERR_INVALID_ARG;
    }

  base = mmap (0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, map_index * page_size);
  close (fd);
  if (base == MAP_FAILED)
    {
      log_err (dev, "cannot map UIO region '%s': %s", name, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }

  vec_add1 (dd->mappings, ((vnet_dev_bus_platform_mapping_t) {
			    .base = base,
			    .size = map_size,
			  }));
  *va = base + uio_offset;
  return VNET_DEV_OK;
}

/* Registered once with vppinfra's physmem allocator (see
 * vnet_dev_bus_platform_open ()); called with (va, size) right after new
 * pages are mapped into the coherent arena, so they can be remapped
 * non-cacheable in place before any allocation out of them is handed out. */
static int platform_bus_kdi_fd = -1;

static int
vnet_dev_bus_platform_coherent_page_map (void *va, uword size, uword *pa)
{
  struct kdi_dma_mem_map request = {
    .addr = pointer_to_uword (va),
    .size = size,
  };
  void *mapped;
  int fd;

  ASSERT (platform_bus_kdi_fd >= 0);

  fd = ioctl (platform_bus_kdi_fd, KDI_IOC_MAP_DMA_MEM_UNCACHED, &request);
  if (fd < 0)
    {
      log_err (0, "cannot map virtual memory %p as uncached: %s", va, strerror (errno));
      return -1;
    }

  mapped = mmap (va, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
  close (fd);
  if (mapped == MAP_FAILED)
    {
      log_err (0, "cannot remap virtual memory %p as uncached: %s", va, strerror (errno));
      return -1;
    }

  /* The kernel resolved this via pin_user_pages_fast ()/page_to_pfn (), not
   * /proc/self/pagemap, so it stays correct even after the remap above. */
  *pa = request.phys_addr;
  return 0;
}

static vnet_dev_rv_t
vnet_dev_bus_platform_dma_mem_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size, u32 align,
				     void **pp)
{
  clib_error_t *err;
  void *p;

  align = align ? align : CLIB_CACHE_LINE_BYTES;
  size = round_pow2 (size, align);

  p = vlib_physmem_alloc_aligned_on_numa (vm, size, align, dev->numa_node);
  if (p == 0)
    {
      err = vlib_physmem_last_error (vm);
      log_err (dev, "dev_dma_mem_alloc: physmem_alloc_aligned error %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
    }

  clib_memset (p, 0, size);
  pp[0] = p;
  return VNET_DEV_OK;
}

static void
vnet_dev_bus_platform_dma_mem_free (vlib_main_t *vm, vnet_dev_t *dev __clib_unused, void *p)
{
  if (p)
    vlib_physmem_free (vm, p);
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

  *dd = (vnet_dev_bus_platform_device_data_t) {
    .node = n,
    .kdi_fd = open (KDI_DEVICE_PATH, O_RDWR | O_CLOEXEC),
  };
  if (dd->kdi_fd < 0)
    {
      log_err (dev, "cannot open %s: %s", KDI_DEVICE_PATH, strerror (errno));
      return VNET_DEV_ERR_BUS;
    }

  if (platform_bus_kdi_fd < 0)
    {
      platform_bus_kdi_fd = open (KDI_DEVICE_PATH, O_RDWR | O_CLOEXEC);
      if (platform_bus_kdi_fd < 0)
	{
	  log_err (dev, "cannot open %s: %s", KDI_DEVICE_PATH, strerror (errno));
	  return VNET_DEV_ERR_BUS;
	}
      vlib_physmem_set_coherent_page_map_fn (vm, vnet_dev_bus_platform_coherent_page_map);
    }

  return VNET_DEV_OK;
}

static u8 *
format_dev_bus_platform_device_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
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
  .device_data_size = sizeof (vnet_dev_bus_platform_device_data_t),
  .ops = {
    .get_device_info = vnet_dev_bus_platform_get_device_info,
    .free_device_info = vnet_dev_bus_platform_free_device_info,
    .device_open = vnet_dev_bus_platform_open,
    .device_close = vnet_dev_bus_platform_close,
    .dma_mem_alloc_fn = vnet_dev_bus_platform_dma_mem_alloc,
    .dma_mem_free_fn = vnet_dev_bus_platform_dma_mem_free,
    .format_device_info = format_dev_bus_platform_device_info,
    .format_device_addr = format_dev_bus_platform_device_addr,
  },
};
