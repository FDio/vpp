/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_rdma/bus.h>
#include <vlib/pci/pci.h>
#include <vppinfra/file.h>
#include <vppinfra/linux/sysfs.h>

#include <fcntl.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "rdma",
  .subclass_name = "bus",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

static struct ibv_device *
vnet_dev_bus_rdma_device_id_to_ibv_device (char *str,
					   struct ibv_device **dev_list,
					   int n_devs)
{
  unformat_input_t input;
  uword rv;
  u8 *s;
  struct ibv_device *dev = 0;

  unformat_init_string (&input, str, strlen (str));
  rv = unformat (&input, "rdma" VNET_DEV_DEVICE_ID_PREFIX_DELIMITER "%s", &s);
  unformat_free (&input);
  if (rv == 0)
    return 0;

  for (int i = 0; i < n_devs; i++)
    if (strcmp ((char *) s, dev_list[i]->name) == 0)
      {
	dev = dev_list[i];
	break;
      }

  vec_free (s);
  return dev;
}

static void *
vnet_dev_bus_rdma_get_device_info (vlib_main_t *vm, char *device_id)
{
  vnet_dev_bus_rdma_device_info_t *info = 0;
  struct ibv_device **dev_list, *dev;
  int n;

  dev_list = ibv_get_device_list (&n);
  dev = vnet_dev_bus_rdma_device_id_to_ibv_device (device_id, dev_list, n);

  if (dev)
    {
      info = clib_mem_alloc (sizeof (*info));
      info->dev = dev;
      info->dev_list = dev_list;
    }
  else
    ibv_free_device_list (dev_list);

  return info;
}

static void
vnet_dev_bus_rdma_free_device_info (vlib_main_t *vm, void *p)
{
  vnet_dev_bus_rdma_device_info_t *info = p;
  ibv_free_device_list (info->dev_list);
  clib_mem_free (info);
}

static void
vnet_dev_bus_rdma_close (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_bus_rdma_device_data_t *rdd = vnet_dev_get_bus_data (dev);

  if (rdd->mr)
    ibv_dereg_mr (rdd->mr);

  if (rdd->pd)
    ibv_dealloc_pd (rdd->pd);

  if (rdd->ctx)
    ibv_close_device (rdd->ctx);
}

static vnet_dev_rv_t
vnet_dev_bus_rdma_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_bus_rdma_device_data_t *rdd = vnet_dev_get_bus_data (dev);
  struct ibv_device **dev_list, *rd;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  int n;

  dev_list = ibv_get_device_list (&n);
  rd = vnet_dev_bus_rdma_device_id_to_ibv_device (dev->device_id, dev_list, n);

  if (rd == 0)
    {
      log_err (dev, "failed to find corresponding device");
      ibv_free_device_list (dev_list);
      return VNET_DEV_ERR_INVALID_DEVICE_ID;
    }

  rdd->dev = rd;
  rdd->ctx = ibv_open_device (rd);
  ibv_free_device_list (dev_list);

  if (rdd->ctx == 0)
    {
      log_err (dev, "failed to open device [errno %d]", errno);
      return VNET_DEV_ERR_BUS;
    }

  rdd->pd = ibv_alloc_pd (rdd->ctx);
  if (rdd->pd == 0)
    {
      log_err (dev, "failed to allocate protection domain [errno %d]", errno);
      rv = VNET_DEV_ERR_BUS;
      goto error;
    }

  rdd->mr =
    ibv_reg_mr (rdd->pd, (void *) vm->buffer_main->buffer_mem_start,
		vm->buffer_main->buffer_mem_size, IBV_ACCESS_LOCAL_WRITE);
  if (rdd->mr == 0)
    {
      log_err (dev, "failed to register memory region [errno %d]", errno);
      rv = VNET_DEV_ERR_BUS;
      goto error;
    }

error:
  if (rv != VNET_DEV_OK)
    vnet_dev_bus_rdma_close (vm, dev);
  return rv;
}

#if 0
static vnet_dev_rv_t
vnet_dev_bus_rdma_dma_mem_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size,
				u32 align, void **pp)
{
  clib_error_t *err;
  void *p;

  align = align ? align : CLIB_CACHE_LINE_BYTES;
  size = round_pow2 (size, align);

  p = vlib_physmem_alloc_aligned_on_numa (vm, size, align, dev->numa_node);

  if (p == 0)
    {
      err = vlib_physmem_last_error (vm);
      log_err (dev, "dev_dma_mem_alloc: physmem_alloc_aligned error %U",
	       format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_PHYSMEM_ALLOC;
    }

  if ((err = vlib_rdma_map_dma (vm, vnet_dev_get_rdma_handle (dev), p)))
    {
      log_err (dev, "dev_dma_mem_alloc: rdma_map_dma: %U", format_clib_error,
	       err);
      clib_error_free (err);
      return VNET_DEV_ERR_PHYSMEM_ALLOC;
    }

  clib_memset (p, 0, size);
  pp[0] = p;
  return VNET_DEV_OK;
}

static void
vnet_dev_bus_rdma_dma_mem_free (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  if (p)
    vlib_physmem_free (vm, p);
  log_debug (dev, "dev_physmem_free: %p", p);
}

vnet_dev_rv_t
vnet_dev_rdma_map_region (vlib_main_t *vm, vnet_dev_t *dev, u8 region,
			 void **pp)
{
  vlib_rdma_dev_handle_t h = vnet_dev_get_rdma_handle (dev);
  clib_error_t *err;

  if ((err = vlib_rdma_map_region (vm, h, region, pp)))
    {
      log_err (dev, "rdma_map_region: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_rdma_get_revision (vlib_main_t *vm, vnet_dev_t *dev, u8 *revision)
{
  vlib_rdma_dev_handle_t h = vnet_dev_get_rdma_handle (dev);
  u8 rev;
  clib_error_t *err;

  if ((err = vlib_rdma_read_config_u8 (vm, h, 8, &rev)))
    {
      log_err (dev, "rdma_map_region: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  *revision = rev;

  return VNET_DEV_OK;
}
#endif

u8 *
format_vnet_dev_rdma_desc (u8 *s, va_list *args)
{
  struct ibv_device *dev = va_arg (*args, struct ibv_device *);
  clib_error_t *err;
  u8 *path = 0;
  u8 *desc;

  path = format (0, "%s/node_desc%c", dev->ibdev_path, 0);

  err = clib_sysfs_read ((char *) path, "%U", unformat_line, &desc);
  if (err)
    {
      clib_error_free (err);
      vec_free (path);
      return format (s, "%s", dev->dev_name);
    }
  s = format (s, "%v", desc);
  vec_free (path);
  vec_free (desc);
  return s;
}

u8 *clib_file_read_all (u32 max_len, char *fmt, ...);

static u8 *
format_vpd (u8 *s, va_list *args)
{
  u8 *data = va_arg (*args, u8 *), *p = data;
  u8 *id = 0, *vpd_r = 0, *vpd_w = 0;
  u8 *end = vec_end (data);

  while (p < end)
    {
      u8 tag;
      u16 len;
      u8 hdr_sz;

      if (p[0] & (1 << 7))
	{
	  /* large resource type */
	  tag = p[0] & 0x7f;
	  if (end - p < 3)
	    break;
	  len = p[2] << 8 | p[1];
	  hdr_sz = 3;
	}
      else
	{
	  /* small resource type */
	  tag = (p[0] & 0x7f) >> 3;
	  len = p[0] & 0x07;
	  hdr_sz = 1;
	}

      if (end - p < hdr_sz)
	break;
      p += hdr_sz;

      if (tag == 0x02)
	vec_add (id, p, len);
      else if (tag == 0x10)
	vec_add (vpd_r, p, len);
      else if (tag == 0x11)
	vec_add (vpd_w, p, len);
      else if (tag == 0x0f)
	break;

      p += len;
    }

  if (id)
    {
      s = format (s, "%v", id);
      vec_free (id);
    }

  if (vpd_r)
    {
      p = vpd_r;
      end = vec_end (vpd_r);
      while (end - p >= 3)
	{
	  p += 3;

	  s = format (s, "\n[%c%c] ", p[-3], p[-2]);
	  vec_add (s, p, p[-1]);
	  p += p[-1];
	}
      vec_free (vpd_r);
    }

  return s;
}

static u8 *
format_dev_rdma_device_info (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_rdma_device_data_t *rdd = vnet_dev_get_bus_data (dev);
  u32 indent = format_get_indent (s);
  unformat_input_t in;
  u8 *device;

  s = format (
    s, "Kernel IB name is '%s', uverbs device name is '%s', node type is '%s'",
    rdd->dev->name, rdd->dev->dev_name,
    ibv_node_type_str (rdd->dev->node_type));

  if (unformat_init_file (&in, "%s/fw_ver", rdd->dev->ibdev_path))
    {
      u8 *fw_ver;
      if (unformat (&in, "%U", unformat_line, &fw_ver))
	{
	  s = format (s, "\n%UFW version is '%v'", format_white_space, indent,
		      fw_ver);
	  vec_free (fw_ver);
	}
      unformat_free (&in);
    }

  u8 *vpd;
  vpd = clib_file_read_all (32768, "%s/device/vpd", rdd->dev->ibdev_path);
  if (vpd)
    {
      s = format (s, "\n%UVPD[%u]  %U", format_white_space, indent,
		  vec_len (vpd), format_hexdump, vpd, vec_len (vpd));
      s = format (s, "\n%UVPD[%u]  %U", format_white_space, indent,
		  vec_len (vpd), format_vpd, vpd);
    }

  device = clib_file_get_resolved_basename ("%s/device", rdd->dev->ibdev_path);
  if (device)
    {
      vlib_pci_addr_t pci_addr;
      unformat_init_string (&in, (char *) device, strlen ((char *) device));
      vec_free (device);

      if (unformat (&in, "%U", unformat_vlib_pci_addr, &pci_addr))
	{
	  vlib_pci_config_t cfg = {};
	  int fd;
	  u8 *path;

	  s = format (s, "\n%UPCIe address is %U", format_white_space, indent,
		      format_vlib_pci_addr, &pci_addr);
	  path = format (0, "%s/device/config%c", rdd->dev->ibdev_path, 0);
	  fd = open ((char *) path, 0);
	  vec_free (path);
	  if (fd >= 0)
	    {
	      if (read (fd, &cfg, sizeof (cfg)) == sizeof (cfg))
		{
		  s = format (s, ", port is %U, speed is %U (max %U)",
			      format_vlib_pci_link_port, &cfg,
			      format_vlib_pci_link_speed, &cfg,
			      format_vlib_pci_link_speed_cap, &cfg);
		}
	      close (fd);
	    }
	}
      unformat_free (&in);
    }

  return s;
}

static u8 *
format_dev_rdma_device_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_rdma_device_data_t *rdd = vnet_dev_get_bus_data (dev);
  return format (s, "%s", rdd->dev->name);
}

VNET_DEV_REGISTER_BUS (rdma) = {
  .name = "rdma",
  .device_data_size = sizeof (vnet_dev_bus_rdma_device_info_t),
  .ops = {
    .get_device_info = vnet_dev_bus_rdma_get_device_info,
    .free_device_info = vnet_dev_bus_rdma_free_device_info,
    .device_open = vnet_dev_bus_rdma_open,
    .device_close = vnet_dev_bus_rdma_close,
#if 0
    .dma_mem_alloc_fn = vnet_dev_bus_rdma_dma_mem_alloc,
    .dma_mem_free_fn = vnet_dev_bus_rdma_dma_mem_free,
#endif
    .format_device_info = format_dev_rdma_device_info,
    .format_device_addr = format_dev_rdma_device_addr,
  },
};
