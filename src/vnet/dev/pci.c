/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vlib/pci/pci.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "pci",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

static int
vnet_dev_bus_pci_device_id_to_pci_addr (vlib_pci_addr_t *addr, char *str)
{
  unformat_input_t input;
  uword rv;
  unformat_init_string (&input, str, strlen (str));
  rv = unformat (&input, "pci" VNET_DEV_DEVICE_ID_PREFIX_DELIMITER "%U",
		 unformat_vlib_pci_addr, addr);
  unformat_free (&input);
  return rv;
}

static void *
vnet_dev_bus_pci_get_device_info (vlib_main_t *vm, char *device_id)
{
  vnet_dev_bus_pci_device_info_t *info;
  vlib_pci_addr_t addr = {};
  clib_error_t *err = 0;
  vlib_pci_device_info_t *di = 0;

  vlib_log_debug (dev_log.class, "get_device_info: %s", device_id);

  if (vnet_dev_bus_pci_device_id_to_pci_addr (&addr, device_id) == 0)
    return 0;

  di = vlib_pci_get_device_info (vm, &addr, &err);
  if (err)
    {
      vlib_log_err (dev_log.class, "get_device_info: %U", format_clib_error,
		    err);
      clib_error_free (err);
      return 0;
    }

  info = clib_mem_alloc (sizeof (vnet_dev_bus_pci_device_info_t));
  info->addr = addr;
  info->vendor_id = di->vendor_id;
  info->device_id = di->device_id;
  info->revision = di->revision;

  vlib_pci_free_device_info (di);
  return info;
}

static vnet_dev_rv_t
vnet_dev_bus_pci_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  clib_error_t *err = 0;
  vlib_pci_addr_t addr;
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);

  if (vnet_dev_bus_pci_device_id_to_pci_addr (&addr, dev->device_id) == 0)
    return VNET_DEV_ERR_INVALIDE_DEVICE_ID;

  if ((err = vlib_pci_device_open (vm, &addr, 0, &pdd->handle)))
    {
      log_err (dev, "device_open: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  pdd->pci_handle_valid = 1;
  dev->numa_node = vlib_pci_get_numa_node (vm, pdd->handle);

  if (vlib_pci_supports_virtual_addr_dma (vm, pdd->handle))
    {
      dev->va_dma = 1;
      log_debug (dev, "device supports VA DMA");
    }

  return VNET_DEV_OK;
}

static void
vnet_dev_bus_pci_close (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  if (pdd->pci_handle_valid)
    vlib_pci_device_close (vm, pdd->handle);
}

static vnet_dev_rv_t
vnet_dev_bus_pci_dma_mem_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size,
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

  if ((err = vlib_pci_map_dma (vm, vnet_dev_get_pci_handle (dev), p)))
    {
      log_err (dev, "dev_dma_mem_alloc: pci_map_dma: %U", format_clib_error,
	       err);
      clib_error_free (err);
      return VNET_DEV_ERR_PHYSMEM_ALLOC;
    }

  clib_memset (p, 0, size);
  pp[0] = p;
  return VNET_DEV_OK;
}

static void
vnet_dev_bus_pci_dma_mem_free (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  if (p)
    vlib_physmem_free (vm, p);
  log_debug (dev, "dev_physmem_free: %p", p);
}

static u8 *
format_dev_pci_device_info (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  u32 indent = format_get_indent (s);
  vlib_main_t *vm = vlib_get_main ();
  vlib_pci_config_t cfg = {};
  clib_error_t *err;

  s = format (s, "\n%UPCIe address is %U", format_white_space, indent + 2,
	      format_vlib_pci_addr, &pdd->addr);

  err = vlib_pci_read_write_config (vm, pdd->handle, VLIB_READ, 0, &cfg,
				    sizeof (cfg));
  if (!err)
    {
      s = format (s, ", port is %U, speed is %U (max %U)",
		  format_vlib_pci_link_port, &cfg, format_vlib_pci_link_speed,
		  &cfg, format_vlib_pci_link_speed_cap, &cfg);
    }
  else
    clib_error_free (err);

  return s;
}

static u8 *
format_dev_pci_device_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  return format (s, "%U", format_vlib_pci_addr, &pdd->addr);
}

VNET_DEV_REGISTER_BUS (pci) = {
  .name = "pci",
  .device_data_size = sizeof (vnet_dev_bus_pci_device_info_t),
  .ops = {
    .device_open = vnet_dev_bus_pci_open,
    .device_close = vnet_dev_bus_pci_close,
    .get_device_info = vnet_dev_bus_pci_get_device_info,
    .dma_mem_alloc_fn = vnet_dev_bus_pci_dma_mem_alloc,
    .dma_mem_free_fn = vnet_dev_bus_pci_dma_mem_free,
    .format_device_info = format_dev_pci_device_info,
    .format_device_addr = format_dev_pci_device_addr,
  },
};
