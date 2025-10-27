/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/log.h>
#include <vlib/file.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "pci",
};

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

  vlib_log_debug (dev_log.class, "device %s", device_id);

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

static void
vnet_dev_bus_pci_free_device_info (vlib_main_t *vm, void *dev_info)
{
  clib_mem_free (dev_info);
}

static vnet_dev_rv_t
vnet_dev_bus_pci_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  clib_error_t *err = 0;
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);

  if (vnet_dev_bus_pci_device_id_to_pci_addr (&pdd->addr, dev->device_id) == 0)
    return VNET_DEV_ERR_INVALID_DEVICE_ID;

  if ((err = vlib_pci_device_open (vm, &pdd->addr, 0, &pdd->handle)))
    {
      log_err (dev, "device_open: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  dev->numa_node = vlib_pci_get_numa_node (vm, pdd->handle);

  if (vlib_pci_supports_virtual_addr_dma (vm, pdd->handle))
    {
      dev->va_dma = 1;
      log_debug (dev, "device supports VA DMA");
    }

  vlib_pci_set_private_data (vm, pdd->handle, (uword) dev);

  pdd->n_msix_int = vlib_pci_get_num_msix_interrupts (vm, pdd->handle);
  if (pdd->n_msix_int)
    {
      u32 sz = sizeof (pdd->msix_handlers[0]) * pdd->n_msix_int;
      sz = round_pow2 (sz, CLIB_CACHE_LINE_BYTES);
      pdd->msix_handlers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
      clib_memset (pdd->msix_handlers, 0, sz);
    }

  return VNET_DEV_OK;
}

static void
vnet_dev_bus_pci_close (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);

  if (pdd->intx_handler)
    vnet_dev_pci_intx_remove_handler (vm, dev);

  if (pdd->msix_handlers)
    {
      for (u16 i = 0; i < pdd->n_msix_int; i++)
	if (pdd->msix_handlers[i])
	  vnet_dev_pci_msix_remove_handler (vm, dev, i, 1);
      clib_mem_free (pdd->msix_handlers);
      pdd->msix_handlers = 0;
    }

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
      return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
    }

  if ((err = vlib_pci_map_dma (vm, vnet_dev_get_pci_handle (dev), p)))
    {
      log_err (dev, "dev_dma_mem_alloc: pci_map_dma: %U", format_clib_error,
	       err);
      clib_error_free (err);
      return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
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
}

vnet_dev_rv_t
vnet_dev_pci_read_config_header (vlib_main_t *vm, vnet_dev_t *dev,
				 vlib_pci_config_hdr_t *hdr)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_read_write_config (vm, h, VLIB_READ, 0, hdr, sizeof (*hdr));
  if (err)
    {
      log_err (dev, "pci_read_config_header: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_read_config (vlib_main_t *vm, vnet_dev_t *dev,
			  vlib_pci_config_t *config)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err =
    vlib_pci_read_write_config (vm, h, VLIB_READ, 0, config, sizeof (*config));
  if (err)
    {
      log_err (dev, "pci_read_config: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_read_config_ext (vlib_main_t *vm, vnet_dev_t *dev,
			      vlib_pci_config_ext_t *config_ext)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_read_write_config (vm, h, VLIB_READ, 0, config_ext,
				    sizeof (*config_ext));
  if (err)
    {
      log_err (dev, "pci_read_config_ext: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_map_region (vlib_main_t *vm, vnet_dev_t *dev, u8 region,
			 void **pp)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  if ((err = vlib_pci_map_region (vm, h, region, pp)))
    {
      log_err (dev, "pci_map_region: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_function_level_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  if ((err = vlib_pci_function_level_reset (vm, h)))
    {
      log_err (dev, "pci_function_level_reset: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_bus_master_enable (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  if ((err = vlib_pci_bus_master_enable (vm, h)))
    {
      log_err (dev, "pci_bus_master_enable: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }
  return VNET_DEV_OK;
}

static void
vnet_dev_pci_intx_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  vnet_dev_t *dev = (vnet_dev_t *) vlib_pci_get_private_data (vm, h);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);

  if (pdd->intx_handler)
    pdd->intx_handler (vm, dev);
}

vnet_dev_rv_t
vnet_dev_pci_intx_add_handler (vlib_main_t *vm, vnet_dev_t *dev,
			       vnet_dev_pci_intx_handler_fn_t *fn)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_register_intx_handler (vm, h, vnet_dev_pci_intx_handler);

  if (err)
    {
      log_err (dev, "pci_register_intx_handler: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_intx_remove_handler (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  clib_error_t *err;

  err = vlib_pci_unregister_intx_handler (vm, h);

  if (err)
    {
      log_err (dev, "pci_unregister_intx_handler: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  pdd->intx_handler = 0;

  return VNET_DEV_OK;
}

static void
vnet_dev_pci_msix_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_dev_t *dev = (vnet_dev_t *) vlib_pci_get_private_data (vm, h);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);

  if (line < pdd->n_msix_int && pdd->msix_handlers[line])
    pdd->msix_handlers[line](vm, dev, line);
}

vnet_dev_rv_t
vnet_dev_pci_msix_add_handler (vlib_main_t *vm, vnet_dev_t *dev,
			       vnet_dev_pci_msix_handler_fn_t *fn, u16 first,
			       u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  clib_error_t *err;

  err = vlib_pci_register_msix_handler (vm, h, first, count,
					vnet_dev_pci_msix_handler);

  if (err)
    {
      log_err (dev, "pci_register_msix_handler: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  for (u16 i = first; i < first + count; i++)
    {
      ASSERT (pdd->msix_handlers[i] == 0);
      pdd->msix_handlers[i] = fn;
    }

  return VNET_DEV_OK;
}

void
vnet_dev_pci_msix_set_polling_thread (vlib_main_t *vm, vnet_dev_t *dev,
				      u16 line,
				      clib_thread_index_t thread_index)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  u32 index;

  index = vlib_pci_get_msix_file_index (vm, h, line);

  clib_file_set_polling_thread (&file_main, index, thread_index);
}

vnet_dev_rv_t
vnet_dev_pci_msix_remove_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 first,
				  u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  clib_error_t *err;

  err = vlib_pci_unregister_msix_handler (vm, h, first, count);

  if (err)
    {
      log_err (dev, "pci_unregister_msix_handler: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  for (u16 i = first; i < first + count; i++)
    {
      ASSERT (pdd->msix_handlers[i] != 0);
      pdd->msix_handlers[i] = 0;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_msix_enable (vlib_main_t *vm, vnet_dev_t *dev, u16 first,
			  u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_enable_msix_irq (vm, h, first, count);

  if (err)
    {
      log_err (dev, "pci_enable_msix_irq: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_msix_disable (vlib_main_t *vm, vnet_dev_t *dev, u16 first,
			   u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_disable_msix_irq (vm, h, first, count);

  if (err)
    {
      log_err (dev, "pci_disable_msix_irq: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_bus_master_disable (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  if ((err = vlib_pci_bus_master_disable (vm, h)))
    {
      log_err (dev, "pci_bus_master_disable: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }
  return VNET_DEV_OK;
}

static u8 *
format_dev_pci_device_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  vlib_main_t *vm = vlib_get_main ();
  vlib_pci_config_t cfg = {};
  clib_error_t *err;

  s = format (s, "PCIe address is %U", format_vlib_pci_addr, &pdd->addr);

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
    .free_device_info = vnet_dev_bus_pci_free_device_info,
    .dma_mem_alloc_fn = vnet_dev_bus_pci_dma_mem_alloc,
    .dma_mem_free_fn = vnet_dev_bus_pci_dma_mem_free,
    .format_device_info = format_dev_pci_device_info,
    .format_device_addr = format_dev_pci_device_addr,
  },
};
