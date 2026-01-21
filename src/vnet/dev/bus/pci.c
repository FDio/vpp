/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/log.h>
#include <vlib/file.h>
#include <vppinfra/unix.h>

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
  info->sub_vendor_id = di->config.sub_vendor_id;
  info->sub_device_id = di->config.sub_device_id;
  info->class_code = (di->device_class << 8) | di->config.prog_if;
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

  if (vnet_dev_main.drivers[dev->driver_index].registration->passive == 1)
    {
      pdd->is_passive = 1;
      return VNET_DEV_OK;
    }

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

  pdd->n_msi_int = vlib_pci_get_num_msi_interrupts (vm, pdd->handle);
  if (pdd->n_msi_int)
    {
      u32 sz = sizeof (pdd->msi_handlers[0]) * pdd->n_msi_int;
      sz = round_pow2 (sz, CLIB_CACHE_LINE_BYTES);
      pdd->msi_handlers = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
      clib_memset (pdd->msi_handlers, 0, sz);
    }

  return VNET_DEV_OK;
}

static void
vnet_dev_bus_pci_close (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);

  if (pdd->is_passive)
    return;

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

  if (pdd->msi_handlers)
    {
      for (u16 i = 0; i < pdd->n_msi_int; i++)
	if (pdd->msi_handlers[i])
	  vnet_dev_pci_msi_remove_handler (vm, dev, i, 1);
      clib_mem_free (pdd->msi_handlers);
      pdd->msi_handlers = 0;
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
vnet_dev_pci_config_read (vlib_main_t *vm, vnet_dev_t *dev, u32 offset, u32 len, u32 *val)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_read_write_config (vm, h, VLIB_READ, offset, val, len);
  if (err)
    {
      log_err (dev, "pci_config_read: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_config_write (vlib_main_t *vm, vnet_dev_t *dev, u32 offset, u32 len, u32 val)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_read_write_config (vm, h, VLIB_WRITE, offset, &val, len);
  if (err)
    {
      log_err (dev, "pci_config_write: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_read_config_header (vlib_main_t *vm, vnet_dev_t *dev, vlib_pci_config_hdr_t *hdr)
{
  return vnet_dev_pci_config_read (vm, dev, 0, sizeof (*hdr), (u32 *) hdr);
}

vnet_dev_rv_t
vnet_dev_pci_read_config (vlib_main_t *vm, vnet_dev_t *dev, vlib_pci_config_t *config)
{
  return vnet_dev_pci_config_read (vm, dev, 0, sizeof (*config), (u32 *) config);
}

vnet_dev_rv_t
vnet_dev_pci_read_config_ext (vlib_main_t *vm, vnet_dev_t *dev,
			      vlib_pci_config_ext_t *config_ext)
{
  return vnet_dev_pci_config_read (vm, dev, 0, sizeof (*config_ext), (u32 *) config_ext);
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

static void
vnet_dev_pci_msi_handler (vlib_main_t *vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_dev_t *dev = (vnet_dev_t *) vlib_pci_get_private_data (vm, h);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);

  if (line < pdd->n_msi_int && pdd->msi_handlers[line])
    pdd->msi_handlers[line](vm, dev, line);
}

vnet_dev_rv_t
vnet_dev_pci_msi_add_handler (vlib_main_t *vm, vnet_dev_t *dev,
			      vnet_dev_pci_msix_handler_fn_t *fn, u16 first,
			      u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  clib_error_t *err;

  err = vlib_pci_register_msi_handler (vm, h, first, count,
				       vnet_dev_pci_msi_handler);

  if (err)
    {
      log_err (dev, "pci_register_msi_handler: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  for (u16 i = first; i < first + count; i++)
    {
      ASSERT (pdd->msi_handlers[i] == 0);
      pdd->msi_handlers[i] = fn;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_msi_remove_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 first,
				 u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  vnet_dev_bus_pci_device_data_t *pdd = vnet_dev_get_bus_pci_device_data (dev);
  clib_error_t *err;

  err = vlib_pci_unregister_msi_handler (vm, h, first, count);

  if (err)
    {
      log_err (dev, "pci_unregister_msi_handler: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  for (u16 i = first; i < first + count; i++)
    {
      ASSERT (pdd->msi_handlers[i] != 0);
      pdd->msi_handlers[i] = 0;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_msi_enable (vlib_main_t *vm, vnet_dev_t *dev, u16 first,
			 u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_enable_msi_irq (vm, h, first, count);

  if (err)
    {
      log_err (dev, "pci_enable_msi_irq: %U", format_clib_error, err);
      clib_error_free (err);
      return VNET_DEV_ERR_BUS;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_msi_disable (vlib_main_t *vm, vnet_dev_t *dev, u16 first,
			  u16 count)
{
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;

  err = vlib_pci_disable_msi_irq (vm, h, first, count);

  if (err)
    {
      log_err (dev, "pci_disable_msi_irq: %U", format_clib_error, err);
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

u8
vnet_dev_pci_find_next_std_capa_offset (vlib_main_t *vm, vnet_dev_t *dev, u8 capa_id,
					u8 current_capa_offset)
{
  u32 pos = current_capa_offset;
  u32 val;
  u8 id, next;

  if (pos == 0)
    {
      if (vnet_dev_pci_config_read (vm, dev, 0x34, 1, &pos) != VNET_DEV_OK)
	return 0;
    }
  else
    {
      if (vnet_dev_pci_config_read (vm, dev, pos + 1, 1, &pos) != VNET_DEV_OK)
	return 0;
    }

  pos &= 0xff;

  while (pos)
    {
      if (vnet_dev_pci_config_read (vm, dev, pos, 2, &val) != VNET_DEV_OK)
	return 0;

      id = val & 0xff;
      next = (val >> 8) & 0xff;

      if (id == capa_id)
	return pos;

      pos = next;
    }
  return 0;
}

vnet_dev_rv_t
vnet_dev_pci_set_power_state (vlib_main_t *vm, vnet_dev_t *dev, u8 state)
{
  u32 ctrl;
  vnet_dev_rv_t rv;
  u8 pos;

  log_debug (dev, "pci_set_power_state: start state %u", state);

  pos = vnet_dev_pci_find_next_std_capa_offset (vm, dev, VNET_DEV_PCI_STD_CAP_PM, 0);
  if (!pos)
    return VNET_DEV_ERR_NOT_SUPPORTED;

  rv = vnet_dev_pci_config_read (vm, dev, pos + 4, 2, &ctrl);
  if (rv != VNET_DEV_OK)
    return rv;

  if ((ctrl & 0x3) != (state & 0x3))
    {
      log_debug (dev, "pci_set_power_state: setting state to D%u", state & 0x3);
      ctrl &= ~0x3;
      ctrl |= (state & 0x3);
      rv = vnet_dev_pci_config_write (vm, dev, pos + 4, 2, ctrl);
      if (rv != VNET_DEV_OK)
	return rv;

      /* Wait for transition (D3->D0 requires 10ms) */
      if ((state & 0x3) == 0)
	vlib_process_suspend (vm, 10e-3);
      log_debug (dev, "pci_set_power_state: transition complete");
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_pci_get_power_state (vlib_main_t *vm, vnet_dev_t *dev, u8 *state)
{
  u32 ctrl;
  vnet_dev_rv_t rv;
  u8 pos;

  pos = vnet_dev_pci_find_next_std_capa_offset (vm, dev, VNET_DEV_PCI_STD_CAP_PM, 0);
  if (!pos)
    {
      *state = 0; /* Assume D0 if no PM capability */
      return VNET_DEV_OK;
    }

  rv = vnet_dev_pci_config_read (vm, dev, pos + 4, 2, &ctrl);
  if (rv != VNET_DEV_OK)
    {
      *state = 0; /* Assume D0 if error */
      return VNET_DEV_OK;
    }

  *state = ctrl & 0x3;
  return VNET_DEV_OK;
}
static u8 *
pci_ids_helper (u16 vid, u16 did)
{
  unformat_input_t input;
  u32 id = CLIB_U32_MAX;
  uword c;
  u8 *data = 0;
  u8 *name = 0;

  foreach_pointer (p, "/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids")
    {
      clib_error_t *err = clib_file_contents (p, &data);
      if (!err)
	break;
      clib_error_free (err);
    }

  if (!data)
    return 0;

  unformat_init_vector (&input, data);

  while (1)
    {
      c = unformat_peek_input (&input);

      if (c == UNFORMAT_END_OF_INPUT)
	break;

      if (c != '\t' && c != '#' && c != '\n')
	unformat (&input, "%x", &id);

      if (id == vid)
	break;

      unformat_skip_line (&input);
    }

  if (id != vid)
    goto done;

  if (did == 0xffff)
    {
      unformat (&input, "%U", unformat_line, &name);
      goto done;
    }
  else
    unformat_skip_line (&input);

  id = CLIB_U32_MAX;
  while (!name)
    {
      c = unformat_get_input (&input);

      if (c == UNFORMAT_END_OF_INPUT)
	break;

      if (c != '\t' && c != '#' && c != '\n')
	break;

      if (c == '\t' && unformat_peek_input (&input) != '\t' &&
	  unformat (&input, "%x", &id) && id == did)
	unformat (&input, "%U", unformat_line, &name);
      unformat_skip_line (&input);
    }

done:
  unformat_free (&input);
  return name;
}

u8 *
format_dev_pci_device_name_from_ids (u8 *s, va_list *args)
{
  u16 vid = va_arg (*args, u32);
  u16 did = va_arg (*args, u32);

  u8 *name = pci_ids_helper (vid, did);

  if (!name)
    return format (s, "Unknown Device (%04x:%04x)", vid, did);

  s = format (s, "%v", name);
  vec_free (name);
  return s;
}

u8 *
format_dev_pci_vendor_name_from_ids (u8 *s, va_list *args)
{
  u16 vid = va_arg (*args, u32);

  u8 *name = pci_ids_helper (vid, 0xffff);

  if (!name)
    return format (s, "Unknown Vendor (%04x)", vid);

  s = format (s, "%v", name);
  vec_free (name);
  return s;
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

  s = format (s, "PCIe address is %U", format_vlib_pci_addr, &pdd->addr);

  if (pdd->is_passive)
    return s;

  if (vnet_dev_pci_config_read (vm, dev, 0, sizeof (cfg), (u32 *) &cfg) == VNET_DEV_OK)
    {
      s = format (s, ", port is %U, speed is %U (max %U)",
		  format_vlib_pci_link_port, &cfg, format_vlib_pci_link_speed,
		  &cfg, format_vlib_pci_link_speed_cap, &cfg);
    }

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
