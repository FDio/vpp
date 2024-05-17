/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_armada/musdk.h>
#include <dev_armada/bus.h>

int n_open_devices = 0;
int dma_mem_initialized = 0;

#define MV_SYS_DMA_MEM_SZ (2 << 20)

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "armada",
  .subclass_name = "bus",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U" f,                      \
	    format_vnet_dev_log_prefix, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U" f,                        \
	    format_vnet_dev_log_prefix, dev, ##__VA_ARGS__)

static int
device_id_to_pp_id (char *str, vnet_dev_bus_armada_device_type_t *type,
		    u8 *idp)
{
  unformat_input_t input;
  u32 id;
  uword rv;

  unformat_init_string (&input, str, strlen (str));
  rv = unformat (&input,
		 ARMADA_BUS_NAME VNET_DEV_DEVICE_ID_PREFIX_DELIMITER "ppio-%u",
		 &id);
  unformat_free (&input);

  if (rv == 0)
    return 0;

  *idp = id;
  *type = ARMADA_DEVICE_TYPE_PPIO;
  return 1;
}

static void *
vnet_dev_bus_armada_get_device_info (vlib_main_t *vm, char *device_id)
{
  vnet_dev_bus_armada_device_info_t *info = 0;
  vnet_dev_bus_armada_device_type_t type = ARMADA_DEVICE_TYPE_UNKNOWN;
  u8 id, n_inst;

  device_id_to_pp_id (device_id, &type, &id);

  if (type == ARMADA_DEVICE_TYPE_PPIO)
    {
      n_inst = pp2_get_num_inst ();
      log_debug (0, "%u packet processors available", n_inst);
      if (id >= n_inst)
	return 0;

      info = clib_mem_alloc (sizeof (*info));
      info->pp_id = id;
      info->type = type;
      return info;
    }

  return 0;
}

static void
vnet_dev_bus_armada_free_device_info (vlib_main_t *vm, void *p)
{
  vnet_dev_bus_armada_device_info_t *info = p;
  clib_mem_free (info);
}

static void
vnet_dev_bus_armada_close (vlib_main_t *vm, vnet_dev_t *dev)
{
  if (--n_open_devices)
    return;

  if (dma_mem_initialized)
    {
      mv_sys_dma_mem_destroy ();
      log_debug (0, "mv_sys_dma_mem_destroy()");
      dma_mem_initialized = 0;
    }
}

static vnet_dev_rv_t
vnet_dev_bus_armada_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_bus_armada_device_type_t type = ARMADA_DEVICE_TYPE_UNKNOWN;
  u8 id, n_inst;

  device_id_to_pp_id (dev->device_id, &type, &id);

  if (type == ARMADA_DEVICE_TYPE_UNKNOWN)
    {
      log_err (dev, "invalid device id");
      return VNET_DEV_ERR_INVALID_DEVICE_ID;
    }

  if (type == ARMADA_DEVICE_TYPE_PPIO)
    {
      n_inst = pp2_get_num_inst ();
      if (id >= n_inst)
	{
	  log_err (dev, "failed to find corresponding device");
	  return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	}
    }
  else
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if (n_open_devices++ == 0)
    {
      int mrv = mv_sys_dma_mem_init (MV_SYS_DMA_MEM_SZ);
      if (mrv < 0)
	{
	  log_err (0, "mv_sys_dma_mem_init failed, err %d", mrv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto done;
	}
      dma_mem_initialized = 1;
      log_debug (0, "mv_sys_dma_mem_init(%u) ok", MV_SYS_DMA_MEM_SZ);
    }

done:
  if (rv != VNET_DEV_OK)
    vnet_dev_bus_armada_close (vm, dev);

  return rv;
}

static u8 *
format_dev_armada_device_info (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_armada_device_data_t *dd = vnet_dev_get_bus_data (dev);

  return format (s, "Marvel Packet Processor %u", dd->pp_id);
}

static u8 *
format_dev_armada_device_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_armada_device_data_t *dd = vnet_dev_get_bus_data (dev);
  return format (s, "ppv2-%u", dd->pp_id);
}

VNET_DEV_REGISTER_BUS (pp2) = {
  .name = ARMADA_BUS_NAME,
  .device_data_size = sizeof (vnet_dev_bus_armada_device_info_t),
  .ops = {
    .get_device_info = vnet_dev_bus_armada_get_device_info,
    .free_device_info = vnet_dev_bus_armada_free_device_info,
    .device_open = vnet_dev_bus_armada_open,
    .device_close = vnet_dev_bus_armada_close,
    .format_device_info = format_dev_armada_device_info,
    .format_device_addr = format_dev_armada_device_addr,
  },
};
