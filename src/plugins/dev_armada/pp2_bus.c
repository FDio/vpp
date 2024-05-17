/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_armada/pp2_bus.h>
#include <vlib/pci/pci.h>
#include <vppinfra/file.h>
#include <vppinfra/linux/sysfs.h>

#include <marvell/pp2/pp2.h>

u8 n_open_devices = 0;
#define MVPP2_BUS_NAME "mvpp2"

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "mvpp2",
  .subclass_name = "bus",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

static int
device_id_to_pp_ids (char *str, u8 *pp_idp, u8 *ppio_idp)
{
  unformat_input_t input;
  u32 pp_id, ppio_id;
  uword rv;

  unformat_init_string (&input, str, strlen (str));
  rv = unformat (&input,
		 MVPP2_BUS_NAME VNET_DEV_DEVICE_ID_PREFIX_DELIMITER "%u.%u",
		 &pp_id, &ppio_id);
  unformat_free (&input);

  if (rv == 0)
    return 0;

  if (!pp2_ppio_available (pp_id, ppio_id))
    return 0;

  *pp_idp = pp_id;
  *ppio_idp = ppio_id;
  return 1;
}

static void *
vnet_dev_bus_mvpp2_get_device_info (vlib_main_t *vm, char *device_id)
{
  vnet_dev_bus_mvpp2_device_info_t *info = 0;
  u8 pp_id, ppio_id;

  if (device_id_to_pp_ids (device_id, &pp_id, &ppio_id) == 0)
    return 0;

  info = clib_mem_alloc (sizeof (*info));
  info->pp_id = pp_id;
  info->ppio_id = ppio_id;

  return info;
}

static void
vnet_dev_bus_mvpp2_free_device_info (vlib_main_t *vm, void *p)
{
  vnet_dev_bus_mvpp2_device_info_t *info = p;
  clib_mem_free (info);
}

static void
vnet_dev_bus_mvpp2_close (vlib_main_t *vm, vnet_dev_t *dev)
{
  if (--n_open_devices)
    return;

  pp2_deinit ();
  mv_sys_dma_mem_destroy ();
}

static vnet_dev_rv_t
vnet_dev_bus_mvpp2_open (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  u8 pp_id, ppio_id;

  if (device_id_to_pp_ids (dev->device_id, &pp_id, &ppio_id) == 0)
    {
      log_err (dev, "failed to find corresponding device");
      return VNET_DEV_ERR_INVALID_DEVICE_ID;
    }

  n_open_devices++;
  return rv;
}

static u8 *
format_dev_mvpp2_device_info (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_mvpp2_device_data_t *dd = vnet_dev_get_bus_data (dev);

  return format (s, "Marvel Packet Processor %u port %u", dd->pp_id,
		 dd->ppio_id);
}

static u8 *
format_dev_mvpp2_device_addr (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_mvpp2_device_data_t *dd = vnet_dev_get_bus_data (dev);
  return format (s, "%u.%u", dd->pp_id, dd->ppio_id);
}

VNET_DEV_REGISTER_BUS (pp2) = {
  .name = MVPP2_BUS_NAME,
  .device_data_size = sizeof (vnet_dev_bus_mvpp2_device_info_t),
  .ops = {
    .get_device_info = vnet_dev_bus_mvpp2_get_device_info,
    .free_device_info = vnet_dev_bus_mvpp2_free_device_info,
    .device_open = vnet_dev_bus_mvpp2_open,
    .device_close = vnet_dev_bus_mvpp2_close,
    .format_device_info = format_dev_mvpp2_device_info,
    .format_device_addr = format_dev_mvpp2_device_addr,
  },
};
