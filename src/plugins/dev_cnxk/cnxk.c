/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_cnxk/cnxk.h>
#include <dev_cnxk/mbox.h>
#include <dev_cnxk/bar.h>

VLIB_REGISTER_LOG_CLASS (cnxk_log, static) = {
  .class_name = "dev_cnxk",
  .subclass_name = "init",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cnxk_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_info(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, cnxk_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_notice(id, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, cnxk_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_warn(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cnxk_log.class, "%U: " f,                 \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_err(id, f, ...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_ERR, cnxk_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)

vnet_dev_node_fn_t cnxk_rx_node_fn = {};
vnet_dev_node_fn_t cnxk_tx_node_fn = {};

static struct
{
  u16 device_id;
  cnxk_device_type_t type;
  char *description;
} cnxk_dev_types[] = {

#define _(id, device_type, desc)                                              \
  {                                                                           \
    .device_id = (id), .type = CNXK_DEVICE_TYPE_##device_type,                \
    .description = (desc)                                                     \
  }

  _ (0xa063, RVU_PF, "Marvell CNXK Resource Virtualization Unit PF"),
  _ (0xa0f3, CPT_VF, "Marvell CNXK Cryptographic Accelerator Unit VF"),
#undef _
};

static u8 *
cnxk_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x177d) /* Cavium */
    return 0;

  FOREACH_ARRAY_ELT (dt, cnxk_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

#if 0
static vnet_dev_rv_t
cnxk_err (cnxk_device_t *cd, vnet_dev_rv_t rv, char *fmt, ...)
{
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  log_err (cd, "%v", s);
  vec_free (s);
  return rv;
}
#endif

static_always_inline void
cnxk_clear_int (vnet_dev_t *dev, u64 reg)
{
  u64 intr = cnxk_bar_reg64_read (dev, 2, reg);
  if (intr)
    cnxk_bar_reg64_write (dev, 2, reg, intr);
}

static vnet_dev_rv_t
cnxk_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != 0x177d)
    return VNET_DEV_ERR_UNSUPPORTED_DEV;

  FOREACH_ARRAY_ELT (dt, cnxk_dev_types)
    {
      if (dt->device_id == pci_hdr.device_id)
	cd->type = dt->type;
    }

  rv = VNET_DEV_ERR_UNSUPPORTED_DEV;

  if (cd->type == CNXK_DEVICE_TYPE_UNKNOWN)
    return rv;

  if (cd->bar4 == 0)
    {
      rv = vnet_dev_pci_map_region (vm, dev, 4, &cd->bar4);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  if (cd->bar2 == 0)
    {
      rv = vnet_dev_pci_map_region (vm, dev, 2, &cd->bar2);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  cnxk_clear_int (dev, 0xc20); /* RVU_PF_INT */

  cd->mbox = cnxk_mbox_init (vm, dev);

  return 0;
}

static void
cnxk_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  cnxk_device_t *cd = vnet_dev_get_data (dev);
  cnxk_mbox_free (vm, dev, cd->mbox);
}

VNET_DEV_REGISTER_DRIVER (cnxk) = {
  .name = "cnxk",
  .bus = "pci",
  .device_data_sz = sizeof (cnxk_device_t),
  .ops = {
    .device_init = cnxk_init,
    .device_free = cnxk_free,
    .probe = cnxk_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_cnxk",
};
