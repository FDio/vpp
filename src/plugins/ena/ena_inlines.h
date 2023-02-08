/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_INLINES_H_
#define _ENA_INLINES_H_

#include "ena/ena_defs.h"
#include "vppinfra/lock.h"
#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <ena/ena.h>

#define ena_log_err(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_log.class, "%U: " f,                      \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_warn(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ena_log.class, "%U: " f,                  \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_info(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_INFO, ena_log.class, "%U: " f,                     \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_debug(dev, f, ...)                                            \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_log.class, "%U: " f,                    \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_is_debug()                                                    \
  vlib_log_is_enabled (VLIB_LOG_LEVEL_DEBUG, ena_log.class)

static_always_inline ena_device_t *
ena_get_device (u32 dev_instance)
{
  return pool_elt_at_index (ena_main.devices, dev_instance)[0];
}

static_always_inline uword
ena_dma_addr (vlib_main_t *vm, ena_device_t *ed, void *p)
{
  return ed->va_dma ? pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}

static_always_inline void
ena_set_mem_addr (vlib_main_t *vm, ena_device_t *ed, ena_mem_addr_t *m,
		  void *p)
{
  u64 pa = ena_dma_addr (vm, ed, p);
  *m = (ena_mem_addr_t){ .addr_lo = (u32) pa, .addr_hi = (u16) (pa >> 32) };
}

static_always_inline int
ena_admin_feature_is_supported (ena_device_t *ed,
				ena_admin_feature_id_t feat_id)
{
  return (ed->supported_feat_id & (1U << feat_id)) != 0;
}

#endif /* ENA_INLINES_H */
