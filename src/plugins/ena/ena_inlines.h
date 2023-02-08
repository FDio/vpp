/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_INLINES_H_
#define _ENA_INLINES_H_

#include "ena/ena_defs.h"
#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <ena/ena.h>

#define ena_log_err(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_log.class, "%U: " f,                      \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_warn(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ena_log.class, "%U: " f,                  \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_notice(dev, f, ...)                                           \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, ena_log.class, "%U: " f,                   \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_info(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_INFO, ena_log.class, "%U: " f,                     \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_debug(dev, f, ...)                                            \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_log.class, "%U: " f,                    \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_is_debug()                                                    \
  vlib_log_is_enabled (VLIB_LOG_LEVEL_DEBUG, ena_log.class)

#define ena_stats_log_err(dev, f, ...)                                        \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_stats_log.class, "%U: " f,                \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_stats_log_debug(dev, f, ...)                                      \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_stats_log.class, "%U: " f,              \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_stats_log_is_debug()                                              \
  vlib_log_is_enabled (VLIB_LOG_LEVEL_DEBUG, ena_stats_log.class)

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
  return (ed->dev_attr.supported_features & (1U << feat_id)) != 0;
}

static_always_inline ena_queue_state_t
ena_queue_state_set_in_use (ena_queue_state_t *lock)
{
  while (1)
    {
      ena_queue_state_t tmp = ENA_QUEUE_STATE_READY;

      if (__atomic_compare_exchange_n (lock, &tmp, ENA_QUEUE_STATE_IN_USE, 0,
				       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	return ENA_QUEUE_STATE_IN_USE;

      if (tmp != ENA_QUEUE_STATE_IN_USE)
	return tmp;

      while (__atomic_load_n (lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
    }
}

static_always_inline void
ena_queue_state_set_disabled (ena_queue_state_t *lock)
{
  if (*lock == ENA_QUEUE_STATE_DISABLED)
    return;

  while (1)
    {
      ena_queue_state_t tmp = ENA_QUEUE_STATE_READY;

      if (__atomic_compare_exchange_n (lock, &tmp, ENA_QUEUE_STATE_DISABLED, 0,
				       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	return;

      while (__atomic_load_n (lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
    }
}

static_always_inline void
ena_queue_state_set_ready (u8 *lock)
{
  __atomic_store_n (lock, ENA_QUEUE_STATE_READY, __ATOMIC_RELEASE);
}

static_always_inline u16 *
ena_rxq_get_compl_sqe_indices (ena_rxq_t *rxq)
{
  return (u16 *) ((u8 *) rxq + rxq->compl_sq_indices_off);
}

static_always_inline u64 *
ena_txq_get_sqe_templates (ena_txq_t *txq)
{
  return (u64 *) ((u8 *) txq + txq->sqe_templates_offset);
}

#endif /* ENA_INLINES_H */
