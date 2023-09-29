/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_FUNCS_H_
#define _VNET_DEV_FUNCS_H_

#include <vppinfra/clib.h>
#include <vnet/dev/dev.h>

static_always_inline void *
vnet_dev_get_data (vnet_dev_t *dev)
{
  return dev->data;
}

static_always_inline vnet_dev_t *
vnet_dev_from_data (void *p)
{
  return (void *) ((u8 *) p - STRUCT_OFFSET_OF (vnet_dev_t, data));
}

static_always_inline void *
vnet_dev_get_port_data (vnet_dev_port_t *port)
{
  return port->data;
}

static_always_inline void *
vnet_dev_get_rx_queue_data (vnet_dev_rx_queue_t *rxq)
{
  return rxq->data;
}

static_always_inline void *
vnet_dev_get_tx_queue_data (vnet_dev_tx_queue_t *txq)
{
  return txq->data;
}

static_always_inline vnet_dev_t *
vnet_dev_get_by_index (u32 index)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  return pool_elt_at_index (dm->devices, index)[0];
}

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_by_index (vnet_dev_t *dev, u32 index)
{
  return pool_elt_at_index (dev->ports, index)[0];
}

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_from_dev_instance (u32 dev_instance)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  return pool_elt_at_index (dm->ports_by_dev_instance, dev_instance)[0];
}

static_always_inline vnet_dev_t *
vnet_dev_by_id (char *id)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  uword *p = hash_get (dm->device_index_by_id, id);
  if (p)
    return *pool_elt_at_index (dm->devices, p[0]);
  return 0;
}

static_always_inline uword
vnet_dev_get_dma_addr (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  return dev->va_dma ? pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}

static_always_inline void *
vnet_dev_get_bus_data (vnet_dev_t *dev)
{
  return (void *) dev->bus_data;
}

static_always_inline vnet_dev_bus_t *
vnet_dev_get_bus (vnet_dev_t *dev)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  return pool_elt_at_index (dm->buses, dev->bus_index);
}

static_always_inline void
vnet_dev_validate (vlib_main_t *vm, vnet_dev_t *dev)
{
  ASSERT (dev->process_node_index == vlib_get_current_process_node_index (vm));
  ASSERT (vm->thread_index == 0);
}

static_always_inline void
vnet_dev_port_validate (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ASSERT (port->dev->process_node_index ==
	  vlib_get_current_process_node_index (vm));
  ASSERT (vm->thread_index == 0);
}

static_always_inline u32
vnet_dev_port_get_sw_if_index (vnet_dev_port_t *port)
{
  return port->intf.sw_if_index;
}

static_always_inline void *
vnet_dev_alloc_with_data (u32 sz, u32 data_sz)
{
  void *p;
  sz += data_sz;
  sz = round_pow2 (sz, CLIB_CACHE_LINE_BYTES);
  p = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (p, 0, sz);
  return p;
}

#endif /* _VNET_DEV_FUNCS_H_ */
