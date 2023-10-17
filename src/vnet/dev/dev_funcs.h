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
  if (pool_is_free_index (dm->ports_by_dev_instance, dev_instance))
    return 0;
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

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_by_id (vnet_dev_t *dev, vnet_dev_port_id_t port_id)
{
  foreach_vnet_dev_port (p, dev)
    if (p->port_id == port_id)
      return p;
  return 0;
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

static_always_inline void
vnet_dev_tx_queue_lock_if_needed (vnet_dev_tx_queue_t *txq)
{
  u8 free = 0;

  if (!txq->lock_needed)
    return;

  while (!__atomic_compare_exchange_n (&txq->lock, &free, 1, 0,
				       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
      while (__atomic_load_n (&txq->lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
      free = 0;
    }
}

static_always_inline void
vnet_dev_tx_queue_unlock_if_needed (vnet_dev_tx_queue_t *txq)
{
  if (!txq->lock_needed)
    return;
  __atomic_store_n (&txq->lock, 0, __ATOMIC_RELEASE);
}

static_always_inline u8
vnet_dev_get_rx_queue_buffer_pool_index (vnet_dev_rx_queue_t *rxq)
{
  return rxq->buffer_template.buffer_pool_index;
}

static_always_inline void
vnet_dev_rx_queue_rt_request (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq,
			      vnet_dev_rx_queue_rt_req_t req)
{
  __atomic_fetch_or (&rxq->runtime_request.as_number, req.as_number,
		     __ATOMIC_RELEASE);
}

static_always_inline vnet_dev_rx_node_runtime_t *
vnet_dev_get_rx_node_runtime (vlib_node_runtime_t *node)
{
  return (void *) node->runtime_data;
}

static_always_inline vnet_dev_tx_node_runtime_t *
vnet_dev_get_tx_node_runtime (vlib_node_runtime_t *node)
{
  return (void *) node->runtime_data;
}

static_always_inline vnet_dev_rx_queue_t **
foreach_vnet_dev_rx_queue_runtime_helper (vlib_node_runtime_t *node)
{
  vnet_dev_rx_node_runtime_t *rt = vnet_dev_get_rx_node_runtime (node);
  return rt->rx_queues;
}

static_always_inline int
vnet_dev_rx_queue_runtime_update (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port;
  vnet_dev_rx_queue_rt_req_t req;
  int rv = 1;

  if (PREDICT_TRUE (rxq->runtime_request.as_number == 0))
    return 1;

  req.as_number =
    __atomic_exchange_n (&rxq->runtime_request.as_number, 0, __ATOMIC_ACQUIRE);

  port = rxq->port;
  if (req.update_next_index)
    rxq->next_index = port->intf.rx_next_index;

  if (req.update_feature_arc)
    {
      vlib_buffer_template_t *bt = &rxq->buffer_template;
      bt->current_config_index = port->intf.current_config_index;
      vnet_buffer (bt)->feature_arc_index = port->intf.feature_arc_index;
    }

  if (req.suspend_on)
    {
      rxq->suspended = 1;
      rv = 0;
    }

  if (req.suspend_off)
    rxq->suspended = 0;

  return rv;
}

static_always_inline void *
vnet_dev_get_rt_temp_space (vlib_main_t *vm)
{
  return vnet_dev_main.runtime_temp_spaces +
	 ((uword) vm->thread_index
	  << vnet_dev_main.log2_runtime_temp_space_sz);
}

static_always_inline void
vnet_dev_set_hw_addr_eth_mac (vnet_dev_hw_addr_t *addr, const u8 *eth_mac_addr)
{
  vnet_dev_hw_addr_t ha = {};
  clib_memcpy_fast (&ha.eth_mac, eth_mac_addr, sizeof (ha.eth_mac));
  *addr = ha;
}

#define foreach_vnet_dev_rx_queue_runtime(q, node)                            \
  for (vnet_dev_rx_queue_t *                                                  \
	 *__qp = foreach_vnet_dev_rx_queue_runtime_helper (node),             \
	**__last = __qp + (vnet_dev_get_rx_node_runtime (node))->n_rx_queues, \
	*(q) = *__qp;                                                         \
       __qp < __last; __qp++, (q) = *__qp)                                    \
    if (vnet_dev_rx_queue_runtime_update (q))

#endif /* _VNET_DEV_FUNCS_H_ */
