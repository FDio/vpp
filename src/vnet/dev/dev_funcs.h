/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_FUNCS_H_
#define _VNET_DEV_FUNCS_H_

#include <vppinfra/clib.h>
#include <vnet/dev/dev.h>

VLIB_REGISTER_LOG_CLASS (dev_log4h, static) = {
  .class_name = "dev",
  .subclass_name = "funcs",
};
#define log4h_info(f, ...)                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, dev_log4h.class, f, 0, ##__VA_ARGS__)

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

static_always_inline vnet_dev_instance_t *
vnet_dev_get_dev_instance (u32 dev_instance)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  if (pool_is_free_index (dm->dev_instances, dev_instance))
    return 0;
  return pool_elt_at_index (dm->dev_instances, dev_instance);
}

static_always_inline vnet_dev_port_interface_t *
vnet_dev_port_get_primary_if (vnet_dev_port_t *p)
{
  return &p->interfaces->primary_interface;
}

static_always_inline vnet_dev_port_interface_t *
vnet_dev_port_get_sec_if_by_index (vnet_dev_port_t *p, u32 index)
{
  return *pool_elt_at_index (p->interfaces->secondary_interfaces, index);
}

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_from_dev_instance (u32 dev_instance)
{
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (dev_instance);

  return di ? di->port : 0;
}

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_from_hw_if_index (u32 hw_if_index)
{
  vnet_hw_interface_t *hw;
  vnet_dev_port_t *port;
  hw = vnet_get_hw_interface (vnet_get_main (), hw_if_index);
  port = vnet_dev_get_port_from_dev_instance (hw->dev_instance);

  if (!port || !port->interfaces ||
      port->interfaces->primary_interface.hw_if_index != hw_if_index)
    return 0;

  return port;
}

static_always_inline u32
vnet_dev_get_rx_queue_if_sw_if_index (vnet_dev_rx_queue_t *rxq)
{
  return rxq->port->interfaces->primary_interface.sw_if_index;
}

static_always_inline u32
vnet_dev_get_rx_queue_if_hw_if_index (vnet_dev_rx_queue_t *rxq)
{
  return rxq->port->interfaces->primary_interface.hw_if_index;
}

static_always_inline u32
vnet_dev_get_port_rx_node_index (vnet_dev_port_t *port)
{
  return port->interfaces->rx_node_index;
}

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_from_sw_if_index (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *si;

  si = vnet_get_sw_interface_or_null (vnm, sw_if_index);
  if (!si)
    return 0;

  return vnet_dev_get_port_from_hw_if_index (si->hw_if_index);
}

static_always_inline vnet_dev_t *
vnet_dev_by_index (u32 index)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  if (pool_is_free_index (dm->devices, index))
    return 0;

  return *pool_elt_at_index (dm->devices, index);
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

static_always_inline vnet_dev_port_t *
vnet_dev_get_port_by_id (vnet_dev_t *dev, vnet_dev_port_id_t port_id)
{
  foreach_vnet_dev_port (p, dev)
    if (p->port_id == port_id)
      return p;
  return 0;
}

static_always_inline vnet_dev_rx_queue_t *
vnet_dev_get_port_rx_queue_by_id (vnet_dev_port_t *port,
				  vnet_dev_queue_id_t queue_id)
{
  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->queue_id == queue_id)
      return q;
  return 0;
}

static_always_inline vnet_dev_tx_queue_t *
vnet_dev_get_port_tx_queue_by_id (vnet_dev_port_t *port,
				  vnet_dev_queue_id_t queue_id)
{
  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->queue_id == queue_id)
      return q;
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

static_always_inline vnet_dev_rx_queue_if_rt_data_t *
vnet_dev_get_rx_queue_if_rt_data (vnet_dev_rx_queue_t *rxq)
{
  return &rxq->if_rt_data;
}

static_always_inline vnet_dev_rx_queue_if_rt_data_t *
vnet_dev_get_rx_queue_sec_if_rt_data (vnet_dev_rx_queue_t *rxq,
				      u32 sec_if_index)
{
  return rxq->sec_if_rt_data[sec_if_index];
}

static_always_inline vlib_buffer_template_t
vnet_dev_get_rx_queue_if_buffer_template (vnet_dev_rx_queue_t *rxq)
{
  return rxq->if_rt_data.buffer_template;
}

static_always_inline vlib_buffer_template_t
vnet_dev_get_rx_queue_sec_if_buffer_template (vnet_dev_rx_queue_t *rxq,
					      u32 sec_if_index)
{
  return rxq->sec_if_rt_data[sec_if_index]->buffer_template;
}

static_always_inline u16
vnet_dev_get_rx_queue_if_next_index (vnet_dev_rx_queue_t *rxq)
{
  return rxq->if_rt_data.next_index;
}

static_always_inline u16
vnet_dev_get_rx_queue_sec_if_next_index (vnet_dev_rx_queue_t *rxq,
					 u32 sec_if_index)
{
  return rxq->sec_if_rt_data[sec_if_index]->next_index;
}

static_always_inline u8
vnet_dev_get_rx_queue_buffer_pool_index (vnet_dev_rx_queue_t *rxq)
{
  return rxq->if_rt_data.buffer_template.buffer_pool_index;
}

static_always_inline u32
vnet_dev_get_rx_queue_buffer_data_size (vlib_main_t *vm,
					vnet_dev_rx_queue_t *rxq)
{
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  return vlib_get_buffer_pool (vm, bpi)->data_size;
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

static_always_inline vnet_dev_rx_queue_t *
foreach_vnet_dev_rx_queue_runtime_helper (vlib_node_runtime_t *node,
					  vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_rx_queue_rt_req_t req;
  vnet_dev_port_interfaces_t *ifs;

  if (rxq == 0)
    rxq = vnet_dev_get_rx_node_runtime (node)->first_rx_queue;
  else
  next:
    rxq = rxq->next_on_thread;

  if (PREDICT_FALSE (rxq == 0))
    return 0;

  if (PREDICT_TRUE (rxq->runtime_request.as_number == 0))
    return rxq;

  req.as_number =
    __atomic_exchange_n (&rxq->runtime_request.as_number, 0, __ATOMIC_ACQUIRE);

  ifs = rxq->port->interfaces;
  if (req.update_next_index)
    {
      log4h_info ("fvdrqrh: update_next_index");
      vnet_dev_port_interface_t **si =
	rxq->port->interfaces->secondary_interfaces;
      rxq->if_rt_data.next_index = ifs->primary_interface.rx_next_index;
      vec_foreach_pointer (rtd, rxq->sec_if_rt_data)
	if (rtd)
	  rtd->next_index = si[rtd->sec_if_index]->rx_next_index;
    }

  if (req.update_feature_arc)
    {
      log4h_info ("fvdrqrh: update_feature_arc");
      vnet_dev_port_interface_t **si =
	rxq->port->interfaces->secondary_interfaces;
      vlib_buffer_template_t *bt = &rxq->if_rt_data.buffer_template;
      bt->current_config_index = ifs->primary_interface.current_config_index;
      vnet_buffer (bt)->feature_arc_index =
	ifs->primary_interface.feature_arc_index;
      vec_foreach_pointer (rtd, rxq->sec_if_rt_data)
	if (rtd)
	  {
	    vlib_buffer_template_t *bt = &rtd->buffer_template;
	    bt->current_config_index =
	      si[rtd->sec_if_index]->current_config_index;
	    vnet_buffer (bt)->feature_arc_index =
	      si[rtd->sec_if_index]->feature_arc_index;
	  }
    }

  if (req.suspend_on)
    {
      rxq->suspended = 1;
      goto next;
    }

  if (req.suspend_off)
    rxq->suspended = 0;

  return rxq;
}

#define foreach_vnet_dev_rx_queue_runtime(q, node)                            \
  for (vnet_dev_rx_queue_t * (q) =                                            \
	 foreach_vnet_dev_rx_queue_runtime_helper (node, 0);                  \
       q; (q) = foreach_vnet_dev_rx_queue_runtime_helper (node, q))

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

static_always_inline vnet_dev_arg_t *
vnet_dev_get_port_arg_by_id (vnet_dev_port_t *port, u32 id)
{
  foreach_vnet_dev_port_args (a, port)
    if (a->id == id)
      return a;
  return 0;
}

static_always_inline int
vnet_dev_arg_get_bool (vnet_dev_arg_t *arg)
{
  ASSERT (arg->type == VNET_DEV_ARG_TYPE_BOOL);
  return arg->val_set ? arg->val.boolean : arg->default_val.boolean;
}

static_always_inline u32
vnet_dev_arg_get_uint32 (vnet_dev_arg_t *arg)
{
  ASSERT (arg->type == VNET_DEV_ARG_TYPE_UINT32);
  return arg->val_set ? arg->val.uint32 : arg->default_val.uint32;
}

static_always_inline u8 *
vnet_dev_arg_get_string (vnet_dev_arg_t *arg)
{
  ASSERT (arg->type == VNET_DEV_ARG_TYPE_STRING);
  return arg->val_set ? arg->val.string : arg->default_val.string;
}

#endif /* _VNET_DEV_FUNCS_H_ */
