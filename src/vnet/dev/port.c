/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/log.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "port",
};

static uword
dummy_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_frame_t *frame)
{
  ASSERT (0);
  return 0;
}

VLIB_REGISTER_NODE (port_rx_eth_node) = {
  .function = dummy_input_fn,
  .name = "port-rx-eth",
  .runtime_data_bytes = sizeof (vnet_dev_rx_node_runtime_t),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_next_nodes = VNET_DEV_ETH_RX_PORT_N_NEXTS,
  .next_nodes = {
#define _(n, s) [VNET_DEV_ETH_RX_PORT_NEXT_##n] = s,
  foreach_vnet_dev_port_rx_next
#undef _
  },
};

u16 vnet_dev_default_next_index_by_port_type[] = {
  [VNET_DEV_PORT_TYPE_ETHERNET] = VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT,
};

VNET_FEATURE_ARC_INIT (eth_port_rx, static) = {
  .arc_name = "port-rx-eth",
  .start_nodes = VNET_FEATURES ("port-rx-eth"),
  .last_in_arc = "ethernet-input",
  .arc_index_ptr = &vnet_dev_main.eth_port_rx_feature_arc_index,
};

VNET_FEATURE_INIT (l2_patch, static) = {
  .arc_name = "port-rx-eth",
  .node_name = "l2-patch",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (worker_handoff, static) = {
  .arc_name = "port-rx-eth",
  .node_name = "worker-handoff",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (span_input, static) = {
  .arc_name = "port-rx-eth",
  .node_name = "span-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (p2p_ethernet_node, static) = {
  .arc_name = "port-rx-eth",
  .node_name = "p2p-ethernet-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (ethernet_input, static) = {
  .arc_name = "port-rx-eth",
  .node_name = "ethernet-input",
  .runs_before = 0, /* not before any other features */
};

void
vnet_dev_port_free (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;

  vnet_dev_port_validate (vm, port);

  ASSERT (port->started == 0);

  log_debug (dev, "port %u", port->port_id);

  if (port->port_ops.free)
    port->port_ops.free (vm, port);

  pool_free (port->secondary_hw_addr);
  pool_free (port->rx_queues);
  pool_free (port->tx_queues);
  vnet_dev_arg_free (&port->args);
  pool_put_index (dev->ports, port->index);
  clib_mem_free (port);
}

void
vnet_dev_port_update_tx_node_runtime (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_validate (vm, port);

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      u32 ti;
      clib_bitmap_foreach (ti, q->assigned_threads)
	{
	  vlib_main_t *tvm = vlib_get_main_by_index (ti);
	  vlib_node_runtime_t *nr =
	    vlib_node_get_runtime (tvm, port->intf.tx_node_index);
	  vnet_dev_tx_node_runtime_t *tnr = vnet_dev_get_tx_node_runtime (nr);
	  tnr->hw_if_index = port->intf.hw_if_index;
	  tnr->tx_queue = q;
	}
    }
}

void
vnet_dev_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rt_op_t *ops = 0;
  u16 n_threads = vlib_get_n_threads ();

  log_debug (dev, "stopping port %u", port->port_id);

  for (u16 i = 0; i < n_threads; i++)
    {
      vnet_dev_rt_op_t op = { .thread_index = i, .port = port };
      vec_add1 (ops, op);
    }

  vnet_dev_rt_exec_ops (vm, dev, ops, vec_len (ops));
  vec_free (ops);

  port->port_ops.stop (vm, port);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      q->started = 0;
      log_debug (dev, "port %u rx queue %u stopped", port->port_id,
		 q->queue_id);
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      q->started = 0;
      log_debug (dev, "port %u tx queue %u stopped", port->port_id,
		 q->queue_id);
    }

  log_debug (dev, "port %u stopped", port->port_id);
  port->started = 0;
}

vnet_dev_rv_t
vnet_dev_port_start_all_rx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  vnet_dev_port_validate (vm, port);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      rv = vnet_dev_rx_queue_start (vm, q);
      if (rv != VNET_DEV_OK)
	return rv;
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_start_all_tx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  vnet_dev_port_validate (vm, port);

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      rv = vnet_dev_tx_queue_start (vm, q);
      if (rv != VNET_DEV_OK)
	return rv;
    }
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  u16 n_threads = vlib_get_n_threads ();
  vnet_dev_t *dev = port->dev;
  vnet_dev_rt_op_t *ops = 0;
  vnet_dev_rv_t rv;

  vnet_dev_port_validate (vm, port);

  log_debug (dev, "starting port %u", port->port_id);

  vnet_dev_port_update_tx_node_runtime (vm, port);

  if ((rv = port->port_ops.start (vm, port)) != VNET_DEV_OK)
    {
      vnet_dev_port_stop (vm, port);
      return rv;
    }

  for (u16 i = 0; i < n_threads; i++)
    {
      vnet_dev_rt_op_t op = { .thread_index = i, .port = port };
      vec_add1 (ops, op);
    }

  vnet_dev_rt_exec_ops (vm, dev, ops, vec_len (ops));
  vec_free (ops);

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      {
	log_debug (dev, "port %u rx queue %u started", port->port_id,
		   q->queue_id);
	q->started = 1;
      }

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->enabled)
      {
	log_debug (dev, "port %u tx queue %u started", port->port_id,
		   q->queue_id);
	q->started = 1;
      }

  port->started = 1;
  log_debug (dev, "port %u started", port->port_id);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_port_add (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t id,
		   vnet_dev_port_add_args_t *args)
{
  vnet_dev_port_t **pp, *port;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  ASSERT (args->port.attr.type != VNET_DEV_PORT_TYPE_UNKNOWN);
  ASSERT (args->port.attr.max_supported_rx_frame_size);

  port =
    vnet_dev_alloc_with_data (sizeof (vnet_dev_port_t), args->port.data_size);
  pool_get (dev->ports, pp);
  pp[0] = port;
  clib_memcpy (vnet_dev_get_port_data (port), args->port.initial_data,
	       args->port.data_size);
  port->port_id = id;
  port->index = pp - dev->ports;
  port->dev = dev;
  port->attr = args->port.attr;
  port->rx_queue_config = args->rx_queue.config;
  port->tx_queue_config = args->tx_queue.config;
  port->rx_queue_ops = args->rx_queue.ops;
  port->tx_queue_ops = args->tx_queue.ops;
  port->port_ops = args->port.ops;
  port->rx_node = *args->rx_node;
  port->tx_node = *args->tx_node;

  if (args->port.args)
    for (vnet_dev_arg_t *a = args->port.args; a->type != VNET_DEV_ARG_END; a++)
      vec_add1 (port->args, *a);

  /* defaults out of port attributes */
  port->max_rx_frame_size = args->port.attr.max_supported_rx_frame_size;
  port->primary_hw_addr = args->port.attr.hw_addr;

  if (port->attr.type == VNET_DEV_PORT_TYPE_ETHERNET)
    {
      if (port->max_rx_frame_size > 1514 &&
	  port->attr.caps.change_max_rx_frame_size)
	port->max_rx_frame_size = 1514;
    }

  if (port->port_ops.alloc)
    rv = port->port_ops.alloc (vm, port);

  if (rv == VNET_DEV_OK)
    port->initialized = 1;

  return rv;
}

vnet_dev_rv_t
vnet_dev_port_cfg_change_req_validate (vlib_main_t *vm, vnet_dev_port_t *port,
				       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv;
  vnet_dev_hw_addr_t *addr;
  int found;

  if (req->validated)
    return VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      if ((req->max_rx_frame_size > port->attr.max_supported_rx_frame_size) ||
	  (req->max_rx_frame_size < ETHERNET_MIN_PACKET_BYTES))
	return VNET_DEV_ERR_INVALID_VALUE;
      if (req->max_rx_frame_size == port->max_rx_frame_size)
	return VNET_DEV_ERR_NO_CHANGE;
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      if (req->promisc == port->promisc)
	return VNET_DEV_ERR_NO_CHANGE;
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      if (clib_memcmp (&req->addr, &port->primary_hw_addr,
		       sizeof (vnet_dev_hw_addr_t)) == 0)
	return VNET_DEV_ERR_NO_CHANGE;
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      pool_foreach (addr, port->secondary_hw_addr)
	if (clib_memcmp (addr, &req->addr, sizeof (*addr)) == 0)
	  return VNET_DEV_ERR_ALREADY_EXISTS;
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      found = 0;
      pool_foreach (addr, port->secondary_hw_addr)
	if (clib_memcmp (addr, &req->addr, sizeof (*addr)) == 0)
	  found = 1;
      if (!found)
	return VNET_DEV_ERR_NO_SUCH_ENTRY;
      break;

    default:
      break;
    }

  if (port->port_ops.config_change_validate)
    {
      rv = port->port_ops.config_change_validate (vm, port, req);
      if (rv != VNET_DEV_OK)
	return rv;
    }
  else
    return VNET_DEV_ERR_NOT_SUPPORTED;

  req->validated = 1;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
			  vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  vnet_dev_hw_addr_t *a;
  vnet_dev_rx_queue_t *rxq = 0;
  u8 enable = 0;

  vnet_dev_port_validate (vm, port);

  if (req->type == VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE ||
      req->type == VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE)
    {
      if (req->all_queues == 0)
	{
	  rxq = vnet_dev_port_get_rx_queue_by_id (port, req->queue_id);
	  if (rxq == 0)
	    return VNET_DEV_ERR_BUG;
	}
    }

  if ((rv = vnet_dev_port_cfg_change_req_validate (vm, port, req)))
    return rv;

  if (port->port_ops.config_change)
    rv = port->port_ops.config_change (vm, port, req);
  else
    return VNET_DEV_ERR_NOT_SUPPORTED;

  if (rv != VNET_DEV_OK)
    return rv;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      port->max_rx_frame_size = req->max_rx_frame_size;
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      port->promisc = req->promisc;
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
      enable = 1;
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      if (req->all_queues)
	{
	  clib_bitmap_t *bmp = 0;
	  vnet_dev_rt_op_t *ops = 0;
	  u32 i;

	  foreach_vnet_dev_port_rx_queue (q, port)
	    {
	      q->interrupt_mode = enable;
	      bmp = clib_bitmap_set (bmp, q->rx_thread_index, 1);
	    }

	  clib_bitmap_foreach (i, bmp)
	    {
	      vnet_dev_rt_op_t op = { .port = port, .thread_index = i };
	      vec_add1 (ops, op);
	    }

	  vnet_dev_rt_exec_ops (vm, port->dev, ops, vec_len (ops));
	  clib_bitmap_free (bmp);
	  vec_free (ops);
	}
      else
	{
	  rxq->interrupt_mode = enable;
	  vnet_dev_rt_exec_ops (vm, port->dev,
				&(vnet_dev_rt_op_t){
				  .port = port,
				  .thread_index = rxq->rx_thread_index,
				},
				1);
	}
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      clib_memcpy (&port->primary_hw_addr, &req->addr,
		   sizeof (vnet_dev_hw_addr_t));
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      pool_get (port->secondary_hw_addr, a);
      clib_memcpy (a, &req->addr, sizeof (vnet_dev_hw_addr_t));
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      pool_foreach (a, port->secondary_hw_addr)
	if (clib_memcmp (a, &req->addr, sizeof (vnet_dev_hw_addr_t)) == 0)
	  {
	    pool_put (port->secondary_hw_addr, a);
	    break;
	  }
      break;

    default:
      break;
    }

  return VNET_DEV_OK;
}

void
vnet_dev_port_state_change (vlib_main_t *vm, vnet_dev_port_t *port,
			    vnet_dev_port_state_changes_t changes)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_dev_port_validate (vm, port);

  if (changes.change.link_speed)
    {
      port->speed = changes.link_speed;
      if (port->interface_created)
	vnet_hw_interface_set_link_speed (vnm, port->intf.hw_if_index,
					  changes.link_speed);
      log_debug (port->dev, "port speed changed to %u", changes.link_speed);
    }

  if (changes.change.link_state)
    {
      port->link_up = changes.link_state;
      if (port->interface_created)
	vnet_hw_interface_set_flags (
	  vnm, port->intf.hw_if_index,
	  changes.link_state ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      log_debug (port->dev, "port link state changed to %s",
		 changes.link_state ? "up" : "down");
    }
}

void
vnet_dev_port_add_counters (vlib_main_t *vm, vnet_dev_port_t *port,
			    vnet_dev_counter_t *counters, u16 n_counters)
{
  vnet_dev_port_validate (vm, port);

  port->counter_main =
    vnet_dev_counters_alloc (vm, counters, n_counters, "%s port %u counters",
			     port->dev->device_id, port->port_id);
}

void
vnet_dev_port_free_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_port_validate (vm, port);

  if (port->counter_main)
    vnet_dev_counters_free (vm, port->counter_main);
}

vnet_dev_rv_t
vnet_dev_port_if_create (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_main_t *vnm = vnet_get_main ();
  u16 n_threads = vlib_get_n_threads ();
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = port->dev;
  vnet_dev_port_t **pp;
  vnet_dev_rv_t rv;
  u16 ti = 0;

  if (port->intf.name[0] == 0)
    {
      u8 *s;
      s = format (0, "%s%u/%u",
		  dm->drivers[port->dev->driver_index].registration->name,
		  port->dev->index, port->index);
      u32 n = vec_len (s);

      if (n >= sizeof (port->intf.name))
	{
	  vec_free (s);
	  return VNET_DEV_ERR_BUG;
	}
      clib_memcpy (port->intf.name, s, n);
      port->intf.name[n] = 0;
      vec_free (s);
    }

  log_debug (
    dev, "allocating %u rx queues with size %u and %u tx queues with size %u",
    port->intf.num_rx_queues, port->intf.rxq_sz, port->intf.num_tx_queues,
    port->intf.txq_sz);

  for (int i = 0; i < port->intf.num_rx_queues; i++)
    if ((rv = vnet_dev_rx_queue_alloc (vm, port, port->intf.rxq_sz)) !=
	VNET_DEV_OK)
      goto error;

  for (u32 i = 0; i < port->intf.num_tx_queues; i++)
    if ((rv = vnet_dev_tx_queue_alloc (vm, port, port->intf.txq_sz)) !=
	VNET_DEV_OK)
      goto error;

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      q->assigned_threads = clib_bitmap_set (q->assigned_threads, ti, 1);
      log_debug (dev, "port %u tx queue %u assigned to thread %u",
		 port->port_id, q->queue_id, ti);
      if (++ti >= n_threads)
	break;
    }

  /* pool of port pointers helps us to assign unique dev_instance */
  pool_get (dm->ports_by_dev_instance, pp);
  port->intf.dev_instance = pp - dm->ports_by_dev_instance;
  pp[0] = port;

  if (port->attr.type == VNET_DEV_PORT_TYPE_ETHERNET)
    {
      vnet_device_class_t *dev_class;
      vnet_dev_driver_t *driver;
      vnet_sw_interface_t *sw;
      vnet_hw_interface_t *hw;
      vnet_hw_if_caps_t caps = 0;
      u32 rx_node_index;

      driver = pool_elt_at_index (dm->drivers, dev->driver_index);

      /* hack to provide per-port tx node function */
      dev_class = vnet_get_device_class (vnm, driver->dev_class_index);
      dev_class->tx_fn_registrations = port->tx_node.registrations;
      dev_class->format_tx_trace = port->tx_node.format_trace;
      dev_class->tx_function_error_counters = port->tx_node.error_counters;
      dev_class->tx_function_n_errors = port->tx_node.n_error_counters;

      /* create new interface including tx and output nodes */
      port->intf.hw_if_index = vnet_eth_register_interface (
	vnm, &(vnet_eth_interface_registration_t){
	       .address = port->primary_hw_addr.eth_mac,
	       .max_frame_size = port->max_rx_frame_size,
	       .dev_class_index = driver->dev_class_index,
	       .dev_instance = port->intf.dev_instance,
	       .cb.set_max_frame_size = vnet_dev_port_set_max_frame_size,
	       .cb.flag_change = vnet_dev_port_eth_flag_change,
	     });

      sw = vnet_get_hw_sw_interface (vnm, port->intf.hw_if_index);
      hw = vnet_get_hw_interface (vnm, port->intf.hw_if_index);
      port->intf.sw_if_index = sw->sw_if_index;
      vnet_hw_interface_set_flags (
	vnm, port->intf.hw_if_index,
	port->link_up ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
      if (port->speed)
	vnet_hw_interface_set_link_speed (vnm, port->intf.hw_if_index,
					  port->speed);

      port->intf.tx_node_index = hw->tx_node_index;

      caps |= port->attr.caps.interrupt_mode ? VNET_HW_IF_CAP_INT_MODE : 0;
      caps |= port->attr.caps.mac_filter ? VNET_HW_IF_CAP_MAC_FILTER : 0;
      caps |= port->attr.tx_offloads.tcp_gso ? VNET_HW_IF_CAP_TCP_GSO : 0;
      caps |= port->attr.tx_offloads.ip4_cksum ? VNET_HW_IF_CAP_TX_CKSUM : 0;

      if (caps)
	vnet_hw_if_set_caps (vnm, port->intf.hw_if_index, caps);

      /* create / reuse rx node */
      if (vec_len (dm->free_rx_node_indices))
	{
	  vlib_node_t *n;
	  rx_node_index = vec_pop (dm->free_rx_node_indices);
	  vlib_node_rename (vm, rx_node_index, "%s-rx", port->intf.name);
	  n = vlib_get_node (vm, rx_node_index);
	  n->function = vlib_node_get_preferred_node_fn_variant (
	    vm, port->rx_node.registrations);
	  n->format_trace = port->rx_node.format_trace;
	  vlib_register_errors (vm, rx_node_index,
				port->rx_node.n_error_counters, 0,
				port->rx_node.error_counters);
	}
      else
	{
	  dev_class->format_tx_trace = port->tx_node.format_trace;
	  dev_class->tx_function_error_counters = port->tx_node.error_counters;
	  dev_class->tx_function_n_errors = port->tx_node.n_error_counters;
	  vlib_node_registration_t rx_node_reg = {
	    .sibling_of = "port-rx-eth",
	    .type = VLIB_NODE_TYPE_INPUT,
	    .state = VLIB_NODE_STATE_DISABLED,
	    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
	    .node_fn_registrations = port->rx_node.registrations,
	    .format_trace = port->rx_node.format_trace,
	    .error_counters = port->rx_node.error_counters,
	    .n_errors = port->rx_node.n_error_counters,
	  };
	  rx_node_index =
	    vlib_register_node (vm, &rx_node_reg, "%s-rx", port->intf.name);
	}
      port->rx_node_assigned = 1;
      port->intf.rx_node_index = rx_node_index;
      port->intf.rx_next_index =
	vnet_dev_default_next_index_by_port_type[port->attr.type];

      vlib_worker_thread_node_runtime_update ();
      log_debug (dev,
		 "ethernet interface created, hw_if_index %u sw_if_index %u "
		 "rx_node_index %u tx_node_index %u",
		 port->intf.hw_if_index, port->intf.sw_if_index,
		 port->intf.rx_node_index, port->intf.tx_node_index);
    }

  port->interface_created = 1;
  foreach_vnet_dev_port_rx_queue (q, port)
    {
      vnet_buffer (&q->buffer_template)->sw_if_index[VLIB_RX] =
	port->intf.sw_if_index;
      /* poison to catch node not calling runtime update function */
      q->next_index = ~0;
      q->interrupt_mode = port->intf.default_is_intr_mode;
      vnet_dev_rx_queue_rt_request (
	vm, q, (vnet_dev_rx_queue_rt_req_t){ .update_next_index = 1 });
    }

  vnet_dev_port_update_tx_node_runtime (vm, port);

  if (port->port_ops.init)
    rv = port->port_ops.init (vm, port);

error:
  if (rv != VNET_DEV_OK)
    vnet_dev_port_if_remove (vm, port);
  return rv;
}

vnet_dev_rv_t
vnet_dev_port_if_remove (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_main_t *vnm = vnet_get_main ();

  vnet_dev_port_validate (vm, port);

  if (port->started)
    vnet_dev_port_stop (vm, port);

  if (port->rx_node_assigned)
    {
      vlib_node_rename (vm, port->intf.rx_node_index, "deleted-%u",
			port->intf.rx_node_index);
      vec_add1 (dm->free_rx_node_indices, port->intf.rx_node_index);
      port->rx_node_assigned = 0;
    }

  if (port->interface_created)
    {
      vlib_worker_thread_barrier_sync (vm);
      vnet_delete_hw_interface (vnm, port->intf.hw_if_index);
      vlib_worker_thread_barrier_release (vm);
      pool_put_index (dm->ports_by_dev_instance, port->intf.dev_instance);
      port->interface_created = 0;
    }

  port->intf = (typeof (port->intf)){};

  if (port->port_ops.deinit)
    port->port_ops.deinit (vm, port);

  foreach_vnet_dev_port_tx_queue (q, port)
    vnet_dev_tx_queue_free (vm, q);

  foreach_vnet_dev_port_rx_queue (q, port)
    vnet_dev_rx_queue_free (vm, q);

  vnet_dev_port_free_counters (vm, port);

  foreach_vnet_dev_port_args (v, port)
    vnet_dev_arg_clear_value (v);

  return VNET_DEV_OK;
}
void
vnet_dev_port_clear_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  if (port->port_ops.clear_counters)
    port->port_ops.clear_counters (vm, port);
  else if (port->counter_main)
    vnet_dev_counters_clear (vm, port->counter_main);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      if (port->rx_queue_ops.clear_counters)
	port->rx_queue_ops.clear_counters (vm, q);
      else if (q->counter_main)
	vnet_dev_counters_clear (vm, q->counter_main);
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      if (port->tx_queue_ops.clear_counters)
	port->tx_queue_ops.clear_counters (vm, q);
      else if (q->counter_main)
	vnet_dev_counters_clear (vm, q->counter_main);
    }

  log_notice (port->dev, "counters cleared on port %u", port->port_id);
}
