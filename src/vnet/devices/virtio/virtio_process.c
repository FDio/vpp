/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020-2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/gso/gro_func.h>
#include <vnet/interface/rx_queue_funcs.h>

static uword
virtio_send_interrupt_process (vlib_main_t * vm,
			       vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  virtio_if_t *vif;
  f64 timeout = 3153600000.0 /* 100 years */ ;
  uword event_type, *event_data = 0;
  virtio_main_t *vim = &virtio_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      switch (event_type)
	{
	case VIRTIO_EVENT_STOP_TIMER:
	  timeout = 3153600000.0;
	  break;

	case VIRTIO_EVENT_START_TIMER:
	  timeout = 1e-3;	/* 1 millisecond */
	  break;

	case ~0:
	  pool_foreach (vif, vim->interfaces)
	    {
	      if (vif->packet_coalesce || vif->packet_buffering)
		{
		  vnet_virtio_vring_t *vring;
		  vec_foreach (vring, vif->rxq_vrings)
		    {
		      if (vring->mode == VNET_HW_IF_RX_MODE_INTERRUPT ||
			  vring->mode == VNET_HW_IF_RX_MODE_ADAPTIVE)
			vnet_hw_if_rx_queue_set_int_pending (
			  vnet_get_main (), vring->queue_index);
		    }
		}
	    }
	  break;

	default:
	  clib_warning ("BUG: unhandled event type %d", event_type);
	  break;
	}
    }
  return 0;
}

VLIB_REGISTER_NODE (virtio_send_interrupt_node) = {
  .function = virtio_send_interrupt_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "virtio-send-interrupt-process",
};
