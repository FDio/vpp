/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
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
		  virtio_vring_t *vring;
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (virtio_send_interrupt_node) = {
    .function = virtio_send_interrupt_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "virtio-send-interrupt-process",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
