/*
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
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <vnet/devices/virtio/virtio.h>

typedef struct
{
  u32 buffer_index;
  u32 sw_if_index;
  u8 is_ip4;
  u8 is_ip6;
} virtio_process_tun_packet_trace_t;

#ifndef CLIB_MARCH_VARIANT
int
vnet_sw_interface_process_tun_packets_enable_disable (u32 sw_if_index,
						      u8 enable)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif;
  vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);

  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  if (vif->type == VIRTIO_IF_TYPE_TUN)
    {
      vnet_feature_enable_disable ("device-input", "process-ip4-tun-packets",
				   sw_if_index, enable, 0, 0);
      vnet_feature_enable_disable ("device-input", "process-ip6-tun-packets",
				   sw_if_index, enable, 0, 0);
    }

  return (0);
}
#endif /* CLIB_MARCH_VARIANT */

static u8 *
format_process_tun_packets_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  virtio_process_tun_packet_trace_t *t =
    va_arg (*args, virtio_process_tun_packet_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U %U buffer-index 0x%x:",
	      format_white_space, indent,
	      format_vnet_sw_if_index_name, vnm, t->sw_if_index,
	      t->buffer_index);
  if (t->is_ip4)
    s = format (s, " ip4 \n");
  else if (t->is_ip6)
    s = format (s, " ip6 \n");

  return s;
}

static_always_inline uword
process_tun_packets_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  u32 n_left_from, *from, *to_next;
  u32 next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      virtio_process_tun_packet_trace_t *t;
	      t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
	      t->buffer_index = bi0;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	      switch (((u8 *) vlib_buffer_get_current (b0))[0] & 0xf0)
		{
		case 0x40:
		  t->is_ip4 = 1;
		  break;
		case 0x60:
		  t->is_ip6 = 1;
		  break;
		default:
		  break;
		}
	    }

	  vnet_feature_next (&next0, b0);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (process_ip4_tun_packets_node) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
{
  return process_tun_packets_inline (vm, node, frame);
}


VLIB_NODE_FN (process_ip6_tun_packets_node) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
{
  return process_tun_packets_inline (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (process_ip4_tun_packets_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_process_tun_packets_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .name = "process-ip4-tun-packets",
};

VLIB_REGISTER_NODE (process_ip6_tun_packets_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_process_tun_packets_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .name = "process-ip6-tun-packets",
};

VNET_FEATURE_INIT (process_tun_packets_node, static) = {
  .arc_name = "device-input",
  .node_name = "process-ip4-tun-packets",
  .runs_before = VNET_FEATURES ("ip4-input"),
};

VNET_FEATURE_INIT (process_ip6_tun_packets_node, static) = {
  .arc_name = "device-input",
  .node_name = "process-ip6-tun-packets",
  .runs_before = VNET_FEATURES ("ip6-input"),
};
/* *INDENT-ON* */

static clib_error_t *
process_tun_packets_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (process_tun_packets_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
