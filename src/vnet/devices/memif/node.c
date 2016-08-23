/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <vnet/devices/memif/memif.h>

#define foreach_memif_input_error

typedef enum
{
#define _(f,s) MEMIF_INPUT_ERROR_##f,
  foreach_memif_input_error
#undef _
    MEMIF_INPUT_N_ERROR,
} memif_input_error_t;

static char *memif_input_error_strings[] = {
#define _(n,s) s,
  foreach_memif_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
} memif_input_trace_t;

static u8 *
format_memif_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  memif_input_trace_t *t = va_arg (*args, memif_input_trace_t *);
  uword indent = format_get_indent (s);

  s = format (s, "memif: hw_if_index %d next-index %d",
	      t->hw_if_index, t->next_index);
  s = format (s, "\n%Uslot: TODO", format_white_space, indent + 2);
  return s;
}

static_always_inline uword
memif_device_input_master (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  u8 rid = 0;			/* Ring id */
  memif_ring_t *ring = memif_get_s2m_ring (mif, rid);
  memif_ring_data_t *rd = vec_elt_at_index (mif->s2m_ring_data, rid);
  u16 head;

  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  memif_main_t *nm = &memif_main;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 n_free_bufs;
  u32 cpu_index = os_get_cpu_number ();
  static __thread struct iovec *liov = 0;
  static __thread struct iovec *riov = 0;
  u32 bi0;
  vlib_buffer_t *b0;
  u16 ring_size = 1 << mif->log2_ring_size;
  u16 mask = ring_size - 1;

  if (mif->per_interface_next_index != ~0)
    next_index = mif->per_interface_next_index;

  n_free_bufs = vec_len (nm->rx_buffers[cpu_index]);
  if (PREDICT_FALSE (n_free_bufs < ring_size))
    {
      vec_validate (nm->rx_buffers[cpu_index], ring_size + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &nm->rx_buffers[cpu_index][n_free_bufs],
			   ring_size);
      _vec_len (nm->rx_buffers[cpu_index]) = n_free_bufs;

      if (n_free_bufs < ring_size)
	clib_warning ("ERRROR %d", n_free_bufs);
    }

  head = ring->head;
  if (head == rd->last_head)
    return 0;

  while (head != rd->last_head)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (head != rd->last_head && n_left_to_next)
	{
	  struct iovec *iov;

	  /* Add remote iov */
	  vec_add2 (riov, iov, 1);
	  iov->iov_base = (void *) ring->desc[rd->last_head].addr;
	  iov->iov_len = ring->desc[rd->last_head].length;

	  /* get one free buffer */
	  u32 last_empty_buffer = vec_len (nm->rx_buffers[cpu_index]) - 1;
	  bi0 = nm->rx_buffers[cpu_index][last_empty_buffer];
	  _vec_len (nm->rx_buffers[cpu_index]) = last_empty_buffer;

	  /* fill buffer metadata */
	  b0 = vlib_get_buffer (vm, bi0);
	  b0->current_length = ring->desc[rd->last_head].length;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* enqueue */
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next--;

	  /* Add local iov */
	  vec_add2 (liov, iov, 1);
	  iov->iov_base = vlib_buffer_get_current (b0);
	  iov->iov_len = b0->current_length;

	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      if (PREDICT_TRUE (b0 != 0))
		{
		  memif_input_trace_t *tr;
		  vlib_trace_buffer (vm, node, next0, b0,
				     /* follow_chain */ 0);
		  vlib_set_trace_count (vm, node, --n_trace);
		  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->next_index = next0;
		  tr->hw_if_index = mif->hw_if_index;
		}
	    }
	  /* redirect if feature path enabled */
	  vnet_feature_start_device_input_x1 (mif->sw_if_index, &next0, b0,
					      0);

	  /* enque and take next packet */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next packet */
	  rd->last_head = (rd->last_head + 1) & mask;
	  n_rx_packets++;
	  n_rx_bytes += b0->current_length;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  process_vm_readv (mif->remote_pid, liov, vec_len (liov), riov,
		    vec_len (riov), 0);

  vec_reset_length (liov);
  vec_reset_length (riov);
  CLIB_MEMORY_BARRIER ();
  ring->tail = head;

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, cpu_index,
				   mif->hw_if_index, n_rx_packets,
				   n_rx_bytes);

  return n_rx_packets;
}

static_always_inline uword
memif_device_input_slave (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  u8 rid = 0;			/* Ring id */
  memif_ring_t *ring = memif_get_m2s_ring (mif, rid);
  memif_ring_data_t *rd = vec_elt_at_index (mif->m2s_ring_data, rid);
  u16 head, tail;

  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  memif_main_t *nm = &memif_main;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 n_free_bufs;
  u32 cpu_index = os_get_cpu_number ();
  u32 bi0;
  vlib_buffer_t *b0;
  u16 ring_size = 1 << mif->log2_ring_size;
  u16 mask = ring_size - 1;
  u32 n_buffer_bytes = vlib_buffer_free_list_buffer_size (vm,
							  VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  if (mif->per_interface_next_index != ~0)
    next_index = mif->per_interface_next_index;

  n_free_bufs = vec_len (nm->rx_buffers[cpu_index]);
  if (PREDICT_FALSE (n_free_bufs < ring_size))
    {
      vec_validate (nm->rx_buffers[cpu_index], ring_size + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &nm->rx_buffers[cpu_index][n_free_bufs],
			   ring_size);
      _vec_len (nm->rx_buffers[cpu_index]) = n_free_bufs;
    }

  head = ring->head;
  tail = ring->tail;
  if (tail == rd->last_tail)
    return 0;

  while (tail != rd->last_tail)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (tail != rd->last_tail && n_left_to_next)
	{
	  /* take buffer from ring */
	  bi0 = rd->buffers[rd->last_tail];
	  b0 = vlib_get_buffer (vm, bi0);
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next--;

	  /* fill buffer metadata */
	  b0->current_length = ring->desc[rd->last_tail].length;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = mif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* fill slot with empty buffer */
	  u32 last_empty_buffer = vec_len (nm->rx_buffers[cpu_index]) - 1;
	  u32 empty_bi0 = nm->rx_buffers[cpu_index][last_empty_buffer];
	  vlib_buffer_t *eb0 = vlib_get_buffer (vm, empty_bi0);
	  _vec_len (nm->rx_buffers[cpu_index]) = last_empty_buffer;
	  rd->buffers[rd->last_tail] = empty_bi0;
	  ring->desc[rd->last_tail].addr =
	    pointer_to_uword (vlib_buffer_get_current (eb0));
	  ring->desc[rd->last_tail].length = n_buffer_bytes;
	  ring->desc[rd->last_tail].flags = 0;

	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      if (PREDICT_TRUE (b0 != 0))
		{
		  memif_input_trace_t *tr;
		  vlib_trace_buffer (vm, node, next0, b0,
				     /* follow_chain */ 0);
		  vlib_set_trace_count (vm, node, --n_trace);
		  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->next_index = next0;
		  tr->hw_if_index = mif->hw_if_index;
		}
	    }


	  /* redirect if feature path enabled */
	  vnet_feature_start_device_input_x1 (mif->sw_if_index, &next0, b0,
					      0);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next packet */
	  rd->last_tail = (rd->last_tail + 1) & mask;
	  head = (head + 1) & mask;
	  n_rx_packets++;
	  n_rx_bytes += b0->current_length;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  CLIB_MEMORY_BARRIER ();
  ring->head = head;

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, cpu_index,
				   mif->hw_if_index, n_rx_packets,
				   n_rx_bytes);

  return n_rx_packets;
}

static uword
memif_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  int i;
  u32 n_rx_packets = 0;
  u32 cpu_index = os_get_cpu_number ();
  memif_main_t *nm = &memif_main;
  memif_if_t *mif;

  for (i = 0; i < vec_len (nm->interfaces); i++)
    {
      mif = vec_elt_at_index (nm->interfaces, i);
      if (mif->flags & MEMIF_IF_FLAG_ADMIN_UP &&
	  mif->flags & MEMIF_IF_FLAG_CONNECTED &&
	  (i % nm->input_cpu_count) ==
	  (cpu_index - nm->input_cpu_first_index))
	{
	  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
	    n_rx_packets += memif_device_input_slave (vm, node, frame, mif);
	  else
	    n_rx_packets += memif_device_input_master (vm, node, frame, mif);
	}
    }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memif_input_node) = {
  .function = memif_input_fn,
  .name = "memif-input",
  .sibling_of = "device-input",
  .format_trace = format_memif_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = MEMIF_INPUT_N_ERROR,
  .error_strings = memif_input_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (memif_input_node, memif_input_fn)
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
