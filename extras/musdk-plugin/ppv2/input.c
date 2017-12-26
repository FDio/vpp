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

#include <ppv2/ppv2.h>

#define foreach_ppv2_input_error \
  _(PPIO_RECV, "pp2_ppio_recv error") \
  _(BPOOL_GET_NUM_BUFFS, "pp2_bpool_get_num_buffs error") \
  _(BPOOL_PUT_BUFFS, "pp2_bpool_put_buffs error") \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) PPV2_INPUT_ERROR_##f,
  foreach_ppv2_input_error
#undef _
    PPV2_INPUT_N_ERROR,
} ppv2_input_error_t;

static __clib_unused char *ppv2_input_error_strings[] = {
#define _(n,s) s,
  foreach_ppv2_input_error
#undef _
};

static_always_inline void
ppv2_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node, u32 next0,
		  vlib_buffer_t * b0, uword * n_trace, ppv2_if_t * ppif,
		  struct pp2_ppio_desc *d)
{
  ppv2_input_trace_t *tr;
  vlib_trace_buffer (vm, node, next0, b0,
		     /* follow_chain */ 0);
  vlib_set_trace_count (vm, node, --(*n_trace));
  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
  tr->next_index = next0;
  tr->hw_if_index = ppif->hw_if_index;
  tr->status = pp2_ppio_inq_desc_get_pkt_error (d);
  tr->len = pp2_ppio_inq_desc_get_pkt_len (d);
  tr->isfrag = pp2_ppio_inq_desc_get_ip_isfrag (d);
  tr->cookie = pp2_ppio_inq_desc_get_cookie (d);
  tr->paddr = pp2_ppio_inq_desc_get_phys_addr (d);
  pp2_ppio_inq_desc_get_l3_info (d, &tr->l3_type, &tr->l3_offset);
  pp2_ppio_inq_desc_get_l4_info (d, &tr->l4_type, &tr->l4_offset);
}

static_always_inline uword
ppv2_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, ppv2_if_t * ppif, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  ppv2_main_t *ppm = &ppv2_main;
  u32 thread_index = vlib_get_thread_index ();
  ppv2_inq_t *inq = vec_elt_at_index (ppif->inqs, qid);
  uword n_trace = vlib_get_trace_count (vm, node);
  ppv2_per_thread_data_t *ptd =
    vec_elt_at_index (ppm->per_thread_data, thread_index);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  struct pp2_ppio_desc *d;
  u16 n_desc = VLIB_FRAME_SIZE;
  u32 n_bufs;

  if (PREDICT_FALSE (pp2_ppio_recv (ppif->ppio, 0, qid, ptd->descs, &n_desc)))
    {
      vlib_error_count (vm, node->node_index, PPV2_INPUT_ERROR_PPIO_RECV, 1);
      n_desc = 0;
    }

  vec_validate_aligned (ptd->descs, n_desc, CLIB_CACHE_LINE_BYTES);

  d = ptd->descs;
  while (n_desc)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_desc && n_left_to_next)
	{
	  vlib_buffer_t *b0;
	  u32 bi0 = pp2_ppio_inq_desc_get_cookie (d);
	  u16 len0;

	  len0 = pp2_ppio_inq_desc_get_pkt_len (d);
	  b0 = vlib_get_buffer (vm, bi0);
	  b0->current_data = 2;
	  b0->current_length = len0;
	  b0->total_length_not_including_first_buffer = 0;
	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = ppif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

#if 0
	  u8 l3_offset0, l4_offset0;
	  enum pp2_inq_l3_type l3_type0;
	  enum pp2_inq_l4_type l4_type0;
	  pp2_ppio_inq_desc_get_l3_info (d, &l3_type0, &l3_offset0);
	  pp2_ppio_inq_desc_get_l4_info (d, &l4_type0, &l4_offset0);
	  clib_warning
	    ("received %x len %u, err %d l3_type %u l3_offset %u l4_type %u l4_offset %u",
	     bi0, len0, pp2_ppio_inq_desc_get_l3_pkt_error (d), l3_type0,
	     l3_offset0, l4_type0, l4_offset0);
	  clib_warning ("%p\n%U", b0->data, format_hexdump, b0->data, 128);
#endif

	  if (PREDICT_FALSE (ppif->per_interface_next_index != ~0))
	    next0 = ppif->per_interface_next_index;
	  else
	    vnet_feature_start_device_input_x1 (ppif->sw_if_index, &next0,
						b0);

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  if (PREDICT_FALSE (n_trace > 0))
	    ppv2_input_trace (vm, node, next0, b0, &n_trace, ppif, d);

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next--;
	  d++;
	  n_desc--;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next packet */
	  n_rx_packets++;
	  n_rx_bytes += len0;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_increment_combined_counter (vnm->
				   interface_main.combined_sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX, thread_index,
				   ppif->hw_if_index, n_rx_packets,
				   n_rx_bytes);

  if (PREDICT_FALSE (pp2_bpool_get_num_buffs (inq->bpool, &n_bufs)))
    {
      vlib_error_count (vm, node->node_index,
			PPV2_INPUT_ERROR_BPOOL_GET_NUM_BUFFS, 1);
      goto done;
    }

  n_bufs = inq->size - n_bufs;
  while (n_bufs >= PPV2_BUFF_BATCH_SZ)
    {
      u16 n_alloc, i;
      struct buff_release_entry *e = ptd->bre;
      u32 *buffers = ptd->buffers;

      i = n_alloc = vlib_buffer_alloc (vm, ptd->buffers, PPV2_BUFF_BATCH_SZ);

      if (PREDICT_FALSE (n_alloc == 0))
	{
	  vlib_error_count (vm, node->node_index,
			    PPV2_INPUT_ERROR_BUFFER_ALLOC, 1);
	  goto done;
	}

      while (i--)
	{
	  u32 bi = buffers[0];
	  e->buff.addr = vlib_get_buffer_data_physical_address (vm, bi) - 64;
	  e->buff.cookie = bi;
	  e->bpool = inq->bpool;
	  e++;
	  buffers++;
	}

      i = n_alloc;
      if (PREDICT_FALSE (pp2_bpool_put_buffs (ptd->hif, ptd->bre, &i)))
	{
	  vlib_error_count (vm, node->node_index,
			    PPV2_INPUT_ERROR_BPOOL_PUT_BUFFS, 1);
	  vlib_buffer_free (vm, ptd->buffers, n_alloc);
	  goto done;
	}

      if (PREDICT_FALSE (i != n_alloc))
	vlib_buffer_free (vm, ptd->buffers + i, n_alloc - i);

      n_bufs -= i;
    }

done:
  return n_rx_packets;
}

uword
ppv2_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  u32 n_rx = 0;
  ppv2_main_t *ppm = &ppv2_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    ppv2_if_t *ppif;
    ppif = vec_elt_at_index (ppm->interfaces, dq->dev_instance);
    if (ppif->flags & PPV2_IF_F_ADMIN_UP)
      n_rx += ppv2_device_input_inline (vm, node, frame, ppif, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ppv2_input_node) = {
  .function = ppv2_input_fn,
  .name = "ppv2-input",
  .sibling_of = "device-input",
  .format_trace = format_ppv2_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = PPV2_INPUT_N_ERROR,
  .error_strings = ppv2_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
