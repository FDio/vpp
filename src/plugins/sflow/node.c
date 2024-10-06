/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vlibmemory/api.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

// different logging options
// #define SFLOW_LOG_CYCLES 1
// #define SFLOW_LOG_SAMPLES 1  // will add to cycles

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} sflow_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
my_format_mac_address (u8 *s, va_list *args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3],
		 a[4], a[5]);
}

/* packet trace format function */
static u8 *
format_sflow_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sflow_trace_t *t = va_arg (*args, sflow_trace_t *);

  s = format (s, "SFLOW: sw_if_index %d, next index %d\n", t->sw_if_index,
	      t->next_index);
  s = format (s, "  src %U -> dst %U", my_format_mac_address, t->new_src_mac,
	      my_format_mac_address, t->new_dst_mac);
  return s;
}

vlib_node_registration_t sflow_node;

#endif /* CLIB_MARCH_VARIANT */

#ifndef CLIB_MARCH_VARIANT
static char *sflow_error_strings[] = {
#define _(sym, string) string,
  foreach_sflow_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  SFLOW_NEXT_ETHERNET_INPUT,
  SFLOW_N_NEXT,
} sflow_next_t;

VLIB_NODE_FN (sflow_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  sflow_next_t next_index;
  u32 pkts_processed = 0, pkts_sampled = 0, pkts_dropped = 0;

  sflow_main_t *smp = &sflow_main;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  uword thread_index = os_get_thread_index ();
  sflow_per_thread_data_t *sfwk =
    vec_elt_at_index (smp->per_thread_data, thread_index);

  u32 pkts = n_left_from;
  if (sfwk->skip >= pkts)
    {
      /* skip the whole frame */
      sfwk->skip -= pkts;
      sfwk->pool += pkts;
      // clib_warning("sflow frame skip->%u", sfwk->skip);
    }
  else
    {
      // TODO: if we simply refuse to sample more than one packet from
      // a batch does it avoid destabilizing VPP under high load?  A
      // minimum skip count is allowed in sFlow. Which translates to
      // a minimum sampling-rate setting of, say, minimum skip count * 2
      // so that there is still some random variation. If we require it to
      // be the batch size then we won't ever have to loop here and
      // "while" becomes "if". Obviously we would enforce a min-skip
      // in sflow.c at config time, but perhaps we end up with an override like
      // the Arista one "sflow enable GigabitEthernet0/8/0 dangerous 1"
      // so that 1:1 can still be set if you know what you are doing :)
      while (pkts > sfwk->skip)
	{
#ifdef SFLOW_LOG_CYCLES
	  u64 cycles1 = clib_cpu_time_now ();
#endif
	  /* reach in to get the one we want. */
	  vlib_buffer_t *bN = vlib_get_buffer (vm, from[sfwk->skip]);
	  /* Seems unlikely that prefetch is going to help here. */
	  // vlib_prefetch_buffer_header(bN, LOAD);
	  // CLIB_PREFETCH(bN->data, CLIB_CACHE_LINE_BYTES, STORE);

	  /* Sample this packet header. */
	  u32 hdr = bN->current_length;
	  if (hdr > smp->header_bytes)
	    hdr = smp->header_bytes;

	  ethernet_header_t *en = vlib_buffer_get_current (bN);
	  u32 if_index = vnet_buffer (bN)->sw_if_index[VLIB_RX];
	  vnet_hw_interface_t *hw =
	    vnet_get_sup_hw_interface (smp->vnet_main, if_index);
	  if (hw)
	    if_index = hw->hw_if_index;
	  else
	    {
	      // TODO: can we get interfaces that have no hw interface?
	      // If so,  should we ignore the sample?
	    }
#ifdef SFLOW_LOG_SAMPLES
	  clib_warning ("sflow take sample if_index=%u len=%u "
			"en->src_address=%02x:%02x:%02x:%02x:%02x:%02x",
			if_index, bN->current_length, en->src_address[0],
			en->src_address[1], en->src_address[2],
			en->src_address[3], en->src_address[4],
			en->src_address[5]);
#endif
	  /* copy to the PSAMPLE generic netlink channel (via the main thread
	   * so that we don't stall the worker thread on a system call).
	   */
	  /* increment seqN before we decide whether to drop the sample or not.
	   * That way the combined seqN that we give to PSAMPLE can be
	   * interpreted correctly at the receiving end to infer drops.
	   */
	  sfwk->seqN++;
	  sflow_sample_t sample = {
	    .samplingN = sfwk->smpN,
	    .input_if_index = if_index,
	    .sampled_packet_size =
	      bN->current_length + bN->total_length_not_including_first_buffer,
	    .header_bytes = hdr,
	    .thread_index = thread_index,
	    .thread_seqN = sfwk->seqN,
	    .thread_drop = sfwk->drop
	  };
	  pkts_sampled++;

	  // clib_warning("sflow hw if_index = %u, rpc_queue_depth=%u",
	  //		     hw->hw_if_index,
	  //		     vec_len(vm->pending_rpc_requests));
	  memcpy (sample.header, en, hdr);
	  // TODO: adjust size (though it might be just as fast to always copy
	  // sizeof(sflow_sample_t) bytes)

	  if (!sflow_fifo_enqueue (&sfwk->fifo, &sample))
	    pkts_dropped++;

	  pkts -= sfwk->skip;
	  sfwk->pool += sfwk->skip;
	  sfwk->skip = sflow_next_random_skip (sfwk);
#ifdef SFLOW_LOG_CYCLES
	  uint64_t cycles2 = clib_cpu_time_now ();
	  clib_warning ("sample cycles = %u", (cycles2 - cycles1));
	  vlib_node_increment_counter (
	    vm, sflow_node.index, SFLOW_ERROR_CYCLES, (cycles2 - cycles1));
#endif
	}
    }

  /* the rest of this is boilerplate code just to make sure
   * that packets are passed on the same way as they would
   * have been if this node were not enabled.
   *
   * Not sure at all if this is right.
   * There has got to be an easier way?
   */

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = SFLOW_NEXT_ETHERNET_INPUT;
	  u32 next1 = SFLOW_NEXT_ETHERNET_INPUT;
	  ethernet_header_t *en0, *en1;
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* do this to always pass on to the next node on feature arc */
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);

	  en0 = vlib_buffer_get_current (b0);
	  en1 = vlib_buffer_get_current (b1);

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->new_src_mac, en0->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en0->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      t->next_index = next1;
	      clib_memcpy (t->new_src_mac, en1->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en1->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  pkts_processed += 2;

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SFLOW_NEXT_ETHERNET_INPUT;
	  ethernet_header_t *en0;

	  // clib_warning("Loop one-at-a-time: %u next0=%u", n_left_from,
	  // next0);

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* do this to always pass on to the next node on feature arc */
	  vnet_feature_next (&next0, b0);

	  /*
	   * Direct from the driver, we should be at offset 0
	   * aka at &b0->data[0]
	   */
	  ASSERT (b0->current_data == 0);

	  en0 = vlib_buffer_get_current (b0);

	  // Are we supposed to tweak this buffer metadata?
	  // clib_warning("TX ifIndex currently=%u",
	  // vnet_buffer(b0)->sw_if_index[VLIB_TX]);
	  // vnet_buffer(b0)->sw_if_index[VLIB_TX] = ~0; // sw_if_index0;

	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->new_src_mac, en0->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en0->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  pkts_processed += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sflow_node.index, SFLOW_ERROR_PROCESSED,
			       pkts_processed);
  if (pkts_sampled)
    vlib_node_increment_counter (vm, sflow_node.index, SFLOW_ERROR_SAMPLED,
				 pkts_sampled);
  if (pkts_dropped)
    vlib_node_increment_counter (vm, sflow_node.index, SFLOW_ERROR_DROPPED,
				 pkts_dropped);
  return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (sflow_node) =
{
  .name = "sflow",
  .vector_size = sizeof (u32),
  .format_trace = format_sflow_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(sflow_error_strings),
  .error_strings = sflow_error_strings,
  .n_next_nodes = SFLOW_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [SFLOW_NEXT_ETHERNET_INPUT] = "ethernet-input",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
