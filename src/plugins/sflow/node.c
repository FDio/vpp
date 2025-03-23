/*
 * Copyright (c) 2024 InMon Corp.
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
vlib_node_registration_t sflow_egress_node;
vlib_node_registration_t sflow_drop_node;

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
  SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT,
  SFLOW_N_NEXT,
} sflow_next_t;

static_always_inline uword
sflow_node_ingress_egress (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame,
			   sflow_enum_sample_t sample_type)
{
  u32 n_left_from, *from, *to_next;
  sflow_next_t next_index;

  sflow_main_t *smp = &sflow_main;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  uword thread_index = os_get_thread_index ();
  sflow_per_thread_data_t *sfwk =
    vec_elt_at_index (smp->per_thread_data, thread_index);

  /* note that sfwk->skip==1 means "take the next packet",
     so we never see sfwk->skip==0. */

  u32 pkts = n_left_from;
  if (PREDICT_TRUE (sfwk->skip > pkts))
    {
      /* skip the whole frame-vector */
      sfwk->skip -= pkts;
      sfwk->pool += pkts;
    }
  else
    {
      while (pkts >= sfwk->skip)
	{
	  /* reach in to get the one we want. */
	  vlib_buffer_t *bN = vlib_get_buffer (vm, from[sfwk->skip - 1]);

	  /* Sample this packet header. */
	  u32 hdr = bN->current_length;
	  if (hdr > smp->headerB)
	    hdr = smp->headerB;

	  ethernet_header_t *en = vlib_buffer_get_current (bN);
	  u32 if_index = vnet_buffer (bN)->sw_if_index[VLIB_RX];
	  u32 if_index_out = 0;
	  vnet_hw_interface_t *hw =
	    vnet_get_sup_hw_interface (smp->vnet_main, if_index);
	  if (hw)
	    if_index = hw->hw_if_index;
	  else
	    {
	      // TODO: can we get interfaces that have no hw interface?
	      // If so,  should we ignore the sample?
	    }

	  if (sample_type == SFLOW_SAMPLETYPE_EGRESS)
	    {
	      if_index_out = vnet_buffer (bN)->sw_if_index[VLIB_TX];
	      vnet_hw_interface_t *hw_out =
		vnet_get_sup_hw_interface (smp->vnet_main, if_index_out);
	      if (hw_out)
		if_index_out = hw_out->hw_if_index;
	    }

	  sflow_sample_t sample = {
	    .sample_type = sample_type,
	    .samplingN = sfwk->smpN,
	    .input_if_index = if_index,
	    .output_if_index = if_index_out,
	    .sampled_packet_size =
	      bN->current_length + bN->total_length_not_including_first_buffer,
	    .header_bytes = hdr
	  };

	  // TODO: what bit in the buffer can we set right here to indicate
	  // that this packet was sampled (and perhaps another bit to say if it
	  // was dropped or sucessfully enqueued)? That way we can check it
	  // below if the packet is traced, and indicate that in the trace
	  // output.

	  // TODO: we end up copying the header twice here. Consider allowing
	  // the enqueue to be just a little more complex.  Like this:
	  // if(!sflow_fifo_enqueue(&sfwk->fifo, &sample, en, hdr).
	  // With headerB==128 that would be memcpy(,,24) plus memcpy(,,128)
	  // instead of the memcpy(,,128) plus memcpy(,,24+256) that we do
	  // here. (We also know that it could be done as a multiple of 8
	  // (aligned) bytes because the sflow_sample_t fields are (6xu32) and
	  // the headerB setting is quantized to the nearest 32 bytes, so there
	  // may be ways to make it even easier for the compiler.)
	  sfwk->smpl++;
	  memcpy (sample.header, en, hdr);
	  if (PREDICT_FALSE (!sflow_fifo_enqueue (&sfwk->fifo, &sample)))
	    sfwk->drop++;

	  pkts -= sfwk->skip;
	  sfwk->pool += sfwk->skip;
	  sfwk->skip = sflow_next_random_skip (sfwk);
	}
      /* We took a sample (or several) from this frame-vector, but now we are
	 skipping the rest. */
      sfwk->skip -= pkts;
      sfwk->pool += pkts;
    }

  /* the rest of this is boilerplate code just to make sure
   * that packets are passed on the same way as they would
   * have been if this node were not enabled.
   * TODO: If there is ever a way to do this in one step
   * (i.e. pass on the whole frame-vector unchanged) then it
   * might help performance.
   */

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 next0 = SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT;
	  u32 next1 = SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT;
	  u32 next2 = SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT;
	  u32 next3 = SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT;
	  ethernet_header_t *en0, *en1, *en2, *en3;
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0-b3 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  /* do this to always pass on to the next node on feature arc */
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);
	  vnet_feature_next (&next2, b2);
	  vnet_feature_next (&next3, b3);

	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);
	  ASSERT (b2->current_data == 0);
	  ASSERT (b3->current_data == 0);

	  en0 = vlib_buffer_get_current (b0);
	  en1 = vlib_buffer_get_current (b1);
	  en2 = vlib_buffer_get_current (b2);
	  en3 = vlib_buffer_get_current (b3);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->new_src_mac, en0->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en0->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      t->next_index = next1;
	      clib_memcpy (t->new_src_mac, en1->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en1->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  if (PREDICT_FALSE (b2->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b2, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b2)->sw_if_index[VLIB_RX];
	      t->next_index = next2;
	      clib_memcpy (t->new_src_mac, en2->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en2->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  if (PREDICT_FALSE (b3->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b3, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b3)->sw_if_index[VLIB_RX];
	      t->next_index = next3;
	      clib_memcpy (t->new_src_mac, en3->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en3->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT;
	  ethernet_header_t *en0;

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

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sflow_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->new_src_mac, en0->src_address,
			   sizeof (t->new_src_mac));
	      clib_memcpy (t->new_dst_mac, en0->dst_address,
			   sizeof (t->new_dst_mac));
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_NODE_FN (sflow_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sflow_node_ingress_egress (vm, node, frame, SFLOW_SAMPLETYPE_INGRESS);
}

VLIB_NODE_FN (sflow_egress_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sflow_node_ingress_egress (vm, node, frame, SFLOW_SAMPLETYPE_EGRESS);
}

typedef enum
{
  SFLOW_DROP_NEXT_DROP,
  SFLOW_DROP_N_NEXT,
} sflow_drop_next_t;

static_always_inline void
buffer_rewind_current (vlib_buffer_t *bN)
{
  /*
   * Typically, we'll need to rewind the buffer
   * if l2_hdr_offset is valid, make sure to rewind to the start of
   * the L2 header. This may not be the buffer start in case we pop-ed
   * vlan tags.
   * Otherwise, rewind to buffer start and hope for the best.
   */
  /*
   * If the packet was rewritten the start may be somewhere
   * in buffer->pre_data, which comes before buffer->data. In
   * other words, the buffer->current_data index can be negative.
   */
  if (bN->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    {
      if (bN->current_data > vnet_buffer (bN)->l2_hdr_offset)
	vlib_buffer_advance (bN, vnet_buffer (bN)->l2_hdr_offset -
				   bN->current_data);
    }
  else if (bN->current_data > 0)
    {
      vlib_buffer_advance (bN, (word) -bN->current_data);
    }
}

VLIB_NODE_FN (sflow_drop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  sflow_drop_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  sflow_main_t *smp = &sflow_main;
  uword thread_index = os_get_thread_index ();
  sflow_per_thread_data_t *sfwk =
    vec_elt_at_index (smp->per_thread_data, thread_index);

  for (u32 pkt = n_left_from; pkt > 0; --pkt)
    {
      vlib_buffer_t *bN = vlib_get_buffer (vm, from[pkt - 1]);
      buffer_rewind_current (bN);
      // drops are subject to header_bytes limit too
      u32 hdr = bN->current_length;
      if (hdr > smp->headerB)
	hdr = smp->headerB;
      ethernet_header_t *en = vlib_buffer_get_current (bN);
      // Where did this packet come in originally?
      // (Doesn't have to be known)
      u32 if_index = vnet_buffer (bN)->sw_if_index[VLIB_RX];
      if (if_index)
	{
	  vnet_hw_interface_t *hw =
	    vnet_get_sup_hw_interface (smp->vnet_main, if_index);
	  if (hw)
	    if_index = hw->hw_if_index;
	}
      // queue the discard sample for the main thread
      sflow_sample_t discard = { .sample_type = SFLOW_SAMPLETYPE_DISCARD,
				 .input_if_index = if_index,
				 .sampled_packet_size =
				   bN->current_length +
				   bN->total_length_not_including_first_buffer,
				 .header_bytes = hdr,
				 // .header_protocol = 0,
				 .drop_reason = bN->error };
      sfwk->dsmp++; // drop-samples
      memcpy (discard.header, en, hdr);
      if (PREDICT_FALSE (
	    !sflow_drop_fifo_enqueue (&sfwk->drop_fifo, &discard)))
	sfwk->ddrp++; // drop-sample drops
    }

  /* the rest of this is boilerplate code to pass packets on - typically to
     "drop" */
  /* TODO: put back tracing code? */
  /* TODO: process 2 or 4 at a time? */
  /* TODO: by using this variant of the pipeline are we assuming that
     we are in a feature arc where frames are not converging or dividing? Just
     processing through a linear list of nodes that will each pass the whole
     frame of buffers on unchanged ("lighting fools the way to dusty death").
     And if so, how do we make that assumption explicit?
     To improve the flexibility would we have to go back and change the way
     that interface_output.c (error-drop) launches the frame along the arc
     in the first place?
  */
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SFLOW_DROP_NEXT_DROP;
	  /* enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  /* do this to always pass on to the next node on feature arc */
	  vnet_feature_next (&next0, b0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
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
    [SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT] = "ethernet-input",
  },
};

VLIB_REGISTER_NODE (sflow_egress_node) =
{
  .name = "sflow-egress",
  .vector_size = sizeof (u32),
  .format_trace = format_sflow_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(sflow_error_strings),
  .error_strings = sflow_error_strings,
  .n_next_nodes = SFLOW_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [SFLOW_NEXT_ETHERNET_INPUT_OR_INTERFACE_OUTPUT] = "interface-output",
  },
};

VLIB_REGISTER_NODE (sflow_drop_node) =
{
  .name = "sflow-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_sflow_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(sflow_error_strings),
  .error_strings = sflow_error_strings,
  .n_next_nodes = SFLOW_DROP_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    //[SFLOW_DROP_NEXT_DROP] = "error-drop",
    [SFLOW_DROP_NEXT_DROP] = "drop",
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
