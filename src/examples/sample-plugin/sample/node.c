/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <sample/sample.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} sample_trace_t;


/* packet trace format function */
static u8 *
format_sample_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sample_trace_t *t = va_arg (*args, sample_trace_t *);

  s = format (s, "SAMPLE: sw_if_index %d, next index %d\n",
	      t->sw_if_index, t->next_index);
  s = format (s, "  new src %U -> new dst %U",
	      format_mac_address, t->new_src_mac,
	      format_mac_address, t->new_dst_mac);

  return s;
}

extern vlib_node_registration_t sample_node;

#define foreach_sample_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum
{
#define _(sym,str) SAMPLE_ERROR_##sym,
  foreach_sample_error
#undef _
    SAMPLE_N_ERROR,
} sample_error_t;

static char *sample_error_strings[] = {
#define _(sym,string) string,
  foreach_sample_error
#undef _
};

typedef enum
{
  SAMPLE_NEXT_INTERFACE_OUTPUT,
  SAMPLE_N_NEXT,
} sample_next_t;

/*
 * Simple dual/single loop version, default version which will compile
 * everywhere.
 *
 * Node costs 30 clocks/pkt at a vector size of 51
 */
#define VERSION_1 1

#ifdef VERSION_1
#define foreach_mac_address_offset              \
_(0)                                            \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)

VLIB_NODE_FN (sample_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  sample_next_t next_index;
  u32 pkts_swapped = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = SAMPLE_NEXT_INTERFACE_OUTPUT;
	  u32 next1 = SAMPLE_NEXT_INTERFACE_OUTPUT;
	  u32 sw_if_index0, sw_if_index1;
	  u8 tmp0[6], tmp1[6];
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

	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);

	  en0 = vlib_buffer_get_current (b0);
	  en1 = vlib_buffer_get_current (b1);

	  /* This is not the fastest way to swap src + dst mac addresses */
#define _(a) tmp0[a] = en0->src_address[a];
	  foreach_mac_address_offset;
#undef _
#define _(a) en0->src_address[a] = en0->dst_address[a];
	  foreach_mac_address_offset;
#undef _
#define _(a) en0->dst_address[a] = tmp0[a];
	  foreach_mac_address_offset;
#undef _

#define _(a) tmp1[a] = en1->src_address[a];
	  foreach_mac_address_offset;
#undef _
#define _(a) en1->src_address[a] = en1->dst_address[a];
	  foreach_mac_address_offset;
#undef _
#define _(a) en1->dst_address[a] = tmp1[a];
	  foreach_mac_address_offset;
#undef _

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  /* Send pkt back out the RX interface */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = sw_if_index1;

	  pkts_swapped += 2;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  sample_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		  _clib_memcpy (t->new_src_mac, en0->src_address,
				sizeof (t->new_src_mac));
		  _clib_memcpy (t->new_dst_mac, en0->dst_address,
				sizeof (t->new_dst_mac));

		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  sample_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		  _clib_memcpy (t->new_src_mac, en1->src_address,
				sizeof (t->new_src_mac));
		  _clib_memcpy (t->new_dst_mac, en1->dst_address,
				sizeof (t->new_dst_mac));
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SAMPLE_NEXT_INTERFACE_OUTPUT;
	  u32 sw_if_index0;
	  u8 tmp0[6];
	  ethernet_header_t *en0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /*
	   * Direct from the driver, we should be at offset 0
	   * aka at &b0->data[0]
	   */
	  ASSERT (b0->current_data == 0);

	  en0 = vlib_buffer_get_current (b0);

	  /* This is not the fastest way to swap src + dst mac addresses */
#define _(a) tmp0[a] = en0->src_address[a];
	  foreach_mac_address_offset;
#undef _
#define _(a) en0->src_address[a] = en0->dst_address[a];
	  foreach_mac_address_offset;
#undef _
#define _(a) en0->dst_address[a] = tmp0[a];
	  foreach_mac_address_offset;
#undef _

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* Send pkt back out the RX interface */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      sample_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      _clib_memcpy (t->new_src_mac, en0->src_address,
			    sizeof (t->new_src_mac));
	      _clib_memcpy (t->new_dst_mac, en0->dst_address,
			    sizeof (t->new_dst_mac));
	    }

	  pkts_swapped += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sample_node.index,
			       SAMPLE_ERROR_SWAPPED, pkts_swapped);
  return frame->n_vectors;
}
#endif

/*
 * This version swaps mac addresses using an MMX vector shuffle
 * Node costs about 17 clocks/pkt at a vector size of 26
 */
#ifdef VERSION_2
VLIB_NODE_FN (sample_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  sample_next_t next_index;
  u32 pkts_swapped = 0;
  /* Vector shuffle mask to swap src, dst */
  u8x16 swapmac = { 6, 7, 8, 9, 10, 11, 0, 1, 2, 3, 4, 5, 12, 13, 14, 15 };

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = SAMPLE_NEXT_INTERFACE_OUTPUT;
	  u32 next1 = SAMPLE_NEXT_INTERFACE_OUTPUT;
	  u32 sw_if_index0, sw_if_index1;
	  u8x16 src_dst0, src_dst1;
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

	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);

	  en0 = vlib_buffer_get_current (b0);
	  en1 = vlib_buffer_get_current (b1);

	  src_dst0 = ((u8x16 *) en0)[0];
	  src_dst1 = ((u8x16 *) en1)[0];
	  src_dst0 = u8x16_shuffle (src_dst0, swapmac);
	  src_dst1 = u8x16_shuffle (src_dst1, swapmac);
	  ((u8x16 *) en0)[0] = src_dst0;
	  ((u8x16 *) en1)[0] = src_dst1;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  /* Send pkt back out the RX interface */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = sw_if_index1;

	  pkts_swapped += 2;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  sample_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		  _clib_memcpy (t->new_src_mac, en0->src_address,
				sizeof (t->new_src_mac));
		  _clib_memcpy (t->new_dst_mac, en0->dst_address,
				sizeof (t->new_dst_mac));

		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  sample_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		  _clib_memcpy (t->new_src_mac, en1->src_address,
				sizeof (t->new_src_mac));
		  _clib_memcpy (t->new_dst_mac, en1->dst_address,
				sizeof (t->new_dst_mac));
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = SAMPLE_NEXT_INTERFACE_OUTPUT;
	  u32 sw_if_index0;
	  u8x16 src_dst0;
	  ethernet_header_t *en0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /*
	   * Direct from the driver, we should be at offset 0
	   * aka at &b0->data[0]
	   */
	  ASSERT (b0->current_data == 0);

	  en0 = vlib_buffer_get_current (b0);
	  src_dst0 = ((u8x16 *) en0)[0];
	  src_dst0 = u8x16_shuffle (src_dst0, swapmac);
	  ((u8x16 *) en0)[0] = src_dst0;

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* Send pkt back out the RX interface */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      sample_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      _clib_memcpy (t->new_src_mac, en0->src_address,
			    sizeof (t->new_src_mac));
	      _clib_memcpy (t->new_dst_mac, en0->dst_address,
			    sizeof (t->new_dst_mac));
	    }

	  pkts_swapped += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sample_node.index,
			       SAMPLE_ERROR_SWAPPED, pkts_swapped);
  return frame->n_vectors;
}
#endif


/*
 * This version computes all of the buffer pointers in
 * one motion, uses a quad/single loop model, and
 * traces the entire frame in one motion.
 *
 * Node costs about 16 clocks/pkt at a vector size of 26
 *
 * Some compilation drama with u8x16_shuffle, so turned off by
 * default.
 */

#ifdef VERSION_3

#define u8x16_shuffle __builtin_shuffle
/* This would normally be a stack local, but since it's a constant... */
static const u16 nexts[VLIB_FRAME_SIZE] = { 0 };

VLIB_NODE_FN (sample_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  u32 pkts_swapped = 0;
  /* Vector shuffle mask to swap src, dst */
  u8x16 swapmac = { 6, 7, 8, 9, 10, 11, 0, 1, 2, 3, 4, 5, 12, 13, 14, 15 };
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  /* See comment below about sending all pkts to the same place... */
  u16 *next __attribute__ ((unused));

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  // next = nexts;

  /*
   * We send all pkts to SAMPLE_NEXT_INTERFACE_OUTPUT, aka
   * graph arc 0. So the usual setting of next[0...3] is commented
   * out below
   */

  while (n_left_from >= 4)
    {
      u8x16 src_dst0, src_dst1, src_dst2, src_dst3;
      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_header (b[6], STORE);
	  vlib_prefetch_buffer_header (b[7], STORE);
	  CLIB_PREFETCH (&b[4]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&b[5]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&b[6]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&b[7]->data, CLIB_CACHE_LINE_BYTES, STORE);
	}

      src_dst0 = ((u8x16 *) vlib_buffer_get_current (b[0]))[0];
      src_dst1 = ((u8x16 *) vlib_buffer_get_current (b[1]))[0];
      src_dst2 = ((u8x16 *) vlib_buffer_get_current (b[2]))[0];
      src_dst3 = ((u8x16 *) vlib_buffer_get_current (b[3]))[0];

      src_dst0 = u8x16_shuffle (src_dst0, swapmac);
      src_dst1 = u8x16_shuffle (src_dst1, swapmac);
      src_dst2 = u8x16_shuffle (src_dst2, swapmac);
      src_dst3 = u8x16_shuffle (src_dst3, swapmac);

      ((u8x16 *) vlib_buffer_get_current (b[0]))[0] = src_dst0;
      ((u8x16 *) vlib_buffer_get_current (b[1]))[0] = src_dst1;
      ((u8x16 *) vlib_buffer_get_current (b[2]))[0] = src_dst2;
      ((u8x16 *) vlib_buffer_get_current (b[3]))[0] = src_dst3;

      vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
	vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      vnet_buffer (b[1])->sw_if_index[VLIB_TX] =
	vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      vnet_buffer (b[2])->sw_if_index[VLIB_TX] =
	vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      vnet_buffer (b[3])->sw_if_index[VLIB_TX] =
	vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      // next[0] = SAMPLE_NEXT_INTERFACE_OUTPUT;
      // next[1] = SAMPLE_NEXT_INTERFACE_OUTPUT;
      // next[2] = SAMPLE_NEXT_INTERFACE_OUTPUT;
      // next[3] = SAMPLE_NEXT_INTERFACE_OUTPUT;

      b += 4;
      // next += 4;
      n_left_from -= 4;
      pkts_swapped += 4;
    }

  while (n_left_from > 0)
    {
      u8x16 src_dst0;
      src_dst0 = ((u8x16 *) vlib_buffer_get_current (b[0]))[0];
      src_dst0 = u8x16_shuffle (src_dst0, swapmac);
      ((u8x16 *) vlib_buffer_get_current (b[0]))[0] = src_dst0;
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] =
	vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      // next[0] = SAMPLE_NEXT_INTERFACE_OUTPUT;

      b += 1;
      // next += 1;
      n_left_from -= 1;
      pkts_swapped += 1;

    }
  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);

  vlib_node_increment_counter (vm, sample_node.index,
			       SAMPLE_ERROR_SWAPPED, pkts_swapped);

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;

      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ethernet_header_t *en;
	      sample_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	      t->next_index = SAMPLE_NEXT_INTERFACE_OUTPUT;
	      en = vlib_buffer_get_current (b[0]);
	      _clib_memcpy (t->new_src_mac, en->src_address,
			    sizeof (t->new_src_mac));
	      _clib_memcpy (t->new_dst_mac, en->dst_address,
			    sizeof (t->new_dst_mac));
	      b++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}
#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sample_node) =
{
  .name = "sample",
  .vector_size = sizeof (u32),
  .format_trace = format_sample_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(sample_error_strings),
  .error_strings = sample_error_strings,

  .n_next_nodes = SAMPLE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [SAMPLE_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
