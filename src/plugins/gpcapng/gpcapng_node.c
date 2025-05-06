#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <stdbool.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */

#include "gpcapng.h"
#include "gpcapng_node.h"
#include "write_pcapng.h"
#include "gpcapng_filter_api.h"

/******************************************************************************
 * Packet processing
 ******************************************************************************/

// extern void process_http_gpcapng_retries(u16 worker_index);

/* First pass: classify packets and determine destination indices */
static_always_inline u32
gpcapng_classify_packets (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, int is_output,
			  gpcapng_per_worker_t *pw, u32 *n_matched)
{
  gpcapng_filter_impl_t *filter_impl;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_captured = 0;

  /* Get buffers for the entire frame */
  vlib_get_buffers (vm, from, pw->bufs, frame->n_vectors);
  /* set the "wraparound" value - not part of processed packets, but prefetch
   * will spill onto it */
  if (frame->n_vectors)
    {
      pw->bufs[frame->n_vectors] = pw->bufs[0];
    }

  /* Get active filter implementation */
  filter_impl = gpcapng_get_active_filter_impl ();
  if (!filter_impl || !filter_impl->selected_fn)
    {
      /* No filter implementation - don't capture anything */
      clib_memset (pw->dest_indices, 0xFF, frame->n_vectors * sizeof (u32));
      return frame->n_vectors;
    }

  /* Call the filter implementation */
  gpcapng_main_t *gpm = get_gpcapng_main ();
  filter_impl->selected_fn (GPCAPNG_FILTER_API_VERSION, pw->bufs,
			    frame->n_vectors, vm, node, frame, is_output,
			    gpm->capture_enabled_bitmap, pw->dest_indices,
			    n_matched, &n_captured);

  /* Store buffer indices for second pass */
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      pw->buffer_indices[i] = from[i];

      /* Tracing */
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (pw->bufs[i]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  pcapng_capture_trace_t *t =
	    vlib_add_trace (vm, node, pw->bufs[i], sizeof (*t));
	  t->sw_if_index = vnet_buffer (pw->bufs[i])
			     ->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
	  t->elapsed = 0; /* Filter implementation doesn't provide timing */
	  t->dest_index = pw->dest_indices[i];
	}
    }

  return frame->n_vectors;
}


/* Second pass: requeue packets to appropriate destinations */
static_always_inline void
gpcapng_requeue_packets (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, int is_output,
			 gpcapng_per_worker_t *pw, u32 n_classified,
			 u32 *n_captured, u32 *n_dropped, u32 *n_not_ready)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();
  u32 worker_index = vlib_get_thread_index ();

  for (u32 pkt_idx = 0; pkt_idx < n_classified; pkt_idx++)
    {
      u32 destination_capture_index = pw->dest_indices[pkt_idx];
      vlib_buffer_t *b0 = pw->bufs[pkt_idx];
      u32 sw_if_index0 =
	vnet_buffer (b0)->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
      {
	/* prefetch the next buffer, possibly with a "spill", which will
	 * re-prefetch the first buffer again */
	vlib_buffer_t *b1 = pw->bufs[pkt_idx + 1];
	CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);
      }

      /* Process packets that matched a destination */
      if (destination_capture_index <
	    vec_len (gpm->worker_output_ctx[worker_index]) &&
	  destination_capture_index < vec_len (gpm->outputs) &&
	  clib_bitmap_get (gpm->worker_output_ctx_is_ready[worker_index],
			   destination_capture_index))
	{
	  /* Capture the matching packet */
	  gpcapng_dest_t *output =
	    &vec_elt (gpm->outputs, destination_capture_index);
	  void *output_ctx =
	    gpm->worker_output_ctx[worker_index][destination_capture_index];
	  u64 timestamp = vlib_time_now (vm) * 1000000;

	  gpcapng_worker_context_common_t *worker_common = output_ctx;
	  worker_common->packet_counter += 1;

	  vec_add_pcapng_epb (vm, &worker_common->buffer_vec, output_ctx,
			      (sw_if_index0 << 1) | is_output, timestamp,
			      b0, ~0);

	  /* Write packet data to PCAPng file when there is enough of it */
	  if (vec_len (worker_common->buffer_vec) > 4000)
	    {
	      int res =
		output->chunk_write (output_ctx, worker_common->buffer_vec,
				     vec_len (worker_common->buffer_vec));
	      if (res == 0)
		{
		  worker_common->last_sent_packet_counter =
		    worker_common->packet_counter;
		  worker_common->last_batch_sent_packet_counter =
		    worker_common->packet_counter;
		}
	      else
		{
		  (*n_dropped)+= worker_common->last_batch_sent_packet_counter - worker_common->last_sent_packet_counter;
		  worker_common->last_sent_packet_counter = worker_common->last_batch_sent_packet_counter;
		}
	      vec_reset_length (worker_common->buffer_vec);
	    }
	  else
	    {
	      /* optimistically count as sent */
	      worker_common->last_sent_packet_counter =
		worker_common->packet_counter;
	    }

	  (*n_captured)++;
	}
      else if (destination_capture_index != ~0)
	{
	  (*n_not_ready)++;
	}
    }
}

/* Filter and capture Geneve packets - Two-pass implementation */
static_always_inline uword
gpcapng_node_common (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, int is_output)
{
  gpcapng_main_t *gpm = get_gpcapng_main ();
  u32 n_left_from, *from, *to_next;
  u32 n_left_to_next;
  u32 worker_index = vlib_get_thread_index ();
  u32 next_index;
  u32 n_captured = 0;
  u32 n_matched = 0;
  u32 n_dropped = 0;
  u32 n_not_ready = 0;
  u32 n_classified = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  /* Get pre-allocated per-worker structure */
  gpcapng_per_worker_t *pw = &gpm->per_worker[worker_index];
  pw->n_vectors = n_left_from;

  /* First pass: classify all packets */
  n_classified =
    gpcapng_classify_packets (vm, node, frame, is_output, pw, &n_matched);

  /* Second pass: requeue packets to destinations */
  gpcapng_requeue_packets (vm, node, frame, is_output, pw, n_classified,
			   &n_captured, &n_dropped, &n_not_ready);

  /* Standard VPP forwarding - process all packets in frame */
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, next0 = 0;

	  /* Prefetch next packet */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  /* Get current packet */
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_feature_next (&next0, b0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       PCAPNG_CAPTURE_ERROR_MATCHED, n_matched);
  vlib_node_increment_counter (vm, node->node_index,
			       PCAPNG_CAPTURE_ERROR_CAPTURED, n_captured);
  vlib_node_increment_counter (vm, node->node_index,
			       PCAPNG_CAPTURE_ERROR_DROPPED, n_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       PCAPNG_CAPTURE_ERROR_NOT_READY, n_not_ready);

  /* Process HTTP retries for this worker - done in a separate node*/
  // process_http_gpcapng_retries(vlib_get_thread_index());

  return frame->n_vectors;
}

VLIB_NODE_FN (gpcapng_node_out)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return gpcapng_node_common (vm, node, frame, 1);
}

VLIB_NODE_FN (gpcapng_node_in)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return gpcapng_node_common (vm, node, frame, 0);
}
