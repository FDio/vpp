/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#include <sfdp_services/snort/snort.h>
#include <snort/export.h>

#define foreach_sfdp_snort_input_error _ (ENQUEUED, "Packets enqueued to snort")

typedef enum
{
#define _(sym, str) SFDP_SNORT_INPUT_ERROR_##sym,
  foreach_sfdp_snort_input_error
#undef _
    SFDP_SNORT_INPUT_N_ERROR,
} sfdp_snort_input_error_t;

static char *sfdp_snort_input_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_snort_input_error
#undef _
};

typedef struct
{
  u16 instance_index;
  u16 dequeue_node_next_index;
  u8 use_rewrite_length_offset;
} sfdp_snort_enq_scalar_args_t;

typedef struct
{
  u32 buffer_index;
  u16 instance;
} sfdp_snort_input_trace_t;

static u8 *
format_sfdp_snort_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sfdp_snort_input_trace_t *t = va_arg (*args, sfdp_snort_input_trace_t *);

  return format (s, "buffer-index %u instance %u", t->buffer_index, t->instance);
}

static_always_inline uword
sfdp_snort_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  sfdp_snort_main_t *vsm = &sfdp_snort_main;
  u32 *buffer_indices = vlib_frame_vector_args (frame), *bi = buffer_indices;
  u32 n_pkts = frame->n_vectors, n_left = n_pkts;
  vlib_next_frame_t *nf;
  vlib_frame_t *f;
  sfdp_snort_enq_scalar_args_t *sa;
  u32 *to_next, n_left_to_next;
  u32 next_index = vsm->snort_enq_next_index; /* snort_enq */
  u16 n_enq = 0;
#define SFDP_DAQ_PKT_FLAG_PRE_ROUTING 0x0004
  daq_vpp_pkt_metadata_t metadata = {
    .flags = SFDP_DAQ_PKT_FLAG_PRE_ROUTING,
  };

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  for (; n_left >= 8; n_left -= 4, bi += 4, to_next += 4, n_enq += 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;

      clib_prefetch_load (vlib_get_buffer (vm, bi[4]));
      b0 = vlib_get_buffer (vm, bi[0]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[5]));
      b1 = vlib_get_buffer (vm, bi[1]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[6]));
      b2 = vlib_get_buffer (vm, bi[2]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[7]));
      b3 = vlib_get_buffer (vm, bi[3]);

      /**
       * The buffer is enqueued to snort_enq node, which will send it to
       * the snort for processing.
       */
      to_next[0] = bi[0];
      to_next[1] = bi[1];
      to_next[2] = bi[2];
      to_next[3] = bi[3];

      /**
       * Set the snort metadata for each buffer.
       * Since sfdp stores its own buffer metadata at the
       * vnet_buffer->unused. Snort uses the same space for its
       * metadata. We need to move the sfdp metadata to sfdp_buffer2
       * which points to the vnet_buffer2->unused before
       * setting the snort metadata.
       */
      *sfdp_buffer2 (b0) = *sfdp_buffer (b0);
      *sfdp_buffer2 (b1) = *sfdp_buffer (b1);
      *sfdp_buffer2 (b2) = *sfdp_buffer (b2);
      *sfdp_buffer2 (b3) = *sfdp_buffer (b3);
      *sfdp_snort_get_buffer_metadata (b0) = metadata;
      *sfdp_snort_get_buffer_metadata (b1) = metadata;
      *sfdp_snort_get_buffer_metadata (b2) = metadata;
      *sfdp_snort_get_buffer_metadata (b3) = metadata;
    }

  for (; n_left; n_left -= 1, bi += 1, to_next += 1, n_enq += 1)
    {
      vlib_buffer_t *b0;
      b0 = vlib_get_buffer (vm, bi[0]);
      to_next[0] = bi[0];
      *sfdp_buffer2 (b0) = *sfdp_buffer (b0);
      *sfdp_snort_get_buffer_metadata (b0) = metadata;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      for (u32 i = 0; i < n_pkts; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
	  if (b->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_snort_input_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	      t->buffer_index = buffer_indices[i];
	      t->instance = vsm->instance_index;
	    }
	}
    }

  {
    nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
    f = vlib_get_frame (vm, nf->frame);
    sa = vlib_frame_scalar_args (f);
    *sa = (sfdp_snort_enq_scalar_args_t){
      .instance_index = vsm->instance_index,
      /**
       * On return from snort, the buffers will be received at snort_deq node.
       * Snort deq node will send the buffers to snort_output service using the
       * following dequeue node next index.
       */
      .dequeue_node_next_index = vsm->snort_dequeue_node_next_index,
      .use_rewrite_length_offset = 0,
    };
    vlib_frame_no_append (f);
    vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_enq);
  }

  vlib_node_increment_counter (vm, node->node_index, SFDP_SNORT_INPUT_ERROR_ENQUEUED, n_enq);
  return n_pkts;
}

VLIB_NODE_FN (sfdp_snort_input)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_snort_input_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (sfdp_snort_input) = {
  .name = "sfdp-snort-input",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_snort_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SFDP_SNORT_INPUT_N_ERROR,
  .error_strings = sfdp_snort_input_error_strings,
};

SFDP_SERVICE_DEFINE (sfdp_snort_input) = {
  .node_name = "sfdp-snort-input",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES (0),
  .is_terminal = 1,
};
