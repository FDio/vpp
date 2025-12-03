/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */
#include <vppinfra/format.h>
#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#include <sfdp_services/snort/snort.h>

#define foreach_sfdp_snort_output_error _ (INVALID_SESSION, "Invalid session")

typedef enum
{
#define _(sym, str) SFDP_SNORT_OUTPUT_ERROR_##sym,
  foreach_sfdp_snort_output_error
#undef _
    SFDP_SNORT_OUTPUT_N_ERROR,
} sfdp_snort_output_error_t;

static char *sfdp_snort_output_error_strings[] = {
#define _(sym, str) str,
  foreach_sfdp_snort_output_error
#undef _
};

typedef struct
{
  u32 buffer_index;
  u16 next_index;
  SFDP_DAQ_Verdict verdict;
} sfdp_snort_output_trace_t;

static_always_inline u32
sfdp_snort_is_session_not_valid (sfdp_per_thread_data_t *ptd, vlib_buffer_t *b)
{
  u32 session_idx = sfdp_session_from_flow_index (b->flow_id);

  if (sfdp_session_at_index_is_active (session_idx))
    return 0;

  return 1;
}

static u8 *
format_sfdp_snort_verdict (u8 *s, va_list *args)
{
  SFDP_DAQ_Verdict v = va_arg (*args, SFDP_DAQ_Verdict);
  static char *strings[SFDP_MAX_DAQ_VERDICT] = {
    [SFDP_DAQ_VERDICT_PASS] = "PASS",
    [SFDP_DAQ_VERDICT_BLOCK] = "BLOCK",
    [SFDP_DAQ_VERDICT_REPLACE] = "REPLACE",
    [SFDP_DAQ_VERDICT_WHITELIST] = "WHITELIST",
    [SFDP_DAQ_VERDICT_BLACKLIST] = "BLACKLIST",
    [SFDP_DAQ_VERDICT_IGNORE] = "IGNORE",
  };

  if (v >= SFDP_MAX_DAQ_VERDICT || strings[v] == 0)
    return format (s, "unknown (%d)", v);

  return format (s, "%s", strings[v]);
}

static u8 *
format_sfdp_snort_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sfdp_snort_output_trace_t *t = va_arg (*args, sfdp_snort_output_trace_t *);
  s = format (s, "sfdp-snort-output: buffer-index %d next-index %d verdict %U",
	      t->buffer_index, t->next_index, format_sfdp_snort_verdict,
	      t->verdict);
  return s;
}

SFDP_SERVICE_DECLARE (drop)

static_always_inline uword
sfdp_snort_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  sfdp_per_thread_data_t *ptd = sfdp_get_per_thread_data (vm->thread_index);
  u32 *buffer_indices = vlib_frame_vector_args (frame), *bi = buffer_indices;
  u16 next_indices[VLIB_FRAME_SIZE], *ni = next_indices;
  u32 n_pkts = frame->n_vectors, n_left = n_pkts;
  u32 n_invalid_session_pkt_drop = 0;

  for (; n_left >= 8; n_left -= 4, bi += 4, ni += 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;
      daq_vpp_pkt_metadata_t metadata0 = {}, metadata1 = {}, metadata2 = {},
			     metadata3 = {};

      clib_prefetch_load (vlib_get_buffer (vm, bi[4]));
      b0 = vlib_get_buffer (vm, bi[0]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[5]));
      b1 = vlib_get_buffer (vm, bi[1]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[6]));
      b2 = vlib_get_buffer (vm, bi[2]);
      clib_prefetch_load (vlib_get_buffer (vm, bi[7]));
      b3 = vlib_get_buffer (vm, bi[3]);

      /*
       * Get the verdict from the buffers and reset the sfdp metadata
       * back to sfdp_buffer from sfdp_buffer2.
       */
      metadata0 = *sfdp_snort_get_buffer_metadata (b0);
      metadata1 = *sfdp_snort_get_buffer_metadata (b1);
      metadata2 = *sfdp_snort_get_buffer_metadata (b2);
      metadata3 = *sfdp_snort_get_buffer_metadata (b3);

      *sfdp_buffer (b0) = *sfdp_buffer2 (b0);
      *sfdp_buffer (b1) = *sfdp_buffer2 (b1);
      *sfdp_buffer (b2) = *sfdp_buffer2 (b2);
      *sfdp_buffer (b3) = *sfdp_buffer2 (b3);

      if (sfdp_snort_is_session_not_valid (ptd, b0))
	{
	  sfdp_buffer (b0)->service_bitmap = SFDP_SERVICE_MASK (drop);
	  n_invalid_session_pkt_drop++;
	}

      if (sfdp_snort_is_session_not_valid (ptd, b1))
	{
	  sfdp_buffer (b1)->service_bitmap = SFDP_SERVICE_MASK (drop);
	  n_invalid_session_pkt_drop++;
	}

      if (sfdp_snort_is_session_not_valid (ptd, b2))
	{
	  sfdp_buffer (b2)->service_bitmap = SFDP_SERVICE_MASK (drop);
	  n_invalid_session_pkt_drop++;
	}

      if (sfdp_snort_is_session_not_valid (ptd, b3))
	{
	  sfdp_buffer (b3)->service_bitmap = SFDP_SERVICE_MASK (drop);
	  n_invalid_session_pkt_drop++;
	}

      sfdp_next (b0, ni + 0);
      sfdp_next (b1, ni + 1);
      sfdp_next (b2, ni + 2);
      sfdp_next (b3, ni + 3);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  sfdp_snort_output_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->buffer_index = bi[0];
	  t->next_index = ni[0];
	  t->verdict = metadata0.verdict;
	}

      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  sfdp_snort_output_trace_t *t =
	    vlib_add_trace (vm, node, b1, sizeof (*t));
	  t->buffer_index = bi[1];
	  t->next_index = ni[1];
	  t->verdict = metadata1.verdict;
	}

      if (b2->flags & VLIB_BUFFER_IS_TRACED)
	{
	  sfdp_snort_output_trace_t *t =
	    vlib_add_trace (vm, node, b2, sizeof (*t));
	  t->buffer_index = bi[2];
	  t->next_index = ni[2];
	  t->verdict = metadata2.verdict;
	}
      if (b3->flags & VLIB_BUFFER_IS_TRACED)
	{
	  sfdp_snort_output_trace_t *t =
	    vlib_add_trace (vm, node, b3, sizeof (*t));
	  t->buffer_index = bi[3];
	  t->next_index = ni[3];
	  t->verdict = metadata3.verdict;
	}
    }

  for (; n_left > 0; n_left -= 1, bi += 1, ni += 1)
    {
      vlib_buffer_t *b0;
      daq_vpp_pkt_metadata_t metadata0 = {};

      b0 = vlib_get_buffer (vm, bi[0]);
      /*
       * Get the verdict from the buffer and reset the sfdp metadata
       * back to sfdp_buffer from sfdp_buffer2.
       */
      metadata0 = *sfdp_snort_get_buffer_metadata (b0);
      *sfdp_buffer (b0) = *sfdp_buffer2 (b0);

      if (sfdp_snort_is_session_not_valid (ptd, b0))
	{
	  sfdp_buffer (b0)->service_bitmap = SFDP_SERVICE_MASK (drop);
	  n_invalid_session_pkt_drop++;
	}

      sfdp_next (b0, ni + 0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  sfdp_snort_output_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->buffer_index = bi[0];
	  t->next_index = ni[0];
	  t->verdict = metadata0.verdict;
	}
    }

  vlib_node_increment_counter (vm, node->node_index,
			       SFDP_SNORT_OUTPUT_ERROR_INVALID_SESSION,
			       n_invalid_session_pkt_drop);

  vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices, n_pkts);
  return n_pkts;
}

VLIB_NODE_FN (sfdp_snort_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_snort_output_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (sfdp_snort_output_node) = {
  .name = "sfdp-snort-output",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_snort_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SFDP_SNORT_OUTPUT_N_ERROR,
  .error_strings = sfdp_snort_output_error_strings,

};

SFDP_SERVICE_DEFINE (sfdp_snort_output) = {
  .node_name = "sfdp-snort-output",
  .runs_before = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle"),
  .runs_after = SFDP_SERVICES ("sfdp-snort-input"),
  .is_terminal = 0
};
