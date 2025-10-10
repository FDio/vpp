/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/reass/reass.h>

typedef struct
{
} sfdp_lookup_sp_sv_reass_trace_t;

static u8 *
format_sfdp_lookup_sp_sv_reass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  CLIB_UNUSED (sfdp_lookup_sp_sv_reass_trace_t * t) =
    va_arg (*args, sfdp_lookup_sp_sv_reass_trace_t *);

  s = format (s, "%v: sent to svr node", node->name);
  return s;
}

#define foreach_sfdp_lookup_sp_sv_reass_next                                  \
  _ (IP4_SVR, "ip4-sv-reassembly-custom-context")                             \
  _ (IP6_SVR, "ip6-sv-reassembly-custom-context")

enum
{
#define _(sym, str) SFDP_LOOKUP_SP_SV_REASS_NEXT_##sym,
  foreach_sfdp_lookup_sp_sv_reass_next
#undef _
    SFDP_LOOKUP_SP_SV_REASS_N_NEXT
};

#define foreach_sfdp_lookup_sp_sv_reass_error _ (NOERROR, "No error")

typedef enum
{
#define _(sym, str) SFDP_LOOKUP_SP_SV_REASS_ERROR_##sym,
  SFDP_LOOKUP_SP_SV_REASS_N_ERROR
#undef _
} sfdp_lookup_sp_sv_reass_error_t;

static char *sfdp_lookup_sp_sv_reass_error_strings[] = {
#define _(sym, str) str,
  foreach_sfdp_lookup_sp_sv_reass_error
#undef _
};

static_always_inline u32
sfdp_lookup_sp_sv_reass_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				vlib_frame_t *frame, bool is_ip6)
{
  sfdp_reass_main_t *vrm = &sfdp_reass_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 aux_data[VLIB_FRAME_SIZE], *a;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  a = aux_data;
  // TODO: prefetch + 4-loop
  while (n_left)
    {
      a[0] = b[0]->flow_id;
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  sfdp_lookup_sp_sv_reass_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	}

      /* Save the tenant index */
      sfdp_buffer2 (b[0])->tenant_index = sfdp_buffer (b[0])->tenant_index;
      sfdp_buffer2 (b[0])->flags = SFDP_BUFFER_FLAG_SV_REASSEMBLED;

      vnet_buffer (b[0])->ip.reass.next_index =
	is_ip6 ? vrm->ip6_sv_reass_next_index : vrm->ip4_sv_reass_next_index;
      b += 1;
      a += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_single_next_with_aux (
    vm, node, from, aux_data,
    is_ip6 ? SFDP_LOOKUP_SP_SV_REASS_NEXT_IP6_SVR :
	     SFDP_LOOKUP_SP_SV_REASS_NEXT_IP4_SVR,
    frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_lookup_ip4_sp_sv_reass)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_sp_sv_reass_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (sfdp_lookup_ip4_sp_sv_reass) = {
  .name = "sfdp-lookup-ip4-sp-sv-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_sp_sv_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_lookup_sp_sv_reass_error_strings),
  .error_strings = sfdp_lookup_sp_sv_reass_error_strings,
  .next_nodes = {
#define _(sym, str) [SFDP_LOOKUP_SP_SV_REASS_NEXT_##sym] = str,
  foreach_sfdp_lookup_sp_sv_reass_next
#undef _
  },
  .n_next_nodes = SFDP_LOOKUP_SP_SV_REASS_N_NEXT,
};

VLIB_NODE_FN (sfdp_lookup_ip6_sp_sv_reass)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_sp_sv_reass_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (sfdp_lookup_ip6_sp_sv_reass) = {
  .name = "sfdp-lookup-ip6-sp-sv-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_sp_sv_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_lookup_sp_sv_reass_error_strings),
  .error_strings = sfdp_lookup_sp_sv_reass_error_strings,
  .next_nodes = {
#define _(sym, str) [SFDP_LOOKUP_SP_SV_REASS_NEXT_##sym] = str,
  foreach_sfdp_lookup_sp_sv_reass_next
#undef _
  },
  .n_next_nodes = SFDP_LOOKUP_SP_SV_REASS_N_NEXT,
};
