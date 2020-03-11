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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/fib/ip4_fib.h>
#include "unat.h"
#include "unat_inlines.h"
#include "../nat.h"

#define foreach_unat_handoff_error			\
_(CONGESTION_DROP_SP, "congestion drop - slowpath")	\
_(CONGESTION_DROP_FP, "congestion drop - fastpath")	\
_(WRONG_THREAD, "wrong thread")

typedef enum
{
#define _(sym,str) UNAT_HANDOFF_ERROR_##sym,
  foreach_unat_handoff_error
#undef _
    UNAT_HANDOFF_N_ERROR,
} unat_handoff_error_t;

static char *unat_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_unat_handoff_error
#undef _
};

typedef struct {
  u32 next_worker_index;
  u32 trace_index;
} unat_handoff_trace_t;

static u8 *
format_unat_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  unat_handoff_trace_t *t = va_arg (*args, unat_handoff_trace_t *);

  s = format (s, "unat-handoff: next-worker %d trace index %d",
	      t->next_worker_index, t->trace_index);
  return s;
}

static u16 nexts[VLIB_FRAME_SIZE] = { 0 };
static_always_inline uword
unat_handoff_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame,
		     bool in2out)
{
  unat_main_t *um = &unat_main;

  u16 *next;

  u32 n_enq, n_left_from, *from;
  u32 do_handoff_fp = 0;

  u16 fastpath_indices[VLIB_FRAME_SIZE], *fi = fastpath_indices;
  u32 fastpath_buffers[VLIB_FRAME_SIZE], *fb = fastpath_buffers;
  u32 to_buffers[VLIB_FRAME_SIZE], *tb = to_buffers;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *bi;
  u32 thread_index = vm->thread_index;
  u32 no_fastpath = 0, no_slowpath = 0, no_to_buffers = 0;
  ip4_header_t *ip0;
  unat_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  clib_bihash_kv_16_8_t kv;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, b, n_left_from);

  u32 slow_path_node_index = in2out ? UNAT_NEXT_SLOWPATH_I2O : UNAT_NEXT_SLOWPATH_O2I;

  while (n_left_from > 0) {
    u32 sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
    u32 fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
    u16 sport0 = vnet_buffer (b[0])->ip.reass.l4_src_port;
    u16 dport0 = vnet_buffer (b[0])->ip.reass.l4_dst_port;
    ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]));
    unat_calc_key (ip0, fib_index0, sport0, dport0, k);
    clib_memcpy_fast (&kv.key, k, 16);
    h[0] = clib_bihash_hash_16_8 (&kv);

    b += 1;
    k += 1;
    h += 1;
    n_left_from -= 1;
  }

  n_left_from = frame->n_vectors;
  h = hashes;
  k = keys;
  b = bufs;
  bi = from;
  next = nexts;

  while (n_left_from > 0) {
    u32 sw_if_index0 = in2out ? vnet_buffer (b[0])->sw_if_index[VLIB_RX] : vnet_buffer (b[0])->sw_if_index[VLIB_TX];

    /* Not for us? */
    if (sw_if_index0 == ~0 || vec_len(um->interface_by_sw_if_index) < sw_if_index0) {
      clib_warning("DEBUG:HANDOFF PACKET NOT FOR US");
      vnet_feature_next((u32 *)next, b[0]);
      tb[0] = bi[0];
      tb += 1;
      next += 1;
      no_to_buffers++;
      goto next;
    }
    u32 index = um->interface_by_sw_if_index[sw_if_index0];
    if (index == ~0) {
      clib_warning("DEBUG: NAT NOT ENABLED ON INTERFACE");
      vnet_feature_next((u32 *)next, b[0]);
      tb[0] = bi[0];
      tb += 1;
      next += 1;
      no_to_buffers++;
      goto next;
    }
    unat_interface_t *interface = pool_elt_at_index(um->interfaces, index);

    if (PREDICT_TRUE (n_left_from >= 16))
      clib_bihash_prefetch_bucket_16_8 (interface->hash, h[15]);

    if (PREDICT_TRUE (n_left_from >= 8))
      clib_bihash_prefetch_data_16_8 (interface->hash, h[7]);

    clib_memcpy_fast (&kv.key, k, 16);

    /* 6-tuple lookup */
    if (clib_bihash_search_inline_with_hash_16_8 (interface->hash, h[0], &kv)) {
      /* Punt to slowpath */
      next[0] = slow_path_node_index;
      tb[0] = bi[0];
      tb += 1;
      next += 1;
      no_to_buffers++;
    } else {
      u32 to_thread = kv.value >> 32;
      if (to_thread == thread_index) {
	next[0] = UNAT_NEXT_FASTPATH;
	tb[0] = bi[0];
	tb += 1;
	next += 1;
	no_to_buffers++;
      } else {
	fi[0] = kv.value >> 32;
	do_handoff_fp++;
	fi += 1;
	fb[0] = bi[0];
	fb += 1;
      }
      no_fastpath++;
      u32 pool_index = kv.value & 0x00000000FFFFFFFF;
      vnet_buffer(b[0])->unat.pool_index = pool_index;
    }

  next:      
    n_left_from -= 1;
    k += 1;
    h += 1;
    b += 1;
    bi += 1;
  }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE))) {
    u32 i;
    b = bufs;

    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
	unat_handoff_trace_t *t =
	  vlib_add_trace (vm, node, b[0], sizeof (*t));
	t->next_worker_index = 0;
	t->trace_index = vlib_buffer_get_trace_index (b[0]);

	b += 1;
      } else
	break;
    }
  }

  /* fastpath */
  if (do_handoff_fp > 0) {
    n_enq = vlib_buffer_enqueue_to_thread (vm, um->fast_path_node_index, fastpath_buffers, fastpath_indices,
					   do_handoff_fp, 1);
    if (n_enq < do_handoff_fp) {
      vlib_node_increment_counter (vm, node->node_index,
				   UNAT_HANDOFF_ERROR_CONGESTION_DROP_FP,
				   do_handoff_fp - n_enq);
    }
    vlib_increment_simple_counter (um->counters + UNAT_COUNTER_HANDOFF_DIFFERENT_WORKER_FP, thread_index, 0, do_handoff_fp);
  }

  vlib_increment_simple_counter (um->counters + UNAT_COUNTER_HANDOFF_FP, thread_index, 0, no_fastpath);
  vlib_increment_simple_counter (um->counters + UNAT_COUNTER_HANDOFF_SLOWPATH, thread_index, 0, no_slowpath);

  vlib_buffer_enqueue_to_next (vm, node, to_buffers, nexts, no_to_buffers);

  return frame->n_vectors;
}

VLIB_NODE_FN (unat_handoff_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return unat_handoff_inline (vm, node, frame, 1);
}
VLIB_NODE_FN (unat_handoff_o2i_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{
  return unat_handoff_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (unat_handoff_node) = {
  .name = "unat-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_unat_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(unat_handoff_error_strings),
  .error_strings = unat_handoff_error_strings,
  .n_next_nodes = UNAT_N_NEXT,
  .next_nodes =
  {
   [UNAT_NEXT_DROP] = "error-drop",
   [UNAT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
   [UNAT_NEXT_FASTPATH] = "unat-fastpath",
   [UNAT_NEXT_SLOWPATH_I2O] = "unat-slowpath-i2o",
   [UNAT_NEXT_SLOWPATH_O2I] = "unat-slowpath-o2i",
  },
};

VLIB_REGISTER_NODE (unat_handoff_o2i_node) = {
  .name = "unat-handoff-o2i",
  .vector_size = sizeof (u32),
  .format_trace = format_unat_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(unat_handoff_error_strings),
  .error_strings = unat_handoff_error_strings,
  .sibling_of = "unat-handoff",
};

/* Hook up input features */

/* RX NAT on outside interface */
VNET_FEATURE_INIT (unat_handoff_o2i, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "unat-handoff-o2i",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};

/* TX NAT on outside interface */
VNET_FEATURE_INIT (unat_handoff_i2o, static) = {
  .arc_name = "ip4-output",
  .node_name = "unat-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa",
			       "ip4-sv-reassembly-output-feature"),
};

/* *INDENT-ON* */
