/*
 * ah_decrypt.c : IPSec AH decrypt node
 *
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_io.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>
#include <vnet/ipsec/ipsec_io.h>

#define foreach_ah_decrypt_next \
  _ (DROP, "error-drop")        \
  _ (IP4_INPUT, "ip4-input")    \
  _ (IP6_INPUT, "ip6-input")    \
  _ (IPSEC_GRE_INPUT, "ipsec-gre-input")

#define _(v, s) AH_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_ah_decrypt_next
#undef _
    AH_DECRYPT_N_NEXT,
} ah_decrypt_next_t;

#define foreach_ah_decrypt_error                \
  _ (RX_PKTS, "AH pkts received")               \
  _ (DECRYPTION_FAILED, "AH decryption failed") \
  _ (INTEG_ERROR, "Integrity check failed")     \
  _ (REPLAY, "SA replayed packet")              \
  _ (NOT_IP, "Not IP packet (dropped)")         \
  _ (INTERNAL, "internal error")

typedef enum
{
#define _(sym,str) AH_DECRYPT_ERROR_##sym,
  foreach_ah_decrypt_error
#undef _
    AH_DECRYPT_N_ERROR,
} ah_decrypt_error_t;

static char *ah_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_ah_decrypt_error
#undef _
};

always_inline uword
ah_decrypt_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		   int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 thread_index = vlib_get_thread_index ();

  u32 n_jobs = from_frame->n_vectors;
  u32 *from = vlib_frame_vector_args (from_frame);
  ipsec_main_per_thread_data_t *t = &im->per_thread_data[thread_index];
  ipsec_job_desc_t *job = t->jobs;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_get_buffers (vm, from, bufs, from_frame->n_vectors);

  ah_decrypt_prepare_jobs (vm, thread_index, im, em, b, job, n_jobs, is_ip6,
			   AH_DECRYPT_NEXT_DROP);

  //submit all the jobs for processing
  ipsec_process_jobs (em, t->jobs, n_jobs, AH_DECRYPT_NEXT_DROP,
		      0 /* is_decrypt */ );

  // wrap things up
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  ah_decrypt_finish (vm, next, job, n_jobs, is_ip6, AH_DECRYPT_NEXT_DROP,
		     AH_DECRYPT_NEXT_IP4_INPUT, AH_DECRYPT_NEXT_IP6_INPUT,
		     AH_DECRYPT_NEXT_IPSEC_GRE_INPUT);

  ipsec_add_traces (vm, node, job, n_jobs);
  ipsec_update_packet_counters (vm, node, t->jobs, n_jobs,
				AH_DECRYPT_ERROR_DECRYPTION_FAILED,
				AH_DECRYPT_ERROR_INTEG_ERROR,
				AH_DECRYPT_ERROR_INTERNAL,
				AH_DECRYPT_ERROR_REPLAY,
				AH_DECRYPT_ERROR_NOT_IP,
				AH_DECRYPT_ERROR_INTERNAL,
				AH_DECRYPT_ERROR_INTERNAL);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index, AH_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ah4_decrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_decrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah4_decrypt_node) = {
  .name = "ah4-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ah_decrypt_error_strings),
  .error_strings = ah_decrypt_error_strings,

  .n_next_nodes = AH_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [AH_DECRYPT_NEXT_##s] = n,
    foreach_ah_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (ah6_decrypt_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * from_frame)
{
  return ah_decrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ah6_decrypt_node) = {
  .name = "ah6-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ah_decrypt_error_strings),
  .error_strings = ah_decrypt_error_strings,

  .n_next_nodes = AH_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [AH_DECRYPT_NEXT_##s] = n,
    foreach_ah_decrypt_next
#undef _
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
