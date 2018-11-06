/*
 * esp_encrypt.c : IPSec ESP encrypt node
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
#include <vnet/udp/udp.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_io.h>
#include <vnet/ipsec/esp.h>

#ifndef CLIB_MARCH_VARIANT
ipsec_proto_main_t ipsec_proto_main;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_esp_encrypt_next                   \
_(DROP, "error-drop")                              \
_(IP4_LOOKUP, "ip4-lookup")                        \
_(IP6_LOOKUP, "ip6-lookup")                        \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_encrypt_next
#undef _
    ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(NO_BUFFER, "No buffer (packet dropped)")         \
 _(ENCRYPTION_FAILED, "ESP encryption failed")      \
 _(SEQ_CYCLED, "sequence number cycled")            \
 _(RND_GEN_FAILED, "randomness generation failed")  \
 _(INTERNAL, "internal error")


typedef enum
{
#define _(sym,str) ESP_ENCRYPT_ERROR_##sym,
  foreach_esp_encrypt_error
#undef _
    ESP_ENCRYPT_N_ERROR,
} esp_encrypt_error_t;

static char *esp_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_encrypt_error
#undef _
};

always_inline uword
esp_encrypt_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame, int is_ip6)
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

  esp_encrypt_prepare_jobs (vm, thread_index, im, em, b, job, n_jobs, is_ip6,
			    RAND_bytes, ESP_ENCRYPT_NEXT_DROP,
			    ESP_ENCRYPT_NEXT_IP4_LOOKUP,
			    ESP_ENCRYPT_NEXT_IP6_LOOKUP);

  //submit all the jobs for processing
  ipsec_process_jobs (em, t->jobs, n_jobs, ESP_ENCRYPT_NEXT_DROP,
		      1 /* is_encrypt */ );

  // wrap things up
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  esp_encrypt_finish (vm, im, next, job, n_jobs, thread_index, is_ip6,
		      ESP_ENCRYPT_NEXT_DROP,
		      ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT);

  ipsec_add_traces (vm, node, job, n_jobs);
  ipsec_update_packet_counters (vm, node, t->jobs, n_jobs,
				ESP_ENCRYPT_ERROR_ENCRYPTION_FAILED,
				ESP_ENCRYPT_ERROR_INTERNAL,
				ESP_ENCRYPT_ERROR_SEQ_CYCLED,
				ESP_ENCRYPT_ERROR_INTERNAL,
				ESP_ENCRYPT_ERROR_INTERNAL,
				ESP_ENCRYPT_ERROR_NO_BUFFER,
				ESP_ENCRYPT_ERROR_RND_GEN_FAILED);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (esp4_encrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_encrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_node) = {
  .name = "esp4-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
    foreach_esp_encrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp6_encrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_encrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_encrypt_node) = {
  .name = "esp6-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
    foreach_esp_encrypt_next
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
