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

#include <vnet/crypto/crypto.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

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
 _(DECRYPTION_FAILED, "ESP encryption failed")      \
 _(SEQ_CYCLED, "sequence number cycled")


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

typedef struct
{
  u32 sa_index;
  u32 spi;
  u32 seq;
  u8 udp_encap;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);

  s = format (s, "esp: sa-index %d spi %u seq %u crypto %U integrity %U%s",
	      t->sa_index, t->spi, t->seq,
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg,
	      t->udp_encap ? " udp-encap-enabled" : "");
  return s;
}

always_inline void
esp_encrypt_cbc (vlib_main_t * vm, ipsec_sa_t * sa,
		 u8 * in, u8 * out, size_t in_len, u8 * key, u8 * iv)
{
  vnet_crypto_op_t _op, *op = &_op;


  if (PREDICT_FALSE (sa->crypto_enc_op_type == VNET_CRYPTO_OP_NONE))
    return;

  op->op = sa->crypto_enc_op_type;
  op->flags = VNET_CRYPTO_OP_FLAG_INIT_IV;
  op->iv = iv;
  op->src = in;
  op->dst = out;
  op->len = in_len;
  op->key = key;

  vnet_crypto_process_ops (vm, op, 1);
}

always_inline uword
esp_encrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		    int is_ip6)
{
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  u32 new_bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t *i_bufs[VLIB_FRAME_SIZE], **ib = i_bufs;
  vlib_buffer_t *o_bufs[VLIB_FRAME_SIZE], **ob = o_bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 n_alloc, thread_index = vm->thread_index;

  n_alloc = vlib_buffer_alloc (vm, new_bufs, n_left_from);
  if (n_alloc != n_left_from)
    {
      vlib_node_increment_counter (vm, node->node_index,
				   ESP_ENCRYPT_ERROR_NO_BUFFER,
				   n_left_from - n_alloc);
      if (n_alloc == 0)
	goto done;
      n_left_from = n_alloc;
    }

  vlib_get_buffers (vm, from, ib, n_left_from);
  vlib_get_buffers (vm, new_bufs, ob, n_left_from);

  while (n_left_from > 0)
    {
      u32 sa_index0;
      ipsec_sa_t *sa0;
      ip4_and_esp_header_t *oh0 = 0;
      ip6_and_esp_header_t *ih6_0, *oh6_0 = 0;
      ip4_and_udp_and_esp_header_t *iuh0, *ouh0 = 0;
      esp_header_t *o_esp0;
      esp_footer_t *f0;
      u8 ip_udp_hdr_size;
      u8 next_hdr_type;
      u32 ip_proto = 0;
      u8 transport_mode = 0;
      u32 esp_seq_err;

      next[0] = ESP_ENCRYPT_NEXT_DROP;

      sa_index0 = vnet_buffer (ib[0])->ipsec.sad_index;
      sa0 = pool_elt_at_index (im->sad, sa_index0);

      vlib_prefetch_combined_counter (&ipsec_sa_counters, thread_index,
				      sa_index0);

      esp_seq_err = esp_seq_advance (sa0);

      /* grab free buffer */
      ob[0]->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
      ob[0]->current_data = sizeof (ethernet_header_t);
      iuh0 = vlib_buffer_get_current (ib[0]);

      if (is_ip6)
	{
	  ih6_0 = vlib_buffer_get_current (ib[0]);
	  next_hdr_type = IP_PROTOCOL_IPV6;
	  oh6_0 = vlib_buffer_get_current (ob[0]);

	  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
	    ih6_0->ip6.ip_version_traffic_class_and_flow_label;
	  oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
	  ip_udp_hdr_size = sizeof (ip6_header_t);
	  o_esp0 = vlib_buffer_get_current (ob[0]) + ip_udp_hdr_size;
	  oh6_0->ip6.hop_limit = 254;
	  oh6_0->ip6.src_address.as_u64[0] = ih6_0->ip6.src_address.as_u64[0];
	  oh6_0->ip6.src_address.as_u64[1] = ih6_0->ip6.src_address.as_u64[1];
	  oh6_0->ip6.dst_address.as_u64[0] = ih6_0->ip6.dst_address.as_u64[0];
	  oh6_0->ip6.dst_address.as_u64[1] = ih6_0->ip6.dst_address.as_u64[1];
	  o_esp0->spi = clib_net_to_host_u32 (sa0->spi);
	  o_esp0->seq = clib_net_to_host_u32 (sa0->seq);
	  ip_proto = ih6_0->ip6.protocol;

	  next[0] = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
	}
      else
	{
	  next_hdr_type = IP_PROTOCOL_IP_IN_IP;
	  oh0 = vlib_buffer_get_current (ob[0]);
	  ouh0 = vlib_buffer_get_current (ob[0]);

	  oh0->ip4.ip_version_and_header_length = 0x45;
	  oh0->ip4.tos = iuh0->ip4.tos;
	  oh0->ip4.fragment_id = 0;
	  oh0->ip4.flags_and_fragment_offset = 0;
	  oh0->ip4.ttl = 254;
	  if (sa0->udp_encap)
	    {
	      ouh0->udp.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
	      ouh0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
	      ouh0->udp.checksum = 0;
	      ouh0->ip4.protocol = IP_PROTOCOL_UDP;
	      ip_udp_hdr_size = sizeof (udp_header_t) + sizeof (ip4_header_t);
	    }
	  else
	    {
	      oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
	      ip_udp_hdr_size = sizeof (ip4_header_t);
	    }
	  o_esp0 = vlib_buffer_get_current (ob[0]) + ip_udp_hdr_size;
	  oh0->ip4.src_address.as_u32 = iuh0->ip4.src_address.as_u32;
	  oh0->ip4.dst_address.as_u32 = iuh0->ip4.dst_address.as_u32;
	  o_esp0->spi = clib_net_to_host_u32 (sa0->spi);
	  o_esp0->seq = clib_net_to_host_u32 (sa0->seq);
	  ip_proto = iuh0->ip4.protocol;

	  next[0] = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
	}

      if (PREDICT_TRUE (!is_ip6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	{
	  oh0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	  oh0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	  next[0] = sa0->dpo[IPSEC_PROTOCOL_ESP].dpoi_next_node;
	  vnet_buffer (ob[0])->ip.adj_index[VLIB_TX] =
	    sa0->dpo[IPSEC_PROTOCOL_ESP].dpoi_index;
	}
      else if (is_ip6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
	{
	  oh6_0->ip6.src_address.as_u64[0] =
	    sa0->tunnel_src_addr.ip6.as_u64[0];
	  oh6_0->ip6.src_address.as_u64[1] =
	    sa0->tunnel_src_addr.ip6.as_u64[1];
	  oh6_0->ip6.dst_address.as_u64[0] =
	    sa0->tunnel_dst_addr.ip6.as_u64[0];
	  oh6_0->ip6.dst_address.as_u64[1] =
	    sa0->tunnel_dst_addr.ip6.as_u64[1];

	  next[0] = sa0->dpo[IPSEC_PROTOCOL_ESP].dpoi_next_node;
	  vnet_buffer (ob[0])->ip.adj_index[VLIB_TX] =
	    sa0->dpo[IPSEC_PROTOCOL_ESP].dpoi_index;
	}
      else
	{
	  next_hdr_type = ip_proto;
	  if (vnet_buffer (ib[0])->sw_if_index[VLIB_TX] != ~0)
	    {
	      transport_mode = 1;
	      ethernet_header_t *ieh0, *oeh0;
	      ieh0 =
		(ethernet_header_t *) ((u8 *)
				       vlib_buffer_get_current (ib[0]) -
				       sizeof (ethernet_header_t));
	      oeh0 = (ethernet_header_t *) ob[0]->data;
	      clib_memcpy_fast (oeh0, ieh0, sizeof (ethernet_header_t));
	      next[0] = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	      vnet_buffer (ob[0])->sw_if_index[VLIB_TX] =
		vnet_buffer (ib[0])->sw_if_index[VLIB_TX];
	    }

	  if (is_ip6)
	    vlib_buffer_advance (ib[0], sizeof (ip6_header_t));
	  else
	    vlib_buffer_advance (ib[0], sizeof (ip4_header_t));
	}

      ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);
      vlib_increment_combined_counter
	(&ipsec_sa_counters, thread_index, sa_index0,
	 1, ib[0]->current_length);

      if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	{

	  const int BLOCK_SIZE = sa0->crypto_block_size;
	  const int IV_SIZE = sa0->crypto_iv_size;
	  int blocks = 1 + (ib[0]->current_length + 1) / BLOCK_SIZE;

	  /* pad packet in input buffer */
	  u8 pad_bytes = BLOCK_SIZE * blocks - 2 - ib[0]->current_length;
	  u8 i;
	  u8 *padding =
	    vlib_buffer_get_current (ib[0]) + ib[0]->current_length;
	  ib[0]->current_length = BLOCK_SIZE * blocks;
	  for (i = 0; i < pad_bytes; ++i)
	    {
	      padding[i] = i + 1;
	    }
	  f0 = vlib_buffer_get_current (ib[0]) + ib[0]->current_length - 2;
	  f0->pad_length = pad_bytes;
	  f0->next_header = next_hdr_type;

	  ob[0]->current_length = ip_udp_hdr_size + sizeof (esp_header_t) +
	    BLOCK_SIZE * blocks + IV_SIZE;

	  vnet_buffer (ob[0])->sw_if_index[VLIB_RX] =
	    vnet_buffer (ib[0])->sw_if_index[VLIB_RX];

	  u8 *iv = vlib_buffer_get_current (ob[0]) + ip_udp_hdr_size +
	    sizeof (esp_header_t);

	  clib_memcpy_fast ((u8 *) vlib_buffer_get_current (ob[0]) +
			    ip_udp_hdr_size + sizeof (esp_header_t), iv,
			    IV_SIZE);

	  esp_encrypt_cbc (vm, sa0, (u8 *) vlib_buffer_get_current (ib[0]),
			   (u8 *) vlib_buffer_get_current (ob[0]) +
			   ip_udp_hdr_size + sizeof (esp_header_t) +
			   IV_SIZE, BLOCK_SIZE * blocks,
			   sa0->crypto_key.data, iv);
	}

      ob[0]->current_length +=
	hmac_calc (vm, sa0, (u8 *) o_esp0,
		   ob[0]->current_length - ip_udp_hdr_size,
		   vlib_buffer_get_current (ob[0]) + ob[0]->current_length);


      if (is_ip6)
	{
	  oh6_0->ip6.payload_length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, ob[0]) -
				  sizeof (ip6_header_t));
	}
      else
	{
	  oh0->ip4.length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, ob[0]));
	  oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	  if (sa0->udp_encap)
	    {
	      ouh0->udp.length =
		clib_host_to_net_u16 (clib_net_to_host_u16
				      (oh0->ip4.length) -
				      ip4_header_bytes (&oh0->ip4));
	    }
	}

      if (transport_mode)
	vlib_buffer_reset (ob[0]);

      if (PREDICT_FALSE (esp_seq_err))
	{
	  ob[0]->error = node->errors[ESP_ENCRYPT_ERROR_SEQ_CYCLED];
	  next[0] = ESP_ENCRYPT_NEXT_DROP;
	}

      if (PREDICT_FALSE (ib[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  if (ob[0])
	    {
	      ob[0]->flags |= VLIB_BUFFER_IS_TRACED;
	      ob[0]->trace_index = ib[0]->trace_index;
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, ob[0], sizeof (*tr));
	      tr->sa_index = sa_index0;
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->udp_encap = sa0->udp_encap;
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }
	}

      /* next */
      n_left_from -= 1;
      ib += 1;
      ob += 1;
      next += 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       ESP_ENCRYPT_ERROR_RX_PKTS, n_alloc);

  vlib_buffer_enqueue_to_next (vm, node, new_bufs, nexts, n_alloc);
done:
  vlib_buffer_free (vm, from, from_frame->n_vectors);
  return n_alloc;
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
  .format_trace = format_esp_encrypt_trace,
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
  .format_trace = format_esp_encrypt_trace,
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
