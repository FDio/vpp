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
#include <vnet/ipsec/esp.h>

ipsec_proto_main_t ipsec_proto_main;

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

  s = format (s, "esp: spi %u seq %u crypto %U integrity %U%s",
	      t->spi, t->seq,
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg,
	      t->udp_encap ? " udp-encap-enabled" : "");
  return s;
}

always_inline uword
esp_encrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		    int is_ip6)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 *recycle = 0;
  u32 thread_index = vm->thread_index;

  ipsec_alloc_empty_buffers (vm, im);

  u32 *empty_buffers = im->empty_buffers[thread_index];

  if (PREDICT_FALSE (vec_len (empty_buffers) < n_left_from))
    {
      vlib_node_increment_counter (vm, node->node_index,
				   ESP_ENCRYPT_ERROR_NO_BUFFER, n_left_from);
      clib_warning ("not enough empty buffers. discarding frame");
      goto free_buffers_and_exit;
    }

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 i_bi0, o_bi0, next0;
	  vlib_buffer_t *i_b0, *o_b0 = 0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ip4_and_esp_header_t *oh0 = 0;
	  ip6_and_esp_header_t *ih6_0, *oh6_0 = 0;
	  ip4_and_udp_and_esp_header_t *iuh0, *ouh0 = 0;
	  uword last_empty_buffer;
	  esp_header_t *o_esp0;
	  esp_footer_t *f0;
	  u8 ip_udp_hdr_size;
	  u8 next_hdr_type;
	  u32 ip_proto = 0;
	  u8 transport_mode = 0;

	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_ENCRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);
	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, node->node_index,
					   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO: rekey SA
	      o_bi0 = i_bi0;
	      to_next[0] = o_bi0;
	      to_next += 1;
	      goto trace;
	    }

	  sa0->total_data_size += vlib_buffer_length_in_chain (vm, i_b0);

	  u32 last_i_bi0 = i_bi0;
	  vlib_buffer_t *last_i_b0 = i_b0;
	  int count = 0;
	  while (last_i_b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      last_i_bi0 = last_i_b0->next_buffer;
	      last_i_b0 = vlib_get_buffer (vm, last_i_bi0);
	      ++count;
	    }

	  if (2 * count + 1 > vec_len (empty_buffers))
	    {
	      ipsec_alloc_empty_buffers (vm, im);
	      if (PREDICT_FALSE (2 * count + 1 > vec_len (empty_buffers)))
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ESP_ENCRYPT_ERROR_NO_BUFFER,
					       1);
		  o_bi0 = i_bi0;
		  to_next[0] = o_bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  /* grab free buffer */
	  last_empty_buffer = vec_len (empty_buffers) - 1;
	  o_bi0 = empty_buffers[last_empty_buffer];
	  o_b0 = vlib_get_buffer (vm, o_bi0);
	  o_b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  o_b0->current_data = sizeof (ethernet_header_t);
	  iuh0 = vlib_buffer_get_current (i_b0);
	  vlib_prefetch_buffer_with_index (vm,
					   empty_buffers[last_empty_buffer -
							 1], STORE);
	  _vec_len (empty_buffers) = last_empty_buffer;
	  if (is_ip6)
	    {
	      ih6_0 = vlib_buffer_get_current (i_b0);
	      next_hdr_type = IP_PROTOCOL_IPV6;
	      oh6_0 = vlib_buffer_get_current (o_b0);

	      oh6_0->ip6.ip_version_traffic_class_and_flow_label =
		ih6_0->ip6.ip_version_traffic_class_and_flow_label;
	      oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
	      ip_udp_hdr_size = sizeof (ip6_header_t);
	      o_esp0 = vlib_buffer_get_current (o_b0) + ip_udp_hdr_size;
	      oh6_0->ip6.hop_limit = 254;
	      oh6_0->ip6.src_address.as_u64[0] =
		ih6_0->ip6.src_address.as_u64[0];
	      oh6_0->ip6.src_address.as_u64[1] =
		ih6_0->ip6.src_address.as_u64[1];
	      oh6_0->ip6.dst_address.as_u64[0] =
		ih6_0->ip6.dst_address.as_u64[0];
	      oh6_0->ip6.dst_address.as_u64[1] =
		ih6_0->ip6.dst_address.as_u64[1];
	      o_esp0->spi = clib_net_to_host_u32 (sa0->spi);
	      o_esp0->seq = clib_net_to_host_u32 (sa0->seq);
	      ip_proto = ih6_0->ip6.protocol;

	      next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
	    }
	  else
	    {
	      next_hdr_type = IP_PROTOCOL_IP_IN_IP;
	      oh0 = vlib_buffer_get_current (o_b0);
	      ouh0 = vlib_buffer_get_current (o_b0);

	      oh0->ip4.ip_version_and_header_length = 0x45;
	      oh0->ip4.tos = iuh0->ip4.tos;
	      oh0->ip4.fragment_id = 0;
	      oh0->ip4.flags_and_fragment_offset = 0;
	      oh0->ip4.ttl = 254;
	      if (sa0->udp_encap)
		{
		  ouh0->udp.src_port =
		    clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
		  ouh0->udp.dst_port =
		    clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
		  ouh0->udp.checksum = 0;
		  ouh0->ip4.protocol = IP_PROTOCOL_UDP;
		  ip_udp_hdr_size =
		    sizeof (udp_header_t) + sizeof (ip4_header_t);
		}
	      else
		{
		  oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
		  ip_udp_hdr_size = sizeof (ip4_header_t);
		}
	      o_esp0 = vlib_buffer_get_current (o_b0) + ip_udp_hdr_size;
	      oh0->ip4.src_address.as_u32 = iuh0->ip4.src_address.as_u32;
	      oh0->ip4.dst_address.as_u32 = iuh0->ip4.dst_address.as_u32;
	      o_esp0->spi = clib_net_to_host_u32 (sa0->spi);
	      o_esp0->seq = clib_net_to_host_u32 (sa0->seq);
	      ip_proto = iuh0->ip4.protocol;

	      next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
	    }

	  if (PREDICT_TRUE (!is_ip6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      oh0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	      oh0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	      vnet_buffer (o_b0)->sw_if_index[VLIB_TX] = sa0->tx_fib_index;
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

	      vnet_buffer (o_b0)->sw_if_index[VLIB_TX] = sa0->tx_fib_index;
	    }
	  else
	    {
	      next_hdr_type = ip_proto;
	      if (vnet_buffer (i_b0)->sw_if_index[VLIB_TX] != ~0)
		{
		  transport_mode = 1;
		  ethernet_header_t *ieh0, *oeh0;
		  ieh0 =
		    (ethernet_header_t *) ((u8 *)
					   vlib_buffer_get_current (i_b0) -
					   sizeof (ethernet_header_t));
		  oeh0 = (ethernet_header_t *) o_b0->data;
		  clib_memcpy_fast (oeh0, ieh0, sizeof (ethernet_header_t));
		  next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
		  vnet_buffer (o_b0)->sw_if_index[VLIB_TX] =
		    vnet_buffer (i_b0)->sw_if_index[VLIB_TX];
		}

	      if (is_ip6)
		{
		  vlib_buffer_advance (i_b0, sizeof (ip6_header_t));
		}
	      else
		{
		  vlib_buffer_advance (i_b0, sizeof (ip4_header_t));
		}
	    }

	  ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

	  if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	    {

	      const int block_size =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;
	      const int iv_size =
		em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;
	      const int blocks =
		1 + (vlib_buffer_length_in_chain (vm, i_b0) + 1) / block_size;

	      /* pad packet in input buffer */
	      u8 pad_bytes =
		block_size * blocks - sizeof (esp_footer_t) -
		vlib_buffer_length_in_chain (vm, i_b0);
	      const size_t space_left_in_buffer = VLIB_BUFFER_DATA_SIZE -
		((u8 *) vlib_buffer_get_current (last_i_b0) +
		 last_i_b0->current_length - last_i_b0->data);
	      if (pad_bytes + sizeof (esp_footer_t) > space_left_in_buffer)
		{
		  last_empty_buffer = vec_len (empty_buffers) - 1;
		  u32 ebi = empty_buffers[last_empty_buffer];
		  vlib_buffer_t *eb = vlib_get_buffer (vm, ebi);
		  eb->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
		  eb->current_data = 0;
		  eb->current_length = 0;
		  vlib_buffer_chain_buffer (vm, last_i_b0, ebi);
		  vlib_prefetch_buffer_with_index (vm,
						   empty_buffers
						   [last_empty_buffer - 1],
						   STORE);
		  _vec_len (empty_buffers) = last_empty_buffer;
		  last_i_bi0 = ebi;
		  last_i_b0 = eb;
		}
	      u8 *padding =
		vlib_buffer_get_current (last_i_b0) +
		last_i_b0->current_length;
	      u8 i;
	      for (i = 0; i < pad_bytes; ++i)
		{
		  padding[i] = i + 1;
		}
	      f0 =
		vlib_buffer_get_current (last_i_b0) +
		last_i_b0->current_length + pad_bytes;
	      f0->pad_length = pad_bytes;
	      f0->next_header = next_hdr_type;

	      if (i_b0 != last_i_b0)
		{
		  last_i_b0->current_length += pad_bytes + sizeof (*f0);
		  i_b0->total_length_not_including_first_buffer =
		    block_size * blocks - i_b0->current_length;
		  i_b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
		}
	      else
		{
		  i_b0->current_length = block_size * blocks;
		}

	      o_b0->current_length =
		ip_udp_hdr_size + sizeof (esp_header_t) + iv_size;

	      vnet_buffer (o_b0)->sw_if_index[VLIB_RX] =
		vnet_buffer (i_b0)->sw_if_index[VLIB_RX];

	      u8 iv[iv_size];
	      RAND_bytes (iv, sizeof (iv));

	      clib_memcpy_fast ((u8 *) vlib_buffer_get_current (o_b0) +
				ip_udp_hdr_size + sizeof (esp_header_t), iv,
				iv_size);

	      if (!esp_cipher_cbc
		  (vm, sa0->crypto_alg, i_b0, 0, o_b0, sa0->crypto_key, iv,
		   NULL, empty_buffers, 1 /* is_encrypt */ ))
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ESP_ENCRYPT_ERROR_ENCRYPTION_FAILED,
					       1);
		  vec_add1 (recycle, o_bi0);
		  o_bi0 = i_bi0;
		  to_next[0] = o_bi0;
		  to_next += 1;
		  next0 = ESP_ENCRYPT_NEXT_DROP;
		  goto trace;
		}
	    }

	  HMAC_CTX *ctx = hmac_calc_start (sa0->integ_alg, sa0->integ_key,
					   sa0->integ_key_len);

	  hmac_calc_update (ctx, (u8 *) o_esp0,
			    o_b0->current_length - ip_udp_hdr_size);

	  vlib_buffer_t *last_ob0 = o_b0;
	  while (last_ob0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      last_ob0 = vlib_get_buffer (vm, last_ob0->next_buffer);
	      hmac_calc_update (ctx, vlib_buffer_get_current (last_ob0),
				last_ob0->current_length);
	    }

	  const size_t sig_size =
	    em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;
	  const size_t space_left_in_buffer =
	    VLIB_BUFFER_DATA_SIZE -
	    ((u8 *) vlib_buffer_get_current (last_ob0) +
	     last_ob0->current_length - last_ob0->data);
	  if (sig_size > space_left_in_buffer)
	    {
	      u32 last_empty_buffer = vec_len (empty_buffers) - 1;
	      u32 ebi = empty_buffers[last_empty_buffer];
	      vlib_buffer_t *eb = vlib_get_buffer (vm, ebi);
	      eb->current_data = 0;
	      eb->current_length = 0;
	      vlib_buffer_chain_buffer (vm, last_ob0, ebi);
	      vlib_prefetch_buffer_with_index (vm,
					       empty_buffers[last_empty_buffer
							     - 1], STORE);
	      _vec_len (empty_buffers) = last_empty_buffer;
	      last_ob0 = eb;
	    }
	  void *sig =
	    vlib_buffer_get_current (last_ob0) + last_ob0->current_length;
	  hmac_calc_finalize (ctx, sig, sa0->use_esn, sa0->seq_hi);

	  last_ob0->current_length += sig_size;
	  o_b0->total_length_not_including_first_buffer += sig_size;

	  if (is_ip6)
	    {
	      oh6_0->ip6.payload_length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, o_b0) -
				      sizeof (ip6_header_t));
	    }
	  else
	    {
	      oh0->ip4.length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, o_b0));
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
	    vlib_buffer_reset (o_b0);

	  to_next[0] = o_bi0;
	  to_next += 1;

	  /* add old buffer to the recycle list */
	  vec_add1 (recycle, i_bi0);

	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      if (o_b0)
		{
		  o_b0->flags |= VLIB_BUFFER_IS_TRACED;
		  o_b0->trace_index = i_b0->trace_index;
		  esp_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, o_b0, sizeof (*tr));
		  tr->spi = sa0->spi;
		  tr->seq = sa0->seq - 1;
		  tr->udp_encap = sa0->udp_encap;
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, o_bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

free_buffers_and_exit:
  if (recycle)
    vlib_buffer_free (vm, recycle, vec_len (recycle));
  vec_free (recycle);
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
