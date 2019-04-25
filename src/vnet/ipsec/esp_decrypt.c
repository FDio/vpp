/*
 * esp_decrypt.c : IPSec ESP decrypt node
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
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec_io.h>

#define foreach_esp_decrypt_next                \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input-no-checksum")           \
_(IP6_INPUT, "ip6-input")                       \
_(IPSEC_GRE_INPUT, "ipsec-gre-input")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_decrypt_next
#undef _
    ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;


#define foreach_esp_decrypt_error                               \
 _(RX_PKTS, "ESP pkts received")                                \
 _(DECRYPTION_FAILED, "ESP decryption failed")                  \
 _(INTEG_ERROR, "Integrity check failed")                       \
 _(CRYPTO_ENGINE_ERROR, "crypto engine error (packet dropped)") \
 _(REPLAY, "SA replayed packet")                                \
 _(RUNT, "undersized packet")                                   \
 _(CHAINED_BUFFER, "chained buffers (packet dropped)")          \
 _(OVERSIZED_HEADER, "buffer with oversized header (dropped)")  \
 _(NO_TAIL_SPACE, "no enough buffer tail space (dropped)")


typedef enum
{
#define _(sym,str) ESP_DECRYPT_ERROR_##sym,
  foreach_esp_decrypt_error
#undef _
    ESP_DECRYPT_N_ERROR,
} esp_decrypt_error_t;

static char *esp_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_decrypt_error
#undef _
};

typedef struct
{
  u32 seq;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t *t = va_arg (*args, esp_decrypt_trace_t *);

  s = format (s, "esp: crypto %U integrity %U seq %u",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg, t->seq);
  return s;
}

typedef struct
{
  union
  {
    struct
    {
      u8 icv_sz;
      u8 iv_sz;
      ipsec_sa_flags_t flags:8;
      u32 sa_index;
    };
    u64 sa_data;
  };

  i16 current_data;
  i16 current_length;
  u16 hdr_sz;
} esp_decrypt_packet_data_t;

STATIC_ASSERT_SIZEOF (esp_decrypt_packet_data_t, 2 * sizeof (u64));

#define ESP_ENCRYPT_PD_F_FD_TRANSPORT (1 << 2)

always_inline uword
esp_decrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * from_frame,
		    int is_ip6)
{
  ipsec_main_t *im = &ipsec_main;
  u32 thread_index = vm->thread_index;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u16 len;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, thread_index);
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n, n_left = from_frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  esp_decrypt_packet_data_t pkt_data[VLIB_FRAME_SIZE], *pd = pkt_data;
  esp_decrypt_packet_data_t cpd = { };
  u32 current_sa_index = ~0, current_sa_bytes = 0, current_sa_pkts = 0;
  const u8 esp_sz = sizeof (esp_header_t);
  ipsec_sa_t *sa0 = 0;

  vlib_get_buffers (vm, from, b, n_left);
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->integ_ops);
  clib_memset_u16 (nexts, -1, n_left);

  while (n_left > 0)
    {
      u8 *payload;

      if (n_left > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	  p -= CLIB_CACHE_LINE_BYTES;
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      if (vlib_buffer_chain_linearize (vm, b[0]) != 1)
	{
	  b[0]->error = node->errors[ESP_DECRYPT_ERROR_CHAINED_BUFFER];
	  next[0] = ESP_DECRYPT_NEXT_DROP;
	  goto next;
	}

      if (vnet_buffer (b[0])->ipsec.sad_index != current_sa_index)
	{
	  current_sa_index = vnet_buffer (b[0])->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, current_sa_index);
	  cpd.icv_sz = sa0->integ_icv_size;
	  cpd.iv_sz = sa0->crypto_iv_size;
	  cpd.flags = sa0->flags;
	  cpd.sa_index = current_sa_index;

	  vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					   current_sa_index, current_sa_pkts,
					   current_sa_bytes);

	  current_sa_bytes = current_sa_pkts = 0;
	}

      /* store packet data for next round for easier prefetch */
      pd->sa_data = cpd.sa_data;
      pd->current_data = b[0]->current_data;
      pd->current_length = b[0]->current_length;
      pd->hdr_sz = pd->current_data - vnet_buffer (b[0])->l3_hdr_offset;
      payload = b[0]->data + pd->current_data;

      /* we need 4 extra bytes for HMAC calculation when ESN are used */
      if (ipsec_sa_is_set_USE_ESN (sa0) && pd->icv_sz &&
	  (pd->current_data + pd->current_length + 4 > buffer_data_size))
	{
	  b[0]->error = node->errors[ESP_DECRYPT_ERROR_NO_TAIL_SPACE];
	  next[0] = ESP_DECRYPT_NEXT_DROP;
	  goto next;
	}

      /* anti-reply check */
      if (ipsec_sa_anti_replay_check (sa0, &((esp_header_t *) payload)->seq))
	{
	  b[0]->error = node->errors[ESP_DECRYPT_ERROR_REPLAY];
	  next[0] = ESP_DECRYPT_NEXT_DROP;
	  goto next;
	}

      if (pd->current_length < cpd.icv_sz + esp_sz + cpd.iv_sz)
	{
	  b[0]->error = node->errors[ESP_DECRYPT_ERROR_RUNT];
	  next[0] = ESP_DECRYPT_NEXT_DROP;
	  goto next;
	}

      len = pd->current_length - cpd.icv_sz;
      current_sa_pkts += 1;
      current_sa_bytes += pd->current_length;

      if (PREDICT_TRUE (sa0->integ_op_id != VNET_CRYPTO_OP_NONE))
	{
	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->integ_ops, op, 1, CLIB_CACHE_LINE_BYTES);

	  vnet_crypto_op_init (op, sa0->integ_op_id);
	  op->key_index = sa0->integ_key_index;
	  op->src = payload;
	  op->flags = VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
	  op->user_data = b - bufs;
	  op->digest = payload + len;
	  op->digest_len = cpd.icv_sz;
	  op->len = len;
	  if (ipsec_sa_is_set_USE_ESN (sa0))
	    {
	      /* shift ICV for 4 bytes to insert ESN */
	      u8 tmp[ESP_MAX_ICV_SIZE], sz = sizeof (sa0->seq_hi);
	      clib_memcpy_fast (tmp, payload + len, ESP_MAX_ICV_SIZE);
	      clib_memcpy_fast (payload + len, &sa0->seq_hi, sz);
	      clib_memcpy_fast (payload + len + sz, tmp, ESP_MAX_ICV_SIZE);
	      op->len += sz;
	      op->digest += sz;
	    }
	}

      payload += esp_sz;
      len -= esp_sz;

      if (sa0->crypto_enc_op_id != VNET_CRYPTO_OP_NONE)
	{
	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
	  vnet_crypto_op_init (op, sa0->crypto_dec_op_id);
	  op->key_index = sa0->crypto_key_index;
	  op->iv = payload;

	  if (ipsec_sa_is_set_IS_AEAD (sa0))
	    {
	      esp_header_t *esp0;
	      esp_aead_t *aad;
	      u8 *scratch;

	      /*
	       * construct the AAD and the nonce (Salt || IV) in a scratch
	       * space in front of the IP header.
	       */
	      scratch = payload - esp_sz;
	      esp0 = (esp_header_t *) (scratch);

	      scratch -= (sizeof (*aad) + pd->hdr_sz);
	      op->aad = scratch;

	      esp_aad_fill (op, esp0, sa0);

	      /*
	       * we don't need to refer to the ESP header anymore so we
	       * can overwrite it with the salt and use the IV where it is
	       * to form the nonce = (Salt + IV)
	       */
	      op->iv -= sizeof (sa0->salt);
	      clib_memcpy_fast (op->iv, &sa0->salt, sizeof (sa0->salt));

	      op->tag = payload + len;
	      op->tag_len = 16;
	    }
	  op->src = op->dst = payload += cpd.iv_sz;
	  op->len = len - cpd.iv_sz;
	  op->user_data = b - bufs;
	}

      /* next */
    next:
      n_left -= 1;
      next += 1;
      pd += 1;
      b += 1;
    }

  vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
				   current_sa_index, current_sa_pkts,
				   current_sa_bytes);

  if ((n = vec_len (ptd->integ_ops)))
    {
      vnet_crypto_op_t *op = ptd->integ_ops;
      n -= vnet_crypto_process_ops (vm, op, n);
      while (n)
	{
	  ASSERT (op - ptd->integ_ops < vec_len (ptd->integ_ops));
	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 err, bi = op->user_data;
	      if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
		err = ESP_DECRYPT_ERROR_INTEG_ERROR;
	      else
		err = ESP_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;
	      bufs[bi]->error = node->errors[err];
	      nexts[bi] = ESP_DECRYPT_NEXT_DROP;
	      n--;
	    }
	  op++;
	}
    }
  if ((n = vec_len (ptd->crypto_ops)))
    {
      vnet_crypto_op_t *op = ptd->crypto_ops;
      n -= vnet_crypto_process_ops (vm, op, n);
      while (n)
	{
	  ASSERT (op - ptd->crypto_ops < vec_len (ptd->crypto_ops));
	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 err, bi;

	      bi = op->user_data;

	      if (op->status == VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC)
		err = ESP_DECRYPT_ERROR_DECRYPTION_FAILED;
	      else
		err = ESP_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR;

	      bufs[bi]->error = node->errors[err];
	      nexts[bi] = ESP_DECRYPT_NEXT_DROP;
	      n--;
	    }
	  op++;
	}
    }

  /* Post decryption ronud - adjust packet data start and length and next
     node */

  n_left = from_frame->n_vectors;
  next = nexts;
  pd = pkt_data;
  b = bufs;

  while (n_left)
    {
      const u8 tun_flags = IPSEC_SA_FLAG_IS_TUNNEL |
	IPSEC_SA_FLAG_IS_TUNNEL_V6;

      if (n_left >= 2)
	{
	  void *data = b[1]->data + pd[1].current_data;

	  /* buffer metadata */
	  vlib_prefetch_buffer_header (b[1], LOAD);

	  /* esp_footer_t */
	  CLIB_PREFETCH (data + pd[1].current_length - pd[1].icv_sz - 2,
			 CLIB_CACHE_LINE_BYTES, LOAD);

	  /* packet headers */
	  CLIB_PREFETCH (data - CLIB_CACHE_LINE_BYTES,
			 CLIB_CACHE_LINE_BYTES * 2, LOAD);
	}

      if (next[0] < ESP_DECRYPT_N_NEXT)
	goto trace;

      sa0 = vec_elt_at_index (im->sad, pd->sa_index);
      u8 *payload = b[0]->data + pd->current_data;

      ipsec_sa_anti_replay_advance (sa0, &((esp_header_t *) payload)->seq);

      esp_footer_t *f = (esp_footer_t *) (b[0]->data + pd->current_data +
					  pd->current_length - sizeof (*f) -
					  pd->icv_sz);
      u16 adv = pd->iv_sz + esp_sz;
      u16 tail = sizeof (esp_footer_t) + f->pad_length + pd->icv_sz;

      if ((pd->flags & tun_flags) == 0)	/* transport mode */
	{
	  u8 udp_sz = (is_ip6 == 0 && pd->flags & IPSEC_SA_FLAG_UDP_ENCAP) ?
	    sizeof (udp_header_t) : 0;
	  u16 ip_hdr_sz = pd->hdr_sz - udp_sz;
	  u8 *old_ip = b[0]->data + pd->current_data - ip_hdr_sz - udp_sz;
	  u8 *ip = old_ip + adv + udp_sz;

	  if (is_ip6 && ip_hdr_sz > 64)
	    memmove (ip, old_ip, ip_hdr_sz);
	  else
	    clib_memcpy_le64 (ip, old_ip, ip_hdr_sz);

	  b[0]->current_data = pd->current_data + adv - ip_hdr_sz;
	  b[0]->current_length = pd->current_length + ip_hdr_sz - tail - adv;

	  if (is_ip6)
	    {
	      ip6_header_t *ip6 = (ip6_header_t *) ip;
	      u16 len = clib_net_to_host_u16 (ip6->payload_length);
	      len -= adv + tail;
	      ip6->payload_length = clib_host_to_net_u16 (len);
	      ip6->protocol = f->next_header;
	      next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
	    }
	  else
	    {
	      ip4_header_t *ip4 = (ip4_header_t *) ip;
	      ip_csum_t sum = ip4->checksum;
	      u16 len = clib_net_to_host_u16 (ip4->length);
	      len = clib_host_to_net_u16 (len - adv - tail - udp_sz);
	      sum = ip_csum_update (sum, ip4->protocol, f->next_header,
				    ip4_header_t, protocol);
	      sum = ip_csum_update (sum, ip4->length, len,
				    ip4_header_t, length);
	      ip4->checksum = ip_csum_fold (sum);
	      ip4->protocol = f->next_header;
	      ip4->length = len;
	      next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
	    }
	}
      else
	{
	  if (PREDICT_TRUE (f->next_header == IP_PROTOCOL_IP_IN_IP))
	    {
	      next[0] = ESP_DECRYPT_NEXT_IP4_INPUT;
	      b[0]->current_data = pd->current_data + adv;
	      b[0]->current_length = pd->current_length + adv - tail;
	    }
	  else if (f->next_header == IP_PROTOCOL_IPV6)
	    {
	      next[0] = ESP_DECRYPT_NEXT_IP6_INPUT;
	      b[0]->current_data = pd->current_data + adv;
	      b[0]->current_length = pd->current_length + adv - tail;
	    }
	  else
	    {
	      next[0] = ESP_DECRYPT_NEXT_DROP;
	      b[0]->error = node->errors[ESP_DECRYPT_ERROR_DECRYPTION_FAILED];
	    }
	}

      if (PREDICT_FALSE (ipsec_sa_is_set_IS_GRE (sa0)))
	next[0] = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;

    trace:
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_decrypt_trace_t *tr;
	  u8 *payload = b[0]->data + pd->current_data;
	  tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  sa0 = pool_elt_at_index (im->sad,
				   vnet_buffer (b[0])->ipsec.sad_index);
	  tr->crypto_alg = sa0->crypto_alg;
	  tr->integ_alg = sa0->integ_alg;
	  tr->seq = clib_host_to_net_u32 (((esp_header_t *) payload)->seq);
	}

      /* next */
      n_left -= 1;
      next += 1;
      pd += 1;
      b += 1;
    }

  n_left = from_frame->n_vectors;
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_DECRYPT_ERROR_RX_PKTS, n_left);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_left);

  b = bufs;
  return n_left;
}

VLIB_NODE_FN (esp4_decrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 0 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_decrypt_node) = {
  .name = "esp4-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_DECRYPT_NEXT_##s] = n,
    foreach_esp_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (esp6_decrypt_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  return esp_decrypt_inline (vm, node, from_frame, 1 /* is_ip6 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_decrypt_node) = {
  .name = "esp6-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_DECRYPT_NEXT_##s] = n,
    foreach_esp_decrypt_next
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
