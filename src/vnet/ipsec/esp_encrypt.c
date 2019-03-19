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
 _(SEQ_CYCLED, "sequence number cycled")            \
 _(NO_TRAILER_SPACE, "no enough space for ESP trailer and ICV")


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

/* pad packet in input buffer */
static_always_inline u8 *
esp_add_footer_and_icv (vlib_buffer_t * b, u8 block_size, u8 icv_sz)
{
  esp_footer_t *f;
  u16 current_length = b->current_length;
  int blocks = 1 + (current_length + 1) / block_size;
  u8 pad_bytes = block_size * blocks - 2 - current_length;
  u8 i;
  u8 *padding = vlib_buffer_get_current (b) + current_length;
  b->current_length = current_length = block_size * blocks;

  for (i = 0; i < pad_bytes; ++i)
    padding[i] = i + 1;

  f = vlib_buffer_get_current (b) + current_length - 2;
  f->pad_length = pad_bytes;

  b->current_length += icv_sz;

  return &f->next_header;
}

static_always_inline void
esp_update_ip4_hdr (ip4_header_t * ip4, u16 len, int is_transport, int is_udp)
{
  ip_csum_t sum = ip4->checksum;
  u16 old_len = 0;

  if (is_transport)
    {
      u8 prot = is_udp ? IP_PROTOCOL_UDP : IP_PROTOCOL_IPSEC_ESP;
      old_len = ip4->length;
      sum = ip_csum_update (sum, ip4->protocol, prot, ip4_header_t, protocol);
      ip4->protocol = prot;
    }

  ip4->length = len = clib_net_to_host_u16 (len);
  sum = ip_csum_update (ip4->checksum, old_len, len, ip4_header_t, length);
  ip4->checksum = ip_csum_fold (sum);
}

static_always_inline void
esp_fill_udp_hdr (ipsec_sa_t * sa, udp_header_t * udp, u16 len)
{
  clib_memcpy_fast (udp, &sa->udp_hdr, sizeof (udp_header_t));
  udp->length = clib_net_to_host_u16 (len);
}

static_always_inline u8
ext_hdr_is_pre_esp (u8 nexthdr)
{
#ifdef CLIB_HAVE_VEC128
  static const u8x16 ext_hdr_types = {
    IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS,
    IP_PROTOCOL_IPV6_ROUTE,
    IP_PROTOCOL_IPV6_FRAGMENTATION,
  };

  return !u8x16_is_all_zero (ext_hdr_types == u8x16_splat (nexthdr));
#else
  return ((nexthdr ^ IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS) |
	  (nexthdr ^ IP_PROTOCOL_IPV6_ROUTE) |
	  (nexthdr ^ IP_PROTOCOL_IPV6_FRAGMENTATION) != 0);
#endif
}

static_always_inline u8
esp_get_ip6_hdr_len (ip6_header_t * ip6)
{
  /* this code assumes that HbH, route and frag headers will be before
     others, if that is not the case, they will end up encrypted */

  u8 len = sizeof (ip6_header_t);
  ip6_ext_header_t *p;

  /* if next packet doens't have ext header */
  if (ext_hdr_is_pre_esp (ip6->protocol) == 0)
    return len;

  p = (void *) (ip6 + 1);
  len += ip6_ext_header_len (p);

  while (ext_hdr_is_pre_esp (p->next_hdr))
    {
      len += ip6_ext_header_len (p);
      p = ip6_ext_next_header (p);
    }

  return len;
}

static_always_inline int
esp_trailer_icv_overflow (vlib_node_runtime_t * node, vlib_buffer_t * b,
			  u16 * next, u16 buffer_data_size)
{
  if (b->current_data + b->current_length <= buffer_data_size)
    return 0;

  b->current_length -= buffer_data_size - b->current_data;
  b->error = node->errors[ESP_ENCRYPT_ERROR_NO_TRAILER_SPACE];
  next[0] = ESP_ENCRYPT_NEXT_DROP;
  return 1;
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
  ipsec_main_t *im = &ipsec_main;
  ipsec_per_thread_data_t *ptd = vec_elt_at_index (im->ptd, vm->thread_index);
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_left = from_frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 thread_index = vm->thread_index;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);

  vlib_get_buffers (vm, from, b, n_left);
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->integ_ops);

  while (n_left > 0)
    {
      u32 sa_index0 = vnet_buffer (b[0])->ipsec.sad_index;
      ipsec_sa_t *sa0 = pool_elt_at_index (im->sad, sa_index0);
      u8 block_sz = sa0->crypto_block_size;
      u8 icv_sz = sa0->integ_trunc_size;
      dpo_id_t *dpo;
      esp_header_t *esp;
      u8 *payload, *next_hdr_ptr;
      u16 payload_len;
      u32 hdr_len;

      if (PREDICT_FALSE (esp_seq_advance (sa0)))
	{
	  b[0]->error = node->errors[ESP_ENCRYPT_ERROR_SEQ_CYCLED];
	  next[0] = ESP_ENCRYPT_NEXT_DROP;
	  goto next;
	}

      /* space for IV */
      hdr_len = sa0->crypto_iv_size;

      if (sa0->is_tunnel)
	{
	  payload = vlib_buffer_get_current (b[0]);
	  next_hdr_ptr = esp_add_footer_and_icv (b[0], block_sz, icv_sz);
	  payload_len = b[0]->current_length;

	  if (esp_trailer_icv_overflow (node, b[0], next, buffer_data_size))
	    goto next;

	  /* ESP header */
	  hdr_len += sizeof (*esp);
	  esp = (esp_header_t *) (payload - hdr_len);

	  /* optional UDP header */
	  if (sa0->udp_encap)
	    {
	      hdr_len += sizeof (udp_header_t);
	      esp_fill_udp_hdr (sa0, (udp_header_t *) (payload - hdr_len),
				payload_len + hdr_len);
	    }

	  /* IP header */
	  if (sa0->is_tunnel_ip6)
	    {
	      ip6_header_t *ip6;
	      u16 len = sizeof (ip6_header_t);
	      hdr_len += len;
	      ip6 = (ip6_header_t *) (payload - hdr_len);
	      clib_memcpy_fast (ip6, &sa0->ip6_hdr, len);
	      *next_hdr_ptr = IP_PROTOCOL_IPV6;
	      len = payload_len + hdr_len - len;
	      ip6->payload_length = clib_net_to_host_u16 (len);
	    }
	  else
	    {
	      ip4_header_t *ip4;
	      u16 len = sizeof (ip4_header_t);
	      hdr_len += len;
	      ip4 = (ip4_header_t *) (payload - hdr_len);
	      clib_memcpy_fast (ip4, &sa0->ip4_hdr, len);
	      *next_hdr_ptr = IP_PROTOCOL_IP_IN_IP;
	      len = payload_len + hdr_len;
	      esp_update_ip4_hdr (ip4, len, /* is_transport */ 0, 0);
	    }

	  dpo = sa0->dpo + IPSEC_PROTOCOL_ESP;
	  next[0] = dpo->dpoi_next_node;
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo->dpoi_index;
	}
      else			/* transport mode */
	{
	  u8 *l2_hdr, l2_len, *ip_hdr, ip_len;
	  udp_header_t *udp = 0;
	  u8 *old_ip_hdr = vlib_buffer_get_current (b[0]);

	  ip_len = is_ip6 ?
	    esp_get_ip6_hdr_len ((ip6_header_t *) old_ip_hdr) :
	    ip4_header_bytes ((ip4_header_t *) old_ip_hdr);

	  vlib_buffer_advance (b[0], ip_len);
	  payload = vlib_buffer_get_current (b[0]);
	  next_hdr_ptr = esp_add_footer_and_icv (b[0], block_sz, icv_sz);
	  payload_len = b[0]->current_length;

	  if (esp_trailer_icv_overflow (node, b[0], next, buffer_data_size))
	    goto next;

	  /* ESP header */
	  hdr_len += sizeof (*esp);
	  esp = (esp_header_t *) (payload - hdr_len);

	  /* optional UDP header */
	  if (sa0->udp_encap)
	    {
	      hdr_len += sizeof (udp_header_t);
	      udp = (udp_header_t *) (payload - hdr_len);
	    }

	  /* IP header */
	  hdr_len += ip_len;
	  ip_hdr = payload - hdr_len;

	  /* L2 header */
	  l2_len = vnet_buffer (b[0])->ip.save_rewrite_length;
	  hdr_len += l2_len;
	  l2_hdr = payload - hdr_len;

	  /* copy l2 and ip header */
	  clib_memcpy_fast (l2_hdr, old_ip_hdr - l2_len, l2_len);
	  clib_memcpy_fast (ip_hdr, old_ip_hdr, ip_len);

	  if (is_ip6)
	    {
	      ip6_header_t *ip6 = (ip6_header_t *) (ip_hdr);
	      *next_hdr_ptr = ip6->protocol;
	      ip6->protocol = IP_PROTOCOL_IPSEC_ESP;
	      ip6->payload_length = payload_len + hdr_len - l2_len - ip_len;
	    }
	  else
	    {
	      u16 len;
	      ip4_header_t *ip4 = (ip4_header_t *) (ip_hdr);
	      *next_hdr_ptr = ip4->protocol;
	      len = payload_len + hdr_len + l2_len;
	      if (udp)
		{
		  esp_update_ip4_hdr (ip4, len, /* is_transport */ 1, 1);
		  esp_fill_udp_hdr (sa0, udp, len - ip_len);
		}
	      else
		esp_update_ip4_hdr (ip4, len, /* is_transport */ 1, 0);
	    }

	  next[0] = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	}

      esp->spi = clib_net_to_host_u32 (sa0->spi);
      esp->seq = clib_net_to_host_u32 (sa0->seq);

      if (sa0->crypto_enc_op_type)
	{
	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
	  op->op = sa0->crypto_enc_op_type;
	  op->iv = payload - sa0->crypto_iv_size;
	  op->src = op->dst = payload;
	  op->key = sa0->crypto_key.data;
	  op->len = payload_len - icv_sz;
	  op->flags = VNET_CRYPTO_OP_FLAG_INIT_IV;
	  op->user_data = b - bufs;
	}

      if (sa0->integ_op_type)
	{
	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ptd->integ_ops, op, 1, CLIB_CACHE_LINE_BYTES);
	  op->op = sa0->integ_op_type;
	  op->src = payload - sa0->crypto_iv_size - sizeof (esp_header_t);
	  op->dst = payload + payload_len - icv_sz;
	  op->key = sa0->integ_key.data;
	  op->key_len = sa0->integ_key.len;
	  op->hmac_trunc_len = icv_sz;
	  op->len = payload_len - icv_sz + sa0->crypto_iv_size +
	    sizeof (esp_header_t);
	  op->user_data = b - bufs;
	}

      vlib_buffer_advance (b[0], 0 - hdr_len);

      vlib_increment_combined_counter
	(&ipsec_sa_counters, thread_index, sa_index0, 1,
	 b[0]->current_length);

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  esp_encrypt_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->sa_index = sa_index0;
	  tr->spi = sa0->spi;
	  tr->seq = sa0->seq - 1;
	  tr->udp_encap = sa0->udp_encap;
	  tr->crypto_alg = sa0->crypto_alg;
	  tr->integ_alg = sa0->integ_alg;
	}
      /* next */
    next:
      n_left -= 1;
      next += 1;
      b += 1;
    }

  if (vec_len (ptd->crypto_ops))
    vnet_crypto_process_ops (vm, ptd->crypto_ops, vec_len (ptd->crypto_ops));

  if (vec_len (ptd->integ_ops))
    vnet_crypto_process_ops (vm, ptd->integ_ops, vec_len (ptd->integ_ops));

  vlib_node_increment_counter (vm, node->node_index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);
  return n_left;
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
