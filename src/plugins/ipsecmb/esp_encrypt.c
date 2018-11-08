/*
 * esp_encrypt.c : ipsecmb ESP encrypt node
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

#include <ipsecmb/ipsecmb.h>

#define foreach_esp_encrypt_next \
  _ (DROP, "error-drop")         \
  _ (IP4_LOOKUP, "ip4-lookup")   \
  _ (IP6_LOOKUP, "ip6-lookup")   \
  _ (INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_encrypt_next
#undef _
    ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                \
  _ (RX_PKTS, "ESP pkts received")               \
  _ (NO_BUFFER, "No buffer (packet dropped)")    \
  _ (DECRYPTION_FAILED, "ESP encryption failed") \
  _ (SEQ_CYCLED, "sequence number cycled")

typedef enum
{
#define _(sym, str) ESP_ENCRYPT_ERROR_##sym,
  foreach_esp_encrypt_error
#undef _
    ESP_ENCRYPT_N_ERROR,
} esp_encrypt_error_t;

typedef struct
{
  u32 spi;
  u32 seq;
  u8 udp_encap;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

#ifdef CLIB_MARCH_VARIANT
static inline void
add_random_bytes_from_traffic (ipsecmb_main_t * imbm,
			       u32 thread_index, void *from, u8 size)
{
  ASSERT (STRUCT_SIZE_OF (random_bytes_t, data) == size);
  u32 idx;
  random_bytes_t *rb;
  ipsecmb_per_thread_data_t *t = &imbm->per_thread_data[thread_index];;
  if (PREDICT_TRUE (vec_len (t->rb_recycle_list)))
    {
      idx = vec_pop (t->rb_recycle_list);
      rb = pool_elt_at_index (t->rb_pool, idx);
    }
  else
    {
      pool_get (t->rb_pool, rb);
      idx = rb - t->rb_pool;
    }
  clib_memcpy (rb->data, from, STRUCT_SIZE_OF (random_bytes_t, data));
  vec_add1 (t->rb_from_traffic, idx);
}

static inline int
random_bytes (ipsecmb_main_t * imbm, u32 thread_index, u8 * where, u8 size)
{
  ASSERT (STRUCT_SIZE_OF (random_bytes_t, data) == size);
  const u8 block_size = STRUCT_SIZE_OF (random_bytes_t, data);
  ipsecmb_per_thread_data_t *t = &imbm->per_thread_data[thread_index];;
  if (PREDICT_TRUE (vec_len (t->rb_from_traffic)))
    {
      u32 idx = vec_pop (t->rb_from_traffic);
      random_bytes_t *rb = pool_elt_at_index (t->rb_pool, idx);
      clib_memcpy (where, rb->data, block_size);
      vec_add1 (t->rb_recycle_list, idx);
      return 0;
    }
  if (PREDICT_FALSE (0 == vec_len (t->rb_from_dev_urandom)))
    {
      ssize_t bytes_read = read (imbm->dev_urandom_fd, t->urandom_buffer,
				 sizeof (t->urandom_buffer));
      if (bytes_read < 0)
	{
	  clib_unix_warning ("read() from /dev/urandom failed");
	  return -1;
	}
      if (bytes_read < block_size)
	{
	  clib_unix_warning
	    ("read() from /dev/urandom produced only %zd bytes", bytes_read);
	  return -1;
	}
      const ssize_t limit = clib_min (bytes_read, sizeof (t->urandom_buffer));
      int i;
      for (i = 0; limit - i >= block_size && vec_len (t->rb_recycle_list) > 0;
	   i += block_size)
	{
	  u32 idx = vec_pop (t->rb_recycle_list);
	  random_bytes_t *rb = pool_elt_at_index (t->rb_pool, idx);
	  clib_memcpy (rb->data, t->urandom_buffer + i, block_size);
	  vec_add1 (t->rb_from_dev_urandom, idx);
	}
      for (; limit - i >= block_size; i += block_size)
	{
	  random_bytes_t *rb;
	  pool_get (t->rb_pool, rb);
	  clib_memcpy (rb->data, t->urandom_buffer + i, block_size);
	  vec_add1 (t->rb_from_dev_urandom, rb - t->rb_pool);
	}
    }
  u32 idx = vec_pop (t->rb_from_dev_urandom);
  random_bytes_t *rb = pool_elt_at_index (t->rb_pool, idx);
  clib_memcpy (where, rb->data, block_size);
  vec_add1 (t->rb_recycle_list, idx);
  return 0;
}

static inline void
esp_finish_encrypt (vlib_main_t * vm, JOB_AES_HMAC * job,
		    ipsecmb_main_t * imbm, int thread_index,
		    u32 * bi0, u32 * next0, ipsec_sa_t ** sa0, int is_ip6)
{
  ip4_header_t *oh4 = 0;
  udp_header_t *udp = 0;
  ip6_header_t *oh6 = 0;
  ipsec_main_t *im = &ipsec_main;
  *bi0 = (uintptr_t) job->user_data;
  vlib_buffer_t *b0 = vlib_get_buffer (vm, *bi0);
  u32 sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
  *sa0 = pool_elt_at_index (im->sad, sa_index0);
  oh4 = vlib_buffer_get_current (b0);
  oh6 = vlib_buffer_get_current (b0);
  if (is_ip6)
    {
      oh6->payload_length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      sizeof (ip6_header_t));
    }
  else
    {
      oh4->length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
      oh4->checksum = ip4_header_checksum (oh4);
      if ((*sa0)->udp_encap)
	{
	  udp = (udp_header_t *) (oh4 + 1);
	  udp->length =
	    clib_host_to_net_u16 (clib_net_to_host_u16 (oh4->length) -
				  ip4_header_bytes (oh4));
	}
    }

  *next0 = (uintptr_t) job->user_data2;
  const int iv_size = imbm->crypto_algs[(*sa0)->crypto_alg].iv_size;
  add_random_bytes_from_traffic (imbm, thread_index,
				 vlib_buffer_get_current (b0) +
				 b0->current_length - iv_size, iv_size);
  if (!(*sa0)->is_tunnel)
    {
      *next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
      vlib_buffer_advance (b0, -sizeof (ethernet_header_t));
    }
}

always_inline void
ipsemb_ip4_fill_comon_values (ip4_header_t * oh4, u8 tos)
{
  oh4->ip_version_and_header_length = 0x45;
  oh4->tos = tos;
  oh4->fragment_id = 0;
  oh4->flags_and_fragment_offset = 0;
  oh4->ttl = 254;
}

always_inline void
ipsemb_handle_udp_encap (ipsec_sa_t * sa0, esp_header_t ** esp,
			 ip4_header_t ** oh4)
{
  if (sa0->udp_encap)
    {
      *esp = (esp_header_t *) ((u8 *) esp + sizeof (udp_header_t));
      udp_header_t *udp = (udp_header_t *) ((*oh4) + 1);
      udp->src_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_ipsec);
      udp->checksum = 0;
      (*oh4)->protocol = IP_PROTOCOL_UDP;
    }
  else
    {
      (*oh4)->protocol = IP_PROTOCOL_IPSEC_ESP;
    }
}

always_inline void
esp_prepare_tunneL_headers (vlib_buffer_t * b0, ipsec_sa_t * sa0, u32 * next0,
			    u8 * next_hdr_type, ip4_header_t * ih4,
			    ip4_header_t ** oh4, ip6_header_t * ih6,
			    ip6_header_t ** oh6, esp_header_t ** esp,
			    u32 iv_size, int is_ip6)
{
  if (is_ip6)
    {
      *next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
      *next_hdr_type = IP_PROTOCOL_IPV6;
      *oh6 = (ip6_header_t *) ((u8 *) ih6 - sizeof (esp_header_t) -
			       sizeof (ip6_header_t) - iv_size);
      (*oh6)->src_address.as_u64[0] = sa0->tunnel_src_addr.ip6.as_u64[0];
      (*oh6)->src_address.as_u64[1] = sa0->tunnel_src_addr.ip6.as_u64[1];
      (*oh6)->dst_address.as_u64[0] = sa0->tunnel_dst_addr.ip6.as_u64[0];
      (*oh6)->dst_address.as_u64[1] = sa0->tunnel_dst_addr.ip6.as_u64[1];

      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
      vlib_buffer_advance (b0, -(sizeof (esp_header_t) +
				 sizeof (ip6_header_t) + iv_size));
      (*oh6)->ip_version_traffic_class_and_flow_label =
	ih6->ip_version_traffic_class_and_flow_label;
      (*oh6)->protocol = IP_PROTOCOL_IPSEC_ESP;
      (*oh6)->hop_limit = 254;
      *esp = (esp_header_t *) ((*oh6) + 1);
    }
  else
    {				/* is ipv4 */
      *next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
      u32 udp_hdr_size = 0;
      if (sa0->udp_encap)
	{
	  udp_hdr_size = sizeof (udp_header_t);
	}
      *next_hdr_type = IP_PROTOCOL_IP_IN_IP;
      (*oh4) =
	(ip4_header_t *) (((u8 *) ih4) - sizeof (ip4_header_t) -
			  sizeof (esp_header_t) - udp_hdr_size - iv_size);
      (*oh4)->src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
      (*oh4)->dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;
      vlib_buffer_advance (b0, -(sizeof (ip4_header_t) +
				 sizeof (esp_header_t) +
				 udp_hdr_size + iv_size));
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
      *esp = (esp_header_t *) ((*oh4) + 1);

      ipsemb_ip4_fill_comon_values (*oh4, ih4->tos);
      ipsemb_handle_udp_encap (sa0, esp, oh4);
    }
}

always_inline void
esp_prepare_transport_headers (vlib_buffer_t * b0, ipsec_sa_t * sa0,
			       u32 * next0, u8 * next_hdr_type,
			       ip4_header_t * ih4, ip4_header_t ** oh4,
			       ip6_header_t * ih6, ip6_header_t ** oh6,
			       esp_header_t ** esp, u32 iv_size, int is_ip6)
{
  if (is_ip6)
    {
      *next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
      *next_hdr_type = ih6->protocol;
      (*oh6) = (ip6_header_t *) ((u8 *) ih6 - sizeof (esp_header_t) -
				 iv_size);
      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
	{
	  ethernet_header_t *ieh0, *oeh0;
	  ieh0 = (ethernet_header_t *) vlib_buffer_get_current (b0) - 1;
	  oeh0 = (ethernet_header_t *) (*oh6) - 1;
	  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	}
      (*oh6)->src_address.as_u64[0] = ih6->src_address.as_u64[0];
      (*oh6)->src_address.as_u64[1] = ih6->src_address.as_u64[1];
      (*oh6)->dst_address.as_u64[0] = ih6->dst_address.as_u64[0];
      (*oh6)->dst_address.as_u64[1] = ih6->dst_address.as_u64[1];
      vlib_buffer_advance (b0, -(sizeof (esp_header_t) + iv_size));
      (*oh6)->ip_version_traffic_class_and_flow_label =
	ih6->ip_version_traffic_class_and_flow_label;
      (*oh6)->protocol = IP_PROTOCOL_IPSEC_ESP;
      (*oh6)->hop_limit = 254;
      *esp = (esp_header_t *) ((*oh6) + 1);
    }
  else
    {				/* is ipv4 */
      *next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
      u32 udp_hdr_size = 0;
      if (sa0->udp_encap)
	{
	  udp_hdr_size = sizeof (udp_header_t);
	}
      *next_hdr_type = ih4->protocol;
      (*oh4) = (ip4_header_t *) (((u8 *) ih4) - sizeof (esp_header_t) -
				 udp_hdr_size - iv_size);
      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
	{
	  ethernet_header_t *ieh0, *oeh0;
	  ieh0 = (ethernet_header_t *) vlib_buffer_get_current (b0) - 1;
	  oeh0 = (ethernet_header_t *) (*oh4) - 1;
	  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	}
      (*oh4)->src_address.as_u32 = ih4->src_address.as_u32;
      (*oh4)->dst_address.as_u32 = ih4->dst_address.as_u32;
      vlib_buffer_advance (b0,
			   -(sizeof (esp_header_t) + udp_hdr_size + iv_size));
      *esp = (esp_header_t *) ((*oh4) + 1);

      ipsemb_ip4_fill_comon_values (*oh4, ih4->tos);
      ipsemb_handle_udp_encap (sa0, esp, oh4);
    }
}

static uword
esp_encrypt_ipsecmb_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * from_frame, int is_ip6)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsecmb_main_t *imbm = &ipsecmb_main;
  ipsec_main_t *im = &ipsec_main;
  u32 packets_in_flight = 0;
  next_index = node->cached_next_index;
  u32 thread_index = vlib_get_thread_index ();
  ipsec_alloc_empty_buffers (vm, im);
  u32 *to_be_freed = NULL;
  ipsecmb_per_thread_data_t *t = &imbm->per_thread_data[thread_index];;

  MB_MGR *mgr = imbm->mb_mgr[thread_index];

  while (n_left_from > 0 || packets_in_flight > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0 = 0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ipsecmb_sa_t *samb0;
	  ip4_header_t *ih4, *oh4 = 0;
	  ip6_header_t *ih6, *oh6 = 0;
	  esp_header_t *esp;
	  u8 next_hdr_type;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  next0 = ESP_ENCRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);
	  samb0 = pool_elt_at_index (imbm->sad, sa_index0);

	  if (esp_seq_advance (sa0))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, node->node_index,
					   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      // TODO: rekey SA
	      to_next[0] = bi0;
	      to_next += 1;
	      goto trace;
	    }

	  sa0->total_data_size += b0->current_length;

	  if (PREDICT_FALSE (b0->n_add_refs > 0))
	    {
	      vec_add1 (to_be_freed, bi0);
	      b0 = vlib_buffer_copy (vm, b0);
	      bi0 = vlib_get_buffer_index (vm, b0);
	    }

	  ih4 = vlib_buffer_get_current (b0);
	  ih6 = vlib_buffer_get_current (b0);

	  const int iv_size = imbm->crypto_algs[sa0->crypto_alg].iv_size;
	  if (sa0->is_tunnel)
	    esp_prepare_tunneL_headers (b0, sa0, &next0, &next_hdr_type, ih4,
					&oh4, ih6, &oh6, &esp, iv_size,
					is_ip6);
	  else
	    esp_prepare_transport_headers (b0, sa0, &next0, &next_hdr_type,
					   ih4, &oh4, ih6, &oh6, &esp,
					   iv_size, is_ip6);


	  esp->spi = clib_net_to_host_u32 (sa0->spi);
	  esp->seq = clib_net_to_host_u32 (sa0->seq);
	  ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

	  esp_footer_t *f0;
	  const u32 payload_offset =
	    (u8 *) (esp + 1) + iv_size - (u8 *) vlib_buffer_get_current (b0);
	  JOB_AES_HMAC *job = IPSECMB_FUNC (get_next_job) (mgr);
	  if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	    {
	      const int block_size =
		imbm->crypto_algs[sa0->crypto_alg].block_size;
	      u32 payload_length = b0->current_length - payload_offset;
	      int blocks = 1 + (payload_length + 1) / block_size;

	      /* pad packet in input buffer */
	      u8 pad_bytes =
		block_size * blocks - sizeof (esp_footer_t) - payload_length;
	      u8 i;
	      u8 *padding = vlib_buffer_get_current (b0) + b0->current_length;
	      b0->current_length = payload_offset + block_size * blocks;
	      for (i = 0; i < pad_bytes; ++i)
		{
		  padding[i] = i + 1;
		}
	      f0 = vlib_buffer_get_current (b0) + b0->current_length -
		sizeof (esp_footer_t);
	      f0->pad_length = pad_bytes;
	      f0->next_header = next_hdr_type;

	      random_bytes (imbm, thread_index, (u8 *) (esp + 1), iv_size);
	      job->iv = (u8 *) (esp + 1);
	      job->iv_len_in_bytes = iv_size;
	    }

	  job->chain_order = CIPHER_HASH;
	  job->cipher_direction = ENCRYPT;
	  job->src = (u8 *) esp;
	  job->dst = (u8 *) ((u8 *) (esp + 1) + iv_size);
	  job->cipher_mode = imbm->crypto_algs[sa0->crypto_alg].cipher_mode;
	  job->aes_enc_key_expanded = samb0->aes_enc_key_expanded;
	  job->aes_dec_key_expanded = samb0->aes_dec_key_expanded;
	  job->aes_key_len_in_bytes = sa0->crypto_key_len;
	  job->cipher_start_src_offset_in_bytes =
	    sizeof (esp_header_t) + iv_size;
	  job->hash_start_src_offset_in_bytes = 0;
	  job->msg_len_to_cipher_in_bytes =
	    b0->current_length - payload_offset;
	  if (PREDICT_TRUE (IPSEC_INTEG_ALG_NONE != sa0->integ_alg))
	    {
	      if (sa0->use_esn)
		{
		  *(u32 *) (vlib_buffer_get_current (b0) +
			    b0->current_length) = sa0->seq_hi;
		  b0->current_length += sizeof (u32);
		}
	      job->msg_len_to_hash_in_bytes = b0->current_length -
		payload_offset + sizeof (esp_header_t) + iv_size;
	      job->u.HMAC._hashed_auth_key_xor_ipad = samb0->ipad_hash;
	      job->u.HMAC._hashed_auth_key_xor_opad = samb0->opad_hash;
	      job->auth_tag_output =
		vlib_buffer_get_current (b0) + b0->current_length;
	      job->auth_tag_output_len_in_bytes =
		imbm->integ_algs[sa0->integ_alg].hash_output_length;
	      b0->current_length +=
		imbm->integ_algs[sa0->integ_alg].hash_output_length;
	    }
	  job->hash_alg = imbm->integ_algs[sa0->integ_alg].hash_alg;
	  job->user_data = (void *) (uintptr_t) bi0;
	  job->user_data2 = (void *) (uintptr_t) next0;
	  job = IPSECMB_FUNC (submit_job) (mgr);
	  ++packets_in_flight;

	  if (!job)
	    {
	      continue;
	    }

	  --packets_in_flight;
	  esp_finish_encrypt (vm, job, imbm, thread_index, &bi0, &next0, &sa0,
			      is_ip6);

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->udp_encap = sa0->udp_encap;
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      if (PREDICT_FALSE (n_left_from == 0))
	{
	  JOB_AES_HMAC *job = NULL;
	  while (n_left_to_next > 0 && (job = IPSECMB_FUNC (flush_job) (mgr)))
	    {
	      --packets_in_flight;
	      u32 bi0, next0;
	      vlib_buffer_t *b0;
	      ipsec_sa_t *sa0;

	      esp_finish_encrypt (vm, job, imbm, thread_index, &bi0, &next0,
				  &sa0, is_ip6);
	      b0 = vlib_get_buffer (vm, bi0);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  esp_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->spi = sa0->spi;
		  tr->seq = sa0->seq - 1;
		  tr->udp_encap = sa0->udp_encap;
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
		}

	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  if (to_be_freed)
    vlib_buffer_free (vm, to_be_freed, vec_len (to_be_freed));
  vec_free (to_be_freed);
  if (PREDICT_TRUE (vec_len (t->rb_from_traffic) > 0))
    {
      /* recycle traffic generated buffers, because once the packets are sent
       * out, bytes from these packets are no longer unpredictable */
      vec_add (t->rb_recycle_list, t->rb_from_traffic,
	       vec_len (t->rb_from_traffic));
      _vec_len (t->rb_from_traffic) = 0;
    }
  return from_frame->n_vectors;
}

VLIB_NODE_FN (esp4_encrypt_ipsecmb_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * from_frame)
{
  return esp_encrypt_ipsecmb_inline (vm, node, from_frame, 0 /*is_ip6 */ );
}

VLIB_NODE_FN (esp6_encrypt_ipsecmb_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * from_frame)
{
  return esp_encrypt_ipsecmb_inline (vm, node, from_frame, 1 /*is_ip6 */ );
}
#endif

static char *esp_encrypt_error_strings[] = {
#define _(sym, string) string,
  foreach_esp_encrypt_error
#undef _
};

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);

  s =
    format (s, "esp: spi %u seq %u crypto %U integrity %U%s", t->spi, t->seq,
	    format_ipsec_crypto_alg, t->crypto_alg, format_ipsec_integ_alg,
	    t->integ_alg, t->udp_encap ? " udp-encap-enabled" : "");
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_ipsecmb_node) = {
    .name = "esp4-encrypt-ipsecmb",
    .vector_size = sizeof (u32),
    .format_trace = format_esp_encrypt_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN (esp_encrypt_error_strings),
    .error_strings = esp_encrypt_error_strings,

    .n_next_nodes = ESP_ENCRYPT_N_NEXT,
    .next_nodes =
        {
#define _(s, n) [ESP_ENCRYPT_NEXT_##s] = n,
            foreach_esp_encrypt_next
#undef _
        },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp6_encrypt_ipsecmb_node) = {
    .name = "esp6-encrypt-ipsecmb",
    .vector_size = sizeof (u32),
    .format_trace = format_esp_encrypt_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN (esp_encrypt_error_strings),
    .error_strings = esp_encrypt_error_strings,

    .n_next_nodes = ESP_ENCRYPT_N_NEXT,
    .next_nodes =
        {
#define _(s, n) [ESP_ENCRYPT_NEXT_##s] = n,
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
