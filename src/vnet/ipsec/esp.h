/*
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
#ifndef __ESP_H__
#define __ESP_H__

#include <vnet/ip/ip.h>
#include <vnet/crypto/crypto.h>
#include <vnet/ipsec/ipsec.h>

typedef struct
{
  union
  {
    u32 spi;
    u8 spi_bytes[4];
  };
  u32 seq;
  u8 data[0];
} esp_header_t;

typedef struct
{
  u8 pad_length;
  u8 next_header;
} esp_footer_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  esp_header_t esp;
}) ip4_and_esp_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  udp_header_t udp;
  esp_header_t esp;
}) ip4_and_udp_and_esp_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  esp_header_t esp;
}) ip6_and_esp_header_t;
/* *INDENT-ON* */

/**
 * AES GCM Additional Authentication data
 */
typedef struct esp_aead_t_
{
  /**
   * for GCM: when using ESN it's:
   *   SPI, seq-hi, seg-low
   * else
   *   SPI, seq-low
   */
  u32 data[3];
} __clib_packed esp_aead_t;

#define ESP_SEQ_MAX		(4294967295UL)
#define ESP_MAX_BLOCK_SIZE	(16)
#define ESP_MAX_IV_SIZE		(16)
#define ESP_MAX_ICV_SIZE	(32)

u8 *format_esp_header (u8 * s, va_list * args);

/* TODO seq increment should be atomic to be accessed by multiple workers */
always_inline int
esp_seq_advance (ipsec_sa_t * sa)
{
  if (PREDICT_TRUE (ipsec_sa_is_set_USE_ESN (sa)))
    {
      if (PREDICT_FALSE (sa->seq == ESP_SEQ_MAX))
	{
	  if (PREDICT_FALSE (ipsec_sa_is_set_USE_ANTI_REPLAY (sa) &&
			     sa->seq_hi == ESP_SEQ_MAX))
	    return 1;
	  sa->seq_hi++;
	}
      sa->seq++;
    }
  else
    {
      if (PREDICT_FALSE (ipsec_sa_is_set_USE_ANTI_REPLAY (sa) &&
			 sa->seq == ESP_SEQ_MAX))
	return 1;
      sa->seq++;
    }

  return 0;
}


always_inline unsigned int
hmac_calc (vlib_main_t * vm, ipsec_sa_t * sa, u8 * data, int data_len,
	   u8 * signature)
{
  vnet_crypto_op_t _op, *op = &_op;

  if (PREDICT_FALSE (sa->integ_op_id == 0))
    return 0;

  vnet_crypto_op_init (op, sa->integ_op_id);
  op->key_index = sa->integ_key_index;
  op->src = data;
  op->len = data_len;
  op->digest = signature;
  op->digest_len = sa->integ_icv_size;

  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      u32 seq_hi = clib_host_to_net_u32 (sa->seq_hi);

      op->len += 4;
      clib_memcpy (data + data_len, &seq_hi, 4);
    }

  vnet_crypto_process_ops (vm, op, 1);
  return sa->integ_icv_size;
}

always_inline void
esp_aad_fill (vnet_crypto_op_t * op,
	      const esp_header_t * esp, const ipsec_sa_t * sa)
{
  esp_aead_t *aad;

  aad = (esp_aead_t *) op->aad;
  aad->data[0] = esp->spi;

  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      /* SPI, seq-hi, seq-low */
      aad->data[1] = clib_host_to_net_u32 (sa->seq_hi);
      aad->data[2] = esp->seq;
      op->aad_len = 12;
    }
  else
    {
      /* SPI, seq-low */
      aad->data[1] = esp->seq;
      op->aad_len = 8;
    }
}

/**
 * Function prototype to get a vnet_crypto_op_t for both sync and async modes,
 * to avoid branch in esp_encrypt/decrypt_inline.
 **/
typedef vnet_crypto_op_t *(esp_get_crypto_op_t) (vlib_main_t * vm,
						 vnet_crypto_op_t ** ops_vec,
						 u32 op_id);

static_always_inline vnet_crypto_op_t *
esp_get_sync_op (vlib_main_t * vm, vnet_crypto_op_t ** ops_vec, u32 op_id)
{
  vnet_crypto_op_t *op;
  vec_add2_aligned (*ops_vec, op, 1, CLIB_CACHE_LINE_BYTES);
  vnet_crypto_op_init (op, op_id);
  return op;
}

static_always_inline vnet_crypto_op_t *
esp_get_async_op (vlib_main_t * vm, vnet_crypto_op_t ** ops_vec, u32 op_id)
{
  vnet_crypto_op_t *op = vnet_crypto_async_get_available_op (vm, op_id);
  return op;
}

typedef struct
{
  union
  {
    struct
    {
      u8 icv_sz;
      u8 iv_sz;
      ipsec_sa_flags_t flags;
      u32 sa_index;
    };
    u64 sa_data;
  };

  u32 seq;
  i16 current_data;
  i16 current_length;
  u16 hdr_sz;
} esp_decrypt_packet_data_t;

STATIC_ASSERT_SIZEOF (esp_decrypt_packet_data_t, 3 * sizeof (u64));

/**
 * The post data structure to for esp_encrypt/decrypt_inline to write to
 * vib_buffer_t opaque unused field, and for post nodes to pick up after
 * dequeue.
 **/
typedef union
{
  u16 next_index;
  esp_decrypt_packet_data_t decrypt_data;
} esp_post_data_t;

STATIC_ASSERT (sizeof (esp_post_data_t) <=
	       STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
	       "Custom meta-data too large for vnet_buffer_opaque_t");

#define esp_post_data(b) \
    ((esp_post_data_t *)((u8 *)((b)->opaque) \
        + STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

typedef enum
{
  ESP_PROCESS_SYNC_MODE = 0,
  ESP_PROCESS_ASYNC_MODE,
  ESP_PROCESS_N_MODES
} esp_process_mode_t;

typedef struct
{
  /* esp encrypt post node index for async crypto */
  u32 esp4_encrypt_post_index;
  u32 esp6_encrypt_post_index;
  u32 esp4_encrypt_tun_post_index;
  u32 esp6_encrypt_tun_post_index;
} esp_encrypt_async_index_t;

typedef struct
{
  /* esp decrypt post node index for async crypto */
  u32 esp4_decrypt_post_index[ESP_PROCESS_N_MODES];
  u32 esp6_decrypt_post_index[ESP_PROCESS_N_MODES];
  u32 esp4_decrypt_tun_post_index[ESP_PROCESS_N_MODES];
  u32 esp6_decrypt_tun_post_index[ESP_PROCESS_N_MODES];
} esp_decrypt_async_index_t;

extern esp_encrypt_async_index_t esp_encrypt_async_next;
extern esp_decrypt_async_index_t esp_decrypt_async_next;

#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
