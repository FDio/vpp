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
  u32 spi;
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
  clib_memcpy_fast (aad, esp, 8);

  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      /* SPI, seq-hi, seq-low */
      aad->data[2] = aad->data[1];
      aad->data[1] = clib_host_to_net_u32 (sa->seq_hi);
      op->aad_len = 12;
    }
  else
    /* SPI, seq-low */
    op->aad_len = 8;
}
#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
