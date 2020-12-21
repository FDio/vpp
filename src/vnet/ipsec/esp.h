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

always_inline u16
esp_aad_fill (u8 * data, const esp_header_t * esp, const ipsec_sa_t * sa)
{
  esp_aead_t *aad;

  aad = (esp_aead_t *) data;
  aad->data[0] = esp->spi;

  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      /* SPI, seq-hi, seq-low */
      aad->data[1] = (u32) clib_host_to_net_u32 (sa->seq_hi);
      aad->data[2] = esp->seq;
      return 12;
    }
  else
    {
      /* SPI, seq-low */
      aad->data[1] = esp->seq;
      return 8;
    }
}

/* Special case to drop or hand off packets for sync/async modes.
 *
 * Different than sync mode, async mode only enqueue drop or hand-off packets
 * to next nodes.
 */
always_inline void
esp_set_next_index (int is_async, u32 * from, u16 * nexts, u32 bi,
		    u16 * drop_index, u16 drop_next, u16 * next)
{
  if (is_async)
    {
      from[*drop_index] = bi;
      nexts[*drop_index] = drop_next;
      *drop_index += 1;
    }
  else
    next[0] = drop_next;
}

/* when submitting a frame is failed, drop all buffers in the frame */
always_inline void
esp_async_recycle_failed_submit (vnet_crypto_async_frame_t * f,
				 vlib_buffer_t ** b, u32 * from, u16 * nexts,
				 u16 * n_dropped, u16 drop_next_index,
				 vlib_error_t err)
{
  u32 n_drop = f->n_elts;
  u32 *bi = f->buffer_indices;
  b -= n_drop;
  while (n_drop--)
    {
      b[0]->error = err;
      esp_set_next_index (1, from, nexts, bi[0], n_dropped, drop_next_index,
			  NULL);
      bi++;
      b++;
    }
  vnet_crypto_async_reset_frame (f);
}

/**
 * The post data structure to for esp_encrypt/decrypt_inline to write to
 * vib_buffer_t opaque unused field, and for post nodes to pick up after
 * dequeue.
 **/
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
  u16 is_chain;
  u32 protect_index;
} esp_decrypt_packet_data_t;

STATIC_ASSERT_SIZEOF (esp_decrypt_packet_data_t, 3 * sizeof (u64));

/* we are forced to store the decrypt post data into 2 separate places -
   vlib_opaque and opaque2. */
typedef struct
{
  vlib_buffer_t *lb;
  u32 free_buffer_index;
  u8 icv_removed;
} esp_decrypt_packet_data2_t;

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

STATIC_ASSERT (sizeof (esp_decrypt_packet_data2_t) <=
	       STRUCT_SIZE_OF (vnet_buffer_opaque2_t, unused),
	       "Custom meta-data too large for vnet_buffer_opaque2_t");

#define esp_post_data2(b) \
    ((esp_decrypt_packet_data2_t *)((u8 *)((b)->opaque2) \
        + STRUCT_OFFSET_OF (vnet_buffer_opaque2_t, unused)))

typedef struct
{
  /* esp post node index for async crypto */
  u32 esp4_post_next;
  u32 esp6_post_next;
  u32 esp4_tun_post_next;
  u32 esp6_tun_post_next;
  u32 esp_mpls_tun_post_next;
} esp_async_post_next_t;

extern esp_async_post_next_t esp_encrypt_async_next;
extern esp_async_post_next_t esp_decrypt_async_next;

#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
