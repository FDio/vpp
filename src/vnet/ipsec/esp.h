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
#include <vnet/ipsec/ipsec.api_enum.h>

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

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  esp_header_t esp;
}) ip4_and_esp_header_t;

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  udp_header_t udp;
  esp_header_t esp;
}) ip4_and_udp_and_esp_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  esp_header_t esp;
}) ip6_and_esp_header_t;

/**
 * AES counter mode nonce
 */
typedef struct
{
  u32 salt;
  u64 iv;
  u32 ctr; /* counter: 1 in big-endian for ctr, unused for gcm */
} __clib_packed esp_ctr_nonce_t;

STATIC_ASSERT_SIZEOF (esp_ctr_nonce_t, 16);

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

u8 *format_esp_header (u8 * s, va_list * args);

/* TODO seq increment should be atomic to be accessed by multiple workers */
always_inline int
esp_seq_advance (ipsec_sa_outb_rt_t *ort)
{
  u64 max = ort->use_esn ? CLIB_U64_MAX : CLIB_U32_MAX;
  if (ort->seq64 == max)
    return 1;
  ort->seq64++;
  return 0;
}

always_inline u16
esp_aad_fill (u8 *data, const esp_header_t *esp, int use_esn, u32 seq_hi)
{
  esp_aead_t *aad;

  aad = (esp_aead_t *) data;
  aad->data[0] = esp->spi;

  if (use_esn)
    {
      /* SPI, seq-hi, seq-low */
      aad->data[1] = (u32) clib_host_to_net_u32 (seq_hi);
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

always_inline u32
esp_encrypt_err_to_sa_err (u32 err)
{
  switch (err)
    {
    case ESP_ENCRYPT_ERROR_HANDOFF:
      return IPSEC_SA_ERROR_HANDOFF;
    case ESP_ENCRYPT_ERROR_SEQ_CYCLED:
      return IPSEC_SA_ERROR_SEQ_CYCLED;
    case ESP_ENCRYPT_ERROR_CRYPTO_ENGINE_ERROR:
      return IPSEC_SA_ERROR_CRYPTO_ENGINE_ERROR;
    case ESP_ENCRYPT_ERROR_CRYPTO_QUEUE_FULL:
      return IPSEC_SA_ERROR_CRYPTO_QUEUE_FULL;
    case ESP_ENCRYPT_ERROR_NO_BUFFERS:
      return IPSEC_SA_ERROR_NO_BUFFERS;
    case ESP_ENCRYPT_ERROR_NO_ENCRYPTION:
      return IPSEC_SA_ERROR_NO_ENCRYPTION;
    }
  return ~0;
}

always_inline u32
esp_decrypt_err_to_sa_err (u32 err)
{
  switch (err)
    {
    case ESP_DECRYPT_ERROR_HANDOFF:
      return IPSEC_SA_ERROR_HANDOFF;
    case ESP_DECRYPT_ERROR_DECRYPTION_FAILED:
      return IPSEC_SA_ERROR_DECRYPTION_FAILED;
    case ESP_DECRYPT_ERROR_INTEG_ERROR:
      return IPSEC_SA_ERROR_INTEG_ERROR;
    case ESP_DECRYPT_ERROR_CRYPTO_ENGINE_ERROR:
      return IPSEC_SA_ERROR_CRYPTO_ENGINE_ERROR;
    case ESP_DECRYPT_ERROR_REPLAY:
      return IPSEC_SA_ERROR_REPLAY;
    case ESP_DECRYPT_ERROR_RUNT:
      return IPSEC_SA_ERROR_RUNT;
    case ESP_DECRYPT_ERROR_NO_BUFFERS:
      return IPSEC_SA_ERROR_NO_BUFFERS;
    case ESP_DECRYPT_ERROR_OVERSIZED_HEADER:
      return IPSEC_SA_ERROR_OVERSIZED_HEADER;
    case ESP_DECRYPT_ERROR_NO_TAIL_SPACE:
      return IPSEC_SA_ERROR_NO_TAIL_SPACE;
    case ESP_DECRYPT_ERROR_TUN_NO_PROTO:
      return IPSEC_SA_ERROR_TUN_NO_PROTO;
    case ESP_DECRYPT_ERROR_UNSUP_PAYLOAD:
      return IPSEC_SA_ERROR_UNSUP_PAYLOAD;
    }
  return ~0;
}

always_inline void
esp_encrypt_set_next_index (vlib_buffer_t *b, vlib_node_runtime_t *node,
			    clib_thread_index_t thread_index, u32 err,
			    u16 index, u16 *nexts, u16 drop_next, u32 sa_index)
{
  ipsec_set_next_index (b, node, thread_index, err,
			esp_encrypt_err_to_sa_err (err), index, nexts,
			drop_next, sa_index);
}

always_inline void
esp_decrypt_set_next_index (vlib_buffer_t *b, vlib_node_runtime_t *node,
			    clib_thread_index_t thread_index, u32 err,
			    u16 index, u16 *nexts, u16 drop_next, u32 sa_index)
{
  ipsec_set_next_index (b, node, thread_index, err,
			esp_decrypt_err_to_sa_err (err), index, nexts,
			drop_next, sa_index);
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
      u8 udp_sz;
      u8 is_transport;
      u32 sa_index;
    };
    u64 sa_data;
  };

  u32 seq;
  i16 current_data;
  i16 current_length;
  u16 hdr_sz;
  u16 is_chain;
  u32 seq_hi;
} esp_decrypt_packet_data_t;

STATIC_ASSERT_SIZEOF (esp_decrypt_packet_data_t, 3 * sizeof (u64));
STATIC_ASSERT_OFFSET_OF (esp_decrypt_packet_data_t, seq, sizeof (u64));

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

/* when submitting a frame is failed, drop all buffers in the frame */
always_inline u32
esp_async_recycle_failed_submit (vlib_main_t *vm, vnet_crypto_async_frame_t *f,
				 vlib_node_runtime_t *node, u32 err,
				 u32 ipsec_sa_err, u16 index, u32 *from,
				 u16 *nexts, u16 drop_next_index,
				 bool is_encrypt)
{
  vlib_buffer_t *b;
  u32 n_drop = f->n_elts;
  u32 *bi = f->buffer_indices;

  while (n_drop--)
    {
      u32 sa_index;

      from[index] = bi[0];
      b = vlib_get_buffer (vm, bi[0]);

      if (is_encrypt)
	{
	  sa_index = vnet_buffer (b)->ipsec.sad_index;
	}
      else
	{
	  sa_index = esp_post_data (b)->decrypt_data.sa_index;
	}

      ipsec_set_next_index (b, node, vm->thread_index, err, ipsec_sa_err,
			    index, nexts, drop_next_index, sa_index);
      bi++;
      index++;
    }

  return (f->n_elts);
}

#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
