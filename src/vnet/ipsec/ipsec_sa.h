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
#ifndef __IPSEC_SPD_SA_H__
#define __IPSEC_SPD_SA_H__

#include <vlib/vlib.h>
#include <vppinfra/pcg.h>
#include <vnet/crypto/crypto.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_node.h>
#include <vnet/tunnel/tunnel.h>

#define ESP_MAX_ICV_SIZE   (32)
#define ESP_MAX_IV_SIZE	   (16)
#define ESP_MAX_BLOCK_SIZE (16)

#define foreach_ipsec_crypto_alg                                              \
  _ (0, NONE, "none")                                                         \
  _ (1, AES_CBC_128, "aes-cbc-128")                                           \
  _ (2, AES_CBC_192, "aes-cbc-192")                                           \
  _ (3, AES_CBC_256, "aes-cbc-256")                                           \
  _ (4, AES_CTR_128, "aes-ctr-128")                                           \
  _ (5, AES_CTR_192, "aes-ctr-192")                                           \
  _ (6, AES_CTR_256, "aes-ctr-256")                                           \
  _ (7, AES_GCM_128, "aes-gcm-128")                                           \
  _ (8, AES_GCM_192, "aes-gcm-192")                                           \
  _ (9, AES_GCM_256, "aes-gcm-256")                                           \
  _ (10, DES_CBC, "des-cbc")                                                  \
  _ (11, 3DES_CBC, "3des-cbc")                                                \
  _ (12, CHACHA20_POLY1305, "chacha20-poly1305")                              \
  _ (13, AES_NULL_GMAC_128, "aes-null-gmac-128")                              \
  _ (14, AES_NULL_GMAC_192, "aes-null-gmac-192")                              \
  _ (15, AES_NULL_GMAC_256, "aes-null-gmac-256")

typedef enum
{
#define _(v, f, s) IPSEC_CRYPTO_ALG_##f = v,
  foreach_ipsec_crypto_alg
#undef _
    IPSEC_CRYPTO_N_ALG,
} __clib_packed ipsec_crypto_alg_t;

#define foreach_ipsec_integ_alg                                            \
  _ (0, NONE, "none")                                                      \
  _ (1, MD5_96, "md5-96")           /* RFC2403 */                          \
  _ (2, SHA1_96, "sha1-96")         /* RFC2404 */                          \
  _ (3, SHA_256_96, "sha-256-96")   /* draft-ietf-ipsec-ciph-sha-256-00 */ \
  _ (4, SHA_256_128, "sha-256-128") /* RFC4868 */                          \
  _ (5, SHA_384_192, "sha-384-192") /* RFC4868 */                          \
  _ (6, SHA_512_256, "sha-512-256")	/* RFC4868 */

typedef enum
{
#define _(v, f, s) IPSEC_INTEG_ALG_##f = v,
  foreach_ipsec_integ_alg
#undef _
    IPSEC_INTEG_N_ALG,
} __clib_packed ipsec_integ_alg_t;

typedef enum
{
  IPSEC_PROTOCOL_AH = 0,
  IPSEC_PROTOCOL_ESP = 1
} __clib_packed ipsec_protocol_t;

#define IPSEC_KEY_MAX_LEN 128
typedef struct ipsec_key_t_
{
  u8 len;
  u8 data[IPSEC_KEY_MAX_LEN];
} ipsec_key_t;

/*
 * Enable extended sequence numbers
 * Enable Anti-replay
 * IPsec tunnel mode if non-zero, else transport mode
 * IPsec tunnel mode is IPv6 if non-zero,
 * else IPv4 tunnel only valid if is_tunnel is non-zero
 * enable UDP encapsulation for NAT traversal
 */
#define foreach_ipsec_sa_flags                                                \
  _ (0, NONE, "none")                                                         \
  _ (1, USE_ESN, "esn")                                                       \
  _ (2, USE_ANTI_REPLAY, "anti-replay")                                       \
  _ (4, IS_TUNNEL, "tunnel")                                                  \
  _ (8, IS_TUNNEL_V6, "tunnel-v6")                                            \
  _ (16, UDP_ENCAP, "udp-encap")                                              \
  _ (32, IS_PROTECT, "Protect")                                               \
  _ (64, IS_INBOUND, "inbound")                                               \
  _ (512, IS_ASYNC, "async")                                                  \
  _ (1024, NO_ALGO_NO_DROP, "no-algo-no-drop")

typedef enum ipsec_sad_flags_t_
{
#define _(v, f, s) IPSEC_SA_FLAG_##f = v,
  foreach_ipsec_sa_flags
#undef _
} __clib_packed ipsec_sa_flags_t;

STATIC_ASSERT (sizeof (ipsec_sa_flags_t) == 2, "IPSEC SA flags != 2 byte");

#define foreach_ipsec_sa_err                                                  \
  _ (0, LOST, lost, "packets lost")                                           \
  _ (1, HANDOFF, handoff, "hand-off")                                         \
  _ (2, INTEG_ERROR, integ_error, "Integrity check failed")                   \
  _ (3, DECRYPTION_FAILED, decryption_failed, "Decryption failed")            \
  _ (4, CRYPTO_ENGINE_ERROR, crypto_engine_error,                             \
     "crypto engine error (dropped)")                                         \
  _ (5, REPLAY, replay, "SA replayed packet")                                 \
  _ (6, RUNT, runt, "undersized packet")                                      \
  _ (7, NO_BUFFERS, no_buffers, "no buffers (dropped)")                       \
  _ (8, OVERSIZED_HEADER, oversized_header,                                   \
     "buffer with oversized header (dropped)")                                \
  _ (9, NO_TAIL_SPACE, no_tail_space,                                         \
     "no enough buffer tail space (dropped)")                                 \
  _ (10, TUN_NO_PROTO, tun_no_proto, "no tunnel protocol")                    \
  _ (11, UNSUP_PAYLOAD, unsup_payload, "unsupported payload")                 \
  _ (12, SEQ_CYCLED, seq_cycled, "sequence number cycled (dropped)")          \
  _ (13, CRYPTO_QUEUE_FULL, crypto_queue_full, "crypto queue full (dropped)") \
  _ (14, NO_ENCRYPTION, no_encryption, "no Encrypting SA (dropped)")          \
  _ (15, DROP_FRAGMENTS, drop_fragments, "IP fragments drop")

typedef enum
{
#define _(v, f, s, d) IPSEC_SA_ERROR_##f = v,
  foreach_ipsec_sa_err
#undef _
    IPSEC_SA_N_ERRORS,
} __clib_packed ipsec_sa_err_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 is_aead : 1;
  u16 is_ctr : 1;
  u16 is_null_gmac : 1;
  u16 use_esn : 1;
  u16 use_anti_replay : 1;
  u16 is_protect : 1;
  u16 is_tunnel : 1;
  u16 is_transport : 1;
  u16 is_async : 1;
  u16 cipher_op_id;
  u16 integ_op_id;
  u8 cipher_iv_size;
  u8 integ_icv_size;
  u8 udp_sz;
  u16 thread_index;
  u32 salt;
  u64 seq64;
  u16 async_op_id;
  vnet_crypto_key_index_t cipher_key_index;
  vnet_crypto_key_index_t integ_key_index;
  u32 anti_replay_window_size;
  uword replay_window[];
} ipsec_sa_inb_rt_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 is_aead : 1;
  u16 is_ctr : 1;
  u16 is_null_gmac : 1;
  u16 is_tunnel : 1;
  u16 is_tunnel_v6 : 1;
  u16 udp_encap : 1;
  u16 use_esn : 1;
  u16 use_anti_replay : 1;
  u16 drop_no_crypto : 1;
  u16 is_async : 1;
  u16 cipher_op_id;
  u16 integ_op_id;
  u8 cipher_iv_size;
  u8 esp_block_align;
  u8 integ_icv_size;
  ip_dscp_t t_dscp;
  tunnel_encap_decap_flags_t tunnel_flags;
  u16 thread_index;
  u16 async_op_id;
  u32 salt;
  u32 spi_be;
  u64 seq64;
  dpo_id_t dpo;
  clib_pcg64i_random_t iv_prng;
  vnet_crypto_key_index_t cipher_key_index;
  vnet_crypto_key_index_t integ_key_index;
  union
  {
    ip4_header_t ip4_hdr;
    ip6_header_t ip6_hdr;
  };
  udp_header_t udp_hdr;
} ipsec_sa_outb_rt_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 spi;

  ipsec_sa_flags_t flags;

  u16 udp_src_port;
  u16 udp_dst_port;

  /* Salt used in CTR modes (incl. GCM) - stored in network byte order */
  u32 salt;

  ipsec_protocol_t protocol;

  /* Elements with u64 size multiples */
  tunnel_t tunnel;
  fib_node_t node;

  /* elements with u32 size */
  u32 id;
  u32 stat_index;
  vnet_crypto_alg_t integ_calg;
  vnet_crypto_alg_t crypto_calg;
  u32 crypto_sync_key_index;
  u32 integ_sync_key_index;
  u32 linked_key_index;

  /* elements with u16 size */
  u16 crypto_sync_enc_op_id;
  u16 crypto_sync_dec_op_id;
  u16 integ_sync_op_id;
  u16 crypto_async_enc_op_id;
  u16 crypto_async_dec_op_id;

  /* else u8 packed */
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;

  ipsec_key_t integ_key;
  ipsec_key_t crypto_key;
} ipsec_sa_t;

STATIC_ASSERT (VNET_CRYPTO_N_OP_IDS < (1 << 16), "crypto ops overflow");
STATIC_ASSERT (ESP_MAX_ICV_SIZE < (1 << 6), "integer icv overflow");
STATIC_ASSERT (ESP_MAX_IV_SIZE < (1 << 5), "esp iv overflow");
STATIC_ASSERT (ESP_MAX_BLOCK_SIZE < (1 << 5), "esp alignment overflow");

/*
 * Ensure that the IPsec data does not overlap with the IP data in
 * the buffer meta data
 */
STATIC_ASSERT (STRUCT_OFFSET_OF (vnet_buffer_opaque_t, ipsec.sad_index) ==
		 STRUCT_OFFSET_OF (vnet_buffer_opaque_t, ip.save_protocol),
	       "IPSec data is overlapping with IP data");

#define _(a, v, s)                                                            \
  always_inline bool ipsec_sa_is_set_##v (const ipsec_sa_t *sa)               \
  {                                                                           \
    return (sa->flags & IPSEC_SA_FLAG_##v);                                   \
  }
foreach_ipsec_sa_flags
#undef _
#define _(a, v, s)                                                            \
  always_inline void ipsec_sa_set_##v (ipsec_sa_t *sa)                        \
  {                                                                           \
    sa->flags |= IPSEC_SA_FLAG_##v;                                           \
  }
  foreach_ipsec_sa_flags
#undef _
#define _(a, v, s)                                                            \
  always_inline int ipsec_sa_unset_##v (ipsec_sa_t *sa)                       \
  {                                                                           \
    return (sa->flags &= ~IPSEC_SA_FLAG_##v);                                 \
  }
    foreach_ipsec_sa_flags
#undef _
  /**
   * @brief
   * SA packet & bytes counters
   */
  extern vlib_combined_counter_main_t ipsec_sa_counters;
extern vlib_simple_counter_main_t ipsec_sa_err_counters[IPSEC_SA_N_ERRORS];

extern void ipsec_mk_key (ipsec_key_t *key, const u8 *data, u8 len);

extern int ipsec_sa_update (u32 id, u16 src_port, u16 dst_port,
			    const tunnel_t *tun, bool is_tun);
extern void ipsec_sa_update_runtime (ipsec_sa_t *sa);
extern int ipsec_sa_add_and_lock (
  u32 id, u32 spi, ipsec_protocol_t proto, ipsec_crypto_alg_t crypto_alg,
  const ipsec_key_t *ck, ipsec_integ_alg_t integ_alg, const ipsec_key_t *ik,
  ipsec_sa_flags_t flags, u32 salt, u16 src_port, u16 dst_port,
  u32 anti_replay_window_size, const tunnel_t *tun, u32 *sa_out_index);
extern int ipsec_sa_bind (u32 id, u32 worker, bool bind);
extern index_t ipsec_sa_find_and_lock (u32 id);
extern int ipsec_sa_unlock_id (u32 id);
extern void ipsec_sa_unlock (index_t sai);
extern void ipsec_sa_lock (index_t sai);
extern void ipsec_sa_clear (index_t sai);
extern void ipsec_sa_set_crypto_alg (ipsec_sa_t *sa,
				     ipsec_crypto_alg_t crypto_alg);
extern void ipsec_sa_set_integ_alg (ipsec_sa_t *sa,
				    ipsec_integ_alg_t integ_alg);
extern void ipsec_sa_set_async_mode (ipsec_sa_t *sa, int is_enabled);

typedef walk_rc_t (*ipsec_sa_walk_cb_t) (ipsec_sa_t *sa, void *ctx);
extern void ipsec_sa_walk (ipsec_sa_walk_cb_t cd, void *ctx);

extern u8 *format_ipsec_replay_window (u8 *s, va_list *args);
extern u8 *format_ipsec_crypto_alg (u8 *s, va_list *args);
extern u8 *format_ipsec_integ_alg (u8 *s, va_list *args);
extern u8 *format_ipsec_sa (u8 *s, va_list *args);
extern u8 *format_ipsec_key (u8 *s, va_list *args);
extern uword unformat_ipsec_crypto_alg (unformat_input_t *input,
					va_list *args);
extern uword unformat_ipsec_integ_alg (unformat_input_t *input, va_list *args);
extern uword unformat_ipsec_key (unformat_input_t *input, va_list *args);

#define IPSEC_UDP_PORT_NONE ((u16) ~0)

always_inline u64
ipsec_sa_anti_replay_get_64b_window (const ipsec_sa_inb_rt_t *irt)
{
  u64 w;
  u32 window_size = irt->anti_replay_window_size;
  u32 tl_win_index = irt->seq64 & (window_size - 1);
  uword *bmp = (uword *) irt->replay_window;

  if (PREDICT_TRUE (tl_win_index >= 63))
    return uword_bitmap_get_multiple (bmp, tl_win_index - 63, 64);

  w = uword_bitmap_get_multiple_no_check (bmp, 0, tl_win_index + 1)
      << (63 - tl_win_index);
  w |= uword_bitmap_get_multiple_no_check (
    bmp, window_size - 63 + tl_win_index, 63 - tl_win_index);

  return w;
}

always_inline int
ipsec_sa_anti_replay_check (const ipsec_sa_inb_rt_t *irt, u32 window_size,
			    u32 seq)
{
  /* we assume that the packet is in the window.
   * if the packet falls left (sa->seq - seq >= window size),
   * the result is wrong */

  return uword_bitmap_is_bit_set ((uword *) irt->replay_window,
				  seq & (window_size - 1));
}

/*
 * Anti replay check.
 *  inputs need to be in host byte order.
 *
 * The function runs in two contexts. pre and post decrypt.
 * Pre-decrypt it:
 *  1 - determines if a packet is a replay - a simple check in the window
 *  2 - returns the hi-seq number that should be used to decrypt.
 * post-decrypt:
 *  Checks whether the packet is a replay or falls out of window
 *
 * This funcion should be called even without anti-replay enabled to ensure
 * the high sequence number is set.
 */
always_inline int
ipsec_sa_anti_replay_and_sn_advance (const ipsec_sa_inb_rt_t *irt, u32 seq,
				     u32 hi_seq_used, bool post_decrypt,
				     u32 *hi_seq_req)
{
  ASSERT ((post_decrypt == false) == (hi_seq_req != 0));

  u32 window_size = irt->anti_replay_window_size;
  u32 exp_lo = irt->seq64;
  u32 exp_hi = irt->seq64 >> 32;
  u32 window_lower_bound = exp_lo - window_size + 1;

  if (!irt->use_esn)
    {
      if (hi_seq_req)
	/* no ESN, therefore the hi-seq is always 0 */
	*hi_seq_req = 0;

      if (!irt->use_anti_replay)
	return 0;

      if (PREDICT_TRUE (seq > exp_lo))
	return 0;

      /* does the packet fall out on the left of the window */
      if (exp_lo >= seq + window_size)
	return 1;

      return ipsec_sa_anti_replay_check (irt, window_size, seq);
    }

  if (!irt->use_anti_replay)
    {
      /* there's no AR configured for this SA, but in order
       * to know whether a packet has wrapped the hi ESN we need
       * to know whether it is out of window. if we use the default
       * lower bound then we are effectively forcing AR because
       * out of window packets will get the increased hi seq number
       * and will thus fail to decrypt. IOW we need a window to know
       * if the SN has wrapped, but we don't want a window to check for
       * anti replay. to resolve the contradiction we use a huge window.
       * if the packet is not within 2^30 of the current SN, we'll consider
       * it a wrap.
       */
      if (hi_seq_req)
	{
	  if (seq >= exp_lo)
	    /* The packet's sequence number is larger that the SA's.
	     * that can't be a warp - unless we lost more than
	     * 2^32 packets ... how could we know? */
	    *hi_seq_req = exp_hi;
	  else
	    {
	      /* The packet's SN is less than the SAs, so either the SN has
	       * wrapped or the SN is just old. */
	      if (exp_lo - seq > (1 << 30))
		/* It's really really really old => it wrapped */
		*hi_seq_req = exp_hi + 1;
	      else
		*hi_seq_req = exp_hi;
	    }
	}
      /*
       * else
       *   this is post-decrpyt and since it decrypted we accept it
       */
      return 0;
    }

  if (PREDICT_TRUE (exp_lo >= window_size - 1))
    {
      /*
       * the last sequence number VPP received is more than one
       * window size greater than zero.
       * Case A from RFC4303 Appendix A.
       */
      if (seq < window_lower_bound)
	{
	  /*
	   * the received sequence number is lower than the lower bound
	   * of the window, this could mean either a replay packet or that
	   * the high sequence number has wrapped. if it decrypts corrently
	   * then it's the latter.
	   */
	  if (post_decrypt)
	    {
	      if (hi_seq_used == exp_hi)
		/* the high sequence number used to succesfully decrypt this
		 * packet is the same as the last-sequence number of the SA.
		 * that means this packet did not cause a wrap.
		 * this packet is thus out of window and should be dropped */
		return 1;
	      else
		/* The packet decrypted with a different high sequence number
		 * to the SA, that means it is the wrap packet and should be
		 * accepted */
		return 0;
	    }
	  else
	    {
	      /* pre-decrypt it might be the packet that causes a wrap, we
	       * need to decrypt it to find out */
	      if (hi_seq_req)
		*hi_seq_req = exp_hi + 1;
	      return 0;
	    }
	}
      else
	{
	  /*
	   * the received sequence number greater than the low
	   * end of the window.
	   */
	  if (hi_seq_req)
	    *hi_seq_req = exp_hi;
	  if (seq <= exp_lo)
	    /*
	     * The received seq number is within bounds of the window
	     * check if it's a duplicate
	     */
	    return ipsec_sa_anti_replay_check (irt, window_size, seq);
	  else
	    /*
	     * The received sequence number is greater than the window
	     * upper bound. this packet will move the window along, assuming
	     * it decrypts correctly.
	     */
	    return 0;
	}
    }
  else
    {
      /*
       * the last sequence number VPP received is within one window
       * size of zero, i.e. 0 < TL < WINDOW_SIZE, the lower bound is thus a
       * large sequence number.
       * Note that the check below uses unsigned integer arithmetic, so the
       * RHS will be a larger number.
       * Case B from RFC4303 Appendix A.
       */
      if (seq < window_lower_bound)
	{
	  /*
	   * the sequence number is less than the lower bound.
	   */
	  if (seq <= exp_lo)
	    {
	      /*
	       * the packet is within the window upper bound.
	       * check for duplicates.
	       */
	      if (hi_seq_req)
		*hi_seq_req = exp_hi;
	      return ipsec_sa_anti_replay_check (irt, window_size, seq);
	    }
	  else
	    {
	      /*
	       * the packet is less the window lower bound or greater than
	       * the higher bound, depending on how you look at it...
	       * We're assuming, given that the last sequence number received,
	       * TL < WINDOW_SIZE, that a larger seq num is more likely to be
	       * a packet that moves the window forward, than a packet that has
	       * wrapped the high sequence again. If it were the latter then
	       * we've lost close to 2^32 packets.
	       */
	      if (hi_seq_req)
		*hi_seq_req = exp_hi;
	      return 0;
	    }
	}
      else
	{
	  /*
	   * the packet seq number is between the lower bound (a large number)
	   * and MAX_SEQ_NUM. This is in the window since the window upper
	   * bound tl > 0. However, since TL is the other side of 0 to the
	   * received packet, the SA has moved on to a higher sequence number.
	   */
	  if (hi_seq_req)
	    *hi_seq_req = exp_hi - 1;
	  return ipsec_sa_anti_replay_check (irt, window_size, seq);
	}
    }

  /* unhandled case */
  ASSERT (0);
  return 0;
}

always_inline u32
ipsec_sa_anti_replay_window_shift (ipsec_sa_inb_rt_t *irt, u32 window_size,
				   u32 inc)
{
  uword *window = irt->replay_window;
  u32 window_mask = window_size - 1;
  u32 n_lost = 0;
  u32 seen = 0;

  if (inc < window_size)
    {
      /* the number of packets we saw in this section of the window */
      u32 window_lower_bound = (irt->seq64 + 1) & window_mask;
      u32 window_next_lower_bound = (window_lower_bound + inc) & window_mask;

      uword i_block, i_word_start, i_word_end, full_words;
      uword n_blocks = window_size >> log2_uword_bits;
      uword mask;

      i_block = window_lower_bound >> log2_uword_bits;

      i_word_start = window_lower_bound & (uword_bits - 1);
      i_word_end = window_next_lower_bound & (uword_bits - 1);

      /* We stay in the same word */
      if (i_word_start + inc <= uword_bits)
	{
	  mask = pow2_mask (inc) << i_word_start;
	  seen += count_set_bits (window[i_block] & mask);
	  window[i_block] &= ~mask;
	}
      else
	{
	  full_words =
	    (inc + i_word_start - uword_bits - i_word_end) >> log2_uword_bits;

	  /* count set bits in the first word */
	  mask = (uword) ~0 << i_word_start;
	  seen += count_set_bits (window[i_block] & mask);
	  window[i_block] &= ~mask;
	  i_block = (i_block + 1) & (n_blocks - 1);

	  /* count set bits in the next full words */
	  /* even if the last word need to be fully counted, we treat it
	   * apart */
	  while (full_words >= 8)
	    {
	      if (full_words >= 16)
		{
		  /* prefect the next 8 blocks (64 bytes) */
		  clib_prefetch_store (
		    &window[(i_block + 8) & (n_blocks - 1)]);
		}

	      seen += count_set_bits (window[i_block]);
	      seen += count_set_bits (window[(i_block + 1) & (n_blocks - 1)]);
	      seen += count_set_bits (window[(i_block + 2) & (n_blocks - 1)]);
	      seen += count_set_bits (window[(i_block + 3) & (n_blocks - 1)]);
	      seen += count_set_bits (window[(i_block + 4) & (n_blocks - 1)]);
	      seen += count_set_bits (window[(i_block + 5) & (n_blocks - 1)]);
	      seen += count_set_bits (window[(i_block + 6) & (n_blocks - 1)]);
	      seen += count_set_bits (window[(i_block + 7) & (n_blocks - 1)]);
	      window[i_block] = 0;
	      window[(i_block + 1) & (n_blocks - 1)] = 0;
	      window[(i_block + 2) & (n_blocks - 1)] = 0;
	      window[(i_block + 3) & (n_blocks - 1)] = 0;
	      window[(i_block + 4) & (n_blocks - 1)] = 0;
	      window[(i_block + 5) & (n_blocks - 1)] = 0;
	      window[(i_block + 6) & (n_blocks - 1)] = 0;
	      window[(i_block + 7) & (n_blocks - 1)] = 0;

	      i_block = (i_block + 8) & (n_blocks - 1);
	      full_words -= 8;
	    }
	  while (full_words > 0)
	    {
	      // last word is treated after the loop
	      seen += count_set_bits (window[i_block]);
	      window[i_block] = 0;
	      i_block = (i_block + 1) & (n_blocks - 1);
	      full_words--;
	    }

	  /* the last word */
	  mask = pow2_mask (i_word_end);
	  seen += count_set_bits (window[i_block] & mask);
	  window[i_block] &= ~mask;
	}

      uword_bitmap_set_bits_at_index (window, (irt->seq64 + inc) & window_mask,
				      1);

      /*
       * the number we missed is the size of the window section
       * minus the number we saw.
       */
      n_lost = inc - seen;
    }
  else
    {
      u32 n_uwords = window_size / uword_bits;
      /* holes in the replay window are lost packets */
      n_lost = window_size - uword_bitmap_count_set_bits (window, n_uwords);

      /* any sequence numbers that now fall outside the window
       * are forever lost */
      n_lost += inc - window_size;

      uword_bitmap_clear (window, n_uwords);
      uword_bitmap_set_bits_at_index (window, (irt->seq64 + inc) & window_mask,
				      1);
    }

  return n_lost;
}

/*
 * Anti replay window advance
 *  inputs need to be in host byte order.
 * This function both advances the anti-replay window and the sequence number
 * We always need to move on the SN but the window updates are only needed
 * if AR is on.
 * However, updating the window is trivial, so we do it anyway to save
 * the branch cost.
 */
always_inline u64
ipsec_sa_anti_replay_advance (ipsec_sa_inb_rt_t *irt, u32 thread_index,
			      u32 seq, u32 hi_seq)
{
  u64 n_lost = 0;
  u32 window_size = irt->anti_replay_window_size;
  u32 masked_seq = seq & (window_size - 1);
  u32 exp_lo = irt->seq64;
  u32 exp_hi = irt->seq64 >> 32;
  u32 pos;

  if (irt->use_esn)
    {
      int wrap = hi_seq - exp_hi;

      if (wrap == 0 && seq > exp_lo)
	{
	  pos = seq - exp_lo;
	  n_lost = ipsec_sa_anti_replay_window_shift (irt, window_size, pos);
	  irt->seq64 = (u64) exp_hi << 32 | seq;
	}
      else if (wrap > 0)
	{
	  pos = seq + ~exp_lo + 1;
	  n_lost = ipsec_sa_anti_replay_window_shift (irt, window_size, pos);
	  irt->seq64 = (u64) hi_seq << 32 | seq;
	}
      else
	uword_bitmap_set_bits_at_index (irt->replay_window, masked_seq, 1);
    }
  else
    {
      if (seq > exp_lo)
	{
	  pos = seq - exp_lo;
	  n_lost = ipsec_sa_anti_replay_window_shift (irt, window_size, pos);
	  irt->seq64 = (u64) exp_hi << 32 | seq;
	}
      else
	uword_bitmap_set_bits_at_index (irt->replay_window, masked_seq, 1);
    }

  return n_lost;
}


/*
 * Makes choice for thread_id should be assigned.
 *  if input ~0, gets random worker_id based on unix_time_now_nsec
*/
always_inline u16
ipsec_sa_assign_thread (u16 thread_id)
{
  return ((thread_id) ? thread_id
	  : (unix_time_now_nsec () % vlib_num_workers ()) + 1);
}

#endif /* __IPSEC_SPD_SA_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
