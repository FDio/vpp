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
#include <vnet/crypto/crypto.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_node.h>
#include <vnet/tunnel/tunnel.h>

#define foreach_ipsec_crypto_alg    \
  _ (0, NONE, "none")               \
  _ (1, AES_CBC_128, "aes-cbc-128") \
  _ (2, AES_CBC_192, "aes-cbc-192") \
  _ (3, AES_CBC_256, "aes-cbc-256") \
  _ (4, AES_CTR_128, "aes-ctr-128") \
  _ (5, AES_CTR_192, "aes-ctr-192") \
  _ (6, AES_CTR_256, "aes-ctr-256") \
  _ (7, AES_GCM_128, "aes-gcm-128") \
  _ (8, AES_GCM_192, "aes-gcm-192") \
  _ (9, AES_GCM_256, "aes-gcm-256") \
  _ (10, DES_CBC, "des-cbc")        \
  _ (11, 3DES_CBC, "3des-cbc")

typedef enum
{
#define _(v, f, s) IPSEC_CRYPTO_ALG_##f = v,
  foreach_ipsec_crypto_alg
#undef _
    IPSEC_CRYPTO_N_ALG,
} __clib_packed ipsec_crypto_alg_t;

#define IPSEC_CRYPTO_ALG_IS_GCM(_alg)                     \
  (((_alg == IPSEC_CRYPTO_ALG_AES_GCM_128) ||             \
    (_alg == IPSEC_CRYPTO_ALG_AES_GCM_192) ||             \
    (_alg == IPSEC_CRYPTO_ALG_AES_GCM_256)))

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
  IPSEC_PROTOCOL_ESP = 50,
  IPSEC_PROTOCOL_AH = 51
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
#define foreach_ipsec_sa_flags                            \
  _ (0, NONE, "none")                                     \
  _ (1, USE_ESN, "esn")                                   \
  _ (2, USE_ANTI_REPLAY, "anti-replay")                   \
  _ (4, IS_TUNNEL, "tunnel")                              \
  _ (8, IS_TUNNEL_V6, "tunnel-v6")                        \
  _ (16, UDP_ENCAP, "udp-encap")                          \
  _ (32, IS_PROTECT, "Protect")                           \
  _ (64, IS_INBOUND, "inbound")                           \
  _ (128, IS_AEAD, "aead")                                \

typedef enum ipsec_sad_flags_t_
{
#define _(v, f, s) IPSEC_SA_FLAG_##f = v,
  foreach_ipsec_sa_flags
#undef _
} __clib_packed ipsec_sa_flags_t;

STATIC_ASSERT (sizeof (ipsec_sa_flags_t) == 1, "IPSEC SA flags > 1 byte");

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* flags */
  ipsec_sa_flags_t flags;

  u8 crypto_iv_size;
  u8 esp_block_align;
  u8 integ_icv_size;
  u32 encrypt_thread_index;
  u32 decrypt_thread_index;
  u32 spi;
  u32 seq;
  u32 seq_hi;
  u32 last_seq;
  u32 last_seq_hi;
  u64 replay_window;
  dpo_id_t dpo;

  vnet_crypto_key_index_t crypto_key_index;
  vnet_crypto_key_index_t integ_key_index;

  /* Union data shared by sync and async ops, updated when mode is
   * changed. */
  union
  {
    struct
    {
      vnet_crypto_op_id_t crypto_enc_op_id:16;
      vnet_crypto_op_id_t crypto_dec_op_id:16;
      vnet_crypto_op_id_t integ_op_id:16;
    };

    struct
    {
      vnet_crypto_async_op_id_t crypto_async_enc_op_id:16;
      vnet_crypto_async_op_id_t crypto_async_dec_op_id:16;
      vnet_crypto_key_index_t linked_key_index;
    };

    u64 crypto_op_data;
  };

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  u64 gcm_iv_counter;
  union
  {
    ip4_header_t ip4_hdr;
    ip6_header_t ip6_hdr;
  };
  udp_header_t udp_hdr;

  /* Salt used in GCM modes - stored in network byte order */
  u32 salt;

  ipsec_protocol_t protocol;
  tunnel_encap_decap_flags_t tunnel_flags;
  ip_dscp_t dscp;
  u8 __pad[1];

  /* data accessed by dataplane code should be above this comment */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);

  /* Elements with u64 size multiples */
  union
  {
    struct
    {
      vnet_crypto_op_id_t crypto_enc_op_id:16;
      vnet_crypto_op_id_t crypto_dec_op_id:16;
      vnet_crypto_op_id_t integ_op_id:16;
    };
    u64 data;
  } sync_op_data;

  union
  {
    struct
    {
      vnet_crypto_async_op_id_t crypto_async_enc_op_id:16;
      vnet_crypto_async_op_id_t crypto_async_dec_op_id:16;
      vnet_crypto_key_index_t linked_key_index;
    };
    u64 data;
  } async_op_data;

  ip46_address_t tunnel_src_addr;
  ip46_address_t tunnel_dst_addr;

  fib_node_t node;

  /* elements with u32 size */
  u32 id;
  u32 stat_index;
  vnet_crypto_alg_t integ_calg;
  vnet_crypto_alg_t crypto_calg;

  fib_node_index_t fib_entry_index;
  u32 sibling;
  u32 tx_fib_index;

  /* else u8 packed */
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;

  ipsec_key_t integ_key;
  ipsec_key_t crypto_key;
} ipsec_sa_t;

STATIC_ASSERT_OFFSET_OF (ipsec_sa_t, cacheline1, CLIB_CACHE_LINE_BYTES);
STATIC_ASSERT_OFFSET_OF (ipsec_sa_t, cacheline2, 2 * CLIB_CACHE_LINE_BYTES);

#define _(a,v,s)                                                        \
  always_inline int                                                     \
  ipsec_sa_is_set_##v (const ipsec_sa_t *sa) {                          \
    return (sa->flags & IPSEC_SA_FLAG_##v);                             \
  }
foreach_ipsec_sa_flags
#undef _
#define _(a,v,s)                                                        \
  always_inline int                                                     \
  ipsec_sa_set_##v (ipsec_sa_t *sa) {                                   \
    return (sa->flags |= IPSEC_SA_FLAG_##v);                            \
  }
  foreach_ipsec_sa_flags
#undef _
#define _(a,v,s)                                                        \
  always_inline int                                                     \
  ipsec_sa_unset_##v (ipsec_sa_t *sa) {                                 \
    return (sa->flags &= ~IPSEC_SA_FLAG_##v);                           \
  }
  foreach_ipsec_sa_flags
#undef _
/**
 * @brief
 * SA packet & bytes counters
 */
extern vlib_combined_counter_main_t ipsec_sa_counters;

extern void ipsec_mk_key (ipsec_key_t * key, const u8 * data, u8 len);

extern int ipsec_sa_add_and_lock (u32 id,
				  u32 spi,
				  ipsec_protocol_t proto,
				  ipsec_crypto_alg_t crypto_alg,
				  const ipsec_key_t * ck,
				  ipsec_integ_alg_t integ_alg,
				  const ipsec_key_t * ik,
				  ipsec_sa_flags_t flags,
				  u32 tx_table_id,
				  u32 salt,
				  const ip46_address_t * tunnel_src_addr,
				  const ip46_address_t * tunnel_dst_addr,
				  tunnel_encap_decap_flags_t tunnel_flags,
				  ip_dscp_t dscp,
				  u32 * sa_index, u16 src_port, u16 dst_port);
extern index_t ipsec_sa_find_and_lock (u32 id);
extern int ipsec_sa_unlock_id (u32 id);
extern void ipsec_sa_unlock (index_t sai);
extern void ipsec_sa_lock (index_t sai);
extern void ipsec_sa_clear (index_t sai);
extern void ipsec_sa_set_crypto_alg (ipsec_sa_t * sa,
				     ipsec_crypto_alg_t crypto_alg);
extern void ipsec_sa_set_integ_alg (ipsec_sa_t * sa,
				    ipsec_integ_alg_t integ_alg);

typedef walk_rc_t (*ipsec_sa_walk_cb_t) (ipsec_sa_t * sa, void *ctx);
extern void ipsec_sa_walk (ipsec_sa_walk_cb_t cd, void *ctx);

extern u8 *format_ipsec_crypto_alg (u8 * s, va_list * args);
extern u8 *format_ipsec_integ_alg (u8 * s, va_list * args);
extern u8 *format_ipsec_sa (u8 * s, va_list * args);
extern u8 *format_ipsec_key (u8 * s, va_list * args);
extern uword unformat_ipsec_crypto_alg (unformat_input_t * input,
					va_list * args);
extern uword unformat_ipsec_integ_alg (unformat_input_t * input,
				       va_list * args);
extern uword unformat_ipsec_key (unformat_input_t * input, va_list * args);

#define IPSEC_UDP_PORT_NONE ((u16)~0)

/*
 * Anti Replay definitions
 */

#define IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE (64)
#define IPSEC_SA_ANTI_REPLAY_WINDOW_MAX_INDEX (IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE-1)

/*
 * sequence number less than the lower bound are outside of the window
 * From RFC4303 Appendix A:
 *  Bl = Tl - W + 1
 */
#define IPSEC_SA_ANTI_REPLAY_WINDOW_LOWER_BOUND(_tl) (_tl - IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE + 1)

/*
 * Anti replay check.
 *  inputs need to be in host byte order.
 */
always_inline int
ipsec_sa_anti_replay_check (ipsec_sa_t * sa, u32 seq)
{
  u32 diff, tl, th;

  if ((sa->flags & IPSEC_SA_FLAG_USE_ANTI_REPLAY) == 0)
    return 0;

  if (!ipsec_sa_is_set_USE_ESN (sa))
    {
      if (PREDICT_TRUE (seq > sa->last_seq))
	return 0;

      diff = sa->last_seq - seq;

      if (IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE > diff)
	return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
      else
	return 1;

      return 0;
    }

  tl = sa->last_seq;
  th = sa->last_seq_hi;
  diff = tl - seq;

  if (PREDICT_TRUE (tl >= (IPSEC_SA_ANTI_REPLAY_WINDOW_MAX_INDEX)))
    {
      /*
       * the last sequence number VPP recieved is more than one
       * window size greater than zero.
       * Case A from RFC4303 Appendix A.
       */
      if (seq < IPSEC_SA_ANTI_REPLAY_WINDOW_LOWER_BOUND (tl))
	{
	  /*
	   * the received sequence number is lower than the lower bound
	   * of the window, this could mean either a replay packet or that
	   * the high sequence number has wrapped. if it decrypts corrently
	   * then it's the latter.
	   */
	  sa->seq_hi = th + 1;
	  return 0;
	}
      else
	{
	  /*
	   * the recieved sequence number greater than the low
	   * end of the window.
	   */
	  sa->seq_hi = th;
	  if (seq <= tl)
	    /*
	     * The recieved seq number is within bounds of the window
	     * check if it's a duplicate
	     */
	    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
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
       * the last sequence number VPP recieved is within one window
       * size of zero, i.e. 0 < TL < WINDOW_SIZE, the lower bound is thus a
       * large sequence number.
       * Note that the check below uses unsiged integer arthimetic, so the
       * RHS will be a larger number.
       * Case B from RFC4303 Appendix A.
       */
      if (seq < IPSEC_SA_ANTI_REPLAY_WINDOW_LOWER_BOUND (tl))
	{
	  /*
	   * the sequence number is less than the lower bound.
	   */
	  if (seq <= tl)
	    {
	      /*
	       * the packet is within the window upper bound.
	       * check for duplicates.
	       */
	      sa->seq_hi = th;
	      return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	    }
	  else
	    {
	      /*
	       * the packet is less the window lower bound or greater than
	       * the higher bound, depending on how you look at it...
	       * We're assuming, given that the last sequence number received,
	       * TL < WINDOW_SIZE, that a largeer seq num is more likely to be
	       * a packet that moves the window forward, than a packet that has
	       * wrapped the high sequence again. If it were the latter then
	       * we've lost close to 2^32 packets.
	       */
	      sa->seq_hi = th;
	      return 0;
	    }
	}
      else
	{
	  /*
	   * the packet seq number is between the lower bound (a large nubmer)
	   * and MAX_SEQ_NUM. This is in the window since the window upper bound
	   * tl > 0.
	   * However, since TL is the other side of 0 to the received
	   * packet, the SA has moved on to a higher sequence number.
	   */
	  sa->seq_hi = th - 1;
	  return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	}
    }

  return 0;
}

/*
 * Anti replay window advance
 *  inputs need to be in host byte order.
 */
always_inline void
ipsec_sa_anti_replay_advance (ipsec_sa_t * sa, u32 seq)
{
  u32 pos;
  if (PREDICT_TRUE (sa->flags & IPSEC_SA_FLAG_USE_ANTI_REPLAY) == 0)
    return;

  if (PREDICT_TRUE (sa->flags & IPSEC_SA_FLAG_USE_ESN))
    {
      int wrap = sa->seq_hi - sa->last_seq_hi;

      if (wrap == 0 && seq > sa->last_seq)
	{
	  pos = seq - sa->last_seq;
	  if (pos < IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE)
	    sa->replay_window = ((sa->replay_window) << pos) | 1;
	  else
	    sa->replay_window = 1;
	  sa->last_seq = seq;
	}
      else if (wrap > 0)
	{
	  pos = ~seq + sa->last_seq + 1;
	  if (pos < IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE)
	    sa->replay_window = ((sa->replay_window) << pos) | 1;
	  else
	    sa->replay_window = 1;
	  sa->last_seq = seq;
	  sa->last_seq_hi = sa->seq_hi;
	}
      else if (wrap < 0)
	{
	  pos = ~seq + sa->last_seq + 1;
	  sa->replay_window |= (1ULL << pos);
	}
      else
	{
	  pos = sa->last_seq - seq;
	  sa->replay_window |= (1ULL << pos);
	}
    }
  else
    {
      if (seq > sa->last_seq)
	{
	  pos = seq - sa->last_seq;
	  if (pos < IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE)
	    sa->replay_window = ((sa->replay_window) << pos) | 1;
	  else
	    sa->replay_window = 1;
	  sa->last_seq = seq;
	}
      else
	{
	  pos = sa->last_seq - seq;
	  sa->replay_window |= (1ULL << pos);
	}
    }
}


/*
 * Makes choice for thread_id should be assigned.
 *  if input ~0, gets random worker_id based on unix_time_now_nsec
*/
always_inline u32
ipsec_sa_assign_thread (u32 thread_id)
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
