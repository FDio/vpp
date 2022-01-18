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

#define IPSEC_CRYPTO_ALG_IS_CTR(_alg)                                         \
  (((_alg == IPSEC_CRYPTO_ALG_AES_CTR_128) ||                                 \
    (_alg == IPSEC_CRYPTO_ALG_AES_CTR_192) ||                                 \
    (_alg == IPSEC_CRYPTO_ALG_AES_CTR_256)))

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
  _ (128, IS_AEAD, "aead")                                                    \
  _ (256, IS_CTR, "ctr")                                                      \
  _ (512, IS_ASYNC, "async")                                                  \
  _ (1024, NO_ALGO_NO_DROP, "no-algo-no-drop")

typedef enum ipsec_sad_flags_t_
{
#define _(v, f, s) IPSEC_SA_FLAG_##f = v,
  foreach_ipsec_sa_flags
#undef _
} __clib_packed ipsec_sa_flags_t;

STATIC_ASSERT (sizeof (ipsec_sa_flags_t) == 2, "IPSEC SA flags != 2 byte");

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* flags */
  ipsec_sa_flags_t flags;

  u8 crypto_iv_size;
  u8 esp_block_align;
  u8 integ_icv_size;

  u8 __pad1[11];

  u32 thread_index;

  u32 spi;
  u32 seq;
  u32 seq_hi;
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

  union
  {
    ip4_header_t ip4_hdr;
    ip6_header_t ip6_hdr;
  };
  udp_header_t udp_hdr;

  /* Salt used in CTR modes (incl. GCM) - stored in network byte order */
  u32 salt;

  ipsec_protocol_t protocol;
  tunnel_encap_decap_flags_t tunnel_flags;
  u8 __pad[2];

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

  tunnel_t tunnel;

  fib_node_t node;

  /* elements with u32 size */
  u32 id;
  u32 stat_index;
  vnet_crypto_alg_t integ_calg;
  vnet_crypto_alg_t crypto_calg;

  /* else u8 packed */
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;

  ipsec_key_t integ_key;
  ipsec_key_t crypto_key;
} ipsec_sa_t;

STATIC_ASSERT_OFFSET_OF (ipsec_sa_t, cacheline1, CLIB_CACHE_LINE_BYTES);
STATIC_ASSERT_OFFSET_OF (ipsec_sa_t, cacheline2, 2 * CLIB_CACHE_LINE_BYTES);

/**
 * Pool of IPSec SAs
 */
extern ipsec_sa_t *ipsec_sa_pool;

/*
 * Ensure that the IPsec data does not overlap with the IP data in
 * the buffer meta data
 */
STATIC_ASSERT (STRUCT_OFFSET_OF (vnet_buffer_opaque_t, ipsec.sad_index) ==
		 STRUCT_OFFSET_OF (vnet_buffer_opaque_t, ip.save_protocol),
	       "IPSec data is overlapping with IP data");

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
extern vlib_simple_counter_main_t ipsec_sa_lost_counters;

extern void ipsec_mk_key (ipsec_key_t * key, const u8 * data, u8 len);

extern int
ipsec_sa_add_and_lock (u32 id, u32 spi, ipsec_protocol_t proto,
		       ipsec_crypto_alg_t crypto_alg, const ipsec_key_t *ck,
		       ipsec_integ_alg_t integ_alg, const ipsec_key_t *ik,
		       ipsec_sa_flags_t flags, u32 salt, u16 src_port,
		       u16 dst_port, const tunnel_t *tun, u32 *sa_out_index);
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

extern u8 *format_ipsec_replay_window (u8 *s, va_list *args);
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

always_inline int
ipsec_sa_anti_replay_check (const ipsec_sa_t *sa, u32 seq)
{
  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa) &&
      sa->replay_window & (1ULL << (sa->seq - seq)))
    return 1;
  else
    return 0;
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
ipsec_sa_anti_replay_and_sn_advance (const ipsec_sa_t *sa, u32 seq,
				     u32 hi_seq_used, bool post_decrypt,
				     u32 *hi_seq_req)
{
  ASSERT ((post_decrypt == false) == (hi_seq_req != 0));

  if (!ipsec_sa_is_set_USE_ESN (sa))
    {
      if (hi_seq_req)
	/* no ESN, therefore the hi-seq is always 0 */
	*hi_seq_req = 0;

      if (!ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
	return 0;

      if (PREDICT_TRUE (seq > sa->seq))
	return 0;

      u32 diff = sa->seq - seq;

      if (IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE > diff)
	return ((sa->replay_window & (1ULL << diff)) ? 1 : 0);
      else
	return 1;

      return 0;
    }

  if (!ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
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
	  if (seq >= sa->seq)
	    /* The packet's sequence number is larger that the SA's.
	     * that can't be a warp - unless we lost more than
	     * 2^32 packets ... how could we know? */
	    *hi_seq_req = sa->seq_hi;
	  else
	    {
	      /* The packet's SN is less than the SAs, so either the SN has
	       * wrapped or the SN is just old. */
	      if (sa->seq - seq > (1 << 30))
		/* It's really really really old => it wrapped */
		*hi_seq_req = sa->seq_hi + 1;
	      else
		*hi_seq_req = sa->seq_hi;
	    }
	}
      /*
       * else
       *   this is post-decrpyt and since it decrypted we accept it
       */
      return 0;
    }
  if (PREDICT_TRUE (sa->seq >= (IPSEC_SA_ANTI_REPLAY_WINDOW_MAX_INDEX)))
    {
      /*
       * the last sequence number VPP recieved is more than one
       * window size greater than zero.
       * Case A from RFC4303 Appendix A.
       */
      if (seq < IPSEC_SA_ANTI_REPLAY_WINDOW_LOWER_BOUND (sa->seq))
	{
	  /*
	   * the received sequence number is lower than the lower bound
	   * of the window, this could mean either a replay packet or that
	   * the high sequence number has wrapped. if it decrypts corrently
	   * then it's the latter.
	   */
	  if (post_decrypt)
	    {
	      if (hi_seq_used == sa->seq_hi)
		/* the high sequence number used to succesfully decrypt this
		 * packet is the same as the last-sequnence number of the SA.
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
	      /* pre-decrypt it might be the might that casues a wrap, we
	       * need to decrpyt to find out */
	      if (hi_seq_req)
		*hi_seq_req = sa->seq_hi + 1;
	      return 0;
	    }
	}
      else
	{
	  /*
	   * the recieved sequence number greater than the low
	   * end of the window.
	   */
	  if (hi_seq_req)
	    *hi_seq_req = sa->seq_hi;
	  if (seq <= sa->seq)
	    /*
	     * The recieved seq number is within bounds of the window
	     * check if it's a duplicate
	     */
	    return (ipsec_sa_anti_replay_check (sa, seq));
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
      if (seq < IPSEC_SA_ANTI_REPLAY_WINDOW_LOWER_BOUND (sa->seq))
	{
	  /*
	   * the sequence number is less than the lower bound.
	   */
	  if (seq <= sa->seq)
	    {
	      /*
	       * the packet is within the window upper bound.
	       * check for duplicates.
	       */
	      if (hi_seq_req)
		*hi_seq_req = sa->seq_hi;
	      return (ipsec_sa_anti_replay_check (sa, seq));
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
	      if (hi_seq_req)
		*hi_seq_req = sa->seq_hi;
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
	  if (hi_seq_req)
	    *hi_seq_req = sa->seq_hi - 1;
	  return (ipsec_sa_anti_replay_check (sa, seq));
	}
    }

  /* unhandled case */
  ASSERT (0);
  return 0;
}

always_inline u32
ipsec_sa_anti_replay_window_shift (ipsec_sa_t *sa, u32 inc)
{
  u32 n_lost = 0;

  if (inc < IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE)
    {
      if (sa->seq > IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE)
	{
	  /*
	   * count how many holes there are in the portion
	   * of the window that we will right shift of the end
	   * as a result of this increments
	   */
	  u64 mask = (((u64) 1 << inc) - 1) << (BITS (u64) - inc);
	  u64 old = sa->replay_window & mask;
	  /* the number of packets we saw in this section of the window */
	  u64 seen = count_set_bits (old);

	  /*
	   * the number we missed is the size of the window section
	   * minus the number we saw.
	   */
	  n_lost = inc - seen;
	}
      sa->replay_window = ((sa->replay_window) << inc) | 1;
    }
  else
    {
      /* holes in the replay window are lost packets */
      n_lost = BITS (u64) - count_set_bits (sa->replay_window);

      /* any sequence numbers that now fall outside the window
       * are forever lost */
      n_lost += inc - IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE;

      sa->replay_window = 1;
    }

  return (n_lost);
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
ipsec_sa_anti_replay_advance (ipsec_sa_t *sa, u32 thread_index, u32 seq,
			      u32 hi_seq)
{
  u64 n_lost = 0;
  u32 pos;

  if (ipsec_sa_is_set_USE_ESN (sa))
    {
      int wrap = hi_seq - sa->seq_hi;

      if (wrap == 0 && seq > sa->seq)
	{
	  pos = seq - sa->seq;
	  n_lost = ipsec_sa_anti_replay_window_shift (sa, pos);
	  sa->seq = seq;
	}
      else if (wrap > 0)
	{
	  pos = ~seq + sa->seq + 1;
	  n_lost = ipsec_sa_anti_replay_window_shift (sa, pos);
	  sa->seq = seq;
	  sa->seq_hi = hi_seq;
	}
      else if (wrap < 0)
	{
	  pos = ~seq + sa->seq + 1;
	  sa->replay_window |= (1ULL << pos);
	}
      else
	{
	  pos = sa->seq - seq;
	  sa->replay_window |= (1ULL << pos);
	}
    }
  else
    {
      if (seq > sa->seq)
	{
	  pos = seq - sa->seq;
	  n_lost = ipsec_sa_anti_replay_window_shift (sa, pos);
	  sa->seq = seq;
	}
      else
	{
	  pos = sa->seq - seq;
	  sa->replay_window |= (1ULL << pos);
	}
    }

  return n_lost;
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

always_inline ipsec_sa_t *
ipsec_sa_get (u32 sa_index)
{
  return (pool_elt_at_index (ipsec_sa_pool, sa_index));
}

#endif /* __IPSEC_SPD_SA_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
