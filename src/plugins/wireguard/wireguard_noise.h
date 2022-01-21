/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>.
 * Copyright (c) 2019-2020 Matt Dunwoodie <ncon@noconroy.net>.
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

#ifndef __included_wg_noise_h__
#define __included_wg_noise_h__

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <wireguard/blake/blake2s.h>
#include <wireguard/blake/blake3.h>
#include <wireguard/wireguard_key.h>

#define NOISE_PUBLIC_KEY_LEN	CURVE25519_KEY_SIZE
#define NOISE_SYMMETRIC_KEY_LEN	  32	// CHACHA20POLY1305_KEY_SIZE
#define NOISE_TIMESTAMP_LEN	(sizeof(uint64_t) + sizeof(uint32_t))
#define NOISE_AUTHTAG_LEN	16	//CHACHA20POLY1305_AUTHTAG_SIZE
#define NOISE_HASH_LEN		BLAKE2S_HASH_SIZE

/* Protocol string constants */
#define NOISE_HANDSHAKE_NAME	"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define NOISE_IDENTIFIER_NAME	"WireGuard v1 zx2c4 Jason@zx2c4.com"

/* Constants for the counter */
#define COUNTER_BITS_TOTAL	8192
#define COUNTER_BITS		(sizeof(unsigned long) * 8)
#define COUNTER_NUM		(COUNTER_BITS_TOTAL / COUNTER_BITS)
#define COUNTER_WINDOW_SIZE	(COUNTER_BITS_TOTAL - COUNTER_BITS)

/* Constants for the keypair */
#define REKEY_AFTER_MESSAGES	(1ull << 60)
#define REJECT_AFTER_MESSAGES	(UINT64_MAX - COUNTER_WINDOW_SIZE - 1)
#define REKEY_AFTER_TIME	120
#define REKEY_AFTER_TIME_RECV	165
#define REJECT_AFTER_TIME	180
#define REJECT_INTERVAL		(0.02)	/* fifty times per sec */
/* 24 = floor(log2(REJECT_INTERVAL)) */
#define REJECT_INTERVAL_MASK	(~((1ull<<24)-1))

enum noise_state_crypt
{
  SC_OK = 0,
  SC_CONN_RESET,
  SC_KEEP_KEY_FRESH,
  SC_FAILED,
};

enum noise_state_hs
{
  HS_ZEROED = 0,
  CREATED_INITIATION,
  CONSUMED_INITIATION,
  CREATED_RESPONSE,
  CONSUMED_RESPONSE,
};

typedef struct noise_handshake
{
  enum noise_state_hs hs_state;
  uint32_t hs_local_index;
  uint32_t hs_remote_index;
  uint8_t hs_e[NOISE_PUBLIC_KEY_LEN];
  uint8_t hs_hash[NOISE_HASH_LEN];
  uint8_t hs_ck[NOISE_HASH_LEN];
} noise_handshake_t;

typedef struct noise_counter
{
  uint64_t c_send;
  uint64_t c_recv;
  unsigned long c_backtrack[COUNTER_NUM];
} noise_counter_t;

typedef struct noise_keypair
{
  int kp_valid;
  int kp_is_initiator;
  uint32_t kp_local_index;
  uint32_t kp_remote_index;
  vnet_crypto_key_index_t kp_send_index;
  vnet_crypto_key_index_t kp_recv_index;
  f64 kp_birthdate;
  noise_counter_t kp_ctr;
} noise_keypair_t;

typedef struct noise_local noise_local_t;
typedef struct noise_remote
{
  uint32_t r_peer_idx;
  uint8_t r_public[NOISE_PUBLIC_KEY_LEN];
  uint32_t r_local_idx;
  uint8_t r_ss[NOISE_PUBLIC_KEY_LEN];

  noise_handshake_t r_handshake;
  uint8_t r_psk[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t r_timestamp[NOISE_TIMESTAMP_LEN];
  f64 r_last_init;

  clib_rwlock_t r_keypair_lock;
  noise_keypair_t *r_next, *r_current, *r_previous;
} noise_remote_t;

typedef struct noise_local
{
  uint8_t l_public[NOISE_PUBLIC_KEY_LEN];
  uint8_t l_private[NOISE_PUBLIC_KEY_LEN];

  struct noise_upcall
  {
    void *u_arg;
    noise_remote_t *(*u_remote_get) (const uint8_t[NOISE_PUBLIC_KEY_LEN]);
      uint32_t (*u_index_set) (noise_remote_t *);
    void (*u_index_drop) (uint32_t);
  } l_upcall;
} noise_local_t;

/* pool of noise_local */
extern noise_local_t *noise_local_pool;

/* Set/Get noise parameters */
static_always_inline noise_local_t *
noise_local_get (uint32_t locali)
{
  return (pool_elt_at_index (noise_local_pool, locali));
}

void noise_local_init (noise_local_t *, struct noise_upcall *);
bool noise_local_set_private (noise_local_t *,
			      const uint8_t[NOISE_PUBLIC_KEY_LEN]);

void noise_remote_init (noise_remote_t *, uint32_t,
			const uint8_t[NOISE_PUBLIC_KEY_LEN], uint32_t);

/* Should be called anytime noise_local_set_private is called */
void noise_remote_precompute (noise_remote_t *);

/* Cryptographic functions */
bool noise_create_initiation (vlib_main_t * vm, noise_remote_t *,
			      uint32_t * s_idx,
			      uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			      uint8_t es[NOISE_PUBLIC_KEY_LEN +
					 NOISE_AUTHTAG_LEN],
			      uint8_t ets[NOISE_TIMESTAMP_LEN +
					  NOISE_AUTHTAG_LEN]);

bool noise_consume_initiation (vlib_main_t * vm, noise_local_t *,
			       noise_remote_t **,
			       uint32_t s_idx,
			       uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			       uint8_t es[NOISE_PUBLIC_KEY_LEN +
					  NOISE_AUTHTAG_LEN],
			       uint8_t ets[NOISE_TIMESTAMP_LEN +
					   NOISE_AUTHTAG_LEN]);

bool noise_create_response (vlib_main_t * vm, noise_remote_t *,
			    uint32_t * s_idx,
			    uint32_t * r_idx,
			    uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			    uint8_t en[0 + NOISE_AUTHTAG_LEN]);

bool noise_consume_response (vlib_main_t * vm, noise_remote_t *,
			     uint32_t s_idx,
			     uint32_t r_idx,
			     uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			     uint8_t en[0 + NOISE_AUTHTAG_LEN]);

bool noise_remote_begin_session (vlib_main_t * vm, noise_remote_t * r);
void noise_remote_clear (vlib_main_t * vm, noise_remote_t * r);
void noise_remote_expire_current (noise_remote_t * r);

bool noise_remote_ready (noise_remote_t *);

enum noise_state_crypt
noise_remote_encrypt (vlib_main_t * vm, noise_remote_t *,
		      uint32_t * r_idx,
		      uint64_t * nonce,
		      uint8_t * src, size_t srclen, uint8_t * dst);

enum noise_state_crypt
noise_sync_remote_encrypt (vlib_main_t *vm, vnet_crypto_op_t **crypto_ops,
			   noise_remote_t *r, uint32_t *r_idx, uint64_t *nonce,
			   uint8_t *src, size_t srclen, uint8_t *dst, u32 bi,
			   u8 *iv, f64 time);

enum noise_state_crypt
noise_sync_remote_decrypt (vlib_main_t *vm, vnet_crypto_op_t **crypto_ops,
			   noise_remote_t *, uint32_t r_idx, uint64_t nonce,
			   uint8_t *src, size_t srclen, uint8_t *dst, u32 bi,
			   u8 *iv, f64 time);

static_always_inline noise_keypair_t *
wg_get_active_keypair (noise_remote_t *r, uint32_t r_idx)
{
  if (r->r_current != NULL && r->r_current->kp_local_index == r_idx)
    {
      return r->r_current;
    }
  else if (r->r_previous != NULL && r->r_previous->kp_local_index == r_idx)
    {
      return r->r_previous;
    }
  else if (r->r_next != NULL && r->r_next->kp_local_index == r_idx)
    {
      return r->r_next;
    }
  else
    {
      return NULL;
    }
}

inline bool
noise_counter_recv (noise_counter_t *ctr, uint64_t recv)
{
  uint64_t i, top, index_recv, index_ctr;
  unsigned long bit;
  bool ret = false;

  /* Check that the recv counter is valid */
  if (ctr->c_recv >= REJECT_AFTER_MESSAGES || recv >= REJECT_AFTER_MESSAGES)
    goto error;

  /* If the packet is out of the window, invalid */
  if (recv + COUNTER_WINDOW_SIZE < ctr->c_recv)
    goto error;

  /* If the new counter is ahead of the current counter, we'll need to
   * zero out the bitmap that has previously been used */
  index_recv = recv / COUNTER_BITS;
  index_ctr = ctr->c_recv / COUNTER_BITS;

  if (recv > ctr->c_recv)
    {
      top = clib_min (index_recv - index_ctr, COUNTER_NUM);
      for (i = 1; i <= top; i++)
	ctr->c_backtrack[(i + index_ctr) & (COUNTER_NUM - 1)] = 0;
      ctr->c_recv = recv;
    }

  index_recv %= COUNTER_NUM;
  bit = 1ul << (recv % COUNTER_BITS);

  if (ctr->c_backtrack[index_recv] & bit)
    goto error;

  ctr->c_backtrack[index_recv] |= bit;

  ret = true;
error:
  return ret;
}

#endif /* __included_wg_noise_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
