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

#include <openssl/hmac.h>
#include <wireguard/wireguard.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

noise_local_t *noise_local_pool;

/* Private functions */
static noise_keypair_t *noise_remote_keypair_allocate (noise_remote_t *);
static void noise_remote_keypair_free (vlib_main_t * vm, noise_remote_t *,
				       noise_keypair_t **);
static uint32_t noise_remote_handshake_index_get (noise_remote_t *);
static void noise_remote_handshake_index_drop (noise_remote_t *);

static uint64_t noise_counter_send (noise_counter_t *);
bool noise_counter_recv (noise_counter_t *, uint64_t);

static void noise_kdf (uint8_t *, uint8_t *, uint8_t *, const uint8_t *,
		       size_t, size_t, size_t, size_t,
		       const uint8_t[NOISE_HASH_LEN]);
static bool noise_mix_dh (uint8_t[NOISE_HASH_LEN],
			  uint8_t[NOISE_SYMMETRIC_KEY_LEN],
			  const uint8_t[NOISE_PUBLIC_KEY_LEN],
			  const uint8_t[NOISE_PUBLIC_KEY_LEN]);
static bool noise_mix_ss (uint8_t ck[NOISE_HASH_LEN],
			  uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
			  const uint8_t ss[NOISE_PUBLIC_KEY_LEN]);
static void noise_mix_hash (uint8_t[NOISE_HASH_LEN], const uint8_t *, size_t);
static void noise_mix_psk (uint8_t[NOISE_HASH_LEN],
			   uint8_t[NOISE_HASH_LEN],
			   uint8_t[NOISE_SYMMETRIC_KEY_LEN],
			   const uint8_t[NOISE_SYMMETRIC_KEY_LEN]);
static void noise_param_init (uint8_t[NOISE_HASH_LEN],
			      uint8_t[NOISE_HASH_LEN],
			      const uint8_t[NOISE_PUBLIC_KEY_LEN]);

static void noise_msg_encrypt (vlib_main_t * vm, uint8_t *, uint8_t *, size_t,
			       uint32_t key_idx, uint8_t[NOISE_HASH_LEN]);
static bool noise_msg_decrypt (vlib_main_t * vm, uint8_t *, uint8_t *, size_t,
			       uint32_t key_idx, uint8_t[NOISE_HASH_LEN]);
static void noise_msg_ephemeral (uint8_t[NOISE_HASH_LEN],
				 uint8_t[NOISE_HASH_LEN],
				 const uint8_t src[NOISE_PUBLIC_KEY_LEN]);

static void noise_tai64n_now (uint8_t[NOISE_TIMESTAMP_LEN]);

static void secure_zero_memory (void *v, size_t n);

/* Set/Get noise parameters */
void
noise_local_init (noise_local_t * l, struct noise_upcall *upcall)
{
  clib_memset (l, 0, sizeof (*l));
  l->l_upcall = *upcall;
}

bool
noise_local_set_private (noise_local_t * l,
			 const uint8_t private[NOISE_PUBLIC_KEY_LEN])
{
  clib_memcpy (l->l_private, private, NOISE_PUBLIC_KEY_LEN);

  return curve25519_gen_public (l->l_public, private);
}

void
noise_remote_init (noise_remote_t * r, uint32_t peer_pool_idx,
		   const uint8_t public[NOISE_PUBLIC_KEY_LEN],
		   u32 noise_local_idx)
{
  clib_memset (r, 0, sizeof (*r));
  clib_memcpy (r->r_public, public, NOISE_PUBLIC_KEY_LEN);
  clib_rwlock_init (&r->r_keypair_lock);
  r->r_peer_idx = peer_pool_idx;
  r->r_local_idx = noise_local_idx;
  r->r_handshake.hs_state = HS_ZEROED;

  noise_remote_precompute (r);
}

void
noise_remote_precompute (noise_remote_t * r)
{
  noise_local_t *l = noise_local_get (r->r_local_idx);

  if (!curve25519_gen_shared (r->r_ss, l->l_private, r->r_public))
    clib_memset (r->r_ss, 0, NOISE_PUBLIC_KEY_LEN);

  noise_remote_handshake_index_drop (r);
  secure_zero_memory (&r->r_handshake, sizeof (r->r_handshake));
}

/* Handshake functions */
bool
noise_create_initiation (vlib_main_t * vm, noise_remote_t * r,
			 uint32_t * s_idx, uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			 uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
			 uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN])
{
  noise_handshake_t *hs = &r->r_handshake;
  noise_local_t *l = noise_local_get (r->r_local_idx);
  uint8_t _key[NOISE_SYMMETRIC_KEY_LEN];
  uint32_t key_idx;
  uint8_t *key;
  int ret = false;

  key_idx =
    vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_CHACHA20_POLY1305, _key,
			 NOISE_SYMMETRIC_KEY_LEN);
  key = vnet_crypto_get_key (key_idx)->data;

  noise_param_init (hs->hs_ck, hs->hs_hash, r->r_public);

  /* e */
  curve25519_gen_secret (hs->hs_e);
  if (!curve25519_gen_public (ue, hs->hs_e))
    goto error;
  noise_msg_ephemeral (hs->hs_ck, hs->hs_hash, ue);

  /* es */
  if (!noise_mix_dh (hs->hs_ck, key, hs->hs_e, r->r_public))
    goto error;

  /* s */
  noise_msg_encrypt (vm, es, l->l_public, NOISE_PUBLIC_KEY_LEN, key_idx,
		     hs->hs_hash);

  /* ss */
  if (!noise_mix_ss (hs->hs_ck, key, r->r_ss))
    goto error;

  /* {t} */
  noise_tai64n_now (ets);
  noise_msg_encrypt (vm, ets, ets, NOISE_TIMESTAMP_LEN, key_idx, hs->hs_hash);
  noise_remote_handshake_index_drop (r);
  hs->hs_state = CREATED_INITIATION;
  hs->hs_local_index = noise_remote_handshake_index_get (r);
  *s_idx = hs->hs_local_index;
  ret = true;
error:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  vnet_crypto_key_del (vm, key_idx);
  return ret;
}

bool
noise_consume_initiation (vlib_main_t * vm, noise_local_t * l,
			  noise_remote_t ** rp, uint32_t s_idx,
			  uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			  uint8_t es[NOISE_PUBLIC_KEY_LEN +
				     NOISE_AUTHTAG_LEN],
			  uint8_t ets[NOISE_TIMESTAMP_LEN +
				      NOISE_AUTHTAG_LEN])
{
  noise_remote_t *r;
  noise_handshake_t hs;
  uint8_t _key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t r_public[NOISE_PUBLIC_KEY_LEN];
  uint8_t timestamp[NOISE_TIMESTAMP_LEN];
  u32 key_idx;
  uint8_t *key;
  int ret = false;

  key_idx =
    vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_CHACHA20_POLY1305, _key,
			 NOISE_SYMMETRIC_KEY_LEN);
  key = vnet_crypto_get_key (key_idx)->data;

  noise_param_init (hs.hs_ck, hs.hs_hash, l->l_public);

  /* e */
  noise_msg_ephemeral (hs.hs_ck, hs.hs_hash, ue);

  /* es */
  if (!noise_mix_dh (hs.hs_ck, key, l->l_private, ue))
    goto error;

  /* s */

  if (!noise_msg_decrypt (vm, r_public, es,
			  NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN, key_idx,
			  hs.hs_hash))
    goto error;

  /* Lookup the remote we received from */
  if ((r = l->l_upcall.u_remote_get (r_public)) == NULL)
    goto error;

  /* ss */
  if (!noise_mix_ss (hs.hs_ck, key, r->r_ss))
    goto error;

  /* {t} */
  if (!noise_msg_decrypt (vm, timestamp, ets,
			  NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN, key_idx,
			  hs.hs_hash))
    goto error;
  ;

  hs.hs_state = CONSUMED_INITIATION;
  hs.hs_local_index = 0;
  hs.hs_remote_index = s_idx;
  clib_memcpy (hs.hs_e, ue, NOISE_PUBLIC_KEY_LEN);

  /* Replay */
  if (clib_memcmp (timestamp, r->r_timestamp, NOISE_TIMESTAMP_LEN) > 0)
    clib_memcpy (r->r_timestamp, timestamp, NOISE_TIMESTAMP_LEN);
  else
    goto error;

  /* Flood attack */
  if (wg_birthdate_has_expired (r->r_last_init, REJECT_INTERVAL))
    r->r_last_init = vlib_time_now (vm);
  else
    goto error;

  /* Ok, we're happy to accept this initiation now */
  noise_remote_handshake_index_drop (r);
  r->r_handshake = hs;
  *rp = r;
  ret = true;

error:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  vnet_crypto_key_del (vm, key_idx);
  secure_zero_memory (&hs, sizeof (hs));
  return ret;
}

bool
noise_create_response (vlib_main_t * vm, noise_remote_t * r, uint32_t * s_idx,
		       uint32_t * r_idx, uint8_t ue[NOISE_PUBLIC_KEY_LEN],
		       uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
  noise_handshake_t *hs = &r->r_handshake;
  uint8_t _key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t e[NOISE_PUBLIC_KEY_LEN];
  uint32_t key_idx;
  uint8_t *key;
  int ret = false;

  key_idx =
    vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_CHACHA20_POLY1305, _key,
			 NOISE_SYMMETRIC_KEY_LEN);
  key = vnet_crypto_get_key (key_idx)->data;

  if (hs->hs_state != CONSUMED_INITIATION)
    goto error;

  /* e */
  curve25519_gen_secret (e);
  if (!curve25519_gen_public (ue, e))
    goto error;
  noise_msg_ephemeral (hs->hs_ck, hs->hs_hash, ue);

  /* ee */
  if (!noise_mix_dh (hs->hs_ck, NULL, e, hs->hs_e))
    goto error;

  /* se */
  if (!noise_mix_dh (hs->hs_ck, NULL, e, r->r_public))
    goto error;

  /* psk */
  noise_mix_psk (hs->hs_ck, hs->hs_hash, key, r->r_psk);

  /* {} */
  noise_msg_encrypt (vm, en, NULL, 0, key_idx, hs->hs_hash);


  hs->hs_state = CREATED_RESPONSE;
  hs->hs_local_index = noise_remote_handshake_index_get (r);
  *r_idx = hs->hs_remote_index;
  *s_idx = hs->hs_local_index;
  ret = true;
error:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  vnet_crypto_key_del (vm, key_idx);
  secure_zero_memory (e, NOISE_PUBLIC_KEY_LEN);
  return ret;
}

bool
noise_consume_response (vlib_main_t * vm, noise_remote_t * r, uint32_t s_idx,
			uint32_t r_idx, uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
  noise_local_t *l = noise_local_get (r->r_local_idx);
  noise_handshake_t hs;
  uint8_t _key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t preshared_key[NOISE_PUBLIC_KEY_LEN];
  uint32_t key_idx;
  uint8_t *key;
  int ret = false;

  key_idx =
    vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_CHACHA20_POLY1305, _key,
			 NOISE_SYMMETRIC_KEY_LEN);
  key = vnet_crypto_get_key (key_idx)->data;

  hs = r->r_handshake;
  clib_memcpy (preshared_key, r->r_psk, NOISE_SYMMETRIC_KEY_LEN);

  if (hs.hs_state != CREATED_INITIATION || hs.hs_local_index != r_idx)
    goto error;

  /* e */
  noise_msg_ephemeral (hs.hs_ck, hs.hs_hash, ue);

  /* ee */
  if (!noise_mix_dh (hs.hs_ck, NULL, hs.hs_e, ue))
    goto error;

  /* se */
  if (!noise_mix_dh (hs.hs_ck, NULL, l->l_private, ue))
    goto error;

  /* psk */
  noise_mix_psk (hs.hs_ck, hs.hs_hash, key, preshared_key);

  /* {} */

  if (!noise_msg_decrypt
      (vm, NULL, en, 0 + NOISE_AUTHTAG_LEN, key_idx, hs.hs_hash))
    goto error;


  hs.hs_remote_index = s_idx;

  if (r->r_handshake.hs_state == hs.hs_state &&
      r->r_handshake.hs_local_index == hs.hs_local_index)
    {
      r->r_handshake = hs;
      r->r_handshake.hs_state = CONSUMED_RESPONSE;
      ret = true;
    }
error:
  secure_zero_memory (&hs, sizeof (hs));
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  vnet_crypto_key_del (vm, key_idx);
  return ret;
}

bool
noise_remote_begin_session (vlib_main_t * vm, noise_remote_t * r)
{
  noise_handshake_t *hs = &r->r_handshake;
  noise_keypair_t kp, *next, *current, *previous;

  uint8_t key_send[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t key_recv[NOISE_SYMMETRIC_KEY_LEN];

  /* We now derive the keypair from the handshake */
  if (hs->hs_state == CONSUMED_RESPONSE)
    {
      kp.kp_is_initiator = 1;
      noise_kdf (key_send, key_recv, NULL, NULL,
		 NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
		 hs->hs_ck);
    }
  else if (hs->hs_state == CREATED_RESPONSE)
    {
      kp.kp_is_initiator = 0;
      noise_kdf (key_recv, key_send, NULL, NULL,
		 NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
		 hs->hs_ck);
    }
  else
    {
      return false;
    }

  kp.kp_valid = 1;
  kp.kp_send_index = vnet_crypto_key_add (vm,
					  VNET_CRYPTO_ALG_CHACHA20_POLY1305,
					  key_send, NOISE_SYMMETRIC_KEY_LEN);
  kp.kp_recv_index = vnet_crypto_key_add (vm,
					  VNET_CRYPTO_ALG_CHACHA20_POLY1305,
					  key_recv, NOISE_SYMMETRIC_KEY_LEN);
  kp.kp_local_index = hs->hs_local_index;
  kp.kp_remote_index = hs->hs_remote_index;
  kp.kp_birthdate = vlib_time_now (vm);
  clib_memset (&kp.kp_ctr, 0, sizeof (kp.kp_ctr));

  /* Now we need to add_new_keypair */
  clib_rwlock_writer_lock (&r->r_keypair_lock);
  /* Activate barrier to synchronization keys between threads */
  vlib_worker_thread_barrier_sync (vm);
  next = r->r_next;
  current = r->r_current;
  previous = r->r_previous;

  if (kp.kp_is_initiator)
    {
      if (next != NULL)
	{
	  r->r_next = NULL;
	  r->r_previous = next;
	  noise_remote_keypair_free (vm, r, &current);
	}
      else
	{
	  r->r_previous = current;
	}

      noise_remote_keypair_free (vm, r, &previous);

      r->r_current = noise_remote_keypair_allocate (r);
      *r->r_current = kp;
    }
  else
    {
      noise_remote_keypair_free (vm, r, &next);
      r->r_previous = NULL;
      noise_remote_keypair_free (vm, r, &previous);

      r->r_next = noise_remote_keypair_allocate (r);
      *r->r_next = kp;
    }
  vlib_worker_thread_barrier_release (vm);
  clib_rwlock_writer_unlock (&r->r_keypair_lock);

  secure_zero_memory (&r->r_handshake, sizeof (r->r_handshake));

  secure_zero_memory (&kp, sizeof (kp));
  return true;
}

void
noise_remote_clear (vlib_main_t * vm, noise_remote_t * r)
{
  noise_remote_handshake_index_drop (r);
  secure_zero_memory (&r->r_handshake, sizeof (r->r_handshake));

  clib_rwlock_writer_lock (&r->r_keypair_lock);
  noise_remote_keypair_free (vm, r, &r->r_next);
  noise_remote_keypair_free (vm, r, &r->r_current);
  noise_remote_keypair_free (vm, r, &r->r_previous);
  r->r_next = NULL;
  r->r_current = NULL;
  r->r_previous = NULL;
  clib_rwlock_writer_unlock (&r->r_keypair_lock);
}

void
noise_remote_expire_current (noise_remote_t * r)
{
  clib_rwlock_writer_lock (&r->r_keypair_lock);
  if (r->r_next != NULL)
    r->r_next->kp_valid = 0;
  if (r->r_current != NULL)
    r->r_current->kp_valid = 0;
  clib_rwlock_writer_unlock (&r->r_keypair_lock);
}

bool
noise_remote_ready (noise_remote_t * r)
{
  noise_keypair_t *kp;
  int ret;

  clib_rwlock_reader_lock (&r->r_keypair_lock);
  if ((kp = r->r_current) == NULL ||
      !kp->kp_valid ||
      wg_birthdate_has_expired (kp->kp_birthdate, REJECT_AFTER_TIME) ||
      kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
      kp->kp_ctr.c_send >= REJECT_AFTER_MESSAGES)
    ret = false;
  else
    ret = true;
  clib_rwlock_reader_unlock (&r->r_keypair_lock);
  return ret;
}

static bool
chacha20poly1305_calc (vlib_main_t * vm,
		       u8 * src,
		       u32 src_len,
		       u8 * dst,
		       u8 * aad,
		       u32 aad_len,
		       u64 nonce,
		       vnet_crypto_op_id_t op_id,
		       vnet_crypto_key_index_t key_index)
{
  vnet_crypto_op_t _op, *op = &_op;
  u8 iv[12];
  u8 tag_[NOISE_AUTHTAG_LEN] = { };
  u8 src_[] = { };

  clib_memset (iv, 0, 12);
  clib_memcpy (iv + 4, &nonce, sizeof (nonce));

  vnet_crypto_op_init (op, op_id);

  op->tag_len = NOISE_AUTHTAG_LEN;
  if (op_id == VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC)
    {
      op->tag = src + src_len - NOISE_AUTHTAG_LEN;
      src_len -= NOISE_AUTHTAG_LEN;
      op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
    }
  else
    op->tag = tag_;

  op->src = !src ? src_ : src;
  op->len = src_len;

  op->dst = dst;
  op->key_index = key_index;
  op->aad = aad;
  op->aad_len = aad_len;
  op->iv = iv;

  vnet_crypto_process_ops (vm, op, 1);
  if (op_id == VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC)
    {
      clib_memcpy (dst + src_len, op->tag, NOISE_AUTHTAG_LEN);
    }

  return (op->status == VNET_CRYPTO_OP_STATUS_COMPLETED);
}

enum noise_state_crypt
noise_remote_encrypt (vlib_main_t * vm, noise_remote_t * r, uint32_t * r_idx,
		      uint64_t * nonce, uint8_t * src, size_t srclen,
		      uint8_t * dst)
{
  noise_keypair_t *kp;
  enum noise_state_crypt ret = SC_FAILED;

  if ((kp = r->r_current) == NULL)
    goto error;

  /* We confirm that our values are within our tolerances. We want:
   *  - a valid keypair
   *  - our keypair to be less than REJECT_AFTER_TIME seconds old
   *  - our receive counter to be less than REJECT_AFTER_MESSAGES
   *  - our send counter to be less than REJECT_AFTER_MESSAGES
   */
  if (!kp->kp_valid ||
      wg_birthdate_has_expired (kp->kp_birthdate, REJECT_AFTER_TIME) ||
      kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
      ((*nonce = noise_counter_send (&kp->kp_ctr)) > REJECT_AFTER_MESSAGES))
    goto error;

  /* We encrypt into the same buffer, so the caller must ensure that buf
   * has NOISE_AUTHTAG_LEN bytes to store the MAC. The nonce and index
   * are passed back out to the caller through the provided data pointer. */
  *r_idx = kp->kp_remote_index;

  chacha20poly1305_calc (vm, src, srclen, dst, NULL, 0, *nonce,
			 VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC,
			 kp->kp_send_index);

  /* If our values are still within tolerances, but we are approaching
   * the tolerances, we notify the caller with ESTALE that they should
   * establish a new keypair. The current keypair can continue to be used
   * until the tolerances are hit. We notify if:
   *  - our send counter is valid and not less than REKEY_AFTER_MESSAGES
   *  - we're the initiator and our keypair is older than
   *    REKEY_AFTER_TIME seconds */
  ret = SC_KEEP_KEY_FRESH;
  if ((kp->kp_valid && *nonce >= REKEY_AFTER_MESSAGES) ||
      (kp->kp_is_initiator &&
       wg_birthdate_has_expired (kp->kp_birthdate, REKEY_AFTER_TIME)))
    goto error;

  ret = SC_OK;
error:
  return ret;
}

/* Private functions - these should not be called outside this file under any
 * circumstances. */
static noise_keypair_t *
noise_remote_keypair_allocate (noise_remote_t * r)
{
  noise_keypair_t *kp;
  kp = clib_mem_alloc (sizeof (*kp));
  return kp;
}

static uint32_t
noise_remote_handshake_index_get (noise_remote_t * r)
{
  noise_local_t *local = noise_local_get (r->r_local_idx);
  struct noise_upcall *u = &local->l_upcall;
  return u->u_index_set (r);
}

static void
noise_remote_handshake_index_drop (noise_remote_t * r)
{
  noise_handshake_t *hs = &r->r_handshake;
  noise_local_t *local = noise_local_get (r->r_local_idx);
  struct noise_upcall *u = &local->l_upcall;
  if (hs->hs_state != HS_ZEROED)
    u->u_index_drop (hs->hs_local_index);
}

static void
noise_kdf (uint8_t * a, uint8_t * b, uint8_t * c, const uint8_t * x,
	   size_t a_len, size_t b_len, size_t c_len, size_t x_len,
	   const uint8_t ck[NOISE_HASH_LEN])
{
  uint8_t out[BLAKE2S_HASH_SIZE + 1];
  uint8_t sec[BLAKE2S_HASH_SIZE];

  /* Extract entropy from "x" into sec */
  u32 l = 0;
  HMAC (EVP_blake2s256 (), ck, NOISE_HASH_LEN, x, x_len, sec, &l);
  ASSERT (l == BLAKE2S_HASH_SIZE);
  if (a == NULL || a_len == 0)
    goto out;

  /* Expand first key: key = sec, data = 0x1 */
  out[0] = 1;
  HMAC (EVP_blake2s256 (), sec, BLAKE2S_HASH_SIZE, out, 1, out, &l);
  ASSERT (l == BLAKE2S_HASH_SIZE);
  clib_memcpy (a, out, a_len);

  if (b == NULL || b_len == 0)
    goto out;

  /* Expand second key: key = sec, data = "a" || 0x2 */
  out[BLAKE2S_HASH_SIZE] = 2;
  HMAC (EVP_blake2s256 (), sec, BLAKE2S_HASH_SIZE, out, BLAKE2S_HASH_SIZE + 1,
	out, &l);
  ASSERT (l == BLAKE2S_HASH_SIZE);
  clib_memcpy (b, out, b_len);

  if (c == NULL || c_len == 0)
    goto out;

  /* Expand third key: key = sec, data = "b" || 0x3 */
  out[BLAKE2S_HASH_SIZE] = 3;
  HMAC (EVP_blake2s256 (), sec, BLAKE2S_HASH_SIZE, out, BLAKE2S_HASH_SIZE + 1,
	out, &l);
  ASSERT (l == BLAKE2S_HASH_SIZE);

  clib_memcpy (c, out, c_len);

out:
  /* Clear sensitive data from stack */
  secure_zero_memory (sec, BLAKE2S_HASH_SIZE);
  secure_zero_memory (out, BLAKE2S_HASH_SIZE + 1);
}

static bool
noise_mix_dh (uint8_t ck[NOISE_HASH_LEN],
	      uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
	      const uint8_t private[NOISE_PUBLIC_KEY_LEN],
	      const uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
  uint8_t dh[NOISE_PUBLIC_KEY_LEN];
  if (!curve25519_gen_shared (dh, private, public))
    return false;
  noise_kdf (ck, key, NULL, dh,
	     NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN,
	     ck);
  secure_zero_memory (dh, NOISE_PUBLIC_KEY_LEN);
  return true;
}

static bool
noise_mix_ss (uint8_t ck[NOISE_HASH_LEN],
	      uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
	      const uint8_t ss[NOISE_PUBLIC_KEY_LEN])
{
  static uint8_t null_point[NOISE_PUBLIC_KEY_LEN];
  if (clib_memcmp (ss, null_point, NOISE_PUBLIC_KEY_LEN) == 0)
    return false;
  noise_kdf (ck, key, NULL, ss,
	     NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN,
	     ck);
  return true;
}

static void
noise_mix_hash (uint8_t hash[NOISE_HASH_LEN], const uint8_t * src,
		size_t src_len)
{
  blake2s_state_t blake;

  blake2s_init (&blake, NOISE_HASH_LEN);
  blake2s_update (&blake, hash, NOISE_HASH_LEN);
  blake2s_update (&blake, src, src_len);
  blake2s_final (&blake, hash, NOISE_HASH_LEN);
}

static void
noise_mix_psk (uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
	       uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
	       const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
  uint8_t tmp[NOISE_HASH_LEN];

  noise_kdf (ck, tmp, key, psk,
	     NOISE_HASH_LEN, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN,
	     NOISE_SYMMETRIC_KEY_LEN, ck);
  noise_mix_hash (hash, tmp, NOISE_HASH_LEN);
  secure_zero_memory (tmp, NOISE_HASH_LEN);
}

static void
noise_param_init (uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
		  const uint8_t s[NOISE_PUBLIC_KEY_LEN])
{
  blake2s_state_t blake;

  blake2s (ck, NOISE_HASH_LEN, (uint8_t *) NOISE_HANDSHAKE_NAME,
	   strlen (NOISE_HANDSHAKE_NAME), NULL, 0);

  blake2s_init (&blake, NOISE_HASH_LEN);
  blake2s_update (&blake, ck, NOISE_HASH_LEN);
  blake2s_update (&blake, (uint8_t *) NOISE_IDENTIFIER_NAME,
		  strlen (NOISE_IDENTIFIER_NAME));
  blake2s_final (&blake, hash, NOISE_HASH_LEN);

  noise_mix_hash (hash, s, NOISE_PUBLIC_KEY_LEN);
}

static void
noise_msg_encrypt (vlib_main_t * vm, uint8_t * dst, uint8_t * src,
		   size_t src_len, uint32_t key_idx,
		   uint8_t hash[NOISE_HASH_LEN])
{
  /* Nonce always zero for Noise_IK */
  chacha20poly1305_calc (vm, src, src_len, dst, hash, NOISE_HASH_LEN, 0,
			 VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC, key_idx);
  noise_mix_hash (hash, dst, src_len + NOISE_AUTHTAG_LEN);
}

static bool
noise_msg_decrypt (vlib_main_t * vm, uint8_t * dst, uint8_t * src,
		   size_t src_len, uint32_t key_idx,
		   uint8_t hash[NOISE_HASH_LEN])
{
  /* Nonce always zero for Noise_IK */
  if (!chacha20poly1305_calc (vm, src, src_len, dst, hash, NOISE_HASH_LEN, 0,
			      VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC, key_idx))
    return false;
  noise_mix_hash (hash, src, src_len);
  return true;
}

static void
noise_msg_ephemeral (uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
		     const uint8_t src[NOISE_PUBLIC_KEY_LEN])
{
  noise_mix_hash (hash, src, NOISE_PUBLIC_KEY_LEN);
  noise_kdf (ck, NULL, NULL, src, NOISE_HASH_LEN, 0, 0,
	     NOISE_PUBLIC_KEY_LEN, ck);
}

static void
noise_tai64n_now (uint8_t output[NOISE_TIMESTAMP_LEN])
{
  uint32_t unix_sec;
  uint32_t unix_nanosec;

  uint64_t sec;
  uint32_t nsec;

  unix_time_now_nsec_fraction (&unix_sec, &unix_nanosec);

  /* Round down the nsec counter to limit precise timing leak. */
  unix_nanosec &= REJECT_INTERVAL_MASK;

  /* https://cr.yp.to/libtai/tai64.html */
  sec = htobe64 (0x400000000000000aULL + unix_sec);
  nsec = htobe32 (unix_nanosec);

  /* memcpy to output buffer, assuming output could be unaligned. */
  clib_memcpy (output, &sec, sizeof (sec));
  clib_memcpy (output + sizeof (sec), &nsec, sizeof (nsec));
}

static void
secure_zero_memory (void *v, size_t n)
{
  static void *(*const volatile memset_v) (void *, int, size_t) = &memset;
  memset_v (v, 0, n);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
