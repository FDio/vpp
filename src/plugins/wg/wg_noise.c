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

#include <wg/wg.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

/* Private functions */
static noise_keypair_t *noise_remote_keypair_allocate (noise_remote_t *);
static void noise_remote_keypair_free (noise_remote_t *, noise_keypair_t **);
static uint32_t noise_remote_handshake_index_get (noise_remote_t *);
static void noise_remote_handshake_index_drop (noise_remote_t *);

static uint64_t noise_counter_send (noise_counter_t *);
static bool noise_counter_recv (noise_counter_t *, uint64_t);

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

static void noise_msg_encrypt (uint8_t *, const uint8_t *, size_t,
			       uint8_t[NOISE_SYMMETRIC_KEY_LEN],
			       uint8_t[NOISE_HASH_LEN]);
static bool noise_msg_decrypt (uint8_t *, const uint8_t *, size_t,
			       uint8_t[NOISE_SYMMETRIC_KEY_LEN],
			       uint8_t[NOISE_HASH_LEN]);
static void noise_msg_ephemeral (uint8_t[NOISE_HASH_LEN],
				 uint8_t[NOISE_HASH_LEN],
				 const uint8_t src[NOISE_PUBLIC_KEY_LEN]);

static void noise_tai64n_now (uint8_t[NOISE_TIMESTAMP_LEN]);

/* Set/Get noise parameters */
void
noise_local_init (noise_local_t * l, struct noise_upcall *upcall)
{
  clib_memset (l, 0, sizeof (*l));
  l->l_upcall = *upcall;
}

bool
noise_local_set_private (noise_local_t * l,
			 uint8_t private[NOISE_PUBLIC_KEY_LEN])
{
  clib_memcpy (l->l_private, private, NOISE_PUBLIC_KEY_LEN);
  curve25519_clamp_secret (l->l_private);
  l->l_has_identity = curve25519_gen_public (l->l_public, private);

  return l->l_has_identity;
}

bool
noise_local_keys (noise_local_t * l, uint8_t public[NOISE_PUBLIC_KEY_LEN],
		  uint8_t private[NOISE_PUBLIC_KEY_LEN])
{
  if (l->l_has_identity)
    {
      if (public != NULL)
	clib_memcpy (public, l->l_public, NOISE_PUBLIC_KEY_LEN);
      if (private != NULL)
	clib_memcpy (private, l->l_private, NOISE_PUBLIC_KEY_LEN);
    }
  else
    {
      return false;
    }
  return true;
}

void
noise_remote_init (noise_remote_t * r, uint32_t peer_pool_idx,
		   uint8_t public[NOISE_PUBLIC_KEY_LEN], noise_local_t * l)
{
  clib_memset (r, 0, sizeof (*r));
  clib_memcpy (r->r_public, public, NOISE_PUBLIC_KEY_LEN);
  r->r_peer_idx = peer_pool_idx;

  ASSERT (l != NULL);
  r->r_local = l;
  r->r_handshake.hs_state = HS_ZEROED;
  noise_remote_precompute (r);
}

bool
noise_remote_set_psk (noise_remote_t * r,
		      uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
  int same;
  same = !clib_memcmp (r->r_psk, psk, NOISE_SYMMETRIC_KEY_LEN);
  if (!same)
    {
      clib_memcpy (r->r_psk, psk, NOISE_SYMMETRIC_KEY_LEN);
    }
  return same == 0;
}

bool
noise_remote_keys (noise_remote_t * r, uint8_t public[NOISE_PUBLIC_KEY_LEN],
		   uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
  static uint8_t null_psk[NOISE_SYMMETRIC_KEY_LEN];
  int ret;

  if (public != NULL)
    clib_memcpy (public, r->r_public, NOISE_PUBLIC_KEY_LEN);

  if (psk != NULL)
    clib_memcpy (psk, r->r_psk, NOISE_SYMMETRIC_KEY_LEN);
  ret = clib_memcmp (r->r_psk, null_psk, NOISE_SYMMETRIC_KEY_LEN);

  return ret;
}

void
noise_remote_precompute (noise_remote_t * r)
{
  noise_local_t *l = r->r_local;
  if (!l->l_has_identity)
    clib_memset (r->r_ss, 0, NOISE_PUBLIC_KEY_LEN);
  else if (!curve25519_gen_shared (r->r_ss, l->l_private, r->r_public))
    clib_memset (r->r_ss, 0, NOISE_PUBLIC_KEY_LEN);

  noise_remote_handshake_index_drop (r);
  secure_zero_memory (&r->r_handshake, sizeof (r->r_handshake));
}

/* Handshake functions */
bool
noise_create_initiation (noise_remote_t * r, uint32_t * s_idx,
			 uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			 uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
			 uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN])
{
  noise_handshake_t *hs = &r->r_handshake;
  noise_local_t *l = r->r_local;
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  int ret = false;

  if (!l->l_has_identity)
    goto error;
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
  noise_msg_encrypt (es, l->l_public, NOISE_PUBLIC_KEY_LEN, key, hs->hs_hash);

  /* ss */
  if (!noise_mix_ss (hs->hs_ck, key, r->r_ss))
    goto error;

  /* {t} */
  noise_tai64n_now (ets);
  noise_msg_encrypt (ets, ets, NOISE_TIMESTAMP_LEN, key, hs->hs_hash);
  noise_remote_handshake_index_drop (r);
  hs->hs_state = CREATED_INITIATION;
  hs->hs_local_index = noise_remote_handshake_index_get (r);
  *s_idx = hs->hs_local_index;
  ret = true;
error:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

bool
noise_consume_initiation (noise_local_t * l, noise_remote_t ** rp,
			  uint32_t s_idx, uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			  uint8_t es[NOISE_PUBLIC_KEY_LEN +
				     NOISE_AUTHTAG_LEN],
			  uint8_t ets[NOISE_TIMESTAMP_LEN +
				      NOISE_AUTHTAG_LEN])
{
  noise_remote_t *r;
  noise_handshake_t hs;
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t r_public[NOISE_PUBLIC_KEY_LEN];
  uint8_t timestamp[NOISE_TIMESTAMP_LEN];
  int ret = false;

  if (!l->l_has_identity)
    goto error;
  noise_param_init (hs.hs_ck, hs.hs_hash, l->l_public);

  /* e */
  noise_msg_ephemeral (hs.hs_ck, hs.hs_hash, ue);

  /* es */
  if (!noise_mix_dh (hs.hs_ck, key, l->l_private, ue))
    goto error;

  /* s */
  if (!noise_msg_decrypt (r_public, es,
			  NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN, key,
			  hs.hs_hash))
    goto error;

  /* Lookup the remote we received from */
  if ((r = l->l_upcall.u_remote_get (r_public)) == NULL)
    goto error;

  /* ss */
  if (!noise_mix_ss (hs.hs_ck, key, r->r_ss))
    goto error;

  /* {t} */
  if (!noise_msg_decrypt (timestamp, ets,
			  NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN, key,
			  hs.hs_hash))
    goto error;

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
    r->r_last_init = vlib_time_now (vlib_get_main ());
  else
    goto error;

  /* Ok, we're happy to accept this initiation now */
  noise_remote_handshake_index_drop (r);
  r->r_handshake = hs;
  *rp = r;
  ret = true;
error:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  secure_zero_memory (&hs, sizeof (hs));
  return ret;
}

bool
noise_create_response (noise_remote_t * r, uint32_t * s_idx, uint32_t * r_idx,
		       uint8_t ue[NOISE_PUBLIC_KEY_LEN],
		       uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
  noise_handshake_t *hs = &r->r_handshake;
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t e[NOISE_PUBLIC_KEY_LEN];
  int ret = false;

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
  noise_msg_encrypt (en, NULL, 0, key, hs->hs_hash);

  hs->hs_state = CREATED_RESPONSE;
  hs->hs_local_index = noise_remote_handshake_index_get (r);
  *r_idx = hs->hs_remote_index;
  *s_idx = hs->hs_local_index;
  ret = true;
error:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  secure_zero_memory (e, NOISE_PUBLIC_KEY_LEN);
  return ret;
}

bool
noise_consume_response (noise_remote_t * r, uint32_t s_idx, uint32_t r_idx,
			uint8_t ue[NOISE_PUBLIC_KEY_LEN],
			uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
  noise_local_t *l = r->r_local;
  noise_handshake_t hs;
  uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
  uint8_t preshared_key[NOISE_PUBLIC_KEY_LEN];
  int ret = false;

  if (!l->l_has_identity)
    goto error;

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
  if (!noise_msg_decrypt (NULL, en, 0 + NOISE_AUTHTAG_LEN, key, hs.hs_hash))
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
  return ret;
}

bool
noise_remote_begin_session (noise_remote_t * r)
{
  noise_handshake_t *hs = &r->r_handshake;
  noise_keypair_t kp, *next, *current, *previous;

  /* We now derive the keypair from the handshake */
  if (hs->hs_state == CONSUMED_RESPONSE)
    {
      kp.kp_is_initiator = 1;
      noise_kdf (kp.kp_send, kp.kp_recv, NULL, NULL,
		 NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
		 hs->hs_ck);
    }
  else if (hs->hs_state == CREATED_RESPONSE)
    {
      kp.kp_is_initiator = 0;
      noise_kdf (kp.kp_recv, kp.kp_send, NULL, NULL,
		 NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
		 hs->hs_ck);
    }
  else
    {
      return false;
    }

  kp.kp_valid = 1;
  kp.kp_local_index = hs->hs_local_index;
  kp.kp_remote_index = hs->hs_remote_index;
  kp.kp_birthdate = vlib_time_now (vlib_get_main ());
  clib_memset (&kp.kp_ctr, 0, sizeof (kp.kp_ctr));

  /* Now we need to add_new_keypair */
  next = r->r_next;
  current = r->r_current;
  previous = r->r_previous;

  if (kp.kp_is_initiator)
    {
      if (next != NULL)
	{
	  r->r_next = NULL;
	  r->r_previous = next;
	  noise_remote_keypair_free (r, &current);
	}
      else
	{
	  r->r_previous = current;
	}

      noise_remote_keypair_free (r, &previous);

      r->r_current = noise_remote_keypair_allocate (r);
      *r->r_current = kp;
    }
  else
    {
      noise_remote_keypair_free (r, &next);
      r->r_previous = NULL;
      noise_remote_keypair_free (r, &previous);

      r->r_next = noise_remote_keypair_allocate (r);
      *r->r_next = kp;
    }
  secure_zero_memory (&r->r_handshake, sizeof (r->r_handshake));
  secure_zero_memory (&kp, sizeof (kp));
  return true;
}

void
noise_remote_clear (noise_remote_t * r)
{
  noise_remote_handshake_index_drop (r);
  secure_zero_memory (&r->r_handshake, sizeof (r->r_handshake));

  noise_remote_keypair_free (r, &r->r_next);
  noise_remote_keypair_free (r, &r->r_current);
  noise_remote_keypair_free (r, &r->r_previous);
  r->r_next = NULL;
  r->r_current = NULL;
  r->r_previous = NULL;
}

void
noise_remote_expire_current (noise_remote_t * r)
{
  if (r->r_next != NULL)
    r->r_next->kp_valid = 0;
  if (r->r_current != NULL)
    r->r_current->kp_valid = 0;
}

bool
noise_remote_ready (noise_remote_t * r)
{
  noise_keypair_t *kp;
  int ret;

  if ((kp = r->r_current) == NULL ||
      !kp->kp_valid ||
      wg_birthdate_has_expired (kp->kp_birthdate, REJECT_AFTER_TIME) ||
      kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES ||
      kp->kp_ctr.c_send >= REJECT_AFTER_MESSAGES)
    ret = false;
  else
    ret = true;
  return ret;
}

enum noise_state_crypt
noise_remote_encrypt (noise_remote_t * r, uint32_t * r_idx, uint64_t * nonce,
		      uint8_t * src, size_t srclen, uint8_t * dst)
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
  chacha20poly1305_encrypt (dst, src, srclen, NULL, 0, *nonce, kp->kp_send);

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

enum noise_state_crypt
noise_remote_decrypt (noise_remote_t * r, uint32_t r_idx, uint64_t nonce,
		      uint8_t * src, size_t srclen, uint8_t * dst)
{
  noise_keypair_t *kp;
  enum noise_state_crypt ret = SC_FAILED;

  if (r->r_current != NULL && r->r_current->kp_local_index == r_idx)
    {
      kp = r->r_current;
    }
  else if (r->r_previous != NULL && r->r_previous->kp_local_index == r_idx)
    {
      kp = r->r_previous;
    }
  else if (r->r_next != NULL && r->r_next->kp_local_index == r_idx)
    {
      kp = r->r_next;
    }
  else
    {
      goto error;
    }

  /* We confirm that our values are within our tolerances. These values
   * are the same as the encrypt routine.
   *
   * kp_ctr isn't locked here, we're happy to accept a racy read. */
  if (wg_birthdate_has_expired (kp->kp_birthdate, REJECT_AFTER_TIME) ||
      kp->kp_ctr.c_recv >= REJECT_AFTER_MESSAGES)
    goto error;

  /* Decrypt, then validate the counter. We don't want to validate the
   * counter before decrypting as we do not know the message is authentic
   * prior to decryption. */
  if (chacha20poly1305_decrypt (dst, src, srclen,
				NULL, 0, nonce, kp->kp_recv) == 0)
    goto error;

  if (!noise_counter_recv (&kp->kp_ctr, nonce))
    goto error;

  /* If we've received the handshake confirming data packet then move the
   * next keypair into current. If we do slide the next keypair in, then
   * we skip the REKEY_AFTER_TIME_RECV check. This is safe to do as a
   * data packet can't confirm a session that we are an INITIATOR of. */
  if (kp == r->r_next && kp->kp_local_index == r_idx)
    {
      noise_remote_keypair_free (r, &r->r_previous);
      r->r_previous = r->r_current;
      r->r_current = r->r_next;
      r->r_next = NULL;

      ret = SC_CONN_RESET;
      goto error;
    }


  /* Similar to when we encrypt, we want to notify the caller when we
   * are approaching our tolerances. We notify if:
   *  - we're the initiator and the current keypair is older than
   *    REKEY_AFTER_TIME_RECV seconds. */
  ret = SC_KEEP_KEY_FRESH;
  kp = r->r_current;
  if (kp != NULL &&
      kp->kp_valid &&
      kp->kp_is_initiator &&
      wg_birthdate_has_expired (kp->kp_birthdate, REKEY_AFTER_TIME_RECV))
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

static void
noise_remote_keypair_free (noise_remote_t * r, noise_keypair_t ** kp)
{
  struct noise_upcall *u = &r->r_local->l_upcall;
  if (*kp)
    {
      u->u_index_drop ((*kp)->kp_local_index);

      clib_memset ((*kp)->kp_send, 0, sizeof ((*kp)->kp_send));
      clib_memset ((*kp)->kp_recv, 0, sizeof ((*kp)->kp_recv));
      clib_mem_free (*kp);
    }
}

static uint32_t
noise_remote_handshake_index_get (noise_remote_t * r)
{
  struct noise_upcall *u = &r->r_local->l_upcall;
  return u->u_index_set (r);
}

static void
noise_remote_handshake_index_drop (noise_remote_t * r)
{
  noise_handshake_t *hs = &r->r_handshake;
  struct noise_upcall *u = &r->r_local->l_upcall;
  if (hs->hs_state != HS_ZEROED)
    u->u_index_drop (hs->hs_local_index);
}

static uint64_t
noise_counter_send (noise_counter_t * ctr)
{
  uint64_t ret = ctr->c_send++;
  return ret;
}

static bool
noise_counter_recv (noise_counter_t * ctr, uint64_t recv)
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

static void
noise_kdf (uint8_t * a, uint8_t * b, uint8_t * c, const uint8_t * x,
	   size_t a_len, size_t b_len, size_t c_len, size_t x_len,
	   const uint8_t ck[NOISE_HASH_LEN])
{
  uint8_t out[BLAKE2S_HASH_SIZE + 1];
  uint8_t sec[BLAKE2S_HASH_SIZE];

  /* Extract entropy from "x" into sec */
  blake2s_hmac (sec, x, ck, BLAKE2S_HASH_SIZE, x_len, NOISE_HASH_LEN);

  if (a == NULL || a_len == 0)
    goto out;

  /* Expand first key: key = sec, data = 0x1 */
  out[0] = 1;
  blake2s_hmac (out, out, sec, BLAKE2S_HASH_SIZE, 1, BLAKE2S_HASH_SIZE);
  clib_memcpy (a, out, a_len);

  if (b == NULL || b_len == 0)
    goto out;

  /* Expand second key: key = sec, data = "a" || 0x2 */
  out[BLAKE2S_HASH_SIZE] = 2;
  blake2s_hmac (out, out, sec, BLAKE2S_HASH_SIZE, BLAKE2S_HASH_SIZE + 1,
		BLAKE2S_HASH_SIZE);
  clib_memcpy (b, out, b_len);

  if (c == NULL || c_len == 0)
    goto out;

  /* Expand third key: key = sec, data = "b" || 0x3 */
  out[BLAKE2S_HASH_SIZE] = 3;
  blake2s_hmac (out, out, sec, BLAKE2S_HASH_SIZE, BLAKE2S_HASH_SIZE + 1,
		BLAKE2S_HASH_SIZE);

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
  blake2s_final (&blake, hash);
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

  blake2s (ck, (uint8_t *) NOISE_HANDSHAKE_NAME, NULL, NOISE_HASH_LEN,
	   strlen (NOISE_HANDSHAKE_NAME), 0);
  blake2s_init (&blake, NOISE_HASH_LEN);
  blake2s_update (&blake, ck, NOISE_HASH_LEN);
  blake2s_update (&blake, (uint8_t *) NOISE_IDENTIFIER_NAME,
		  strlen (NOISE_IDENTIFIER_NAME));
  blake2s_final (&blake, hash);

  noise_mix_hash (hash, s, NOISE_PUBLIC_KEY_LEN);
}

static void
noise_msg_encrypt (uint8_t * dst, const uint8_t * src, size_t src_len,
		   uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
		   uint8_t hash[NOISE_HASH_LEN])
{
  /* Nonce always zero for Noise_IK */
  chacha20poly1305_encrypt (dst, src, src_len, hash, NOISE_HASH_LEN, 0, key);
  noise_mix_hash (hash, dst, src_len + NOISE_AUTHTAG_LEN);
}

static bool
noise_msg_decrypt (uint8_t * dst, const uint8_t * src, size_t src_len,
		   uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
		   uint8_t hash[NOISE_HASH_LEN])
{
  /* Nonce always zero for Noise_IK */
  if (!chacha20poly1305_decrypt (dst, src, src_len,
				 hash, NOISE_HASH_LEN, 0, key))
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
