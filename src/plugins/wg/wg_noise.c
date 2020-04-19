// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <openssl/hmac.h>
#include <wg/wg.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static const u8 handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static u8 handshake_init_hash[NOISE_HASH_LEN];
static u8 handshake_init_chaining_key[NOISE_HASH_LEN];
static u64 keypair_counter = 0;

void
wg_noise_init ()
{
  blake2s_state_t blake;

  blake2s (handshake_init_chaining_key, NOISE_HASH_LEN, handshake_name,
	   sizeof (handshake_name), NULL, 0);
  blake2s_init (&blake, NOISE_HASH_LEN);
  blake2s_update (&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
  blake2s_update (&blake, identifier_name, sizeof (identifier_name));
  blake2s_final (&blake, handshake_init_hash, NOISE_HASH_LEN);
}

void
wg_noise_handshake_init (wg_peer_t * peer,
			 noise_static_identity_t * static_identity,
			 const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN],
			 const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
  noise_handshake_t *handshake = &peer->handshake;
  memset (handshake, 0, sizeof (*handshake));
  handshake->peer = peer;
  memcpy (handshake->remote_static, peer_public_key, NOISE_PUBLIC_KEY_LEN);
  if (peer_preshared_key)
    memcpy (handshake->preshared_key, peer_preshared_key,
	    NOISE_SYMMETRIC_KEY_LEN);
  handshake->static_identity = static_identity;
  handshake->state = HANDSHAKE_ZEROED;
  wg_noise_precompute_static_static (handshake);
}

static void
handshake_zero (noise_handshake_t * handshake)
{
  clib_memset (&handshake->ephemeral_private, 0, NOISE_PUBLIC_KEY_LEN);
  clib_memset (&handshake->remote_ephemeral, 0, NOISE_PUBLIC_KEY_LEN);
  clib_memset (&handshake->hash, 0, NOISE_HASH_LEN);
  clib_memset (&handshake->chaining_key, 0, NOISE_HASH_LEN);
  handshake->remote_index = 0;
  handshake->local_index = 0;
  handshake->state = HANDSHAKE_ZEROED;
}

void
wg_noise_handshake_clear (noise_handshake_t * handshake)
{
  wg_main_t *wmp = &wg_main;

  wg_index_table_del (&wmp->index_table, handshake->local_index);
  handshake_zero (handshake);
}

static void
del_keypair (wg_index_table_t * table, noise_keypair_t ** keypair)
{
  if (*keypair)
    {
      wg_index_table_del (table, (*keypair)->local_index);
      clib_mem_free (*keypair);
      *keypair = NULL;
    }
}

void
wg_noise_keypairs_clear (noise_keypairs_t * keypairs)
{
  wg_main_t *wmp = &wg_main;
  del_keypair (&wmp->index_table, &keypairs->next_keypair);
  del_keypair (&wmp->index_table, &keypairs->previous_keypair);
  del_keypair (&wmp->index_table, &keypairs->current_keypair);
}

bool
wg_noise_received_with_keypair (wg_index_table_t * table,
				noise_keypairs_t * keypairs,
				noise_keypair_t * new_keypair)
{
  noise_keypair_t *old_keypair;

  if (keypairs->next_keypair != new_keypair)
    {
      return false;
    }

  old_keypair = keypairs->previous_keypair;
  keypairs->previous_keypair = keypairs->current_keypair;
  keypairs->current_keypair = keypairs->next_keypair;
  keypairs->next_keypair = NULL;

  del_keypair (table, &old_keypair);

  return true;
}

void
wg_noise_set_static_identity_private_key (noise_static_identity_t *
					  static_identity,
					  const u8
					  private_key[NOISE_PUBLIC_KEY_LEN])
{
  clib_memcpy (static_identity->static_private, private_key,
	       NOISE_PUBLIC_KEY_LEN);
  curve25519_clamp_secret (static_identity->static_private);
  static_identity->has_identity =
    curve25519_gen_public (static_identity->static_public, private_key);
}

void
wg_noise_precompute_static_static (noise_handshake_t * handshake)
{
  if (!handshake->static_identity->has_identity ||
      !curve25519_gen_shared (handshake->precomputed_static_static,
			      handshake->static_identity->static_private,
			      handshake->remote_static))
    memset (handshake->precomputed_static_static, 0, NOISE_PUBLIC_KEY_LEN);
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static void
kdf (u8 * first_dst, u8 * second_dst, u8 * third_dst, const u8 * data,
     size_t first_len, size_t second_len, size_t third_len,
     size_t data_len, const u8 chaining_key[NOISE_HASH_LEN])
{
  u8 output[BLAKE2S_HASHSIZE + 1];
  u8 secret[BLAKE2S_HASHSIZE];

  /* Extract entropy from data into secret */
  u32 l = 0;
  HMAC (EVP_blake2s256 (), chaining_key, NOISE_HASH_LEN, data, data_len,
	secret, &l);
  ASSERT (l == BLAKE2S_HASHSIZE);

  if (!first_dst || !first_len)
    goto out;

  /* Expand first key: key = secret, data = 0x1 */
  output[0] = 1;
  HMAC (EVP_blake2s256 (), secret, BLAKE2S_HASHSIZE, output, 1, output, &l);
  ASSERT (l == BLAKE2S_HASHSIZE);

  clib_memcpy (first_dst, output, first_len);

  if (!second_dst || !second_len)
    goto out;

  /* Expand second key: key = secret, data = first-key || 0x2 */
  output[BLAKE2S_HASHSIZE] = 2;
  HMAC (EVP_blake2s256 (), secret, BLAKE2S_HASHSIZE, output,
	BLAKE2S_HASHSIZE + 1, output, &l);
  ASSERT (l == BLAKE2S_HASHSIZE);

  clib_memcpy (second_dst, output, second_len);

  if (!third_dst || !third_len)
    goto out;

  /* Expand third key: key = secret, data = second-key || 0x3 */
  output[BLAKE2S_HASHSIZE] = 3;
  HMAC (EVP_blake2s256 (), secret, BLAKE2S_HASHSIZE, output,
	BLAKE2S_HASHSIZE + 1, output, &l);
  ASSERT (l == BLAKE2S_HASHSIZE);

  clib_memcpy (third_dst, output, third_len);

out:
  /* Clear sensitive data from stack */
  secure_zero_memory (secret, BLAKE2S_HASHSIZE);
  secure_zero_memory (output, BLAKE2S_HASHSIZE + 1);
}

static void
symmetric_key_init (noise_symmetric_key_t * key, f64 now)
{
  key->counter.counter = 0;
  clib_memset (key->counter.receive.backtrack, 0,
	       sizeof (key->counter.receive.backtrack));
  key->birthdate = now;
  key->is_valid = true;
}

static void
derive_keys (noise_symmetric_key_t * first_dst,
	     noise_symmetric_key_t * second_dst,
	     const u8 chaining_key[NOISE_HASH_LEN], f64 now)
{
  kdf (first_dst->key, second_dst->key, NULL, NULL,
       NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0, chaining_key);
  symmetric_key_init (first_dst, now);
  symmetric_key_init (second_dst, now);
}

static bool
mix_dh (u8 chaining_key[NOISE_HASH_LEN],
	u8 key[NOISE_SYMMETRIC_KEY_LEN],
	const u8 private[NOISE_PUBLIC_KEY_LEN],
	const u8 public[NOISE_PUBLIC_KEY_LEN])
{
  u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];

  if (!curve25519_gen_shared (dh_calculation, private, public))
    return false;
  kdf (chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN,
       NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
  secure_zero_memory (dh_calculation, NOISE_PUBLIC_KEY_LEN);
  return true;
}

static bool
mix_precomputed_dh (u8 chaining_key[NOISE_HASH_LEN],
		    u8 key[NOISE_SYMMETRIC_KEY_LEN],
		    const u8 precomputed[NOISE_PUBLIC_KEY_LEN])
{
  static u8 zero_point[NOISE_PUBLIC_KEY_LEN];
  if (!memcmp (precomputed, zero_point, NOISE_PUBLIC_KEY_LEN))
    return false;
  kdf (chaining_key, key, NULL, precomputed, NOISE_HASH_LEN,
       NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
  return true;
}

static void
mix_hash (u8 hash[NOISE_HASH_LEN], const u8 * src, size_t src_len)
{
  blake2s_state_t blake;

  blake2s_init (&blake, NOISE_HASH_LEN);
  blake2s_update (&blake, hash, NOISE_HASH_LEN);
  blake2s_update (&blake, src, src_len);
  blake2s_final (&blake, hash, NOISE_HASH_LEN);
}

static void
mix_psk (u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN],
	 u8 key[NOISE_SYMMETRIC_KEY_LEN],
	 const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
  u8 temp_hash[NOISE_HASH_LEN];

  kdf (chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN,
       NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
  mix_hash (hash, temp_hash, NOISE_HASH_LEN);
  secure_zero_memory (temp_hash, NOISE_HASH_LEN);
}

static void
handshake_init (u8 chaining_key[NOISE_HASH_LEN],
		u8 hash[NOISE_HASH_LEN],
		const u8 remote_static[NOISE_PUBLIC_KEY_LEN])
{
  clib_memcpy (hash, handshake_init_hash, NOISE_HASH_LEN);
  clib_memcpy (chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
  mix_hash (hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void
message_encrypt (u8 * dst_ciphertext, const u8 * src_plaintext,
		 size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
		 u8 hash[NOISE_HASH_LEN])
{
  chacha20poly1305_encrypt (dst_ciphertext, src_plaintext, src_len, hash,
			    NOISE_HASH_LEN,
			    0 /* Always zero for Noise_IK */ , key);
  mix_hash (hash, dst_ciphertext, noise_encrypted_len (src_len));
}

static bool
message_decrypt (u8 * dst_plaintext, const u8 * src_ciphertext,
		 size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
		 u8 hash[NOISE_HASH_LEN])
{
  if (!chacha20poly1305_decrypt (dst_plaintext, src_ciphertext, src_len,
				 hash, NOISE_HASH_LEN,
				 0 /* Always zero for Noise_IK */ , key))
    return false;
  mix_hash (hash, src_ciphertext, src_len);
  return true;
}

static void
message_ephemeral (u8 ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
		   const u8 ephemeral_src[NOISE_PUBLIC_KEY_LEN],
		   u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN])
{
  if (ephemeral_dst != ephemeral_src)
    memcpy (ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
  mix_hash (hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
  kdf (chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0,
       NOISE_PUBLIC_KEY_LEN, chaining_key);
}

static void
tai64n_now (vlib_main_t * vm, u8 output[NOISE_TIMESTAMP_LEN])
{
  //TODO: check this method.
  u64 timeNow = vlib_time_now (vm);
  if (!CLIB_ARCH_IS_BIG_ENDIAN)
    {
      *(u64 *) output = clib_byte_swap_u64 (0x400000000000000aULL + timeNow);
    }
  else
    {
      *(u64 *) output = (0x400000000000000aULL + timeNow);
    }
}

bool
wg_noise_handshake_create_initiation (vlib_main_t * vm,
				      message_handshake_initiation_t * dst,
				      wg_peer_t * peer,
				      wg_index_table_t * index_table,
				      wg_peer_t * peer_pool)
{
  u8 timestamp[NOISE_TIMESTAMP_LEN];
  u8 key[NOISE_SYMMETRIC_KEY_LEN];
  bool ret = false;

  noise_handshake_t *handshake = &peer->handshake;

  if (!handshake->static_identity->has_identity)
    goto out;

  dst->header.type = MESSAGE_HANDSHAKE_INITIATION;

  handshake_init (handshake->chaining_key, handshake->hash,
		  handshake->remote_static);

  /* e */
  curve25519_gen_secret (handshake->ephemeral_private);
  if (!curve25519_gen_public (dst->unencrypted_ephemeral,
			      handshake->ephemeral_private))
    goto out;
  message_ephemeral (dst->unencrypted_ephemeral,
		     dst->unencrypted_ephemeral, handshake->chaining_key,
		     handshake->hash);

  /* es */
  if (!mix_dh (handshake->chaining_key, key, handshake->ephemeral_private,
	       handshake->remote_static))
    goto out;

  /* s */
  message_encrypt (dst->encrypted_static,
		   handshake->static_identity->static_public,
		   NOISE_PUBLIC_KEY_LEN, key, handshake->hash);

  /* ss */
  if (!mix_precomputed_dh (handshake->chaining_key, key,
			   handshake->precomputed_static_static))
    goto out;

  /* {t} */
  tai64n_now (vm, timestamp);
  message_encrypt (dst->encrypted_timestamp, timestamp,
		   NOISE_TIMESTAMP_LEN, key, handshake->hash);

  dst->sender_index = wg_index_table_add (index_table, peer - peer_pool);
  handshake->local_index = dst->sender_index;

  handshake->state = HANDSHAKE_CREATED_INITIATION;
  ret = true;

out:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

wg_peer_t *
wg_noise_handshake_consume_response (message_handshake_response_t * src,
				     noise_static_identity_t *
				     static_identify,
				     wg_index_table_t * index_table,
				     wg_peer_t * peer_pool)
{
  enum noise_handshake_state state = HANDSHAKE_ZEROED;
  wg_peer_t *peer = NULL, *ret_peer = NULL;
  noise_handshake_t *handshake;
  u8 key[NOISE_SYMMETRIC_KEY_LEN];
  u8 hash[NOISE_HASH_LEN];
  u8 chaining_key[NOISE_HASH_LEN];
  u8 e[NOISE_PUBLIC_KEY_LEN];
  u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
  u8 static_private[NOISE_PUBLIC_KEY_LEN];

  if (!static_identify->has_identity)
    goto out;

  index_table_entry_t *entry =
    wg_index_table_lookup (index_table, src->receiver_index);
  if (entry)
    {
      peer = pool_elt_at_index (peer_pool, entry->peer_pool_idx);
      handshake = &peer->handshake;
      if (!handshake || !peer)
	goto out;
    }
  else
    {
      goto out;
    }

  state = handshake->state;
  clib_memcpy (hash, handshake->hash, NOISE_HASH_LEN);
  clib_memcpy (chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
  clib_memcpy (ephemeral_private, handshake->ephemeral_private,
	       NOISE_PUBLIC_KEY_LEN);

  if (state != HANDSHAKE_CREATED_INITIATION)
    goto out;

  /* e */
  message_ephemeral (e, src->unencrypted_ephemeral, chaining_key, hash);

  /* ee */
  if (!mix_dh (chaining_key, NULL, ephemeral_private, e))
    goto out;

  /* se */
  if (!mix_dh (chaining_key, NULL, static_identify->static_private, e))
    goto out;

  /* psk */
  mix_psk (chaining_key, hash, key, handshake->preshared_key);

  /* {} */
  if (!message_decrypt (NULL, src->encrypted_nothing,
			sizeof (src->encrypted_nothing), key, hash))
    goto out;

  if (handshake->state != state)
    {
      goto out;
    }
  clib_memcpy (handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
  clib_memcpy (handshake->hash, hash, NOISE_HASH_LEN);
  clib_memcpy (handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = src->sender_index;
  handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
  ret_peer = peer;

out:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  secure_zero_memory (hash, NOISE_HASH_LEN);
  secure_zero_memory (chaining_key, NOISE_HASH_LEN);
  secure_zero_memory (ephemeral_private, NOISE_PUBLIC_KEY_LEN);
  secure_zero_memory (static_private, NOISE_PUBLIC_KEY_LEN);
  return ret_peer;
}

bool
wg_noise_handshake_create_response (message_handshake_response_t * dst,
				    wg_peer_t * peer,
				    wg_index_table_t * index_table,
				    wg_peer_t * peer_pool)
{
  u8 key[NOISE_SYMMETRIC_KEY_LEN];
  bool ret = false;

  noise_handshake_t *handshake = &peer->handshake;

  if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
    goto out;

  dst->header.type = MESSAGE_HANDSHAKE_RESPONSE;
  dst->receiver_index = handshake->remote_index;

  /* e */
  curve25519_gen_secret (handshake->ephemeral_private);
  if (!curve25519_gen_public (dst->unencrypted_ephemeral,
			      handshake->ephemeral_private))
    goto out;
  message_ephemeral (dst->unencrypted_ephemeral,
		     dst->unencrypted_ephemeral, handshake->chaining_key,
		     handshake->hash);

  /* ee */
  if (!mix_dh (handshake->chaining_key, NULL, handshake->ephemeral_private,
	       handshake->remote_ephemeral))
    goto out;

  /* se */
  if (!mix_dh (handshake->chaining_key, NULL, handshake->ephemeral_private,
	       handshake->remote_static))
    goto out;

  /* psk */
  mix_psk (handshake->chaining_key, handshake->hash, key,
	   handshake->preshared_key);

  /* {} */
  message_encrypt (dst->encrypted_nothing, NULL, 0, key, handshake->hash);

  dst->sender_index = wg_index_table_add (index_table, peer - peer_pool);
  handshake->local_index = dst->sender_index;

  handshake->state = HANDSHAKE_CREATED_RESPONSE;
  ret = true;

out:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  return ret;
}

static void
add_new_keypair (wg_index_table_t * table, noise_keypairs_t * keypairs,
		 noise_keypair_t * new_keypair)
{
  noise_keypair_t *next_keypair, *current_keypair, *previous_keypair;

  next_keypair = keypairs->next_keypair;
  current_keypair = keypairs->current_keypair;
  previous_keypair = keypairs->previous_keypair;

  if (new_keypair->i_am_the_initiator)
    {
      if (next_keypair)
	{
	  keypairs->next_keypair = NULL;
	  keypairs->previous_keypair = next_keypair;
	  del_keypair (table, &current_keypair);
	}
      else
	{
	  keypairs->previous_keypair = current_keypair;
	}

      del_keypair (table, &previous_keypair);
      keypairs->current_keypair = new_keypair;
    }
  else
    {
      keypairs->next_keypair = new_keypair;
      del_keypair (table, &next_keypair);
      keypairs->previous_keypair = NULL;
      del_keypair (table, &previous_keypair);
    }
}

static noise_keypair_t *
keypair_create (wg_peer_t * peer)
{
  noise_keypair_t *keypair = clib_mem_alloc (sizeof (*keypair));

  if (!keypair)
    return NULL;
  keypair->internal_id = keypair_counter++;
  return keypair;
}



bool
wg_noise_handshake_begin_session (vlib_main_t * vm,
				  noise_handshake_t * handshake,
				  noise_keypairs_t * keypairs)
{
  f64 now;
  noise_keypair_t *new_keypair;
  bool ret = false;

  if (handshake->state != HANDSHAKE_CREATED_RESPONSE &&
      handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
    goto out;

  new_keypair = keypair_create (handshake->peer);
  if (!new_keypair)
    goto out;

  new_keypair->i_am_the_initiator = handshake->state ==
    HANDSHAKE_CONSUMED_RESPONSE;
  new_keypair->remote_index = handshake->remote_index;
  new_keypair->local_index = handshake->local_index;

  now = vlib_time_now (vm);
  if (new_keypair->i_am_the_initiator)
    derive_keys (&new_keypair->sending, &new_keypair->receiving,
		 handshake->chaining_key, now);
  else
    derive_keys (&new_keypair->receiving, &new_keypair->sending,
		 handshake->chaining_key, now);

  wg_main_t *wmp = &wg_main;
  wg_index_table_add_keypair (&wmp->index_table, handshake->local_index,
			      new_keypair);
  handshake_zero (handshake);

  if (!handshake->peer->is_dead)
    {
      add_new_keypair (&wmp->index_table, keypairs, new_keypair);
      ret = true;
    }

out:
  return ret;
}

wg_peer_t *
wg_noise_handshake_consume_initiation (message_handshake_initiation_t * src,
				       noise_static_identity_t *
				       static_identify, wg_peer_t * peer_pool)
{
  wg_peer_t *peer = NULL, *ret_peer = NULL;
  noise_handshake_t *handshake;
  u8 key[NOISE_SYMMETRIC_KEY_LEN];
  u8 chaining_key[NOISE_HASH_LEN];
  u8 hash[NOISE_HASH_LEN];
  u8 s[NOISE_PUBLIC_KEY_LEN];
  u8 e[NOISE_PUBLIC_KEY_LEN];
  u8 t[NOISE_TIMESTAMP_LEN];

  if (!static_identify->has_identity)
    goto out;

  handshake_init (chaining_key, hash, static_identify->static_public);

  /* e */
  message_ephemeral (e, src->unencrypted_ephemeral, chaining_key, hash);

  /* es */
  if (!mix_dh (chaining_key, key, static_identify->static_private, e))
    goto out;

  /* s */
  if (!message_decrypt (s, src->encrypted_static,
			sizeof (src->encrypted_static), key, hash))
    goto out;

  wg_peer_t *peer_iter;
  pool_foreach (peer_iter, peer_pool, (
					{
					if (!memcmp
					    (peer_iter->
					     handshake.remote_static, s,
					     NOISE_PUBLIC_KEY_LEN))
					{
					peer = peer_iter; break;}
					}
		));
  if (!peer)
    {
      return NULL;
    }

  handshake = &peer->handshake;

  /* ss */
  if (!mix_precomputed_dh (chaining_key, key,
			   handshake->precomputed_static_static))
    goto out;

  /* {t} */
  if (!message_decrypt (t, src->encrypted_timestamp,
			sizeof (src->encrypted_timestamp), key, hash))
    goto out;

  clib_memcpy (handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
  if (memcmp (t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
    clib_memcpy (handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
  clib_memcpy (handshake->hash, hash, NOISE_HASH_LEN);
  clib_memcpy (handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
  handshake->remote_index = src->sender_index;
  handshake->state = HANDSHAKE_CONSUMED_INITIATION;
  ret_peer = peer;

out:
  secure_zero_memory (key, NOISE_SYMMETRIC_KEY_LEN);
  secure_zero_memory (hash, NOISE_HASH_LEN);
  secure_zero_memory (chaining_key, NOISE_HASH_LEN);
  return ret_peer;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
