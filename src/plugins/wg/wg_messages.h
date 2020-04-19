/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef __included_wg_messages_h__
#define __included_wg_messages_h__

#include <stdint.h>

#include <wg/crypto/include/curve25519.h>
#include <wg/crypto/include/chacha20poly1305.h>
#include <wg/crypto/include/blake2s.h>

#define WG_TICK 0.1				/**< WG tick period (s) */
#define WHZ (u32) (1/WG_TICK)		/**< WG tick frequency */

#ifndef BITS_PER_LONG
#define BITS_PER_LONG 32
#endif

#define NOISE_KEY_LEN_BASE64 ((((NOISE_PUBLIC_KEY_LEN) + 2) / 3) * 4 + 1)

enum noise_lengths
{
  NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
  NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
  NOISE_TIMESTAMP_LEN = sizeof (u64) + sizeof (u32),
  NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAG_SIZE,
  NOISE_HASH_LEN = BLAKE2S_HASHSIZE
};

#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

enum cookie_values
{
  COOKIE_SECRET_MAX_AGE = 2 * 60,
  COOKIE_SECRET_LATENCY = 5,
  COOKIE_NONCE_LEN = XCHACHA20POLY1305_NONCE_SIZE,
  COOKIE_LEN = 16
};

enum counter_values
{
  COUNTER_BITS_TOTAL = 2048,
  COUNTER_REDUNDANT_BITS = BITS_PER_LONG,
  COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS
};

enum limits
{
  REKEY_AFTER_MESSAGES = 1ULL << 60,
  REJECT_AFTER_MESSAGES = UINT64_MAX - COUNTER_WINDOW_SIZE - 1,
  REKEY_TIMEOUT = 5,
  REKEY_TIMEOUT_JITTER = WHZ / 3,
  REKEY_AFTER_TIME = 120,
  REJECT_AFTER_TIME = 180,
  KEEPALIVE_TIMEOUT = 10,
  MAX_TIMER_HANDSHAKES = 90 / REKEY_TIMEOUT,
  MAX_PEERS = 1U << 20
};

#define foreach_wg_message_type	\
  _(INVALID, "Invalid")		\
  _(HANDSHAKE_INITIATION, "Handshake initiation")		\
  _(HANDSHAKE_RESPONSE, "Handshake response") \
  _(HANDSHAKE_COOKIE, "Handshake cookie") \
  _(DATA, "Data") \

typedef enum message_type
{
#define _(v,s) MESSAGE_##v,
  foreach_wg_message_type
#undef _
} message_type_t;

typedef struct message_header
{
  message_type_t type;
} message_header_t;

typedef struct message_macs
{
  u8 mac1[COOKIE_LEN];
  u8 mac2[COOKIE_LEN];
} message_macs_t;

typedef struct message_handshake_initiation
{
  message_header_t header;
  u32 sender_index;
  u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
  u8 encrypted_static[noise_encrypted_len (NOISE_PUBLIC_KEY_LEN)];
  u8 encrypted_timestamp[noise_encrypted_len (NOISE_TIMESTAMP_LEN)];
  message_macs_t macs;
} message_handshake_initiation_t;

typedef struct message_handshake_response
{
  message_header_t header;
  u32 sender_index;
  u32 receiver_index;
  u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
  u8 encrypted_nothing[noise_encrypted_len (0)];
  message_macs_t macs;
} message_handshake_response_t;

typedef struct message_handshake_cookie
{
  message_header_t header;
  u32 receiver_index;
  u8 nonce[COOKIE_NONCE_LEN];
  u8 encrypted_cookie[noise_encrypted_len (COOKIE_LEN)];
} message_handshake_cookie_t;

typedef struct message_data
{
  message_header_t header;
  u32 receiver_index;
  u64 counter;
  u8 encrypted_data[];
} message_data_t;

#define message_data_len(plain_len) \
    (noise_encrypted_len(plain_len) + sizeof(message_data_t))

enum message_alignments
{
  MESSAGE_MINIMUM_LENGTH = message_data_len (0)
};

#endif /* __included_wg_messages_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
