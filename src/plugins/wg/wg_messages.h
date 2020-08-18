/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#ifndef __included_wg_messages_h__
#define __included_wg_messages_h__

#include <stdint.h>
#include <wg/wg_noise.h>
#include <wg/wg_cookie.h>

#define WG_TICK 0.01				/**< WG tick period (s) */
#define WHZ (u32) (1/WG_TICK)		/**< WG tick frequency */

#define NOISE_KEY_LEN_BASE64 ((((NOISE_PUBLIC_KEY_LEN) + 2) / 3) * 4 + 1)
#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

enum limits
{
  REKEY_TIMEOUT = 5,
  REKEY_TIMEOUT_JITTER = WHZ / 3,
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
  u8 nonce[COOKIE_NONCE_SIZE];
  u8 encrypted_cookie[noise_encrypted_len (COOKIE_MAC_SIZE)];
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

#endif /* __included_wg_messages_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
