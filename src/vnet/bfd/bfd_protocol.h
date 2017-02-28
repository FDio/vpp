/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
#ifndef __included_bfd_protocol_h__
#define __included_bfd_protocol_h__
/**
 * @file
 * @brief BFD protocol declarations
 */

#include <vppinfra/types.h>
#include <vppinfra/clib.h>

/* auth type value, max key length, name, description */
#define foreach_bfd_auth_type(F)                          \
  F (0, 0, reserved, "Reserved")                          \
  F (1, 16, simple_password, "Simple Password")           \
  F (2, 16, keyed_md5, "Keyed MD5")                       \
  F (3, 16, meticulous_keyed_md5, "Meticulous Keyed MD5") \
  F (4, 20, keyed_sha1, "Keyed SHA1")                     \
  F (5, 20, meticulous_keyed_sha1, "Meticulous Keyed SHA1")

#define BFD_AUTH_TYPE_NAME(t) BFD_AUTH_TYPE_##t

typedef enum
{
#define F(n, l, t, s) BFD_AUTH_TYPE_NAME (t) = n,
  foreach_bfd_auth_type (F)
#undef F
} bfd_auth_type_e;

/**
 * @brief get the maximum length of key data for given auth type
 */
u32 bfd_max_key_len_for_auth_type (bfd_auth_type_e auth_type);
const char *bfd_auth_type_str (bfd_auth_type_e auth_type);

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 type;
  u8 len;
}) bfd_auth_common_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  /*
   * 4.4.  Keyed SHA1 and Meticulous Keyed SHA1 Authentication Section Format

   *     If the Authentication Present (A) bit is set in the header, and the
   *     Authentication Type field contains 4 (Keyed SHA1) or 5 (Meticulous
   *     Keyed SHA1), the Authentication Section has the following format:

   *      0                   1                   2                   3
   *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *     |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
   *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *     |                        Sequence Number                        |
   *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *     |                       Auth Key/Hash...                        |
   *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *     |                              ...                              |
   *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  bfd_auth_common_t type_len;
  u8 key_id;
  u8 reserved;
  u32 seq_num;
  /*
   *  Auth Key/Hash

   *     This field carries the 20-byte SHA1 hash for the packet.  When the
   *     hash is calculated, the shared SHA1 key is stored in this field,
   *     padded to a length of 20 bytes with trailing zero bytes if needed.
   *     The shared key MUST be encoded and configured to section 6.7.4.
   */
  u8 hash[20];
}) bfd_auth_sha1_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  /*
   *  The Mandatory Section of a BFD Control packet has the following
   *  format:

   *   0                   1                   2                   3
   *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                       My Discriminator                        |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                      Your Discriminator                       |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                    Desired Min TX Interval                    |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                   Required Min RX Interval                    |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                 Required Min Echo RX Interval                 |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  struct
  {
    u8 vers_diag;
    u8 sta_flags;
    u8 detect_mult;
    u8 length;
  } head;
  u32 my_disc;
  u32 your_disc;
  u32 des_min_tx;
  u32 req_min_rx;
  u32 req_min_echo_rx;
}) bfd_pkt_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  bfd_pkt_t pkt;
  bfd_auth_common_t common_auth;
}) bfd_pkt_with_common_auth_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  bfd_pkt_t pkt;
  bfd_auth_sha1_t sha1_auth;
}) bfd_pkt_with_sha1_auth_t;
/* *INDENT-ON* */

u8 bfd_pkt_get_version (const bfd_pkt_t * pkt);
void bfd_pkt_set_version (bfd_pkt_t * pkt, int version);
u8 bfd_pkt_get_diag_code (const bfd_pkt_t * pkt);
void bfd_pkt_set_diag_code (bfd_pkt_t * pkt, int value);
u8 bfd_pkt_get_state (const bfd_pkt_t * pkt);
void bfd_pkt_set_state (bfd_pkt_t * pkt, int value);
u8 bfd_pkt_get_poll (const bfd_pkt_t * pkt);
void bfd_pkt_set_final (bfd_pkt_t * pkt);
u8 bfd_pkt_get_final (const bfd_pkt_t * pkt);
void bfd_pkt_set_poll (bfd_pkt_t * pkt);
u8 bfd_pkt_get_control_plane_independent (const bfd_pkt_t * pkt);
void bfd_pkt_set_control_plane_independent (bfd_pkt_t * pkt);
u8 bfd_pkt_get_auth_present (const bfd_pkt_t * pkt);
void bfd_pkt_set_auth_present (bfd_pkt_t * pkt);
u8 bfd_pkt_get_demand (const bfd_pkt_t * pkt);
void bfd_pkt_set_demand (bfd_pkt_t * pkt);
u8 bfd_pkt_get_multipoint (const bfd_pkt_t * pkt);
void bfd_pkt_set_multipoint (bfd_pkt_t * pkt);

/* BFD diagnostic codes */
#define foreach_bfd_diag_code(F)                             \
  F (0, no_diag, "No Diagnostic")                            \
  F (1, det_time_exp, "Control Detection Time Expired")      \
  F (2, echo_failed, "Echo Function Failed")                 \
  F (3, neighbor_sig_down, "Neighbor Signaled Session Down") \
  F (4, fwd_plain_reset, "Forwarding Plane Reset")           \
  F (5, path_down, "Path Down")                              \
  F (6, concat_path_down, "Concatenated Path Down")          \
  F (7, admin_down, "Administratively Down")                 \
  F (8, reverse_concat_path_down, "Reverse Concatenated Path Down")

#define BFD_DIAG_CODE_NAME(t) BFD_DIAG_CODE_##t

typedef enum
{
#define F(n, t, s) BFD_DIAG_CODE_NAME (t) = n,
  foreach_bfd_diag_code (F)
#undef F
} bfd_diag_code_e;

const char *bfd_diag_code_string (bfd_diag_code_e diag);

/* BFD state values */
#define foreach_bfd_state(F)     \
  F (0, admin_down, "AdminDown") \
  F (1, down, "Down")            \
  F (2, init, "Init")            \
  F (3, up, "Up")

#define BFD_STATE_NAME(t) BFD_STATE_##t

typedef enum
{
#define F(n, t, s) BFD_STATE_NAME (t) = n,
  foreach_bfd_state (F)
#undef F
} bfd_state_e;

const char *bfd_state_string (bfd_state_e state);

#endif /* __included_bfd_protocol_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
