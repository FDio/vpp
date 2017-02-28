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
/**
 * @file
 * @brief BFD protocol implementation
 */
#include <vnet/bfd/bfd_protocol.h>

u8
bfd_pkt_get_version (const bfd_pkt_t * pkt)
{
  return pkt->head.vers_diag >> 5;
}

void
bfd_pkt_set_version (bfd_pkt_t * pkt, int version)
{
  pkt->head.vers_diag =
    (version << 5) | (pkt->head.vers_diag & ((1 << 5) - 1));
}

u8
bfd_pkt_get_diag_code (const bfd_pkt_t * pkt)
{
  return pkt->head.vers_diag & ((1 << 5) - 1);
}

void
bfd_pkt_set_diag_code (bfd_pkt_t * pkt, int value)
{
  pkt->head.vers_diag =
    (pkt->head.vers_diag & ~((1 << 5) - 1)) | (value & ((1 << 5) - 1));
}

u8
bfd_pkt_get_state (const bfd_pkt_t * pkt)
{
  return pkt->head.sta_flags >> 6;
}

void
bfd_pkt_set_state (bfd_pkt_t * pkt, int value)
{
  pkt->head.sta_flags = (value << 6) | (pkt->head.sta_flags & ((1 << 6) - 1));
}

u8
bfd_pkt_get_poll (const bfd_pkt_t * pkt)
{
  return (pkt->head.sta_flags >> 5) & 1;
}

void
bfd_pkt_set_poll (bfd_pkt_t * pkt)
{
  pkt->head.sta_flags |= 1 << 5;
}

u8
bfd_pkt_get_final (const bfd_pkt_t * pkt)
{
  return (pkt->head.sta_flags >> 4) & 1;
}

void
bfd_pkt_set_final (bfd_pkt_t * pkt)
{
  pkt->head.sta_flags |= 1 << 4;
}

u8
bfd_pkt_get_control_plane_independent (const bfd_pkt_t * pkt)
{
  return (pkt->head.sta_flags >> 3) & 1;
}

#if 0
void
bfd_pkt_set_control_plane_independent (bfd_pkt_t * pkt)
{
  pkt->head.sta_flags |= 1 << 3;
}
#endif

u8
bfd_pkt_get_auth_present (const bfd_pkt_t * pkt)
{
  return (pkt->head.sta_flags >> 2) & 1;
}

void
bfd_pkt_set_auth_present (bfd_pkt_t * pkt)
{
  pkt->head.sta_flags |= 1 << 2;
}

u8
bfd_pkt_get_demand (const bfd_pkt_t * pkt)
{
  return (pkt->head.sta_flags >> 1) & 1;
}

#if 0
void
bfd_pkt_set_demand (bfd_pkt_t * pkt)
{
  pkt->head.sta_flags |= 1 << 1;
}
#endif

u8
bfd_pkt_get_multipoint (const bfd_pkt_t * pkt)
{
  return (pkt->head.sta_flags >> 0) & 1;
}

#if 0
void
bfd_pkt_set_multipoint (bfd_pkt_t * pkt)
{
  pkt->head.sta_flags |= 1 << 0;
}
#endif

u32
bfd_max_key_len_for_auth_type (bfd_auth_type_e auth_type)
{
#define F(t, l, n, s) \
  if (auth_type == t) \
    {                 \
      return l;       \
    }
  foreach_bfd_auth_type (F);
#undef F
  return 0;
}

const char *
bfd_auth_type_str (bfd_auth_type_e auth_type)
{
#define F(t, l, n, s) \
  if (auth_type == t) \
    {                 \
      return s;       \
    }
  foreach_bfd_auth_type (F);
#undef F
  return "UNKNOWN";
}

const char *
bfd_diag_code_string (bfd_diag_code_e diag)
{
#define F(n, t, s)             \
  case BFD_DIAG_CODE_NAME (t): \
    return s;
  switch (diag)
    {
    foreach_bfd_diag_code (F)}
  return "UNKNOWN";
#undef F
}

const char *
bfd_state_string (bfd_state_e state)
{
#define F(n, t, s)         \
  case BFD_STATE_NAME (t): \
    return s;
  switch (state)
    {
    foreach_bfd_state (F)}
  return "UNKNOWN";
#undef F
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
