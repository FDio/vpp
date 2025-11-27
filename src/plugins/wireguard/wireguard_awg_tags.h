/*
 * Copyright (c) 2025 Internet Mastering & Company, Inc.
 * Copyright (c) 2025 AmneziaWG 1.5 i-header support for VPP
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

#ifndef __included_wg_awg_tags_h__
#define __included_wg_awg_tags_h__

#include <vppinfra/types.h>
#include <vppinfra/vec.h>

/*
 * AmneziaWG 1.5 Tag-based Packet Generation
 *
 * This implements the i-header signature chain (i1-i5) feature that allows
 * WireGuard traffic to masquerade as legitimate protocols (QUIC, DNS, etc.)
 *
 * Tag Format: <tagname param>
 *
 * Supported tags:
 *   <b 0xHEXDATA>  - Inject literal hex bytes
 *   <c>            - Insert 8-byte packet counter (big-endian)
 *   <t>            - Insert 8-byte timestamp (big-endian, unix time)
 *   <r N>          - Insert N random bytes
 *   <rc N>         - Insert N random ASCII alphanumeric characters
 *   <rd N>         - Insert N random digits (0-9)
 *
 * Example i1 to mimic QUIC:
 *   "<b 0xc00000000108...><r 16><c><t>"
 */

#define WG_AWG_MAX_TAG_STRING_LEN 2048
#define WG_AWG_MAX_I_HEADERS	  5

/* Tag types */
typedef enum wg_awg_tag_type_
{
  WG_AWG_TAG_BYTES,	   /* <b 0xHEXDATA> */
  WG_AWG_TAG_COUNTER,	   /* <c> */
  WG_AWG_TAG_TIMESTAMP,	   /* <t> */
  WG_AWG_TAG_RANDOM,	   /* <r N> */
  WG_AWG_TAG_RANDOM_ASCII, /* <rc N> */
  WG_AWG_TAG_RANDOM_DIGIT, /* <rd N> */
} wg_awg_tag_type_t;

/* Parsed tag element */
typedef struct wg_awg_tag_
{
  wg_awg_tag_type_t type;
  union
  {
    struct
    {
      u8 *data; /* Hex bytes */
      u32 len;
    } bytes;
    u32 random_len; /* For random types */
  };
} wg_awg_tag_t;

/* i-header definition (sequence of tags) */
typedef struct wg_awg_i_header_
{
  u8 enabled;
  wg_awg_tag_t *tags; /* Vector of tags */
  u32 counter;	      /* Packet counter for <c> tags */
  u32 total_size;     /* Cached total size */
} wg_awg_i_header_t;

/* Parse a tag string into tag elements */
int wg_awg_parse_tag_string (const char *tag_string, wg_awg_i_header_t *hdr);

/* Generate packet data from i-header tags */
u8 *wg_awg_generate_i_header_packet (wg_awg_i_header_t *hdr);

/* Free i-header resources */
void wg_awg_free_i_header (wg_awg_i_header_t *hdr);

/* Calculate total size of generated packet */
u32 wg_awg_i_header_size (const wg_awg_i_header_t *hdr);

#endif /* __included_wg_awg_tags_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
