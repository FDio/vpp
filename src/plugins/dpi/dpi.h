/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef included_vnet_dpi_h
#define included_vnet_dpi_h

#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>

#include <hs/hs.h>
#include <hs/hs_common.h>
#include <hs/hs_compile.h>
#include <hs/hs_runtime.h>

#define foreach_dpi_scan_next    \
_(DROP, "error-drop")                  \
_(INTERFACE, "interface-output" )      \
_(L2_INPUT, "l2-input")                \
_(IP4_INPUT,  "ip4-input")             \
_(IP6_INPUT, "ip6-input" )

typedef enum
{
#define _(s,n) DPI_SCAN_NEXT_##s,
  foreach_dpi_scan_next
#undef _
    DPI_SCAN_N_NEXT,
} dpi_scan_next_t;

#define foreach_dpi_error                       \
_(SCAN_FAIL, "failed to scan")

typedef enum
{
#define _(sym,str) DPI_ERROR_##sym,
  foreach_dpi_error
#undef _
    DPI_ERROR_N_ERROR,
} dpi_scan_error_t;

typedef enum
{
  DPI_ACTION_PERMIT,
  DPI_ACTION_DROP,
} dpi_action_t;

typedef u8 *regex_t;

typedef struct
{
  /* App index */
  u32 index;
  /* Regex expression */
  regex_t rule;
} dpi_args_t;

typedef struct
{
  regex_t *expressions;
  u32 *flags;
  hs_database_t *database;
  hs_scratch_t *scratch;
  u32 ref_cnt;
} dpi_entry_t;

typedef struct
{
  int res;
  u32 id;
} dpi_cb_args_t;

typedef struct
{
  u32 id;
  regex_t host;
  regex_t path;
} dpi_rule_t;

typedef struct
{
  regex_t host;
  regex_t path;
  ip46_address_t src_ip;
  ip46_address_t dst_ip;
} dpi_rule_args_t;

typedef struct
{
  u32 id;
  u8 *name;
  /* hash over rules id */
  uword *rules_by_id;
  /* vector of rules definitio */
  dpi_rule_t *rules;
  u32 db_index;
} dpi_app_t;

typedef struct
{
  u32 app_id;
  u32 db_id;
} dpi_app_db_t;

typedef struct
{
  /* Compiler mode flags that affect the database as a whole.
   * HS_MODE_BLOCK or HS_MODE_STREAM or HS_MODE_VECTORED must be supplied */
  u32 mode;

  /*
   * Flags which modify the behaviour of the expression.
   * Multiple flags may be used by ORing them together.
   * Valid values are:
   *   HS_FLAG_CASELESS - Matching will be performed case-insensitively.
   *   HS_FLAG_DOTALL - Matching a . will not exclude newlines.
   *   HS_FLAG_MULTILINE - ^ and $ anchors match any newlines in data.
   *   HS_FLAG_SINGLEMATCH - Only one match will be generated for the expression per stream.
   *   HS_FLAG_ALLOWEMPTY - Allow expressions which can match against an empty string, such as .*.
   *   HS_FLAG_UTF8 - Treat this pattern as a sequence of UTF-8 characters.
   *   HS_FLAG_UCP - Use Unicode properties for character classes.
   *   HS_FLAG_PREFILTER - Compile pattern in prefiltering mode.
   *   HS_FLAG_SOM_LEFTMOST - Report the leftmost start of match offset when a match is found.
   */
  u32 flags;

  /* If not NULL, the platform structure is used to determine the target platform for the database.
   * If NULL, a database suitable for running on the current host platform is produced.
   */
  u32 platform;

  /* The NULL-terminated expression to parse */
  char *pattern;
  u32 pattern_len;
  /* Take action when matched */
  u32 action;

  /* Dpi compiled database (block mode) */
  hs_database_t *db_block;

  /* Dpi compiled database (streaming mode) */
  hs_database_t *db_streaming;

  /* Dpi temporary scratch space (used in both modes) */
  hs_scratch_t *scratch;

  /* Vector of Dpi stream state (used in streaming mode) */
  hs_stream_t *streams;

  /* DPI apps hash */
  uword *dpi_app_by_name;
  /* DPI apps vector */
  dpi_app_t *dpi_apps;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dpi_main_t;

extern dpi_main_t dpi_main;

/* perfect hash over the HTTP keywords:
 *   GET
 *   PUT
 *   HEAD
 *   POST
 *   COPY
 *   MOVE
 *   LOCK
 *   MKCOL
 *   TRACE
 *   PATCH
 *   DELETE
 *   UNLOCK
 *   CONNECT
 *   OPTIONS
 *   PROPPATCH
 */
#if CLIB_ARCH_IS_BIG_ENDIAN
#define char_to_u32(A,B,C,D)                \
  (((A) << 24) | ((B) << 16) | ((C) <<  8) | (D))
#define char_to_u64(A,B,C,D,E,F,G,H)            \
  (((u64)(A) << 56) | ((u64)(B) << 48) |        \
   ((u64)(C) << 40) | ((u64)(D) << 32) |        \
   ((u64)(E) << 24) | ((u64)(F) << 16) |        \
   ((u64)(G) <<  8) | (u64)(H))
#else
#define char_to_u32(A,B,C,D)                \
  (((D) << 24) | ((C) << 16) | ((B) <<  8) | (A))
#define char_to_u64(A,B,C,D,E,F,G,H)            \
  (((u64)(H) << 56) | ((u64)(G) << 48) |        \
   ((u64)(F) << 40) | ((u64)(E) << 32) |        \
   ((u64)(D) << 24) | ((u64)(C) << 16) |        \
   ((u64)(B) <<  8) | (u64)(A))
#endif

#define char_mask_64_5 char_to_u64(0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0)
#define char_mask_64_6 char_to_u64(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0)
#define char_mask_64_7 char_to_u64(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0)

always_inline int
is_http_request (u8 ** payload, word * len)
{
  u32 c0 = *(u32 *) * payload;
  u64 d0 = *(u64 *) * payload;

  if (*len < 10)
    return 0;

  if (c0 == char_to_u32 ('G', 'E', 'T', ' ') ||
      c0 == char_to_u32 ('P', 'U', 'T', ' '))
    {
      *payload += 4;
      *len -= 4;
      return 1;
    }
  else if ((c0 == char_to_u32 ('H', 'E', 'A', 'D') ||
	    c0 == char_to_u32 ('P', 'O', 'S', 'T') ||
	    c0 == char_to_u32 ('C', 'O', 'P', 'Y') ||
	    c0 == char_to_u32 ('M', 'O', 'V', 'E') ||
	    c0 == char_to_u32 ('L', 'O', 'C', 'K')) && *payload[4] == ' ')
    {
      *payload += 5;
      *len -= 5;
      return 1;
    }
  else
    if (((d0 & char_mask_64_6) ==
	 char_to_u64 ('M', 'K', 'C', 'O', 'L', ' ', 0, 0))
	|| ((d0 & char_mask_64_6) ==
	    char_to_u64 ('T', 'R', 'A', 'C', 'E', ' ', 0, 0))
	|| ((d0 & char_mask_64_6) ==
	    char_to_u64 ('P', 'A', 'T', 'C', 'H', ' ', 0, 0)))
    {
      *payload += 6;
      *len -= 6;
      return 1;
    }
  else
    if (((d0 & char_mask_64_7) ==
	 char_to_u64 ('D', 'E', 'L', 'E', 'T', 'E', ' ', 0))
	|| ((d0 & char_mask_64_7) ==
	    char_to_u64 ('U', 'N', 'L', 'O', 'C', 'K', ' ', 0)))
    {
      *payload += 7;
      *len -= 7;
      return 1;
    }
  else if ((d0 == char_to_u64 ('C', 'O', 'N', 'N', 'E', 'C', 'T', ' ')) ||
	   (d0 == char_to_u64 ('O', 'P', 'T', 'I', 'O', 'N', 'S', ' ')))
    {
      *payload += 8;
      *len -= 8;
      return 1;
    }
  if (c0 == char_to_u32 ('P', 'R', 'O', 'P'))
    {
      u64 d1 = *(u64 *) (*payload + 4);

      if ((d1 & char_mask_64_5) ==
	  char_to_u64 ('F', 'I', 'N', 'D', ' ', 0, 0, 0))
	{
	  *payload += 9;
	  *len -= 9;
	  return 1;
	}
      else if ((d1 & char_mask_64_6) ==
	       char_to_u64 ('P', 'A', 'T', 'C', 'H', ' ', 0, 0))
	{
	  *payload += 10;
	  *len -= 10;
	  return 1;
	}
    }

  return 0;
}

always_inline int
is_host_header (u8 ** s, word * len)
{
  u8 *eol;
  u8 *c;

  eol = memchr (*s, '\n', *len);
  if (!eol)
    {
      *s += *len;
      *len = 0;
      return 0;
    }

  if ((eol - *s) < 5)
    goto out_skip;

  u64 d0 = *(u64 *) (*s);

  /* upper case 1st 4 characters of header */
  d0 &= char_to_u64 (0xdf, 0xdf, 0xdf, 0xdf, 0xff, 0, 0, 0);
  if (d0 != char_to_u64 ('H', 'O', 'S', 'T', ':', 0, 0, 0))
    goto out_skip;

  *s += 5;
  *len -= 5;

  /* find first non OWS */
  for (; *len > 0 && **s <= ' '; (*len)--, (*s)++)
    ;
  /* find last non OWS */
  for (c = *s; *len > 0 && *c > ' '; (*len)--, c++)
    ;

  if (len <= 0)
    return 0;

  *len = c - *s;
  return 1;

out_skip:
  eol++;
  *len -= eol - *s;
  *s = eol;

  return 0;
}

#define MIN(x,y) (((x)<(y))?(x):(y))

int dpi_app_add_del (u8 * name, u8 add);
int dpi_rule_add_del (u8 * name, u32 id, u8 add, dpi_rule_args_t * args);
void vnet_int_dpi_bypass (u32 sw_if_index, u8 is_ip6, u8 is_enable);
int dpi_db_lookup (u32 db_index, u8 * str, uint16_t length);
int dpi_db_remove (u32 db_index);
u32 dpi_parse_flagstr (char *flagsStr);
int dpi_create_update_db (dpi_app_t * app);

#endif /* included_vnet_dpi_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
