/*
 * upf_adf.h - 3GPP TS 29.244 UPF adf header file
 *
 * Copyright (c) 2017 Travelping GmbH
 *
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

#ifndef __included_upf_adf_h__
#define __included_upf_adf_h__

#include <stddef.h>
#include <upf/upf.h>

#if CLIB_DEBUG > 0
#define adf_debug clib_warning
#else
#define adf_debug(...)				\
  do { } while (0)
#endif

int upf_adf_lookup(u32 db_index, u8 * str, uint16_t length);
int upf_app_add_del (upf_main_t * sm, u8 * name, int add);
int upf_rule_add_del (upf_main_t * sm, u8 * name, u32 id,
		      int add, upf_rule_args_t * args);

u32 upf_adf_get_adr_db(u32 application_id);
void upf_adf_put_adr_db(u32 db_index);

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
#define char_to_u32(A,B,C,D)				\
  (((A) << 24) | ((B) << 16) | ((C) <<  8) | (D))
#define char_to_u64(A,B,C,D,E,F,G,H)			\
  (((u64)(A) << 56) | ((u64)(B) << 48) |		\
   ((u64)(C) << 40) | ((u64)(D) << 32) |		\
   ((u64)(E) << 24) | ((u64)(F) << 16) |		\
   ((u64)(G) <<  8) | (u64)(H))
#else
#define char_to_u32(A,B,C,D)				\
  (((D) << 24) | ((C) << 16) | ((B) <<  8) | (A))
#define char_to_u64(A,B,C,D,E,F,G,H)			\
  (((u64)(H) << 56) | ((u64)(G) << 48) |		\
   ((u64)(F) << 40) | ((u64)(E) << 32) |		\
   ((u64)(D) << 24) | ((u64)(C) << 16) |		\
   ((u64)(B) <<  8) | (u64)(A))
#endif

#define char_mask_64_5 char_to_u64(0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0)
#define char_mask_64_6 char_to_u64(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0)
#define char_mask_64_7 char_to_u64(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0)

always_inline int is_http_request(u8 ** payload, word * len)
{
  u32 c0 = *(u32 *)*payload;
  u64 d0 = *(u64 *)*payload;

  if (*len < 10)
    return 0;

  if (c0 == char_to_u32('G', 'E', 'T', ' ') ||
      c0 == char_to_u32('P', 'U', 'T', ' '))
    {
      *payload += 4;
      *len -= 4;
      return 1;
    }
  else if ((c0 == char_to_u32('H', 'E', 'A', 'D') ||
	    c0 == char_to_u32('P', 'O', 'S', 'T') ||
	    c0 == char_to_u32('C', 'O', 'P', 'Y') ||
	    c0 == char_to_u32('M', 'O', 'V', 'E') ||
	    c0 == char_to_u32('L', 'O', 'C', 'K')) &&
	   *payload[4] == ' ')
    {
      *payload += 5;
      *len -= 5;
      return 1;
    }
  else if (((d0 & char_mask_64_6) == char_to_u64('M', 'K', 'C', 'O', 'L', ' ', 0, 0)) ||
	   ((d0 & char_mask_64_6) == char_to_u64('T', 'R', 'A', 'C', 'E', ' ', 0, 0)) ||
	   ((d0 & char_mask_64_6) == char_to_u64('P', 'A', 'T', 'C', 'H', ' ', 0, 0)))
    {
      *payload += 6;
      *len -= 6;
      return 1;
    }
  else if (((d0 & char_mask_64_7) == char_to_u64('D', 'E', 'L', 'E', 'T', 'E', ' ', 0)) ||
	   ((d0 & char_mask_64_7) == char_to_u64('U', 'N', 'L', 'O', 'C', 'K', ' ', 0)))
    {
      *payload += 7;
      *len -= 7;
      return 1;
    }
  else if ((d0 == char_to_u64('C', 'O', 'N', 'N', 'E', 'C', 'T', ' ')) ||
	   (d0 == char_to_u64('O', 'P', 'T', 'I', 'O', 'N', 'S', ' ')))
    {
      *payload += 8;
      *len -= 8;
      return 1;
    }
  if (c0 == char_to_u32('P', 'R', 'O', 'P'))
    {
      u64 d1 = *(u64 *)(*payload + 4);

      if ((d1 & char_mask_64_5) == char_to_u64('F', 'I', 'N', 'D', ' ', 0, 0, 0))
	{
	  *payload += 9;
	  *len -= 9;
	  return 1;
	}
      else if ((d1 & char_mask_64_6) == char_to_u64('P', 'A', 'T', 'C', 'H', ' ', 0, 0))
	{
	  *payload += 10;
	  *len -= 10;
	  return 1;
	}
    }

  return 0;
}

always_inline int
is_host_header(u8 ** s, word * len)
{
  u8 * eol;
  u8 * c;

  eol = memchr(*s, '\n', *len);
  if (!eol)
    {
      *s += *len;
      *len = 0;
      return 0;
    }

  if ((eol - *s) < 5)
    goto out_skip;

  u64 d0 = *(u64 *)(*s);

  /* upper case 1st 4 characters of header */
  d0 &= char_to_u64(0xdf, 0xdf, 0xdf, 0xdf, 0xff, 0, 0, 0);
  if (d0 != char_to_u64('H', 'O', 'S', 'T', ':', 0, 0, 0))
    goto out_skip;

  *s += 5;
  *len -= 5;

  /* find first non OWS */
  for (; *len > 0 && **s <= ' '; (*len)--, (*s)++)
    ;
  /* find last non OWS */
  for (c = *s ;
       *len > 0 && *c > ' '; (*len)--, c++)
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

#endif /* __included_upf_adf_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
