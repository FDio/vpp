/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#pragma once

#include <vppinfra/clib.h>

always_inline u32
clib_unicode_get_utf8_char (u8 *s, u32 *codepoint)
{
  u32 c0 = s[0], c1, c2, c3;

  if (c0 < 0x80)
    {
      *codepoint = c0;
      return 1;
    }

  c1 = s[1];
  if (c0 >= 0xc2 && c0 <= 0xdf)
    {
      if ((c1 & 0xc0) != 0x80)
	goto invalid;

      *codepoint = ((c0 & 0x1f) << 6) | (c1 & 0x3f);
      return 2;
    }

  c2 = s[2];
  if (c0 >= 0xe0 && c0 <= 0xef)
    {
      if ((c1 & 0xc0) != 0x80 || (c2 & 0xc0) != 0x80)
	goto invalid;

      if ((c0 == 0xe0 && c1 < 0xa0) || (c0 == 0xed && c1 >= 0xa0))
	goto invalid;

      *codepoint = ((c0 & 0x0f) << 12) | ((c1 & 0x3f) << 6) | (c2 & 0x3f);
      return 3;
    }

  c3 = s[3];
  if (c0 >= 0xf0 && c0 <= 0xf4)
    {

      if ((c1 & 0xc0) != 0x80 || (c2 & 0xc0) != 0x80 || (c3 & 0xc0) != 0x80)
	goto invalid;

      if ((c0 == 0xf0 && c1 < 0x90) || (c0 == 0xf4 && c1 >= 0x90))
	goto invalid;

      *codepoint = ((c0 & 0x07) << 18) | ((c1 & 0x3f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f);
      return 4;
    }

invalid:
  *codepoint = c0;
  return 1;
}

__clib_export u8 clib_unicode_get_visible_len (u32 cp);
