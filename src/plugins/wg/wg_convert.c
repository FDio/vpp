/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <wg/wg_convert.h>

static inline int
decode_base64 (const char src[4])
{
  int val = 0;

  for (unsigned int i = 0; i < 4; ++i)
    val |= (-1
	    +
	    ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] -
								     64)) +
	    ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] -
								     70)) +
	    ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] +
								     5)) +
	    ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63) +
	    ((((('/' - 1) - src[i]) & (src[i] -
				       ('/' + 1))) >> 8) & 64)) << (18 -
								    6 * i);
  return val;
}

bool
key_from_base64 (u8 key[NOISE_PUBLIC_KEY_LEN], const char *base64)
{
  unsigned int i;
  volatile u8 ret = 0;
  int val;

  if (strlen (base64) != NOISE_KEY_LEN_BASE64 - 1
      || base64[NOISE_KEY_LEN_BASE64 - 2] != '=')
    return false;

  for (i = 0; i < NOISE_PUBLIC_KEY_LEN / 3; ++i)
    {
      val = decode_base64 (&base64[i * 4]);
      ret |= (u32) val >> 31;
      key[i * 3 + 0] = (val >> 16) & 0xff;
      key[i * 3 + 1] = (val >> 8) & 0xff;
      key[i * 3 + 2] = val & 0xff;
    }
  val = decode_base64 ((const char[])
		       {
		       base64[i * 4 + 0], base64[i * 4 + 1],
		       base64[i * 4 + 2], 'A'});
  ret |= ((u32) val >> 31) | (val & 0xff);
  key[i * 3 + 0] = (val >> 16) & 0xff;
  key[i * 3 + 1] = (val >> 8) & 0xff;

  return 1 & ((ret - 1) >> 8);
}

static inline void
encode_base64 (char dest[4], const uint8_t src[3])
{
  const uint8_t input[] =
    { (src[0] >> 2) & 63, ((src[0] << 4) | (src[1] >> 4)) & 63,
    ((src[1] << 2) | (src[2] >> 6)) & 63, src[2] & 63
  };

  for (unsigned int i = 0; i < 4; ++i)
    dest[i] = input[i] + 'A'
      + (((25 - input[i]) >> 8) & 6)
      - (((51 - input[i]) >> 8) & 75)
      - (((61 - input[i]) >> 8) & 15) + (((62 - input[i]) >> 8) & 3);

}

void
key_to_base64 (char base64[NOISE_KEY_LEN_BASE64],
	       const uint8_t key[NOISE_PUBLIC_KEY_LEN])
{
  unsigned int i;

  for (i = 0; i < NOISE_PUBLIC_KEY_LEN / 3; ++i)
    encode_base64 (&base64[i * 4], &key[i * 3]);
  encode_base64 (&base64[i * 4], (const uint8_t[])
		 {
		 key[i * 3 + 0], key[i * 3 + 1], 0});
  base64[NOISE_KEY_LEN_BASE64 - 2] = '=';
  base64[NOISE_KEY_LEN_BASE64 - 1] = '\0';
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
