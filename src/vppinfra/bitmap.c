/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>

/** unformat an any sized hexadecimal bitmask into a bitmap

    uword * bitmap;
    rv = unformat ("%U", unformat_bitmap_mask, &bitmap);

    Standard unformat_function_t arguments

    @param input - pointer an unformat_input_t
    @param va - varargs list comprising a single uword **
    @returns 1 on success, 0 on failure
*/
__clib_export uword
unformat_bitmap_mask (unformat_input_t *input, va_list *va)
{
  u8 *v = 0; /* hexadecimal vector */
  uword **bitmap_return = va_arg (*va, uword **);
  uword *bitmap = 0;

  if (unformat (input, "%U", unformat_hex_string, &v))
    {
      int i, s = vec_len (v) - 1; /* 's' for significance or shift */

      /* v[0] holds the most significant byte */
      for (i = 0; s >= 0; i++, s--)
	bitmap = clib_bitmap_set_multiple (bitmap, s * BITS (v[i]), v[i],
					   BITS (v[i]));

      vec_free (v);
      *bitmap_return = bitmap;
      return 1;
    }

  return 0;
}

/** unformat a list of bit ranges into a bitmap (eg "0-3,5-7,11" )

    uword * bitmap;
    rv = unformat ("%U", unformat_bitmap_list, &bitmap);

    Standard unformat_function_t arguments

    @param input - pointer an unformat_input_t
    @param va - varargs list comprising a single uword **
    @returns 1 on success, 0 on failure
*/
__clib_export uword
unformat_bitmap_list (unformat_input_t *input, va_list *va)
{
  uword **bitmap_return = va_arg (*va, uword **);
  uword *bitmap = 0;

  u32 a, b;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int i;
      if (unformat (input, "%u-%u,", &a, &b))
	;
      else if (unformat (input, "%u,", &a))
	b = a;
      else if (unformat (input, "%u-%u", &a, &b))
	;
      else if (unformat (input, "%u", &a))
	b = a;
      else if (bitmap)
	{
	  unformat_put_input (input);
	  break;
	}
      else
	goto error;

      if (b < a)
	goto error;

      for (i = a; i <= b; i++)
	bitmap = clib_bitmap_set (bitmap, i, 1);
    }
  *bitmap_return = bitmap;
  return 1;
error:
  clib_bitmap_free (bitmap);
  return 0;
}

/** Format a bitmap as a string of hex bytes

    uword * bitmap;
    s = format ("%U", format_bitmap_hex, bitmap);

    Standard format_function_t arguments

    @param s - string under construction
    @param args - varargs list comprising a single uword *
    @returns string under construction
*/

__clib_export u8 *
format_bitmap_hex (u8 *s, va_list *args)
{
  uword *bitmap = va_arg (*args, uword *);
  int i, is_trailing_zero = 1;

  if (!bitmap)
    return format (s, "0");

  i = vec_bytes (bitmap) * 2;

  while (i > 0)
    {
      u8 x = clib_bitmap_get_multiple (bitmap, --i * 4, 4);

      if (x && is_trailing_zero)
	is_trailing_zero = 0;

      if (x || !is_trailing_zero)
	s = format (s, "%x", x);
    }
  return s;
}

/** Format a bitmap as a list

    uword * bitmap;
    s = format ("%U", format_bitmap_list, bitmap);

    Standard format_function_t arguments

    @param s - string under construction
    @param args - varargs list comprising a single uword *
    @returns string under construction
*/

__clib_export u8 *
format_bitmap_list (u8 *s, va_list *args)
{
  uword *bitmap = va_arg (*args, uword *);
  uword fs, fc;

  if (!bitmap)
    return s;

  fs = clib_bitmap_first_set (bitmap);
  if (fs == ~0)
    return s;

  while (1)
    {
      fc = clib_bitmap_next_clear (bitmap, fs + 1);
      if (fc > fs + 1)
	s = format (s, "%lu-%lu", fs, fc - 1);
      else
	s = format (s, "%lu", fs);

      if ((fs = clib_bitmap_next_set (bitmap, fc)) == ~0)
	return s;
      s = format (s, ", ");
    }
}
