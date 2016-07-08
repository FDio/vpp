/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * format.c: generic network formatting/unformating
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>

u8 *
format_vlib_rx_tx (u8 * s, va_list * args)
{
  vlib_rx_or_tx_t r = va_arg (*args, vlib_rx_or_tx_t);
  char *t;

  switch (r)
    {
    case VLIB_RX:
      t = "rx";
      break;
    case VLIB_TX:
      t = "tx";
      break;
    default:
      t = "INVALID";
      break;
    }

  vec_add (s, t, strlen (t));
  return s;
}

u8 *
format_vlib_read_write (u8 * s, va_list * args)
{
  vlib_rx_or_tx_t r = va_arg (*args, vlib_rx_or_tx_t);
  char *t;

  switch (r)
    {
    case VLIB_READ:
      t = "read";
      break;
    case VLIB_WRITE:
      t = "write";
      break;
    default:
      t = "INVALID";
      break;
    }

  vec_add (s, t, strlen (t));
  return s;
}

/* Formats buffer data as printable ascii or as hex. */
u8 *
format_vlib_buffer_data (u8 * s, va_list * args)
{
  u8 *data = va_arg (*args, u8 *);
  u32 n_data_bytes = va_arg (*args, u32);
  u32 i, is_printable;

  is_printable = 1;
  for (i = 0; i < n_data_bytes && is_printable; i++)
    {
      u8 c = data[i];
      if (c < 0x20)
	is_printable = 0;
      else if (c >= 0x7f)
	is_printable = 0;
    }

  if (is_printable)
    vec_add (s, data, n_data_bytes);
  else
    s = format (s, "%U", format_hex_bytes, data, n_data_bytes);

  return s;
}

/* Enable/on => 1; disable/off => 0. */
uword
unformat_vlib_enable_disable (unformat_input_t * input, va_list * args)
{
  int *result = va_arg (*args, int *);
  int enable;

  if (unformat (input, "enable") || unformat (input, "on"))
    enable = 1;
  else if (unformat (input, "disable") || unformat (input, "off"))
    enable = 0;
  else
    return 0;

  *result = enable;
  return 1;
}

/* rx/tx => VLIB_RX/VLIB_TX. */
uword
unformat_vlib_rx_tx (unformat_input_t * input, va_list * args)
{
  int *result = va_arg (*args, int *);
  if (unformat (input, "rx"))
    *result = VLIB_RX;
  else if (unformat (input, "tx"))
    *result = VLIB_TX;
  else
    return 0;
  return 1;
}

/* Parse an int either %d or 0x%x. */
uword
unformat_vlib_number (unformat_input_t * input, va_list * args)
{
  int *result = va_arg (*args, int *);

  return (unformat (input, "0x%x", result) || unformat (input, "%d", result));
}

/* Parse a-zA-Z0-9_ token and hash to value. */
uword
unformat_vlib_number_by_name (unformat_input_t * input, va_list * args)
{
  uword *hash = va_arg (*args, uword *);
  int *result = va_arg (*args, int *);
  uword *p;
  u8 *token;
  int i;

  if (!unformat_user (input, unformat_token, "a-zA-Z0-9_", &token))
    return 0;

  /* Null terminate. */
  if (vec_len (token) > 0 && token[vec_len (token) - 1] != 0)
    vec_add1 (token, 0);

  /* Check for exact match. */
  p = hash_get_mem (hash, token);
  if (p)
    goto done;

  /* Convert to upper case & try match. */
  for (i = 0; i < vec_len (token); i++)
    if (token[i] >= 'a' && token[i] <= 'z')
      token[i] = 'A' + token[i] - 'a';
  p = hash_get_mem (hash, token);

done:
  vec_free (token);
  if (p)
    *result = p[0];
  return p != 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
