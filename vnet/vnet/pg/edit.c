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
 * pg_edit.c: packet generator edits
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
#include <vnet/pg/pg.h>

static void
pg_edit_set_value_helper (pg_edit_t * e, u64 value, u8 * result)
{
  int i, j, n_bits_left;
  u8 *v, tmp[8];

  v = tmp;

  n_bits_left = e->n_bits;
  i = 0;
  j = e->lsb_bit_offset % BITS (v[0]);

  if (n_bits_left > 0 && j != 0)
    {
      v[i] = (value & 0xff) << j;
      value >>= BITS (v[0]) - j;
      n_bits_left -= BITS (v[0]) - j;
      i += 1;
    }

  while (n_bits_left > 0)
    {
      v[i] = value & 0xff;
      value >>= 8;
      n_bits_left -= 8;
      i += 1;
    }

  /* Convert to network byte order. */
  for (j = 0; j < i; j++)
    result[j] = v[i - 1 - j];
}

void
pg_edit_set_value (pg_edit_t * e, int hi_or_lo, u64 value)
{
  pg_edit_alloc_value (e, hi_or_lo);
  pg_edit_set_value_helper (e, value, e->values[hi_or_lo]);
}

/* Parse an int either %d or 0x%x into network byte order. */
uword
unformat_pg_number (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  pg_edit_t *e = va_arg (*args, pg_edit_t *);
  u64 value;

  ASSERT (BITS (value) >= e->n_bits);

  if (!unformat (input, "0x%X", sizeof (value), &value)
      && !unformat (input, "%D", sizeof (value), &value))
    return 0;

  /* Number given does not fit into bit field. */
  if (e->n_bits < 64 && value >= (u64) 1 << (u64) e->n_bits)
    return 0;

  pg_edit_set_value_helper (e, value, result);
  return 1;
}

uword
unformat_pg_edit (unformat_input_t * input, va_list * args)
{
  unformat_function_t *f = va_arg (*args, unformat_function_t *);
  pg_edit_t *e = va_arg (*args, pg_edit_t *);

  pg_edit_alloc_value (e, PG_EDIT_LO);
  if (!unformat_user (input, f, e->values[PG_EDIT_LO], e))
    return 0;

  pg_edit_alloc_value (e, PG_EDIT_HI);
  if (unformat (input, "-%U", f, e->values[PG_EDIT_HI], e))
    e->type = PG_EDIT_INCREMENT;
  else if (unformat (input, "+%U", f, e->values[PG_EDIT_HI], e))
    e->type = PG_EDIT_RANDOM;
  else
    e->type = PG_EDIT_FIXED;

  return 1;
}

uword
unformat_pg_payload (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  vlib_main_t *vm = vlib_get_main ();
  pg_edit_t *e;
  u32 i, node_index, len, max_len;
  u8 *v;

  v = 0;

  if (unformat (input, "incrementing %d", &len))
    {
      vec_resize (v, len);
      for (i = 0; i < len; i++)
	v[i] = i;
    }
  else if (unformat (input, "hex 0x%U", unformat_hex_string, &v))
    ;

  else if (unformat (input, "%U", unformat_vlib_node, vm, &node_index))
    {
      pg_node_t *pn = pg_get_node (node_index);
      if (!pn->unformat_edit)
	return 0;
      return unformat (input, "%U", pn->unformat_edit, s);
    }

  else
    return 0;

  /* Length not including this payload. */
  max_len = pg_edit_group_n_bytes (s, 0);
  if (max_len + vec_len (v) >= s->max_packet_bytes)
    {
      if (s->max_packet_bytes >= max_len)
	_vec_len (v) = s->max_packet_bytes - max_len;
      else
	_vec_len (v) = 0;
    }

  e = pg_create_edit_group (s, sizeof (e[0]), vec_len (v), 0);

  e->type = PG_EDIT_FIXED;
  e->n_bits = vec_len (v) * BITS (v[0]);

  /* Least significant bit is at end of bitstream, since everything is always bigendian. */
  e->lsb_bit_offset = e->n_bits - BITS (v[0]);

  e->values[PG_EDIT_LO] = v;

  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
