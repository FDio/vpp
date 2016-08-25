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
 * snap_pg.c: packet generator snap interface
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
#include <vnet/snap/snap.h>

typedef struct
{
  pg_edit_t oui;
  pg_edit_t protocol;
} pg_snap_header_t;

static inline void
pg_snap_header_init (pg_snap_header_t * e)
{
  pg_edit_init (&e->oui, snap_header_t, oui);
  pg_edit_init (&e->protocol, snap_header_t, protocol);
}

uword
unformat_pg_snap_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_snap_header_t *h;
  u32 group_index, error;

  h = pg_create_edit_group (s, sizeof (h[0]), sizeof (snap_header_t),
			    &group_index);
  pg_snap_header_init (h);

  error = 1;
  if (!unformat (input, "%U -> %U",
		 unformat_pg_edit,
		 unformat_snap_protocol, &h->oui, &h->protocol))
    goto done;

  {
    snap_main_t *pm = &snap_main;
    snap_protocol_info_t *pi = 0;
    pg_node_t *pg_node = 0;

    if (h->oui.type == PG_EDIT_FIXED && h->protocol.type == PG_EDIT_FIXED)
      {
	u8 *o = h->oui.values[PG_EDIT_LO];
	u8 *p = h->protocol.values[PG_EDIT_LO];
	snap_header_t h;

	h.oui[0] = o[0];
	h.oui[1] = o[1];
	h.oui[2] = o[2];
	h.protocol = *(u16 *) p;
	pi = snap_get_protocol_info (pm, &h);
	if (pi && pi->node_index != ~0)
	  pg_node = pg_get_node (pi->node_index);
      }

    if (pg_node && pg_node->unformat_edit
	&& unformat_user (input, pg_node->unformat_edit, s))
      ;

    else if (!unformat_user (input, unformat_pg_payload, s))
      goto done;
  }

  error = 0;
done:
  if (error)
    pg_free_edit_group (s);
  return error == 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
