/*
 * hdlc_pg.c: packet generator gre interface
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/gre/gre.h>

typedef struct
{
  pg_edit_t flags_and_version;
  pg_edit_t protocol;
} pg_gre_header_t;

static inline void
pg_gre_header_init (pg_gre_header_t * e)
{
  pg_edit_init (&e->flags_and_version, gre_header_t, flags_and_version);
  pg_edit_init (&e->protocol, gre_header_t, protocol);
}

uword
unformat_pg_gre_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_gre_header_t *h;
  u32 group_index, error;

  h = pg_create_edit_group (s, sizeof (h[0]), sizeof (gre_header_t),
			    &group_index);
  pg_gre_header_init (h);

  pg_edit_set_fixed (&h->flags_and_version, 0);

  error = 1;
  if (!unformat (input, "%U",
		 unformat_pg_edit,
		 unformat_gre_protocol_net_byte_order, &h->protocol))
    goto done;

  {
    gre_main_t *pm = &gre_main;
    gre_protocol_info_t *pi = 0;
    pg_node_t *pg_node = 0;

    if (h->protocol.type == PG_EDIT_FIXED)
      {
	u16 t = *(u16 *) h->protocol.values[PG_EDIT_LO];
	pi = gre_get_protocol_info (pm, clib_net_to_host_u16 (t));
	if (pi && pi->node_index != ~0)
	  pg_node = pg_get_node (pi->node_index);
      }

    if (pg_node && pg_node->unformat_edit
	&& unformat_user (input, pg_node->unformat_edit, s))
      ;
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
