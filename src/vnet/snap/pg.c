/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* snap_pg.c: packet generator snap interface */

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
