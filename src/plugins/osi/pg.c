/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* osi_pg.c: packet generator osi interface */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <osi/osi.h>

typedef struct
{
  pg_edit_t protocol;
} pg_osi_header_t;

static inline void
pg_osi_header_init (pg_osi_header_t * e)
{
  pg_edit_init (&e->protocol, osi_header_t, protocol);
}

uword
unformat_pg_osi_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_osi_header_t *h;
  u32 group_index, error;

  h = pg_create_edit_group (s, sizeof (h[0]), sizeof (osi_header_t),
			    &group_index);
  pg_osi_header_init (h);

  error = 1;
  if (!unformat (input, "%U",
		 unformat_pg_edit, unformat_osi_protocol, &h->protocol))
    goto done;

  {
    osi_main_t *pm = &osi_main;
    osi_protocol_info_t *pi = 0;
    pg_node_t *pg_node = 0;

    if (h->protocol.type == PG_EDIT_FIXED)
      {
	u8 t = *h->protocol.values[PG_EDIT_LO];
	pi = osi_get_protocol_info (pm, t);
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
