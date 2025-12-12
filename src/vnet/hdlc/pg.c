/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* hdlc_pg.c: packet generator hdlc interface */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/hdlc/hdlc.h>

typedef struct
{
  pg_edit_t address;
  pg_edit_t control;
  pg_edit_t protocol;
} pg_hdlc_header_t;

static inline void
pg_hdlc_header_init (pg_hdlc_header_t * e)
{
  pg_edit_init (&e->address, hdlc_header_t, address);
  pg_edit_init (&e->control, hdlc_header_t, control);
  pg_edit_init (&e->protocol, hdlc_header_t, protocol);
}

uword
unformat_pg_hdlc_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_hdlc_header_t *h;
  u32 group_index, error;

  h = pg_create_edit_group (s, sizeof (h[0]), sizeof (hdlc_header_t),
			    &group_index);
  pg_hdlc_header_init (h);

  pg_edit_set_fixed (&h->address, 0x0f);
  pg_edit_set_fixed (&h->control, 0x00);

  error = 1;
  if (!unformat (input, "%U",
		 unformat_pg_edit,
		 unformat_hdlc_protocol_net_byte_order, &h->protocol))
    goto done;

  {
    hdlc_main_t *pm = &hdlc_main;
    hdlc_protocol_info_t *pi = 0;
    pg_node_t *pg_node = 0;

    if (h->protocol.type == PG_EDIT_FIXED)
      {
	u16 t = *(u16 *) h->protocol.values[PG_EDIT_LO];
	pi = hdlc_get_protocol_info (pm, clib_net_to_host_u16 (t));
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
