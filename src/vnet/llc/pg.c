/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* llc_pg.c: packet generator llc interface */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/llc/llc.h>

typedef struct
{
  pg_edit_t dst_sap;
  pg_edit_t src_sap;
  pg_edit_t control;
} pg_llc_header_t;

static inline void
pg_llc_header_init (pg_llc_header_t * e)
{
  pg_edit_init (&e->dst_sap, llc_header_t, dst_sap);
  pg_edit_init (&e->src_sap, llc_header_t, src_sap);
  pg_edit_init (&e->control, llc_header_t, control);
}

uword
unformat_pg_llc_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_llc_header_t *h;
  u32 group_index, error;

  h = pg_create_edit_group (s, sizeof (h[0]), sizeof (llc_header_t),
			    &group_index);
  pg_llc_header_init (h);

  pg_edit_set_fixed (&h->control, 0x03);

  error = 1;
  if (!unformat (input, "%U -> %U",
		 unformat_pg_edit,
		 unformat_llc_protocol, &h->src_sap, &h->dst_sap))
    goto done;

  {
    llc_main_t *pm = &llc_main;
    llc_protocol_info_t *pi = 0;
    pg_node_t *pg_node = 0;

    if (h->dst_sap.type == PG_EDIT_FIXED)
      {
	u8 t = *h->dst_sap.values[PG_EDIT_LO];
	pi = llc_get_protocol_info (pm, t);
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
