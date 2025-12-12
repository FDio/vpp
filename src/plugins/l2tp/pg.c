/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2013 Cisco and/or its affiliates.
 */

/* pg.c: packet generator for L2TPv3 header */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <l2tp/l2tp.h>

typedef struct
{
  pg_edit_t session_id;
  pg_edit_t cookie;
} pg_l2tp_header_t;

typedef struct
{
  pg_edit_t l2_sublayer;
} pg_l2tp_header_l2_sublayer_t;

static inline void
pg_l2tp_header_init (pg_l2tp_header_t * e)
{
  pg_edit_init (&e->session_id, l2tpv3_header_t, session_id);
  pg_edit_init (&e->cookie, l2tpv3_header_t, cookie);
}

uword
unformat_pg_l2tp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_l2tp_header_t *h;
  u32 group_index, error;
  vlib_main_t *vm = vlib_get_main ();

  h = pg_create_edit_group (s, sizeof (h[0]),
			    sizeof (l2tpv3_header_t) - sizeof (u32),
			    &group_index);
  pg_l2tp_header_init (h);

  error = 1;

  /* session id and cookie are required */
  if (!unformat (input, "L2TP: session_id %U cookie %U",
		 unformat_pg_edit, unformat_pg_number, &h->session_id,
		 unformat_pg_edit, unformat_pg_number, &h->cookie))
    {
      goto done;
    }

  /* "l2_sublayer <value>" is optional */
  if (unformat (input, "l2_sublayer"))
    {
      pg_l2tp_header_l2_sublayer_t *h2;

      h2 = pg_add_edits (s, sizeof (h2[0]), sizeof (u32), group_index);
      pg_edit_init (&h2->l2_sublayer, l2tpv3_header_t, l2_specific_sublayer);
      if (!unformat_user (input, unformat_pg_edit,
			  unformat_pg_number, &h2->l2_sublayer))
	{
	  goto done;
	}
    }

  /* Parse an ethernet header if it is present */
  {
    pg_node_t *pg_node = 0;
    vlib_node_t *eth_lookup_node;

    eth_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
    ASSERT (eth_lookup_node);

    pg_node = pg_get_node (eth_lookup_node->index);

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
