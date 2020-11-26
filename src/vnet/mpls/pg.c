/*
 * pg.c: packet generator mpls interface
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
#include <vnet/mpls/mpls.h>

typedef struct {
  pg_edit_t label;
} pg_mpls_header_t;

static inline void
pg_mpls_header_init (pg_mpls_header_t * e)
{
  pg_edit_init (&e->label, mpls_unicast_header_t, label_exp_s_ttl);
}

uword
unformat_pg_mpls_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t * s = va_arg (*args, pg_stream_t *);
  pg_mpls_header_t * h;
  vlib_main_t * vm = vlib_get_main();
  u32 group_index, error;
  
  h = pg_create_edit_group (s, sizeof (h[0]), sizeof (mpls_unicast_header_t),
			    &group_index);
  pg_mpls_header_init (h);

  error = 1;
  if (! unformat (input, "%U",
		  unformat_pg_edit,
                  unformat_mpls_label_net_byte_order, &h->label))
    goto done;

  {
    pg_node_t * pg_node = 0;
    vlib_node_t * ip_lookup_node;

    ip_lookup_node = vlib_get_node_by_name (vm, (u8 *)"ip4-input");
    ASSERT (ip_lookup_node);

    pg_node = pg_get_node (ip_lookup_node->index);

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

