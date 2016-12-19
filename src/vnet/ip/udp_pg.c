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
 * ip/udp_pg: UDP packet-generator interface
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

#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>		/* for unformat_udp_udp_port */

#define UDP_PG_EDIT_LENGTH (1 << 0)
#define UDP_PG_EDIT_CHECKSUM (1 << 1)

always_inline void
udp_pg_edit_function_inline (pg_main_t * pg,
			     pg_stream_t * s,
			     pg_edit_group_t * g,
			     u32 * packets, u32 n_packets, u32 flags)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 ip_offset, udp_offset;

  udp_offset = g->start_byte_offset;
  ip_offset = (g - 1)->start_byte_offset;

  while (n_packets >= 1)
    {
      vlib_buffer_t *p0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      u32 udp_len0;

      p0 = vlib_get_buffer (vm, packets[0]);
      n_packets -= 1;
      packets += 1;

      ip0 = (void *) (p0->data + ip_offset);
      udp0 = (void *) (p0->data + udp_offset);
      udp_len0 = clib_net_to_host_u16 (ip0->length) - sizeof (ip0[0]);

      if (flags & UDP_PG_EDIT_LENGTH)
	udp0->length =
	  clib_net_to_host_u16 (vlib_buffer_length_in_chain (vm, p0)
				- ip_offset);

      /* Initialize checksum with header. */
      if (flags & UDP_PG_EDIT_CHECKSUM)
	{
	  ip_csum_t sum0;

	  sum0 = clib_mem_unaligned (&ip0->src_address, u64);

	  sum0 = ip_csum_with_carry
	    (sum0, clib_host_to_net_u32 (udp_len0 + (ip0->protocol << 16)));

	  /* Invalidate possibly old checksum. */
	  udp0->checksum = 0;

	  sum0 =
	    ip_incremental_checksum_buffer (vm, p0, udp_offset, udp_len0,
					    sum0);

	  sum0 = ~ip_csum_fold (sum0);

	  /* Zero checksum means checksumming disabled. */
	  sum0 = sum0 != 0 ? sum0 : 0xffff;

	  udp0->checksum = sum0;
	}
    }
}

static void
udp_pg_edit_function (pg_main_t * pg,
		      pg_stream_t * s,
		      pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  switch (g->edit_function_opaque)
    {
    case UDP_PG_EDIT_LENGTH:
      udp_pg_edit_function_inline (pg, s, g, packets, n_packets,
				   UDP_PG_EDIT_LENGTH);
      break;

    case UDP_PG_EDIT_CHECKSUM:
      udp_pg_edit_function_inline (pg, s, g, packets, n_packets,
				   UDP_PG_EDIT_CHECKSUM);
      break;

    case UDP_PG_EDIT_CHECKSUM | UDP_PG_EDIT_LENGTH:
      udp_pg_edit_function_inline (pg, s, g, packets, n_packets,
				   UDP_PG_EDIT_CHECKSUM | UDP_PG_EDIT_LENGTH);
      break;

    default:
      ASSERT (0);
      break;
    }
}

typedef struct
{
  pg_edit_t src_port, dst_port;
  pg_edit_t length;
  pg_edit_t checksum;
} pg_udp_header_t;

static inline void
pg_udp_header_init (pg_udp_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, udp_header_t, f);
  _(src_port);
  _(dst_port);
  _(length);
  _(checksum);
#undef _
}

uword
unformat_pg_udp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_udp_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (udp_header_t),
			    &group_index);
  pg_udp_header_init (p);

  /* Defaults. */
  p->checksum.type = PG_EDIT_UNSPECIFIED;
  p->length.type = PG_EDIT_UNSPECIFIED;

  if (!unformat (input, "UDP: %U -> %U",
		 unformat_pg_edit,
		 unformat_tcp_udp_port, &p->src_port,
		 unformat_pg_edit, unformat_tcp_udp_port, &p->dst_port))
    goto error;

  /* Parse options. */
  while (1)
    {
      if (unformat (input, "length %U",
		    unformat_pg_edit, unformat_pg_number, &p->length))
	;

      else if (unformat (input, "checksum %U",
			 unformat_pg_edit, unformat_pg_number, &p->checksum))
	;

      /* Can't parse input: try next protocol level. */
      else
	break;
    }

  {
    ip_main_t *im = &ip_main;
    u16 dst_port;
    tcp_udp_port_info_t *pi;

    pi = 0;
    if (p->dst_port.type == PG_EDIT_FIXED)
      {
	dst_port = pg_edit_get_value (&p->dst_port, PG_EDIT_LO);
	pi = ip_get_tcp_udp_port_info (im, dst_port);
      }

    if (pi && pi->unformat_pg_edit
	&& unformat_user (input, pi->unformat_pg_edit, s))
      ;

    else if (!unformat_user (input, unformat_pg_payload, s))
      goto error;

    p = pg_get_edit_group (s, group_index);
    if (p->checksum.type == PG_EDIT_UNSPECIFIED
	|| p->length.type == PG_EDIT_UNSPECIFIED)
      {
	pg_edit_group_t *g = pg_stream_get_group (s, group_index);
	g->edit_function = udp_pg_edit_function;
	g->edit_function_opaque = 0;
	if (p->checksum.type == PG_EDIT_UNSPECIFIED)
	  g->edit_function_opaque |= UDP_PG_EDIT_CHECKSUM;
	if (p->length.type == PG_EDIT_UNSPECIFIED)
	  g->edit_function_opaque |= UDP_PG_EDIT_LENGTH;
      }

    return 1;
  }

error:
  /* Free up any edits we may have added. */
  pg_free_edit_group (s);
  return 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
