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
 * ip/ip6_pg: IP v4 packet-generator interface
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

#include <vnet/ip/ip.h>
#include <vnet/pg/pg.h>

static void
ip6_pg_edit_function (pg_main_t * pg,
		      pg_stream_t * s,
		      pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 ip_header_offset = g->start_byte_offset;

  while (n_packets >= 2)
    {
      u32 pi0, pi1;
      vlib_buffer_t *p0, *p1;
      ip6_header_t *ip0, *ip1;

      pi0 = packets[0];
      pi1 = packets[1];
      p0 = vlib_get_buffer (vm, pi0);
      p1 = vlib_get_buffer (vm, pi1);
      n_packets -= 2;
      packets += 2;

      ip0 = (void *) (p0->data + ip_header_offset);
      ip1 = (void *) (p1->data + ip_header_offset);

      ip0->payload_length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p0) -
			      ip_header_offset - sizeof (ip0[0]));
      ip1->payload_length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p1) -
			      ip_header_offset - sizeof (ip1[0]));
    }

  while (n_packets >= 1)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      ip6_header_t *ip0;

      pi0 = packets[0];
      p0 = vlib_get_buffer (vm, pi0);
      n_packets -= 1;
      packets += 1;

      ip0 = (void *) (p0->data + ip_header_offset);

      ip0->payload_length =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p0) -
			      ip_header_offset - sizeof (ip0[0]));
    }
}

typedef struct
{
  pg_edit_t ip_version;
  pg_edit_t traffic_class;
  pg_edit_t flow_label;
  pg_edit_t payload_length;
  pg_edit_t protocol;
  pg_edit_t hop_limit;
  pg_edit_t src_address, dst_address;
} pg_ip6_header_t;

static inline void
pg_ip6_header_init (pg_ip6_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, ip6_header_t, f);
  _(payload_length);
  _(hop_limit);
  _(protocol);
  _(src_address);
  _(dst_address);
#undef _

  /* Initialize bit fields. */
  pg_edit_init_bitfield (&p->ip_version, ip6_header_t,
			 ip_version_traffic_class_and_flow_label, 28, 4);
  pg_edit_init_bitfield (&p->traffic_class, ip6_header_t,
			 ip_version_traffic_class_and_flow_label, 20, 8);
  pg_edit_init_bitfield (&p->flow_label, ip6_header_t,
			 ip_version_traffic_class_and_flow_label, 0, 20);
}

uword
unformat_pg_ip6_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_ip6_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (ip6_header_t),
			    &group_index);
  pg_ip6_header_init (p);

  /* Defaults. */
  pg_edit_set_fixed (&p->ip_version, 6);
  pg_edit_set_fixed (&p->traffic_class, 0);
  pg_edit_set_fixed (&p->flow_label, 0);
  pg_edit_set_fixed (&p->hop_limit, 64);

  p->payload_length.type = PG_EDIT_UNSPECIFIED;

  if (!unformat (input, "%U: %U -> %U",
		 unformat_pg_edit,
		 unformat_ip_protocol, &p->protocol,
		 unformat_pg_edit,
		 unformat_ip6_address, &p->src_address,
		 unformat_pg_edit, unformat_ip6_address, &p->dst_address))
    goto error;

  /* Parse options. */
  while (1)
    {
      if (unformat (input, "version %U",
		    unformat_pg_edit, unformat_pg_number, &p->ip_version))
	;

      else if (unformat (input, "traffic-class %U",
			 unformat_pg_edit,
			 unformat_pg_number, &p->traffic_class))
	;

      else if (unformat (input, "length %U",
			 unformat_pg_edit,
			 unformat_pg_number, &p->payload_length))
	;

      else if (unformat (input, "hop-limit %U",
			 unformat_pg_edit, unformat_pg_number, &p->hop_limit))
	;

      /* Can't parse input: try next protocol level. */
      else
	break;
    }

  {
    ip_main_t *im = &ip_main;
    ip_protocol_t protocol;
    ip_protocol_info_t *pi;

    pi = 0;
    if (p->protocol.type == PG_EDIT_FIXED)
      {
	protocol = pg_edit_get_value (&p->protocol, PG_EDIT_LO);
	pi = ip_get_protocol_info (im, protocol);
      }

    if (pi && pi->unformat_pg_edit
	&& unformat_user (input, pi->unformat_pg_edit, s))
      ;

    else if (!unformat_user (input, unformat_pg_payload, s))
      goto error;

    if (p->payload_length.type == PG_EDIT_UNSPECIFIED
	&& s->min_packet_bytes == s->max_packet_bytes
	&& group_index + 1 < vec_len (s->edit_groups))
      {
	pg_edit_set_fixed (&p->payload_length,
			   pg_edit_group_n_bytes (s,
						  group_index) -
			   sizeof (ip6_header_t));
      }

    p = pg_get_edit_group (s, group_index);
    if (p->payload_length.type == PG_EDIT_UNSPECIFIED)
      {
	pg_edit_group_t *g = pg_stream_get_group (s, group_index);
	g->edit_function = ip6_pg_edit_function;
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
