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
 * ip/ip4_pg: IP v4 packet-generator interface
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

#define IP4_PG_EDIT_CHECKSUM (1 << 0)
#define IP4_PG_EDIT_LENGTH (1 << 1)

static_always_inline void
compute_length_and_or_checksum (vlib_main_t * vm,
				u32 * packets,
				u32 n_packets,
				u32 ip_header_offset, u32 flags)
{
  ASSERT (flags != 0);

  while (n_packets >= 2)
    {
      u32 pi0, pi1;
      vlib_buffer_t *p0, *p1;
      ip4_header_t *ip0, *ip1;
      ip_csum_t sum0, sum1;

      pi0 = packets[0];
      pi1 = packets[1];
      p0 = vlib_get_buffer (vm, pi0);
      p1 = vlib_get_buffer (vm, pi1);
      n_packets -= 2;
      packets += 2;

      ip0 = (void *) (p0->data + ip_header_offset);
      ip1 = (void *) (p1->data + ip_header_offset);

      if (flags & IP4_PG_EDIT_LENGTH)
	{
	  ip0->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p0) -
				  ip_header_offset);
	  ip1->length =
	    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p1) -
				  ip_header_offset);
	}

      if (flags & IP4_PG_EDIT_CHECKSUM)
	{
	  ASSERT (ip4_header_bytes (ip0) == sizeof (ip0[0]));
	  ASSERT (ip4_header_bytes (ip1) == sizeof (ip1[0]));

	  ip0->checksum = 0;
	  ip1->checksum = 0;

	  ip4_partial_header_checksum_x2 (ip0, ip1, sum0, sum1);
	  ip0->checksum = ~ip_csum_fold (sum0);
	  ip1->checksum = ~ip_csum_fold (sum1);

	  ASSERT (ip0->checksum == ip4_header_checksum (ip0));
	  ASSERT (ip1->checksum == ip4_header_checksum (ip1));
	}
    }

  while (n_packets >= 1)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      ip4_header_t *ip0;
      ip_csum_t sum0;

      pi0 = packets[0];
      p0 = vlib_get_buffer (vm, pi0);
      n_packets -= 1;
      packets += 1;

      ip0 = (void *) (p0->data + ip_header_offset);

      if (flags & IP4_PG_EDIT_LENGTH)
	ip0->length =
	  clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, p0) -
				ip_header_offset);

      if (flags & IP4_PG_EDIT_CHECKSUM)
	{
	  ASSERT (ip4_header_bytes (ip0) == sizeof (ip0[0]));

	  ip0->checksum = 0;

	  ip4_partial_header_checksum_x1 (ip0, sum0);
	  ip0->checksum = ~ip_csum_fold (sum0);

	  ASSERT (ip0->checksum == ip4_header_checksum (ip0));
	}
    }
}

static void
ip4_pg_edit_function (pg_main_t * pg,
		      pg_stream_t * s,
		      pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 ip_offset;

  ip_offset = g->start_byte_offset;

  switch (g->edit_function_opaque)
    {
    case IP4_PG_EDIT_LENGTH:
      compute_length_and_or_checksum (vm, packets, n_packets, ip_offset,
				      IP4_PG_EDIT_LENGTH);
      break;

    case IP4_PG_EDIT_CHECKSUM:
      compute_length_and_or_checksum (vm, packets, n_packets, ip_offset,
				      IP4_PG_EDIT_CHECKSUM);
      break;

    case IP4_PG_EDIT_LENGTH | IP4_PG_EDIT_CHECKSUM:
      compute_length_and_or_checksum (vm, packets, n_packets, ip_offset,
				      IP4_PG_EDIT_LENGTH
				      | IP4_PG_EDIT_CHECKSUM);
      break;

    default:
      ASSERT (0);
      break;
    }
}

typedef struct
{
  pg_edit_t ip_version, header_length;
  pg_edit_t tos;
  pg_edit_t length;

  pg_edit_t fragment_id, fragment_offset;

  /* Flags together with fragment offset. */
  pg_edit_t mf_flag, df_flag, ce_flag;

  pg_edit_t ttl;

  pg_edit_t protocol;

  pg_edit_t checksum;

  pg_edit_t src_address, dst_address;
} pg_ip4_header_t;

static inline void
pg_ip4_header_init (pg_ip4_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, ip4_header_t, f);
  _(tos);
  _(length);
  _(fragment_id);
  _(ttl);
  _(protocol);
  _(checksum);
  _(src_address);
  _(dst_address);
#undef _

  /* Initialize bit fields. */
  pg_edit_init_bitfield (&p->header_length, ip4_header_t,
			 ip_version_and_header_length, 0, 4);
  pg_edit_init_bitfield (&p->ip_version, ip4_header_t,
			 ip_version_and_header_length, 4, 4);

  pg_edit_init_bitfield (&p->fragment_offset, ip4_header_t,
			 flags_and_fragment_offset, 0, 13);
  pg_edit_init_bitfield (&p->mf_flag, ip4_header_t,
			 flags_and_fragment_offset, 13, 1);
  pg_edit_init_bitfield (&p->df_flag, ip4_header_t,
			 flags_and_fragment_offset, 14, 1);
  pg_edit_init_bitfield (&p->ce_flag, ip4_header_t,
			 flags_and_fragment_offset, 15, 1);
}

uword
unformat_pg_ip4_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_ip4_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (ip4_header_t),
			    &group_index);
  pg_ip4_header_init (p);

  /* Defaults. */
  pg_edit_set_fixed (&p->ip_version, 4);
  pg_edit_set_fixed (&p->header_length, sizeof (ip4_header_t) / sizeof (u32));

  pg_edit_set_fixed (&p->tos, 0);
  pg_edit_set_fixed (&p->ttl, 64);

  pg_edit_set_fixed (&p->fragment_id, 0);
  pg_edit_set_fixed (&p->fragment_offset, 0);
  pg_edit_set_fixed (&p->mf_flag, 0);
  pg_edit_set_fixed (&p->df_flag, 0);
  pg_edit_set_fixed (&p->ce_flag, 0);

  p->length.type = PG_EDIT_UNSPECIFIED;
  p->checksum.type = PG_EDIT_UNSPECIFIED;

  if (unformat (input, "%U: %U -> %U",
		unformat_pg_edit,
		unformat_ip_protocol, &p->protocol,
		unformat_pg_edit,
		unformat_ip4_address, &p->src_address,
		unformat_pg_edit, unformat_ip4_address, &p->dst_address))
    goto found;

  if (!unformat (input, "%U:",
		 unformat_pg_edit, unformat_ip_protocol, &p->protocol))
    goto error;

found:
  /* Parse options. */
  while (1)
    {
      if (unformat (input, "version %U",
		    unformat_pg_edit, unformat_pg_number, &p->ip_version))
	;

      else if (unformat (input, "header-length %U",
			 unformat_pg_edit,
			 unformat_pg_number, &p->header_length))
	;

      else if (unformat (input, "tos %U",
			 unformat_pg_edit, unformat_pg_number, &p->tos))
	;

      else if (unformat (input, "length %U",
			 unformat_pg_edit, unformat_pg_number, &p->length))
	;

      else if (unformat (input, "checksum %U",
			 unformat_pg_edit, unformat_pg_number, &p->checksum))
	;

      else if (unformat (input, "ttl %U",
			 unformat_pg_edit, unformat_pg_number, &p->ttl))
	;

      else if (unformat (input, "fragment id %U offset %U",
			 unformat_pg_edit,
			 unformat_pg_number, &p->fragment_id,
			 unformat_pg_edit,
			 unformat_pg_number, &p->fragment_offset))
	{
	  int i;
	  for (i = 0; i < ARRAY_LEN (p->fragment_offset.values); i++)
	    pg_edit_set_value (&p->fragment_offset, i,
			       pg_edit_get_value (&p->fragment_offset,
						  i) / 8);

	}

      /* Flags. */
      else if (unformat (input, "mf") || unformat (input, "MF"))
	pg_edit_set_fixed (&p->mf_flag, 1);

      else if (unformat (input, "df") || unformat (input, "DF"))
	pg_edit_set_fixed (&p->df_flag, 1);

      else if (unformat (input, "ce") || unformat (input, "CE"))
	pg_edit_set_fixed (&p->ce_flag, 1);

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

    if (p->length.type == PG_EDIT_UNSPECIFIED
	&& s->min_packet_bytes == s->max_packet_bytes
	&& group_index + 1 < vec_len (s->edit_groups))
      {
	pg_edit_set_fixed (&p->length,
			   pg_edit_group_n_bytes (s, group_index));
      }

    /* Compute IP header checksum if all edits are fixed. */
    if (p->checksum.type == PG_EDIT_UNSPECIFIED)
      {
	ip4_header_t fixed_header, fixed_mask, cmp_mask;

	/* See if header is all fixed and specified except for
	   checksum field. */
	clib_memset (&cmp_mask, ~0, sizeof (cmp_mask));
	cmp_mask.checksum = 0;

	pg_edit_group_get_fixed_packet_data (s, group_index,
					     &fixed_header, &fixed_mask);
	if (!memcmp (&fixed_mask, &cmp_mask, sizeof (cmp_mask)))
	  pg_edit_set_fixed (&p->checksum,
			     clib_net_to_host_u16 (ip4_header_checksum
						   (&fixed_header)));
      }

    p = pg_get_edit_group (s, group_index);
    if (p->length.type == PG_EDIT_UNSPECIFIED
	|| p->checksum.type == PG_EDIT_UNSPECIFIED)
      {
	pg_edit_group_t *g = pg_stream_get_group (s, group_index);
	g->edit_function = ip4_pg_edit_function;
	g->edit_function_opaque = 0;
	if (p->length.type == PG_EDIT_UNSPECIFIED)
	  g->edit_function_opaque |= IP4_PG_EDIT_LENGTH;
	if (p->checksum.type == PG_EDIT_UNSPECIFIED)
	  g->edit_function_opaque |= IP4_PG_EDIT_CHECKSUM;
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
