/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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
 * ip/tcp_pg: TCP packet-generator interface
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

/* TCP flags bit 0 first. */
#define foreach_tcp_flag			\
  _ (FIN)					\
  _ (SYN)					\
  _ (RST)					\
  _ (PSH)					\
  _ (ACK)					\
  _ (URG)					\
  _ (ECE)					\
  _ (CWR)

#define foreach_tcp_options                                                   \
  _ (mss, TCP_OPTION_MSS, TCP_OPTION_LEN_MSS, 1)                              \
  _ (timestamp, TCP_OPTION_TIMESTAMP, TCP_OPTION_LEN_TIMESTAMP, 2)            \
  _ (winscale, TCP_OPTION_WINDOW_SCALE, TCP_OPTION_LEN_WINDOW_SCALE, 1)       \
  _ (sackperm, TCP_OPTION_SACK_PERMITTED, TCP_OPTION_LEN_SACK_PERMITTED, 0)   \
  _ (sack, TCP_OPTION_SACK_BLOCK, TCP_OPTION_LEN_SACK_BLOCK, 0)

static void
tcp_pg_edit_function (pg_main_t * pg,
		      pg_stream_t * s,
		      pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 ip_offset, tcp_offset;

  tcp_offset = g->start_byte_offset;
  ip_offset = (g - 1)->start_byte_offset;

  while (n_packets >= 1)
    {
      vlib_buffer_t *p0;
      ip4_header_t *ip0;
      tcp_header_t *tcp0;
      ip_csum_t sum0;
      u32 tcp_len0;

      p0 = vlib_get_buffer (vm, packets[0]);
      n_packets -= 1;
      packets += 1;

      ASSERT (p0->current_data == 0);
      ip0 = (void *) (p0->data + ip_offset);
      tcp0 = (void *) (p0->data + tcp_offset);
      /* if IP length has been specified, then calculate the length based on buffer */
      if (ip0->length == 0)
	tcp_len0 = vlib_buffer_length_in_chain (vm, p0) - tcp_offset;
      else
	tcp_len0 = clib_net_to_host_u16 (ip0->length) - tcp_offset;

      /* Initialize checksum with header. */
      if (BITS (sum0) == 32)
	{
	  sum0 = clib_mem_unaligned (&ip0->src_address, u32);
	  sum0 =
	    ip_csum_with_carry (sum0,
				clib_mem_unaligned (&ip0->dst_address, u32));
	}
      else
	sum0 = clib_mem_unaligned (&ip0->src_address, u64);

      sum0 = ip_csum_with_carry
	(sum0, clib_host_to_net_u32 (tcp_len0 + (ip0->protocol << 16)));

      /* Invalidate possibly old checksum. */
      tcp0->checksum = 0;

      sum0 =
	ip_incremental_checksum_buffer (vm, p0, tcp_offset, tcp_len0, sum0);

      tcp0->checksum = ~ip_csum_fold (sum0);
    }
}

typedef struct
{
  pg_edit_t src, dst;
  pg_edit_t seq_number, ack_number;
  pg_edit_t data_offset_and_reserved;
#define _(f) pg_edit_t f##_flag;
    foreach_tcp_flag
#undef _
    pg_edit_t window;
  pg_edit_t checksum;
  pg_edit_t urgent_pointer;
} pg_tcp_header_t;

static inline void
pg_tcp_header_init (pg_tcp_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, tcp_header_t, f);
  _(src);
  _(dst);
  _(seq_number);
  _(ack_number);
  _(window);
  _(checksum);
  _(urgent_pointer);
#undef _

  /* Initialize bit fields. */
#define _(f)						\
  pg_edit_init_bitfield (&p->f##_flag, tcp_header_t,	\
			 flags,				\
			 TCP_FLAG_BIT_##f, 1);

  foreach_tcp_flag
#undef _
    pg_edit_init_bitfield (&p->data_offset_and_reserved, tcp_header_t,
			   data_offset_and_reserved, 4, 4);
}

uword
unformat_pg_tcp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  pg_tcp_header_t *pth;
  u32 header_group_index, opt_group_index = ~0, noop_len, opts_len = 0;

  pth = pg_create_edit_group (s, sizeof (pth[0]), sizeof (tcp_header_t),
			      &header_group_index);
  pg_tcp_header_init (pth);

  /* Defaults. */
  pg_edit_set_fixed (&pth->seq_number, 0);
  pg_edit_set_fixed (&pth->ack_number, 0);

  pg_edit_set_fixed (&pth->window, 4096);
  pg_edit_set_fixed (&pth->urgent_pointer, 0);

#define _(f) pg_edit_set_fixed (&pth->f##_flag, 0);
  foreach_tcp_flag
#undef _
    pth->checksum.type = PG_EDIT_UNSPECIFIED;

  if (!unformat (input, "TCP: %U -> %U", unformat_pg_edit,
		 unformat_tcp_udp_port, &pth->src, unformat_pg_edit,
		 unformat_tcp_udp_port, &pth->dst))
    goto error;

  /* Parse options. */
  while (1)
    {
      if (unformat (input, "window %U", unformat_pg_edit, unformat_pg_number,
		    &pth->window))
	;

      else if (unformat (input, "checksum %U", unformat_pg_edit,
			 unformat_pg_number, &pth->checksum))
	;

      else if (unformat (input, "seqnum %U", unformat_pg_edit,
			 unformat_pg_number, &pth->seq_number))
	;
      else if (unformat (input, "acknum %U", unformat_pg_edit,
			 unformat_pg_number, &pth->ack_number))
	;
      /* Flags. */
#define _(f)                                                                  \
  else if (unformat (input, #f)) pg_edit_set_fixed (&pth->f##_flag, 1);
      foreach_tcp_flag
#undef _
	/* Can't parse input: try TCP options and next protocol level. */
	else break;
    }

  while (unformat (input, "opt"))
    {
      int i;
      pg_edit_t *opt_header, *opt_values;
      u8 type, opt_len, n_values;

      /* first allocate a new edit group for options */
      if (opt_group_index == ~0)
	(void) pg_create_edit_group (s, 0, 0, &opt_group_index);

      if (false)
	{
	}
#define _(n, t, l, k)                                                         \
  else if (unformat (input, #n))                                              \
  {                                                                           \
    type = (t);                                                               \
    opt_len = (l);                                                            \
    n_values = (k);                                                           \
  }
      foreach_tcp_options
#undef _
	else
      {
	/* unknown TCP option */
	break;
      }

#define pg_tcp_option_init(e, o, b)                                           \
  do                                                                          \
    {                                                                         \
      *(o) += (b);                                                            \
      (e)->lsb_bit_offset = *(o) > 0 ? (*(o) -1) * BITS (u8) : 0;             \
      (e)->n_bits = (b) *BITS (u8);                                           \
    }                                                                         \
  while (0);

      /* if we don't know how many values to read, just ask */
      if (n_values == 0 &&
	  unformat (input, "nvalues %D", sizeof (n_values), &n_values))
	{
	  switch (type)
	    {
	    case TCP_OPTION_SACK_BLOCK:
	      /* each sack block is composed of 2 32-bits values */
	      n_values *= 2;
	      /*
		opt_len contains the length of a single sack block,
		it needs to be updated to contains the final number of bytes
		for the sack options
	      */
	      opt_len = 2 + 2 * opt_len;
	      break;
	    default:
	      /* unknown variable options */
	      continue;
	    }
	}

      opt_header = pg_add_edits (s, sizeof (pg_edit_t) * (2 + n_values),
				 opt_len, opt_group_index);
      pg_tcp_option_init (opt_header, &opts_len, 1);
      pg_tcp_option_init (opt_header + 1, &opts_len, 1);
      pg_edit_set_fixed (opt_header, type);
      pg_edit_set_fixed (opt_header + 1, opt_len);
      opt_values = opt_header + 2;

      switch (type)
	{
	case TCP_OPTION_MSS:
	  pg_tcp_option_init (opt_values, &opts_len, 2);
	  break;
	case TCP_OPTION_WINDOW_SCALE:
	  pg_tcp_option_init (opt_values, &opts_len, 1);
	  break;
	case TCP_OPTION_TIMESTAMP:
	case TCP_OPTION_SACK_BLOCK:
	  for (i = 0; i < n_values; ++i)
	    pg_tcp_option_init (opt_values + i, &opts_len, 4);
	  break;
	default:
	  break;
	}

      for (i = 0; i < n_values; ++i)
	{
	  if (!unformat (input, "%U", unformat_pg_edit, unformat_pg_number,
			 opt_values + i))
	    goto error;
	}
    }

  /* add TCP NO-OP options to fill options up to a 4-bytes boundary */
  noop_len = (TCP_OPTS_ALIGN - opts_len % TCP_OPTS_ALIGN) % TCP_OPTS_ALIGN;
  if (noop_len > 0)
    {
      pg_edit_t *noop_edit;
      u8 *noops = 0;

      vec_validate (noops, noop_len - 1);
      clib_memset (noops, 1, noop_len);

      noop_edit =
	pg_add_edits (s, sizeof (noop_edit[0]), noop_len, opt_group_index);
      pg_tcp_option_init (noop_edit, &opts_len, noop_len);
      noop_edit->type = PG_EDIT_FIXED;
      noop_edit->values[PG_EDIT_LO] = noops;
    }
#undef pg_tcp_option_init

  /* set the data offset according to options */
  pg_edit_set_fixed (&pth->data_offset_and_reserved,
		     (sizeof (tcp_header_t) + opts_len) / sizeof (u32));

  {
    ip_main_t *im = &ip_main;
    u16 dst_port;
    tcp_udp_port_info_t *pi;

    pi = 0;
    if (pth->dst.type == PG_EDIT_FIXED)
      {
	dst_port = pg_edit_get_value (&pth->dst, PG_EDIT_LO);
	pi = ip_get_tcp_udp_port_info (im, dst_port);
      }

    if (pi && pi->unformat_pg_edit &&
	unformat_user (input, pi->unformat_pg_edit, s))
      ;

    else if (!unformat_user (input, unformat_pg_payload, s))
      goto error;

    if (pth->checksum.type == PG_EDIT_UNSPECIFIED)
      {
	pg_edit_group_t *g = pg_stream_get_group (s, header_group_index);
	g->edit_function = tcp_pg_edit_function;
	g->edit_function_opaque = 0;
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
