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

#ifndef included_tcp_packet_h
#define included_tcp_packet_h

#include <vnet/vnet.h>

/* TCP flags bit 0 first. */
#define foreach_tcp_flag                                \
  _ (FIN) /**< No more data from sender. */             \
  _ (SYN) /**< Synchronize sequence numbers. */         \
  _ (RST) /**< Reset the connection. */                 \
  _ (PSH) /**< Push function. */                        \
  _ (ACK) /**< Ack field significant. */                \
  _ (URG) /**< Urgent pointer field significant. */     \
  _ (ECE) /**< ECN-echo. Receiver got CE packet */      \
  _ (CWR) /**< Sender reduced congestion window */

enum
{
#define _(f) TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
    TCP_N_FLAG_BITS,
};

enum
{
#define _(f) TCP_FLAG_##f = 1 << TCP_FLAG_BIT_##f,
  foreach_tcp_flag
#undef _
};

typedef struct _tcp_header
{
  union
  {
    struct
    {
      u16 src_port; /**< Source port. */
      u16 dst_port; /**< Destination port. */
    };
    struct
    {
      u16 src, dst;
    };
  };

  u32 seq_number;	/**< Sequence number of the first data octet in this
                         *   segment, except when SYN is present. If SYN
                         *   is present the seq number is is the ISN and the
                         *   first data octet is ISN+1 */
  u32 ack_number;	/**< Acknowledgement number if ACK is set. It contains
                         *   the value of the next sequence number the sender
                         *   of the segment is expecting to receive. */
  u8 data_offset_and_reserved;
  u8 flags;		/**< Flags: see the macro above */
  u16 window;		/**< Number of bytes sender is willing to receive. */

  u16 checksum;		/**< Checksum of TCP pseudo header and data. */
  u16 urgent_pointer;	/**< Seq number of the byte after the urgent data. */
} __attribute__ ((packed)) tcp_header_t;

/* Flag tests that return 0 or !0 */
#define tcp_doff(_th) ((_th)->data_offset_and_reserved >> 4)
#define tcp_fin(_th) ((_th)->flags & TCP_FLAG_FIN)
#define tcp_syn(_th) ((_th)->flags & TCP_FLAG_SYN)
#define tcp_rst(_th) ((_th)->flags & TCP_FLAG_RST)
#define tcp_psh(_th) ((_th)->flags & TCP_FLAG_PSH)
#define tcp_ack(_th) ((_th)->flags & TCP_FLAG_ACK)
#define tcp_urg(_th) ((_th)->flags & TCP_FLAG_URG)
#define tcp_ece(_th) ((_th)->flags & TCP_FLAG_ECE)
#define tcp_cwr(_th) ((_th)->flags & TCP_FLAG_CWR)

/* Flag tests that return 0 or 1 */
#define tcp_is_syn(_th) !!((_th)->flags & TCP_FLAG_SYN)
#define tcp_is_fin(_th) !!((_th)->flags & TCP_FLAG_FIN)

always_inline int
tcp_header_bytes (tcp_header_t * t)
{
  return tcp_doff (t) * sizeof (u32);
}

/*
 * TCP options.
 */

typedef enum tcp_option_type
{
  TCP_OPTION_EOL = 0,			/**< End of options. */
  TCP_OPTION_NOOP = 1,			/**< No operation. */
  TCP_OPTION_MSS = 2,			/**< Limit MSS. */
  TCP_OPTION_WINDOW_SCALE = 3,		/**< Window scale. */
  TCP_OPTION_SACK_PERMITTED = 4,	/**< Selective Ack permitted. */
  TCP_OPTION_SACK_BLOCK = 5,		/**< Selective Ack block. */
  TCP_OPTION_TIMESTAMP = 8,		/**< Timestamps. */
  TCP_OPTION_UTO = 28,			/**< User timeout. */
  TCP_OPTION_AO = 29,			/**< Authentication Option. */
} tcp_option_type_t;

#define foreach_tcp_options_flag                                        \
  _ (MSS)               /**< MSS advertised in SYN */                   \
  _ (TSTAMP)            /**< Timestamp capability advertised in SYN */  \
  _ (WSCALE)            /**< Wnd scale capability advertised in SYN */  \
  _ (SACK_PERMITTED)    /**< SACK capability advertised in SYN */       \
  _ (SACK)		/**< SACK present */

enum
{
#define _(f) TCP_OPTS_FLAG_BIT_##f,
  foreach_tcp_options_flag
#undef _
    TCP_OPTIONS_N_FLAG_BITS,
};

enum
{
#define _(f) TCP_OPTS_FLAG_##f = 1 << TCP_OPTS_FLAG_BIT_##f,
  foreach_tcp_options_flag
#undef _
};

typedef struct _sack_block
{
  u32 start;		/**< Start sequence number */
  u32 end;		/**< End sequence number (first outside) */
} sack_block_t;

typedef struct
{
  u8 flags;		/** Option flags, see above */
  u8 wscale;		/**< Window scale advertised */
  u16 mss;		/**< Maximum segment size advertised */
  u32 tsval;		/**< Timestamp value */
  u32 tsecr;		/**< Echoed/reflected time stamp */
  sack_block_t *sacks;	/**< SACK blocks */
  u8 n_sack_blocks;	/**< Number of SACKs blocks */
} tcp_options_t;

/* Flag tests that return 0 or !0 */
#define tcp_opts_mss(_to) ((_to)->flags & TCP_OPTS_FLAG_MSS)
#define tcp_opts_tstamp(_to) ((_to)->flags & TCP_OPTS_FLAG_TSTAMP)
#define tcp_opts_wscale(_to) ((_to)->flags & TCP_OPTS_FLAG_WSCALE)
#define tcp_opts_sack(_to) ((_to)->flags & TCP_OPTS_FLAG_SACK)
#define tcp_opts_sack_permitted(_to) ((_to)->flags & TCP_OPTS_FLAG_SACK_PERMITTED)

/* TCP option lengths */
#define TCP_OPTION_LEN_EOL              1
#define TCP_OPTION_LEN_NOOP             1
#define TCP_OPTION_LEN_MSS              4
#define TCP_OPTION_LEN_WINDOW_SCALE     3
#define TCP_OPTION_LEN_SACK_PERMITTED   2
#define TCP_OPTION_LEN_TIMESTAMP        10
#define TCP_OPTION_LEN_SACK_BLOCK        8

#define TCP_HDR_LEN_MAX			60
#define TCP_WND_MAX                     65535U
#define TCP_MAX_WND_SCALE               14	/* See RFC 1323 */
#define TCP_OPTS_ALIGN                  4
#define TCP_OPTS_MAX_SACK_BLOCKS        3

/* Modulo arithmetic for TCP sequence numbers */
#define seq_lt(_s1, _s2) ((i32)((_s1)-(_s2)) < 0)
#define seq_leq(_s1, _s2) ((i32)((_s1)-(_s2)) <= 0)
#define seq_gt(_s1, _s2) ((i32)((_s1)-(_s2)) > 0)
#define seq_geq(_s1, _s2) ((i32)((_s1)-(_s2)) >= 0)
#define seq_max(_s1, _s2) (seq_gt((_s1), (_s2)) ? (_s1) : (_s2))

/* Modulo arithmetic for timestamps */
#define timestamp_lt(_t1, _t2) ((i32)((_t1)-(_t2)) < 0)
#define timestamp_leq(_t1, _t2) ((i32)((_t1)-(_t2)) <= 0)

/**
 * Parse TCP header options.
 *
 * @param th TCP header
 * @param to TCP options data structure to be populated
 * @param is_syn set if packet is syn
 * @return -1 if parsing failed
 */
always_inline int
tcp_options_parse (tcp_header_t * th, tcp_options_t * to, u8 is_syn)
{
  const u8 *data;
  u8 opt_len, opts_len, kind;
  int j;
  sack_block_t b;

  opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);
  data = (const u8 *) (th + 1);

  /* Zero out all flags but those set in SYN */
  to->flags &= (TCP_OPTS_FLAG_SACK_PERMITTED | TCP_OPTS_FLAG_WSCALE
		| TCP_OPTS_FLAG_TSTAMP | TCP_OPTS_FLAG_MSS);

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      /* Get options length */
      if (kind == TCP_OPTION_EOL)
	break;
      else if (kind == TCP_OPTION_NOOP)
	{
	  opt_len = 1;
	  continue;
	}
      else
	{
	  /* broken options */
	  if (opts_len < 2)
	    return -1;
	  opt_len = data[1];

	  /* weird option length */
	  if (opt_len < 2 || opt_len > opts_len)
	    return -1;
	}

      /* Parse options */
      switch (kind)
	{
	case TCP_OPTION_MSS:
	  if (!is_syn)
	    break;
	  if ((opt_len == TCP_OPTION_LEN_MSS) && tcp_syn (th))
	    {
	      to->flags |= TCP_OPTS_FLAG_MSS;
	      to->mss = clib_net_to_host_u16 (*(u16 *) (data + 2));
	    }
	  break;
	case TCP_OPTION_WINDOW_SCALE:
	  if (!is_syn)
	    break;
	  if ((opt_len == TCP_OPTION_LEN_WINDOW_SCALE) && tcp_syn (th))
	    {
	      to->flags |= TCP_OPTS_FLAG_WSCALE;
	      to->wscale = data[2];
	      if (to->wscale > TCP_MAX_WND_SCALE)
		to->wscale = TCP_MAX_WND_SCALE;
	    }
	  break;
	case TCP_OPTION_TIMESTAMP:
	  if (is_syn)
	    to->flags |= TCP_OPTS_FLAG_TSTAMP;
	  if ((to->flags & TCP_OPTS_FLAG_TSTAMP)
	      && opt_len == TCP_OPTION_LEN_TIMESTAMP)
	    {
	      to->tsval = clib_net_to_host_u32 (*(u32 *) (data + 2));
	      to->tsecr = clib_net_to_host_u32 (*(u32 *) (data + 6));
	    }
	  break;
	case TCP_OPTION_SACK_PERMITTED:
	  if (!is_syn)
	    break;
	  if (opt_len == TCP_OPTION_LEN_SACK_PERMITTED && tcp_syn (th))
	    to->flags |= TCP_OPTS_FLAG_SACK_PERMITTED;
	  break;
	case TCP_OPTION_SACK_BLOCK:
	  /* If SACK permitted was not advertised or a SYN, break */
	  if ((to->flags & TCP_OPTS_FLAG_SACK_PERMITTED) == 0 || tcp_syn (th))
	    break;

	  /* If too short or not correctly formatted, break */
	  if (opt_len < 10 || ((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
	    break;

	  to->flags |= TCP_OPTS_FLAG_SACK;
	  to->n_sack_blocks = (opt_len - 2) / TCP_OPTION_LEN_SACK_BLOCK;
	  vec_reset_length (to->sacks);
	  for (j = 0; j < to->n_sack_blocks; j++)
	    {
	      b.start = clib_net_to_host_u32 (*(u32 *) (data + 2 + 8 * j));
	      b.end = clib_net_to_host_u32 (*(u32 *) (data + 6 + 8 * j));
	      vec_add1 (to->sacks, b);
	    }
	  break;
	default:
	  /* Nothing to see here */
	  continue;
	}
    }
  return 0;
}

/**
 * Write TCP options to segment.
 *
 * @param data	buffer where to write the options
 * @param opts	options to write
 * @return	length of options written
 */
always_inline u32
tcp_options_write (u8 * data, tcp_options_t * opts)
{
  u32 opts_len = 0;
  u32 buf, seq_len = 4;

  if (tcp_opts_mss (opts))
    {
      *data++ = TCP_OPTION_MSS;
      *data++ = TCP_OPTION_LEN_MSS;
      buf = clib_host_to_net_u16 (opts->mss);
      clib_memcpy_fast (data, &buf, sizeof (opts->mss));
      data += sizeof (opts->mss);
      opts_len += TCP_OPTION_LEN_MSS;
    }

  if (tcp_opts_wscale (opts))
    {
      *data++ = TCP_OPTION_WINDOW_SCALE;
      *data++ = TCP_OPTION_LEN_WINDOW_SCALE;
      *data++ = opts->wscale;
      opts_len += TCP_OPTION_LEN_WINDOW_SCALE;
    }

  if (tcp_opts_sack_permitted (opts))
    {
      *data++ = TCP_OPTION_SACK_PERMITTED;
      *data++ = TCP_OPTION_LEN_SACK_PERMITTED;
      opts_len += TCP_OPTION_LEN_SACK_PERMITTED;
    }

  if (tcp_opts_tstamp (opts))
    {
      *data++ = TCP_OPTION_TIMESTAMP;
      *data++ = TCP_OPTION_LEN_TIMESTAMP;
      buf = clib_host_to_net_u32 (opts->tsval);
      clib_memcpy_fast (data, &buf, sizeof (opts->tsval));
      data += sizeof (opts->tsval);
      buf = clib_host_to_net_u32 (opts->tsecr);
      clib_memcpy_fast (data, &buf, sizeof (opts->tsecr));
      data += sizeof (opts->tsecr);
      opts_len += TCP_OPTION_LEN_TIMESTAMP;
    }

  if (tcp_opts_sack (opts))
    {
      int i;

      if (opts->n_sack_blocks != 0)
	{
	  *data++ = TCP_OPTION_SACK_BLOCK;
	  *data++ = 2 + opts->n_sack_blocks * TCP_OPTION_LEN_SACK_BLOCK;
	  for (i = 0; i < opts->n_sack_blocks; i++)
	    {
	      buf = clib_host_to_net_u32 (opts->sacks[i].start);
	      clib_memcpy_fast (data, &buf, seq_len);
	      data += seq_len;
	      buf = clib_host_to_net_u32 (opts->sacks[i].end);
	      clib_memcpy_fast (data, &buf, seq_len);
	      data += seq_len;
	    }
	  opts_len += 2 + opts->n_sack_blocks * TCP_OPTION_LEN_SACK_BLOCK;
	}
    }

  /* Terminate TCP options */
  if (opts_len % 4)
    {
      *data++ = TCP_OPTION_EOL;
      opts_len += TCP_OPTION_LEN_EOL;
    }

  /* Pad with zeroes to a u32 boundary */
  while (opts_len % 4)
    {
      *data++ = TCP_OPTION_NOOP;
      opts_len += TCP_OPTION_LEN_NOOP;
    }
  return opts_len;
}

#endif /* included_tcp_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
