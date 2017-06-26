/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

  u16 mss;		/**< Maximum segment size advertised */
  u8 wscale;		/**< Window scale advertised */
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
#endif /* included_tcp_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
