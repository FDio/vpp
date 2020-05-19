/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __CALICO_SESSION_H__
#define __CALICO_SESSION_H__

#include <vnet/udp/udp.h>

#include <calico/calico_types.h>
#include <calico/calico_client.h>
#include <calico/bihash_40_48.h>


/**
 * A session represents the memory of a translation.
 * In the tx direction (from behind to in front of the NAT), the
 * session is preserved so subsequent packets follow the same path
 * even if the translation has been updated. In the tx direction
 * the session represents the swap from the VIP to the server address
 * In the RX direction the swap is from the server address/port to VIP.
 *
 * A session exists only as key and value in the bihash, there is no
 * pool for this object. If there were a pool, one would need to be
 * concerned about what worker is using it.
 */
typedef struct calico_session_t_
{
  /**
   * this key sits in the same memory location a 'key' in the bihash kvp
   */
  struct
  {
    /**
     * IP 4/6 address in the rx/tx direction
     */
    ip46_address_t cs_ip[VLIB_N_DIR];

    /**
     * ports in rx/tx
     */
    u16 cs_port[VLIB_N_DIR];

    /**
     * The IP protocol TCP or UDP only supported
     */
    ip_protocol_t cs_proto;

    /**
     * The address family describing the IP addresses
     */
    u8 cs_af;

    /**
     * spare space
     */
    u8 __cs_pad[2];
  } key;
  /**
   * this value sits in the same memory location a 'value' in the bihash kvp
   */
  struct
  {
    /**
     * The IP address to translate to.
     */
    ip46_address_t cs_ip[VLIB_N_DIR];

    /**
     * the port to translate to.
     */
    u16 cs_port[VLIB_N_DIR];

    /**
     * The load balance object to use to forward
     */
    index_t cs_lbi;

    /**
     * Timestamp index this session was last used
     */
    u32 cs_ts_index;
    /**
     * Indicates a return path session that was source NATed
     * on the way in.
     */
    u32 flags;
  } value;
} calico_session_t;

typedef enum calico_session_flag_t_
{
  CALICO_SESSION_FLAG_HAS_SNAT = (1 << 0),
  CALICO_SESSION_FLAG_NO_CLIENT = (1 << 1),
} calico_session_flag_t;

extern u8 *format_calico_session (u8 * s, va_list * args);

/**
 * Ensure the session object correctly overlays the bihash key/value pair
 */
STATIC_ASSERT (STRUCT_OFFSET_OF (calico_session_t, key) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_48_t, key),
	       "key overlaps");
STATIC_ASSERT (STRUCT_OFFSET_OF (calico_session_t, value) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_48_t, value),
	       "value overlaps");
STATIC_ASSERT (sizeof (calico_session_t) == sizeof (clib_bihash_kv_40_48_t),
	       "session kvp");

/**
 * The DB of sessions
 */
extern clib_bihash_40_48_t calico_session_db;

/**
 * Callback function invoked during a walk of all translations
 */
typedef walk_rc_t (*calico_session_walk_cb_t) (const calico_session_t *
					       session, void *ctx);

/**
 * Walk/visit each of the calico session
 */
extern void calico_session_walk (calico_session_walk_cb_t cb, void *ctx);

/**
 * Scan the session DB for expired sessions
 */
extern u64 calico_session_scan (vlib_main_t * vm, f64 start_time, int i);

/**
 * Purge all the sessions
 */
extern int calico_session_purge (void);

/**
 * Inline translation functions
 */

static_always_inline u8
has_ip6_address (ip6_address_t * a)
{
  return ((0 != a->as_u64[0]) || (0 != a->as_u64[1]));
}

static_always_inline void
calico_ip4_translate_l4 (ip4_header_t * ip4, udp_header_t * udp,
			 u16 * checksum,
			 ip4_address_t new_addr[VLIB_N_DIR],
			 u16 new_port[VLIB_N_DIR])
{
  u16 old_port[VLIB_N_DIR];
  ip4_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;

  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;
  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;

  sum = *checksum;
  if (new_addr[VLIB_TX].as_u32)
    sum =
      ip_csum_update (sum, old_addr[VLIB_TX].as_u32, new_addr[VLIB_TX].as_u32,
		      ip4_header_t, dst_address);
  if (new_port[VLIB_TX])
    {
      udp->dst_port = new_port[VLIB_TX];
      sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  if (new_addr[VLIB_RX].as_u32)
    sum =
      ip_csum_update (sum, old_addr[VLIB_RX].as_u32, new_addr[VLIB_RX].as_u32,
		      ip4_header_t, src_address);

  if (new_port[VLIB_RX])
    {
      udp->src_port = new_port[VLIB_RX];
      sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  *checksum = ip_csum_fold (sum);
}

static_always_inline void
calico_ip4_translate_l3 (ip4_header_t * ip4,
			 ip4_address_t new_addr[VLIB_N_DIR])
{
  ip4_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;

  old_addr[VLIB_TX] = ip4->dst_address;
  old_addr[VLIB_RX] = ip4->src_address;

  sum = ip4->checksum;
  if (new_addr[VLIB_TX].as_u32)
    {
      ip4->dst_address = new_addr[VLIB_TX];
      sum =
	ip_csum_update (sum, old_addr[VLIB_TX].as_u32,
			new_addr[VLIB_TX].as_u32, ip4_header_t, dst_address);
    }
  if (new_addr[VLIB_RX].as_u32)
    {
      ip4->src_address = new_addr[VLIB_RX];
      sum =
	ip_csum_update (sum, old_addr[VLIB_RX].as_u32,
			new_addr[VLIB_RX].as_u32, ip4_header_t, src_address);
    }
  ip4->checksum = ip_csum_fold (sum);
}

static_always_inline void
calico_tcp_update_session_lifetime (tcp_header_t * tcp, u32 index)
{
  calico_main_t *cm = &calico_main;
  if (PREDICT_FALSE (tcp_fin (tcp)))
    {
      calico_timestamp_set_lifetime (index, CALICO_DEFAULT_TCP_RST_TIMEOUT);
    }

  if (PREDICT_FALSE (tcp_rst (tcp)))
    {
      calico_timestamp_set_lifetime (index, CALICO_DEFAULT_TCP_RST_TIMEOUT);
    }

  if (PREDICT_FALSE (tcp_syn (tcp) && tcp_ack (tcp)))
    {
      calico_timestamp_set_lifetime (index, cm->tcp_max_age);
    }
}

static_always_inline void
calico_translation_ip4 (const calico_session_t * session,
			ip4_header_t * ip4, udp_header_t * udp)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip4_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  new_addr[VLIB_TX] = session->value.cs_ip[VLIB_TX].ip4;
  new_addr[VLIB_RX] = session->value.cs_ip[VLIB_RX].ip4;
  new_port[VLIB_TX] = session->value.cs_port[VLIB_TX];
  new_port[VLIB_RX] = session->value.cs_port[VLIB_RX];

  if (ip4->protocol == IP_PROTOCOL_TCP)
    {
      if (PREDICT_FALSE (tcp->checksum))
	calico_ip4_translate_l4 (ip4, udp, &tcp->checksum, new_addr,
				 new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
      calico_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
    }
  else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
      if (PREDICT_FALSE (udp->checksum))
	calico_ip4_translate_l4 (ip4, udp, &udp->checksum, new_addr,
				 new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
    }

  calico_ip4_translate_l3 (ip4, new_addr);
}

static_always_inline void
calico_ip6_translate_l3 (ip6_header_t * ip6,
			 ip6_address_t new_addr[VLIB_N_DIR])
{
  if (has_ip6_address (&new_addr[VLIB_TX]))
    ip6_address_copy (&ip6->dst_address, &new_addr[VLIB_TX]);
  if (has_ip6_address (&new_addr[VLIB_RX]))
    ip6_address_copy (&ip6->src_address, &new_addr[VLIB_RX]);
}

static_always_inline void
calico_ip6_translate_l4 (ip6_header_t * ip6, udp_header_t * udp,
			 u16 * checksum,
			 ip6_address_t new_addr[VLIB_N_DIR],
			 u16 new_port[VLIB_N_DIR])
{
  u16 old_port[VLIB_N_DIR];
  ip6_address_t old_addr[VLIB_N_DIR];
  ip_csum_t sum;

  old_port[VLIB_TX] = udp->dst_port;
  old_port[VLIB_RX] = udp->src_port;
  ip6_address_copy (&old_addr[VLIB_TX], &ip6->dst_address);
  ip6_address_copy (&old_addr[VLIB_RX], &ip6->src_address);

  sum = *checksum;
  if (has_ip6_address (&new_addr[VLIB_TX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_TX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_TX].as_u64[1]);
    }

  if (new_port[VLIB_TX])
    {
      udp->dst_port = new_port[VLIB_TX];
      sum = ip_csum_update (sum, old_port[VLIB_TX], new_port[VLIB_TX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  if (has_ip6_address (&new_addr[VLIB_RX]))
    {
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_add_even (sum, new_addr[VLIB_RX].as_u64[1]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[0]);
      sum = ip_csum_sub_even (sum, old_addr[VLIB_RX].as_u64[1]);
    }

  if (new_port[VLIB_RX])
    {
      udp->src_port = new_port[VLIB_RX];
      sum = ip_csum_update (sum, old_port[VLIB_RX], new_port[VLIB_RX],
			    ip4_header_t /* cheat */ ,
			    length /* changed member */ );
    }
  *checksum = ip_csum_fold (sum);
}

static_always_inline void
calico_translation_ip6 (const calico_session_t * session,
			ip6_header_t * ip6, udp_header_t * udp)
{
  tcp_header_t *tcp = (tcp_header_t *) udp;
  ip6_address_t new_addr[VLIB_N_DIR];
  u16 new_port[VLIB_N_DIR];

  ip6_address_copy (&new_addr[VLIB_TX], &session->value.cs_ip[VLIB_TX].ip6);
  ip6_address_copy (&new_addr[VLIB_RX], &session->value.cs_ip[VLIB_RX].ip6);
  new_port[VLIB_TX] = session->value.cs_port[VLIB_TX];
  new_port[VLIB_RX] = session->value.cs_port[VLIB_RX];

  if (ip6->protocol == IP_PROTOCOL_TCP)
    {
      if (PREDICT_FALSE (tcp->checksum))
	calico_ip6_translate_l4 (ip6, udp, &tcp->checksum, new_addr,
				 new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
      calico_tcp_update_session_lifetime (tcp, session->value.cs_ts_index);
    }
  else if (ip6->protocol == IP_PROTOCOL_UDP)
    {
      if (PREDICT_FALSE (udp->checksum))
	calico_ip6_translate_l4 (ip6, udp, &udp->checksum, new_addr,
				 new_port);
      else
	{
	  udp->dst_port = new_port[VLIB_TX];
	  udp->src_port = new_port[VLIB_RX];
	}
    }

  calico_ip6_translate_l3 (ip6, new_addr);
}

always_inline void
calico_mk_ip4_key (calico_session_t * key,
		   const ip4_header_t * ip4, const udp_header_t * udp)
{
  key->key.cs_af = AF_IP4;
  key->key.__cs_pad[0] = 0;
  key->key.__cs_pad[1] = 0;

  ip46_address_set_ip4 (&key->key.cs_ip[VLIB_TX], &ip4->dst_address);
  ip46_address_set_ip4 (&key->key.cs_ip[VLIB_RX], &ip4->src_address);
  key->key.cs_port[VLIB_RX] = udp->src_port;
  key->key.cs_port[VLIB_TX] = udp->dst_port;
  key->key.cs_proto = ip4->protocol;
}

always_inline void
calico_mk_ip6_key (calico_session_t * key,
		   const ip6_header_t * ip6, const udp_header_t * udp)
{
  key->key.cs_af = AF_IP6;
  key->key.__cs_pad[0] = 0;
  key->key.__cs_pad[1] = 0;

  ip46_address_set_ip6 (&key->key.cs_ip[VLIB_TX], &ip6->dst_address);
  ip46_address_set_ip6 (&key->key.cs_ip[VLIB_RX], &ip6->src_address);
  key->key.cs_port[VLIB_RX] = udp->src_port;
  key->key.cs_port[VLIB_TX] = udp->dst_port;
  key->key.cs_proto = ip6->protocol;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
