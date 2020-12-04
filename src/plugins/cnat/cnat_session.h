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

#ifndef __CNAT_SESSION_H__
#define __CNAT_SESSION_H__

#include <vnet/udp/udp_packet.h>

#include <cnat/cnat_types.h>
#include <cnat/cnat_client.h>
#include <cnat/bihash_40_48.h>


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
typedef struct cnat_session_t_
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

    union
    {
	/**
	 * session flags if cs_lbi == INDEX_INVALID
	 */
      u32 flags;
	/**
	 * Persist translation->ct_lb.dpoi_next_node
	 * when cs_lbi != INDEX_INVALID
	 */
      u32 dpoi_next_node;
    };
  } value;
} cnat_session_t;

typedef enum cnat_session_flag_t_
{
  /**
   * Indicates a return path session that was source NATed
   * on the way in.
   */
  CNAT_SESSION_FLAG_HAS_SNAT = (1 << 0),
  /**
   * This session source port was allocated, free it on cleanup
   */
  CNAT_SESSION_FLAG_ALLOC_PORT = (1 << 1),
  /**
   * This session doesn't have a client, do not attempt to free it
   */
  CNAT_SESSION_FLAG_NO_CLIENT = (1 << 2),
} cnat_session_flag_t;

extern u8 *format_cnat_session (u8 * s, va_list * args);

/**
 * Ensure the session object correctly overlays the bihash key/value pair
 */
STATIC_ASSERT (STRUCT_OFFSET_OF (cnat_session_t, key) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_48_t, key),
	       "key overlaps");
STATIC_ASSERT (STRUCT_OFFSET_OF (cnat_session_t, value) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_48_t, value),
	       "value overlaps");
STATIC_ASSERT (sizeof (cnat_session_t) == sizeof (clib_bihash_kv_40_48_t),
	       "session kvp");

/**
 * The DB of sessions
 */
extern clib_bihash_40_48_t cnat_session_db;

/**
 * Callback function invoked during a walk of all translations
 */
typedef walk_rc_t (*cnat_session_walk_cb_t) (const cnat_session_t *
					     session, void *ctx);

/**
 * Walk/visit each of the cnat session
 */
extern void cnat_session_walk (cnat_session_walk_cb_t cb, void *ctx);

/**
 * Scan the session DB for expired sessions
 */
extern u64 cnat_session_scan (vlib_main_t * vm, f64 start_time, int i);

/**
 * Purge all the sessions
 */
extern int cnat_session_purge (void);

/**
 * Free a session & update refcounts
 */
extern void cnat_session_free (cnat_session_t * session);

/**
 * Port cleanup callback
 */
extern void (*cnat_free_port_cb) (u16 port, ip_protocol_t iproto);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
