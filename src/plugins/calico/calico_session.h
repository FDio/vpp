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

#include <calico/calico_types.h>
#include <calico/bihash_40_32.h>

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
     * The direction. ideally this would be vlib_dir_t but that is
     * not a packed type
     */
    u8 cs_dir;

    /**
     * spare space
     */
    u8 __cs_pad;
  } key;
  /**
   * this value sits in the same memory location a 'key' in the bihash kvp
   */
  struct
  {
    /**
     * The IP address to translate to.
     */
    ip46_address_t cs_ip;

    /**
     * the port to translate to
     */
    u16 cs_port;

    /**
     * The load balance object to use to forward
     */
    index_t cs_lbi;

    /**
     * Timestamp this session was last used
     */
    u32 cs_ts_index;

    u32 opaque;
  } value;
} calico_session_t;

extern u8 *format_calico_session (u8 * s, va_list * args);

/**
 * Ensure the session object correctly overlays the bihash key/value pair
 */
STATIC_ASSERT (STRUCT_OFFSET_OF (calico_session_t, key) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_32_t, key),
	       "key overlaps");
STATIC_ASSERT (STRUCT_OFFSET_OF (calico_session_t, value) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_32_t, value),
	       "value overlaps");
STATIC_ASSERT (sizeof (calico_session_t) == sizeof (clib_bihash_kv_40_32_t),
	       "session kvp");

/**
 * The DB of sessions
 */
extern clib_bihash_40_32_t calico_session_db;

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
