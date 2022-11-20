/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
#ifndef __included_udp_h__
#define __included_udp_h__

#include <vnet/vnet.h>
#include <vnet/udp/udp_inlines.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/format.h>

#include <vnet/ip/ip.h>
#include <vnet/session/transport.h>

typedef enum
{
#define udp_error(f, n, s, d) UDP_ERROR_##f,
#include <vnet/udp/udp_error.def>
#undef udp_error
  UDP_N_ERROR,
} udp_error_t;

#define foreach_udp_connection_flag					\
  _(CONNECTED, "CONNECTED")	/**< connected mode */			\
  _(OWNS_PORT, "OWNS_PORT")	/**< port belong to conn (UDPC) */	\
  _(CLOSING, "CLOSING")		/**< conn closed with data */		\
  _(LISTEN, "LISTEN")		/**< conn is listening */		\
  _(MIGRATED, "MIGRATED")	/**< cloned to another thread */	\

enum udp_conn_flags_bits
{
#define _(sym, str) UDP_CONN_F_BIT_##sym,
  foreach_udp_connection_flag
#undef _
  UDP_CONN_N_FLAGS
};

typedef enum udp_conn_flags_
{
#define _(sym, str) UDP_CONN_F_##sym = 1 << UDP_CONN_F_BIT_##sym,
  foreach_udp_connection_flag
#undef _
} udp_conn_flags_t;

#define foreach_udp_cfg_flag _ (NO_CSUM_OFFLOAD, "no-csum-offload")

typedef enum udp_cfg_flag_bits_
{
#define _(sym, str) UDP_CFG_F_##sym##_BIT,
  foreach_udp_cfg_flag
#undef _
    UDP_CFG_N_FLAG_BITS
} udp_cfg_flag_bits_e;

typedef enum udp_cfg_flag_
{
#define _(sym, str) UDP_CFG_F_##sym = 1 << UDP_CFG_F_##sym##_BIT,
  foreach_udp_cfg_flag
#undef _
    UDP_CFG_N_FLAGS
} __clib_packed udp_cfg_flags_t;

typedef struct
{
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  transport_connection_t connection;	/**< must be first */
  clib_spinlock_t rx_lock;		/**< rx fifo lock */
  u8 flags;				/**< connection flags */
  udp_cfg_flags_t cfg_flags;		/**< configuration flags */
  u16 mss;				/**< connection mss */
  u32 sw_if_index;			/**< connection sw_if_index */
  u32 next_node_index;	/**< Can be used to control next node in output */
  u32 next_node_opaque; /**< Opaque to pass to next node */
} udp_connection_t;

#define udp_csum_offload(uc) (!((uc)->cfg_flags & UDP_CFG_F_NO_CSUM_OFFLOAD))

typedef struct
{
  /* Name (a c string). */
  char *name;

  /* Port number in host byte order. */
  udp_dst_port_t dst_port;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;

  /* UDP sessions refcount (not tunnels) */
  u32 n_connections;

  /* Parser for packet generator edits for this protocol */
  unformat_function_t *unformat_pg_edit;
} udp_dst_port_info_t;

typedef enum
{
  UDP_IP6 = 0,
  UDP_IP4,			/* the code is full of is_ip4... */
  N_UDP_AF,
} udp_af_t;

typedef struct udp_worker_
{
  udp_connection_t *connections;
  u32 *pending_cleanups;
} udp_worker_t;

typedef struct
{
  udp_dst_port_info_t *dst_port_infos[N_UDP_AF];

  /* Hash tables mapping name/protocol to protocol info index. */
  uword *dst_port_info_by_name[N_UDP_AF];
  uword *dst_port_info_by_dst_port[N_UDP_AF];

  /* Sparse vector mapping udp dst_port in network byte order
     to next index. */
  u16 *next_by_dst_port4;
  u16 *next_by_dst_port6;
  u8 punt_unknown4;
  u8 punt_unknown6;

  /* Udp local to input arc index */
  u32 local_to_input_edge[N_UDP_AF];

  /*
   * UDP transport layer per-thread context
   */

  udp_worker_t *wrk;
  udp_connection_t *listener_pool;

  u16 default_mtu;
  u16 msg_id_base;
  u8 csum_offload;

  u32 udp4_input_frame_queue_index;
  u32 udp6_input_frame_queue_index;

  u8 icmp_send_unreachable_disabled;
} udp_main_t;

extern udp_main_t udp_main;
extern vlib_node_registration_t udp4_input_node;
extern vlib_node_registration_t udp6_input_node;
extern vlib_node_registration_t udp4_local_node;
extern vlib_node_registration_t udp6_local_node;
extern vlib_node_registration_t udp4_output_node;
extern vlib_node_registration_t udp6_output_node;

void udp_add_dst_port (udp_main_t * um, udp_dst_port_t dst_port,
		       char *dst_port_name, u8 is_ip4);

always_inline udp_worker_t *
udp_worker_get (u32 thread_index)
{
  return vec_elt_at_index (udp_main.wrk, thread_index);
}

always_inline udp_connection_t *
udp_connection_get (u32 conn_index, u32 thread_index)
{
  udp_worker_t *wrk = udp_worker_get (thread_index);

  if (pool_is_free_index (wrk->connections, conn_index))
    return 0;
  return pool_elt_at_index (wrk->connections, conn_index);
}

always_inline udp_connection_t *
udp_listener_get (u32 conn_index)
{
  return pool_elt_at_index (udp_main.listener_pool, conn_index);
}

always_inline udp_main_t *
vnet_get_udp_main ()
{
  return &udp_main;
}

always_inline udp_connection_t *
udp_connection_from_transport (transport_connection_t * tc)
{
  return ((udp_connection_t *) tc);
}

void udp_connection_free (udp_connection_t * uc);
udp_connection_t *udp_connection_alloc (u32 thread_index);

always_inline udp_connection_t *
udp_connection_clone_safe (u32 connection_index, u32 thread_index)
{
  u32 current_thread_index = vlib_get_thread_index (), new_index;
  udp_connection_t *old_c, *new_c;

  new_c = udp_connection_alloc (current_thread_index);
  new_index = new_c->c_c_index;
  /* Connection pool always realloced with barrier */
  old_c = udp_main.wrk[thread_index].connections + connection_index;
  clib_memcpy_fast (new_c, old_c, sizeof (*new_c));
  old_c->flags |= UDP_CONN_F_MIGRATED;
  new_c->c_thread_index = current_thread_index;
  new_c->c_c_index = new_index;
  new_c->c_fib_index = old_c->c_fib_index;
  /* Assume cloned sessions don't need lock */
  new_c->rx_lock = 0;
  return new_c;
}

always_inline udp_dst_port_info_t *
udp_get_dst_port_info (udp_main_t * um, udp_dst_port_t dst_port, u8 is_ip4)
{
  uword *p = hash_get (um->dst_port_info_by_dst_port[is_ip4], dst_port);
  return p ? vec_elt_at_index (um->dst_port_infos[is_ip4], p[0]) : 0;
}

format_function_t format_udp_header;
format_function_t format_udp_rx_trace;
format_function_t format_udp_connection;
unformat_function_t unformat_udp_header;
unformat_function_t unformat_udp_port;

void udp_connection_share_port (u16 lcl_port, u8 is_ip4);

void udp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_udp_h__ */
