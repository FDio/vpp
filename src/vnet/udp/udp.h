/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>

#include <vnet/ip/ip.h>
#include <vnet/session/transport.h>

typedef enum
{
#define udp_error(n,s) UDP_ERROR_##n,
#include <vnet/udp/udp_error.def>
#undef udp_error
  UDP_N_ERROR,
} udp_error_t;

typedef struct
{
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  transport_connection_t connection;	/**< must be first */
  clib_spinlock_t rx_lock;		/**< rx fifo lock */
  u8 is_connected;			/**< connected mode */
} udp_connection_t;

#define foreach_udp4_dst_port			\
_ (53, dns)					\
_ (67, dhcp_to_server)                          \
_ (68, dhcp_to_client)                          \
_ (500, ikev2)                                  \
_ (2152, GTPU)					\
_ (3784, bfd4)                                  \
_ (3785, bfd_echo4)                             \
_ (4341, lisp_gpe)                              \
_ (4342, lisp_cp)                          	\
_ (4500, ipsec)                                 \
_ (4739, ipfix)                                 \
_ (4789, vxlan)					\
_ (4789, vxlan6)				\
_ (48879, vxlan_gbp)				\
_ (4790, VXLAN_GPE)				\
_ (6633, vpath_3)				\
_ (6081, geneve)				\
_ (53053, dns_reply)


#define foreach_udp6_dst_port                   \
_ (53, dns6)					\
_ (547, dhcpv6_to_server)                       \
_ (546, dhcpv6_to_client)			\
_ (2152, GTPU6)					\
_ (3784, bfd6)                                  \
_ (3785, bfd_echo6)                             \
_ (4341, lisp_gpe6)                             \
_ (4342, lisp_cp6)                          	\
_ (48879, vxlan6_gbp)				\
_ (4790, VXLAN6_GPE)                            \
_ (6633, vpath6_3)				\
_ (6081, geneve6)				\
_ (8138, BIER)		         		\
_ (53053, dns_reply6)

typedef enum
{
#define _(n,f) UDP_DST_PORT_##f = n,
  foreach_udp4_dst_port foreach_udp6_dst_port
#undef _
} udp_dst_port_t;

typedef enum
{
#define _(n,f) UDP6_DST_PORT_##f = n,
  foreach_udp6_dst_port
#undef _
} udp6_dst_port_t;

typedef struct
{
  /* Name (a c string). */
  char *name;

  /* GRE protocol type in host byte order. */
  udp_dst_port_t dst_port;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;

  /* Parser for packet generator edits for this protocol */
  unformat_function_t *unformat_pg_edit;
} udp_dst_port_info_t;

typedef enum
{
  UDP_IP6 = 0,
  UDP_IP4,			/* the code is full of is_ip4... */
  N_UDP_AF,
} udp_af_t;

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

  /*
   * Per-worker thread udp connection pools used with session layer
   */
  udp_connection_t **connections;
  u32 *connection_peekers;
  clib_spinlock_t *peekers_readers_locks;
  clib_spinlock_t *peekers_write_locks;
  udp_connection_t *listener_pool;

} udp_main_t;

extern udp_main_t udp_main;
extern vlib_node_registration_t udp4_input_node;
extern vlib_node_registration_t udp6_input_node;

always_inline udp_connection_t *
udp_connection_get (u32 conn_index, u32 thread_index)
{
  if (pool_is_free_index (udp_main.connections[thread_index], conn_index))
    return 0;
  return pool_elt_at_index (udp_main.connections[thread_index], conn_index);
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
udp_get_connection_from_transport (transport_connection_t * tc)
{
  return ((udp_connection_t *) tc);
}

always_inline u32
udp_connection_index (udp_connection_t * uc)
{
  return (uc - udp_main.connections[uc->c_thread_index]);
}

udp_connection_t *udp_connection_alloc (u32 thread_index);

/**
 * Acquires a lock that blocks a connection pool from expanding.
 */
always_inline void
udp_pool_add_peeker (u32 thread_index)
{
  if (thread_index != vlib_get_thread_index ())
    return;
  clib_spinlock_lock_if_init (&udp_main.peekers_readers_locks[thread_index]);
  udp_main.connection_peekers[thread_index] += 1;
  if (udp_main.connection_peekers[thread_index] == 1)
    clib_spinlock_lock_if_init (&udp_main.peekers_write_locks[thread_index]);
  clib_spinlock_unlock_if_init (&udp_main.peekers_readers_locks
				[thread_index]);
}

always_inline void
udp_pool_remove_peeker (u32 thread_index)
{
  if (thread_index != vlib_get_thread_index ())
    return;
  ASSERT (udp_main.connection_peekers[thread_index] > 0);
  clib_spinlock_lock_if_init (&udp_main.peekers_readers_locks[thread_index]);
  udp_main.connection_peekers[thread_index] -= 1;
  if (udp_main.connection_peekers[thread_index] == 0)
    clib_spinlock_unlock_if_init (&udp_main.peekers_write_locks
				  [thread_index]);
  clib_spinlock_unlock_if_init (&udp_main.peekers_readers_locks
				[thread_index]);
}

always_inline udp_connection_t *
udp_connection_clone_safe (u32 connection_index, u32 thread_index)
{
  udp_connection_t *old_c, *new_c;
  u32 current_thread_index = vlib_get_thread_index ();
  new_c = udp_connection_alloc (current_thread_index);

  /* If during the memcpy pool is reallocated AND the memory allocator
   * decides to give the old chunk of memory to somebody in a hurry to
   * scribble something on it, we have a problem. So add this thread as
   * a session pool peeker.
   */
  udp_pool_add_peeker (thread_index);
  old_c = udp_main.connections[thread_index] + connection_index;
  clib_memcpy (new_c, old_c, sizeof (*new_c));
  udp_pool_remove_peeker (thread_index);
  new_c->c_thread_index = current_thread_index;
  new_c->c_c_index = udp_connection_index (new_c);
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
unformat_function_t unformat_udp_header;

void udp_register_dst_port (vlib_main_t * vm,
			    udp_dst_port_t dst_port,
			    u32 node_index, u8 is_ip4);
void udp_unregister_dst_port (vlib_main_t * vm,
			      udp_dst_port_t dst_port, u8 is_ip4);

void udp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add);

always_inline void *
vlib_buffer_push_udp (vlib_buffer_t * b, u16 sp, u16 dp, u8 offload_csum)
{
  udp_header_t *uh;
  u16 udp_len = sizeof (udp_header_t) + b->current_length;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID))
    udp_len += b->total_length_not_including_first_buffer;

  uh = vlib_buffer_push_uninit (b, sizeof (udp_header_t));
  uh->src_port = sp;
  uh->dst_port = dp;
  uh->checksum = 0;
  uh->length = clib_host_to_net_u16 (udp_len);
  if (offload_csum)
    {
      b->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
      vnet_buffer (b)->l4_hdr_offset = (u8 *) uh - b->data;
    }
  return uh;
}

always_inline void
ip_udp_fixup_one (vlib_main_t * vm, vlib_buffer_t * b0, u8 is_ip4)
{
  u16 new_l0;
  udp_header_t *udp0;

  if (is_ip4)
    {
      ip4_header_t *ip0;
      ip_csum_t sum0;
      u16 old_l0 = 0;

      ip0 = vlib_buffer_get_current (b0);

      /* fix the <bleep>ing outer-IP checksum */
      sum0 = ip0->checksum;
      /* old_l0 always 0, see the rewrite setup */
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));

      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
			     length /* changed member */ );
      ip0->checksum = ip_csum_fold (sum0);
      ip0->length = new_l0;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				     - sizeof (*ip0));
      udp0->length = new_l0;
    }
  else
    {
      ip6_header_t *ip0;
      int bogus0;

      ip0 = vlib_buffer_get_current (b0);

      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				     - sizeof (*ip0));
      ip0->payload_length = new_l0;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      udp0->length = new_l0;

      udp0->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0, &bogus0);
      ASSERT (bogus0 == 0);

      if (udp0->checksum == 0)
	udp0->checksum = 0xffff;
    }
}

always_inline void
ip_udp_encap_one (vlib_main_t * vm, vlib_buffer_t * b0, u8 * ec0, word ec_len,
		  u8 is_ip4)
{
  vlib_buffer_advance (b0, -ec_len);

  if (is_ip4)
    {
      ip4_header_t *ip0;

      ip0 = vlib_buffer_get_current (b0);

      /* Apply the encap string. */
      clib_memcpy (ip0, ec0, ec_len);
      ip_udp_fixup_one (vm, b0, 1);
    }
  else
    {
      ip6_header_t *ip0;

      ip0 = vlib_buffer_get_current (b0);

      /* Apply the encap string. */
      clib_memcpy (ip0, ec0, ec_len);
      ip_udp_fixup_one (vm, b0, 0);
    }
}

always_inline void
ip_udp_encap_two (vlib_main_t * vm, vlib_buffer_t * b0, vlib_buffer_t * b1,
		  u8 * ec0, u8 * ec1, word ec_len, u8 is_v4)
{
  u16 new_l0, new_l1;
  udp_header_t *udp0, *udp1;

  ASSERT (_vec_len (ec0) == _vec_len (ec1));

  vlib_buffer_advance (b0, -ec_len);
  vlib_buffer_advance (b1, -ec_len);

  if (is_v4)
    {
      ip4_header_t *ip0, *ip1;
      ip_csum_t sum0, sum1;
      u16 old_l0 = 0, old_l1 = 0;

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);

      /* Apply the encap string */
      clib_memcpy (ip0, ec0, ec_len);
      clib_memcpy (ip1, ec1, ec_len);

      /* fix the <bleep>ing outer-IP checksum */
      sum0 = ip0->checksum;
      sum1 = ip1->checksum;

      /* old_l0 always 0, see the rewrite setup */
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
      new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1));

      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
			     length /* changed member */ );
      sum1 = ip_csum_update (sum1, old_l1, new_l1, ip4_header_t,
			     length /* changed member */ );

      ip0->checksum = ip_csum_fold (sum0);
      ip1->checksum = ip_csum_fold (sum1);

      ip0->length = new_l0;
      ip1->length = new_l1;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      udp1 = (udp_header_t *) (ip1 + 1);

      new_l0 =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			      sizeof (*ip0));
      new_l1 =
	clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1) -
			      sizeof (*ip1));
      udp0->length = new_l0;
      udp1->length = new_l1;
    }
  else
    {
      ip6_header_t *ip0, *ip1;
      int bogus0, bogus1;

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);

      /* Apply the encap string. */
      clib_memcpy (ip0, ec0, ec_len);
      clib_memcpy (ip1, ec1, ec_len);

      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				     - sizeof (*ip0));
      new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1)
				     - sizeof (*ip1));
      ip0->payload_length = new_l0;
      ip1->payload_length = new_l1;

      /* Fix UDP length */
      udp0 = (udp_header_t *) (ip0 + 1);
      udp1 = (udp_header_t *) (ip1 + 1);

      udp0->length = new_l0;
      udp1->length = new_l1;

      udp0->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip0, &bogus0);
      udp1->checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b1, ip1, &bogus1);
      ASSERT (bogus0 == 0);
      ASSERT (bogus1 == 0);

      if (udp0->checksum == 0)
	udp0->checksum = 0xffff;
      if (udp1->checksum == 0)
	udp1->checksum = 0xffff;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_udp_h__ */
