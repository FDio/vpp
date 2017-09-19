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

typedef struct
{
  transport_connection_t connection;	      /** must be first */

  /** ersatz MTU to limit fifo pushes to test data size */
  u32 mtu;
} udp_connection_t;

typedef struct _udp_uri_main
{
  /* Per-worker thread udp connection pools */
  udp_connection_t **udp_sessions;
  udp_connection_t *udp_listeners;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ip4_main_t *ip4_main;
  ip6_main_t *ip6_main;
} udp_uri_main_t;

extern udp_uri_main_t udp_uri_main;
extern vlib_node_registration_t udp4_uri_input_node;

always_inline udp_uri_main_t *
vnet_get_udp_main ()
{
  return &udp_uri_main;
}

always_inline udp_connection_t *
udp_connection_get (u32 conn_index, u32 thread_index)
{
  return pool_elt_at_index (udp_uri_main.udp_sessions[thread_index],
			    conn_index);
}

always_inline udp_connection_t *
udp_listener_get (u32 conn_index)
{
  return pool_elt_at_index (udp_uri_main.udp_listeners, conn_index);
}

typedef enum
{
#define udp_error(n,s) UDP_ERROR_##n,
#include <vnet/udp/udp_error.def>
#undef udp_error
  UDP_N_ERROR,
} udp_error_t;

#define foreach_udp4_dst_port			\
_ (67, dhcp_to_server)                          \
_ (68, dhcp_to_client)                          \
_ (500, ikev2)                                  \
_ (2152, GTPU)					\
_ (3784, bfd4)                                  \
_ (3785, bfd_echo4)                             \
_ (4341, lisp_gpe)                              \
_ (4342, lisp_cp)                          	\
_ (4739, ipfix)                                 \
_ (4789, vxlan)					\
_ (4789, vxlan6)				\
_ (4790, VXLAN_GPE)				\
_ (6633, vpath_3)				\
_ (6081, geneve)				


#define foreach_udp6_dst_port                   \
_ (547, dhcpv6_to_server)                       \
_ (546, dhcpv6_to_client)			\
_ (2152, GTPU6)					\
_ (3784, bfd6)                                  \
_ (3785, bfd_echo6)                             \
_ (4341, lisp_gpe6)                             \
_ (4342, lisp_cp6)                          	\
_ (4790, VXLAN6_GPE)                            \
_ (6633, vpath6_3)				\
_ (6081, geneve6)				

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

  /* convenience */
  vlib_main_t *vlib_main;
} udp_main_t;

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

void
udp_unregister_dst_port (vlib_main_t * vm,
			 udp_dst_port_t dst_port, u8 is_ip4);

void udp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add);

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
