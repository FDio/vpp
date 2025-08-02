/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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
#ifndef common_h
#define common_h

#include <vnet/ip/ip.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/ip_sas.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ip/ip6_ll_table.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/icmp4.h>

typedef CLIB_PACKED (struct {
  u64 time_now;
  u16 hash;
}) cli_msg_t;

/* Camping on unused data... just ensure statically that there is enough
 * space */
STATIC_ASSERT (STRUCT_ARRAY_LEN (vnet_buffer_opaque_t, unused) *
		   STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused[0]) >
		 sizeof (cli_msg_t),
	       "cli_msg does not fits within remaining space of "
	       "vnet_buffer unused data");

#define vnet_buffer_cli_msg(b) ((cli_msg_t *) &vnet_buffer (b)->unused[0])

#define CLI_UNKNOWN_NODE (~0)

typedef enum
{
  ICMP46_REPLY_NEXT_DROP,
  ICMP46_REPLY_NEXT_PUNT,
  ICMP46_REPLY_N_NEXT,
} icmp46_reply_next_t;

typedef enum
{
  RESPONSE_IP6 = 42,
  RESPONSE_IP4,
} response_type_t;

#define foreach_icmp_type_reply                                               \
  __ (echo_reply)                                                             \
  __ (time_exceeded)                                                          \
  __ (destination_unreachable)

#define __(_type)                                                             \
  extern vlib_node_registration_t ip4_icmp_##_type##_node;                    \
  extern vlib_node_registration_t ip6_icmp_##_type##_node;
foreach_icmp_type_reply
#undef __

  typedef struct
{
  uword cli_process_id;
  u16 run_id;
  u16 current_hash;
} cli_process_run_t;

typedef struct ping_traceroute_main_t
{
  /* a vector of current ping runs. */
  cli_process_run_t *active_runs;
  /* a lock held while add/remove/search on active_ping_runs */
  clib_spinlock_t run_check_lock;
} ping_traceroute_main_t;

extern ping_traceroute_main_t ping_traceroute_main;

static_always_inline u16
id_seq_hash (u16 id, u16 seq)
{
  u32 h = (((u32) id) << 16) | seq;
  return hash_memory (&h, sizeof (h), 0) & 0xffff;
}

uword get_cli_process_id_by_run_id (vlib_main_t *vm, u16 run_id);
uword get_cli_process_id_by_hash (vlib_main_t *vm, u16 hash);
void set_cli_process_id_by_run_id (vlib_main_t *vm, u16 run_id,
				   uword cli_process_id);
void set_hash_by_run_id (vlib_main_t *vm, u16 run_id, u16 hash);
void clear_cli_process_id_by_run_id (vlib_main_t *vm, u16 run_id);
fib_node_index_t ip46_fib_table_lookup_host (u32 fib_index,
					     ip46_address_t *pa46, int is_ip6);
u32 ip46_get_resolving_interface (u32 fib_index, ip46_address_t *pa46,
				  int is_ip6);
u32 ip46_fib_table_get_index_for_sw_if_index (u32 sw_if_index, int is_ip6,
					      ip46_address_t *pa46);
int ip46_fill_l3_header (ip46_address_t *pa46, vlib_buffer_t *b0, u8 l4_proto,
			 u8 ttl, int is_ip6);
bool ip46_set_src_address (u32 sw_if_index, vlib_buffer_t *b0, int is_ip6);
void ip46_print_buffer_src_address (vlib_main_t *vm, vlib_buffer_t *b0,
				    int is_ip6);
u16 ip46_fill_icmp_request_at (vlib_main_t *vm, vlib_buffer_t *b0,
			       int l4_offset, u16 seq_host, u16 id_host,
			       u16 data_len, int is_ip6);
u16 ip46_fill_tcp_syn_at (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
			  u16 seq_host, u16 id_host, u16 port, u16 data_len,
			  int is_ip6);
u16 ip46_fill_udp_at (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
		      u16 seq_host, u16 id_host, u16 port, u16 data_len,
		      int is_ip6);
u16 ip46_fill_l4_payload (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
			  u8 l4_proto, u16 seq_host, u16 id_host, u16 data_len,
			  u16 port, int is_ip6);
u16 ip4_icmp_compute_checksum (vlib_main_t *vm, vlib_buffer_t *p0,
			       ip4_header_t *ip0);
void ip46_fix_len_and_csum (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
			    u8 l4_proto, u16 payload_length, int is_ip6);
int ip46_enqueue_packet (vlib_main_t *vm, vlib_buffer_t *b0, u32 burst,
			 u32 lookup_node_index);

static_always_inline u32
ip46_fib_index_from_table_id (u32 table_id, int is_ip6)
{
  return is_ip6 ? ip6_fib_index_from_table_id (table_id) :
		  ip4_fib_index_from_table_id (table_id);
}

static_always_inline u8
ip46_icmp_populate_vnet_cli_msg (vlib_main_t *vm, vlib_buffer_t *b0,
				 u8 icmp_type, int is_ip6)
{
  i16 outer_l4_offset = 0;
  i16 inner_l3_offset = 0;
  i16 inner_l4_offset = 0;
  u8 inner_l4_proto = IP_PROTOCOL_ICMP;

  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      if (ip6->protocol != IP_PROTOCOL_ICMP6)
	return 0;
      outer_l4_offset = sizeof (ip6_header_t); // FIXME - EH processing ?
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      outer_l4_offset = (i16) ip4_header_bytes (ip4);
    }

  icmp46_header_t *icmp46 = vlib_buffer_get_current (b0) + outer_l4_offset;

  ASSERT (icmp46->type == icmp_type);

  switch (icmp_type)
    {
    case ICMP6_echo_reply:
    case ICMP4_echo_reply:
    handle_icmp_echo_reply:
      {
	icmp_echo_header_t *echo0 = (icmp_echo_header_t *) (icmp46 + 1);
	u16 id = clib_net_to_host_u16 (echo0->identifier);
	u16 seq = clib_net_to_host_u16 (echo0->sequence);
	vnet_buffer_cli_msg (b0)->hash = id_seq_hash (id, seq);
	break;
      }
    case ICMP6_time_exceeded:
    case ICMP4_time_exceeded:
      /* skip unused 4 bytes */
      /* move to inner L4 header */
      inner_l3_offset = outer_l4_offset + (i16) sizeof (icmp46_header_t) + 4;
      void *inner_l3_header = vlib_buffer_get_current (b0) + inner_l3_offset;

      if (is_ip6)
	{
	  ip6_header_t *ip6 = (ip6_header_t *) inner_l3_header;
	  inner_l4_offset = (i16) sizeof (ip6_header_t);
	  inner_l4_proto = ip6->protocol;
	}
      else
	{
	  ip4_header_t *ip4 = (ip4_header_t *) inner_l3_header;
	  inner_l4_offset = (i16) ip4_header_bytes (ip4);
	  inner_l4_proto = ip4->protocol;
	}

      switch (inner_l4_proto)
	{
	case IP_PROTOCOL_ICMP:
	case IP_PROTOCOL_ICMP6:
	  icmp46 = (icmp46_header_t *) (inner_l3_header + inner_l4_offset);
	  goto handle_icmp_echo_reply;
	case IP_PROTOCOL_TCP:
	  {
	    tcp_header_t *tcp0 =
	      (tcp_header_t *) (inner_l3_header + inner_l4_offset);
	    vnet_buffer_cli_msg (b0)->hash =
	      clib_net_to_host_u16 (tcp0->src_port);
	    break;
	  }
	case IP_PROTOCOL_UDP:
	  {
	    udp_header_t *udp0 =
	      (udp_header_t *) (inner_l3_header + inner_l4_offset);
	    vnet_buffer_cli_msg (b0)->hash =
	      clib_net_to_host_u16 (udp0->src_port);
	    break;
	  }
	default:
	  return 0;
	}
    }

  return 1;
}

static_always_inline u8
ip46_tcp_populate_vnet_cli_msg (vlib_main_t *vm, vlib_buffer_t *b0,
				tcp_header_t *tcp0)
{
  vnet_buffer_cli_msg (b0)->hash = clib_net_to_host_u16 (tcp0->dst_port);
  return 1;
}

/*
 * post the buffer to a given cli process node - the caller should forget bi0
 * after return.
 */

static_always_inline void
ip46_post_reply_event (vlib_main_t *vm, uword cli_process_id, u32 bi0,
		       int is_ip6)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

  /* Pass the timestamp to the cli_process thanks to the vnet_buffer unused
   * metadata field */
  vnet_buffer_cli_msg (b0)->time_now = clib_cpu_time_now ();

  u32 event_id = is_ip6 ? RESPONSE_IP6 : RESPONSE_IP4;
  vlib_process_signal_event_mt (vm, cli_process_id, event_id, bi0);
}

#endif /* common_h */
