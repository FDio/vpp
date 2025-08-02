/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
  u16 id;
  u16 seq;
  u64 time_sent;
  u8 data[0];
}) icmp46_echo_request_t;

STATIC_ASSERT (STRUCT_OFFSET_OF (icmp46_echo_request_t, id) ==
		 STRUCT_OFFSET_OF (tcp_header_t, src_port),
	       "icmp46_echo_request_t.id must be at the same offset as "
	       "tcp_header_t.src_port");

STATIC_ASSERT (STRUCT_OFFSET_OF (icmp46_echo_request_t, id) ==
		 STRUCT_OFFSET_OF (udp_header_t, src_port),
	       "icmp46_echo_request_t.id must be at the same offset as "
	       "udp_header_t.src_port");

typedef CLIB_PACKED (struct {
  u16 seq;
  u8 data[0];
}) udp_data_t;

typedef CLIB_PACKED (struct {
  u64 time_now;
  i16 inner_l3_hdr_offset; /* offset to inner L3 header */
  u16 inner_l4_hdr_offset; /* offset to inner L4 header */
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

  /*
   * Currently running ping command.
   */
  typedef struct ping_run_t
{
  uword cli_process_id;
  u16 run_id;
} cli_process_run_t;

typedef struct ping_traceroute_main_t
{
  /* a vector of current ping runs. */
  cli_process_run_t *active_runs;
  /* a lock held while add/remove/search on active_ping_runs */
  clib_spinlock_t run_check_lock;
} ping_traceroute_main_t;

extern ping_traceroute_main_t ping_traceroute_main;

/*
 * Poor man's get-set-clear functions
 * for manipulation of icmp_id -> cli_process_id
 * mappings.
 *
 * There should normally be very few (0..1..2) of these
 * mappings, so the linear search is a good strategy.
 *
 * Make them thread-safe via a simple spinlock.
 *
 */

static_always_inline uword
get_cli_process_id_by_run_id (vlib_main_t *vm, u16 run_id)
{
  ping_traceroute_main_t *ptm = &ping_traceroute_main;
  uword cli_process_id = CLI_UNKNOWN_NODE;
  cli_process_run_t *cpr;

  clib_spinlock_lock_if_init (&ptm->run_check_lock);
  vec_foreach (cpr, ptm->active_runs)
    {
      if (cpr->run_id == run_id)
	{
	  cli_process_id = cpr->cli_process_id;
	  break;
	}
    }
  clib_spinlock_unlock_if_init (&ptm->run_check_lock);
  return cli_process_id;
}

static_always_inline void
set_cli_process_id_by_run_id (vlib_main_t *vm, u16 run_id,
			      uword cli_process_id)
{
  ping_traceroute_main_t *ptm = &ping_traceroute_main;
  cli_process_run_t *cpr;

  clib_spinlock_lock_if_init (&ptm->run_check_lock);
  vec_foreach (cpr, ptm->active_runs)
    {
      if (cpr->run_id == run_id)
	{
	  cpr->cli_process_id = cli_process_id;
	  goto have_found_and_set;
	}
    }
  /* no such key yet - add a new one */
  cli_process_run_t new_cpr = { .run_id = run_id,
				.cli_process_id = cli_process_id };
  vec_add1 (ptm->active_runs, new_cpr);
have_found_and_set:
  clib_spinlock_unlock_if_init (&ptm->run_check_lock);
}

static_always_inline void
clear_cli_process_id_by_run_id (vlib_main_t *vm, u16 run_id)
{
  ping_traceroute_main_t *ptm = &ping_traceroute_main;
  cli_process_run_t *cpr;

  clib_spinlock_lock_if_init (&ptm->run_check_lock);
  vec_foreach (cpr, ptm->active_runs)
    {
      if (cpr->run_id == run_id)
	{
	  vec_del1 (ptm->active_runs, cpr - ptm->active_runs);
	  break;
	}
    }
  clib_spinlock_unlock_if_init (&ptm->run_check_lock);
}

static_always_inline u32
ip46_fib_index_from_table_id (u32 table_id, int is_ip6)
{
  return is_ip6 ? ip6_fib_index_from_table_id (table_id) :
		  ip4_fib_index_from_table_id (table_id);
}

static_always_inline fib_node_index_t
ip46_fib_table_lookup_host (u32 fib_index, ip46_address_t *pa46, int is_ip6)
{
  return is_ip6 ?
	   ip6_fib_table_lookup (fib_index, &pa46->ip6, 128) :
	   ip4_fib_table_lookup (ip4_fib_get (fib_index), &pa46->ip4, 32);
}

static_always_inline u32
ip46_get_resolving_interface (u32 fib_index, ip46_address_t *pa46, int is_ip6)
{
  u32 sw_if_index = ~0;
  if (~0 != fib_index)
    {
      fib_node_index_t fib_entry_index;
      fib_entry_index = ip46_fib_table_lookup_host (fib_index, pa46, is_ip6);
      sw_if_index = fib_entry_get_resolving_interface (fib_entry_index);
    }
  return sw_if_index;
}

static_always_inline u32
ip46_fib_table_get_index_for_sw_if_index (u32 sw_if_index, int is_ip6,
					  ip46_address_t *pa46)
{
  if (is_ip6)
    {
      if (ip6_address_is_link_local_unicast (&pa46->ip6))
	return ip6_ll_fib_get (sw_if_index);
      return ip6_fib_table_get_index_for_sw_if_index (sw_if_index);
    }
  return ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
}

static_always_inline int
ip46_fill_l3_header (ip46_address_t *pa46, vlib_buffer_t *b0, u8 l4_proto,
		     u8 ttl, int is_ip6)
{
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      /* Fill in ip6 header fields */
      ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x6 << 28);
      ip6->payload_length = 0; /* will be set later */
      ip6->protocol = l4_proto;
      ip6->hop_limit = ttl;
      ip6->dst_address = pa46->ip6;
      ip6->src_address = pa46->ip6;
      return (sizeof (ip6_header_t));
    }

  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
  /* Fill in ip4 header fields */
  ip4->checksum = 0;
  ip4->ip_version_and_header_length = 0x45;
  ip4->tos = 0;
  ip4->length = 0; /* will be set later */
  ip4->fragment_id = 0;
  ip4->flags_and_fragment_offset = 0;
  ip4->ttl = ttl;
  ip4->protocol = l4_proto;
  ip4->src_address = pa46->ip4;
  ip4->dst_address = pa46->ip4;
  return (sizeof (ip4_header_t));
}

static_always_inline bool
ip46_set_src_address (u32 sw_if_index, vlib_buffer_t *b0, int is_ip6)
{
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      return ip6_sas_by_sw_if_index (sw_if_index, &ip6->dst_address,
				     &ip6->src_address);
    }

  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
  return ip4_sas_by_sw_if_index (sw_if_index, &ip4->dst_address,
				 &ip4->src_address);
}

static_always_inline void
ip46_print_buffer_src_address (vlib_main_t *vm, vlib_buffer_t *b0, int is_ip6)
{
  void *format_addr_func;
  void *paddr;
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      format_addr_func = format_ip6_address;
      paddr = &ip6->src_address;
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      format_addr_func = format_ip4_address;
      paddr = &ip4->src_address;
    }
  vlib_cli_output (vm, "Source address: %U ", format_addr_func, paddr);
}

/*
 * A swarm of address-family agnostic helper functions
 * for building and sending the ICMP echo request.
 */

static_always_inline u8
get_icmp_echo_payload_byte (int offset)
{
  return (offset % 256);
}

/* Fill in the ICMP ECHO structure, return the safety-checked and possibly
 * shrunk data_len */
static u16
init_icmp46_echo_request (vlib_main_t *vm, vlib_buffer_t *b0,
			  int l4_header_offset,
			  icmp46_echo_request_t *icmp46_echo, u16 seq_host,
			  u16 id_host, u64 now, u16 data_len)
{
  int i;

  int l34_len = l4_header_offset + sizeof (icmp46_header_t) +
		offsetof (icmp46_echo_request_t, data);
  int max_data_len = vlib_buffer_get_default_data_size (vm) - l34_len;

  int first_buf_data_len = data_len < max_data_len ? data_len : max_data_len;

  int payload_offset = 0;
  for (i = 0; i < first_buf_data_len; i++)
    icmp46_echo->data[i] = get_icmp_echo_payload_byte (payload_offset++);

  /* inspired by vlib_buffer_add_data */
  vlib_buffer_t *hb = b0;
  int remaining_data_len = data_len - first_buf_data_len;
  while (remaining_data_len)
    {
      int this_buf_data_len =
	remaining_data_len < vlib_buffer_get_default_data_size (vm) ?
	  remaining_data_len :
	  vlib_buffer_get_default_data_size (vm);
      int n_alloc = vlib_buffer_alloc (vm, &b0->next_buffer, 1);
      if (n_alloc < 1)
	{
	  /* That is how much we have so far - return it... */
	  return (data_len - remaining_data_len);
	}
      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      /* move on to the newly acquired buffer */
      b0 = vlib_get_buffer (vm, b0->next_buffer);
      /* initialize the data */
      for (i = 0; i < this_buf_data_len; i++)
	b0->data[i] = get_icmp_echo_payload_byte (payload_offset++);
      b0->current_length = this_buf_data_len;
      b0->current_data = 0;
      remaining_data_len -= this_buf_data_len;
    }
  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  hb->current_length = l34_len + first_buf_data_len;
  hb->total_length_not_including_first_buffer = data_len - first_buf_data_len;

  icmp46_echo->time_sent = now;
  icmp46_echo->seq = clib_host_to_net_u16 (seq_host);
  icmp46_echo->id = clib_host_to_net_u16 (id_host);
  return data_len;
}

static_always_inline u16
ip46_fill_icmp_request_at (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
			   u16 seq_host, u16 id_host, u16 data_len, int is_ip6)
{
  icmp46_header_t *icmp46 = vlib_buffer_get_current (b0) + l4_offset;

  icmp46->type = is_ip6 ? ICMP6_echo_request : ICMP4_echo_request;
  icmp46->code = 0;
  icmp46->checksum = 0;

  icmp46_echo_request_t *icmp46_echo = (icmp46_echo_request_t *) (icmp46 + 1);

  data_len =
    init_icmp46_echo_request (vm, b0, l4_offset, icmp46_echo, seq_host,
			      id_host, clib_cpu_time_now (), data_len);

  return data_len + sizeof (icmp46_header_t) +
	 offsetof (icmp46_echo_request_t, data);
}

static_always_inline u16
ip46_fill_tcp_syn_at (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
		      u16 seq_host, u16 id_host, u16 port, u16 data_len,
		      int is_ip6)
{
  tcp_header_t *tcp0 = vlib_buffer_get_current (b0) + l4_offset;
  tcp0->src_port = clib_host_to_net_u16 (id_host); /* same offset as ICMP ID */
  tcp0->dst_port = clib_host_to_net_u16 (port);
  tcp0->seq_number = clib_host_to_net_u32 (seq_host);
  tcp0->ack_number = 0;
  tcp0->data_offset_and_reserved = 5 << 4; /* 5 words, no options */
  tcp0->flags = TCP_FLAG_SYN;
  tcp0->window = 0;
  tcp0->checksum = 0;
  tcp0->urgent_pointer = 0;

  /* ignore data_len for now */
  return sizeof (tcp_header_t);
}

static_always_inline u16
ip46_fill_udp_at (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
		  u16 seq_host, u16 id_host, u16 port, u16 data_len,
		  int is_ip6)
{
  udp_header_t *udp0 = vlib_buffer_get_current (b0) + l4_offset;
  udp_data_t *udp_data = (udp_data_t *) (udp0 + 1);
  udp0->src_port = clib_host_to_net_u16 (id_host); /* same offset as ICMP ID */
  udp0->dst_port = clib_host_to_net_u16 (port);
  udp0->length = clib_host_to_net_u16 (sizeof (udp_header_t));
  udp0->checksum = 0;
  udp_data->seq = clib_host_to_net_u16 (seq_host);

  /* ignore data_len for now */
  return sizeof (udp_header_t) + offsetof (udp_data_t, data);
}

static_always_inline u16
ip46_fill_l4_payload (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
		      u8 l4_proto, u16 seq_host, u16 id_host, u16 data_len,
		      u16 port, int is_ip6)
{
  switch (l4_proto)
    {
    default:
      /* ICMP by default */
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      return ip46_fill_icmp_request_at (vm, b0, l4_offset, seq_host, id_host,
					data_len, is_ip6);
      break;
    case IP_PROTOCOL_UDP:
      return ip46_fill_tcp_syn_at (vm, b0, l4_offset, seq_host, id_host, port,
				   data_len, is_ip6);
      break;
    case IP_PROTOCOL_TCP:
      return ip46_fill_udp_at (vm, b0, l4_offset, seq_host, id_host, port,
			       data_len, is_ip6);
      break;
    }
}

/* Compute ICMP4 checksum with multibuffer support. */
static_always_inline u16
ip4_icmp_compute_checksum (vlib_main_t *vm, vlib_buffer_t *p0,
			   ip4_header_t *ip0)
{
  ip_csum_t sum0;
  u32 ip_header_length, payload_length_host_byte_order;
  u32 n_this_buffer, n_bytes_left, n_ip_bytes_this_buffer;
  u16 sum16;
  void *data_this_buffer;

  ip_header_length = ip4_header_bytes (ip0);
  payload_length_host_byte_order =
    clib_net_to_host_u16 (ip0->length) - ip_header_length;

  /* ICMP4 checksum does not include the IP header */
  sum0 = 0;

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
  data_this_buffer = (void *) ip0 + ip_header_length;
  n_ip_bytes_this_buffer =
    p0->current_length - (((u8 *) ip0 - p0->data) - p0->current_data);
  if (n_this_buffer + ip_header_length > n_ip_bytes_this_buffer)
    {
      n_this_buffer = n_ip_bytes_this_buffer > ip_header_length ?
			n_ip_bytes_this_buffer - ip_header_length :
			0;
    }
  while (1)
    {
      sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      ASSERT (p0->flags & VLIB_BUFFER_NEXT_PRESENT);
      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = p0->current_length;
    }

  sum16 = ~ip_csum_fold (sum0);

  return sum16;
}

static_always_inline void
ip46_fix_len_and_csum (vlib_main_t *vm, vlib_buffer_t *b0, int l4_offset,
		       u8 l4_proto, u16 payload_length, int is_ip6)
{
  u16 total_length = payload_length + l4_offset;
  void *l3_header = vlib_buffer_get_current (b0);
  void *l4_header = vlib_buffer_get_current (b0) + l4_offset;
  u16 *checksum = 0;
  typeof (ip4_tcp_udp_compute_checksum) *ipv4_checksum_fn =
    ip4_tcp_udp_compute_checksum;

  switch (l4_proto)
    {
    case IP_PROTOCOL_ICMP6:
    case IP_PROTOCOL_ICMP:
      {
	icmp46_header_t *icmp46 = (icmp46_header_t *) (l4_header);
	checksum = &icmp46->checksum;
	ipv4_checksum_fn = ip4_icmp_compute_checksum;
	break;
      }
    case IP_PROTOCOL_TCP:
      {
	tcp_header_t *tcp0 = (tcp_header_t *) (l4_header);
	checksum = &tcp0->checksum;
	break;
      }
    case IP_PROTOCOL_UDP:
      {
	udp_header_t *udp0 = (udp_header_t *) (l4_header);
	checksum = &udp0->checksum;
	break;
      }
    }

  *checksum = 0; /* reset checksum before computing it */

  if (is_ip6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) l3_header;
      ip6->payload_length = clib_host_to_net_u16 (payload_length);

      int bogus_length = 0;
      *checksum =
	ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6, &bogus_length);
    }
  else
    {
      ip4_header_t *ip4 = (ip4_header_t *) l3_header;
      ip4->length = clib_host_to_net_u16 (total_length);
      ip4->checksum = ip4_header_checksum (ip4);

      *checksum = ipv4_checksum_fn (vm, b0, ip4);
    }
}

static u16
at_most_a_frame (u32 count)
{
  return count > VLIB_FRAME_SIZE ? VLIB_FRAME_SIZE : count;
}

static_always_inline int
ip46_enqueue_packet (vlib_main_t *vm, vlib_buffer_t *b0, u32 burst,
		     u32 lookup_node_index)
{
  vlib_frame_t *f = 0;
  int n_sent = 0;

  u16 n_to_send;

  /*
   * Enqueue the packet, possibly as one or more frames of copies to make
   * bursts. We enqueue b0 as the very last buffer, when there is no
   * possibility for error in vlib_buffer_copy, so as to allow the caller to
   * free it in case we encounter the error in the middle of the loop.
   */
  for (n_to_send = at_most_a_frame (burst), burst -= n_to_send; n_to_send > 0;
       n_to_send = at_most_a_frame (burst), burst -= n_to_send)
    {
      f = vlib_get_frame_to_node (vm, lookup_node_index);
      /* f can not be NULL here - frame allocation failure causes panic */

      u32 *to_next = vlib_frame_vector_args (f);
      f->n_vectors = n_to_send;

      while (n_to_send > 1)
	{
	  vlib_buffer_t *b0copy = vlib_buffer_copy (vm, b0);
	  if (PREDICT_FALSE (b0copy == NULL))
	    goto ship_and_ret;
	  *to_next++ = vlib_get_buffer_index (vm, b0copy);
	  n_to_send--;
	  n_sent++;
	}

      /* n_to_send is guaranteed to equal 1 here */
      if (burst > 0)
	{
	  /* not the last burst, so still make a copy for the last buffer */
	  vlib_buffer_t *b0copy = vlib_buffer_copy (vm, b0);
	  if (PREDICT_FALSE (b0copy == NULL))
	    goto ship_and_ret;
	  n_to_send--;
	  *to_next++ = vlib_get_buffer_index (vm, b0copy);
	}
      else
	{
	  /* put the original buffer as the last one of an error-free run */
	  *to_next++ = vlib_get_buffer_index (vm, b0);
	}
      vlib_put_frame_to_node (vm, lookup_node_index, f);
      n_sent += f->n_vectors;
    }
  return n_sent;
  /*
   * We reach here in case we already enqueued one or more buffers
   * and maybe one or more frames but could not make more copies.
   * There is an outstanding frame - so ship it and return.
   * Caller will have to free the b0 in this case, since
   * we did not enqueue it here yet.
   */
ship_and_ret:
  ASSERT (n_to_send <= f->n_vectors);
  f->n_vectors -= n_to_send;
  n_sent += f->n_vectors;
  vlib_put_frame_to_node (vm, lookup_node_index, f);
  return n_sent;
}

static_always_inline u8
ip46_get_icmp_id_and_seq (vlib_main_t *vm, vlib_buffer_t *b0, u8 icmp_type,
			  u16 *out_icmp_id, u16 *out_icmp_seq, i16 *l3_offset,
			  i16 *l4_offset, int is_ip6)
{
  *l4_offset = 0;
  *l3_offset = 0;

  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      if (ip6->protocol != IP_PROTOCOL_ICMP6)
	return 0;
      *l4_offset = sizeof (ip6_header_t); // FIXME - EH processing ?
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      *l4_offset = (i16) ip4_header_bytes (ip4);
    }
  icmp46_header_t *icmp46 = vlib_buffer_get_current (b0) + *l4_offset;

  ASSERT (icmp46->type == icmp_type);

  switch (icmp_type)
    {
    case ICMP6_time_exceeded:
    case ICMP4_time_exceeded:
      /* skip unused 4 bytes */
      /* move to inner L4 header */
      *l3_offset = *l4_offset + (i16) sizeof (icmp46_header_t) + 4;
      icmp46 = vlib_buffer_get_current (b0) + *l3_offset + *l4_offset;
      break;
    }

  icmp46_echo_request_t *icmp46_echo = (icmp46_echo_request_t *) (icmp46 + 1);
  *out_icmp_id = clib_net_to_host_u16 (icmp46_echo->id);
  *out_icmp_seq = clib_net_to_host_u16 (icmp46_echo->seq);
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
  u64 nowts = clib_cpu_time_now ();

  /* Pass the timestamp to the cli_process thanks to the vnet_buffer unused
   * metadata field */
  vnet_buffer_cli_msg (b0)->time_now = nowts;

  u32 event_id = is_ip6 ? RESPONSE_IP6 : RESPONSE_IP4;
  vlib_process_signal_event_mt (vm, cli_process_id, event_id, bi0);
}

#endif /* common_h */
