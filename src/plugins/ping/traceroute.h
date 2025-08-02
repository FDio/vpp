
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
#ifndef traceroute_h
#define traceroute_h

#include <vnet/ip/ip.h>
#include <vnet/ip/lookup.h>

#include <ping/common.h>

typedef struct
{
  ip_address_t dest; /* destination address */
  f64 interval;	     /* time between packets */
  u32 fib_index;     /* FIB table index */
  u32 sw_if_index;   /* egress interface */
  u32 data_len;	     /* length of data to send */
  u16 port;	     /* destination port */
  u8 max_hops;	     /* maximum hops to trace */
  u8 repeat;	     /* repeat number */
  u8 l4_proto;	     /* L4 protocol to use */
  u8 verbose;	     /* verbose output */
} traceroute_args_t;

/*
 * Currently running ping command.
 */
typedef struct
{
  traceroute_args_t *args; /* arguments for the traceroute */
  uword cli_process_id;
  u32 n_packets_sent;	  /* number of packets sent so far */
  u32 n_packets_received; /* number of packets received so far */
  u16 id;		  /* traceroute ID */
  u8 current_hop;	  /* current hop number */
  u8 current_repeat;	  /* current repeat number */
} traceroute_run_t;

#define foreach_traceroute_result                                             \
  _ (OK, "OK")                                                                \
  _ (ALLOC_FAIL, "packet allocation failed")                                  \
  _ (NO_SRC_ADDRESS, "no source address for egress interface")                \
  _ (NO_BUFFERS, "could not allocate a new buffer")

typedef enum
{
#define _(v, s) TRACEROUTE_##v,
  foreach_traceroute_result
#undef _
} traceroute_result_t;

typedef struct traceroute_main_t
{
  /* API message ID base */
  u16 msg_id_base;

  ip6_main_t *ip6_main;
  ip4_main_t *ip4_main;
  /* a vector of current ping runs. */
  traceroute_run_t **active_runs;
  /* a lock held while add/remove/search on active_ping_runs */
  clib_spinlock_t run_check_lock;
} traceroute_main_t;

extern traceroute_main_t traceroute_main;

#define TRACEROUTE_DEFAULT_DATA_LEN 60
#define TRACEROUTE_DEFAULT_INTERVAL 1.0

#define TRACEROUTE_MAXIMUM_DATA_SIZE 32768

#define TRACEROUTE_CLI_UNKNOWN_NODE (~0)

typedef enum
{
  TRACEROUTE_REPLY_NEXT_DROP,
  TRACEROUTE_REPLY_NEXT_PUNT,
  TRACEROUTE_REPLY_N_NEXT,
} traceroute_reply_next_t;

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

static_always_inline traceroute_run_t *
get_run_by_traceroute_id (u16 id)
{
  traceroute_main_t *trm = &traceroute_main;
  traceroute_run_t **trr = 0;
  u8 found = 0;

  clib_spinlock_lock_if_init (&trm->run_check_lock);
  vec_foreach (trr, trm->active_runs)
    {
      if ((*trr)->id == id)
	{
	  found = 1;
	  break;
	}
    }
  clib_spinlock_unlock_if_init (&trm->run_check_lock);
  return found ? *trr : 0;
}

static_always_inline void
clear_run_by_traceroute_id (u16 id)
{
  traceroute_main_t *trm = &traceroute_main;
  traceroute_run_t **trr;

  clib_spinlock_lock_if_init (&trm->run_check_lock);
  vec_foreach (trr, trm->active_runs)
    {
      if ((*trr)->id == id)
	{
	  vec_del1 (trm->active_runs, trr - trm->active_runs);
	  break;
	}
    }
  clib_spinlock_unlock_if_init (&trm->run_check_lock);
}

static_always_inline u16
get_hop_and_repeat (icmp46_header_t *icmp46, u8 l4_proto)
{
  switch (l4_proto)
    {
    case IP_PROTOCOL_ICMP6:
    case IP_PROTOCOL_ICMP:
      {
	icmp46_echo_request_t *icmp46_echo =
	  (icmp46_echo_request_t *) (icmp46 + 1);
	return clib_net_to_host_u16 (icmp46_echo->seq);
      }
    case IP_PROTOCOL_TCP:
      {
	tcp_header_t *tcp = (tcp_header_t *) (icmp46 + 1);
	return clib_net_to_host_u16 (tcp->seq_number);
      }
    case IP_PROTOCOL_UDP:
      {
	udp_header_t *udp = (udp_header_t *) (icmp46 + 1);
	udp_data_t *udp_data = (udp_data_t *) (udp + 1);
	return clib_net_to_host_u16 (udp_data->seq);
      }
    default:
      clib_warning ("Unknown L4 protocol %d", l4_proto);
    }
  return ~0;
}

#endif /* traceroute_h */
