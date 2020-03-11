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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include "pool.h"
#include "unat.h"
#include <vnet/ip/format.h>
#include <arpa/inet.h>

extern vlib_node_registration_t unat_fp_node;
extern vlib_node_registration_t unat_sp_i2o_node;

void
unat_enable_worker (u32 thread_index)
{
  unat_main_t *um = &unat_main;

  pool_init_fixed(um->sessions_per_worker[thread_index], um->max_sessions);
  pool_init_fixed (um->lru_pool[thread_index], um->max_sessions);

  dlist_elt_t *head;
  pool_get (um->lru_pool[thread_index], head);
  um->lru_head_index[thread_index] = head - um->lru_pool[thread_index];
  clib_dlist_init (um->lru_pool[thread_index],
		   um->lru_head_index[thread_index]);

}

/*
 * Will not enable NAT until all required configuration is in place.
 */
void
unat_enable (vlib_main_t *vm)
{
  unat_main_t *um = &unat_main;

  if (um->enabled) return;
  um->max_sessions = 10000000;
  clib_bihash_init_16_8 (&um->in2out_hash, "in2out hash", um->max_sessions, um->max_sessions * 250);
  clib_bihash_init_16_8 (&um->out2in_hash, "out2in hash", um->max_sessions, um->max_sessions * 250);

  vec_validate (um->sessions_per_worker, vlib_num_workers() + 1);
  vec_validate (um->pool_per_thread, vlib_num_workers() + 1);
  vec_validate (um->lru_pool, vlib_num_workers() + 1);
  vec_validate (um->lru_head_index, vlib_num_workers() + 1);

  um->enabled = true;

  /*
   * Register fast path handover
   */
  um->fast_path_node_index = vlib_frame_queue_main_init (unat_fp_node.index, 64);
  um->slow_path_node_index = vlib_frame_queue_main_init (unat_sp_i2o_node.index, 64);

  clib_spinlock_init(&um->counter_lock);
  clib_spinlock_lock (&um->counter_lock); /* should be no need */

  vec_validate (um->counters, UNAT_N_COUNTER - 1);
#define _(E,n,p)                                                        \
  um->counters[UNAT_COUNTER_##E].name = #n;				\
  um->counters[UNAT_COUNTER_##E].stat_segment_name = "/" #p "/" #n;	\
  vlib_validate_simple_counter (&um->counters[UNAT_COUNTER_##E], 0);	\
  vlib_zero_simple_counter (&um->counters[UNAT_COUNTER_##E], 0);
  foreach_unat_counter_name
#undef _
    clib_spinlock_unlock (&um->counter_lock);
}

void
unat_register_interface (u32 sw_if_index, u32 node_index, bool in2out, clib_bihash_16_8_t *h)
{
  unat_main_t *um = &unat_main;
  unat_interface_t *interface;

  pool_get (um->interfaces, interface);
  interface->sw_if_index = sw_if_index;
  vec_validate_init_empty(um->interface_by_sw_if_index, sw_if_index, ~0);
  um->interface_by_sw_if_index[sw_if_index] = interface - um->interfaces;
  interface->in2out = in2out;
  interface->hash = h;

  ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
}

u8 *
format_unat_state (u8 *s, va_list * args)
{
  enum unat_session_state state = va_arg (*args, enum unat_session_state);

  switch (state) {
  case UNAT_STATE_TCP_SYN_SEEN:
    s = format (s, "syn seen");
    break;
  case UNAT_STATE_TCP_ESTABLISHED:
    s = format (s, "tcp established");
    break;
  case UNAT_STATE_TCP_FIN_WAIT:
    s = format (s, "tcp fin wait");
    break;
  case UNAT_STATE_TCP_CLOSE_WAIT:
    s = format (s, "tcp close wait");
    break;
  case UNAT_STATE_TCP_CLOSED:
    s = format (s, "tcp closed");
    break;
  case UNAT_STATE_TCP_LAST_ACK:
    s = format (s, "tcp last ack");
    break;
  case UNAT_STATE_UNKNOWN:
  default:
    s = format (s, "unknown");
  }
  return s;
}

u8 *
format_unat_fp_session (u8 * s, va_list * args)
{
  unat_fp_session_t *ses = va_arg (*args, unat_fp_session_t *);

  if (ses->instructions & (UNAT_INSTR_DESTINATION_ADDRESS|UNAT_INSTR_DESTINATION_PORT)) {
    s = format (s,
		"%U%%%u:%u -> %U:%u (%U:%u) state: %U",
		format_ip4_address, &ses->k.sa,	ses->fib_index, ntohs(ses->k.sp),
		format_ip4_address, &ses->k.da, ntohs(ses->k.dp),
		format_ip4_address, &ses->post_da, ntohs(ses->post_dp),
		format_unat_state, ses->state);
  } else if (ses->instructions & (UNAT_INSTR_SOURCE_ADDRESS|UNAT_INSTR_SOURCE_PORT)) {
    s = format (s,
		"%U%%%u:%u (%U:%u) -> %U:%u state: %U",
		format_ip4_address, &ses->k.sa, ses->fib_index, ntohs(ses->k.sp),
		format_ip4_address, &ses->post_sa, ntohs(ses->post_sp),
		format_ip4_address, &ses->k.da, ntohs(ses->k.dp),
		format_unat_state, ses->state);
  } else
    s = format (s, "UNKNOWN INSTRUCTIONS %u", ses->instructions);
  s = format (s, "\n");
  return s;
}

u8 *
format_unat_session (u8 * s, va_list * args)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  u32 poolidx = va_arg (*args, u32);
  unat_session_t *ses = va_arg (*args, unat_session_t *);

  s = format(s, "[%-8u] i2o: %U", poolidx, format_unat_fp_session, &ses->in2out);
  s = format(s, "          o2i: %U", format_unat_fp_session, &ses->out2in);
  s = format(s, "          last heard: %.2f", now - ses->last_heard);
  s = format (s, "\n");
  return s;
}


clib_error_t *
unat_init (vlib_main_t * vm)
{
  unat_main_t *um = &unat_main;

  memset (um, 0, sizeof(*um));

  um->max_sessions = 1 << 20;	/* Default 1M sessions */
  um->default_timeout = 200;
  um->icmp_timeout = 10;
  um->udp_timeout = 200;
  um->tcp_transitory_timeout = 10;
  um->tcp_established_timeout = 30;

  return 0;
}

VLIB_INIT_FUNCTION (unat_init);
