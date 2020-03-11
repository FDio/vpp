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
#include "pool.h"
#include "unat.h"
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/fib/fib_table.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#define UNAT_PORT_ALLOC_MAX_RETRIES 5

/*
 * Register flowrouter on input path
 * Configuration
 * Deal with punted packets
 */

unat_main_t unat_main;

static u8 *
format_unat_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  s = format (s, "UNAT SLOWPATH");
  return s;
}

/*
 * Errors
 */
#define foreach_unat_sp_errors						\
  _(SESSION_CREATE_NOT_ALLOWED, "session create not allowed")		\
  _(ADDRESS_PORT_ALLOCATION_FAILED, "address and port allocation failed") \
  _(NO_SESSION, "no session")						\
  _(CREATE_FAILED, "create failed")

typedef enum
{
#define _(sym, str) UNAT_SP_ERROR_##sym,
  foreach_unat_sp_errors
#undef _
    UNAT_SP_N_ERROR,
} unat_sp_errors_t;

static char *unat_sp_error_strings[] = {
#define _(sym,string) string,
  foreach_unat_sp_errors
#undef _
};

static inline bool
unat_session_exists (clib_bihash_16_8_t *h, unat_key_t *k)
{
  clib_bihash_kv_16_8_t value;

  if (clib_bihash_search_16_8 (h, (clib_bihash_kv_16_8_t *)k, &value)) {
    return false;
  }
  return true;
}

/*
 * Address and port allocation algorithm
 * - Pick an address from the outside pool modulo the inside source address
 *   This is to achieve some level of load balancing across the pool.
 * - Pick the same outside port and the inside port if possible
 * - If conflict, i.e. there is already a session X':x' -> Y:y,
 *   try the next port.
 * - If this fails more than 10 times, give up.
 */
static inline u16
get_port (unat_pool_t *p, u16 port)
{
  if (p->psid_length == 0) {
    return port;
  }
  return (port & ~p->psid_mask) | p->psid;
}

/*
 * Assuming psid_offset = 0
 */
static inline u16
get_next_port (unat_pool_t *p, u16 port)
{
  if (p->psid_length == 0) {
    return port <= 0xFFFF - 1 ? port + 1 : 1025;
  }
  return get_port(p, port <= p->psid_mask - 1 ? port + 1 : 1025);
}

static int
unat_allocate_address_and_port (u32 thread_index, u32 vrf_id, u8 proto,
				ip4_address_t X, u16 x,
				ip4_address_t Y, u16 y,
				ip4_address_t *X_marked, u16 *x_marked, u32 *conflicts)
{
  unat_main_t *um = &unat_main;
  unat_pool_t *p = unat_pool_get(um->pool_per_thread[thread_index]);
  u32 address;
  u16 port = get_port(p, ntohs(x));
  int i = 0;

  address = ntohl(p->prefix.as_u32) | (ntohl(X.as_u32) % p->count);
  X_marked->as_u32 = htonl(address);
  unat_key_t kv = { .sa.as_u32 = Y.as_u32,
		    .da.as_u32 = X_marked->as_u32,
		    .proto = proto,
		    .fib_index = vrf_id,
		    .sp = y,
		    .dp = htons(port) };

  while (1) {
    if (unat_session_exists(&um->out2in_hash, &kv)) {
      *conflicts += 1;
      if (++i > UNAT_PORT_ALLOC_MAX_RETRIES)
	return -1;
      kv.dp = htons(get_next_port(p, port));
      continue;
    }
    *x_marked = kv.dp;
    return 0;
  }
}

/*
 * Checksum delta
 */
static int
l3_checksum_delta (unat_instructions_t instructions,
                   ip4_address_t *pre_sa, ip4_address_t *post_sa,
		   ip4_address_t *pre_da, ip4_address_t *post_da)
{
  ip_csum_t c = 0;
  if (instructions & UNAT_INSTR_SOURCE_ADDRESS) {
    c = ip_csum_add_even(c, post_sa->as_u32);
    c = ip_csum_sub_even(c, pre_sa->as_u32);
  }
  if (instructions & UNAT_INSTR_DESTINATION_ADDRESS) {
    c = ip_csum_sub_even(c, pre_da->as_u32);
    c = ip_csum_add_even(c, post_da->as_u32);
  }
  return c;
}

/*
 * L4 checksum delta (UDP/TCP)
 */
static int
l4_checksum_delta (unat_instructions_t instructions, ip_csum_t c,
                   u16 pre_sp, u16 post_sp, u16 pre_dp, u16 post_dp)
{
  if (instructions & UNAT_INSTR_SOURCE_PORT) {
    c = ip_csum_add_even(c, post_sp);
    c = ip_csum_sub_even(c, pre_sp);
  }
  if (instructions & UNAT_INSTR_DESTINATION_PORT) {
    c = ip_csum_add_even(c, post_dp);
    c = ip_csum_sub_even(c, pre_dp);
  }
  return c;
}

/*
 * Verify that it is a session initiating packet
 */
static bool
unat_session_tcp_initiation_prohibited (ip4_header_t *ip, enum unat_session_state *state)
{
  tcp_header_t *tcp = ip4_next_header (ip);
  if (tcp->flags & TCP_FLAG_SYN) {
    *state = UNAT_STATE_TCP_SYN_SEEN;
    return false;
  }
  return true;
}

static u32
unat_get_timer (u8 proto)
{
  unat_main_t *um = &unat_main;

  switch (proto) {
  case IP_PROTOCOL_ICMP:
    return um->icmp_timeout;
  case IP_PROTOCOL_UDP:
    return um->udp_timeout;
  case IP_PROTOCOL_TCP:
    return um->tcp_transitory_timeout;
  default:
    ;
  }
  return um->default_timeout;
}

void
unat_session_delete (u32 thread_index, unat_session_t *s)
{
  unat_main_t *um = &unat_main;

  if (um->timers_per_worker[thread_index] && s->timer_handle != ~0) {
    tw_timer_stop_2t_1w_2048sl (um->timers_per_worker[thread_index], s->timer_handle);
  }

  if (clib_bihash_add_del_16_8 (&um->in2out_hash, (clib_bihash_kv_16_8_t *)&s->in2out.k, 0)) {
    clib_warning("bihash delete in2out failed %u %U", s - um->sessions_per_worker[thread_index],
		 format_unat_fp_session, &s->in2out);
  }
  if (clib_bihash_add_del_16_8 (&um->out2in_hash, (clib_bihash_kv_16_8_t *)&s->out2in.k, 0))
    clib_warning("bihash delete out2in failed");
  pool_put(um->sessions_per_worker[thread_index], s);
}

VLIB_NODE_FN (unat_sp_i2o_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{ 
  u32 n_left_from, *from, *to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  unat_main_t *um = &unat_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 conflicts = 0, created = 0;

  while (n_left_from > 0) {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0, sw_if_index0, rx_fib_index0;
      ip4_header_t *ip0;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index0);

      /* Logic:
       *
       * - Allocate outside port and address
       * - Create in2out and out2in sessions
       * - Create fastpath in2out and out2in hashes
       * - Calculate instructions and checksum deltas
       * - Ship packet back to fastpath
       */

      /* Allocate external address and port */
      ip4_address_t X_marked;
      u16 x_marked;
      u16 sport = vnet_buffer (b0)->ip.reass.l4_src_port;
      u16 dport = vnet_buffer (b0)->ip.reass.l4_dst_port;
      enum unat_session_state state0 = UNAT_STATE_UNKNOWN;
      bool has_ports0 = ip0->protocol == IP_PROTOCOL_TCP ||
	ip0->protocol == IP_PROTOCOL_UDP ? true : false;

      /*
       * Check if this packet should be allowed to create a session
       */
      if (has_ports0 && ip0->protocol == IP_PROTOCOL_TCP &&
	  unat_session_tcp_initiation_prohibited(ip0, &state0)) {
	next0 = UNAT_NEXT_DROP;
	b0->error = node->errors[UNAT_SP_ERROR_SESSION_CREATE_NOT_ALLOWED];
	goto trace0;
      }

      int rv = unat_allocate_address_and_port(thread_index,
					      rx_fib_index0, ip0->protocol,
					      ip0->src_address, sport,
					      ip0->dst_address, dport,
					      &X_marked, &x_marked, &conflicts);
      if (rv) {
	next0 = UNAT_NEXT_DROP;
	b0->error = node->errors[UNAT_SP_ERROR_ADDRESS_PORT_ALLOCATION_FAILED];
	goto trace0;
      }

      /*
       * 1) Create BIB
       * 2) Create instructions signal to FP
       *    - Or just create the FP entry directly?
       */
      clib_bihash_kv_16_8_t i2o_kv0, o2i_kv0;
      unat_key_t *in2out_key0 = (unat_key_t *)&i2o_kv0;
      unat_key_t *out2in_key0 = (unat_key_t *)&o2i_kv0;

      /* Create FP sessions (in2out, out2in) */
      ip_csum_t l4_c0 = 0;
      unat_instructions_t in2out_instr0, out2in_instr0;

      unat_session_t *s0;
      pool_get(um->sessions_per_worker[thread_index], s0);
      u32 pool_index0 = s0 - um->sessions_per_worker[thread_index];

      /* in2out session */
      in2out_instr0 = UNAT_INSTR_SOURCE_ADDRESS;

      clib_memcpy_fast(&in2out_key0->sa, &ip0->src_address, 4);
      clib_memcpy_fast(&in2out_key0->da, &ip0->dst_address, 4);
      in2out_key0->proto = ip0->protocol;
      in2out_key0->fib_index = rx_fib_index0;
      in2out_key0->sp = sport;
      in2out_key0->dp = dport;

      /* out2in session */
      clib_memcpy_fast(&out2in_key0->sa, &ip0->dst_address, 4);
      clib_memcpy_fast(&out2in_key0->da, &X_marked, 4);
      out2in_key0->proto = ip0->protocol;
      out2in_key0->fib_index = rx_fib_index0;
      out2in_key0->sp = dport;
      out2in_key0->dp = x_marked;

      unat_fp_session_t *i2o_fs0 = &s0->in2out;
      unat_fp_session_t *o2i_fs0 = &s0->out2in;

      ip_csum_t c0 = l3_checksum_delta(in2out_instr0, &ip0->src_address, &X_marked, 0, 0);
      if (has_ports0) {
	in2out_instr0 |= UNAT_INSTR_SOURCE_PORT | UNAT_INSTR_TCP_CONN_TRACK;
	l4_c0 = l4_checksum_delta(in2out_instr0, c0, sport, x_marked, 0, 0);
      }

      clib_memcpy_fast(&i2o_fs0->k, in2out_key0, sizeof(*in2out_key0));
      i2o_fs0->instructions = in2out_instr0;
      i2o_fs0->fib_index = rx_fib_index0;
      i2o_fs0->post_sa = X_marked;
      i2o_fs0->post_da.as_u32 = 0;
      i2o_fs0->post_sp = x_marked;
      i2o_fs0->post_dp = 0;
      i2o_fs0->checksum = c0;
      i2o_fs0->l4_checksum = l4_c0;
      i2o_fs0->tcp_mss = 0;
      i2o_fs0->state = state0;
      i2o_fs0->last_heard = now;

      out2in_instr0 = UNAT_INSTR_DESTINATION_ADDRESS;
      c0 = l3_checksum_delta(out2in_instr0, 0, 0, &X_marked, &ip0->src_address);
      if (has_ports0) {
	out2in_instr0 |= UNAT_INSTR_DESTINATION_PORT | UNAT_INSTR_TCP_CONN_TRACK;
	l4_c0 = l4_checksum_delta(out2in_instr0, c0, 0, 0, x_marked, sport);
      }

      clib_memcpy_fast(&o2i_fs0->k, out2in_key0, sizeof(*out2in_key0));
      o2i_fs0->instructions = out2in_instr0;
      o2i_fs0->fib_index = rx_fib_index0;
      o2i_fs0->post_sa.as_u32 = 0;
      clib_memcpy_fast(&o2i_fs0->post_da, &ip0->src_address, 4);
      o2i_fs0->post_sp = 0;
      o2i_fs0->post_dp = sport;
      o2i_fs0->checksum = c0;
      o2i_fs0->l4_checksum = l4_c0;
      o2i_fs0->tcp_mss = 0;
      o2i_fs0->state = UNAT_STATE_UNKNOWN;
      o2i_fs0->last_heard = now;

      s0->timer = unat_get_timer(ip0->protocol);

      i2o_kv0.value = ((u64)thread_index << 32) | pool_index0;
      o2i_kv0.value = ((u64)thread_index << 32) | pool_index0;

      if (clib_bihash_add_del_16_8 (&um->in2out_hash, &i2o_kv0, 1)) {
	pool_put(um->sessions_per_worker[thread_index], s0);
	next0 = UNAT_NEXT_DROP;
	b0->error = node->errors[UNAT_SP_ERROR_CREATE_FAILED];
	goto trace0;
      }

      if (clib_bihash_add_del_16_8 (&um->out2in_hash, &o2i_kv0, 1)) {
	clib_warning("ADDING FAILED");
	clib_bihash_add_del_16_8 (&um->in2out_hash, &i2o_kv0, 0);
	pool_put(um->sessions_per_worker[thread_index], s0);
	next0 = UNAT_NEXT_DROP;
	b0->error = node->errors[UNAT_SP_ERROR_CREATE_FAILED];
	goto trace0;
      }

      vnet_buffer(b0)->unat.pool_index = pool_index0;
      s0->timer_handle = tw_timer_start_2t_1w_2048sl (um->timers_per_worker[thread_index], pool_index0, 0,
						      s0->timer);

      next0 = UNAT_NEXT_FASTPATH;
      created += 1;
    trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ;
	}

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
				       to_next, n_left_to_next,
				       bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  if (conflicts > 0)
    vlib_increment_simple_counter (um->counters + UNAT_COUNTER_SLOWPATH_PORT_ALLOC_CONFLICT, thread_index, 0, conflicts);
  if (created > 0)
    vlib_increment_simple_counter (um->counters + UNAT_COUNTER_SLOWPATH_CREATED, thread_index, 0, created);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (unat_sp_i2o_node) = {
  .name = "unat-slowpath-i2o",
  .vector_size = sizeof (u32),
  .format_trace = format_unat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (unat_sp_error_strings),
  .error_strings = unat_sp_error_strings,
  .sibling_of = "unat-handoff",
};
/* *INDENT-ON* */

#if 0
static int
sort_cmp (void *a1, void *a2)
{
  uword *i1 = (uword *) a1, *i2 = (uword *) a2;

  if (*i1 < *i2)
    return -1;
  else if (*i1 > *i2)
    return 1;
  else
    return 0;
}

/*
 * Not duplicate
 * - Timer started twice?
 * - Mismatch between the hash of the bihash key and the pool index?
 *
 */
static void
duplicate_check (u32 *vector)
{
  int i;
  u32 prev = ~0;
  u32 *dup = vec_dup(vector);
  vec_sort_with_function (dup, sort_cmp);

  for (i = 0; i < vec_len (dup); i++) {
    clib_warning("Comparing this and that: %u %u", dup[i], prev);
    if (dup[i] == prev) {
      clib_warning("Duplicat pool index");
    }
    prev = dup[i];
  }
}
#endif

void
unat_sp_spin_timer (u32 thread_index, f64 now, u32 max)
{
  unat_main_t *um = &unat_main;
  u32 *i;
  unat_session_t *s;

  /*
   * Tick the timer when required and process the vector of expired
   * timers
   */
  u32 count = 0, already_freed = 0;

  tw_timer_expire_timers_2t_1w_2048sl (um->timers_per_worker[thread_index], now);

  counter_t emax = vlib_get_simple_counter_thread(um->counters + UNAT_COUNTER_SLOWPATH_EXPIRE_VECTOR_MAX, thread_index, 0);
  if (emax < vec_len(um->expired_sessions_per_worker[thread_index]))
    vlib_set_simple_counter (um->counters + UNAT_COUNTER_SLOWPATH_EXPIRE_VECTOR_MAX, thread_index, 0,
			     vec_len(um->expired_sessions_per_worker[thread_index]));


  //duplicate_check(um->expired_sessions_per_worker[thread_index]);

  vec_foreach (i, um->expired_sessions_per_worker[thread_index]) {
    if (count > max)
      break;
    count++;

    if (pool_is_free_index (um->sessions_per_worker[thread_index], *i)) {
      already_freed++;
      continue;
    } else {
      s = pool_elt_at_index (um->sessions_per_worker[thread_index], *i);
    }

    s->timer_handle = ~0;
    if (now - s->in2out.last_heard < s->timer) { /* Reset timer */
      s->timer_handle = tw_timer_start_2t_1w_2048sl (um->timers_per_worker[thread_index], *i, 0, s->timer);
    } else {
      unat_session_delete(thread_index, s);
    }
  }
  if (count) {
    vec_delete (um->expired_sessions_per_worker[thread_index], count, 0);
    vlib_increment_simple_counter (um->counters + UNAT_COUNTER_SLOWPATH_DELETED, thread_index, 0, count);
  }
  if (already_freed) {
    vlib_increment_simple_counter (um->counters + UNAT_COUNTER_SLOWPATH_FREED_ALREADY, thread_index, 0, already_freed);
  }
}

/* Per worker process processing the active/passive expired entries */
VLIB_NODE_FN (unat_sp_timer_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  //unat_sp_spin_timer(vm->thread_index, vlib_time_now (vm), 256);
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (unat_sp_timer_node) = {
  .name = "unat-sp-timer",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};
/* *INDENT-ON* */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () =
{
.version = VPP_BUILD_VER,.description = "NAT slowpath"
};

VLIB_NODE_FN (unat_sp_o2i_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{ 
  u32 n_left_from, *from, *to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left_from > 0) {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      /*
       * Sessions must be created by the inside
       */
      next0 = UNAT_NEXT_DROP;
      b0->error = node->errors[UNAT_SP_ERROR_NO_SESSION];

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                         && (b0->flags & VLIB_BUFFER_IS_TRACED)))
        {
#if 0
          nat_in2out_ed_trace_t *t =
            vlib_add_trace (vm, node, b0, sizeof (*t));
          t->sw_if_index = sw_if_index0;
          t->next_index = next0;

          if (s0)
            t->session_index = s0 - tsm->sessions;
          else
            t->session_index = ~0;
#endif
        }

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                       to_next, n_left_to_next,
                                       bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  return frame->n_vectors;
}
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (unat_sp_o2i_node) = {
  .name = "unat-slowpath-o2i",
  .vector_size = sizeof (u32),
  .format_trace = format_unat_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (unat_sp_error_strings),
  .error_strings = unat_sp_error_strings,
  .sibling_of = "unat-handoff",
};
/* *INDENT-ON* */

