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
#include "../flowrouter/flowrouter.h"
#include "../flowrouter/flow_instructions.h"
#include "pool.h"
#include "nat_slowpath.h"

#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/fib/fib_table.h>

/*
 * Register flowrouter on input path
 * Configuration
 * Deal with punted packets
 */

nat_slowpath_main_t nat_slowpath_main;

/*
 * XXX: Make these configurable
 */
#define NAT_SLOWPATH_DEFAULT_TIMEOUT 200
#define NAT_SLOWPATH_ICMP_TIMEOUT 10
#define NAT_SLOWPATH_UDP_TIMEOUT 200
#define NAT_SLOWPATH_TCP_TRANSITORY_TIMEOUT 10
#define NAT_SLOWPATH_TCP_ESTABLISHED_TIMEOUT 30 //7440

static u8 *
format_nat_slowpath_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  s = format (s, "NAT SLOWPATH");
  return s;
}

#define foreach_nat_slowpath_next		\
  _(FASTPATH, "flowrouter-fastpath")		\
  _(DROP, "error-drop")				\
  _(ICMP_ERROR, "ip4-icmp-error")

typedef enum {
#define _(s, n) NAT_SLOWPATH_NEXT_##s,
  foreach_nat_slowpath_next
#undef _
    NAT_SLOWPATH_N_NEXT,
} nat_slowpath_next_t;

/*
 * Counters
 */
#define foreach_nat_slowpath_errors					\
  _(SESSION_CREATE_NOT_ALLOWED, "session create not allowed")		\
  _(ADDRESS_PORT_ALLOCATION_FAILED, "address and port allocation failed") \
  _(NO_SESSION, "no session")

typedef enum
{
#define _(sym, str) NAT_SLOWPATH_##sym,
  foreach_nat_slowpath_errors
#undef _
    NAT_SLOWPATH_N_ERROR,
} nat_slowpath_errors_t;

static char *nat_slowpath_error_strings[] = {
#define _(sym,string) string,
  foreach_nat_slowpath_errors
#undef _
};

static bool
nat_sp_session_exists (clib_bihash_16_8_t *h, flowrouter_key_t *k)
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
static int
nat_slowpath_allocate_address_and_port (u32 vrf_id, u8 proto,
					ip4_address_t X, u16 x,
					ip4_address_t Y, u16 y,
					ip4_address_t *X_marked, u16 *x_marked)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  u32 address;
  u16 port = x;

  address = ntohl(nsm->pool.prefix.as_u32) | (ntohl(X.as_u32) % nsm->pool.count);
  X_marked->as_u32 = htonl(address);

  while (1) {
    int i = 0;
    flowrouter_key_t kv = { .sa.as_u32 = Y.as_u32,
			    .da.as_u32 = X_marked->as_u32,
			    .proto = proto,
			    .fib_index = vrf_id,
			    .sp = y,
			    .dp = port };

    if (nat_sp_session_exists(&nsm->out2in_hash, &kv)) {
      if (++i > 10)
	return -1;
      port = port <= 0xFFFF - 1 ? port + 1 : 1025;
      continue;
    }
    *x_marked = port;
    return 0;
  }
}

/*
 * Checksum delta
 */
static int
l3_checksum_delta (flow_instructions_t instructions,
                   ip4_address_t *pre_sa, ip4_address_t *post_sa,
		   ip4_address_t *pre_da, ip4_address_t *post_da)
{
  ip_csum_t c = 0;
  if (instructions & FLOW_INSTR_SOURCE_ADDRESS) {
    c = ip_csum_add_even(c, post_sa->as_u32);
    c = ip_csum_sub_even(c, pre_sa->as_u32);
  }
  if (instructions & FLOW_INSTR_DESTINATION_ADDRESS) {
    c = ip_csum_sub_even(c, pre_da->as_u32);
    c = ip_csum_add_even(c, post_da->as_u32);
  }
  return c;
}

/*
 * L4 checksum delta (UDP/TCP)
 */
static int
l4_checksum_delta (flow_instructions_t instructions, ip_csum_t c,
                   u16 pre_sp, u16 post_sp, u16 pre_dp, u16 post_dp)
{
  if (instructions & FLOW_INSTR_SOURCE_PORT) {
    c = ip_csum_add_even(c, post_sp);
    c = ip_csum_sub_even(c, pre_sp);
  }
  if (instructions & FLOW_INSTR_DESTINATION_PORT) {
    c = ip_csum_add_even(c, post_dp);
    c = ip_csum_sub_even(c, pre_dp);
  }
  return c;
}

/*
 * Verify that it is a session initiating packet
 */
static bool
nat_slowpath_session_initiation_allowed (ip4_header_t *ip, enum flowrouter_session_state *state)
{
  if (ip->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = ip4_next_header (ip);
    if (tcp->flags & TCP_FLAG_SYN) {
      *state = FLOWROUTER_STATE_TCP_SYN_SEEN;
    } else {
      return false;
    }
  }
  return true;
}

static u32
nat_slowpath_get_timer (u8 proto)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;

  switch (proto) {
  case IP_PROTOCOL_ICMP:
    return nsm->icmp_timeout;
  case IP_PROTOCOL_UDP:
    return nsm->udp_timeout;
  case IP_PROTOCOL_TCP:
    return nsm->tcp_transitory_timeout;
  default:
    ;
  }
  return nsm->default_timeout;
}

static void
nat_sp_fp_session_create (flowrouter_session_t *fs, flowrouter_key_t *k,
			  flow_instructions_t instructions,
			  u32 fib_index, ip4_address_t *post_sa, ip4_address_t *post_da,
			  u16 post_sp, u16 post_dp, ip_csum_t checksum, ip_csum_t l4_checksum,
			  u16 tcp_mss, enum flowrouter_session_state state, f64 now)
{
  fs->k.as_u64[0] = k->as_u64[0];
  fs->k.as_u64[1] = k->as_u64[1];
  fs->instructions = instructions;
  fs->fib_index = fib_index;
  fs->post_sa.as_u32 = post_sa ? post_sa->as_u32 : 0;
  fs->post_da.as_u32 = post_da ? post_da->as_u32 : 0;
  fs->post_sp = post_sp;
  fs->post_dp = post_dp;
  fs->checksum = checksum;
  fs->l4_checksum = l4_checksum;
  fs->tcp_mss = tcp_mss;
  fs->state = state;
  fs->last_heard = now;
}

void
nat_sp_session_delete (nat_sp_session_t *s)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;

  /* Signal the workers */
  // need to know owning worker
  // and worker index...
  
  if (nsm->timers && s->timer_handle != ~0) {
    tw_timer_stop_2t_1w_2048sl (nsm->timers, s->timer_handle);
  }
  if (clib_bihash_add_del_16_8 (&nsm->in2out_hash, (clib_bihash_kv_16_8_t *)&s->in2out.k, 0))
    clib_warning("bihash delete failed");
  if (clib_bihash_add_del_16_8 (&nsm->out2in_hash, (clib_bihash_kv_16_8_t *)&s->out2in.k, 0))
    clib_warning("bihash delete failed");

  //clib_warning("Delete %u:%u -> %u:%u", s->in2out.owner, s->in2out.owner_index,
  //s->out2in.owner, s->out2in.owner_index);

  pool_put(nsm->sessions, s);
}

nat_sp_session_t *
nat_sp_session_lookup (clib_bihash_16_8_t *h, flowrouter_key_t *key, u32 *pool_index)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  clib_bihash_kv_16_8_t kv, value;

  /* Add to index */
  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];

  if (clib_bihash_search_16_8 (h, &kv, &value))
    return 0;
  if (pool_is_free_index (nsm->sessions, value.value)) /* Is this check necessary? */
    return 0;
  *pool_index = value.value;
  return pool_elt_at_index (nsm->sessions, value.value);
}

static flowrouter_session_t *
nat_sp_session_i2o_find (flowrouter_key_t *key, u32 *pool_index)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  nat_sp_session_t *s;
  s = nat_sp_session_lookup(&nsm->in2out_hash, key, pool_index);
  return s ? &s->in2out : 0;
}

static flowrouter_session_t *
nat_sp_session_o2i_find (flowrouter_key_t *key, u32 *pool_index)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  nat_sp_session_t *s;
  s = nat_sp_session_lookup(&nsm->out2in_hash, key, pool_index);
  return s ? &s->out2in : 0;
}

VLIB_NODE_FN (nat_slowpath_i2o_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{ 
  u32 n_left_from, *from, *to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  f64 now = vlib_time_now (vm);
  //  u32 thread_index = vm->thread_index;

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
      enum flowrouter_session_state state0 = FLOWROUTER_STATE_UNKNOWN;
      bool has_ports0 = ip0->protocol == IP_PROTOCOL_TCP ||
	ip0->protocol == IP_PROTOCOL_UDP ? true : false;

      /*
       * Check if this packet should be allowed to create a session
       */
      if (!nat_slowpath_session_initiation_allowed(ip0, &state0)) {
	next0 = NAT_SLOWPATH_NEXT_DROP;
	b0->error = node->errors[NAT_SLOWPATH_SESSION_CREATE_NOT_ALLOWED];
	goto trace0;
      }
      int rv = nat_slowpath_allocate_address_and_port(rx_fib_index0, ip0->protocol,
						      ip0->src_address, sport,
						      ip0->dst_address, dport,
						      &X_marked, &x_marked);
      if (rv) {
	next0 = NAT_SLOWPATH_NEXT_DROP;
	b0->error = node->errors[NAT_SLOWPATH_ADDRESS_PORT_ALLOCATION_FAILED];
	goto trace0;
      }

      /*
       * 1) Create BIB
       * 2) Create instructions signal to FP
       *    - Or just create the FP entry directly?
       */

      /* Create FP sessions (in2out, out2in) */
      ip_csum_t l4_c0 = 0;
      flow_instructions_t in2out_instr, out2in_instr;

      /* in2out session */
      in2out_instr = FLOW_INSTR_SOURCE_ADDRESS;
      flowrouter_key_t in2out_kv0 = { .sa.as_u32 = ip0->src_address.as_u32,
				      .da.as_u32 = ip0->dst_address.as_u32,
				      .proto = ip0->protocol,
				      .fib_index = rx_fib_index0,
				      .sp = sport,
				      .dp = dport };

      /* out2in session */
      flowrouter_key_t out2in_kv0 = { .sa.as_u32 = ip0->dst_address.as_u32,
				      .da.as_u32 = X_marked.as_u32,
				      .proto = ip0->protocol,
				      .fib_index = rx_fib_index0,
				      .sp = dport,
				      .dp = x_marked };

      nat_sp_session_t *s;

      pool_get_aligned(nsm->sessions, s, 64);
      u32 pool_index = s - nsm->sessions;

      ip_csum_t c0 = l3_checksum_delta(in2out_instr, &ip0->src_address, &X_marked, 0, 0);
      if (has_ports0) {
	in2out_instr |= FLOW_INSTR_SOURCE_PORT | FLOW_INSTR_TCP_CONN_TRACK;
	l4_c0 = l4_checksum_delta(in2out_instr, c0, sport, x_marked, 0, 0);
      }
      nat_sp_fp_session_create(&s->in2out, &in2out_kv0, in2out_instr,
			       rx_fib_index0, &X_marked, 0, x_marked, 0,
			       c0, l4_c0, 0, state0, now);

      out2in_instr = FLOW_INSTR_DESTINATION_ADDRESS;
      c0 = l3_checksum_delta(out2in_instr, 0, 0, &X_marked, &ip0->src_address);
      if (has_ports0) {
	out2in_instr |= FLOW_INSTR_DESTINATION_PORT | FLOW_INSTR_TCP_CONN_TRACK;
	l4_c0 = l4_checksum_delta(out2in_instr, c0, 0, 0, x_marked, sport);
      }
      nat_sp_fp_session_create(&s->out2in, &out2in_kv0, out2in_instr,
			       rx_fib_index0, 0, &ip0->src_address, 0, sport,
			       c0, l4_c0, 0, FLOWROUTER_STATE_UNKNOWN, now);

      s->timer_handle = tw_timer_start_2t_1w_2048sl (nsm->timers, pool_index, 0,
						     nat_slowpath_get_timer(ip0->protocol));

      clib_bihash_kv_16_8_t kv;
      kv.key[0]  = in2out_kv0.as_u64[0];
      kv.key[1]  = in2out_kv0.as_u64[1];
      kv.value = pool_index;
      if (clib_bihash_add_del_16_8 (&nsm->in2out_hash, &kv, 1)) {
	clib_warning("bihash add failed");
	// XXX: delete pool if hash fails
      }

      kv.key[0]  = out2in_kv0.as_u64[0];
      kv.key[1]  = out2in_kv0.as_u64[1];
      kv.value = pool_index;
      if (clib_bihash_add_del_16_8 (&nsm->out2in_hash, &kv, 1)) {
	clib_warning("bihash add failed");
	// XXX: delete pool if hash fails
      }

      next0 = NAT_SLOWPATH_NEXT_FASTPATH;
      goto trace0;

    trace0:
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

VLIB_NODE_FN (nat_slowpath_o2i_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * frame)
{ 
  u32 n_left_from, *from, *to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  //nat_slowpath_main_t *nsm = &nat_slowpath_main;
  //u32 thread_index = vm->thread_index;

  while (n_left_from > 0) {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;
      //, sw_if_index0; //, rx_fib_index0;
      //ip4_header_t *ip0;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      //ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
      //sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      //rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index0);


      /*
       * Sessions must be created by the inside
       */
      next0 = NAT_SLOWPATH_NEXT_DROP;
      b0->error = node->errors[NAT_SLOWPATH_NO_SESSION];
      goto trace0;

    trace0:
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
VLIB_REGISTER_NODE (nat_slowpath_i2o_node) = {
  .name = "nat-slowpath-i2o",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_slowpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_slowpath_error_strings),
  .error_strings = nat_slowpath_error_strings,
  .n_next_nodes = NAT_SLOWPATH_N_NEXT,
  .next_nodes =
  {
#define _(s, n) [NAT_SLOWPATH_NEXT_##s] = n,
   foreach_nat_slowpath_next
#undef _
  },
};
VLIB_REGISTER_NODE (nat_slowpath_o2i_node) = {
   .name = "nat-slowpath-o2i",
  .vector_size = sizeof (u32),
  .format_trace = format_nat_slowpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat_slowpath_error_strings),
  .error_strings = nat_slowpath_error_strings,
  .n_next_nodes = NAT_SLOWPATH_N_NEXT,
  .next_nodes =
  {
#define _(s, n) [NAT_SLOWPATH_NEXT_##s] = n,
   foreach_nat_slowpath_next
#undef _
  },
};

/* *INDENT-ON* */
static void
nat_sp_process_event (u32 pool_index)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  nat_sp_session_t *s;

  if (pool_is_free_index(nsm->sessions, pool_index)) {
    clib_warning("Fast path referring to non existing slow path session");
    return;
  }
  s = pool_elt_at_index(nsm->sessions, pool_index);

  if (s->in2out.state >= FLOWROUTER_STATE_TCP_FIN_WAIT) {
    tw_timer_update_2t_1w_2048sl (nsm->timers, s->timer_handle, NAT_SLOWPATH_TCP_TRANSITORY_TIMEOUT);
  } else if (s->in2out.state == FLOWROUTER_STATE_TCP_ESTABLISHED) {
    tw_timer_update_2t_1w_2048sl (nsm->timers, s->timer_handle, NAT_SLOWPATH_TCP_ESTABLISHED_TIMEOUT);
  } else {
    ;
    //clib_warning("Unknown state %u %U -> %U", pool_index,
    //format_flowrouter_state, s->in2out.state,
    //format_flowrouter_state, s->out2in.state);
  }
}

static void nat_slowpath_enable (vlib_main_t *vm);
static vlib_node_registration_t nat_slowpath_process_node;
static clib_error_t *
nat_slowpath_interface_command_fn (vlib_main_t * vm,
				   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  //nat_slowpath_main_t *nsm = &nat_slowpath_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 inside_sw_if_index = ~0;
  u32 outside_sw_if_index = ~0;
  u32 sw_if_index;
  bool is_enable = true;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
	inside_sw_if_index = sw_if_index;
      else if (unformat (line_input, "out %U", unformat_vnet_sw_interface,
                         vnm, &sw_if_index))
	outside_sw_if_index = sw_if_index;
      else if (unformat (line_input, "del"))
        is_enable = false;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  nat_slowpath_enable(vm);

  if (inside_sw_if_index != ~0) {
    flowrouter_register_interface(inside_sw_if_index, nat_slowpath_i2o_node.index, nat_sp_session_i2o_find,
				  nat_sp_process_event, nat_slowpath_process_node.index);
    clib_warning("Enabling feature on %u", inside_sw_if_index);
    if (vnet_feature_enable_disable ("ip4-unicast", "flowrouter-handoff",
				     inside_sw_if_index, is_enable, 0, 0) != 0)
      clib_warning("Feature change failed");
  } else if (outside_sw_if_index != ~0) {
    flowrouter_register_interface(outside_sw_if_index, nat_slowpath_o2i_node.index, nat_sp_session_o2i_find,
				  0, nat_slowpath_process_node.index);
    if (vnet_feature_enable_disable ("ip4-unicast", "flowrouter-handoff",
				     outside_sw_if_index, is_enable, 0, 0) != 0)
      clib_warning("Feature change failed");
  }

 done:
  return error;
}

static clib_error_t *
nat_slowpath_max_sessions_command_fn (vlib_main_t * vm,
				      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &nsm->max_sessions))
	;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

 done:
  return error;
}

static clib_error_t *
nat_slowpath_timeout_command_fn (vlib_main_t * vm,
				 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "default %u", &nsm->default_timeout))
	;
      else if (unformat (line_input, "icmp %u", &nsm->icmp_timeout))
	;
      else if (unformat (line_input, "udp %u", &nsm->udp_timeout))
	;
      else if (unformat (line_input, "tcp-transitory %u", &nsm->tcp_transitory_timeout))
	;
      else if (unformat (line_input, "tcp-establshed %u", &nsm->tcp_established_timeout))
	;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

 done:
  return error;
}

static void
nat_slowpath_expired_timer_callback (u32 * expired_timers)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  int i;
  u32 handle;
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      handle = expired_timers[i] & 0x7FFFFFFF;

      nat_sp_session_t *s = pool_elt_at_index (nsm->sessions, handle);

      /*
       * Timer expiry.
       * Figure out if it's an actual entry for deletion or it's an entry
       * that should be extended.
       *
       * if TCP -> check TCP state
       * else check timer versus last_heard
       */
      s->timer_handle = ~0;
      if (s->in2out.k.proto == IP_PROTOCOL_TCP &&
	  s->in2out.state >= FLOWROUTER_STATE_TCP_FIN_WAIT) {
	nat_sp_session_delete(s);
      } else {
	if (now - s->in2out.last_heard < s->timer) { /* Reset timer */
	  s->timer_handle = tw_timer_start_2t_1w_2048sl (nsm->timers, handle, 0, s->timer);

	  //clib_warning("NON TCP session restarting timer");
	} else {
	  clib_warning("NON TCP session deleted");
	  nat_sp_session_delete(s);
	}
      }
    }
}

static void
nat_slowpath_enable (vlib_main_t *vm)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main;

  if (nsm->enabled) return;

  nsm->max_sessions = 1 << 20;	/* Default 1M sessions */
  nsm->default_timeout = 200;
  nsm->icmp_timeout = 10;
  nsm->udp_timeout = 200;
  nsm->tcp_transitory_timeout = 10;
  nsm->tcp_established_timeout = 30;

  nsm->timers = clib_mem_alloc (sizeof (TWT (tw_timer_wheel)));
  tw_timer_wheel_init_2t_1w_2048sl (nsm->timers,
				    nat_slowpath_expired_timer_callback,
				    1.0, 1024);

  clib_bihash_init_16_8 (&nsm->in2out_hash, "in2out hash", nsm->max_sessions, nsm->max_sessions * 250);
  clib_bihash_init_16_8 (&nsm->out2in_hash, "out2in hash", nsm->max_sessions, nsm->max_sessions * 250);


  clib_warning("Starting process");
  vlib_node_set_state (vm, nat_slowpath_process_node.index, VLIB_NODE_STATE_POLLING);
  vlib_node_t *n = vlib_get_node (vm, nat_slowpath_process_node.index);
  vlib_start_process (vm, n->runtime_index);

  nsm->enabled = true;

#if 0  
  if (!nsm->enabled) {
    flowrouter_conntrack_timeouts (nsm->tcp_transitory_timeout, nsm->tcp_established_timeout);
    //nsm->in2out_table = flowrouter_create_table("nat_slowpath_in2out", nsm->max_sessions, true);
    //nsm->out2in_table = flowrouter_create_table("nat_slowpath_out2in", nsm->max_sessions, false);

  }
#endif
}

static u8 *
format_nat_slowpath_session (u8 * s, va_list * args)
{
  u32 poolidx = va_arg (*args, u32);
  nat_sp_session_t *ses = va_arg (*args, nat_sp_session_t *);

  s = format(s, "[%-8u] i2o: %U", poolidx, format_flowrouter_session, &ses->in2out);
  s = format(s, "          o2i: %U", format_flowrouter_session, &ses->out2in);
  s = format (s, "\n");
  return s;
}

static clib_error_t *
show_nat_slowpath_sessions_command_fn (vlib_main_t * vm, unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  nat_sp_session_t *s;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      /* *INDENT-OFF* */
      pool_foreach(s, nsm->sessions,
		   ({vlib_cli_output(vm, "%U", format_nat_slowpath_session,
				     s - nsm->sessions, s);
		   }));
      /* *INDENT-ON* */
      return 0;
    }
  unformat_free (line_input);

  return error;
}



VLIB_CLI_COMMAND (set_interface_nat_command, static) = {
  .path = "set interface nat-slowpath",
  .function = nat_slowpath_interface_command_fn,
  .short_help = "set interface nat-slowpath <intfc> <in | out> [del]",
};

VLIB_CLI_COMMAND (set_nat_max_sessions_command, static) = {
  .path = "set nat-slowpath max-sessions",
  .function = nat_slowpath_max_sessions_command_fn,
  .short_help = "set nat-slowpath max-sessions <n>",
};

VLIB_CLI_COMMAND (set_nat_timeout_command, static) = {
  .path = "set nat-slowpath timeout",
  .function = nat_slowpath_timeout_command_fn,
  .short_help = "set nat-slowpath timeout [udp <sec> | icmp <sec> "
                "tcp-transitory <sec> | tcp-established <sec> | "
                "default <sec>]",
};
VLIB_CLI_COMMAND(show_nat_sessions_command, static) = {
  .path = "show nat-slowpath sessions",
  .short_help = "show nat-slowpath sessions",
  .function = show_nat_slowpath_sessions_command_fn,
};

static uword
nat_slowpath_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      vlib_frame_t * f)
{
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;
  nat_slowpath_main_t *nsm = &nat_slowpath_main;
  int i;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type) {
      case FLOWROUTER_EVENT_STATE_CHANGE:
	for (i = 0; i < vec_len(event_data); i++) {
	  nat_sp_process_event(event_data[i]);
	}
	break;
      default:
	;
      }
      /* expire timers */
      tw_timer_expire_timers_2t_1w_2048sl (nsm->timers, now);
      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat_slowpath_process_node, static) =
{
  .function = nat_slowpath_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "nat-slowpath-process",
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */



#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () =
{
.version = VPP_BUILD_VER,.description = "NAT slowpath"
};
