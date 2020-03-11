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
#include <vnet/udp/udp.h>
#include "unat.h"
#include "unat_inlines.h"
#include "../nat.h"

/*
 * Counters
 */
#define foreach_unat_fp_errors					\
  _(NO_ERROR, "success")					\
  _(NO_SESSION, "no session")

typedef enum
{
#define _(sym, str) UNAT_FP_ERROR_##sym,
  foreach_unat_fp_errors
#undef _
    UNAT_FP_N_ERROR,
} unat_fp_errors_t;

static char *unat_fp_error_strings[] = {
#define _(sym,string) string,
  foreach_unat_fp_errors
#undef _
};

/*
 * Trace
 */
typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 pool_index;
  bool in2out;
} unat_trace_t;

static u8 *
format_unat_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  unat_trace_t *t = va_arg (*args, unat_trace_t *);

  char *tag = t->in2out ? "in2out" : "out2in";
  s = format (s, "%s: sw_if_index %d next index %d session %d ",
	      tag, t->sw_if_index, t->next_index, t->pool_index);
  return s;
}

static inline void
unat_session_update_lru (u32 thread_index, u32 pool_index, unat_session_t * s)
{
  unat_main_t *um = &unat_main;
  /* don't update too often - timeout is in a magnitude of seconds anyway */
  if (s->last_heard > s->last_lru_update + 1)  {
    clib_dlist_remove (um->lru_pool[thread_index], s->lru_index);
    clib_dlist_addtail (um->lru_pool[thread_index], um->lru_head_index[thread_index], s->lru_index);
    s->last_lru_update = s->last_heard;
  }
}

static u32
execute (bool in2out, u32 pool_index, u32 thread_index, ip4_header_t *ip,
	 f64 now, u32 *out_fib_index)
{
  unat_main_t *um = &unat_main;
  if (pool_is_free_index (um->sessions_per_worker[thread_index], pool_index)) {
    return UNAT_FP_ERROR_NO_SESSION;
  }
  unat_session_t *session = pool_elt_at_index (um->sessions_per_worker[thread_index], pool_index);
  unat_fp_session_t *s = in2out ? &session->in2out : &session->out2in;
  *out_fib_index = s->fib_index;

  enum unat_session_state newstate = s->state, state = s->state;
  ip_csum_t l4csum;

  /* Source address Destination address */
  if (s->instructions & UNAT_INSTR_DESTINATION_ADDRESS)
    ip->dst_address = s->post_da;
  if (s->instructions & UNAT_INSTR_SOURCE_ADDRESS)
    ip->src_address = s->post_sa;

  /* Header checksum */
  /* XXX: Assumes that checksum needs to be updated */
  ip_csum_t csum = ip->checksum;
  csum = ip_csum_sub_even(csum, s->checksum);
  ip->checksum = ip_csum_fold(csum);
  ASSERT (ip->checksum == ip4_header_checksum (ip));

  /* L4 ports */
  if (ip->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = ip4_next_header (ip);

    if (s->instructions & UNAT_INSTR_DESTINATION_PORT)
      tcp->dst_port = s->post_dp;
    if (s->instructions & UNAT_INSTR_SOURCE_PORT)
      tcp->src_port = s->post_sp;
    l4csum = tcp->checksum;
    l4csum = ip_csum_sub_even(l4csum, s->l4_checksum);
    tcp->checksum = ip_csum_fold(l4csum);

    /*
     * TCP connection tracking
     */
    u32 timer = 0;
    if (s->instructions & UNAT_INSTR_TCP_CONN_TRACK) {
      if (tcp->flags & TCP_FLAG_SYN)
	newstate = UNAT_STATE_TCP_SYN_SEEN;
      else if (tcp->flags & TCP_FLAG_ACK && s->state == UNAT_STATE_TCP_SYN_SEEN)
	newstate = UNAT_STATE_TCP_ESTABLISHED;
      else if (tcp->flags & TCP_FLAG_FIN && s->state == UNAT_STATE_TCP_ESTABLISHED)
	newstate = UNAT_STATE_TCP_FIN_WAIT;
      else if (tcp->flags & TCP_FLAG_ACK && s->state == UNAT_STATE_TCP_FIN_WAIT)
	newstate = UNAT_STATE_TCP_CLOSED;
      else if (tcp->flags & TCP_FLAG_FIN && s->state == UNAT_STATE_TCP_CLOSE_WAIT)
	newstate = UNAT_STATE_TCP_LAST_ACK;
      else if (tcp->flags == 0 && s->state == UNAT_STATE_UNKNOWN)
	newstate = UNAT_STATE_TCP_ESTABLISHED;
      s->state = s->state != newstate ? newstate : s->state;
      if (in2out && newstate != state) {
	if (newstate >= UNAT_STATE_TCP_FIN_WAIT)
	  timer = um->tcp_transitory_timeout;
	else if (newstate == UNAT_STATE_TCP_ESTABLISHED)
	  timer = um->tcp_established_timeout;
	if (timer != session->timer) {
	  session->timer = timer;
	}
      }
    }
  } else if (ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ip4_next_header (ip);
    if (s->instructions & UNAT_INSTR_DESTINATION_PORT)
      udp->dst_port = s->post_dp;
    if (s->instructions & UNAT_INSTR_SOURCE_PORT)
      udp->src_port = s->post_sp;
    if (udp->checksum) {
      l4csum = udp->checksum;
      l4csum = ip_csum_sub_even(l4csum, s->l4_checksum);
      udp->checksum = ip_csum_fold(l4csum);
    }
  }
  /* Falling through for other L4 protocols */

  if (in2out) {
    session->last_heard = now;
    unat_session_update_lru(thread_index, pool_index, session);
  }

  return UNAT_FP_ERROR_NO_ERROR;
}

static u16 nexts[VLIB_FRAME_SIZE] = { 0 };
VLIB_NODE_FN (unat_fp_node) (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame)
{
  unat_main_t *um = &unat_main;
  u32 n_left_from, *from;
  f64 now = vlib_time_now (vm);
  u16 *next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 cache_hit = 0;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_get_buffers(vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0) {
    ip4_header_t *ip0;
    u32 errno0 = 0;
    u32 pool_index0 = ~0;
    ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]));

    u32 sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
    u32 index = um->interface_by_sw_if_index[sw_if_index0];
    unat_interface_t *interface = pool_elt_at_index(um->interfaces, index);

    if (PREDICT_FALSE (ip0->ttl == 1)) {
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = (u32) ~ 0;
      icmp4_error_set_vnet_buffer (b[0], ICMP4_time_exceeded,
				   ICMP4_time_exceeded_ttl_exceeded_in_transit,
				   0);
      next[0] = UNAT_NEXT_ICMP_ERROR;
      goto trace0;
    }

    /*
     * Lookup and do transform in cache, if miss send to slow path node
     */
    u32 out_fib_index0;
    pool_index0 = vnet_buffer (b[0])->unat.pool_index;
    errno0 = execute(interface->in2out, pool_index0, thread_index,
		     ip0, now, &out_fib_index0);
    if (errno0 == 0) {
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = out_fib_index0;
      cache_hit++;
      vnet_feature_next((u32 *)next, b[0]);
      } else {
      next[0] = UNAT_NEXT_DROP;
      b[0]->error = node->errors[errno0];
    }

  trace0:
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
		       && (b[0]->flags & VLIB_BUFFER_IS_TRACED))) {
      unat_trace_t *t =
	vlib_add_trace (vm, node, b[0], sizeof (*t));
      t->in2out = interface->in2out;
      t->sw_if_index = sw_if_index0;
      t->next_index = next[0];
      t->pool_index = pool_index0;
    }

    b += 1;
    next += 1;
    n_left_from -= 1;
  }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_increment_simple_counter (um->counters + UNAT_COUNTER_FASTPATH_FORWARDED, thread_index, 0, cache_hit);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(unat_fp_node) = {
				       //.function = unat,
    .name = "unat-fastpath",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .sibling_of = "unat-handoff",
    .n_errors = UNAT_FP_N_ERROR,
    .error_strings = unat_fp_error_strings,
    .format_trace = format_unat_trace,
};
/* *INDENT-ON* */
