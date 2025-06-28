// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

// Forward an ICMP error packet. Look up the inner embedded packet and forward it via the ICMP error specific service
// chain.

// Calculate inner session key
// Lookup using inner key
// Pass off to ICMP error specific service chain
// Or handoff to different thread

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/lookup/lookup_inlines.h>
#include <vcdp/timer_lru.h>
#include <vcdp/vcdp.api_enum.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u64 hash;
  u32 flow_id;
  u32 error;
  u32 remote_worker;
  bool hit;
  u32 session_idx;
  u32 service_bitmap;
  vcdp_session_key_t k4;
} vcdp_icmp_fwd_trace_t;

typedef struct {
  u32 next_index;
  u32 flow_id;
} vcdp_icmp_handoff_trace_t;

static u8 *
format_vcdp_icmp_handoff_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_icmp_handoff_trace_t *t = va_arg(*args, vcdp_icmp_handoff_trace_t *);

  s = format(s,
             "vcdp-icmp-handoff: next index %d "
             "flow-id %u (session %u, %s)",
             t->next_index, t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

u32
icmp_service_chain(u32 pbmp)
{
  u32 nbmp = 0;
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  for (i = 0; i < vec_len(sm->services); i++) {
    if (pbmp & sm->services[i]->service_mask[0]) {
      if (sm->services[i]->icmp_error) {
        nbmp |= sm->services[i]->icmp_error_mask;
      }
      if (sm->services[i]->is_terminal) {
        nbmp |= sm->services[i]->service_mask[0];
      }
    }
  }
  return nbmp;
}


VCDP_SERVICE_DECLARE(drop);
VCDP_SERVICE_DECLARE(output);
u32 icmp_service_chain(u32 pbmp);

static_always_inline uword
vcdp_icmp_error_fwd_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool is_ip6)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vcdp_session_t *session;
  u32 session_index;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vcdp_session_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  f64 time_now = vlib_time_now(vm);
  bool hits[VLIB_FRAME_SIZE], *hit = hits;
  u32 session_indices[VLIB_FRAME_SIZE], *si = session_indices;
  u32 service_bitmaps[VLIB_FRAME_SIZE], *sb = service_bitmaps;
  int rvs[VLIB_FRAME_SIZE], *rv = rvs;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;

  // Calculate key and hash
  while (n_left) {
    rv[0] = vcdp_calc_key_slow(b[0], vcdp_buffer(b[0])->context_id, k, h, is_ip6);
    h += 1;
    k += 1;
    b += 1;
    rv += 1;
    n_left -= 1;
  }

  h = hashes;
  k = keys;
  b = bufs;
  n_left = frame->n_vectors;
  rv = rvs;

  while (n_left) {
    u32 error = 0;
    b[0]->error = 0;
    u64 value;
    vcdp_log_debug("ICMP %s fwd Looking up: %U (%d)", is_ip6 ? "ip6": "ip4", format_vcdp_session_key, k, rv[0]);
    if ((rv[0] < 0) || vcdp_lookup_with_hash(h[0], k, &value)) {
      // DROP PACKET
      if (b[0]->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED) {
        // Locally originated ICMP errors. Try to bypass and forward
        b[0]->flow_id = ~0; // No session
        sb[0] = 0;
        vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(output);
        vcdp_log_debug("ICMP fwd: locally originated ICMP error, bypassing %U", format_vcdp_session_key, k);
      } else {
        b[0]->flow_id = ~0; // No session
        sb[0] = 0;
        error = VCDP_ICMP_FWD_ERROR_NO_SESSION;
      }
      hit[0] = false;
      goto next;
    }
    hit[0] = true;

    // Figure out if this is local or remote thread
    u32 flow_thread_index = vcdp_thread_index_from_lookup(value);
    if (flow_thread_index == thread_index) {
      /* known flow which belongs to this thread */
      u32 flow_index = value & (~(u32) 0);
      session_index = vcdp_session_from_flow_index(flow_index);
      si[0] = session_index;
      b[0]->flow_id = flow_index;

      session = vcdp_session_at_index(vcdp, session_index);
      if (vcdp_session_is_expired(session, time_now)) {
        // Received a packet against an expired session. Recycle the session.
        vcdp_log_debug("Expired session: %u %U (%.02f)", session_index, format_vcdp_session_key, k,
                     vcdp_session_remaining_time(session, time_now));
        vcdp_session_remove(vcdp, session, thread_index, session_index);
        error = VCDP_ICMP_FWD_ERROR_NO_SESSION;
        goto next;
      }

      //   ICMP chain
      // Calculate the service chain for this packet, based on direction...
      // XXX: u32 nbmp = icmp_service_chain(session->bitmaps[vcdp_direction_from_flow_index(flow_index)]);
      // vcdp_log_debug("ICMP Service Chain: %U", format_vcdp_bitmap, nbmp);
      // vcdp_buffer(b[0])->service_bitmap = sb[0] = nbmp;

      /* The tenant of the buffer is the tenant of the session */
      vcdp_buffer(b[0])->tenant_index = session->tenant_idx;
      session->pkts[vcdp_direction_from_flow_index(flow_index)]++;
      session->bytes[vcdp_direction_from_flow_index(flow_index)] += vlib_buffer_length_in_chain (vm, b[0]);
    } else {
      /* known flow which belongs to remote thread */
      error = VCDP_ICMP_FWD_ERROR_REMOTE;
      goto next;
    }

    b[0]->flow_id = value & (~(u32) 0);

  next:
    if (error) {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_ICMP_FWD_ERROR_NO_SESSION];
    }
    u32 bmp = vcdp_buffer(b[0])->service_bitmap;
    u8 first = __builtin_ffs(bmp);
    if (first == 0) {
      vcdp_log_err("ICMP fwd: no service chain %U", format_vcdp_session_key, k);
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    }
    vcdp_next(b[0], next);

    next++;

    b += 1;
    n_left -= 1;
    h += 1;
    k += 1;
    hit += 1;
    si += 1;
    sb += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    h = hashes;
    si = session_indices;
    hit = hits;
    sb = service_bitmaps;
    next = nexts;

    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_icmp_fwd_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
        t->flow_id = b[0]->flow_id;
        t->hash = h[0];
        t->hit = hit[0];
        t->session_idx = si[0];
        t->service_bitmap = sb[0];
        t->next_index = next[0];
        if (b[0]->error) {
          t->error = b[0]->error;
        } else {
          t->error = 0;
        }
        clib_memcpy(&t->k4, &keys[i], sizeof(t->k4));
        b++;
        h++;
        hit++;
        si++;
        sb++;
        next++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_icmp_fwd_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
   return vcdp_icmp_error_fwd_inline(vm, node, frame, false);
}

VLIB_NODE_FN(vcdp_icmp_fwd_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
   return vcdp_icmp_error_fwd_inline(vm, node, frame, true);
}

/*
 * This node is used to handoff packets to the correct thread.
 */
VLIB_NODE_FN(vcdp_icmp_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  f64 time_now = vlib_time_now(vm);


  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left) {
    u32 flow_index = b[0]->flow_id;
    u32 session_index = vcdp_session_from_flow_index(flow_index);
    vcdp_session_t *session = vcdp_session_at_index_check(vcdp, session_index);
    if (!session) {
      // Session has been deleted underneath us
        vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
        b[0]->error = node->errors[VCDP_HANDOFF_ERROR_NO_SESSION];
        goto next;
    }

    // Check if session has expired. If so send it back to the icmp_fwd node to be created.
    if (vcdp_session_is_expired(session, time_now)) {
      vcdp_log_debug("Forwarding against expired handoff session, deleting and recreating %d", session_index);
      vcdp_session_remove(vcdp, session, thread_index, session_index);
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_HANDOFF_ERROR_NO_SESSION];
      goto next;
    }

    //   ICMP chain
    // Calculate the service chain for this packet, based on direction...
    // u32 nbmp = icmp_service_chain(session->bitmaps[vcdp_direction_from_flow_index(flow_index)]);
    // vcdp_buffer(b[0])->service_bitmap = nbmp;

  next:
    vcdp_next(b[0], current_next);
    current_next += 1;
    b += 1;
    n_left -= 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    current_next = next_indices;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_icmp_handoff_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->next_index = current_next[0];
        b++;
        current_next++;
      } else
        break;
    }
  }

  return frame->n_vectors;
}

/*
 * next_index is ~0 if the packet was enqueued to the remote node
 */
static u8 *
format_vcdp_icmp_fwd_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_icmp_fwd_trace_t *t = va_arg (*args, vcdp_icmp_fwd_trace_t *);
  u32 indent = format_get_indent (s);

  if (t->error)
    s = format(s, "error: %u", t->error);
  else if (t->next_index == ~0)
    s = format(s, "handoff: %u", t->remote_worker);
  else
    if (t->hit)
      s = format(s, "found session, index: %d", t->session_idx);
    else
      s = format(s, "missed session, index: %d", t->session_idx);
  s = format(s, "\n%Unext index: %u, rx ifindex %d, hash 0x%x flow-id %u  key 0x%U",
             format_white_space, indent, t->next_index, t->sw_if_index, t->hash, t->flow_id, format_hex_bytes_no_wrap, (u8 *) &t->k4, sizeof(t->k4));
  // s = format(s, "\n%Uservice chain: %U", format_white_space, indent, format_vcdp_bitmap, t->service_bitmap);
  return s;

}

VLIB_REGISTER_NODE(vcdp_icmp_fwd_ip4_node) = {
  .name = "vcdp-icmp-error-forwarding",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_icmp_fwd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .error_counters = vcdp_icmp_fwd_error_counters,
  .n_errors = VCDP_ICMP_FWD_N_ERROR,
};
VLIB_REGISTER_NODE(vcdp_icmp_fwd_ip6_node) = {
  .name = "vcdp-icmp6-error-forwarding",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_icmp_fwd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .error_counters = vcdp_icmp_fwd_error_counters,
  .n_errors = VCDP_ICMP_FWD_N_ERROR,
};

VCDP_SERVICE_DEFINE(icmp_error_fwd) = {
  .node_name = "vcdp-icmp-error-forwarding",
  .runs_before = VCDP_SERVICES("vcdp-drop"),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};
VCDP_SERVICE_DEFINE(icmp6_error_fwd) = {
  .node_name = "vcdp-icmp6-error-forwarding",
  .runs_before = VCDP_SERVICES("vcdp-drop"),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};

VLIB_REGISTER_NODE(vcdp_icmp_handoff_node) = {
  .name = "vcdp-icmp-handoff",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_icmp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};
