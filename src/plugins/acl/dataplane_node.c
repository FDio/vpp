/*
 * Copyright (c) 2016-2018 Cisco and/or its affiliates.
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
#include <stddef.h>
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>


#include <acl/acl.h>
#include <vnet/ip/icmp46_packet.h>

#include <plugins/acl/fa_node.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/lookup_context.h>
#include <plugins/acl/public_inlines.h>
#include <plugins/acl/session_inlines.h>

#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 lc_index;
  u32 match_acl_in_index;
  u32 match_rule_index;
  u64 packet_info[6];
  u32 trace_bitmap;
  u8 action;
} acl_fa_trace_t;

/* *INDENT-OFF* */
#define foreach_acl_fa_error \
_(ACL_DROP, "ACL deny packets")  \
_(ACL_PERMIT, "ACL permit packets")  \
_(ACL_NEW_SESSION, "new sessions added") \
_(ACL_EXIST_SESSION, "existing session packets") \
_(ACL_CHECK, "checked packets") \
_(ACL_RESTART_SESSION_TIMER, "restart session timer") \
_(ACL_TOO_MANY_SESSIONS, "too many sessions to add new") \
/* end  of errors */

typedef enum
{
#define _(sym,str) ACL_FA_ERROR_##sym,
  foreach_acl_fa_error
#undef _
    ACL_FA_N_ERROR,
} acl_fa_error_t;

/* *INDENT-ON* */

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u16 ethertype;
} nonip_in_out_trace_t;

/* packet trace format function */
static u8 *
format_nonip_in_out_trace (u8 * s, u32 is_output, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nonip_in_out_trace_t *t = va_arg (*args, nonip_in_out_trace_t *);

  s = format (s, "%s: sw_if_index %d next_index %x ethertype %x",
	      is_output ? "OUT-ETHER-WHITELIST" : "IN-ETHER-WHITELIST",
	      t->sw_if_index, t->next_index, t->ethertype);
  return s;
}

static u8 *
format_l2_nonip_in_trace (u8 * s, va_list * args)
{
  return format_nonip_in_out_trace (s, 0, args);
}

static u8 *
format_l2_nonip_out_trace (u8 * s, va_list * args)
{
  return format_nonip_in_out_trace (s, 1, args);
}

#define foreach_nonip_in_error                    \
_(DROP, "dropped inbound non-whitelisted non-ip packets") \
_(PERMIT, "permitted inbound whitelisted non-ip packets") \


#define foreach_nonip_out_error                    \
_(DROP, "dropped outbound non-whitelisted non-ip packets") \
_(PERMIT, "permitted outbound whitelisted non-ip packets") \


/* *INDENT-OFF* */

typedef enum
{
#define _(sym,str) FA_IN_NONIP_ERROR_##sym,
  foreach_nonip_in_error
#undef _
    FA_IN_NONIP_N_ERROR,
} l2_in_feat_arc_error_t;

static char *fa_in_nonip_error_strings[] = {
#define _(sym,string) string,
  foreach_nonip_in_error
#undef _
};

typedef enum
{
#define _(sym,str) FA_OUT_NONIP_ERROR_##sym,
  foreach_nonip_out_error
#undef _
    FA_OUT_NONIP_N_ERROR,
} l2_out_feat_arc_error_t;

static char *fa_out_nonip_error_strings[] = {
#define _(sym,string) string,
  foreach_nonip_out_error
#undef _
};
/* *INDENT-ON* */


always_inline int
is_permitted_ethertype (acl_main_t * am, int sw_if_index0, int is_output,
			u16 ethertype)
{
  u16 **v = is_output
    ? am->output_etype_whitelist_by_sw_if_index
    : am->input_etype_whitelist_by_sw_if_index;
  u16 *whitelist = vec_elt (v, sw_if_index0);
  int i;

  if (vec_len (whitelist) == 0)
    return 1;

  for (i = 0; i < vec_len (whitelist); i++)
    if (whitelist[i] == ethertype)
      return 1;
  return 0;
}

#define get_u16(addr) ( *((u16 *)(addr)) )

always_inline uword
nonip_in_out_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame,
		      int is_output)
{
  acl_main_t *am = &acl_main;
  u32 n_left, *from;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_node_runtime_t *error_node;

  from = vlib_frame_vector_args (frame);
  error_node = vlib_node_get_runtime (vm, node->node_index);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  /* set the initial values for the current buffer the next pointers */
  b = bufs;
  next = nexts;

  n_left = frame->n_vectors;
  while (n_left > 0)
    {
      u32 next_index = 0;
      u32 sw_if_index0 =
	vnet_buffer (b[0])->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
      u16 ethertype = 0;

      int error0 = 0;

      ethernet_header_t *h0 = vlib_buffer_get_current (b[0]);
      u8 *l3h0 = (u8 *) h0 + vnet_buffer (b[0])->l2.l2_len;
      ethertype = clib_net_to_host_u16 (get_u16 (l3h0 - 2));

      if (is_permitted_ethertype (am, sw_if_index0, is_output, ethertype))
	vnet_feature_next (&next_index, b[0]);

      next[0] = next_index;

      if (0 == next[0])
	b[0]->error = error_node->errors[error0];

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nonip_in_out_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->ethertype = ethertype;
	  t->next_index = next[0];
	}
      next[0] = next[0] < node->n_next_nodes ? next[0] : 0;

      next++;
      b++;
      n_left--;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (acl_in_nonip_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return nonip_in_out_node_fn (vm, node, frame, 0);
}

VLIB_NODE_FN (acl_out_nonip_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return nonip_in_out_node_fn (vm, node, frame, 1);
}


/* *INDENT-OFF* */

VLIB_REGISTER_NODE (acl_in_nonip_node) =
{
  .name = "acl-plugin-in-nonip-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_nonip_in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (fa_in_nonip_error_strings),
  .error_strings = fa_in_nonip_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_l2_nonip_fa_feature, static) =
{
  .arc_name = "l2-input-nonip",
  .node_name = "acl-plugin-in-nonip-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_out_nonip_node) =
{
  .name = "acl-plugin-out-nonip-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_nonip_out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (fa_out_nonip_error_strings),
  .error_strings = fa_out_nonip_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_l2_nonip_fa_feature, static) =
{
  .arc_name = "l2-output-nonip",
  .node_name = "acl-plugin-out-nonip-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};

/* *INDENT-ON* */



always_inline u16
get_current_policy_epoch (acl_main_t * am, int is_input, u32 sw_if_index0)
{
  u32 **p_epoch_vec =
    is_input ? &am->input_policy_epoch_by_sw_if_index :
    &am->output_policy_epoch_by_sw_if_index;
  u16 current_policy_epoch =
    sw_if_index0 < vec_len (*p_epoch_vec) ? vec_elt (*p_epoch_vec,
						     sw_if_index0)
    : (is_input * FA_POLICY_EPOCH_IS_INPUT);
  return current_policy_epoch;
}

always_inline uword
acl_fa_node_fn (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame, int is_ip6,
		int is_input, int is_l2_path)
{
  u32 n_left, *from;
  u32 pkts_acl_checked = 0;
  u32 pkts_new_session = 0;
  u32 pkts_exist_session = 0;
  u32 pkts_acl_permit = 0;
  u32 pkts_restart_session_timer = 0;
  u32 trace_bitmap = 0;
  acl_main_t *am = &acl_main;
  fa_5tuple_t fa_5tuple;
  vlib_node_runtime_t *error_node;
  u64 now = clib_cpu_time_now ();
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;

  from = vlib_frame_vector_args (frame);

  error_node = vlib_node_get_runtime (vm, node->node_index);

  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  /* set the initial values for the current buffer the next pointers */
  b = bufs;
  next = nexts;

  n_left = frame->n_vectors;
  while (n_left > 0)
    {
      u32 next0 = 0;
      u8 action = 0;
      u32 sw_if_index0;
      u32 lc_index0 = ~0;
      int acl_check_needed = 1;
      u32 match_acl_in_index = ~0;
      u32 match_acl_pos = ~0;
      u32 match_rule_index = ~0;
      u8 error0 = 0;

      n_left -= 1;

      if (is_input)
	sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      else
	sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];

      if (is_input)
	lc_index0 = am->input_lc_index_by_sw_if_index[sw_if_index0];
      else
	lc_index0 = am->output_lc_index_by_sw_if_index[sw_if_index0];

      u16 current_policy_epoch =
	get_current_policy_epoch (am, is_input, sw_if_index0);


      /*
       * Extract the L3/L4 matching info into a 5-tuple structure.
       */

      acl_fill_5tuple (&acl_main, sw_if_index0, b[0], is_ip6,
		       is_input, is_l2_path, &fa_5tuple);

#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning
	("ACL_FA_NODE_DBG: packet 5-tuple %016llx %016llx %016llx %016llx %016llx %016llx",
	 fa_5tuple.kv.key[0], fa_5tuple.kv.key[1], fa_5tuple.kv.key[2],
	 fa_5tuple.kv.key[3], fa_5tuple.kv.key[4], fa_5tuple.kv.value);
#endif

      /* Try to match an existing session first */

      if (acl_fa_ifc_has_sessions (am, sw_if_index0))
	{
	  u64 value_sess = ~0ULL;
	  if (acl_fa_find_session
	      (am, is_ip6, sw_if_index0, &fa_5tuple, &value_sess)
	      && (value_sess != ~0ULL))
	    {
	      trace_bitmap |= 0x80000000;
	      error0 = ACL_FA_ERROR_ACL_EXIST_SESSION;
	      fa_full_session_id_t f_sess_id;

	      f_sess_id.as_u64 = value_sess;
	      ASSERT (f_sess_id.thread_index < vec_len (vlib_mains));

	      fa_session_t *sess =
		get_session_ptr (am, f_sess_id.thread_index,
				 f_sess_id.session_index);
	      int old_timeout_type = fa_session_get_timeout_type (am, sess);
	      action =
		acl_fa_track_session (am, is_input, sw_if_index0, now,
				      sess, &fa_5tuple);
	      /* expose the session id to the tracer */
	      match_rule_index = f_sess_id.session_index;
	      int new_timeout_type = fa_session_get_timeout_type (am, sess);
	      acl_check_needed = 0;
	      pkts_exist_session += 1;
	      /* Tracking might have changed the session timeout type, e.g. from transient to established */
	      if (PREDICT_FALSE (old_timeout_type != new_timeout_type))
		{
		  acl_fa_restart_timer_for_session (am, now, f_sess_id);
		  pkts_restart_session_timer++;
		  trace_bitmap |=
		    0x00010000 + ((0xff & old_timeout_type) << 8) +
		    (0xff & new_timeout_type);
		}
	      /*
	       * I estimate the likelihood to be very low - the VPP needs
	       * to have >64K interfaces to start with and then on
	       * exactly 64K indices apart needs to be exactly the same
	       * 5-tuple... Anyway, since this probability is nonzero -
	       * print an error and drop the unlucky packet.
	       * If this shows up in real world, we would need to bump
	       * the hash key length.
	       */
	      if (PREDICT_FALSE (sess->sw_if_index != sw_if_index0))
		{
		  clib_warning
		    ("BUG: session LSB16(sw_if_index) and 5-tuple collision!");
		  acl_check_needed = 0;
		  action = 0;
		}
	      if (PREDICT_FALSE (am->reclassify_sessions))
		{
		  /* if the MSB of policy epoch matches but not the LSB means it is a stale session */
		  if ((0 ==
		       ((current_policy_epoch ^
			 f_sess_id.intf_policy_epoch) &
			FA_POLICY_EPOCH_IS_INPUT))
		      && (current_policy_epoch !=
			  f_sess_id.intf_policy_epoch))
		    {
		      /* delete session and increment the counter */
		      vec_validate
			(pw->fa_session_epoch_change_by_sw_if_index,
			 sw_if_index0);
		      vec_elt (pw->fa_session_epoch_change_by_sw_if_index,
			       sw_if_index0)++;
		      if (acl_fa_conn_list_delete_session
			  (am, f_sess_id, now))
			{
			  /* delete the session only if we were able to unlink it */
			  acl_fa_two_stage_delete_session (am, sw_if_index0,
							   f_sess_id, now);
			}
		      acl_check_needed = 1;
		      trace_bitmap |= 0x40000000;
		    }
		}
	    }
	}

      if (acl_check_needed)
	{
	  action = 0;		/* deny by default */
	  acl_plugin_match_5tuple_inline (&acl_main, lc_index0,
					  (fa_5tuple_opaque_t *) &
					  fa_5tuple, is_ip6, &action,
					  &match_acl_pos,
					  &match_acl_in_index,
					  &match_rule_index, &trace_bitmap);
	  error0 = action;
	  if (1 == action)
	    pkts_acl_permit += 1;
	  if (2 == action)
	    {
	      if (!acl_fa_can_add_session (am, is_input, sw_if_index0))
		acl_fa_try_recycle_session (am, is_input, thread_index,
					    sw_if_index0, now);

	      if (acl_fa_can_add_session (am, is_input, sw_if_index0))
		{
		  fa_session_t *sess =
		    acl_fa_add_session (am, is_input, is_ip6,
					sw_if_index0,
					now, &fa_5tuple,
					current_policy_epoch);
		  acl_fa_track_session (am, is_input, sw_if_index0,
					now, sess, &fa_5tuple);
		  pkts_new_session += 1;
		}
	      else
		{
		  action = 0;
		  error0 = ACL_FA_ERROR_ACL_TOO_MANY_SESSIONS;
		}
	    }
	}



      if (action > 0)
	{
	  vnet_feature_next (&next0, b[0]);
	}
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning
	("ACL_FA_NODE_DBG: sw_if_index %d lc_index %d action %d acl_index %d rule_index %d",
	 sw_if_index0, lc_index0, action, match_acl_in_index,
	 match_rule_index);
#endif

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  acl_fa_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->lc_index = lc_index0;
	  t->next_index = next0;
	  t->match_acl_in_index = match_acl_in_index;
	  t->match_rule_index = match_rule_index;
	  t->packet_info[0] = fa_5tuple.kv_40_8.key[0];
	  t->packet_info[1] = fa_5tuple.kv_40_8.key[1];
	  t->packet_info[2] = fa_5tuple.kv_40_8.key[2];
	  t->packet_info[3] = fa_5tuple.kv_40_8.key[3];
	  t->packet_info[4] = fa_5tuple.kv_40_8.key[4];
	  t->packet_info[5] = fa_5tuple.kv_40_8.value;
	  t->action = action;
	  t->trace_bitmap = trace_bitmap;
	}

      next0 = next0 < node->n_next_nodes ? next0 : 0;
      if (0 == next0)
	b[0]->error = error_node->errors[error0];
      next[0] = next0;

      next++;
      b++;
      pkts_acl_checked += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_CHECK, pkts_acl_checked);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_PERMIT, pkts_acl_permit);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_NEW_SESSION,
			       pkts_new_session);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_EXIST_SESSION,
			       pkts_exist_session);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_RESTART_SESSION_TIMER,
			       pkts_restart_session_timer);
  return frame->n_vectors;
}

VLIB_NODE_FN (acl_in_l2_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 1, 1);
}

VLIB_NODE_FN (acl_in_l2_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 1, 1);
}

VLIB_NODE_FN (acl_out_l2_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 0, 1);
}

VLIB_NODE_FN (acl_out_l2_ip4_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 0, 1);
}

/**** L3 processing path nodes ****/

VLIB_NODE_FN (acl_in_fa_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 1, 0);
}

VLIB_NODE_FN (acl_in_fa_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 1, 0);
}

VLIB_NODE_FN (acl_out_fa_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 0, 0);
}

VLIB_NODE_FN (acl_out_fa_ip4_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 0, 0);
}

static u8 *
format_fa_5tuple (u8 * s, va_list * args)
{
  fa_5tuple_t *p5t = va_arg (*args, fa_5tuple_t *);
  void *paddr0;
  void *paddr1;
  void *format_address_func;
  void *ip_af;
  void *ip_frag_txt =
    p5t->pkt.is_nonfirst_fragment ? " non-initial fragment" : "";

  if (p5t->pkt.is_ip6)
    {
      ip_af = "ip6";
      format_address_func = format_ip6_address;
      paddr0 = &p5t->ip6_addr[0];
      paddr1 = &p5t->ip6_addr[1];
    }
  else
    {
      ip_af = "ip4";
      format_address_func = format_ip4_address;
      paddr0 = &p5t->ip4_addr[0];
      paddr1 = &p5t->ip4_addr[1];
    }

  s =
    format (s, "lc_index %d l3 %s%s ", p5t->pkt.lc_index, ip_af, ip_frag_txt);
  s =
    format (s, "%U -> %U ", format_address_func, paddr0, format_address_func,
	    paddr1);
  s = format (s, "%U ", format_fa_session_l4_key, &p5t->l4);
  s = format (s, "tcp flags (%s) %02x rsvd %x",
	      p5t->pkt.tcp_flags_valid ? "valid" : "invalid",
	      p5t->pkt.tcp_flags, p5t->pkt.flags_reserved);
  return s;
}

#ifndef CLIB_MARCH_VARIANT
u8 *
format_acl_plugin_5tuple (u8 * s, va_list * args)
{
  return format_fa_5tuple (s, args);
}
#endif

/* packet trace format function */
static u8 *
format_acl_plugin_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  acl_fa_trace_t *t = va_arg (*args, acl_fa_trace_t *);

  s =
    format (s,
	    "acl-plugin: lc_index: %d, sw_if_index %d, next index %d, action: %d, match: acl %d rule %d trace_bits %08x\n"
	    "  pkt info %016llx %016llx %016llx %016llx %016llx %016llx",
	    t->lc_index, t->sw_if_index, t->next_index, t->action,
	    t->match_acl_in_index, t->match_rule_index, t->trace_bitmap,
	    t->packet_info[0], t->packet_info[1], t->packet_info[2],
	    t->packet_info[3], t->packet_info[4], t->packet_info[5]);

  /* Now also print out the packet_info in a form usable by humans */
  s = format (s, "\n   %U", format_fa_5tuple, t->packet_info);
  return s;
}

/* *INDENT-OFF* */

static char *acl_fa_error_strings[] = {
#define _(sym,string) string,
  foreach_acl_fa_error
#undef _
};

VLIB_REGISTER_NODE (acl_in_l2_ip6_node) =
{
  .name = "acl-plugin-in-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_l2_ip6_fa_feature, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "acl-plugin-in-ip6-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_in_l2_ip4_node) =
{
  .name = "acl-plugin-in-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_l2_ip4_fa_feature, static) =
{
  .arc_name = "l2-input-ip4",
  .node_name = "acl-plugin-in-ip4-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};


VLIB_REGISTER_NODE (acl_out_l2_ip6_node) =
{
  .name = "acl-plugin-out-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_l2_ip6_fa_feature, static) =
{
  .arc_name = "l2-output-ip6",
  .node_name = "acl-plugin-out-ip6-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};


VLIB_REGISTER_NODE (acl_out_l2_ip4_node) =
{
  .name = "acl-plugin-out-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_l2_ip4_fa_feature, static) =
{
  .arc_name = "l2-output-ip4",
  .node_name = "acl-plugin-out-ip4-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};


VLIB_REGISTER_NODE (acl_in_fa_ip6_node) =
{
  .name = "acl-plugin-in-ip6-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_ip6_fa_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "acl-plugin-in-ip6-fa",
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
};

VLIB_REGISTER_NODE (acl_in_fa_ip4_node) =
{
  .name = "acl-plugin-in-ip4-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_ip4_fa_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "acl-plugin-in-ip4-fa",
  .runs_before = VNET_FEATURES ("ip4-flow-classify"),
};


VLIB_REGISTER_NODE (acl_out_fa_ip6_node) =
{
  .name = "acl-plugin-out-ip6-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_ip6_fa_feature, static) =
{
  .arc_name = "ip6-output",
  .node_name = "acl-plugin-out-ip6-fa",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VLIB_REGISTER_NODE (acl_out_fa_ip4_node) =
{
  .name = "acl-plugin-out-ip4-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
    /* edit / add dispositions here */
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_ip4_fa_feature, static) =
{
  .arc_name = "ip4-output",
  .node_name = "acl-plugin-out-ip4-fa",
  .runs_before = VNET_FEATURES ("interface-output"),
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
