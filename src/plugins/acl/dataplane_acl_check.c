#include <plugins/acl/dataplane_common.h>

always_inline uword
acl_fa_inner_acl_check_fn (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame,
			   const int is_ip6, const int is_input,
			   const int is_l2_path,
			   const int with_stateful_datapath,
			   const int node_trace_on,
			   const int reclassify_sessions)
{
  u32 n_left;
  acl_main_t *am = &acl_main;
  vlib_node_runtime_t *error_node;
  vlib_error_t no_error_existing_session;
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  u16 *next;
  vlib_buffer_t **b;
  u32 *sw_if_index;
  fa_5tuple_t *fa_5tuple;
  u64 *hash;
  u8 *action;
  u8 *match_policy_prio;
  u32 *trace_bitmap;

  /* for the delayed counters */
  u32 saved_matched_acl_index = 0;
  u32 saved_matched_ace_index = 0;
  u32 saved_packet_count = 0;
  u32 saved_byte_count = 0;

  error_node = vlib_node_get_runtime (vm, node->node_index);
  no_error_existing_session =
    error_node->errors[ACL_FA_ERROR_ACL_EXIST_SESSION];

  b = pw->bufs;
  next = pw->nexts;
  sw_if_index = pw->sw_if_indices;
  fa_5tuple = pw->fa_5tuples;
  hash = pw->hashes;
  action = pw->actions;
  match_policy_prio = pw->match_policy_prios;
  trace_bitmap = pw->trace_bitmaps;

  n_left = frame->n_vectors;
  while (n_left > 0)
    {
      u32 lc_index0 = ~0;
      u32 match_acl_index = ~0;
      u32 match_acl_pos = ~0;
      u32 match_rule_index = ~0;

      next[0] = 0;		/* drop by default */


      if (match_policy_prio[0] < PP_EXISTING_SESSION)
	{
	  if (is_input)
	    lc_index0 = am->input_lc_index_by_sw_if_index[sw_if_index[0]];
	  else
	    lc_index0 = am->output_lc_index_by_sw_if_index[sw_if_index[0]];

	  int is_match = acl_plugin_match_5tuple_inline (am, lc_index0,
							 (fa_5tuple_opaque_t
							  *) & fa_5tuple[0],
							 is_ip6,
							 &action[0],
							 &match_acl_pos,
							 &match_acl_index,
							 &match_rule_index,
							 &trace_bitmap[0]);
	  if (is_match)
	    {
	      match_policy_prio[0] = PP_LINEAR_ACL_CHECK;

	      /* expose which ACL# and rule index within the ACL matched */
	      if (node_trace_on)
		{
		  u32 bi = b - pw->bufs;
		  ALWAYS_ASSERT (bi < VLIB_FRAME_SIZE);
		  pw->match_rule_indices[bi] = match_acl_index;
		  pw->match_acl_indices[bi] = match_rule_index;
		}
	    }

	  if (PREDICT_FALSE (is_match && am->interface_acl_counters_enabled))
	    {
	      u32 buf_len = vlib_buffer_length_in_chain (vm, b[0]);
	      vlib_increment_combined_counter (am->combined_acl_counters +
					       saved_matched_acl_index,
					       thread_index,
					       saved_matched_ace_index,
					       saved_packet_count,
					       saved_byte_count);
	      saved_matched_acl_index = match_acl_index;
	      saved_matched_ace_index = match_rule_index;
	      saved_packet_count = 1;
	      saved_byte_count = buf_len;
	      /* prefetch the counter that we are going to increment */
	      vlib_prefetch_combined_counter (am->combined_acl_counters +
					      saved_matched_acl_index,
					      thread_index,
					      saved_matched_ace_index);
	    }

	  b[0]->error = error_node->errors[action[0]];
	}
      /* FIXME here: inc/dec pointers */
      next++;
      b++;
      fa_5tuple++;
      sw_if_index++;
      hash++;
      action++;
      match_policy_prio++;
      n_left -= 1;
      trace_bitmap++;
    }
  /*
   * if we were had an acl match then we have a counter to increment.
   * else it is all zeroes, so this will be harmless.
   */
  vlib_increment_combined_counter (am->combined_acl_counters +
				   saved_matched_acl_index,
				   thread_index,
				   saved_matched_ace_index,
				   saved_packet_count, saved_byte_count);
  return 0;
}


always_inline void
acl_fa_outer_acl_check_fn (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame,
			   const u8 variant)
{
  acl_fa_inner_acl_check_fn (vm, node, frame,
			     (variant & (1 << ACLP_DP_IS_IP6)) != 0,
			     (variant & (1 << ACLP_DP_IS_INPUT)) != 0,
			     (variant & (1 << ACLP_DP_IS_L2_PATH)) != 0,
			     (variant & (1 << ACLP_DP_WITH_STATEFUL_DP)) != 0,
			     (variant & (1 << ACLP_DP_NODE_TRACE_ON)) != 0,
			     (variant & (1 << ACLP_DP_RECLASSIFY_SESSIONS)) !=
			     0);
}

void
CLIB_MULTIARCH_FN (acl_fa_acl_check_fn) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame,
					 const u8 variant)
{
  acl_fa_outer_acl_check_fn (vm, node, frame, variant);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
