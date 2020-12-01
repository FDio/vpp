#include <plugins/acl/dataplane_common.h>

always_inline void
prefetch_session_entry (acl_main_t * am, fa_full_session_id_t f_sess_id)
{
  fa_session_t *sess = get_session_ptr_no_check (am, f_sess_id.thread_index,
                                                 f_sess_id.session_index);
  CLIB_PREFETCH (sess, 2 * CLIB_CACHE_LINE_BYTES, STORE);
}


always_inline uword
acl_fa_inner_check_sessions_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node, vlib_frame_t * frame,
			  const int is_ip6, const int is_input,
			  const int is_l2_path,
			  const int with_stateful_datapath,
			  const int node_trace_on,
			  const int reclassify_sessions)
{
  u32 n_left;
  u32 pkts_exist_session = 0;
  acl_main_t *am = &acl_main;
  vlib_node_runtime_t *error_node;
  vlib_error_t no_error_existing_session;
  vlib_error_t error_unknown;
  u64 now = clib_cpu_time_now ();
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

  error_node = vlib_node_get_runtime (vm, node->node_index);
  no_error_existing_session =
    error_node->errors[ACL_FA_ERROR_ACL_EXIST_SESSION];
  error_unknown = error_node->errors[ACL_FA_ERROR_ACL_UNKNOWN];

  b = pw->bufs;
  next = pw->nexts;
  sw_if_index = pw->sw_if_indices;
  fa_5tuple = pw->fa_5tuples;
  hash = pw->hashes;
  action = pw->actions;
  match_policy_prio = pw->match_policy_prios;
  if (node_trace_on)
    trace_bitmap = pw->trace_bitmaps;

  /*
   * Now the "hard" work of session lookups and ACL lookups for new sessions.
   * Due to the complexity, do it for the time being in single loop with
   * the pipeline of three prefetches:
   *    1) bucket for the session bihash
   *    2) data for the session bihash
   *    3) worker session record
   */

  fa_full_session_id_t f_sess_id_next = {.as_u64 = ~0ULL };

  /* find the "next" session so we can kickstart the pipeline */
  if (with_stateful_datapath)
    acl_fa_find_session_with_hash (am, is_ip6, sw_if_index[0], hash[0],
				   &fa_5tuple[0], &f_sess_id_next.as_u64);

  n_left = frame->n_vectors;
  while (n_left > 0)
    {
      next[0] = 0;		/* drop by default */
      if (node_trace_on)
	trace_bitmap[0] = 0;	/* empty trace */
      b[0]->error = error_unknown;	/* set the error to unknown by default */
      match_policy_prio[0] = 0;

      /* Try to match an existing session first */

      if (with_stateful_datapath)
	{
	  fa_full_session_id_t f_sess_id = f_sess_id_next;
	  switch (n_left)
	    {
	    default:
	      acl_fa_prefetch_session_bucket_for_hash (am, is_ip6, hash[5]);
	      /* fallthrough */
	    case 5:
	    case 4:
	      acl_fa_prefetch_session_data_for_hash (am, is_ip6, hash[3]);
	      /* fallthrough */
	    case 3:
	    case 2:
	      acl_fa_find_session_with_hash (am, is_ip6, sw_if_index[1],
					     hash[1], &fa_5tuple[1],
					     &f_sess_id_next.as_u64);
	      if (f_sess_id_next.as_u64 != ~0ULL)
		{
		  if (node_trace_on)
		    trace_bitmap[0] |= ACL_TRACE_PREFETCH_NEXT_SESSION;
		  prefetch_session_entry (am, f_sess_id_next);
		}
	      /* fallthrough */
	    case 1:
	      if (node_trace_on)
		trace_bitmap[0] |= ACL_TRACE_SESSION_CHECK;
	      if (f_sess_id.as_u64 != ~0ULL)
		{
		  if (node_trace_on)
		    {
		      trace_bitmap[0] |= ACL_TRACE_EXISTING_SESSION;
		    }
		  ASSERT (f_sess_id.thread_index < vec_len (vlib_mains));
		  b[0]->error = no_error_existing_session;
		  match_policy_prio[0] = PP_EXISTING_SESSION;
		  pkts_exist_session += 1;
		  action[0] =
		    process_established_session (vm, am, node->node_index,
						 is_input, now, f_sess_id,
						 &sw_if_index[0],
						 &fa_5tuple[0],
						 b[0]->current_length,
						 node_trace_on,
						 &trace_bitmap[0]);

		  /* expose the session id to the tracer */
		  if (node_trace_on)
		    {
		      u32 bi = b - pw->bufs;
		      ALWAYS_ASSERT (bi < VLIB_FRAME_SIZE);
		      pw->match_rule_indices[bi] = f_sess_id.session_index;
		      pw->match_acl_indices[bi] = f_sess_id.thread_index;
		    }

		  if (reclassify_sessions)
		    {
		      if (PREDICT_FALSE
			  (stale_session_deleted
			   (am, is_input, pw, now, sw_if_index[0],
			    f_sess_id)))
			{
			  match_policy_prio[0] = 0;
			  if (node_trace_on)
			    {
			      trace_bitmap[0] |= ACL_TRACE_STALE_SESSION;
			    }
			  /*
			   * If we have just deleted the session, and the next
			   * buffer is the same 5-tuple, that session prediction
			   * is wrong, correct it.
			   */
			  if ((f_sess_id_next.as_u64 != ~0ULL)
			      && 0 == memcmp (&fa_5tuple[1], &fa_5tuple[0],
					      sizeof (fa_5tuple[1])))
			    f_sess_id_next.as_u64 = ~0ULL;
			}
		    }
		}
	    }
	}
      /* FIXME here: inc/dec current pointers */
      next++;
      b++;
      fa_5tuple++;
      sw_if_index++;
      hash++;
      action++;
      match_policy_prio++;
      n_left -= 1;
      if (node_trace_on)
	trace_bitmap++;
    }
  return 0;			// FIXME
}

void
CLIB_MULTIARCH_FN(acl_fa_check_sessions_fn) (vlib_main_t * vm,
                          vlib_node_runtime_t * node, vlib_frame_t * frame,
			  const u8 variant) 
{

acl_fa_inner_check_sessions_fn(vm, node, frame,
		(variant & (1 << ACLP_DP_IS_IP6)) != 0,
		(variant & (1 << ACLP_DP_IS_INPUT)) != 0,
		(variant & (1 << ACLP_DP_IS_L2_PATH)) != 0,
		(variant & (1 << ACLP_DP_WITH_STATEFUL_DP)) != 0,
		(variant & (1 << ACLP_DP_NODE_TRACE_ON)) != 0,
		(variant & (1 << ACLP_DP_RECLASSIFY_SESSIONS)) != 0);

}


