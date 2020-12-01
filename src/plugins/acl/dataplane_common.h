#ifndef ACL_PLUGIN_DATAPLANE_INCLUDED
#define ACL_PLUGIN_DATAPLANE_INCLUDED

#include <stddef.h>
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
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
  u32 match_acl_index;
  u32 match_rule_index;
  u64 packet_info[6];
  u32 trace_bitmap;
  u8 action;
  u8 policy;
  u64 hash;
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
_(ACL_UNKNOWN, "unknown error") \
/* end  of errors */

typedef enum
{
#define _(sym,str) ACL_FA_ERROR_##sym,
  foreach_acl_fa_error
#undef _
    ACL_FA_N_ERROR,
} acl_fa_error_t;

#define ACL_TRACE_EXISTING_SESSION      0x80000000
#define ACL_TRACE_STALE_SESSION         0x40000000
#define ACL_TRACE_SESSION_CHECK         0x08000000
#define ACL_TRACE_ACL_CHECK             0x04000000
#define ACL_TRACE_PREFETCH_NEXT_SESSION 0x02000000




enum {
   ACLP_DP_IS_IP6 = 0,
   ACLP_DP_IS_INPUT,
   ACLP_DP_IS_L2_PATH,
   ACLP_DP_WITH_STATEFUL_DP,
   ACLP_DP_NODE_TRACE_ON,
   ACLP_DP_RECLASSIFY_SESSIONS
};



#define ACL_TRACE_EXISTING_SESSION      0x80000000
#define ACL_TRACE_STALE_SESSION         0x40000000
#define ACL_TRACE_SESSION_CHECK         0x08000000
#define ACL_TRACE_ACL_CHECK             0x04000000
#define ACL_TRACE_PREFETCH_NEXT_SESSION 0x02000000


#define PP_EXISTING_SESSION 0x80
#define PP_LINEAR_ACL_CHECK 0x40





always_inline u8
process_established_session (vlib_main_t * vm, acl_main_t * am,
			     u32 counter_node_index, int is_input, u64 now,
			     fa_full_session_id_t f_sess_id,
			     u32 * sw_if_index, fa_5tuple_t * fa_5tuple,
			     u32 pkt_len, int node_trace_on,
			     u32 * trace_bitmap)
{
  u8 action = 0;
  fa_session_t *sess = get_session_ptr_no_check (am, f_sess_id.thread_index,
						 f_sess_id.session_index);

  int old_timeout_type = fa_session_get_timeout_type (am, sess);
  action =
    acl_fa_track_session (am, is_input, sw_if_index[0], now,
			  sess, &fa_5tuple[0], pkt_len);
  int new_timeout_type = fa_session_get_timeout_type (am, sess);
  /* Tracking might have changed the session timeout type, e.g. from transient to established */
  if (PREDICT_FALSE (old_timeout_type != new_timeout_type))
    {
      acl_fa_restart_timer_for_session (am, now, f_sess_id);
      vlib_node_increment_counter (vm, counter_node_index,
				   ACL_FA_ERROR_ACL_RESTART_SESSION_TIMER, 1);
      if (node_trace_on)
	*trace_bitmap |=
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
  if (PREDICT_FALSE (sess->sw_if_index != sw_if_index[0]))
    {
      clib_warning
	("BUG: session LSB16(sw_if_index)=%d and 5-tuple=%d collision!",
	 sess->sw_if_index, sw_if_index[0]);
      action = 0;
    }
  return action;

}


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



always_inline int
stale_session_deleted (acl_main_t * am, int is_input,
		       acl_fa_per_worker_data_t * pw, u64 now,
		       u32 sw_if_index0, fa_full_session_id_t f_sess_id)
{
  u16 current_policy_epoch =
    get_current_policy_epoch (am, is_input, sw_if_index0);

  /* if the MSB of policy epoch matches but not the LSB means it is a stale session */
  if ((0 ==
       ((current_policy_epoch ^
	 f_sess_id.intf_policy_epoch) &
	FA_POLICY_EPOCH_IS_INPUT))
      && (current_policy_epoch != f_sess_id.intf_policy_epoch))
    {
      /* delete session and increment the counter */
      vec_validate (pw->fa_session_epoch_change_by_sw_if_index, sw_if_index0);
      vec_elt (pw->fa_session_epoch_change_by_sw_if_index, sw_if_index0)++;
      if (acl_fa_conn_list_delete_session (am, f_sess_id, now))
	{
	  /* delete the session only if we were able to unlink it */
	  acl_fa_two_stage_delete_session (am, sw_if_index0, f_sess_id, now);
	}
      return 1;
    }
  else
    return 0;
}




void
CLIB_MULTIARCH_FN(acl_fa_check_sessions_fn) (vlib_main_t * vm,
                          vlib_node_runtime_t * node, vlib_frame_t * frame,
                          const u8 variant);
void
CLIB_MULTIARCH_FN(acl_fa_acl_check_fn) (vlib_main_t * vm,
                          vlib_node_runtime_t * node, vlib_frame_t * frame,
                          const u8 variant);




#endif

