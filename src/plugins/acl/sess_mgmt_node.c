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
#include <vppinfra/error.h>


#include <acl/acl.h>
#include <vnet/ip/icmp46_packet.h>

#include <plugins/acl/fa_node.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/lookup_context.h>
#include <plugins/acl/public_inlines.h>
#include <plugins/acl/session_inlines.h>



static_always_inline u8 *
format_ip46_session_bihash_kv (u8 * s, va_list * args, int is_ip6)
{
  fa_5tuple_t a5t;
  void *paddr0;
  void *paddr1;
  void *format_addr_func;

  if (is_ip6)
    {
      clib_bihash_kv_40_8_t *kv_40_8 =
	va_arg (*args, clib_bihash_kv_40_8_t *);
      a5t.kv_40_8 = *kv_40_8;
      paddr0 = &a5t.ip6_addr[0];
      paddr1 = &a5t.ip6_addr[1];
      format_addr_func = format_ip6_address;
    }
  else
    {
      clib_bihash_kv_16_8_t *kv_16_8 =
	va_arg (*args, clib_bihash_kv_16_8_t *);
      a5t.kv_16_8 = *kv_16_8;
      paddr0 = &a5t.ip4_addr[0];
      paddr1 = &a5t.ip4_addr[1];
      format_addr_func = format_ip4_address;
    }

  fa_full_session_id_t *sess = (fa_full_session_id_t *) & a5t.pkt;

  return (format (s, "l3 %U -> %U %U | sess id %d thread id %d epoch %04x",
		  format_addr_func, paddr0,
		  format_addr_func, paddr1,
		  format_fa_session_l4_key, &a5t.l4,
		  sess->session_index, sess->thread_index,
		  sess->intf_policy_epoch));
}

static u8 *
format_ip6_session_bihash_kv (u8 * s, va_list * args)
{
  return format_ip46_session_bihash_kv (s, args, 1);
}

static u8 *
format_ip4_session_bihash_kv (u8 * s, va_list * args)
{
  return format_ip46_session_bihash_kv (s, args, 0);
}


static void
acl_fa_verify_init_sessions (acl_main_t * am)
{
  if (!am->fa_sessions_hash_is_initialized)
    {
      u16 wk;
      /* Allocate the per-worker sessions pools */
      for (wk = 0; wk < vec_len (am->per_worker_data); wk++)
	{
	  acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];

	  /*
	   * // In lieu of trying to preallocate the pool and its free bitmap, rather use pool_init_fixed
	   * pool_alloc_aligned(pw->fa_sessions_pool, am->fa_conn_table_max_entries, CLIB_CACHE_LINE_BYTES);
	   * clib_bitmap_validate(pool_header(pw->fa_sessions_pool)->free_bitmap, am->fa_conn_table_max_entries);
	   */
	  pool_init_fixed (pw->fa_sessions_pool,
			   am->fa_conn_table_max_entries);
	}

      /* ... and the interface session hash table */
      clib_bihash_init_40_8 (&am->fa_ip6_sessions_hash,
			     "ACL plugin FA IPv6 session bihash",
			     am->fa_conn_table_hash_num_buckets,
			     am->fa_conn_table_hash_memory_size);
      clib_bihash_set_kvp_format_fn_40_8 (&am->fa_ip6_sessions_hash,
					  format_ip6_session_bihash_kv);

      clib_bihash_init_16_8 (&am->fa_ip4_sessions_hash,
			     "ACL plugin FA IPv4 session bihash",
			     am->fa_conn_table_hash_num_buckets,
			     am->fa_conn_table_hash_memory_size);
      clib_bihash_set_kvp_format_fn_16_8 (&am->fa_ip4_sessions_hash,
					  format_ip4_session_bihash_kv);

      am->fa_sessions_hash_is_initialized = 1;
    }
}


/*
 * Get the timeout of the session in a list since its enqueue time.
 */

static u64
fa_session_get_list_timeout (acl_main_t * am, fa_session_t * sess)
{
  u64 timeout = am->vlib_main->clib_time.clocks_per_second / 1000;
  timeout = fa_session_get_timeout (am, sess);
  /* for all user lists, check them twice per timeout */
  timeout >>= (sess->link_list_id != ACL_TIMEOUT_PURGATORY);
  return timeout;
}

static u64
acl_fa_get_list_head_expiry_time (acl_main_t * am,
				  acl_fa_per_worker_data_t * pw, u64 now,
				  u16 thread_index, int timeout_type)
{
  return pw->fa_conn_list_head_expiry_time[timeout_type];
}

static int
acl_fa_conn_time_to_check (acl_main_t * am, acl_fa_per_worker_data_t * pw,
			   u64 now, u16 thread_index, u32 session_index)
{
  if (session_index == FA_SESSION_BOGUS_INDEX)
    return 0;
  fa_session_t *sess = get_session_ptr (am, thread_index, session_index);
  u64 timeout_time =
    sess->link_enqueue_time + fa_session_get_list_timeout (am, sess);
  return (timeout_time < now)
    || (sess->link_enqueue_time <= pw->swipe_end_time);
}

static int
acl_fa_conn_can_purge (acl_main_t *am, acl_fa_per_worker_data_t *pw,
		       u32 min_run_count, u16 thread_index, u32 session_index)
{
  if (session_index == FA_SESSION_BOGUS_INDEX)
    return 0;
  fa_session_t *sess = get_session_ptr (am, thread_index, session_index);
  u32 distance = min_run_count - sess->purg_max_run_count;
  /* (min_run_count > sess_run_count), with wraparound */
  return ((distance > 0) && (distance < 0x8000000));
}

u32
get_min_run_count (acl_main_t *am)
{
  u16 wk;
  u32 min_run_count =
    clib_atomic_fetch_or (&am->per_worker_data[0].run_count, 0);
  for (wk = 1; wk < vec_len (am->per_worker_data); wk++)
    {
      acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
      u32 test_run_count = clib_atomic_fetch_or (&pw->run_count, 0);
      if (test_run_count < min_run_count)
	{
	  min_run_count = test_run_count;
	}
    }
  return min_run_count;
}

/*
 * see if there are sessions ready to be checked,
 * do the maintenance (requeue or delete), and
 * return the total number of sessions reclaimed.
 */
static int
acl_fa_check_idle_sessions (acl_main_t * am, u16 thread_index, u64 now)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  fa_full_session_id_t fsid;
  fsid.thread_index = thread_index;
  int total_expired = 0;

  u32 min_run_count = get_min_run_count (am);

  /* let the other threads enqueue more requests while we process, if they like */
  aclp_swap_wip_and_pending_session_change_requests (am, thread_index);
  u64 *psr = NULL;

  vec_foreach (psr, pw->wip_session_change_requests)
  {
    acl_fa_sess_req_t op = *psr >> 32;
    fsid.session_index = *psr & 0xffffffff;
    switch (op)
      {
      case ACL_FA_REQ_SESS_RESCHEDULE:
	acl_fa_restart_timer_for_session (am, now, fsid);
	break;
      default:
	/* do nothing */
	break;
      }
  }
  if (pw->wip_session_change_requests)
    vec_set_len (pw->wip_session_change_requests, 0);

  {
    u8 tt = 0;
    int n_pending_swipes = 0;
    for (tt = 0; tt < ACL_N_TIMEOUTS; tt++)
      {
	int n_expired = 0;
	while (n_expired < am->fa_max_deleted_sessions_per_interval)
	  {
	    fsid.session_index = pw->fa_conn_list_head[tt];
	    if ((tt == ACL_TIMEOUT_PURGATORY) &&
		(0 == acl_fa_conn_can_purge (am, pw, min_run_count,
					     thread_index,
					     pw->fa_conn_list_head[tt])))
	      {
		break;
	      }
	    if (!acl_fa_conn_time_to_check
		(am, pw, now, thread_index, pw->fa_conn_list_head[tt]))
	      {
		break;
	      }
	    if (am->trace_sessions > 3)
	      {
		elog_acl_maybe_trace_X3 (am,
					 "acl_fa_check_idle_sessions: expire session %d in list %d on thread %d",
					 "i4i4i4", (u32) fsid.session_index,
					 (u32) tt, (u32) thread_index);
	      }
	    vec_add1 (pw->expired, fsid.session_index);
	    n_expired++;
	    acl_fa_conn_list_delete_session (am, fsid, now);
	  }
      }
    for (tt = 0; tt < ACL_N_TIMEOUTS; tt++)
      {
	u32 session_index = pw->fa_conn_list_head[tt];
	if (session_index == FA_SESSION_BOGUS_INDEX)
	  break;
	fa_session_t *sess =
	  get_session_ptr (am, thread_index, session_index);
	n_pending_swipes += sess->link_enqueue_time <= pw->swipe_end_time;
      }
    if (n_pending_swipes == 0)
      {
	pw->swipe_end_time = 0;
      }
  }

  u32 *psid = NULL;
  vec_foreach (psid, pw->expired)
  {
    fsid.session_index = *psid;
    if (!pool_is_free_index (pw->fa_sessions_pool, fsid.session_index))
      {
	fa_session_t *sess =
	  get_session_ptr (am, thread_index, fsid.session_index);
	u32 sw_if_index = sess->sw_if_index;
	u64 sess_timeout_time =
	  sess->last_active_time + fa_session_get_timeout (am, sess);
	int timeout_passed = (now >= sess_timeout_time);
	int clearing_interface =
	  clib_bitmap_get (pw->pending_clear_sw_if_index_bitmap, sw_if_index);
	if (am->trace_sessions > 3)
	  {
	    elog_acl_maybe_trace_X2 (am,
				     "acl_fa_check_idle_sessions: now %lu sess_timeout_time %lu",
				     "i8i8", now, sess_timeout_time);
	    elog_acl_maybe_trace_X4 (am,
				     "acl_fa_check_idle_sessions: session %d sw_if_index %d timeout_passed %d clearing_interface %d",
				     "i4i4i4i4", (u32) fsid.session_index,
				     (u32) sess->sw_if_index,
				     (u32) timeout_passed,
				     (u32) clearing_interface);
	  }
	if (timeout_passed || clearing_interface)
	  {
	    if (acl_fa_two_stage_delete_session (am, sw_if_index, fsid, now))
	      {
		if (am->trace_sessions > 3)
		  {
		    elog_acl_maybe_trace_X2 (am,
					     "acl_fa_check_idle_sessions: deleted session %d sw_if_index %d",
					     "i4i4", (u32) fsid.session_index,
					     (u32) sess->sw_if_index);
		  }
		/* the session has been put */
		pw->cnt_deleted_sessions++;
	      }
	    else
	      {
		/* the connection marked as deleted and put to purgatory */
		if (am->trace_sessions > 3)
		  {
		    elog_acl_maybe_trace_X2 (am,
					     "acl_fa_check_idle_sessions: session %d sw_if_index %d marked as deleted, put to purgatory",
					     "i4i4", (u32) fsid.session_index,
					     (u32) sess->sw_if_index);
		  }
	      }
	  }
	else

	  {
	    if (am->trace_sessions > 3)
	      {
		elog_acl_maybe_trace_X2 (am,
					 "acl_fa_check_idle_sessions: restart timer for session %d sw_if_index %d",
					 "i4i4", (u32) fsid.session_index,
					 (u32) sess->sw_if_index);
	      }
	    /* There was activity on the session, so the idle timeout
	       has not passed. Enqueue for another time period. */

	    acl_fa_conn_list_add_session (am, fsid, now);
	    pw->cnt_session_timer_restarted++;
	  }
      }
    else
      {
	pw->cnt_already_deleted_sessions++;
      }
  }
  total_expired = vec_len (pw->expired);
  /* zero out the vector which we have acted on */
  if (pw->expired)
    vec_set_len (pw->expired, 0);
  /* if we were advancing and reached the end
   * (no more sessions to recycle), reset the fast-forward timestamp */

  if (pw->swipe_end_time && 0 == total_expired)
    pw->swipe_end_time = 0;

  elog_acl_maybe_trace_X1 (am,
			   "acl_fa_check_idle_sessions: done, total sessions expired: %d",
			   "i4", (u32) total_expired);
  return (total_expired);
}

/*
 * This process ensures the connection cleanup happens every so often
 * even in absence of traffic, as well as provides general orchestration
 * for requests like connection deletion on a given sw_if_index.
 */


/* *INDENT-OFF* */
#define foreach_acl_fa_cleaner_error \
_(UNKNOWN_EVENT, "unknown event received")  \
/* end  of errors */

typedef enum
{
#define _(sym,str) ACL_FA_CLEANER_ERROR_##sym,
  foreach_acl_fa_cleaner_error
#undef _
    ACL_FA_CLEANER_N_ERROR,
} acl_fa_cleaner_error_t;

static char *acl_fa_cleaner_error_strings[] = {
#define _(sym,string) string,
  foreach_acl_fa_cleaner_error
#undef _
};

/* *INDENT-ON* */

static vlib_node_registration_t acl_fa_session_cleaner_process_node;
static vlib_node_registration_t acl_fa_worker_session_cleaner_process_node;

static void
send_one_worker_interrupt (vlib_main_t * vm, acl_main_t * am,
			   int thread_index)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  if (!pw->interrupt_is_pending)
    {
      pw->interrupt_is_pending = 1;
      vlib_node_set_interrupt_pending (
	vlib_get_main_by_index (thread_index),
	acl_fa_worker_session_cleaner_process_node.index);
      elog_acl_maybe_trace_X1 (am,
			       "send_one_worker_interrupt: send interrupt to worker %u",
			       "i4", ((u32) thread_index));
      /* if the interrupt was requested, mark that done. */
      /* pw->interrupt_is_needed = 0; */
      CLIB_MEMORY_BARRIER ();
    }
}

void
aclp_post_session_change_request (acl_main_t * am, u32 target_thread,
				  u32 target_session, u32 request_type)
{
  acl_fa_per_worker_data_t *pw_me =
    &am->per_worker_data[os_get_thread_index ()];
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[target_thread];
  clib_spinlock_lock_if_init (&pw->pending_session_change_request_lock);
  /* vec_add1 might cause a reallocation */
  vec_add1 (pw->pending_session_change_requests,
	    (((u64) request_type) << 32) | target_session);
  pw->rcvd_session_change_requests++;
  pw_me->sent_session_change_requests++;
  if (vec_len (pw->pending_session_change_requests) == 1)
    {
      /* ensure the requests get processed */
      send_one_worker_interrupt (am->vlib_main, am, target_thread);
    }
  clib_spinlock_unlock_if_init (&pw->pending_session_change_request_lock);
}

void
aclp_swap_wip_and_pending_session_change_requests (acl_main_t * am,
						   u32 target_thread)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[target_thread];
  u64 *tmp;
  clib_spinlock_lock_if_init (&pw->pending_session_change_request_lock);
  tmp = pw->pending_session_change_requests;
  pw->pending_session_change_requests = pw->wip_session_change_requests;
  pw->wip_session_change_requests = tmp;
  clib_spinlock_unlock_if_init (&pw->pending_session_change_request_lock);
}


static int
purgatory_has_connections (vlib_main_t * vm, acl_main_t * am,
			   int thread_index)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  return (FA_SESSION_BOGUS_INDEX !=
	  pw->fa_conn_list_head[ACL_TIMEOUT_PURGATORY]);

}


/*
 * Per-worker thread interrupt-driven cleaner thread
 * to clean idle connections if there are no packets
 */
static uword
acl_fa_worker_conn_cleaner_process (vlib_main_t * vm,
				    vlib_node_runtime_t * rt,
				    vlib_frame_t * f)
{
  acl_main_t *am = &acl_main;
  u64 now = clib_cpu_time_now ();
  u16 thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  int num_expired;
  elog_acl_maybe_trace_X1 (am,
			   "acl_fa_worker_conn_cleaner interrupt: now %lu",
			   "i8", now);
  /* allow another interrupt to be queued */
  pw->interrupt_is_pending = 0;
  if (pw->clear_in_process)
    {
      if (0 == pw->swipe_end_time)
	{
	  /*
	   * Someone has just set the flag to start clearing.
	   * we do this by combing through the connections up to a "time T"
	   * which is now, and requeueing everything except the expired
	   * connections and those matching the interface(s) being cleared.
	   */

	  /*
	   * first filter the sw_if_index bitmap that they want from us, by
	   * a bitmap of sw_if_index for which we actually have connections.
	   */
	  if ((pw->pending_clear_sw_if_index_bitmap == 0)
	      || (pw->serviced_sw_if_index_bitmap == 0))
	    {
	      elog_acl_maybe_trace_X1 (am,
				       "acl_fa_worker_conn_cleaner: now %lu, someone tried to call clear but one of the bitmaps are empty",
				       "i8", now);
	      clib_bitmap_zero (pw->pending_clear_sw_if_index_bitmap);
	    }
	  else
	    {
#ifdef FA_NODE_VERBOSE_DEBUG
	      clib_warning
		("WORKER-CLEAR: (before and) swiping sw-if-index bitmap: %U, my serviced bitmap %U",
		 format_bitmap_hex, pw->pending_clear_sw_if_index_bitmap,
		 format_bitmap_hex, pw->serviced_sw_if_index_bitmap);
#endif
	      pw->pending_clear_sw_if_index_bitmap =
		clib_bitmap_and (pw->pending_clear_sw_if_index_bitmap,
				 pw->serviced_sw_if_index_bitmap);
	    }

	  if (clib_bitmap_is_zero (pw->pending_clear_sw_if_index_bitmap))
	    {
	      /* if the cross-section is a zero vector, no need to do anything. */
	      elog_acl_maybe_trace_X1 (am,
				       "acl_fa_worker_conn_cleaner: now %lu, clearing done, nothing to do",
				       "i8", now);
	      pw->clear_in_process = 0;
	      pw->swipe_end_time = 0;
	    }
	  else
	    {
#ifdef FA_NODE_VERBOSE_DEBUG
	      clib_warning
		("WORKER-CLEAR: swiping sw-if-index bitmap: %U, my serviced bitmap %U",
		 format_bitmap_hex, pw->pending_clear_sw_if_index_bitmap,
		 format_bitmap_hex, pw->serviced_sw_if_index_bitmap);
#endif
	      elog_acl_maybe_trace_X1 (am,
				       "acl_fa_worker_conn_cleaner: swiping until %lu",
				       "i8", now);
	      /* swipe through the connection lists until enqueue timestamps become above "now" */
	      pw->swipe_end_time = now;
	    }
	}
    }
  num_expired = acl_fa_check_idle_sessions (am, thread_index, now);
  // clib_warning("WORKER-CLEAR: checked %d sessions (clear_in_progress: %d)", num_expired, pw->clear_in_process);
  elog_acl_maybe_trace_X2 (am,
			   "acl_fa_worker_conn_cleaner: checked %d sessions (clear_in_process: %d)",
			   "i4i4", (u32) num_expired,
			   (u32) pw->clear_in_process);
  if (pw->clear_in_process)
    {
      if (pw->swipe_end_time == 0)
	{
	  /* we were clearing but we could not process any more connections. time to stop. */
	  clib_bitmap_zero (pw->pending_clear_sw_if_index_bitmap);
	  pw->clear_in_process = 0;
	  elog_acl_maybe_trace_X1 (am,
				   "acl_fa_worker_conn_cleaner: now %lu, clearing done - all done",
				   "i8", now);
	}
      else
	{
	  elog_acl_maybe_trace_X1 (am,
				   "acl_fa_worker_conn_cleaner: now %lu, more work to do - requesting interrupt",
				   "i8", now);
	  /* should continue clearing.. So could they please sent an interrupt again? */
	  send_one_worker_interrupt (vm, am, thread_index);
	  // pw->interrupt_is_needed = 1;
	}
    }
  else
    {
      if (num_expired > 0)
	{
	  /* there was too much work, we should get an interrupt ASAP */
	  // pw->interrupt_is_needed = 1;
	  send_one_worker_interrupt (vm, am, thread_index);
	  pw->interrupt_is_unwanted = 0;
	}
      else
	{
	  /* the current rate of interrupts is ok */
	  pw->interrupt_is_needed = 0;
	  pw->interrupt_is_unwanted = 0;
	}
      elog_acl_maybe_trace_X3 (am,
			       "acl_fa_worker_conn_cleaner: now %lu, interrupt needed: %u, interrupt unwanted: %u",
			       "i8i4i4", now, ((u32) pw->interrupt_is_needed),
			       ((u32) pw->interrupt_is_unwanted));
    }
  /* be persistent about quickly deleting the connections from the purgatory */
  if (purgatory_has_connections (vm, am, thread_index))
    {
      send_one_worker_interrupt (vm, am, thread_index);
    }
  pw->interrupt_generation = am->fa_interrupt_generation;
  return 0;
}

static void
send_interrupts_to_workers (vlib_main_t * vm, acl_main_t * am)
{
  int i;
  /* Can't use vec_len(am->per_worker_data) since the threads might not have come up yet; */
  int n_threads = vlib_get_n_threads ();
  for (i = 0; i < n_threads; i++)
    {
      send_one_worker_interrupt (vm, am, i);
    }
}

/* centralized process to drive per-worker cleaners */
static uword
acl_fa_session_cleaner_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f)
{
  acl_main_t *am = &acl_main;
  u64 now;
  f64 cpu_cps = vm->clib_time.clocks_per_second;
  u64 next_expire;
  /* We should check if there are connections to clean up - at least twice a second */
  u64 max_timer_wait_interval = cpu_cps / 2;
  uword event_type, *event_data = 0;
  acl_fa_per_worker_data_t *pw0;

  am->fa_current_cleaner_timer_wait_interval = max_timer_wait_interval;
  am->fa_cleaner_node_index = acl_fa_session_cleaner_process_node.index;
  am->fa_interrupt_generation = 1;
  while (1)
    {
      now = clib_cpu_time_now ();
      next_expire = now + am->fa_current_cleaner_timer_wait_interval;
      int has_pending_conns = 0;
      u16 ti;
      u8 tt;

      /*
       * walk over all per-thread list heads of different timeouts,
       * and see if there are any connections pending.
       * If there aren't - we do not need to wake up until the
       * worker code signals that it has added a connection.
       *
       * Also, while we are at it, calculate the earliest we need to wake up.
       */
      for (ti = 0; ti < vlib_get_n_threads (); ti++)
	{
	  if (ti >= vec_len (am->per_worker_data))
	    {
	      continue;
	    }
	  acl_fa_per_worker_data_t *pw = &am->per_worker_data[ti];
	  for (tt = 0; tt < vec_len (pw->fa_conn_list_head); tt++)
	    {
	      u64 head_expiry =
		acl_fa_get_list_head_expiry_time (am, pw, now, ti, tt);
	      if ((head_expiry < next_expire) && !pw->interrupt_is_pending)
		{
		  elog_acl_maybe_trace_X3 (am,
					   "acl_fa_session_cleaner_process: now %lu, worker: %u tt: %u",
					   "i8i2i2", now, ti, tt);
		  elog_acl_maybe_trace_X2 (am,
					   "acl_fa_session_cleaner_process: head expiry: %lu, is earlier than curr next expire: %lu",
					   "i8i8", head_expiry, next_expire);
		  next_expire = head_expiry;
		}
	      if (FA_SESSION_BOGUS_INDEX != pw->fa_conn_list_head[tt])
		{
		  has_pending_conns = 1;
		}
	    }
	}

      /* If no pending connections and no ACL applied then no point in timing out */
      if (!has_pending_conns && (0 == am->fa_total_enabled_count))
	{
	  am->fa_cleaner_cnt_wait_without_timeout++;
	  elog_acl_maybe_trace_X1 (am,
				   "acl_conn_cleaner: now %lu entering wait without timeout",
				   "i8", now);
	  (void) vlib_process_wait_for_event (vm);
	  event_type = vlib_process_get_events (vm, &event_data);
	}
      else
	{
	  f64 timeout = ((i64) next_expire - (i64) now) / cpu_cps;
	  if (timeout <= 0)
	    {
	      /* skip waiting altogether */
	      event_type = ~0;
	    }
	  else
	    {
	      am->fa_cleaner_cnt_wait_with_timeout++;
	      elog_acl_maybe_trace_X2 (am,
				       "acl_conn_cleaner: now %lu entering wait with timeout %.6f sec",
				       "i8f8", now, timeout);
	      (void) vlib_process_wait_for_event_or_clock (vm, timeout);
	      event_type = vlib_process_get_events (vm, &event_data);
	    }
	}

      switch (event_type)
	{
	case ~0:
	  /* nothing to do */
	  break;
	case ACL_FA_CLEANER_RESCHEDULE:
	  /* Nothing to do. */
	  break;
	case ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX:
	  {
	    uword *clear_sw_if_index_bitmap = 0;
	    uword *sw_if_index0;
	    int clear_all = 0;
	    now = clib_cpu_time_now ();
	    elog_acl_maybe_trace_X1 (am,
				     "acl_fa_session_cleaner_process: now %lu, received ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX",
				     "i8", now);
	    vec_foreach (sw_if_index0, event_data)
	    {
	      am->fa_cleaner_cnt_delete_by_sw_index++;
	      elog_acl_maybe_trace_X1 (am,
				       "acl_fa_session_cleaner_process: ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX %u",
				       "i4", *sw_if_index0);
	      if (*sw_if_index0 == ~0)
		{
		  clear_all = 1;
		}
	      else
		{
		  if (!pool_is_free_index
		      (am->vnet_main->interface_main.sw_interfaces,
		       *sw_if_index0))
		    {
		      clear_sw_if_index_bitmap =
			clib_bitmap_set (clear_sw_if_index_bitmap,
					 *sw_if_index0, 1);
		    }
		}
	    }
	    acl_log_info
	      ("ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX bitmap: %U, clear_all: %u",
	       format_bitmap_hex, clear_sw_if_index_bitmap, clear_all);
	    vec_foreach (pw0, am->per_worker_data)
	    {
	      CLIB_MEMORY_BARRIER ();
	      while (pw0->clear_in_process)
		{
		  CLIB_MEMORY_BARRIER ();
		  elog_acl_maybe_trace_X1 (am,
					   "ACL_FA_NODE_CLEAN: waiting previous cleaning cycle to finish on %u",
					   "i4",
					   (u32) (pw0 - am->per_worker_data));
		  vlib_process_suspend (vm, 0.0001);
		  if (pw0->interrupt_is_needed)
		    {
		      send_one_worker_interrupt (vm, am,
						 (pw0 - am->per_worker_data));
		    }
		}
	      if (pw0->clear_in_process)
		{
		  acl_log_err
		    ("ERROR-BUG! Could not initiate cleaning on worker because another cleanup in progress");
		}
	      else
		{
		  clib_bitmap_free (pw0->pending_clear_sw_if_index_bitmap);
		  if (clear_all)
		    {
		      /* if we need to clear all, then just clear the interfaces that we are servicing */
		      pw0->pending_clear_sw_if_index_bitmap =
			clib_bitmap_dup (pw0->serviced_sw_if_index_bitmap);
		    }
		  else
		    {
		      pw0->pending_clear_sw_if_index_bitmap =
			clib_bitmap_dup (clear_sw_if_index_bitmap);
		    }
		  acl_log_info
		    ("ACL_FA_CLEANER: thread %u, pending clear bitmap: %U",
		     (am->per_worker_data - pw0), format_bitmap_hex,
		     pw0->pending_clear_sw_if_index_bitmap);
		  pw0->clear_in_process = 1;
		}
	    }
	    /* send some interrupts so they can start working */
	    send_interrupts_to_workers (vm, am);

	    /* now wait till they all complete */
	    acl_log_info ("CLEANER mains len: %u per-worker len: %d",
			  vlib_get_n_threads (),
			  vec_len (am->per_worker_data));
	    vec_foreach (pw0, am->per_worker_data)
	    {
	      CLIB_MEMORY_BARRIER ();
	      while (pw0->clear_in_process)
		{
		  CLIB_MEMORY_BARRIER ();
		  elog_acl_maybe_trace_X1 (am,
					   "ACL_FA_NODE_CLEAN: waiting for my cleaning cycle to finish on %u",
					   "i4",
					   (u32) (pw0 - am->per_worker_data));
		  vlib_process_suspend (vm, 0.0001);
		  if (pw0->interrupt_is_needed)
		    {
		      send_one_worker_interrupt (vm, am,
						 (pw0 - am->per_worker_data));
		    }
		}
	    }
	    acl_log_info ("ACL_FA_NODE_CLEAN: cleaning done");
	    clib_bitmap_free (clear_sw_if_index_bitmap);
	  }
	  am->fa_cleaner_cnt_delete_by_sw_index_ok++;
	  break;
	default:
#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning ("ACL plugin connection cleaner: unknown event %u",
			event_type);
#endif
	  vlib_node_increment_counter (vm,
				       acl_fa_session_cleaner_process_node.
				       index,
				       ACL_FA_CLEANER_ERROR_UNKNOWN_EVENT, 1);
	  am->fa_cleaner_cnt_unknown_event++;
	  break;
	}

      send_interrupts_to_workers (vm, am);

      if (event_data)
	vec_set_len (event_data, 0);

      /*
       * If the interrupts were not processed yet, ensure we wait a bit,
       * but up to a point.
       */
      int need_more_wait = 0;
      int max_wait_cycles = 100;
      do
	{
	  need_more_wait = 0;
	  vec_foreach (pw0, am->per_worker_data)
	  {
	    if (pw0->interrupt_generation != am->fa_interrupt_generation)
	      {
		need_more_wait = 1;
	      }
	  }
	  if (need_more_wait)
	    {
	      vlib_process_suspend (vm, 0.0001);
	    }
	}
      while (need_more_wait && (--max_wait_cycles > 0));

      int interrupts_needed = 0;
      int interrupts_unwanted = 0;

      vec_foreach (pw0, am->per_worker_data)
      {
	if (pw0->interrupt_is_needed)
	  {
	    interrupts_needed++;
	    /* the per-worker value is reset when sending the interrupt */
	  }
	if (pw0->interrupt_is_unwanted)
	  {
	    interrupts_unwanted++;
	    pw0->interrupt_is_unwanted = 0;
	  }
      }
      if (interrupts_needed)
	{
	  /* they need more interrupts, do less waiting around next time */
	  am->fa_current_cleaner_timer_wait_interval /= 2;
	  /* never go into zero-wait either though - we need to give the space to others */
	  am->fa_current_cleaner_timer_wait_interval += 1;
	}
      else if (interrupts_unwanted)
	{
	  /* slowly increase the amount of sleep up to a limit */
	  if (am->fa_current_cleaner_timer_wait_interval <
	      max_timer_wait_interval)
	    am->fa_current_cleaner_timer_wait_interval +=
	      cpu_cps * am->fa_cleaner_wait_time_increment;
	}
      am->fa_cleaner_cnt_event_cycles++;
      am->fa_interrupt_generation++;
    }
  /* NOT REACHED */
  return 0;
}


void
acl_fa_enable_disable (u32 sw_if_index, int is_input, int enable_disable)
{
  acl_main_t *am = &acl_main;
  if (enable_disable)
    {
      acl_fa_verify_init_sessions (am);
      am->fa_total_enabled_count++;
      vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
				 ACL_FA_CLEANER_RESCHEDULE, 0);
    }
  else
    {
      am->fa_total_enabled_count--;
    }

  if (is_input)
    {
      ASSERT (clib_bitmap_get (am->fa_in_acl_on_sw_if_index, sw_if_index) !=
	      enable_disable);
      vnet_feature_enable_disable ("ip4-unicast", "acl-plugin-in-ip4-fa",
				   sw_if_index, enable_disable, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "acl-plugin-in-ip6-fa",
				   sw_if_index, enable_disable, 0, 0);
      am->fa_in_acl_on_sw_if_index =
	clib_bitmap_set (am->fa_in_acl_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
  else
    {
      ASSERT (clib_bitmap_get (am->fa_out_acl_on_sw_if_index, sw_if_index) !=
	      enable_disable);
      vnet_feature_enable_disable ("ip4-output", "acl-plugin-out-ip4-fa",
				   sw_if_index, enable_disable, 0, 0);
      vnet_feature_enable_disable ("ip6-output", "acl-plugin-out-ip6-fa",
				   sw_if_index, enable_disable, 0, 0);
      am->fa_out_acl_on_sw_if_index =
	clib_bitmap_set (am->fa_out_acl_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
  if ((!enable_disable) && (!acl_fa_ifc_has_in_acl (am, sw_if_index))
      && (!acl_fa_ifc_has_out_acl (am, sw_if_index)))
    {
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning ("ENABLE-DISABLE: clean the connections on interface %d",
		    sw_if_index);
#endif
      vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
				 ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
				 sw_if_index);
    }
}

void
show_fa_sessions_hash (vlib_main_t * vm, u32 verbose)
{
  acl_main_t *am = &acl_main;
  if (am->fa_sessions_hash_is_initialized)
    {
      vlib_cli_output (vm, "\nIPv6 Session lookup hash table:\n%U\n\n",
		       format_bihash_40_8, &am->fa_ip6_sessions_hash,
		       verbose);

      vlib_cli_output (vm, "\nIPv4 Session lookup hash table:\n%U\n\n",
		       format_bihash_16_8, &am->fa_ip4_sessions_hash,
		       verbose);
    }
  else
    {
      vlib_cli_output (vm,
		       "\nSession lookup hash table is not allocated.\n\n");
    }
}


/* *INDENT-OFF* */

VLIB_REGISTER_NODE (acl_fa_worker_session_cleaner_process_node, static) = {
  .function = acl_fa_worker_conn_cleaner_process,
  .name = "acl-plugin-fa-worker-cleaner-process",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

VLIB_REGISTER_NODE (acl_fa_session_cleaner_process_node, static) = {
  .function = acl_fa_session_cleaner_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "acl-plugin-fa-cleaner-process",
  .n_errors = ARRAY_LEN (acl_fa_cleaner_error_strings),
  .error_strings = acl_fa_cleaner_error_strings,
  .n_next_nodes = 0,
  .next_nodes = {},
};


/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
