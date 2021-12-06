/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Copyright (c) 2021 Graphiant and/or its affiliates.
 *
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

#include <vnet/dependency/dep_walk.h>
#include <vnet/dependency/dep_list.h>

static vlib_log_class_t dep_walk_logger;
static dep_type_t DEP_TYPE_WALK;

/**
 * We consider a depth of 32 to be sufficient to cover all sane
 * network topologies. Anything more is then an indication that
 * there is a loop/cycle in the graph.
 * Note that all object types contribute to 1 to the depth.
 */
#define DEP_GRAPH_MAX_DEPTH ((u32) 32)

/**
 * The flags on a walk
 */
typedef enum dep_walk_flags_t_
{
  /**
   * A synchronous walk.
   * This walk will run to completion, i.e. visit ALL the children.
   * It is a depth first traversal of the graph.
   */
  DEP_WALK_FLAG_SYNC = (1 << 0),
  /**
   * An asynchronous walk.
   * This walk will be scheduled to run in the background. It will thus visits
   * the children at a later point in time.
   * It is a depth first traversal of the graph.
   */
  DEP_WALK_FLAG_ASYNC = (1 << 1),
  /**
   * An indication that the walk is currently executing.
   */
  DEP_WALK_FLAG_EXECUTING = (1 << 2),
} dep_walk_flags_t;

/**
 * A representation of a graph walk from a parent object to its children
 */
typedef struct dep_walk_t_
{
  /**
   * DEP node linkage. This object is not in the DEP object graph,
   * but it is present in other node's dependency lists, so it needs to
   * be pointerable to.
   */
  dep_t dw_node;

  /**
   * the walk's flags
   */
  dep_walk_flags_t dw_flags;

  /**
   * Sibling index in the dependency list
   */
  u32 dw_dep_sibling;

  /**
   * Sibling index in the list of all walks
   */
  u32 dw_prio_sibling;

  /**
   * Pointer to the node whose dependants this walk is walking
   */
  dep_ptr_t dw_parent;

  /**
   * Number of nodes visited by this walk. saved for debugging purposes.
   */
  u32 dw_n_visits;

  /**
   * Time the walk started
   */
  f64 dw_start_time;

  /**
   * The reasons this walk is occuring.
   * This is a vector ordered in time. The reasons and the front were started
   * first, and so should be acted first when a node is visited.
   */
  dep_back_walk_ctx_t *dw_ctx;
} dep_walk_t;

/**
 * @brief The pool of all walk objects
 */
static dep_walk_t *dep_walk_pool;

/**
 * Statistics maintained per-walk queue
 */
#define foreach_dep_walk_queue_stats                                          \
  _ (SCHEDULED, "scheduled")                                                  \
  _ (COMPLETED, "completed")
typedef enum dep_walk_queue_stats_t_
{
#define _(a, b) DEP_WALK_##a,
  foreach_dep_walk_queue_stats
#undef _
} dep_walk_queue_stats_t;

#define DEP_WALK_QUEUE_STATS_NUM                                              \
  ((dep_walk_queue_stats_t) (DEP_WALK_COMPLETED + 1))

#define FOR_EACH_DEP_WALK_QUEUE_STATS(_wqs)                                   \
  for ((_wqs) = DEP_WALK_SCHEDULED; (_wqs) < DEP_WALK_QUEUE_STATS_NUM;        \
       (_wqs)++)

/**
 * A representation of one queue of walk
 */
typedef struct dep_walk_queue_t_
{
  /**
   * Qeuee stats
   */
  u64 dwq_stats[DEP_WALK_QUEUE_STATS_NUM];

  /**
   * The node list which acts as the queue
   */
  dep_list_t dwq_queue;
} dep_walk_queue_t;

/**
 * A set of priority queues for outstanding walks
 */
typedef struct dep_walk_queues_t_
{
  dep_walk_queue_t dwqs_queues[DEP_WALK_PRIORITY_NUM];
} dep_walk_queues_t;

/**
 * The global queues of outstanding walks
 */
static dep_walk_queues_t dep_walk_queues;

/**
 * @brief Histogram stats on the lenths of each walk in elemenets visited.
 * Store upto 1<<23 elements in increments of 1<<10
 */
#define HISTOGRAM_VISITS_PER_WALK_MAX  (1 << 23)
#define HISTOGRAM_VISITS_PER_WALK_INCR (1 << 10)
#define HISTOGRAM_VISITS_PER_WALK_N_BUCKETS                                   \
  (HISTOGRAM_VISITS_PER_WALK_MAX / HISTOGRAM_VISITS_PER_WALK_INCR)
static u64 dep_walk_hist_vists_per_walk[HISTOGRAM_VISITS_PER_WALK_N_BUCKETS];

/**
 * @brief History of state for the last 128 walks
 */
#define HISTORY_N_WALKS	    128
#define MAX_HISTORY_REASONS 16
static u32 history_last_walk_pos;
typedef struct dep_walk_history_t_
{
  u32 dwh_n_visits;
  f64 dwh_duration;
  f64 dwh_completed;
  dep_ptr_t dwh_parent;
  dep_walk_flags_t dwh_flags;
  dep_bw_reason_flag_t dwh_reason[MAX_HISTORY_REASONS];
} dep_walk_history_t;
static dep_walk_history_t dep_walk_history[HISTORY_N_WALKS];

static u8 *format_dep_walk (u8 *s, va_list *ap);

#define DEP_WALK_DBG(_walk, _fmt, _args...)                                   \
  {                                                                           \
    vlib_log_debug (dep_walk_logger, "[%U]:" _fmt, format_dep_walk,           \
		    dep_walk_get_index (_walk), ##_args);                     \
  }

u8 *
format_dep_walk_priority (u8 *s, va_list *ap)
{
  dep_walk_priority_t prio = va_arg (*ap, dep_walk_priority_t);

  if (0)
    ;
#define _(a, b)                                                               \
  else if (prio == DEP_WALK_PRIORITY_##a) return (format (s, "%s", b));
  foreach_dep_walk_priority
#undef _

    return (format (s, "unknown"));
}
static u8 *
format_dep_walk_queue_stats (u8 *s, va_list *ap)
{
  dep_walk_queue_stats_t wqs = va_arg (*ap, dep_walk_queue_stats_t);

  if (0)
    ;
#define _(a, b) else if (wqs == DEP_WALK_##a) return (format (s, "%s", b));
  foreach_dep_walk_queue_stats
#undef _

    return (format (s, "unknown"));
}

static u32
dep_walk_get_index (dep_walk_t *dwalk)
{
  return (dwalk - dep_walk_pool);
}

static dep_walk_t *
dep_walk_get (u32 dwi)
{
  return (pool_elt_at_index (dep_walk_pool, dwi));
}

/*
 * not static so it can be used in the unit tests
 */
u32
dep_walk_queue_get_size (dep_walk_priority_t prio)
{
  return (dep_list_get_size (dep_walk_queues.dwqs_queues[prio].dwq_queue));
}

static dep_index_t
dep_walk_queue_get_front (dep_walk_priority_t prio)
{
  dep_ptr_t wp;

  dep_list_get_front (dep_walk_queues.dwqs_queues[prio].dwq_queue, &wp);

  return (wp.dp_index);
}

static void
dep_walk_destroy (u32 dwi)
{
  dep_walk_t *dwalk;
  u32 bucket, ii;

  dwalk = dep_walk_get (dwi);

  if (DEP_INDEX_INVALID != dwalk->dw_prio_sibling)
    {
      dep_list_elt_remove (dwalk->dw_prio_sibling);
    }
  dep_child_remove (dwalk->dw_parent.dp_type, dwalk->dw_parent.dp_index,
		    dwalk->dw_dep_sibling);

  /*
   * refetch the walk object. More walks could have been spawned as a result
   * of releasing the lock on the parent.
   */
  dwalk = dep_walk_get (dwi);

  /*
   * add the stats to the continuous histogram collection.
   */
  bucket = (dwalk->dw_n_visits / HISTOGRAM_VISITS_PER_WALK_INCR);
  bucket = (bucket >= HISTOGRAM_VISITS_PER_WALK_N_BUCKETS ?
		    HISTOGRAM_VISITS_PER_WALK_N_BUCKETS - 1 :
		    bucket);
  dep_walk_hist_vists_per_walk[bucket]++;

  /*
   * save stats to the recent history
   */

  dep_walk_history[history_last_walk_pos].dwh_n_visits = dwalk->dw_n_visits;
  dep_walk_history[history_last_walk_pos].dwh_completed =
    vlib_time_now (vlib_get_main ());
  dep_walk_history[history_last_walk_pos].dwh_duration =
    dep_walk_history[history_last_walk_pos].dwh_completed -
    dwalk->dw_start_time;
  dep_walk_history[history_last_walk_pos].dwh_parent = dwalk->dw_parent;
  dep_walk_history[history_last_walk_pos].dwh_flags = dwalk->dw_flags;

  vec_foreach_index (ii, dwalk->dw_ctx)
    {
      if (ii < MAX_HISTORY_REASONS)
	{
	  dep_walk_history[history_last_walk_pos].dwh_reason[ii] =
	    dwalk->dw_ctx[ii].dbw_reason;
	}
    }

  history_last_walk_pos = (history_last_walk_pos + 1) % HISTORY_N_WALKS;

  dep_deinit (&dwalk->dw_node);
  vec_free (dwalk->dw_ctx);
  pool_put (dep_walk_pool, dwalk);
}

/**
 * return code when advancing a walk
 */
typedef enum dep_walk_advance_rc_t_
{
  /**
   * The walk is complete
   */
  DEP_WALK_ADVANCE_DONE,
  /**
   * the walk has more work
   */
  DEP_WALK_ADVANCE_MORE,
  /**
   * The walk merged with the one in front
   */
  DEP_WALK_ADVANCE_MERGE,
} dep_walk_advance_rc_t;

/**
 * @brief Advance the walk one element in its work list
 */
static dep_walk_advance_rc_t
dep_walk_advance (dep_index_t dwi)
{
  dep_back_walk_rc_t wrc;
  dep_ptr_t sibling;
  dep_walk_t *dwalk;
  u32 n_ctxs, ii;
  int more_elts;

  /*
   * this walk function is re-entrant - walks acan spawn walks.
   * dep_walk_t objects come from a pool, so they can realloc. we need
   * to retch from said pool at the appropriate times.
   */
  dwalk = dep_walk_get (dwi);

  more_elts = dep_list_elt_get_next (dwalk->dw_dep_sibling, &sibling);

  if (more_elts)
    {

      /*
       * loop through the backwalk contexts. This can grow in length
       * as walks on the same object meet each other. Order is preserved so the
       * most recently started walk as at the back of the vector.
       */
      ii = 0;
      n_ctxs = vec_len (dwalk->dw_ctx);

      while (ii < n_ctxs)
	{
	  dep_back_walk_ctx_t ctx = dwalk->dw_ctx[ii];

	  wrc = dep_back_walk_one (&sibling, &ctx);

	  ii++;
	  dwalk = dep_walk_get (dwi);
	  dwalk->dw_n_visits++;

	  if (DEP_BACK_WALK_MERGE == wrc)
	    {
	      /*
	       * this walk has merged with the one further along the node's
	       * dependecy list.
	       */
	      return (DEP_WALK_ADVANCE_MERGE);
	    }

	  /*
	   * re-evaluate the number of backwalk contexts we need to process.
	   */
	  n_ctxs = vec_len (dwalk->dw_ctx);
	}
      /*
       * if the next on the list is the one we just walked,
       * move foward to the next node to visit, if it's not then it got
       * removed during the walk.
       */
      dep_ptr_t next_sibling;
      more_elts = dep_list_elt_get_next (dwalk->dw_dep_sibling, &next_sibling);

      if (more_elts && 0 == dep_ptr_cmp (&sibling, &next_sibling))
	more_elts = dep_list_advance (dwalk->dw_dep_sibling);
    }

  if (more_elts)
    {
      return (DEP_WALK_ADVANCE_MORE);
    }

  return (DEP_WALK_ADVANCE_DONE);
}

/**
 * @brief Enurmerate the times of sleep between walks
 */
typedef enum dep_walk_sleep_type_t_
{
  DEP_WALK_SHORT_SLEEP,
  DEP_WALK_LONG_SLEEP,
} dep_walk_sleep_type_t;

#define DEP_WALK_N_SLEEP (DEP_WALK_LONG_SLEEP + 1)

/**
 * @brief Durations for the sleep types
 */
static f64 dep_walk_sleep_duration[] = {
  /**
   * Long sleep when there is no more work, i.e. the queues are empty.
   * This is a sleep (as opposed to a wait for event) just to be sure we
   * are not missing events by sleeping forever.
   */
  [DEP_WALK_LONG_SLEEP] = 2,

  /**
   * Short sleep. There is work left in the queues. We are yielding the CPU
   * momentarily.
   */
  [DEP_WALK_SHORT_SLEEP] = 1e-8,
};

/**
 * @brief The time quota for a walk. When more than this amount of time is
 * spent, the walk process will yield.
 */
static f64 quota = 1e-4;

/**
 * Histogram on the amount of work done (in msecs) in each walk
 */
#define N_TIME_BUCKETS	128
#define TIME_INCREMENTS (N_TIME_BUCKETS / 2)
static u64 dep_walk_work_time_taken[N_TIME_BUCKETS];

/**
 * Histogram on the number of nodes visted in each quota
 */
#define N_ELTS_BUCKETS 128
static u32 dep_walk_work_nodes_visited_incr = 2;
static u64 dep_walk_work_nodes_visited[N_ELTS_BUCKETS];

/**
 * Histogram of the sleep lengths
 */
static u64 dep_walk_sleep_lengths[2];

/**
 * @brief Service the queues
 * This is not declared static so that it can be unit tested - i know i know...
 */
f64
dep_walk_process_queues (vlib_main_t *vm, const f64 quota)
{
  f64 start_time, consumed_time;
  dep_walk_sleep_type_t sleep;
  dep_walk_priority_t prio;
  dep_walk_advance_rc_t rc;
  dep_index_t dwi;
  dep_walk_t *dwalk;
  u32 n_elts;
  i32 bucket;

  consumed_time = 0;
  start_time = vlib_time_now (vm);
  n_elts = 0;

  FOR_EACH_DEP_WALK_PRIORITY (prio)
  {
    while (0 != dep_walk_queue_get_size (prio))
      {
	dwi = dep_walk_queue_get_front (prio);

	/*
	 * set this walk as executing
	 */
	dwalk = dep_walk_get (dwi);
	dwalk->dw_flags |= DEP_WALK_FLAG_EXECUTING;

	do
	  {
	    rc = dep_walk_advance (dwi);
	    n_elts++;
	    consumed_time = (vlib_time_now (vm) - start_time);
	  }
	while ((consumed_time < quota) && (DEP_WALK_ADVANCE_MORE == rc));

	/*
	 * if this walk has no more work then pop it from the queue
	 * and move on to the next.
	 */
	if (DEP_WALK_ADVANCE_MORE != rc)
	  {
	    dep_walk_destroy (dwi);
	    dep_walk_queues.dwqs_queues[prio].dwq_stats[DEP_WALK_COMPLETED]++;
	  }
	else
	  {
	    /*
	     * passed our work quota. sleep time.
	     */
	    dwalk = dep_walk_get (dwi);
	    dwalk->dw_flags &= ~DEP_WALK_FLAG_EXECUTING;
	    sleep = DEP_WALK_SHORT_SLEEP;
	    goto that_will_do_for_now;
	  }
      }
  }
  /*
   * got to the end of all the work
   */
  sleep = DEP_WALK_LONG_SLEEP;

that_will_do_for_now:

  /*
   * collect the stats:
   *  - for the number of nodes visited we store 128 increments
   *  - for the time consumed we store quota/TIME_INCREMENTS increments.
   */
  bucket = ((n_elts / dep_walk_work_nodes_visited_incr) > N_ELTS_BUCKETS ?
		    N_ELTS_BUCKETS - 1 :
		    n_elts / dep_walk_work_nodes_visited_incr);
  ++dep_walk_work_nodes_visited[bucket];

  bucket = (consumed_time - quota) / (quota / TIME_INCREMENTS);
  bucket += N_TIME_BUCKETS / 2;
  bucket = (bucket < 0 ? 0 : bucket);
  bucket = (bucket > N_TIME_BUCKETS - 1 ? N_TIME_BUCKETS - 1 : bucket);
  ++dep_walk_work_time_taken[bucket];

  ++dep_walk_sleep_lengths[sleep];

  return (dep_walk_sleep_duration[sleep]);
}

/**
 * Events sent to the DEP walk process
 */
typedef enum dep_walk_process_event_t_
{
  DEP_WALK_PROCESS_EVENT_DATA,
  DEP_WALK_PROCESS_EVENT_ENABLE,
  DEP_WALK_PROCESS_EVENT_DISABLE,
} dep_walk_process_event;

/**
 * @brief The 'dep-walk' process's main loop.
 */
static uword
dep_walk_process (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *f)
{
  uword event_type, *event_data = 0;
  f64 sleep_time;
  int enabled;

  enabled = 1;
  sleep_time = dep_walk_sleep_duration[DEP_WALK_SHORT_SLEEP];

  while (1)
    {
      /*
       * the feature to disable/enable this walk process is only
       * for testing purposes
       */
      if (enabled)
	{
	  vlib_process_wait_for_event_or_clock (vm, sleep_time);
	}
      else
	{
	  vlib_process_wait_for_event (vm);
	}

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      switch (event_type)
	{
	case DEP_WALK_PROCESS_EVENT_ENABLE:
	  enabled = 1;
	  break;
	case DEP_WALK_PROCESS_EVENT_DISABLE:
	  enabled = 0;
	  break;
	default:
	  break;
	}

      if (enabled)
	{
	  sleep_time = dep_walk_process_queues (vm, quota);
	}
    }

  /*
   * Unreached
   */
  ASSERT (!"WTF");
  return 0;
}

VLIB_REGISTER_NODE (dep_walk_process_node, static) = {
  .function = dep_walk_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "dep-walk",
};

/**
 * @brief Allocate a new walk object
 */
static dep_walk_t *
dep_walk_alloc (dep_type_t parent_type, dep_index_t parent_index,
		dep_walk_flags_t flags, dep_back_walk_ctx_t *ctx)
{
  dep_walk_t *dwalk;

  pool_get (dep_walk_pool, dwalk);

  dep_init (&dwalk->dw_node, DEP_TYPE_WALK);

  dwalk->dw_flags = flags;
  dwalk->dw_dep_sibling = DEP_INDEX_INVALID;
  dwalk->dw_prio_sibling = DEP_INDEX_INVALID;
  dwalk->dw_parent.dp_index = parent_index;
  dwalk->dw_parent.dp_type = parent_type;
  dwalk->dw_ctx = NULL;
  dwalk->dw_start_time = vlib_time_now (vlib_get_main ());
  dwalk->dw_n_visits = 0;

  /*
   * make a copy of the backwalk context so the depth count remains
   * the same for each sibling visitsed. This is important in the case
   * where a parent has a loop via one child, but all the others are not.
   * if the looped child were visited first, the depth count would exceed, the
   * max and the walk would terminate before it reached the other siblings.
   */
  vec_add1 (dwalk->dw_ctx, *ctx);

  return (dwalk);
}

/**
 * @brief Enqueue a walk onto the appropriate priority queue. Then signal
 * the background process there is work to do.
 */
static u32
dep_walk_prio_queue_enquue (dep_walk_priority_t prio, dep_walk_t *dwalk)
{
  u32 sibling;

  sibling = dep_list_push_front (dep_walk_queues.dwqs_queues[prio].dwq_queue,
				 0, DEP_TYPE_WALK, dep_walk_get_index (dwalk));
  dep_walk_queues.dwqs_queues[prio].dwq_stats[DEP_WALK_SCHEDULED]++;

  /*
   * poke the dep-walk process to perform the async walk.
   * we are not passing it specific data, hence the last two args,
   * the process will drain the queues
   */
  vlib_process_signal_event (vlib_get_main (), dep_walk_process_node.index,
			     DEP_WALK_PROCESS_EVENT_DATA, 0);

  return (sibling);
}

void
dep_walk_async (dep_type_t parent_type, dep_index_t parent_index,
		dep_walk_priority_t prio, dep_back_walk_ctx_t *ctx)
{
  dep_walk_t *dwalk;

  if (DEP_GRAPH_MAX_DEPTH < ++ctx->dbw_depth)
    {
      /*
       * The walk has reached the maximum depth. there is a loop in the graph.
       * bail.
       */
      return;
    }
  if (0 == dep_get_n_children (parent_type, parent_index))
    {
      /*
       * no children to walk - quit now
       */
      return;
    }
  if (ctx->dbw_flags & DEP_BW_FLAG_FORCE_SYNC)
    {
      /*
       * the originator of the walk wanted it to be synchronous, but the
       * parent object chose async - denied.
       */
      return (dep_walk_sync (parent_type, parent_index, ctx));
    }

  dwalk = dep_walk_alloc (parent_type, parent_index, DEP_WALK_FLAG_ASYNC, ctx);

  dwalk->dw_dep_sibling = dep_child_add (
    parent_type, parent_index, DEP_TYPE_WALK, dep_walk_get_index (dwalk));

  dwalk->dw_prio_sibling = dep_walk_prio_queue_enquue (prio, dwalk);

  DEP_WALK_DBG (dwalk, "async-start: %U", format_dep_bw_reason,
		ctx->dbw_reason);
}

/**
 * @brief Back walk all the children of a DEP node.
 *
 * note this is a synchronous depth first walk. Children visited may propagate
 * the walk to their children. Other children node types may not propagate,
 * synchronously but instead queue the walk for later async completion.
 */
void
dep_walk_sync (dep_type_t parent_type, dep_index_t parent_index,
	       dep_back_walk_ctx_t *ctx)
{
  dep_walk_advance_rc_t rc;
  dep_index_t dwi;
  dep_walk_t *dwalk;

  if (DEP_GRAPH_MAX_DEPTH < ++ctx->dbw_depth)
    {
      /*
       * The walk has reached the maximum depth. there is a loop in the graph.
       * bail.
       */
      return;
    }
  if (0 == dep_get_n_children (parent_type, parent_index))
    {
      /*
       * no children to walk - quit now
       */
      return;
    }

  dwalk = dep_walk_alloc (parent_type, parent_index, DEP_WALK_FLAG_SYNC, ctx);

  dwalk->dw_dep_sibling = dep_child_add (
    parent_type, parent_index, DEP_TYPE_WALK, dep_walk_get_index (dwalk));
  dwi = dep_walk_get_index (dwalk);
  DEP_WALK_DBG (dwalk, "sync-start: %U", format_dep_bw_reason,
		ctx->dbw_reason);

  while (1)
    {
      /*
       * set this walk as executing
       */
      dwalk->dw_flags |= DEP_WALK_FLAG_EXECUTING;

      do
	{
	  rc = dep_walk_advance (dwi);
	}
      while (DEP_WALK_ADVANCE_MORE == rc);

      /*
       * this walk function is re-entrant - walks can spawn walks.
       * dep_walk_t objects come from a pool, so they can realloc. we need
       * to re-fetch from said pool at the appropriate times.
       */
      dwalk = dep_walk_get (dwi);

      if (DEP_WALK_ADVANCE_MERGE == rc)
	{
	  /*
	   * this sync walk merged with an walk in front.
	   * by reqeusting a sync walk the client wanted all children walked,
	   * so we ditch the walk object in hand and continue with the one
	   * we merged into
	   */
	  dep_ptr_t merged_walk;

	  dep_list_elt_get_next (dwalk->dw_dep_sibling, &merged_walk);

	  ASSERT (DEP_INDEX_INVALID != merged_walk.dp_index);
	  ASSERT (DEP_TYPE_WALK == merged_walk.dp_type);

	  dep_walk_destroy (dwi);

	  dwi = merged_walk.dp_index;
	  dwalk = dep_walk_get (dwi);

	  if (DEP_WALK_FLAG_EXECUTING & dwalk->dw_flags)
	    {
	      /*
	       * we are executing a sync walk, and we have met with another
	       * walk that is also executing. since only one walk executs at
	       * once (there is no multi-threading) this implies we have met
	       * ourselves and hence the is a loop in the graph. This function
	       * is re-entrant, so the walk object we met is being acted on in
	       * a stack frame below this one. We must therefore not continue
	       * with it now, but let the stack unwind and along the
	       * appropriate frame to read the depth count and bail.
	       */
	      DEP_WALK_DBG (dwalk, "sync-stop: %U", format_dep_bw_reason,
			    ctx->dbw_reason);

	      dwalk = NULL;
	      break;
	    }
	}
      else
	{
	  /*
	   * the walk reached the end of the depdency list.
	   */
	  break;
	}
    }

  if (NULL != dwalk)
    {
      DEP_WALK_DBG (dwalk, "sync-stop: %U", format_dep_bw_reason,
		    ctx->dbw_reason);
      dep_walk_destroy (dwi);
    }
}

static dep_t *
dep_walk_get_node (dep_index_t index)
{
  dep_walk_t *dwalk;

  dwalk = dep_walk_get (index);

  return (&(dwalk->dw_node));
}

/**
 * Walk objects are not parents, nor are they locked.
 * are no-ops
 */
static void
dep_walk_last_lock_gone (dep_t *node)
{
  ASSERT (0);
}

static dep_walk_t *
dep_walk_get_from_node (dep_t *node)
{
  return (
    (dep_walk_t *) (((char *) node) - STRUCT_OFFSET_OF (dep_walk_t, dw_node)));
}

/**
 * @brief Another back walk has reach this walk.
 * Megre them so there is only one left. It is this node being
 * visited that will remain, so copy or merge the context onto it.
 */
static dep_back_walk_rc_t
dep_walk_back_walk_notify (dep_t *node, dep_back_walk_ctx_t *ctx)
{
  dep_back_walk_ctx_t *last;
  dep_walk_t *dwalk;

  dwalk = dep_walk_get_from_node (node);

  /*
   * check whether the walk context can be merged with the most recent.
   * the most recent was the one last added and is thus at the back of the
   * vector. we can merge walks if the reason for the walk is the same.
   */
  last = vec_end (dwalk->dw_ctx) - 1;

  if (last->dbw_reason == ctx->dbw_reason)
    {
      /*
       * copy the largest of the depth values. in the presence of a loop,
       * the same walk will merge with itself. if we take the smaller depth
       * then it will never end.
       */
      last->dbw_depth =
	((last->dbw_depth >= ctx->dbw_depth) ? last->dbw_depth :
						     ctx->dbw_depth);
    }
  else
    {
      /*
       * walks could not be merged, this means that the walk infront needs to
       * perform different action to this one that has caught up. the one in
       * front was scheduled first so append the new walk context to the back
       * of the list.
       */
      vec_add1 (dwalk->dw_ctx, *ctx);
    }

  return (DEP_BACK_WALK_MERGE);
}

/**
 * The DEP walk's graph node virtual function table
 */
static const dep_vft_t dep_walk_vft = {
  .dv_get = dep_walk_get_node,
  .dv_last_lock = dep_walk_last_lock_gone,
  .dv_back_walk = dep_walk_back_walk_notify,
};

static u8 *
format_dep_walk (u8 *s, va_list *ap)
{
  dep_index_t dwi = va_arg (*ap, dep_index_t);
  dep_walk_t *dwalk;

  dwalk = dep_walk_get (dwi);

  return (format (s, "[@%d] parent:{%s:%d} visits:%d flags:%d", dwi,
		  dep_type_get_name (dwalk->dw_parent.dp_type),
		  dwalk->dw_parent.dp_index, dwalk->dw_n_visits,
		  dwalk->dw_flags));
}

u8 *
format_dep_bw_reason (u8 *s, va_list *args)
{
  dep_bw_reason_flag_t flag = va_arg (*args, int);

  if (0 == flag)
    return (format (s, "none"));
#define _(a, b)                                                               \
  if (flag & DEP_BW_REASON_FLAG_##a)                                          \
    s = format (s, "%s", b);
  foreach_dep_back_walk_reason
#undef _

    return (s);
}

static clib_error_t *
dep_walk_show (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd)
{
  dep_walk_queue_stats_t wqs;
  dep_walk_priority_t prio;
  dep_ptr_t sibling;
  dep_index_t dwi;
  dep_walk_t *dwalk;
  int more_elts, ii;
  u8 *s = NULL;

#define USEC 1000000
  vlib_cli_output (vm, "DEP Walk Quota = %.2fusec:", quota * USEC);
  vlib_cli_output (vm, "DEP Walk queues:");

  FOR_EACH_DEP_WALK_PRIORITY (prio)
  {
    vlib_cli_output (vm, " %U priority queue:", format_dep_walk_priority,
		     prio);
    vlib_cli_output (vm, "  Stats: ");

    FOR_EACH_DEP_WALK_QUEUE_STATS (wqs)
    {
      vlib_cli_output (vm, "    %U:%d", format_dep_walk_queue_stats, wqs,
		       dep_walk_queues.dwqs_queues[prio].dwq_stats[wqs]);
    }
    vlib_cli_output (
      vm, "  Occupancy:%d",
      dep_list_get_size (dep_walk_queues.dwqs_queues[prio].dwq_queue));

    more_elts = dep_list_get_front (
      dep_walk_queues.dwqs_queues[prio].dwq_queue, &sibling);

    while (more_elts)
      {
	ASSERT (DEP_INDEX_INVALID != sibling.dp_index);
	ASSERT (DEP_TYPE_WALK == sibling.dp_type);

	dwi = sibling.dp_index;
	dwalk = dep_walk_get (dwi);

	vlib_cli_output (vm, "  %U", format_dep_walk, dwi);

	more_elts = dep_list_elt_get_next (dwalk->dw_prio_sibling, &sibling);
      }
  }

  vlib_cli_output (vm, "Histogram Statistics:");
  vlib_cli_output (vm, " Number of Elements visit per-quota:");
  for (ii = 0; ii < N_ELTS_BUCKETS; ii++)
    {
      if (0 != dep_walk_work_nodes_visited[ii])
	s = format (s, "%d:%d ", (ii * dep_walk_work_nodes_visited_incr),
		    dep_walk_work_nodes_visited[ii]);
    }
  vlib_cli_output (vm, "  %v", s);
  vec_free (s);

  vlib_cli_output (vm,
		   " Time consumed per-quota (Quota=%f usec):", quota * USEC);
  s = format (s, "0:%d ", dep_walk_work_time_taken[0]);
  for (ii = 1; ii < N_TIME_BUCKETS; ii++)
    {
      if (0 != dep_walk_work_time_taken[ii])
	s = format (
	  s, "%d:%d ",
	  (u32) (
	    (((ii - N_TIME_BUCKETS / 2) * (quota / TIME_INCREMENTS)) + quota) *
	    USEC),
	  dep_walk_work_time_taken[ii]);
    }
  vlib_cli_output (vm, "  %v", s);
  vec_free (s);

  vlib_cli_output (vm, " Sleep Types:");
  vlib_cli_output (vm, "  Short  Long:");
  vlib_cli_output (vm,
		   "  %d %d:", dep_walk_sleep_lengths[DEP_WALK_SHORT_SLEEP],
		   dep_walk_sleep_lengths[DEP_WALK_LONG_SLEEP]);

  vlib_cli_output (vm, " Number of Elements visited per-walk:");
  for (ii = 0; ii < HISTOGRAM_VISITS_PER_WALK_N_BUCKETS; ii++)
    {
      if (0 != dep_walk_hist_vists_per_walk[ii])
	s = format (s, "%d:%d ", ii * HISTOGRAM_VISITS_PER_WALK_INCR,
		    dep_walk_hist_vists_per_walk[ii]);
    }
  vlib_cli_output (vm, "  %v", s);
  vec_free (s);

  vlib_cli_output (vm, "Brief History (last %d walks):", HISTORY_N_WALKS);
  ii = history_last_walk_pos - 1;
  if (ii < 0)
    ii = HISTORY_N_WALKS - 1;

  while (ii != history_last_walk_pos)
    {
      if (0 != dep_walk_history[ii].dwh_reason[0])
	{
	  u8 *s = NULL;
	  u32 jj;

	  s = format (
	    s, "[@%d]: %s:%d visits:%d duration:%.2f completed:%.2f ", ii,
	    dep_type_get_name (dep_walk_history[ii].dwh_parent.dp_type),
	    dep_walk_history[ii].dwh_parent.dp_index,
	    dep_walk_history[ii].dwh_n_visits,
	    dep_walk_history[ii].dwh_duration,
	    dep_walk_history[ii].dwh_completed);
	  if (DEP_WALK_FLAG_SYNC & dep_walk_history[ii].dwh_flags)
	    s = format (s, "sync, ");
	  if (DEP_WALK_FLAG_ASYNC & dep_walk_history[ii].dwh_flags)
	    s = format (s, "async, ");

	  s = format (s, "reason:");
	  jj = 0;
	  while (0 != dep_walk_history[ii].dwh_reason[jj])
	    {
	      s = format (s, "%U,", format_dep_bw_reason,
			  dep_walk_history[ii].dwh_reason[jj]);
	      jj++;
	    }
	  vlib_cli_output (vm, "%v", s);
	}

      ii--;
      if (ii < 0)
	ii = HISTORY_N_WALKS - 1;
    }

  return (NULL);
}

VLIB_CLI_COMMAND (dep_walk_show_command, static) = {
  .path = "show dep walk",
  .short_help = "show dep walk",
  .function = dep_walk_show,
};

static clib_error_t *
dep_walk_set_quota (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  clib_error_t *error = NULL;
  f64 new_quota;

  if (unformat (input, "%f", &new_quota))
    {
      quota = new_quota;
    }
  else
    {
      error = clib_error_return (0, "Pass a float value");
    }

  return (error);
}

VLIB_CLI_COMMAND (dep_walk_set_quota_command, static) = {
  .path = "set dep walk quota",
  .short_help = "set dep walk quota",
  .function = dep_walk_set_quota,
};

static clib_error_t *
dep_walk_set_histogram_elements_size (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  clib_error_t *error = NULL;
  u32 new;

  if (unformat (input, "%d", &new))
    {
      dep_walk_work_nodes_visited_incr = new;
    }
  else
    {
      error = clib_error_return (0, "Pass an int value");
    }

  return (error);
}

VLIB_CLI_COMMAND (dep_walk_set_histogram_elements_size_command, static) = {
  .path = "set dep walk histogram elements size",
  .short_help = "set dep walk histogram elements size",
  .function = dep_walk_set_histogram_elements_size,
};

static clib_error_t *
dep_walk_clear (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  clib_memset (dep_walk_hist_vists_per_walk, 0,
	       sizeof (dep_walk_hist_vists_per_walk));
  clib_memset (dep_walk_history, 0, sizeof (dep_walk_history));
  clib_memset (dep_walk_work_time_taken, 0, sizeof (dep_walk_work_time_taken));
  clib_memset (dep_walk_work_nodes_visited, 0,
	       sizeof (dep_walk_work_nodes_visited));
  clib_memset (dep_walk_sleep_lengths, 0, sizeof (dep_walk_sleep_lengths));

  return (NULL);
}

VLIB_CLI_COMMAND (dep_walk_clear_command, static) = {
  .path = "clear dep walk",
  .short_help = "clear dep walk",
  .function = dep_walk_clear,
};

void
dep_walk_process_enable (void)
{
  vlib_process_signal_event (vlib_get_main (), dep_walk_process_node.index,
			     DEP_WALK_PROCESS_EVENT_ENABLE, 0);
}

void
dep_walk_process_disable (void)
{
  vlib_process_signal_event (vlib_get_main (), dep_walk_process_node.index,
			     DEP_WALK_PROCESS_EVENT_DISABLE, 0);
}

static clib_error_t *
dep_walk_process_enable_disable (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  if (unformat (input, "enable"))
    {
      dep_walk_process_enable ();
    }
  else if (unformat (input, "disable"))
    {
      dep_walk_process_disable ();
    }
  else
    {
      return clib_error_return (0, "choose enable or disable");
    }
  return (NULL);
}

VLIB_CLI_COMMAND (dep_walk_process_command, static) = {
  .path = "test dep-walk-process",
  .short_help = "test dep-walk-process [enable|disable]",
  .function = dep_walk_process_enable_disable,
};

static clib_error_t *
dep_walk_module_init (vlib_main_t *vm)
{
  dep_walk_priority_t prio;

  FOR_EACH_DEP_WALK_PRIORITY (prio)
  {
    dep_walk_queues.dwqs_queues[prio].dwq_queue = dep_list_create ();
  }

  DEP_TYPE_WALK = dep_register_type ("walk", &dep_walk_vft);
  dep_walk_logger = vlib_log_register_class ("dep", "walk");

  return (NULL);
}

VLIB_INIT_FUNCTION (dep_walk_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
