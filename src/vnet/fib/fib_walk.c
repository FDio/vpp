/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/fib/fib_walk.h>
#include <vnet/fib/fib_node_list.h>

vlib_log_class_t fib_walk_logger;

/**
 * The flags on a walk
 */
typedef enum fib_walk_flags_t_
{
    /**
     * A synchronous walk.
     * This walk will run to completion, i.e. visit ALL the children.
     * It is a depth first traversal of the graph.
     */
    FIB_WALK_FLAG_SYNC = (1 << 0),
    /**
     * An asynchronous walk.
     * This walk will be scheduled to run in the background. It will thus visits
     * the children at a later point in time.
     * It is a depth first traversal of the graph.
     */
    FIB_WALK_FLAG_ASYNC = (1 << 1),
    /**
     * An indication that the walk is currently executing.
     */
    FIB_WALK_FLAG_EXECUTING = (1 << 2),
} fib_walk_flags_t;

/**
 * A representation of a graph walk from a parent object to its children
 */
typedef struct fib_walk_t_
{
    /**
     * FIB node linkage. This object is not in the FIB object graph,
     * but it is present in other node's dependency lists, so it needs to
     * be pointerable to.
     */
    fib_node_t fw_node;

    /**
     * the walk's flags
     */
    fib_walk_flags_t fw_flags;

    /**
     * Sibling index in the dependency list
     */
    u32 fw_dep_sibling;

    /**
     * Sibling index in the list of all walks
     */
    u32 fw_prio_sibling;

    /**
     * Pointer to the node whose dependants this walk is walking
     */
    fib_node_ptr_t fw_parent;

    /**
     * Number of nodes visited by this walk. saved for debugging purposes.
     */
    u32 fw_n_visits;

    /**
     * Time the walk started
     */
    f64 fw_start_time;

    /**
     * The reasons this walk is occuring.
     * This is a vector ordered in time. The reasons and the front were started
     * first, and so should be acted first when a node is visited.
     */
    fib_node_back_walk_ctx_t *fw_ctx;
} fib_walk_t;

/**
 * @brief The pool of all walk objects
 */
static fib_walk_t *fib_walk_pool;

/**
 * Statistics maintained per-walk queue
 */
typedef enum fib_walk_queue_stats_t_
{
    FIB_WALK_SCHEDULED,
    FIB_WALK_COMPLETED,
} fib_walk_queue_stats_t;
#define FIB_WALK_QUEUE_STATS_NUM ((fib_walk_queue_stats_t)(FIB_WALK_COMPLETED+1))

#define FIB_WALK_QUEUE_STATS {           \
    [FIB_WALK_SCHEDULED] = "scheduled",  \
    [FIB_WALK_COMPLETED] = "completed",  \
}

#define FOR_EACH_FIB_WALK_QUEUE_STATS(_wqs)   \
    for ((_wqs) = FIB_WALK_SCHEDULED;         \
	 (_wqs) < FIB_WALK_QUEUE_STATS_NUM;   \
	 (_wqs)++)

/**
 * The names of the walk stats
 */
static const char * const fib_walk_queue_stats_names[] = FIB_WALK_QUEUE_STATS;
/**
 * The names of the walk reasons
 */
static const char * const fib_node_bw_reason_names[] = FIB_NODE_BW_REASONS;

/**
 * A representation of one queue of walk
 */
typedef struct fib_walk_queue_t_
{
    /**
     * Qeuee stats
     */
    u64 fwq_stats[FIB_WALK_QUEUE_STATS_NUM];

    /**
     * The node list which acts as the queue
     */
    fib_node_list_t fwq_queue;
} fib_walk_queue_t;

/**
 * A set of priority queues for outstanding walks
 */
typedef struct fib_walk_queues_t_
{
    fib_walk_queue_t fwqs_queues[FIB_WALK_PRIORITY_NUM];
} fib_walk_queues_t;

/**
 * The global queues of outstanding walks
 */
static fib_walk_queues_t fib_walk_queues;

/**
 * The names of the walk priorities
 */
static const char * const fib_walk_priority_names[] = FIB_WALK_PRIORITIES;

/**
 * @brief Histogram stats on the lenths of each walk in elemenets visited.
 * Store upto 1<<23 elements in increments of 1<<10
 */
#define HISTOGRAM_VISITS_PER_WALK_MAX (1<<23)
#define HISTOGRAM_VISITS_PER_WALK_INCR (1<<10)
#define HISTOGRAM_VISITS_PER_WALK_N_BUCKETS \
    (HISTOGRAM_VISITS_PER_WALK_MAX/HISTOGRAM_VISITS_PER_WALK_INCR)
static u64 fib_walk_hist_vists_per_walk[HISTOGRAM_VISITS_PER_WALK_N_BUCKETS];

/**
 * @brief History of state for the last 128 walks
 */
#define HISTORY_N_WALKS 128
#define MAX_HISTORY_REASONS 16
static u32 history_last_walk_pos;
typedef struct fib_walk_history_t_ {
    u32 fwh_n_visits;
    f64 fwh_duration;
    f64 fwh_completed;
    fib_node_ptr_t fwh_parent;
    fib_walk_flags_t fwh_flags;
    fib_node_bw_reason_flag_t fwh_reason[MAX_HISTORY_REASONS];
} fib_walk_history_t;
static fib_walk_history_t fib_walk_history[HISTORY_N_WALKS];

static u8* format_fib_walk (u8* s, va_list *ap);

#define FIB_WALK_DBG(_walk, _fmt, _args...)                     \
{                                                               \
    vlib_log_debug(fib_walk_logger,                             \
                   "[%U]:" _fmt,                                \
                   format_fib_walk,                             \
                   fib_walk_get_index(_walk),                   \
                   ##_args);                                    \
}

u8*
format_fib_walk_priority (u8 *s, va_list *ap)
{
    fib_walk_priority_t prio = va_arg(*ap, fib_walk_priority_t);

    ASSERT(prio < FIB_WALK_PRIORITY_NUM);

    return (format(s, "%s", fib_walk_priority_names[prio]));
}
static u8*
format_fib_walk_queue_stats (u8 *s, va_list *ap)
{
    fib_walk_queue_stats_t wqs = va_arg(*ap, fib_walk_queue_stats_t);

    ASSERT(wqs < FIB_WALK_QUEUE_STATS_NUM);

    return (format(s, "%s", fib_walk_queue_stats_names[wqs]));
}

static index_t
fib_walk_get_index (fib_walk_t *fwalk)
{
    return (fwalk - fib_walk_pool);
}

static fib_walk_t *
fib_walk_get (index_t fwi)
{
    return (pool_elt_at_index(fib_walk_pool, fwi));
}

/*
 * not static so it can be used in the unit tests
 */
u32
fib_walk_queue_get_size (fib_walk_priority_t prio)
{
    return (fib_node_list_get_size(fib_walk_queues.fwqs_queues[prio].fwq_queue));
}

static fib_node_index_t
fib_walk_queue_get_front (fib_walk_priority_t prio)
{
    fib_node_ptr_t wp;

    fib_node_list_get_front(fib_walk_queues.fwqs_queues[prio].fwq_queue, &wp);

    return (wp.fnp_index);
}

static void
fib_walk_destroy (index_t fwi)
{
    fib_walk_t *fwalk;
    u32 bucket, ii;

    fwalk = fib_walk_get(fwi);

    if (FIB_NODE_INDEX_INVALID != fwalk->fw_prio_sibling)
    {
	fib_node_list_elt_remove(fwalk->fw_prio_sibling);
    }
    fib_node_child_remove(fwalk->fw_parent.fnp_type,
			  fwalk->fw_parent.fnp_index,
			  fwalk->fw_dep_sibling);

    /*
     * refetch the walk object. More walks could have been spawned as a result
     * of releasing the lock on the parent.
     */
    fwalk = fib_walk_get(fwi);

    /*
     * add the stats to the continuous histogram collection.
     */
    bucket = (fwalk->fw_n_visits / HISTOGRAM_VISITS_PER_WALK_INCR);
    bucket = (bucket >= HISTOGRAM_VISITS_PER_WALK_N_BUCKETS ?
	      HISTOGRAM_VISITS_PER_WALK_N_BUCKETS - 1 :
	      bucket);
    fib_walk_hist_vists_per_walk[bucket]++;

    /*
     * save stats to the recent history
     */

    fib_walk_history[history_last_walk_pos].fwh_n_visits =
	fwalk->fw_n_visits;
    fib_walk_history[history_last_walk_pos].fwh_completed =
	vlib_time_now(vlib_get_main());
    fib_walk_history[history_last_walk_pos].fwh_duration =
	fib_walk_history[history_last_walk_pos].fwh_completed -
        fwalk->fw_start_time;
    fib_walk_history[history_last_walk_pos].fwh_parent =
	fwalk->fw_parent;
    fib_walk_history[history_last_walk_pos].fwh_flags =
	fwalk->fw_flags;

    vec_foreach_index(ii, fwalk->fw_ctx)
    {
        if (ii < MAX_HISTORY_REASONS)
        {
            fib_walk_history[history_last_walk_pos].fwh_reason[ii] =
                fwalk->fw_ctx[ii].fnbw_reason;
        }
    }

    history_last_walk_pos = (history_last_walk_pos + 1) % HISTORY_N_WALKS;

    fib_node_deinit(&fwalk->fw_node);
    vec_free(fwalk->fw_ctx);
    pool_put(fib_walk_pool, fwalk);
}

/**
 * return code when advancing a walk
 */
typedef enum fib_walk_advance_rc_t_
{
    /**
     * The walk is complete
     */
    FIB_WALK_ADVANCE_DONE,
    /**
     * the walk has more work
     */
    FIB_WALK_ADVANCE_MORE,
    /**
     * The walk merged with the one in front
     */
    FIB_WALK_ADVANCE_MERGE,
} fib_walk_advance_rc_t;

/**
 * @brief Advance the walk one element in its work list
 */
static fib_walk_advance_rc_t
fib_walk_advance (fib_node_index_t fwi)
{
    fib_node_back_walk_rc_t wrc;
    fib_node_ptr_t sibling;
    fib_walk_t *fwalk;
    uint n_ctxs, ii;
    int more_elts;

    /*
     * this walk function is re-entrant - walks acan spawn walks.
     * fib_walk_t objects come from a pool, so they can realloc. we need
     * to retch from said pool at the appropriate times.
     */
    fwalk = fib_walk_get(fwi);

    more_elts = fib_node_list_elt_get_next(fwalk->fw_dep_sibling, &sibling);

    if (more_elts)
    {

        /*
         * loop through the backwalk contexts. This can grow in length
         * as walks on the same object meet each other. Order is preserved so the
         * most recently started walk as at the back of the vector.
         */
        ii = 0;
        n_ctxs = vec_len(fwalk->fw_ctx);

        while (ii < n_ctxs)
        {
            fib_node_back_walk_ctx_t ctx = fwalk->fw_ctx[ii];

	    wrc = fib_node_back_walk_one(&sibling, &ctx);

            ii++;
	    fwalk = fib_walk_get(fwi);
	    fwalk->fw_n_visits++;

	    if (FIB_NODE_BACK_WALK_MERGE == wrc)
	    {
		/*
		 * this walk has merged with the one further along the node's
		 * dependecy list.
		 */
		return (FIB_WALK_ADVANCE_MERGE);
	    }

            /*
             * re-evaluate the number of backwalk contexts we need to process.
             */
            n_ctxs = vec_len(fwalk->fw_ctx);
	}
	/*
	 * move foward to the next node to visit
	 */
	more_elts = fib_node_list_advance(fwalk->fw_dep_sibling);
    }

    if (more_elts)
    {
	return (FIB_WALK_ADVANCE_MORE);
    }

    return (FIB_WALK_ADVANCE_DONE);
}

/**
 * @brief Enurmerate the times of sleep between walks
 */
typedef enum fib_walk_sleep_type_t_
{
    FIB_WALK_SHORT_SLEEP,
    FIB_WALK_LONG_SLEEP,
} fib_walk_sleep_type_t;

#define FIB_WALK_N_SLEEP (FIB_WALK_LONG_SLEEP+1)

/**
 * @brief Durations for the sleep types
 */
static f64 fib_walk_sleep_duration[] = {
    /**
     * Long sleep when there is no more work, i.e. the queues are empty.
     * This is a sleep (as opposed to a wait for event) just to be sure we
     * are not missing events by sleeping forever.
     */
    [FIB_WALK_LONG_SLEEP] = 2,

    /**
     * Short sleep. There is work left in the queues. We are yielding the CPU
     * momentarily.
     */
    [FIB_WALK_SHORT_SLEEP] = 1e-8,
};

/**
 * @brief The time quota for a walk. When more than this amount of time is
 * spent, the walk process will yield.
 */
static f64 quota = 1e-4;

/**
 * Histogram on the amount of work done (in msecs) in each walk
 */
#define N_TIME_BUCKETS 128
#define TIME_INCREMENTS (N_TIME_BUCKETS/2)
static u64 fib_walk_work_time_taken[N_TIME_BUCKETS];

/**
 * Histogram on the number of nodes visted in each quota
 */
#define N_ELTS_BUCKETS 128
static u32 fib_walk_work_nodes_visited_incr = 2;
static u64 fib_walk_work_nodes_visited[N_ELTS_BUCKETS];

/**
 * Histogram of the sleep lengths
 */
static u64 fib_walk_sleep_lengths[2];

/**
 * @brief Service the queues
 * This is not declared static so that it can be unit tested - i know i know...
 */
f64
fib_walk_process_queues (vlib_main_t * vm,
			 const f64 quota)
{
    f64 start_time, consumed_time;
    fib_walk_sleep_type_t sleep;
    fib_walk_priority_t prio;
    fib_walk_advance_rc_t rc;
    fib_node_index_t fwi;
    fib_walk_t *fwalk;
    u32 n_elts;
    i32 bucket;

    consumed_time = 0;
    start_time = vlib_time_now(vm);
    n_elts = 0;

    FOR_EACH_FIB_WALK_PRIORITY(prio)
    {
	while (0 != fib_walk_queue_get_size(prio))
	{
	    fwi = fib_walk_queue_get_front(prio);

	    /*
	     * set this walk as executing
	     */
	    fwalk = fib_walk_get(fwi);
	    fwalk->fw_flags |= FIB_WALK_FLAG_EXECUTING;

	    do
	    {
		rc = fib_walk_advance(fwi);
		n_elts++;
		consumed_time = (vlib_time_now(vm) - start_time);
	    } while ((consumed_time < quota) &&
		     (FIB_WALK_ADVANCE_MORE == rc));

	    /*
	     * if this walk has no more work then pop it from the queue
	     * and move on to the next.
	     */
	    if (FIB_WALK_ADVANCE_MORE != rc)
	    {
                fib_walk_destroy(fwi);
		fib_walk_queues.fwqs_queues[prio].fwq_stats[FIB_WALK_COMPLETED]++;
	    }
	    else
	    {
		/*
		 * passed our work quota. sleep time.
		 */
		fwalk = fib_walk_get(fwi);
		fwalk->fw_flags &= ~FIB_WALK_FLAG_EXECUTING;
		sleep = FIB_WALK_SHORT_SLEEP;
		goto that_will_do_for_now;
	    }
	}
    }
    /*
     * got to the end of all the work
     */
    sleep = FIB_WALK_LONG_SLEEP;

that_will_do_for_now:

    /*
     * collect the stats:
     *  - for the number of nodes visited we store 128 increments
     *  - for the time consumed we store quota/TIME_INCREMENTS increments.
     */
    bucket = ((n_elts/fib_walk_work_nodes_visited_incr) > N_ELTS_BUCKETS ?
	      N_ELTS_BUCKETS-1 :
	      n_elts/fib_walk_work_nodes_visited_incr);
    ++fib_walk_work_nodes_visited[bucket];

    bucket = (consumed_time - quota) / (quota / TIME_INCREMENTS);
    bucket += N_TIME_BUCKETS/2;
    bucket = (bucket < 0 ? 0 : bucket);
    bucket = (bucket > N_TIME_BUCKETS-1 ? N_TIME_BUCKETS-1 : bucket);
    ++fib_walk_work_time_taken[bucket];

    ++fib_walk_sleep_lengths[sleep];

    return (fib_walk_sleep_duration[sleep]);
}

/**
 * Events sent to the FIB walk process
 */
typedef enum fib_walk_process_event_t_
{
    FIB_WALK_PROCESS_EVENT_DATA,
    FIB_WALK_PROCESS_EVENT_ENABLE,
    FIB_WALK_PROCESS_EVENT_DISABLE,
} fib_walk_process_event;

/**
 * @brief The 'fib-walk' process's main loop.
 */
static uword
fib_walk_process (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * f)
{
    uword event_type, *event_data = 0;
    f64 sleep_time;
    int enabled;

    enabled = 1;
    sleep_time = fib_walk_sleep_duration[FIB_WALK_SHORT_SLEEP];

    while (1)
    {
        /*
         * the feature to disable/enable this walk process is only
         * for testing purposes
         */
        if (enabled)
        {
            vlib_process_wait_for_event_or_clock(vm, sleep_time);
        }
        else
        {
            vlib_process_wait_for_event(vm);
        }

        event_type = vlib_process_get_events(vm, &event_data);
        vec_reset_length(event_data);

        switch (event_type)
	{
	case FIB_WALK_PROCESS_EVENT_ENABLE:
            enabled = 1;
            break;
	case FIB_WALK_PROCESS_EVENT_DISABLE:
            enabled = 0;
            break;
	default:
            break;
	}

        if (enabled)
        {
            sleep_time = fib_walk_process_queues(vm, quota);
        }
    }

    /*
     * Unreached
     */
    ASSERT(!"WTF");
    return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (fib_walk_process_node,static) = {
    .function = fib_walk_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "fib-walk",
};
/* *INDENT-ON* */

/**
 * @brief Allocate a new walk object
 */
static fib_walk_t *
fib_walk_alloc (fib_node_type_t parent_type,
		fib_node_index_t parent_index,
		fib_walk_flags_t flags,
		fib_node_back_walk_ctx_t *ctx)
{
    fib_walk_t *fwalk;

    pool_get(fib_walk_pool, fwalk);

    fib_node_init(&fwalk->fw_node, FIB_NODE_TYPE_WALK);

    fwalk->fw_flags = flags;
    fwalk->fw_dep_sibling  = FIB_NODE_INDEX_INVALID;
    fwalk->fw_prio_sibling = FIB_NODE_INDEX_INVALID;
    fwalk->fw_parent.fnp_index = parent_index;
    fwalk->fw_parent.fnp_type = parent_type;
    fwalk->fw_ctx = NULL;
    fwalk->fw_start_time = vlib_time_now(vlib_get_main());
    fwalk->fw_n_visits = 0;

    /*
     * make a copy of the backwalk context so the depth count remains
     * the same for each sibling visitsed. This is important in the case
     * where a parent has a loop via one child, but all the others are not.
     * if the looped child were visited first, the depth count would exceed, the
     * max and the walk would terminate before it reached the other siblings.
     */
    vec_add1(fwalk->fw_ctx, *ctx);

    return (fwalk);
}

/**
 * @brief Enqueue a walk onto the appropriate priority queue. Then signal
 * the background process there is work to do.
 */
static index_t
fib_walk_prio_queue_enquue (fib_walk_priority_t prio,
			    fib_walk_t *fwalk)
{
    index_t sibling;

    sibling = fib_node_list_push_front(fib_walk_queues.fwqs_queues[prio].fwq_queue,
				       0,
				       FIB_NODE_TYPE_WALK,
				       fib_walk_get_index(fwalk));
    fib_walk_queues.fwqs_queues[prio].fwq_stats[FIB_WALK_SCHEDULED]++;

    /*
     * poke the fib-walk process to perform the async walk.
     * we are not passing it specific data, hence the last two args,
     * the process will drain the queues
     */
    vlib_process_signal_event(vlib_get_main(),
			      fib_walk_process_node.index,
			      FIB_WALK_PROCESS_EVENT_DATA,
			      0);

    return (sibling);
}

void
fib_walk_async (fib_node_type_t parent_type,
		fib_node_index_t parent_index,
		fib_walk_priority_t prio,
		fib_node_back_walk_ctx_t *ctx)
{
    fib_walk_t *fwalk;

    if (FIB_NODE_GRAPH_MAX_DEPTH < ++ctx->fnbw_depth)
    {
	/*
	 * The walk has reached the maximum depth. there is a loop in the graph.
	 * bail.
	 */
	ctx->fnbw_depth--;
	return;
    }
    if (0 == fib_node_get_n_children(parent_type,
                                     parent_index))
    {
        /*
         * no children to walk - quit now
         */
        ctx->fnbw_depth--;
        return;
    }
    if (ctx->fnbw_flags & FIB_NODE_BW_FLAG_FORCE_SYNC)
    {
        /*
         * the originator of the walk wanted it to be synchronous, but the
         * parent object chose async - denied.
         */
        fib_walk_sync(parent_type, parent_index, ctx);
        ctx->fnbw_depth--;
        return;
    }


    fwalk = fib_walk_alloc(parent_type,
			   parent_index,
			   FIB_WALK_FLAG_ASYNC,
			   ctx);

    fwalk->fw_dep_sibling = fib_node_child_add(parent_type,
					       parent_index,
					       FIB_NODE_TYPE_WALK,
					       fib_walk_get_index(fwalk));

    fwalk->fw_prio_sibling = fib_walk_prio_queue_enquue(prio, fwalk);

    FIB_WALK_DBG(fwalk, "async-start: %U",
                 format_fib_node_bw_reason, ctx->fnbw_reason);
    ctx->fnbw_depth--;
}

/**
 * @brief Back walk all the children of a FIB node.
 *
 * note this is a synchronous depth first walk. Children visited may propagate
 * the walk to their children. Other children node types may not propagate,
 * synchronously but instead queue the walk for later async completion.
 */
void
fib_walk_sync (fib_node_type_t parent_type,
	       fib_node_index_t parent_index,
	       fib_node_back_walk_ctx_t *ctx)
{
    fib_walk_advance_rc_t rc;
    fib_node_index_t fwi;
    fib_walk_t *fwalk;

    if (FIB_NODE_GRAPH_MAX_DEPTH < ++ctx->fnbw_depth)
    {
	/*
	 * The walk has reached the maximum depth. there is a loop in the graph.
	 * bail.
	 */
	ctx->fnbw_depth--;
	return;
    }
    if (0 == fib_node_get_n_children(parent_type,
                                     parent_index))
    {
        /*
         * no children to walk - quit now
         */
        ctx->fnbw_depth--;
        return;
    }

    fwalk = fib_walk_alloc(parent_type,
			   parent_index,
			   FIB_WALK_FLAG_SYNC,
			   ctx);

    fwalk->fw_dep_sibling = fib_node_child_add(parent_type,
					       parent_index,
					       FIB_NODE_TYPE_WALK,
					       fib_walk_get_index(fwalk));
    fwi = fib_walk_get_index(fwalk);
    FIB_WALK_DBG(fwalk, "sync-start: %U",
                 format_fib_node_bw_reason, ctx->fnbw_reason);

    while (1)
    {
	/*
	 * set this walk as executing
	 */
	fwalk->fw_flags |= FIB_WALK_FLAG_EXECUTING;

	do
	{
	    rc = fib_walk_advance(fwi);
	} while (FIB_WALK_ADVANCE_MORE == rc);


	/*
	 * this walk function is re-entrant - walks can spawn walks.
	 * fib_walk_t objects come from a pool, so they can realloc. we need
	 * to re-fetch from said pool at the appropriate times.
	 */
	fwalk = fib_walk_get(fwi);

	if (FIB_WALK_ADVANCE_MERGE == rc)
	{
	    /*
	     * this sync walk merged with an walk in front.
	     * by reqeusting a sync walk the client wanted all children walked,
	     * so we ditch the walk object in hand and continue with the one
	     * we merged into
	     */
	    fib_node_ptr_t merged_walk;

	    fib_node_list_elt_get_next(fwalk->fw_dep_sibling, &merged_walk);

	    ASSERT(FIB_NODE_INDEX_INVALID != merged_walk.fnp_index);
	    ASSERT(FIB_NODE_TYPE_WALK == merged_walk.fnp_type);

	    fib_walk_destroy(fwi);

	    fwi = merged_walk.fnp_index;
	    fwalk = fib_walk_get(fwi);

	    if (FIB_WALK_FLAG_EXECUTING & fwalk->fw_flags)
	    {
		/*
		 * we are executing a sync walk, and we have met with another
		 * walk that is also executing. since only one walk executs at once
		 * (there is no multi-threading) this implies we have met ourselves
		 * and hence the is a loop in the graph.
		 * This function is re-entrant, so the walk object we met is being
		 * acted on in a stack frame below this one. We must therefore not
		 * continue with it now, but let the stack unwind and along the
		 * appropriate frame to read the depth count and bail.
		 */
                FIB_WALK_DBG(fwalk, "sync-stop: %U",
                             format_fib_node_bw_reason,
                             ctx->fnbw_reason);

		fwalk = NULL;
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

    if (NULL != fwalk)
    {
        FIB_WALK_DBG(fwalk, "sync-stop: %U",
                     format_fib_node_bw_reason,
                     ctx->fnbw_reason);
	fib_walk_destroy(fwi);
    }

    ctx->fnbw_depth--;
}

static fib_node_t *
fib_walk_get_node (fib_node_index_t index)
{
    fib_walk_t *fwalk;

    fwalk = fib_walk_get(index);

    return (&(fwalk->fw_node));
}

/**
 * Walk objects are not parents, nor are they locked.
 * are no-ops
 */
static void
fib_walk_last_lock_gone (fib_node_t *node)
{
    ASSERT(0);
}

static fib_walk_t*
fib_walk_get_from_node (fib_node_t *node)
{
    return ((fib_walk_t*)(((char*)node) -
			  STRUCT_OFFSET_OF(fib_walk_t, fw_node)));
}

/**
 * @brief Another back walk has reach this walk.
 * Megre them so there is only one left. It is this node being
 * visited that will remain, so copy or merge the context onto it.
 */
static fib_node_back_walk_rc_t
fib_walk_back_walk_notify (fib_node_t *node,
			   fib_node_back_walk_ctx_t *ctx)
{
    fib_node_back_walk_ctx_t *last;
    fib_walk_t *fwalk;

    fwalk = fib_walk_get_from_node(node);

    /*
     * check whether the walk context can be merged with the most recent.
     * the most recent was the one last added and is thus at the back of the vector.
     * we can merge walks if the reason for the walk is the same.
     */
    last = vec_end(fwalk->fw_ctx) - 1;

    if (last->fnbw_reason == ctx->fnbw_reason)
    {
        /*
         * copy the largest of the depth values. in the presence of a loop,
         * the same walk will merge with itself. if we take the smaller depth
         * then it will never end.
         */
        last->fnbw_depth = ((last->fnbw_depth >= ctx->fnbw_depth) ?
                            last->fnbw_depth :
                            ctx->fnbw_depth);
    }
    else
    {
        /*
         * walks could not be merged, this means that the walk infront needs to
         * perform different action to this one that has caught up. the one in
         * front was scheduled first so append the new walk context to the back
         * of the list.
         */
        vec_add1(fwalk->fw_ctx, *ctx);
    }

    return (FIB_NODE_BACK_WALK_MERGE);
}

/**
 * The FIB walk's graph node virtual function table
 */
static const fib_node_vft_t fib_walk_vft = {
    .fnv_get = fib_walk_get_node,
    .fnv_last_lock = fib_walk_last_lock_gone,
    .fnv_back_walk = fib_walk_back_walk_notify,
};

void
fib_walk_module_init (void)
{
    fib_walk_priority_t prio;

    FOR_EACH_FIB_WALK_PRIORITY(prio)
    {
	fib_walk_queues.fwqs_queues[prio].fwq_queue = fib_node_list_create();
    }

    fib_node_register_type(FIB_NODE_TYPE_WALK, &fib_walk_vft);
    fib_walk_logger = vlib_log_register_class("fib", "walk");
}

static u8*
format_fib_walk (u8* s, va_list *ap)
{
    fib_node_index_t fwi = va_arg(*ap, fib_node_index_t);
    fib_walk_t *fwalk;

    fwalk = fib_walk_get(fwi);

    return (format(s, "[@%d] parent:{%s:%d} visits:%d flags:%d", fwi,
		   fib_node_type_get_name(fwalk->fw_parent.fnp_type),
		   fwalk->fw_parent.fnp_index,
		   fwalk->fw_n_visits,
		   fwalk->fw_flags));
}

u8 *
format_fib_node_bw_reason (u8 *s, va_list *args)
{
    fib_node_bw_reason_flag_t flag = va_arg (*args, int);
    fib_node_back_walk_reason_t reason;

    FOR_EACH_FIB_NODE_BW_REASON(reason) {
        if ((1<<reason) & flag)
            s = format(s, "%s", fib_node_bw_reason_names[reason]);
    }

    return (s);
}

static clib_error_t *
fib_walk_show (vlib_main_t * vm,
	       unformat_input_t * input,
	       vlib_cli_command_t * cmd)
{
    fib_walk_queue_stats_t wqs;
    fib_walk_priority_t prio;
    fib_node_ptr_t sibling;
    fib_node_index_t fwi;
    fib_walk_t *fwalk;
    int more_elts, ii;
    u8 *s = NULL;

#define USEC 1000000
    vlib_cli_output(vm, "FIB Walk Quota = %.2fusec:", quota * USEC);
    vlib_cli_output(vm, "FIB Walk queues:");

    FOR_EACH_FIB_WALK_PRIORITY(prio)
    {
	vlib_cli_output(vm, " %U priority queue:",
			format_fib_walk_priority, prio);
	vlib_cli_output(vm, "  Stats: ");

	FOR_EACH_FIB_WALK_QUEUE_STATS(wqs)
	{
	    vlib_cli_output(vm, "    %U:%d",
			    format_fib_walk_queue_stats, wqs,
			    fib_walk_queues.fwqs_queues[prio].fwq_stats[wqs]);
	}
	vlib_cli_output(vm, "  Occupancy:%d",
			fib_node_list_get_size(
			    fib_walk_queues.fwqs_queues[prio].fwq_queue));

	more_elts = fib_node_list_get_front(
			fib_walk_queues.fwqs_queues[prio].fwq_queue,
			&sibling);

	while (more_elts)
	{
	    ASSERT(FIB_NODE_INDEX_INVALID != sibling.fnp_index);
	    ASSERT(FIB_NODE_TYPE_WALK == sibling.fnp_type);

	    fwi = sibling.fnp_index;
	    fwalk = fib_walk_get(fwi);

	    vlib_cli_output(vm, "  %U", format_fib_walk, fwi);

	    more_elts = fib_node_list_elt_get_next(fwalk->fw_prio_sibling,
						   &sibling);
	}
    }

    vlib_cli_output(vm, "Histogram Statistics:");
    vlib_cli_output(vm, " Number of Elements visit per-quota:");
    for (ii = 0; ii < N_ELTS_BUCKETS; ii++)
    {
	if (0 != fib_walk_work_nodes_visited[ii])
	    s = format(s, "%d:%d ",
		       (ii * fib_walk_work_nodes_visited_incr),
		       fib_walk_work_nodes_visited[ii]);
    }
    vlib_cli_output(vm, "  %v", s);
    vec_free(s);

    vlib_cli_output(vm, " Time consumed per-quota (Quota=%f usec):", quota*USEC);
    s = format(s, "0:%d ", fib_walk_work_time_taken[0]);
    for (ii = 1; ii < N_TIME_BUCKETS; ii++)
    {
	if (0 != fib_walk_work_time_taken[ii])
	    s = format(s, "%d:%d ", (u32)((((ii - N_TIME_BUCKETS/2) *
					   (quota / TIME_INCREMENTS)) + quota) *
					 USEC),
		       fib_walk_work_time_taken[ii]);
    }
    vlib_cli_output(vm, "  %v", s);
    vec_free(s);

    vlib_cli_output(vm, " Sleep Types:");
    vlib_cli_output(vm, "  Short  Long:");
    vlib_cli_output(vm, "  %d %d:",
		    fib_walk_sleep_lengths[FIB_WALK_SHORT_SLEEP],
		    fib_walk_sleep_lengths[FIB_WALK_LONG_SLEEP]);

    vlib_cli_output(vm, " Number of Elements visited per-walk:");
    for (ii = 0; ii < HISTOGRAM_VISITS_PER_WALK_N_BUCKETS; ii++)
    {
	if (0 != fib_walk_hist_vists_per_walk[ii])
	    s = format(s, "%d:%d ",
		       ii*HISTOGRAM_VISITS_PER_WALK_INCR,
		       fib_walk_hist_vists_per_walk[ii]);
    }
    vlib_cli_output(vm, "  %v", s);
    vec_free(s);


    vlib_cli_output(vm, "Brief History (last %d walks):", HISTORY_N_WALKS);
    ii = history_last_walk_pos - 1;
    if (ii < 0)
        ii = HISTORY_N_WALKS - 1;

    while (ii != history_last_walk_pos)
    {
	if (0 != fib_walk_history[ii].fwh_reason[0])
	{
            u8 *s = NULL;
            u32 jj;

	    s = format(s, "[@%d]: %s:%d visits:%d duration:%.2f completed:%.2f ",
                       ii, fib_node_type_get_name(fib_walk_history[ii].fwh_parent.fnp_type),
                       fib_walk_history[ii].fwh_parent.fnp_index,
                       fib_walk_history[ii].fwh_n_visits,
                       fib_walk_history[ii].fwh_duration,
                       fib_walk_history[ii].fwh_completed);
            if (FIB_WALK_FLAG_SYNC & fib_walk_history[ii].fwh_flags)
                s = format(s, "sync, ");
            if (FIB_WALK_FLAG_ASYNC & fib_walk_history[ii].fwh_flags)
                s = format(s, "async, ");

            s = format(s, "reason:");
            jj = 0;
            while (0 != fib_walk_history[ii].fwh_reason[jj])
            {
                s = format (s, "%U,", format_fib_node_bw_reason,
                            fib_walk_history[ii].fwh_reason[jj]);
                jj++;
            }
            vlib_cli_output(vm, "%v", s);
	}

        ii--;
        if (ii < 0)
            ii = HISTORY_N_WALKS - 1;
    }

    return (NULL);
}

VLIB_CLI_COMMAND (fib_walk_show_command, static) = {
    .path = "show fib walk",
    .short_help = "show fib walk",
    .function = fib_walk_show,
};

static clib_error_t *
fib_walk_set_quota (vlib_main_t * vm,
		    unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
    clib_error_t * error = NULL;
    f64 new_quota;

    if (unformat (input, "%f", &new_quota))
    {
	quota = new_quota;
    }
    else
    {
	error = clib_error_return(0 , "Pass a float value");
    }

    return (error);
}

VLIB_CLI_COMMAND (fib_walk_set_quota_command, static) = {
    .path = "set fib walk quota",
    .short_help = "set fib walk quota",
    .function = fib_walk_set_quota,
};

static clib_error_t *
fib_walk_set_histogram_elements_size (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
    clib_error_t * error = NULL;
    u32 new;

    if (unformat (input, "%d", &new))
    {
	fib_walk_work_nodes_visited_incr = new;
    }
    else
    {
	error = clib_error_return(0 , "Pass an int value");
    }

    return (error);
}

VLIB_CLI_COMMAND (fib_walk_set_histogram_elements_size_command, static) = {
    .path = "set fib walk histogram elements size",
    .short_help = "set fib walk histogram elements size",
    .function = fib_walk_set_histogram_elements_size,
};

static clib_error_t *
fib_walk_clear (vlib_main_t * vm,
		unformat_input_t * input,
		vlib_cli_command_t * cmd)
{
    clib_memset(fib_walk_hist_vists_per_walk, 0, sizeof(fib_walk_hist_vists_per_walk));
    clib_memset(fib_walk_history, 0, sizeof(fib_walk_history));
    clib_memset(fib_walk_work_time_taken, 0, sizeof(fib_walk_work_time_taken));
    clib_memset(fib_walk_work_nodes_visited, 0, sizeof(fib_walk_work_nodes_visited));
    clib_memset(fib_walk_sleep_lengths, 0, sizeof(fib_walk_sleep_lengths));

    return (NULL);
}

VLIB_CLI_COMMAND (fib_walk_clear_command, static) = {
    .path = "clear fib walk",
    .short_help = "clear fib walk",
    .function = fib_walk_clear,
};

void
fib_walk_process_enable (void)
{
    vlib_process_signal_event(vlib_get_main(),
                              fib_walk_process_node.index,
                              FIB_WALK_PROCESS_EVENT_ENABLE,
                              0);
}

void
fib_walk_process_disable (void)
{
    vlib_process_signal_event(vlib_get_main(),
                              fib_walk_process_node.index,
                              FIB_WALK_PROCESS_EVENT_DISABLE,
                              0);
}

static clib_error_t *
fib_walk_process_enable_disable (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
    if (unformat (input, "enable"))
    {
        fib_walk_process_enable();
    }
    else if (unformat (input, "disable"))
    {
        fib_walk_process_disable();
    }
    else
    {
        return clib_error_return(0, "choose enable or disable");
    }
    return (NULL);
}

VLIB_CLI_COMMAND (fib_walk_process_command, static) = {
    .path = "test fib-walk-process",
    .short_help = "test fib-walk-process [enable|disable]",
    .function = fib_walk_process_enable_disable,
};
