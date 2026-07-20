/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

/** \file
 *
 * Delayed free: epoch-based memory reclamation for single-writer,
 * multi-reader structures.
 *
 * Structures marked with vec_mark_mt_safe() / pool_mark_mt_safe() /
 * hash_mark_mt_safe() are mutated by the main thread while worker
 * threads read them without locks. When such a structure grows (the
 * data moves to a new allocation) or is freed, workers may still hold
 * pointers into the old memory until they finish their current main
 * loop iteration. Instead of freeing that memory immediately,
 * vppinfra hands it to vlib_delayed_free_enqueue() (registered via
 * clib_mem_set_delayed_free_cb()), which parks it on a per-epoch free
 * list. The main loop publishes a new epoch whenever frees are
 * pending; each worker acknowledges the epoch it has seen at the top
 * of its main loop. Once every worker has acknowledged epoch E, all
 * memory parked before E can no longer be referenced and is freed for
 * real.
 *
 * Properties and caveats:
 * - Only stale-memory reclamation is deferred; readers must already
 *   tolerate seeing either the old or the new version of the data.
 * - Writers must run on the main thread (or hold the worker barrier,
 *   in which case frees are immediate and safe).
 * - A worker that sleeps (e.g. interrupt mode with no traffic) delays
 *   reclamation, not correctness: parked memory is simply freed later.
 */

#ifndef included_vlib_delayed_free_h
#define included_vlib_delayed_free_h

#include <vppinfra/cache.h>
#include <vppinfra/fifo.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

typedef struct
{
  void *ptr;
  clib_mem_heap_t *heap;
} vlib_delayed_free_entry_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /** main thread only: per-epoch free lists, oldest epoch first */
  vlib_delayed_free_entry_t **frees_by_epoch_fifo;
  /** main thread only: last epoch seen acknowledged by each worker */
  u64 *worker_last_seen_epochs;
  /** main thread only: minimum acknowledged epoch at last full scan */
  u64 last_known_safe_epoch;
  /** main thread only: stats */
  u64 n_enqueued;
  u64 n_freed;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  /** written by main thread, read by workers */
  u64 current_epoch;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
} vlib_delayed_free_main_t;

struct vlib_main_t;

/** Register the delayed free callback with vppinfra and size the
 * per-worker epoch table. Called once workers exist. */
void vlib_delayed_free_enable (struct vlib_main_t *vm);

/** Main-loop housekeeping: publish a new epoch if frees are pending
 * and reclaim epochs all workers have acknowledged. Main thread only. */
void vlib_delayed_free_process (struct vlib_main_t *vm);

#endif /* included_vlib_delayed_free_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
