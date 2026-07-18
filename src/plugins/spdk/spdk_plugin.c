/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <pthread.h>

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/plugin/plugin.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vpp/app/version.h>
#include <vppinfra/bitmap.h>

#include <spdk/cpuset.h>
#include <spdk/bdev.h>
#include <spdk/env.h>
#include <spdk/file.h>
#include <spdk/init.h>
#include <spdk/log.h>
#include <spdk/rpc.h>
#include <spdk/sock.h>
#include <spdk/thread.h>

#include "spdk_plugin.h"

typedef struct spdk_plugin_thread_ctx
{
  struct spdk_thread *thread;
  u32 vpp_thread_index;
  u8 resched;
} spdk_plugin_thread_ctx_t;

typedef struct
{
  struct spdk_ring *pending;
  spdk_plugin_thread_ctx_t **threads;
  u32 pending_count;
  u64 last_tsc;
} spdk_plugin_poller_t;

typedef struct
{
  pthread_mutex_t lock;
  u8 running;
  u8 started;
  u8 stopping;
  u8 subsystem_initialized;
  u8 subsystem_fini_started;
  u8 thread_lib_initialized;
  u8 env_initialized;
  u8 log_opened;
  u8 rpc_initialized;
  u32 polling;
  u32 finishing;
  u32 shutdown_threads;
  u32 active_threads;
  int last_rc;
  char *name;
  char *json_config;
  char *reactor_mask;
  char *rpc_addr;
  void *json_data;
  size_t json_size;
  int no_pci;
  u32 **thread_lcores;
  u32 n_poll_lcores;
  u32 next_poll_thread;
  spdk_plugin_poller_t *pollers;
} spdk_plugin_main_t;

#define SPDK_PLUGIN_THREAD_QUEUE_SIZE 1024
#define SPDK_PLUGIN_PENDING_BATCH     64

static spdk_plugin_main_t spdk_plugin_main = {
  .lock = PTHREAD_MUTEX_INITIALIZER,
};

extern vlib_node_registration_t spdk_poll_input_node;

static u32
spdk_plugin_first_poll_thread (void)
{
  return vlib_get_n_threads () > 1 ? 1 : 0;
}

static void
spdk_plugin_free_lcore_map (spdk_plugin_main_t *sm)
{
  u32 **lcores;

  vec_foreach (lcores, sm->thread_lcores)
    vec_free (*lcores);
  vec_free (sm->thread_lcores);
  sm->n_poll_lcores = 0;
}

static void
spdk_plugin_free_pollers (spdk_plugin_main_t *sm)
{
  spdk_plugin_poller_t *poller;

  vec_foreach (poller, sm->pollers)
    {
      vec_free (poller->threads);
      if (poller->pending)
	spdk_ring_free (poller->pending);
    }
  vec_free (sm->pollers);
}

static char *
spdk_plugin_build_default_reactor_mask (void)
{
  u8 *mask = 0;
  char *rv;
  int first = 1;

  mask = format (mask, "[");
  for (u32 i = spdk_plugin_first_poll_thread (); i < vlib_get_n_threads (); i++)
    {
      int cpu_id = vlib_worker_threads[i].cpu_id;

      if (cpu_id < 0)
	continue;

      mask = format (mask, "%s%d", first ? "" : ",", cpu_id);
      first = 0;
    }
  mask = format (mask, "]%c", 0);

  rv = strdup (first ? "0x1" : (char *) mask);
  vec_free (mask);
  return rv;
}

static int
spdk_plugin_validate_reactor_mask (const char *reactor_mask)
{
  struct spdk_cpuset cpumask;
  u32 first_thread = spdk_plugin_first_poll_thread ();
  u32 expected = 0;

  spdk_cpuset_zero (&cpumask);
  if (spdk_cpuset_parse (&cpumask, reactor_mask))
    return -EINVAL;

  for (u32 ti = first_thread; ti < vlib_get_n_threads (); ti++)
    {
      int cpu_id = vlib_worker_threads[ti].cpu_id;

      if (cpu_id < 0 || !spdk_cpuset_get_cpu (&cpumask, cpu_id))
	{
	  clib_warning ("SPDK reactor mask must contain CPU %d for VPP thread %u", cpu_id, ti);
	  return -EINVAL;
	}
      expected++;
    }

  if (spdk_cpuset_count (&cpumask) != expected)
    {
      clib_warning ("SPDK reactor mask must map exactly one lcore to each VPP dataplane thread");
      return -EINVAL;
    }

  return 0;
}

static int
spdk_plugin_configure_poll_lcores (void)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  struct spdk_cpuset core_mask;
  u32 n_threads = vlib_get_n_threads ();
  u32 first_thread = spdk_plugin_first_poll_thread ();
  u32 expected = n_threads - first_thread;

  if (n_threads == 0 || expected == 0)
    return -EINVAL;

  spdk_plugin_free_lcore_map (sm);
  spdk_plugin_free_pollers (sm);
  vec_validate (sm->thread_lcores, n_threads - 1);
  vec_validate (sm->pollers, n_threads - 1);
  spdk_env_get_cpuset (&core_mask);

  for (u32 ti = first_thread; ti < n_threads; ti++)
    {
      int cpu_id = vlib_worker_threads[ti].cpu_id;

      if (cpu_id < 0 || !spdk_cpuset_get_cpu (&core_mask, cpu_id))
	goto error;

      vec_add1 (sm->thread_lcores[ti], cpu_id);
      sm->pollers[ti].pending =
	spdk_ring_create (SPDK_RING_TYPE_MP_SC, SPDK_PLUGIN_THREAD_QUEUE_SIZE,
			  SPDK_ENV_NUMA_ID_ANY);
      if (!sm->pollers[ti].pending)
	goto error;
      sm->n_poll_lcores++;
    }

  if (sm->n_poll_lcores != expected || spdk_cpuset_count (&core_mask) != expected)
    goto error;

  sm->next_poll_thread = first_thread;

  return 0;

error:
  spdk_plugin_free_pollers (sm);
  spdk_plugin_free_lcore_map (sm);
  return -EINVAL;
}

int
spdk_plugin_lcore_for_vpp_thread (u32 thread_index, u32 *lcore)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  int rv = -ENOENT;

  pthread_mutex_lock (&sm->lock);
  if (thread_index < vec_len (sm->thread_lcores) && vec_len (sm->thread_lcores[thread_index]) == 1)
    {
      *lcore = sm->thread_lcores[thread_index][0];
      rv = 0;
    }
  pthread_mutex_unlock (&sm->lock);
  return rv;
}

int
spdk_plugin_vpp_thread_for_lcore (u32 lcore, u32 *thread_index)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  int rv = -ENOENT;

  pthread_mutex_lock (&sm->lock);
  for (u32 ti = 0; ti < vec_len (sm->thread_lcores); ti++)
    if (vec_len (sm->thread_lcores[ti]) == 1 && sm->thread_lcores[ti][0] == lcore)
      {
	*thread_index = ti;
	rv = 0;
	break;
      }
  pthread_mutex_unlock (&sm->lock);
  return rv;
}

static int
spdk_plugin_schedule_thread (spdk_plugin_thread_ctx_t *ctx, u8 initialize)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  struct spdk_cpuset *cpumask = spdk_thread_get_cpumask (ctx->thread);
  u32 first = spdk_plugin_first_poll_thread ();
  u32 n_threads = vlib_get_n_threads ();
  u32 n_poll_threads = n_threads - first;
  u32 selected = ~0;
  void *item = ctx;

  pthread_mutex_lock (&sm->lock);
  for (u32 i = 0; i < n_poll_threads; i++)
    {
      u32 ti = first + ((sm->next_poll_thread - first + i) % n_poll_threads);
      u32 lcore;

      if (ti >= vec_len (sm->thread_lcores) || vec_len (sm->thread_lcores[ti]) != 1)
	continue;
      lcore = sm->thread_lcores[ti][0];
      if (cpumask && !spdk_cpuset_get_cpu (cpumask, lcore))
	continue;

      selected = ti;
      sm->next_poll_thread = first + ((ti - first + 1) % n_poll_threads);
      break;
    }

  if (selected == ~0 || selected >= vec_len (sm->pollers) ||
      !sm->pollers[selected].pending ||
      spdk_ring_enqueue (sm->pollers[selected].pending, &item, 1, NULL) != 1)
    {
      pthread_mutex_unlock (&sm->lock);
      return -ENOSPC;
    }

  ctx->vpp_thread_index = selected;
  ctx->resched = 0;
  clib_atomic_fetch_add_rel (&sm->pollers[selected].pending_count, 1);
  if (initialize)
    clib_atomic_fetch_add_rel (&sm->active_threads, 1);
  pthread_mutex_unlock (&sm->lock);
  return 0;
}

static int
spdk_plugin_thread_op (struct spdk_thread *thread, enum spdk_thread_op op)
{
  spdk_plugin_thread_ctx_t *ctx = spdk_thread_get_ctx (thread);

  switch (op)
    {
    case SPDK_THREAD_OP_NEW:
      memset (ctx, 0, sizeof (*ctx));
      ctx->thread = thread;
      return spdk_plugin_schedule_thread (ctx, 1);
    case SPDK_THREAD_OP_RESCHED:
      ctx->resched = 1;
      return 0;
    default:
      return -ENOTSUP;
    }
}

static bool
spdk_plugin_thread_op_supported (enum spdk_thread_op op)
{
  return op == SPDK_THREAD_OP_NEW || op == SPDK_THREAD_OP_RESCHED;
}

static void
spdk_plugin_drain_pending_threads (u32 thread_index)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  spdk_plugin_poller_t *poller = &sm->pollers[thread_index];
  spdk_plugin_thread_ctx_t *pending[SPDK_PLUGIN_PENDING_BATCH];
  size_t n_pending;

  while (clib_atomic_load_acq_n (&poller->pending_count))
    {
      n_pending = spdk_ring_dequeue (poller->pending, (void **) pending,
				     ARRAY_LEN (pending));
      if (!n_pending)
	break;
      clib_atomic_fetch_sub_rel (&poller->pending_count, n_pending);
      vec_add (poller->threads, pending, n_pending);
    }
}

static void
spdk_plugin_poll_threads (u32 thread_index)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  spdk_plugin_poller_t *poller = &sm->pollers[thread_index];
  u32 lcore = sm->thread_lcores[thread_index][0];
  u64 now = poller->last_tsc;
  u8 shutdown = clib_atomic_load_acq_n (&sm->shutdown_threads);

  spdk_plugin_drain_pending_threads (thread_index);
  if (PREDICT_FALSE (now == 0))
    now = spdk_get_ticks ();
  spdk_vpp_env_set_current_core (lcore);
  for (u32 i = 0; i < vec_len (poller->threads);)
    {
      spdk_plugin_thread_ctx_t *ctx = poller->threads[i];
      struct spdk_thread *thread = ctx->thread;

      if (shutdown && spdk_thread_is_running (thread))
	{
	  spdk_set_thread (thread);
	  spdk_thread_exit (thread);
	  spdk_set_thread (NULL);
	}

      if (!spdk_thread_is_exited (thread))
	{
	  spdk_thread_poll (thread, 0, now);
	  now = spdk_thread_get_last_tsc (thread);
	}

      if (spdk_thread_is_exited (thread))
	{
	  vec_del1 (poller->threads, i);
	  spdk_thread_destroy (thread);
	  clib_atomic_fetch_sub_rel (&sm->active_threads, 1);
	  continue;
	}

      if (ctx->resched)
	{
	  int rv;

	  vec_del1 (poller->threads, i);
	  rv = spdk_plugin_schedule_thread (ctx, 0);
	  if (PREDICT_FALSE (rv))
	    {
	      ctx->vpp_thread_index = thread_index;
	      ctx->resched = 0;
	      vec_add1 (poller->threads, ctx);
	      sm->last_rc = rv;
	    }
	  continue;
	}
      i++;
    }
  poller->last_tsc = now;
  spdk_vpp_env_set_current_core (SPDK_ENV_LCORE_ID_ANY);
}

static void
spdk_plugin_set_polling_state (vlib_main_t *vm, vlib_node_state_t state)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    {
      u32 ti = this_vlib_main->thread_index;
      vlib_node_state_t thread_state = state;

      /* Main only supervises shutdown when dataplane workers own the reactors. */
      if (state == VLIB_NODE_STATE_POLLING && ti != 0 &&
	  (ti >= vec_len (sm->thread_lcores) || vec_len (sm->thread_lcores[ti]) == 0))
	thread_state = VLIB_NODE_STATE_DISABLED;
      vlib_node_set_state (this_vlib_main, spdk_poll_input_node.index, thread_state);
    }
  vlib_worker_thread_barrier_release (vm);
}

static void
spdk_plugin_finish_app (vlib_main_t *vm)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  int rc;

  if (!clib_atomic_bool_cmp_and_swap (&sm->finishing, 0, 1))
    return;

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    vlib_node_set_state (this_vlib_main, spdk_poll_input_node.index, VLIB_NODE_STATE_DISABLED);

  rc = sm->last_rc;
  if (sm->thread_lib_initialized)
    spdk_thread_lib_fini ();
  sm->thread_lib_initialized = 0;
  spdk_plugin_free_pollers (sm);
  spdk_plugin_free_lcore_map (sm);
  if (sm->env_initialized)
    spdk_env_fini ();
  sm->env_initialized = 0;
  if (sm->log_opened)
    spdk_log_close ();
  sm->log_opened = 0;
  free (sm->json_data);
  sm->json_data = 0;
  sm->json_size = 0;
  vlib_worker_thread_barrier_release (vm);

  pthread_mutex_lock (&sm->lock);
  sm->running = 0;
  sm->started = 0;
  sm->stopping = 0;
  sm->polling = 0;
  sm->subsystem_initialized = 0;
  sm->subsystem_fini_started = 0;
  sm->rpc_initialized = 0;
  sm->shutdown_threads = 0;
  sm->active_threads = 0;
  sm->last_rc = rc;
  sm->finishing = 0;
  pthread_mutex_unlock (&sm->lock);
}

static uword
spdk_poll_input_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  u32 ti = vm->thread_index;

  (void) node;
  (void) frame;

  if (clib_atomic_load_acq_n (&sm->polling) && ti < vec_len (sm->thread_lcores) &&
      ti < vec_len (sm->pollers) && vec_len (sm->thread_lcores[ti]) == 1)
    {
      spdk_plugin_poll_threads (ti);
    }

  if (ti == 0 && sm->running && clib_atomic_load_acq_n (&sm->shutdown_threads) &&
      clib_atomic_load_acq_n (&sm->active_threads) == 0)
    spdk_plugin_finish_app (vm);

  return 0;
}

VLIB_REGISTER_NODE (spdk_poll_input_node) = {
  .function = spdk_poll_input_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "spdk-poll",
  .state = VLIB_NODE_STATE_DISABLED,
};

static void spdk_plugin_begin_shutdown (void *arg);

static void
spdk_plugin_shutdown_threads (int rc)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  if (rc && sm->last_rc == 0)
    sm->last_rc = rc;
  if (sm->rpc_initialized)
    {
      spdk_rpc_finish ();
      sm->rpc_initialized = 0;
    }
  clib_atomic_store_rel_n (&sm->shutdown_threads, 1);
}

static void
spdk_plugin_subsystem_fini_done (void *arg)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  (void) arg;
  sm->subsystem_initialized = 0;
  spdk_plugin_shutdown_threads (0);
}

static void
spdk_plugin_begin_shutdown (void *arg)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  (void) arg;
  if (!sm->subsystem_initialized || sm->subsystem_fini_started)
    return;

  sm->subsystem_fini_started = 1;
  spdk_subsystem_fini (spdk_plugin_subsystem_fini_done, NULL);
}

static void
spdk_plugin_runtime_config_done (int rc, void *arg)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  (void) arg;
  if (rc)
    {
      if (sm->last_rc == 0)
	sm->last_rc = rc;
      spdk_plugin_begin_shutdown (NULL);
      return;
    }

  pthread_mutex_lock (&sm->lock);
  sm->started = 1;
  pthread_mutex_unlock (&sm->lock);
  if (sm->stopping)
    spdk_plugin_begin_shutdown (NULL);
}

static void
spdk_plugin_subsystem_init_done (int rc, void *arg)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  (void) arg;
  if (rc)
    {
      if (sm->last_rc == 0)
	sm->last_rc = rc;
      spdk_plugin_begin_shutdown (NULL);
      return;
    }

  spdk_rpc_set_state (SPDK_RPC_RUNTIME);
  if (sm->rpc_initialized)
    spdk_rpc_server_resume (sm->rpc_addr);

  if (sm->json_data)
    spdk_subsystem_load_config (sm->json_data, sm->json_size,
				spdk_plugin_runtime_config_done, NULL, true);
  else
    spdk_plugin_runtime_config_done (0, NULL);
}

static void
spdk_plugin_start_subsystems (int rc, void *arg)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  (void) arg;
  if (rc)
    {
      spdk_plugin_shutdown_threads (rc);
      return;
    }

  if (sm->rpc_addr)
    {
      rc = spdk_rpc_initialize (sm->rpc_addr, NULL);
      if (rc)
	{
	  spdk_plugin_shutdown_threads (rc);
	  return;
	}
      sm->rpc_initialized = 1;
      spdk_rpc_server_pause (sm->rpc_addr);
    }

  sm->subsystem_initialized = 1;
  spdk_subsystem_init (spdk_plugin_subsystem_init_done, NULL);
}

static void
spdk_plugin_bootstrap (void *arg)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  (void) arg;
  spdk_rpc_set_state (SPDK_RPC_STARTUP);
  if (sm->json_data)
    spdk_subsystem_load_config (sm->json_data, sm->json_size,
				spdk_plugin_start_subsystems, NULL, true);
  else
    spdk_plugin_start_subsystems (0, NULL);
}

typedef struct
{
  u32 vpp_thread_index;
  u32 spdk_main_lcore;
  int rc;
} spdk_plugin_start_ctx_t;

static void
spdk_plugin_start_complete_rpc (void *arg)
{
  spdk_plugin_start_ctx_t *ctx = arg;
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  if (ctx->rc)
    {
      pthread_mutex_lock (&sm->lock);
      sm->running = 0;
      sm->started = 0;
      sm->stopping = 0;
      sm->last_rc = ctx->rc;
      spdk_plugin_free_lcore_map (sm);
      pthread_mutex_unlock (&sm->lock);
    }
  else
    {
      clib_atomic_store_rel_n (&sm->polling, 1);
      spdk_plugin_set_polling_state (vlib_get_main (), VLIB_NODE_STATE_POLLING);
    }

  free (ctx);
}

static void
spdk_plugin_start_rpc (void *arg)
{
  spdk_plugin_start_ctx_t *ctx = arg;
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  struct spdk_env_opts opts = { .opts_size = sizeof (opts) };
  struct spdk_cpuset cpumask;
  struct spdk_thread *app_thread;
  int rc;

  ASSERT (vlib_get_thread_index () == ctx->vpp_thread_index);
  ASSERT (vlib_worker_threads[ctx->vpp_thread_index].cpu_id == (int) ctx->spdk_main_lcore);

  spdk_env_opts_init (&opts);
  opts.name = sm->name ? sm->name : "vpp_spdk";
  opts.core_mask = sm->reactor_mask;
  opts.no_pci = sm->no_pci;
  opts.main_core = ctx->spdk_main_lcore;

  /* Initialize only SPDK's public environment and thread abstractions. VPP
   * owns the system threads and polls each lightweight SPDK thread directly. */
  spdk_vpp_env_set_current_core (ctx->spdk_main_lcore);
  rc = spdk_env_init (&opts);
  if (rc)
    goto done;
  sm->env_initialized = 1;

  spdk_log_open (NULL);
  sm->log_opened = 1;

  rc = spdk_plugin_configure_poll_lcores ();
  if (rc)
    goto error;

  rc = spdk_thread_lib_init_ext (spdk_plugin_thread_op,
				 spdk_plugin_thread_op_supported,
				 sizeof (spdk_plugin_thread_ctx_t),
				 SPDK_DEFAULT_MSG_MEMPOOL_SIZE);
  if (rc)
    goto error;
  sm->thread_lib_initialized = 1;

  if (sm->json_config)
    {
      sm->json_data = spdk_posix_file_load_from_name (sm->json_config, &sm->json_size);
      if (!sm->json_data)
	{
	  rc = -errno;
	  goto error;
	}
    }

  spdk_cpuset_zero (&cpumask);
  spdk_cpuset_set_cpu (&cpumask, ctx->spdk_main_lcore, true);
  app_thread = spdk_thread_create ("app_thread", &cpumask);
  if (!app_thread)
    {
      rc = -ENOMEM;
      goto error;
    }
  rc = spdk_thread_send_msg (app_thread, spdk_plugin_bootstrap, NULL);
  if (rc)
    goto error;

  goto done;

error:
  free (sm->json_data);
  sm->json_data = 0;
  sm->json_size = 0;
  if (sm->thread_lib_initialized && sm->active_threads == 0)
    {
      spdk_thread_lib_fini ();
      sm->thread_lib_initialized = 0;
    }
  spdk_plugin_free_pollers (sm);
  spdk_plugin_free_lcore_map (sm);
  if (sm->env_initialized)
    {
      spdk_env_fini ();
      sm->env_initialized = 0;
    }
  if (sm->log_opened)
    {
      spdk_log_close ();
      sm->log_opened = 0;
    }

done:
  spdk_vpp_env_set_current_core (SPDK_ENV_LCORE_ID_ANY);
  ctx->rc = rc;
  session_send_rpc_evt_to_thread_force (0, spdk_plugin_start_complete_rpc, ctx);
}

int
spdk_plugin_start_app (vlib_main_t *vm, const char *name, const char *json_config,
		       const char *reactor_mask, const char *rpc_addr, int no_pci)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  spdk_plugin_start_ctx_t *ctx = 0;
  char *effective_reactor_mask = 0;
  u32 first_poll_thread = spdk_plugin_first_poll_thread ();
  int rc = 0;

  (void) vm;

  effective_reactor_mask =
    reactor_mask ? strdup (reactor_mask) : spdk_plugin_build_default_reactor_mask ();
  if (!effective_reactor_mask)
    return -ENOMEM;

  rc = spdk_plugin_validate_reactor_mask (effective_reactor_mask);
  if (rc)
    goto early_error;

  rc = spdk_sock_set_default_impl ("vpp");
  if (rc)
    goto early_error;

  if (spdk_vpp_attach ())
    {
      rc = -EIO;
      goto early_error;
    }

  ctx = calloc (1, sizeof (*ctx));
  if (!ctx)
    {
      rc = -ENOMEM;
      goto early_error;
    }
  ctx->vpp_thread_index = first_poll_thread;
  ctx->spdk_main_lcore = vlib_worker_threads[first_poll_thread].cpu_id;

  pthread_mutex_lock (&sm->lock);
  if (sm->running || sm->stopping)
    {
      rc = -EALREADY;
      goto unlock;
    }

  free (sm->name);
  free (sm->json_config);
  free (sm->reactor_mask);
  free (sm->rpc_addr);
  sm->name = name ? strdup (name) : 0;
  sm->json_config = json_config ? strdup (json_config) : 0;
  sm->reactor_mask = strdup (effective_reactor_mask);
  sm->rpc_addr = rpc_addr ? strdup (rpc_addr) : 0;
  sm->no_pci = no_pci;
  sm->running = 1;
  sm->started = 0;
  sm->stopping = 0;
  sm->polling = 0;
  sm->finishing = 0;
  sm->subsystem_initialized = 0;
  sm->subsystem_fini_started = 0;
  sm->thread_lib_initialized = 0;
  sm->env_initialized = 0;
  sm->log_opened = 0;
  sm->rpc_initialized = 0;
  sm->shutdown_threads = 0;
  sm->active_threads = 0;
  sm->last_rc = 0;

unlock:
  pthread_mutex_unlock (&sm->lock);
  if (rc)
    {
      free (effective_reactor_mask);
      free (ctx);
      return rc;
    }

  free (effective_reactor_mask);
  session_send_rpc_evt_to_thread_force (first_poll_thread, spdk_plugin_start_rpc, ctx);
  return 0;

early_error:
  free (effective_reactor_mask);
  free (ctx);
  return rc;
}

void
spdk_plugin_stop_app (void)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  struct spdk_thread *app_thread = NULL;
  u8 should_stop = 0;

  pthread_mutex_lock (&sm->lock);
  if (sm->running && !sm->stopping)
    {
      sm->stopping = 1;
      should_stop = 1;
      if (sm->thread_lib_initialized)
	app_thread = spdk_thread_get_app_thread ();
    }
  pthread_mutex_unlock (&sm->lock);

  if (should_stop && app_thread)
    spdk_thread_send_msg (app_thread, spdk_plugin_begin_shutdown, NULL);
}

u8 *
format_spdk_plugin_state (u8 *s, va_list *args)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;

  (void) args;

  pthread_mutex_lock (&sm->lock);
  s = format (s, "SPDK app: %s%s\n", sm->running ? "running" : "stopped",
	      sm->stopping ? " (stopping)" : "");
  s = format (s, "framework: %s\n", sm->started ? "started" : "-");
  s = format (s, "poll mode: %s\n",
	      sm->polling ? "spdk_thread_poll driven by VPP" : "-");
  s = format (s, "SPDK threads: %u\n", sm->active_threads);
  s = format (s, "last rc: %d\n", sm->last_rc);
  s = format (s, "name: %s\n", sm->name ? sm->name : "vpp_spdk");
  s = format (s, "json: %s\n", sm->json_config ? sm->json_config : "-");
  s = format (s, "reactor mask: %s\n", sm->reactor_mask ? sm->reactor_mask : "-");
  s = format (s, "rpc: %s\n", sm->rpc_addr ? sm->rpc_addr : "-");
  s = format (s, "no-pci: %s\n", sm->no_pci ? "yes" : "no");
  s = format (s, "poll lcores:");
  for (u32 ti = 0; ti < vec_len (sm->thread_lcores); ti++)
    {
      u32 *lcore;

      if (vec_len (sm->thread_lcores[ti]) == 0)
	continue;

      s = format (s, " vpp%u=", ti);
      vec_foreach (lcore, sm->thread_lcores[ti])
	s = format (s, "%s%u", lcore == sm->thread_lcores[ti] ? "" : ",", *lcore);
    }
  s = format (s, "%s\n", sm->n_poll_lcores ? "" : " -");
  pthread_mutex_unlock (&sm->lock);
  return format_spdk_vpp_state (s);
}

static clib_error_t *
spdk_app_start_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *name = 0, *json_config = 0, *reactor_mask = 0, *rpc_addr = 0;
  int no_pci = 0, rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
	;
      else if (unformat (input, "json %s", &json_config))
	;
      else if (unformat (input, "reactor-mask %s", &reactor_mask))
	;
      else if (unformat (input, "rpc %s", &rpc_addr))
	;
      else if (unformat (input, "no-pci"))
	no_pci = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (name)
    vec_add1 (name, 0);
  if (json_config)
    vec_add1 (json_config, 0);
  if (reactor_mask)
    vec_add1 (reactor_mask, 0);
  if (rpc_addr)
    vec_add1 (rpc_addr, 0);

  rv = spdk_plugin_start_app (vm, (char *) name, (char *) json_config, (char *) reactor_mask,
			      (char *) rpc_addr, no_pci);

  vec_free (name);
  vec_free (json_config);
  vec_free (reactor_mask);
  vec_free (rpc_addr);

  if (rv)
    return clib_error_return (0, "SPDK start failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (spdk_app_start_command, static) = {
  .path = "spdk app start",
  .short_help = "spdk app start [name <name>] [json <file>] [reactor-mask <mask>] "
		"[rpc <addr>] [no-pci]",
  .function = spdk_app_start_command_fn,
};

static clib_error_t *
spdk_app_stop_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  spdk_plugin_stop_app ();
  return 0;
}

VLIB_CLI_COMMAND (spdk_app_stop_command, static) = {
  .path = "spdk app stop",
  .short_help = "spdk app stop",
  .function = spdk_app_stop_command_fn,
};

static clib_error_t *
show_spdk_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "%U", format_spdk_plugin_state);
  return 0;
}

VLIB_CLI_COMMAND (show_spdk_command, static) = {
  .path = "show spdk",
  .short_help = "show spdk",
  .function = show_spdk_command_fn,
};

typedef struct
{
  char *bdev_name;
  u32 *buffer_indices;
  struct iovec *iovs;
  u32 n_iovs;
  u64 offset_blocks;
  u64 bytes;
  u32 block_size;
  u32 buf_align;
  u32 pool_index;
  u32 pa_mismatches;
  u32 data_alignment;
  u64 pool_start;
  u64 pool_size;
  u64 first_iova;
  u64 last_iova;
  u64 min_contiguous;
  u64 hash_before;
  u8 explicitly_registered;
  struct spdk_bdev_desc *desc;
  struct spdk_io_channel *ch;
  int rc;
  u32 phase;
  u32 done;
} spdk_vpp_buffer_dma_test_t;

static pthread_mutex_t spdk_vpp_buffer_dma_test_lock = PTHREAD_MUTEX_INITIALIZER;
static spdk_vpp_buffer_dma_test_t *spdk_vpp_buffer_dma_test;

static void
spdk_vpp_buffer_dma_test_finish (spdk_vpp_buffer_dma_test_t *test, int rc)
{
  test->rc = rc;
  clib_atomic_store_rel_n (&test->phase, 10);
  clib_atomic_store_rel_n (&test->done, 1);
}

static void
spdk_vpp_buffer_dma_bdev_event (enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
				void *event_ctx)
{
  (void) type;
  (void) bdev;
  (void) event_ctx;
}

static void
spdk_vpp_buffer_dma_read_done (struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
  spdk_vpp_buffer_dma_test_t *test = cb_arg;

  clib_atomic_store_rel_n (&test->phase, 6);
  spdk_bdev_free_io (bdev_io);
  clib_atomic_store_rel_n (&test->phase, 7);
  spdk_put_io_channel (test->ch);
  clib_atomic_store_rel_n (&test->phase, 8);
  spdk_bdev_close (test->desc);
  clib_atomic_store_rel_n (&test->phase, 9);
  test->ch = 0;
  test->desc = 0;
  spdk_vpp_buffer_dma_test_finish (test, success ? 0 : -EIO);
}

static void
spdk_vpp_buffer_dma_submit (void *arg)
{
  spdk_vpp_buffer_dma_test_t *test = arg;
  struct spdk_bdev *bdev;
  u64 n_blocks, bdev_n_blocks;
  int rc;

  clib_atomic_store_rel_n (&test->phase, 2);

  rc =
    spdk_bdev_open_ext (test->bdev_name, false, spdk_vpp_buffer_dma_bdev_event, test, &test->desc);
  if (rc)
    goto error;
  clib_atomic_store_rel_n (&test->phase, 3);

  bdev = spdk_bdev_desc_get_bdev (test->desc);
  test->block_size = spdk_bdev_get_block_size (bdev);
  test->buf_align = spdk_bdev_get_buf_align (bdev);
  if (test->block_size == 0 || test->bytes % test->block_size)
    {
      rc = -EINVAL;
      goto close_desc;
    }

  n_blocks = test->bytes / test->block_size;
  bdev_n_blocks = spdk_bdev_get_num_blocks (bdev);
  if (n_blocks == 0 || test->offset_blocks >= bdev_n_blocks ||
      n_blocks > bdev_n_blocks - test->offset_blocks)
    {
      rc = -ERANGE;
      goto close_desc;
    }

  test->ch = spdk_bdev_get_io_channel (test->desc);
  if (!test->ch)
    {
      rc = -ENOMEM;
      goto close_desc;
    }
  clib_atomic_store_rel_n (&test->phase, 4);

  rc = spdk_bdev_readv_blocks (test->desc, test->ch, test->iovs, test->n_iovs, test->offset_blocks,
			       n_blocks, spdk_vpp_buffer_dma_read_done, test);
  if (rc == 0)
    {
      clib_atomic_store_rel_n (&test->phase, 5);
      return;
    }

  spdk_put_io_channel (test->ch);
  test->ch = 0;

close_desc:
  spdk_bdev_close (test->desc);
  test->desc = 0;
error:
  spdk_vpp_buffer_dma_test_finish (test, rc);
}

static void
spdk_vpp_buffer_dma_submit_rpc (void *arg)
{
  spdk_vpp_buffer_dma_test_t *test = arg;
  struct spdk_thread *app_thread = spdk_thread_get_app_thread ();

  if (!app_thread)
    {
      spdk_vpp_buffer_dma_test_finish (test, -ENODEV);
      return;
    }

  /* The RPC runs on the VPP worker that owns the app-thread reactor. */
  spdk_set_thread (app_thread);
  spdk_vpp_buffer_dma_submit (test);
  spdk_set_thread (0);
}

static u64
spdk_vpp_buffer_dma_hash (spdk_vpp_buffer_dma_test_t *test)
{
  u64 hash = 1469598103934665603ULL;

  for (u32 i = 0; i < test->n_iovs; i++)
    {
      const u8 *data = test->iovs[i].iov_base;

      for (uword j = 0; j < test->iovs[i].iov_len; j++)
	hash = (hash ^ data[j]) * 1099511628211ULL;
    }

  return hash;
}

static void
spdk_vpp_buffer_dma_test_free (vlib_main_t *vm, spdk_vpp_buffer_dma_test_t *test)
{
  if (test->buffer_indices)
    vlib_buffer_free (vm, test->buffer_indices, test->n_iovs);
  free (test->buffer_indices);
  free (test->iovs);
  free (test->bdev_name);
  free (test);
}

static clib_error_t *
test_spdk_vpp_buffer_dma_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  spdk_plugin_main_t *sm = &spdk_plugin_main;
  spdk_vpp_buffer_dma_test_t *test;
  u8 *bdev_name = 0;
  u64 bytes = 128 << 10, data_alignment = 1, offset_blocks = 0;
  u32 data_size, min_data_capacity, n_buffers, n_allocated, used_buffers = 0, pa_mismatches = 0;
  vlib_buffer_pool_t *buffer_pool;
  u32 thread_index;
  int rc, register_pool = 0, running;

  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "bdev %s", &bdev_name))
	;
      else if (unformat (input, "bytes %U", unformat_memory_size, &bytes))
	;
      else if (unformat (input, "offset-blocks %llu", &offset_blocks))
	;
      else if (unformat (input, "data-align %U", unformat_memory_size, &data_alignment))
	;
      else if (unformat (input, "register-pool"))
	register_pool = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (!bdev_name)
    return clib_error_return (0, "bdev name is required");
  vec_add1 (bdev_name, 0);

  pthread_mutex_lock (&sm->lock);
  running = sm->running && sm->started && sm->polling;
  pthread_mutex_unlock (&sm->lock);
  if (!running)
    {
      vec_free (bdev_name);
      return clib_error_return (0, "SPDK app is not running");
    }

  pthread_mutex_lock (&spdk_vpp_buffer_dma_test_lock);
  test = spdk_vpp_buffer_dma_test;
  pthread_mutex_unlock (&spdk_vpp_buffer_dma_test_lock);
  if (test)
    {
      vec_free (bdev_name);
      return clib_error_return (
	0, "a DMA test is already active; use `show spdk vpp-buffer-dma-test'");
    }

  if (bytes == 0 || bytes > (8 << 20))
    {
      vec_free (bdev_name);
      return clib_error_return (0, "bytes must be between 1 and 8M");
    }

  data_size = vlib_buffer_get_default_data_size (vm);
  if (data_alignment == 0 || data_alignment > data_size || (data_alignment & (data_alignment - 1)))
    {
      vec_free (bdev_name);
      return clib_error_return (0, "data-align must be a power of two between 1 and %u", data_size);
    }
  if (bytes % data_alignment)
    {
      vec_free (bdev_name);
      return clib_error_return (0, "bytes must be a multiple of data-align");
    }

  min_data_capacity = (data_size - data_alignment + 1) & ~(data_alignment - 1);
  if (min_data_capacity == 0)
    {
      vec_free (bdev_name);
      return clib_error_return (0, "data-align leaves no usable payload");
    }
  n_buffers = (bytes + min_data_capacity - 1) / min_data_capacity;
  test = calloc (1, sizeof (*test));
  test->bdev_name = strdup ((char *) bdev_name);
  test->buffer_indices = calloc (n_buffers, sizeof (*test->buffer_indices));
  test->iovs = calloc (n_buffers, sizeof (*test->iovs));
  test->bytes = bytes;
  test->data_alignment = data_alignment;
  test->offset_blocks = offset_blocks;
  vec_free (bdev_name);

  if (!test->bdev_name || !test->buffer_indices || !test->iovs)
    {
      spdk_vpp_buffer_dma_test_free (vm, test);
      return clib_error_return (0, "allocation failed");
    }

  n_allocated = vlib_buffer_alloc (vm, test->buffer_indices, n_buffers);
  test->n_iovs = n_allocated;
  if (n_allocated != n_buffers)
    {
      spdk_vpp_buffer_dma_test_free (vm, test);
      return clib_error_return (0, "allocated %u of %u VPP buffers", n_allocated, n_buffers);
    }

  buffer_pool =
    vlib_get_buffer_pool (vm, vlib_get_buffer (vm, test->buffer_indices[0])->buffer_pool_index);
  if (register_pool)
    {
      rc = spdk_mem_register ((void *) buffer_pool->start, buffer_pool->size);
      if (rc)
	{
	  spdk_vpp_buffer_dma_test_free (vm, test);
	  return clib_error_return (0, "spdk_mem_register(pool %u, %p, %llu) failed: %d",
				    buffer_pool->index, (void *) buffer_pool->start,
				    buffer_pool->size, rc);
	}
    }

  u64 bytes_left = bytes;
  for (u32 i = 0; i < n_buffers && bytes_left; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, test->buffer_indices[i]);
      uword data, aligned_data;
      u64 contiguous, iova, pa;

      data = pointer_to_uword (b->data);
      aligned_data = round_pow2 (data, data_alignment);
      b->current_data = aligned_data - data;
      b->current_length = (data_size - b->current_data) & ~(data_alignment - 1);
      b->current_length = clib_min (bytes_left, b->current_length);
      test->iovs[i].iov_base = vlib_buffer_get_current (b);
      test->iovs[i].iov_len = b->current_length;
      bytes_left -= b->current_length;
      clib_memset (test->iovs[i].iov_base, 0xa5, test->iovs[i].iov_len);

      contiguous = test->iovs[i].iov_len;
      iova = spdk_vtophys (test->iovs[i].iov_base, &contiguous);
      pa = vlib_buffer_get_current_pa (vm, b);
      if (iova == SPDK_VTOPHYS_ERROR || contiguous < test->iovs[i].iov_len)
	{
	  spdk_vpp_buffer_dma_test_free (vm, test);
	  return clib_error_return (
	    0, "buffer %u is not fully DMA mapped (iova 0x%llx, contiguous %llu)", i, iova,
	    contiguous);
	}
      if (i == 0)
	test->first_iova = iova;
      test->last_iova = iova;
      test->min_contiguous = i == 0 ? contiguous : clib_min (test->min_contiguous, contiguous);
      pa_mismatches += iova != pa;
      used_buffers++;
    }
  ASSERT (bytes_left == 0);
  if (used_buffers < n_buffers)
    vlib_buffer_free (vm, test->buffer_indices + used_buffers, n_buffers - used_buffers);
  test->n_iovs = used_buffers;

  test->pool_index = buffer_pool->index;
  test->pool_start = buffer_pool->start;
  test->pool_size = buffer_pool->size;
  test->pa_mismatches = pa_mismatches;
  test->explicitly_registered = register_pool;
  test->hash_before = spdk_vpp_buffer_dma_hash (test);
  rc = spdk_plugin_vpp_thread_for_lcore (spdk_env_get_first_core (), &thread_index);
  if (rc)
    {
      spdk_vpp_buffer_dma_test_free (vm, test);
      return clib_error_return (0, "no VPP worker owns the SPDK app reactor");
    }

  pthread_mutex_lock (&spdk_vpp_buffer_dma_test_lock);
  spdk_vpp_buffer_dma_test = test;
  pthread_mutex_unlock (&spdk_vpp_buffer_dma_test_lock);
  clib_atomic_store_rel_n (&test->phase, 1);
  session_send_rpc_evt_to_thread_force (thread_index, spdk_vpp_buffer_dma_submit_rpc, test);
  vlib_cli_output (vm,
		   "VPP buffer DMA test scheduled on VPP worker %u; use `show "
		   "spdk vpp-buffer-dma-test'",
		   thread_index);
  return 0;
}

VLIB_CLI_COMMAND (test_spdk_vpp_buffer_dma_command, static) = {
  .path = "test spdk vpp-buffer-dma",
  .short_help = "test spdk vpp-buffer-dma bdev <name> [bytes <size>] "
		"[offset-blocks <n>] [data-align <size>] [register-pool]",
  .function = test_spdk_vpp_buffer_dma_command_fn,
};

static clib_error_t *
show_spdk_vpp_buffer_dma_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  spdk_vpp_buffer_dma_test_t *test;
  u64 hash_after;
  u32 phase;
  int rc;

  (void) input;
  (void) cmd;

  pthread_mutex_lock (&spdk_vpp_buffer_dma_test_lock);
  test = spdk_vpp_buffer_dma_test;
  if (!test)
    {
      pthread_mutex_unlock (&spdk_vpp_buffer_dma_test_lock);
      vlib_cli_output (vm, "VPP buffer DMA test: none");
      return 0;
    }

  if (!clib_atomic_load_acq_n (&test->done))
    {
      phase = clib_atomic_load_acq_n (&test->phase);
      pthread_mutex_unlock (&spdk_vpp_buffer_dma_test_lock);
      vlib_cli_output (vm, "VPP buffer DMA test: RUNNING (phase %u)", phase);
      return 0;
    }

  spdk_vpp_buffer_dma_test = 0;
  pthread_mutex_unlock (&spdk_vpp_buffer_dma_test_lock);

  hash_after = spdk_vpp_buffer_dma_hash (test);
  vlib_cli_output (vm,
		   "VPP buffer DMA test: %s\n"
		   "bdev %s, bytes %llu, block-size %u, bdev-alignment %u, data-align %u, "
		   "iovs %u\n"
		   "pool %u, pool-base 0x%llx, pool-size %llu, explicitly-registered %s\n"
		   "first-iova 0x%llx, last-iova 0x%llx, min-contiguous %llu\n"
		   "VPP-PA/iova differences %u, hash-before 0x%llx, hash-after 0x%llx",
		   test->rc ? "FAILED" : "SUCCESS", test->bdev_name, test->bytes, test->block_size,
		   test->buf_align, test->data_alignment, test->n_iovs, test->pool_index,
		   test->pool_start, test->pool_size, test->explicitly_registered ? "yes" : "no",
		   test->first_iova, test->last_iova, test->min_contiguous, test->pa_mismatches,
		   test->hash_before, hash_after);

  rc = test->rc;
  spdk_vpp_buffer_dma_test_free (vm, test);
  return rc ? clib_error_return (0, "SPDK bdev read failed: %d", rc) : 0;
}

VLIB_CLI_COMMAND (show_spdk_vpp_buffer_dma_test_command, static) = {
  .path = "show spdk vpp-buffer-dma-test",
  .short_help = "show spdk vpp-buffer-dma-test",
  .function = show_spdk_vpp_buffer_dma_test_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SPDK NVMe/TCP integration plugin",
};
