/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/log.h>
#include <vlib/unix/unix.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "crypto",
};

/* Called with the worker threads at the barrier. */
static void
vnet_dev_crypto_engine_update_algs (vlib_main_t *vm, vnet_dev_crypto_engine_t *e)
{
  vnet_dev_crypto_alg_handlers_t *h;
  u32 ei = e->index;
  clib_bitmap_t *algs = 0;
  uword alg;

  pool_foreach_pointer (dev, vnet_dev_main.devices)
    vec_foreach_pointer (cq, dev->crypto_queues)
      if (cq->started && cq->group->engine_index == ei)
	algs = clib_bitmap_or (algs, cq->group->algs);

  vec_foreach (h, e->alg_handlers)
    if (clib_bitmap_get (algs, h->alg) && !clib_bitmap_get (e->algs, h->alg))
      {
	for (u32 t = VNET_CRYPTO_OP_TYPE_ENCRYPT; t <= VNET_CRYPTO_OP_TYPE_DECRYPT; t++)
	  vnet_crypto_register_async_alg (vm, e->id, h->alg, t, e->enq_node_index[h->alg][t]);
      }

  clib_bitmap_foreach (alg, e->algs)
    if (!clib_bitmap_get (algs, alg))
      for (u32 type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
	vnet_crypto_unregister_async_alg (vm, e->id, alg, type);

  if (!clib_bitmap_is_equal (algs, e->algs))
    log_debug (0, "crypto engine '%s' has %u algorithms", e->name,
	       clib_bitmap_count_set_bits (algs));

  clib_bitmap_free (e->algs);
  e->algs = algs;
}

static void
vnet_dev_crypto_engines_update_algs (vlib_main_t *vm)
{
  for (u32 i = 0; i < vec_len (vnet_dev_main.crypto_engines); i++)
    vnet_dev_crypto_engine_update_algs (vm, vnet_dev_main.crypto_engines[i]);
}

static vlib_error_desc_t vnet_dev_crypto_error_counters[] = {
#define _(f, n, d)                                                                                 \
  {                                                                                                \
    .name = n,                                                                                     \
    .desc = d,                                                                                     \
    .severity = VL_COUNTER_SEVERITY_ERROR,                                                         \
  },
  foreach_vnet_dev_crypto_error
#undef _
};

/* Called with the worker threads at the barrier. */
static u32
vnet_dev_crypto_enq_node_register (vlib_main_t *vm, vnet_dev_crypto_engine_t *e,
				   vnet_dev_node_t *dn)
{
  u32 ei = e->index, ni;
  vlib_node_registration_t reg = {
    .node_fn_registrations = dn->registrations,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .vector_size = sizeof (u32),
    .scalar_size = sizeof (vnet_crypto_deq_scalar_data_t),
    .aux_size = sizeof (vnet_crypto_ctx_t *),
    .flags = VLIB_NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH | VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .runtime_data = &ei,
    .runtime_data_bytes = sizeof (ei),
    .format_trace = dn->format_trace,
    .error_counters = vnet_dev_crypto_error_counters,
    .n_errors = VNET_DEV_CRYPTO_N_ERROR,
  };

  ni = vlib_register_node (vm, &reg, "%s-%s", e->name, dn->name);

  /* the enqueue node drops to next 0 */
  vlib_node_add_named_next (vm, ni, "error-drop");
  return ni;
}

/* handlers may share enqueue nodes, each node is registered once */
static u32
vnet_dev_crypto_enq_node_index (vlib_main_t *vm, vnet_dev_crypto_engine_t *e,
				vnet_dev_crypto_alg_handlers_t *h, vnet_dev_node_t *dn)
{
  for (vnet_dev_crypto_alg_handlers_t *p = e->alg_handlers; p < h; p++)
    if (p->enc_node == dn)
      return e->enq_node_index[p->alg][VNET_CRYPTO_OP_TYPE_ENCRYPT];
    else if (p->dec_node == dn)
      return e->enq_node_index[p->alg][VNET_CRYPTO_OP_TYPE_DECRYPT];

  if (h->enc_node == dn && h->dec_node == dn &&
      e->enq_node_index[h->alg][VNET_CRYPTO_OP_TYPE_ENCRYPT] != ~0)
    return e->enq_node_index[h->alg][VNET_CRYPTO_OP_TYPE_ENCRYPT];

  return vnet_dev_crypto_enq_node_register (vm, e, dn);
}

/* Called with the worker threads at the barrier. */
static void
vnet_dev_crypto_engine_nodes_register (vlib_main_t *vm, vnet_dev_crypto_engine_t *e,
				       vnet_dev_crypto_queue_group_t *g)
{
  vnet_dev_crypto_alg_handlers_t *h;
  u32 ei = e->index;
  vlib_node_registration_t deq_reg = {
    .node_fn_registrations = g->deq_node->registrations,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .runtime_data = &ei,
    .runtime_data_bytes = sizeof (ei),
    .format_trace = g->deq_node->format_trace,
    .error_counters = vnet_dev_crypto_error_counters,
    .n_errors = VNET_DEV_CRYPTO_N_ERROR,
  };

  e->deq_node_index = vlib_register_node (vm, &deq_reg, "%s-deq", e->name);
  vnet_crypto_register_engine_deq_node (vm, e->id, e->deq_node_index);

  vec_foreach (h, e->alg_handlers)
    {
      e->enq_node_index[h->alg][VNET_CRYPTO_OP_TYPE_ENCRYPT] =
	vnet_dev_crypto_enq_node_index (vm, e, h, h->enc_node);
      e->enq_node_index[h->alg][VNET_CRYPTO_OP_TYPE_DECRYPT] =
	vnet_dev_crypto_enq_node_index (vm, e, h, h->dec_node);
    }

  vlib_worker_thread_node_runtime_update ();
}

/* Called with the worker threads at the barrier. */
static vnet_dev_rv_t
vnet_dev_crypto_group_engine_create (vlib_main_t *vm, vnet_dev_driver_t *drv,
				     vnet_dev_crypto_queue_group_t *g)
{
  u32 ei = vec_len (vnet_dev_main.crypto_engines);
  vnet_dev_crypto_engine_t *e;

  if (ei == CLIB_U8_MAX)
    {
      log_err (0, "too many crypto engines");
      return VNET_DEV_ERR_BUG;
    }

  e = clib_mem_alloc (sizeof (*e));
  *e = (vnet_dev_crypto_engine_t) {
    .name = (char *) format (0, "%s-%s%c", drv->registration->name, g->name, 0),
    .index = ei,
    .driver_index = drv->index,
    .multi_queue_per_thread = g->multi_queue_per_thread,
    .alg_handlers = g->alg_handlers,
    .key_change = g->key_change,
    .key_data_sz = g->key_data_sz,
  };
  vec_add1 (vnet_dev_main.crypto_engines, e);
  g->engine_index = ei;
  clib_memset_u32 (e->enq_node_index, ~0, ARRAY_LEN (e->enq_node_index) * VNET_CRYPTO_OP_N_TYPES);

  e->id = vnet_crypto_register_engine (vm, e->name, g->engine_priority,
				       g->engine_desc ? g->engine_desc : e->name);
  vec_validate_init_empty (vnet_dev_main.crypto_engine_index_by_id, e->id, CLIB_U8_MAX);
  vnet_dev_main.crypto_engine_index_by_id[e->id] = e->index;
  vnet_dev_crypto_engine_nodes_register (vm, e, g);

  if (e->key_change &&
      vnet_crypto_register_key_change_handler (vm, e->id, e->key_change, e->key_data_sz))
    {
      log_err (0, "crypto engine '%s': key data size %u not reserved", e->name, e->key_data_sz);
      return VNET_DEV_ERR_BUG;
    }

  log_debug (0, "crypto engine '%s' registered", e->name);
  return VNET_DEV_OK;
}

static void
vnet_dev_crypto_deferred_free_run (vlib_main_t *vm, vnet_dev_crypto_engine_t *e)
{
  for (u32 i = 0; i < vec_len (e->deferred_frees);)
    {
      vnet_dev_crypto_deferred_free_t *df = e->deferred_frees + i;
      u8 done = 1;

      for (u32 j = 0; j < vec_len (df->marks); j++)
	if (df->marks[j].queue->deq_req < df->marks[j].enq_req)
	  done = 0;

      if (!done)
	{
	  i++;
	  continue;
	}

      df->free_fn (vm, df->ptr);
      vec_free (df->marks);
      vec_del1 (e->deferred_frees, i);
    }
}

void
vnet_dev_crypto_defer_free (vlib_main_t *vm, vnet_crypto_engine_id_t engine, void *ptr,
			    vnet_dev_crypto_free_fn_t *free_fn)
{
  vnet_dev_crypto_engine_t *e = vnet_dev_crypto_get_engine (engine);
  u32 engine_index = e->index;
  vnet_dev_crypto_deferred_free_t df = { .ptr = ptr, .free_fn = free_fn };

  pool_foreach_pointer (dev, vnet_dev_main.devices)
    vec_foreach_pointer (cq, dev->crypto_queues)
      if (cq->started && cq->group->engine_index == engine_index && cq->deq_req < cq->enq_req)
	vec_add1 (df.marks, ((vnet_dev_crypto_queue_mark_t) {
			      .queue = cq,
			      .enq_req = cq->enq_req,
			    }));

  vec_add1 (e->deferred_frees, df);
  vnet_dev_crypto_deferred_free_run (vm, e);
}

static void
vnet_dev_crypto_queue_free (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  vnet_dev_crypto_queue_ops_t *ops = &cq->group->ops;

  if (cq->started && ops->stop)
    ops->stop (vm, cq);
  cq->started = 0;

  if (cq->initialized && ops->deinit)
    ops->deinit (vm, cq);
  cq->initialized = 0;

  clib_bitmap_free (cq->assigned_threads);
  clib_mem_free (cq);
}

static void
vnet_dev_crypto_queue_assign_thread (vnet_dev_crypto_engine_t *e, vnet_dev_crypto_queue_t *cq,
				     u32 ti)
{
  /* frames must be dequeued by the thread which enqueued them */
  if (!clib_bitmap_is_zero (cq->assigned_threads))
    {
      log_warn (cq->dev, "crypto queue %u not assigned to thread %u, it is already assigned",
		cq->index, ti);
      return;
    }

  if (vec_len (e->thread_queues[ti]) && cq->group->multi_queue_per_thread == 0)
    {
      log_warn (cq->dev, "crypto queue %u not assigned to thread %u, it already has a queue",
		cq->index, ti);
      return;
    }

  cq->assigned_threads = clib_bitmap_set (cq->assigned_threads, ti, 1);
  vec_add1 (e->thread_queues[ti], cq);
}

/* Called with the worker threads at the barrier. */
static void
vnet_dev_crypto_engine_assign (vnet_dev_crypto_engine_t *e, u32 n_threads)
{
  vnet_dev_crypto_queue_t **queues = 0;
  u32 n_queues = 0;
  u8 multi = 0;
  uword ti;

  vec_validate (e->thread_queues, n_threads - 1);
  for (ti = 0; ti < n_threads; ti++)
    vec_reset_length (e->thread_queues[ti]);

  pool_foreach_pointer (dev, vnet_dev_main.devices)
    {
      vnet_dev_crypto_config_t *cc = &dev->crypto_config;

      vec_foreach_pointer (cq, dev->crypto_queues)
	{
	  clib_bitmap_t *threads = 0;

	  if (cq->group->engine_index != e->index || cq->started == 0)
	    continue;

	  multi = cq->group->multi_queue_per_thread;
	  clib_bitmap_zero (cq->assigned_threads);
	  n_queues++;

	  if (cq->index < vec_len (cc->queues))
	    threads = cc->queues[cq->index].threads;

	  if (threads == 0)
	    vec_add1 (queues, cq);
	  else
	    clib_bitmap_foreach (ti, threads)
	      vnet_dev_crypto_queue_assign_thread (e, cq, ti);
	}
    }

  if (multi)
    for (u32 k = 0; k < vec_len (queues); k++)
      vnet_dev_crypto_queue_assign_thread (e, queues[k], k % n_threads);
  else
    for (u32 i = 0, k = 0; i < n_threads && k < vec_len (queues); i++)
      if (vec_len (e->thread_queues[i]) == 0)
	vnet_dev_crypto_queue_assign_thread (e, queues[k++], i);

  vec_free (queues);

  for (ti = 0; ti < n_threads && n_queues; ti++)
    if (vec_len (e->thread_queues[ti]) == 0)
      log_warn (0, "thread %u has no %s queue, its requests will fail", ti, e->name);
}

static void
vnet_dev_crypto_engines_assign (void)
{
  for (u32 i = 0; i < vec_len (vnet_dev_main.crypto_engines); i++)
    vnet_dev_crypto_engine_assign (vnet_dev_main.crypto_engines[i], vlib_get_n_threads ());
}

/* Called with the worker threads at the barrier. */
static void
vnet_dev_crypto_queues_remove (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_crypto_deferred_free_t *df;

  vec_foreach_pointer (cq, dev->crypto_queues)
    {
      vnet_dev_crypto_engine_t *e;

      if (cq->group->engine_index == CLIB_U8_MAX)
	continue;

      e = vnet_dev_main.crypto_engines[cq->group->engine_index];
      vec_foreach (df, e->deferred_frees)
	for (u32 i = 0; i < vec_len (df->marks); i++)
	  if (df->marks[i].queue == cq)
	    vec_del1 (df->marks, i--);
    }

  vec_foreach_pointer (cq, dev->crypto_queues)
    vnet_dev_crypto_queue_free (vm, cq);

  vec_free (dev->crypto_queues);

  vnet_dev_crypto_engines_assign ();
  vnet_dev_crypto_engines_update_algs (vm);

  for (u32 i = 0; i < vec_len (vnet_dev_main.crypto_engines); i++)
    vnet_dev_crypto_deferred_free_run (vm, vnet_dev_main.crypto_engines[i]);
}

static vnet_dev_crypto_queue_group_t *
vnet_dev_crypto_queue_group_find (vnet_dev_driver_t *drv, char *name)
{
  vec_foreach_pointer (g, drv->crypto_queue_groups)
    if (strcmp ((char *) g->name, name) == 0)
      return g;
  return 0;
}

static clib_error_t *
vnet_dev_crypto_show_groups_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  vnet_dev_driver_t *drv = pool_elt_at_index (vnet_dev_main.drivers, cmd->function_arg);
  vnet_dev_format_args_t fa = {}, *a = &fa;

  if ((unix_main.flags & UNIX_FLAG_NOCOLOR) || !vlib_unix_cli_ansi_capable ())
    fa.plain_text = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "debug"))
	fa.debug = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  vec_foreach_pointer (g, drv->crypto_queue_groups)
    {
      vlib_cli_output (vm, "Crypto queue group '%s':", g->name);
      vlib_cli_output (vm, "  %U", format_vnet_dev_crypto_queue_group_info, a, g);
    }

  return 0;
}

static void
vnet_dev_crypto_register_show_groups_cmd (vlib_main_t *vm, vnet_dev_driver_t *drv)
{
  char *name = drv->registration->name;
  vlib_cli_command_t cmd = {
    .path = (char *) format (0, "show device driver %s groups%c", name, 0),
    .short_help = (char *) format (0, "show device driver %s groups [debug]%c", name, 0),
    .function = vnet_dev_crypto_show_groups_cmd_fn,
    .function_arg = drv->index,
    .is_mp_safe = 1,
  };
  clib_error_t *err = vlib_cli_register (vm, &cmd);

  if (err)
    {
      log_err (0, "%s: %U", name, format_clib_error, err);
      clib_error_free (err);
    }
}

static int
vnet_dev_crypto_queue_group_args_match (vnet_dev_crypto_queue_group_t *g,
					vnet_dev_crypto_queue_group_add_args_t *args)
{
  return vec_len (g->alg_handlers) == vec_len (args->alg_handlers) &&
	 memcmp (g->alg_handlers, args->alg_handlers, vec_bytes (g->alg_handlers)) == 0 &&
	 memcmp (&g->config, &args->config, sizeof (g->config)) == 0 &&
	 memcmp (&g->ops, &args->ops, sizeof (g->ops)) == 0 && g->deq_node == args->deq_node &&
	 g->key_change == args->key_change && g->key_data_sz == args->key_data_sz &&
	 g->engine_priority == args->engine_priority &&
	 g->multi_queue_per_thread == args->multi_queue_per_thread;
}

/* adds the queue group if it doesn't exist yet, the crypto engine is created when the first
 * device using the group is attached */
vnet_dev_rv_t
vnet_dev_crypto_queue_group_add (vlib_main_t *vm, vnet_dev_driver_t *drv,
				 vnet_dev_crypto_queue_group_add_args_t *args, char *fmt, ...)
{
  vnet_dev_queue_config_t *c = &args->config;
  vnet_dev_crypto_alg_handlers_t *h;
  vnet_dev_crypto_queue_group_t *g;
  clib_bitmap_t *algs = 0;
  u8 *name;
  va_list va;

  va_start (va, fmt);
  name = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (name, 0);

  if (name[0] == 0)
    {
      log_err (0, "%s: crypto queue group name is empty", drv->registration->name);
      vec_free (name);
      return VNET_DEV_ERR_BUG;
    }

  if ((g = vnet_dev_crypto_queue_group_find (drv, (char *) name)))
    {
      vec_free (name);
      if (vnet_dev_crypto_queue_group_args_match (g, args))
	return VNET_DEV_OK;
      log_err (0, "%s: crypto queue group '%s' already added with different arguments",
	       drv->registration->name, g->name);
      return VNET_DEV_ERR_ALREADY_EXISTS;
    }

  if (c->default_size == 0 || !vnet_dev_queue_size_is_valid (c->default_size, c))
    {
      log_err (0, "%s: invalid crypto queue config (min %u max %u default %u)",
	       drv->registration->name, c->min_size, c->max_size, c->default_size);
      vec_free (name);
      return VNET_DEV_ERR_BUG;
    }

  if (vec_len (args->alg_handlers) == 0 || args->deq_node == 0)
    {
      log_err (0, "%s: crypto queue group without algorithms or dequeue node",
	       drv->registration->name);
      vec_free (name);
      return VNET_DEV_ERR_BUG;
    }

  vec_foreach (h, args->alg_handlers)
    if (h->enc_node == 0 || h->dec_node == 0)
      {
	log_err (0, "%s: no enqueue node for %U", drv->registration->name, format_vnet_crypto_alg,
		 h->alg);
	vec_free (name);
	return VNET_DEV_ERR_BUG;
      }

  if (args->key_change && args->key_data_sz > crypto_main.async_key_data_reserved)
    {
      log_err (0, "%s: crypto key data size %u not reserved", drv->registration->name,
	       args->key_data_sz);
      vec_free (name);
      return VNET_DEV_ERR_BUG;
    }

  vec_foreach (h, args->alg_handlers)
    algs = clib_bitmap_set (algs, h->alg, 1);

  g = clib_mem_alloc (sizeof (*g));
  *g = (vnet_dev_crypto_queue_group_t) {
    .name = name,
    .engine_index = CLIB_U8_MAX,
    .config = *c,
    .algs = algs,
    .ops = args->ops,
    .engine_desc = args->engine_desc,
    .engine_priority = args->engine_priority,
    .alg_handlers = vec_dup (args->alg_handlers),
    .deq_node = args->deq_node,
    .key_change = args->key_change,
    .key_data_sz = args->key_data_sz,
    .multi_queue_per_thread = args->multi_queue_per_thread,
  };

  if (vec_len (drv->crypto_queue_groups) == 0)
    vnet_dev_crypto_register_show_groups_cmd (vm, drv);
  vec_add1 (drv->crypto_queue_groups, g);
  log_debug (0, "%s: crypto queue group '%s' added (min %u max %u default %u, %u algorithms)",
	     drv->registration->name, g->name, c->min_size, c->max_size, c->default_size,
	     clib_bitmap_count_set_bits (g->algs));
  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_crypto_queue_add (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_crypto_queue_add_args_t *args)
{
  vnet_dev_driver_t *drv = pool_elt_at_index (vnet_dev_main.drivers, dev->driver_index);
  vnet_dev_crypto_queue_group_t *g;
  vnet_dev_crypto_queue_t *cq;
  vnet_dev_queue_config_t c;

  if (args->group == 0 || (g = vnet_dev_crypto_queue_group_find (drv, args->group)) == 0)
    {
      log_err (dev, "crypto queue group '%s' does not exist", args->group ? args->group : "");
      return VNET_DEV_ERR_BUG;
    }

  c = g->config;
  if (args->max_size)
    c.max_size = args->max_size;
  if (args->default_size)
    c.default_size = args->default_size;

  if (c.max_size > g->config.max_size || !vnet_dev_queue_size_is_valid (c.default_size, &c))
    {
      log_err (dev, "invalid crypto queue limits (max %u default %u)", c.max_size, c.default_size);
      return VNET_DEV_ERR_BUG;
    }

  cq = vnet_dev_alloc_with_data (sizeof (*cq), g->config.data_size);
  cq->dev = dev;
  cq->index = vec_len (dev->crypto_queues);
  cq->group = g;
  cq->max_size = c.max_size;
  cq->default_size = c.default_size;

  if (args->initial_data)
    clib_memcpy (cq->data, args->initial_data, g->config.data_size);

  vec_add1 (dev->crypto_queues, cq);
  log_debug (dev, "crypto queue %u added to group '%s'", cq->index, g->name);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
vnet_dev_crypto_config_validate (vnet_dev_t *dev, u32 n_queues, u32 n_threads)
{
  vnet_dev_crypto_config_t *cc = &dev->crypto_config;

  for (u32 i = 0; i < vec_len (cc->queues); i++)
    {
      vnet_dev_crypto_queue_config_t *qc = cc->queues + i;
      uword last = clib_bitmap_last_set (qc->threads);

      if (i >= n_queues && (qc->size || qc->threads))
	{
	  log_err (dev, "crypto queue %u configured, device uses %u crypto queues", i, n_queues);
	  return VNET_DEV_ERR_INVALID_VALUE;
	}

      if (qc->threads && last >= n_threads)
	{
	  log_err (dev, "crypto queue %u: thread %u does not exist", i, last);
	  return VNET_DEV_ERR_INVALID_VALUE;
	}
    }

  for (u32 i = 0; i < n_queues; i++)
    {
      vnet_dev_crypto_queue_t *cq = dev->crypto_queues[i];
      vnet_dev_queue_config_t qc = cq->group->config;
      u16 sz = cc->queue_size ? cc->queue_size : cq->default_size;

      qc.max_size = cq->max_size;
      if (i < vec_len (cc->queues) && cc->queues[i].size)
	sz = cc->queues[i].size;

      if (!vnet_dev_queue_size_is_valid (sz, &qc))
	{
	  log_err (dev, "invalid size %u for crypto queue %u (min %u max %u%s)", sz, i, qc.min_size,
		   qc.max_size, qc.size_is_power_of_two ? ", power of 2" : "");
	  return VNET_DEV_ERR_INVALID_VALUE;
	}
      cq->size = sz;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
vnet_dev_crypto_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_driver_t *drv = pool_elt_at_index (vnet_dev_main.drivers, dev->driver_index);
  u32 n_threads = vlib_get_n_threads ();
  u32 n_added = vec_len (dev->crypto_queues);
  u32 n_queues = dev->crypto_config.num_queues;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (n_added == 0)
    return VNET_DEV_OK;

  if (n_queues == 0)
    n_queues = clib_min (n_threads, n_added);
  else if (n_queues > n_added)
    {
      log_err (dev, "%u crypto queues requested, device has %u", n_queues, n_added);
      rv = VNET_DEV_ERR_INVALID_VALUE;
      goto done;
    }

  if ((rv = vnet_dev_crypto_config_validate (dev, n_queues, n_threads)) != VNET_DEV_OK)
    goto done;

  /* queues not used by the configuration are not started */
  for (u32 i = n_queues; i < n_added; i++)
    vnet_dev_crypto_queue_free (vm, dev->crypto_queues[i]);
  vec_set_len (dev->crypto_queues, n_queues);

  vlib_worker_thread_barrier_sync (vm);

  vec_foreach_pointer (cq, dev->crypto_queues)
    if (cq->group->engine_index == CLIB_U8_MAX &&
	(rv = vnet_dev_crypto_group_engine_create (vm, drv, cq->group)) != VNET_DEV_OK)
      break;

  vec_foreach_pointer (cq, dev->crypto_queues)
    {
      vnet_dev_crypto_queue_ops_t *ops = &cq->group->ops;

      if (rv != VNET_DEV_OK)
	break;

      if (ops->init && (rv = ops->init (vm, cq)) != VNET_DEV_OK)
	{
	  log_err (dev, "crypto queue %u init failed [rv %d]", cq->index, rv);
	  break;
	}
      cq->initialized = 1;

      if (ops->start && (rv = ops->start (vm, cq)) != VNET_DEV_OK)
	{
	  log_err (dev, "crypto queue %u start failed [rv %d]", cq->index, rv);
	  break;
	}
      cq->started = 1;
      log_debug (dev, "crypto queue %u started, size %u", cq->index, cq->size);
    }

  if (rv == VNET_DEV_OK)
    {
      vnet_dev_crypto_engines_assign ();
      vnet_dev_crypto_engines_update_algs (vm);
    }
  else
    vnet_dev_crypto_queues_remove (vm, dev);

  vlib_worker_thread_barrier_release (vm);

  if (rv == VNET_DEV_OK)
    log_debug (dev, "%u of %u crypto queues used", n_queues, n_added);
  return rv;

done:
  /* not assigned to any thread yet, no barrier needed */
  vnet_dev_crypto_queues_remove (vm, dev);
  return rv;
}

void
vnet_dev_crypto_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  if (vec_len (dev->crypto_queues) == 0)
    return;

  vlib_worker_thread_barrier_sync (vm);
  vnet_dev_crypto_queues_remove (vm, dev);
  vlib_worker_thread_barrier_release (vm);
}

static uword
unformat_vnet_dev_crypto_queue_config (unformat_input_t *input, va_list *args)
{
  vnet_dev_crypto_queue_config_t *qc = va_arg (*args, vnet_dev_crypto_queue_config_t *);
  u32 n;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "size %u", &n) && n && n <= CLIB_U16_MAX)
	qc->size = n;
      else if (unformat (input, "threads %U", unformat_bitmap_list, &qc->threads))
	;
      else
	return 0;
    }

  return 1;
}

uword
unformat_vnet_dev_crypto_config (unformat_input_t *input, va_list *args)
{
  vnet_dev_crypto_config_t *cc = va_arg (*args, vnet_dev_crypto_config_t *);
  unformat_input_t sub;
  u32 n, q;

  if (unformat (input, "num-crypto-queues %u", &n))
    {
      if (n == 0 || n > CLIB_U16_MAX)
	return 0;
      cc->num_queues = n;
    }
  else if (unformat (input, "crypto-queue-size %u", &n))
    {
      if (n == 0 || n > CLIB_U16_MAX)
	return 0;
      cc->queue_size = n;
    }
  else if (unformat (input, "crypto-queue %u %U", &q, unformat_vlib_cli_sub_input, &sub))
    {
      uword rv = 0;

      if (q < CLIB_U16_MAX)
	{
	  vec_validate (cc->queues, q);
	  rv = unformat_user (&sub, unformat_vnet_dev_crypto_queue_config, cc->queues + q);
	}
      unformat_free (&sub);
      return rv;
    }
  else
    return 0;

  return 1;
}

void
vnet_dev_crypto_config_copy (vnet_dev_crypto_config_t *dst, vnet_dev_crypto_config_t *src)
{
  *dst = *src;
  dst->queues = vec_dup (src->queues);
  for (u32 i = 0; i < vec_len (dst->queues); i++)
    dst->queues[i].threads = clib_bitmap_dup (src->queues[i].threads);
}

void
vnet_dev_crypto_config_free (vnet_dev_crypto_config_t *cc)
{
  for (u32 i = 0; i < vec_len (cc->queues); i++)
    clib_bitmap_free (cc->queues[i].threads);
  vec_free (cc->queues);
}

static char *vnet_dev_crypto_alg_family_names[] = {
#define _(n, s) [VNET_CRYPTO_ALG_FAMILY_##n] = s,
  foreach_crypto_alg_family
#undef _
};

typedef struct
{
  vnet_crypto_alg_type_t type;
  vnet_crypto_alg_family_t family;
  u8 *auth_name;
  u8 **variants_by_key_bytes[33];
  u64 icv_mask_by_key_bytes[33];
  u8 has_variants : 1;
} vnet_dev_crypto_alg_family_t;

static u8 *
vnet_dev_crypto_alg_variant (vnet_crypto_alg_data_t *ad)
{
  char *family = vnet_dev_crypto_alg_family_names[ad->cipher_family];
  u8 *name = format (0, "%s", ad->name);
  u8 *key = format (0, "-%u", ad->cipher_key_len * 8);
  u8 *variant = 0;

  /* remove the key size from the name, if it is there */
  for (uword i = 0; i + vec_len (key) <= vec_len (name); i++)
    if (memcmp (name + i, key, vec_len (key)) == 0 &&
	(i + vec_len (key) == vec_len (name) || name[i + vec_len (key)] == '-'))
      {
	vec_delete (name, vec_len (key), i);
	break;
      }

  if (vec_len (name) > strlen (family) + 1 && memcmp (name, family, strlen (family)) == 0)
    variant = format (0, "%s", name + strlen (family) + 1);
  else if (vec_len (name) != strlen (family) || memcmp (name, family, strlen (family)))
    variant = vec_dup (name);

  vec_free (name);
  vec_free (key);
  return variant;
}

static u8 *
vnet_dev_crypto_alg_auth_name (vnet_crypto_alg_data_t *ad)
{
  u8 *name = vnet_dev_crypto_alg_variant (ad);

  for (uword i = 0; i + 4 <= vec_len (name); i++)
    if (memcmp (name + i, "-icv", 4) == 0)
      {
	vec_set_len (name, i);
	break;
      }

  return name;
}

static u8 *
format_vnet_dev_crypto_algs (u8 *s, va_list *args)
{
  clib_bitmap_t *algs = va_arg (*args, clib_bitmap_t *);
  vnet_dev_crypto_alg_family_t *families = 0, *f, *fp;
  u32 indent = format_get_indent (s);
  uword alg;

  clib_bitmap_foreach (alg, algs)
    {
      vnet_crypto_alg_data_t *ad = crypto_main.algs + alg;
      u8 is_combined = ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED;
      u8 *variant = 0, *auth_name = 0;

      if (ad->cipher_key_len >= ARRAY_LEN (f->variants_by_key_bytes))
	continue;

      if (is_combined)
	{
	  if (ad->auth_len == 0 || ad->auth_len > 64)
	    continue;
	  auth_name = vnet_dev_crypto_alg_auth_name (ad);
	}
      else
	variant = vnet_dev_crypto_alg_variant (ad);

      f = 0;
      vec_foreach (fp, families)
	if (fp->type == ad->alg_type && fp->family == ad->cipher_family &&
	    vec_is_equal (fp->auth_name, auth_name))
	  f = fp;

      if (f == 0)
	{
	  vec_add2 (families, f, 1);
	  f->type = ad->alg_type;
	  f->family = ad->cipher_family;
	  f->auth_name = auth_name;
	}
      else
	vec_free (auth_name);

      if (is_combined)
	{
	  f->has_variants = 1;
	  f->icv_mask_by_key_bytes[ad->cipher_key_len] |= 1ULL << (ad->auth_len - 1);
	  continue;
	}

      if (variant)
	f->has_variants = 1;
      vec_add1 (f->variants_by_key_bytes[ad->cipher_key_len], variant);
    }

  vec_foreach (f, families)
    {
      char *name = vnet_dev_crypto_alg_family_names[f->family];
      char *sep = " ";

      if (f != families)
	s = format_newline (s, indent);

      if (f->auth_name)
	s = format (s, "%s-hmac-%v:", name, f->auth_name);
      else
	s = format (s, "%s:", name);

      if (f->has_variants == 0)
	{
	  s = format (s, " key sizes:");
	  for (u32 k = 0; k < ARRAY_LEN (f->variants_by_key_bytes); k++)
	    if (f->variants_by_key_bytes[k])
	      {
		s = format (s, "%s%u", sep, k * 8);
		sep = ", ";
	      }
	}
      else
	for (u32 k = 0; k < ARRAY_LEN (f->variants_by_key_bytes); k++)
	  {
	    u64 icv_mask = f->icv_mask_by_key_bytes[k];

	    if (f->variants_by_key_bytes[k] == 0 && icv_mask == 0)
	      continue;
	    s = format_newline (s, indent + 2);
	    s = format (s, "key size %u:", k * 8);
	    vec_foreach_pointer (v, f->variants_by_key_bytes[k])
	      if (v)
		s = format (s, " %v", v);
	    while (icv_mask)
	      {
		s = format (s, " icv%u", count_trailing_zeros (icv_mask) + 1);
		icv_mask = clear_lowest_set_bit (icv_mask);
	      }
	    s = format_word_wrap_last_line_with_indent (s, 100, 2);
	  }

      for (u32 k = 0; k < ARRAY_LEN (f->variants_by_key_bytes); k++)
	{
	  vec_foreach_pointer (v, f->variants_by_key_bytes[k])
	    vec_free (v);
	  vec_free (f->variants_by_key_bytes[k]);
	}
      vec_free (f->auth_name);
    }

  vec_free (families);
  return s;
}

u8 *
format_vnet_dev_crypto_queue_group_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_crypto_queue_group_t *g = va_arg (*args, vnet_dev_crypto_queue_group_t *);
  vnet_dev_queue_config_t *c = &g->config;
  u32 indent = format_get_indent (s);
  uword alg;

  if (g->engine_index == CLIB_U8_MAX)
    s = format (s, "engine: not created, no device attached yet");
  else
    s = format (s, "engine: %s", vnet_dev_main.crypto_engines[g->engine_index]->name);
  s = format_newline (s, indent);
  s = format (s, "queue size: min %u max %u default %u%s", c->min_size, c->max_size,
	      c->default_size, c->size_is_power_of_two ? ", power of 2" : "");
  s = format_newline (s, indent);
  s = format (s, "algorithms:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_vnet_dev_crypto_algs, g->algs);
  if (a->debug)
    {
      s = format_newline (s, indent);
      s = format (s, "algorithm names:");
      clib_bitmap_foreach (alg, g->algs)
	s = format (s, " %U", format_vnet_crypto_alg, alg);
      s = format_word_wrap_last_line_with_indent (s, 100, sizeof ("algorithm names: ") - 1);
    }
  return s;
}

u8 *
format_vnet_dev_crypto_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_crypto_queue_t *cq = va_arg (*args, vnet_dev_crypto_queue_t *);
  vnet_dev_crypto_queue_ops_t *ops = &cq->group->ops;
  u32 indent = format_get_indent (s);

  s = format (s, "queue group: %s", cq->group->name);
  s = format_newline (s, indent);
  s = format (s, "size %u, %s", cq->size, cq->started ? "started" : "stopped");
  s = format_newline (s, indent);
  s = format (s, "threads: %U", format_bitmap_list, cq->assigned_threads);
  if (ops->format_queue_info)
    {
      s = format_newline (s, indent);
      s = vnet_dev_format_in_process (s, cq->dev, "%U", ops->format_queue_info, a, cq);
    }
  return s;
}

static const struct
{
  char *name;
  u32 offset;
  u32 at_clear_offset;
} crypto_queue_counters[] = {
#define _(f, d)                                                                                    \
  { d, STRUCT_OFFSET_OF (vnet_dev_crypto_queue_t, f),                                              \
    STRUCT_OFFSET_OF (vnet_dev_crypto_queue_t, counters_at_clear.f) },
  foreach_vnet_dev_crypto_queue_counter
#undef _
};

u8 *
format_vnet_dev_crypto_queue_counters (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_crypto_queue_t *cq = va_arg (*args, vnet_dev_crypto_queue_t *);
  u32 indent = format_get_indent (s), n = 0;

  FOREACH_ARRAY_ELT (c, crypto_queue_counters)
    {
      u64 v = *(u64 *) ((u8 *) cq + c->offset) - *(u64 *) ((u8 *) cq + c->at_clear_offset);

      if (a->show_zero_counters == 0 && v == 0)
	continue;
      if (n++)
	s = format_newline (s, indent);
      s = format (s, "%-20s%lu", c->name, v);
    }

  return n ? s : format (s, "none");
}

void
vnet_dev_crypto_queue_clear_counters (vnet_dev_crypto_queue_t *cq)
{
  FOREACH_ARRAY_ELT (c, crypto_queue_counters)
    *(u64 *) ((u8 *) cq + c->at_clear_offset) = *(u64 *) ((u8 *) cq + c->offset);
}
