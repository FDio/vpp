/*
 * Copyright (c) 2021 Intel and/or its affiliates.
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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/scheduler/scheduler.h>

static clib_error_t *
show_scheduler_engines_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_scheduler_main_t *sm = &scheduler_main;
  vnet_scheduler_engine_t *p;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  if (vec_len (sm->engines) == 0)
    {
      vlib_cli_output (vm, "No scheduler engines registered");
      return 0;
    }

  vlib_cli_output (vm, "%-7s%-20s%-8s%s", "Active", "Name", "Prio",
		   "Description");
  vec_foreach (p, sm->engines)
    {
      vlib_cli_output (vm, "%-7s%-20s%-8u%s",
		       (p - sm->engines == sm->active_engine_index ? "*" : ""),
		       p->name, p->priority, p->desc);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_scheduler_engines_command, static) = {
  .path = "show scheduler engines",
  .short_help = "show scheduler engines",
  .function = show_scheduler_engines_command_fn,
};

static clib_error_t *
vnet_scheduler_select_engine (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  vnet_scheduler_main_t *sm = &scheduler_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 engine_index = ~0;
  uword *p;
  char *engine = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &engine))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  p = hash_get_mem (sm->engine_index_by_name, engine);
  if (!p)
    return (clib_error_return (0, "Invalid engine name."));

  engine_index = p[0];

  if (sm->active_engine_index != engine_index)
    {
      sm->active_engine_index = engine_index;
      sm->enqueue_distribute_handler =
	sm->engines[sm->active_engine_index].enqueue_distribute_handler;
      sm->enqueue_aggregate_handler =
	sm->engines[sm->active_engine_index].enqueue_aggregate_handler;
      sm->dequeue_distribute_handler =
	sm->engines[sm->active_engine_index].dequeue_distribute_handler;
      sm->dequeue_aggregate_handler =
	sm->engines[sm->active_engine_index].dequeue_aggregate_handler;
      sm->set_thread_state_handler =
	sm->engines[sm->active_engine_index].set_thread_state_handler;
    }

  vec_free (engine);
  return 0;
}

/*?
 * This command sets active scheduler engine.
 *
 * @cliexpar
 * Example of how to set active scheduler engine:
 * @cliexstart{scheduler select engine gen-sw-sched}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (cmd_vnet_scheduler_select_engine, static) = {
  .path = "scheduler select engine",
  .short_help = "scheduler select engine <name>",
  .function = vnet_scheduler_select_engine,
  .is_mp_safe = 1,
};

static clib_error_t *
vnet_scheduler_set_role (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 *workers[VNET_SCHEDULER_THREAD_N_ROLES] = { 0 };
  u32 n_workers[VNET_SCHEDULER_THREAD_N_ROLES] = { 0 };
  u32 current_role = -1;
  u32 worker_id;
  u32 max_worker_id = 0;
  clib_error_t *err = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
#define _(n, s, b)                                                            \
  if (unformat (line_input, s " %u", &worker_id))                             \
    {                                                                         \
      current_role = VNET_SCHEDULER_THREAD_ROLE_##n;                          \
      max_worker_id = max_worker_id < worker_id ? worker_id : max_worker_id;  \
      vec_add1 (workers[current_role],                                        \
		vlib_get_worker_thread_index (worker_id));                    \
      n_workers[current_role]++;                                              \
    }                                                                         \
  else
      foreach_scheduler_worker_role
#undef _
	if (unformat (line_input, "%u", &worker_id))
      {
	if (current_role == -1)
	  {
	    err = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	    goto error_exit;
	  }
	max_worker_id = max_worker_id < worker_id ? worker_id : max_worker_id;
	vec_add1 (workers[current_role],
		  vlib_get_worker_thread_index (worker_id));
	n_workers[current_role]++;
      }
      else
      {
	err = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
	goto error_exit;
      }
    }

  if (n_workers[VNET_SCHEDULER_THREAD_ROLE_PRODUCER] == 0 ||
      n_workers[VNET_SCHEDULER_THREAD_ROLE_WORKER] == 0 ||
      n_workers[VNET_SCHEDULER_THREAD_ROLE_CONSUMER] == 0)
    {
      err = clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       input);
      goto error_exit;
    }

  if (max_worker_id >= vlib_num_workers ())
    {
      err = clib_error_return (0, "Invalid worker id '%d'", max_worker_id);
      goto error_exit;
    }

  if (vnet_scheduler_change_thread_role (
	vm, workers[VNET_SCHEDULER_THREAD_ROLE_PRODUCER],
	n_workers[VNET_SCHEDULER_THREAD_ROLE_PRODUCER],
	workers[VNET_SCHEDULER_THREAD_ROLE_WORKER],
	n_workers[VNET_SCHEDULER_THREAD_ROLE_WORKER],
	workers[VNET_SCHEDULER_THREAD_ROLE_CONSUMER],
	n_workers[VNET_SCHEDULER_THREAD_ROLE_CONSUMER]) < 0)
    err = clib_error_return (0, "Invalid input '%U'", format_unformat_error,
			     input);

error_exit:
  vec_free (workers[VNET_SCHEDULER_THREAD_ROLE_PRODUCER]);
  vec_free (workers[VNET_SCHEDULER_THREAD_ROLE_WORKER]);
  vec_free (workers[VNET_SCHEDULER_THREAD_ROLE_CONSUMER]);

  return err;
}

/*?
 * This command sets scheduler producer, worker, and consumer worker id list.
 *
 * @cliexpar
 * Example of how to set scheduler roles:
 * @cliexstart{scheduler set worker role producer 0 consumer 1 worker 2 3 4}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (cmd_vnet_scheduler_set_role, static) = {
  .path = "scheduler set worker role",
  .short_help =
    "scheduler set worker role producer <worker_id> <worker_id> ... "
    "worker <wworker_id> <worker_id> ... consumer <worker_id> <worker_id> ...",
  .function = vnet_scheduler_set_role,
  .is_mp_safe = 1,
};

static clib_error_t *
show_scheduler_stats_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_scheduler_main_t *sm = &scheduler_main;
  u32 skip_master = vlib_num_workers () > 0, i;
  u64 now = clib_cpu_time_now ();
  f64 diff = (now - sm->last_time) / (f64) sm->freq;

  if (unformat_user (input, unformat_line_input, line_input))
    unformat_free (line_input);

  vlib_cli_output (vm, "Stats Collection of %20.2f seconds, freq %lu", diff,
		   sm->freq);
  vlib_cli_output (vm, "Producer Stats\n------");
  vlib_cli_output (vm, "%10s%20s%20s", "Thread", "Enqueued", "Enqueue pps");
  for (i = skip_master; i < vlib_thread_main.n_vlib_mains; i++)
    {
      f64 pps;
      u64 curr, *last;

      if (!vnet_scheduler_is_producer (i))
	continue;

      curr = sm->distribute_enqueued[i];
      last = &sm->last_distribute_enqueued[i];
      pps = (curr - *last) / diff;
      vlib_cli_output (vm, "%10u%20lu%20.2f", i, curr, pps);
      *last = curr;
    }

  vlib_cli_output (vm, "Worker Stats\n------");
  vlib_cli_output (vm, "%10s%20s%20s%20s%20s%20s", "Thread", "Dequeued",
		   "Dequeue pps", "Enqueued", "Enqueue pps", "Empty Poll");
  for (i = skip_master; i < vlib_thread_main.n_vlib_mains; i++)
    {
      f64 pps, pps2;
      u64 curr, curr2, *last, *last2;

      if (!vnet_scheduler_is_worker (i))
	continue;

      curr = sm->distribute_dequeued[i];
      curr2 = sm->aggregate_enqueued[i];
      last = &sm->last_distribute_dequeued[i];
      last2 = &sm->last_aggregate_enqueued[i];
      pps = (curr - *last) / diff;
      pps2 = (curr2 - *last2) / diff;
      vlib_cli_output (vm, "%10u%20lu%20.2f%20lu%20.2f%20lu", i, curr, pps,
		       curr2, pps2, sm->distribute_empty_poll[i]);
      *last = curr;
      *last2 = curr2;
    }

  vlib_cli_output (vm, "Consumer Stats\n------");
  vlib_cli_output (vm, "%10s%20s%20s%20s", "Thread", "Dequeued", "Dequeue pps",
		   "Empty Poll");
  for (i = skip_master; i < vlib_thread_main.n_vlib_mains; i++)
    {
      f64 pps;
      u64 curr, *last;
      if (!vnet_scheduler_is_consumer (i))
	continue;

      curr = sm->aggregate_dequeued[i];
      last = &sm->last_aggregate_dequeued[i];
      pps = (curr - *last) / diff;
      vlib_cli_output (vm, "%10u%20lu%20.2f%20lu", i, curr, pps,
		       sm->aggregate_empty_poll[i]);
      *last = curr;
    }
  sm->last_time = now;

  return 0;
}

VLIB_CLI_COMMAND (show_scheduler_stats_command, static) = {
  .path = "show scheduler stats",
  .short_help = "show scheduler stats",
  .function = show_scheduler_stats_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
