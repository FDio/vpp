/*
 * Copyright (c) 2020 Pantheon.tech and/or its affiliates.
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

#include "bpf_tracer.h"

#ifdef USE_BPF_TRACE

bpf_tracer_main_t bpf_tracer_main;

static clib_error_t *
bpftracer_config (vlib_main_t * vm, unformat_input_t * input)
{
  bpf_tracer_main_t *bm = &bpf_tracer_main;
  bm->update_interval = 10.0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "update-interval %d", &bm->update_interval))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

static clib_error_t *
bpf_tracer_init (vlib_main_t * vm)
{
  return 0;
}

static void
update_node_runtime (vlib_main_t * vm)
{
  vlib_node_main_t *nm = 0;
  vlib_main_t **stat_vms = 0, *stat_vm;
  uword i, j;

  for (i = 0; i < vec_len (vlib_mains); i++)
    {
      stat_vm = vlib_mains[i];
      if (stat_vm)
	{
	  vec_add1 (stat_vms, stat_vm);
	}
    }

  /*
   * Barrier sync across stats scraping.
   * Otherwise, the counts will be grossly inaccurate.
   */
  vlib_worker_thread_barrier_sync (vm);

  for (j = 0; j < vec_len (stat_vms); j++)
    {
      stat_vm = stat_vms[j];
      nm = &stat_vm->node_main;

      for (i = 0; i < vec_len (nm->nodes); i++)
	{
	  vlib_node_sync_stats (stat_vm, nm->nodes[i]);
	}

      DTRACE_PROBE3 (vpp, vlib_vector_rate_probe,
		     stat_vm->cpu_id,
		     stat_vm->internal_node_vectors -
		     stat_vm->internal_node_vectors_last_clear,
		     stat_vm->internal_node_calls -
		     stat_vm->internal_node_calls_last_clear);
    }
  vlib_worker_thread_barrier_release (vm);

  vec_free (stat_vms);
}

static uword
bpf_tracer_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  bpf_tracer_main_t *bm = &bpf_tracer_main;

  while (1)
    {
      /* update BPF counters */
      update_node_runtime (vm);

      /* suspend for required time interval */
      vlib_process_suspend (vm, (f64) bm->update_interval);
    }
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (bpftracer_config, "bpftracer");

VLIB_INIT_FUNCTION (bpf_tracer_init) =
{
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bpf_tracer_collector, static) =
{
.function = bpf_tracer_process,
.name = "bpftracer-process",
.type = VLIB_NODE_TYPE_PROCESS,
};
/* *INDENT-ON* */

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
