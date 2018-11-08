/*
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/api_errno.h>

#include <svm/svmdb.h>

typedef struct
{
  svmdb_client_t *svmdb_client;
  f64 *vector_rate_ptr;
  f64 *input_rate_ptr;
  f64 *sig_error_rate_ptr;
  pid_t *vpef_pid_ptr;
  u64 last_sig_errors;
  u64 current_sig_errors;
  uword *sig_error_bitmap;
  vlib_main_t *vlib_main;
  vlib_main_t **my_vlib_mains;

} gmon_main_t;

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/devices/devices.h>

gmon_main_t gmon_main;

static u64
get_significant_errors (gmon_main_t * gm)
{
  vlib_main_t *this_vlib_main;
  vlib_error_main_t *em;
  uword code;
  int vm_index;
  u64 significant_errors = 0;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (code, gm->sig_error_bitmap,
  ({
    for (vm_index = 0; vm_index < vec_len (gm->my_vlib_mains); vm_index++)
      {
        this_vlib_main = gm->my_vlib_mains[vm_index];
        em = &this_vlib_main->error_main;
        significant_errors += em->counters[code] -
          ((vec_len(em->counters_last_clear) > code) ?
           em->counters_last_clear[code] : 0);
      }
  }));
  /* *INDENT-ON* */

  return (significant_errors);
}

static clib_error_t *
publish_pid (vlib_main_t * vm)
{
  gmon_main_t *gm = &gmon_main;

  *gm->vpef_pid_ptr = getpid ();

  return 0;
}

VLIB_API_INIT_FUNCTION (publish_pid);


static uword
gmon_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  f64 vector_rate;
  u64 input_packets, last_input_packets, new_sig_errors;
  f64 last_runtime, dt, now;
  gmon_main_t *gm = &gmon_main;
  int i;

  last_runtime = 0.0;
  last_input_packets = 0;

  last_runtime = 0.0;
  last_input_packets = 0;

  /* Initial wait for the world to settle down */
  vlib_process_suspend (vm, 5.0);

  for (i = 0; i < vec_len (vlib_mains); i++)
    vec_add1 (gm->my_vlib_mains, vlib_mains[i]);

  while (1)
    {
      vlib_process_suspend (vm, 5.0);
      vector_rate = vlib_last_vector_length_per_node (vm);
      *gm->vector_rate_ptr = vector_rate;
      now = vlib_time_now (vm);
      dt = now - last_runtime;
      input_packets = vnet_get_aggregate_rx_packets ();
      *gm->input_rate_ptr = (f64) (input_packets - last_input_packets) / dt;
      last_runtime = now;
      last_input_packets = input_packets;

      new_sig_errors = get_significant_errors (gm);
      *gm->sig_error_rate_ptr =
	((f64) (new_sig_errors - gm->last_sig_errors)) / dt;
      gm->last_sig_errors = new_sig_errors;
    }

  return 0;			/* not so much */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gmon_process_node,static) = {
  .function = gmon_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "gmon-process",
};
/* *INDENT-ON* */

static clib_error_t *
gmon_init (vlib_main_t * vm)
{
  gmon_main_t *gm = &gmon_main;
  api_main_t *am = &api_main;
  pid_t *swp = 0;
  f64 *v = 0;
  clib_error_t *error;
  svmdb_map_args_t _ma, *ma = &_ma;

  if ((error = vlib_call_init_function (vm, vpe_api_init)))
    return (error);

  if ((error = vlib_call_init_function (vm, vlibmemory_init)))
    return (error);

  gm->vlib_main = vm;

  clib_memset (ma, 0, sizeof (*ma));
  ma->root_path = am->root_path;
  ma->uid = am->api_uid;
  ma->gid = am->api_gid;

  gm->svmdb_client = svmdb_map (ma);

  /* Find or create, set to zero */
  vec_add1 (v, 0.0);
  svmdb_local_set_vec_variable (gm->svmdb_client,
				"vpp_vector_rate", (char *) v, sizeof (*v));
  vec_free (v);
  vec_add1 (v, 0.0);
  svmdb_local_set_vec_variable (gm->svmdb_client,
				"vpp_input_rate", (char *) v, sizeof (*v));
  vec_free (v);
  vec_add1 (v, 0.0);
  svmdb_local_set_vec_variable (gm->svmdb_client,
				"vpp_sig_error_rate",
				(char *) v, sizeof (*v));
  vec_free (v);

  vec_add1 (swp, 0.0);
  svmdb_local_set_vec_variable (gm->svmdb_client,
				"vpp_pid", (char *) swp, sizeof (*swp));
  vec_free (swp);

  /* the value cells will never move, so acquire references to them */
  gm->vector_rate_ptr =
    svmdb_local_get_variable_reference (gm->svmdb_client,
					SVMDB_NAMESPACE_VEC,
					"vpp_vector_rate");
  gm->input_rate_ptr =
    svmdb_local_get_variable_reference (gm->svmdb_client,
					SVMDB_NAMESPACE_VEC,
					"vpp_input_rate");
  gm->sig_error_rate_ptr =
    svmdb_local_get_variable_reference (gm->svmdb_client,
					SVMDB_NAMESPACE_VEC,
					"vpp_sig_error_rate");
  gm->vpef_pid_ptr =
    svmdb_local_get_variable_reference (gm->svmdb_client,
					SVMDB_NAMESPACE_VEC, "vpp_pid");
  return 0;
}

VLIB_INIT_FUNCTION (gmon_init);

static clib_error_t *
gmon_exit (vlib_main_t * vm)
{
  gmon_main_t *gm = &gmon_main;

  if (gm->vector_rate_ptr)
    {
      *gm->vector_rate_ptr = 0.0;
      *gm->vpef_pid_ptr = 0;
      *gm->input_rate_ptr = 0.0;
      *gm->sig_error_rate_ptr = 0.0;
      svm_region_unmap ((void *) gm->svmdb_client->db_rp);
      vec_free (gm->svmdb_client);
    }
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (gmon_exit);

static int
significant_error_enable_disable (gmon_main_t * gm, u32 index, int enable)
{
  vlib_main_t *vm = gm->vlib_main;
  vlib_error_main_t *em = &vm->error_main;

  if (index >= vec_len (em->counters))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  gm->sig_error_bitmap =
    clib_bitmap_set (gm->sig_error_bitmap, index, enable);
  return 0;
}

static clib_error_t *
set_significant_error_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  u32 index;
  int enable = 1;
  int rv;
  gmon_main_t *gm = &gmon_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &index))
	;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  rv = significant_error_enable_disable (gm, index, enable);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return
	(0, "significant_error_enable_disable returned %d", rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_significant_error_command, static) = {
  .path = "set significant error",
  .short_help = "set significant error <counter-index-nnn> [disable]",
  .function = set_significant_error_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
