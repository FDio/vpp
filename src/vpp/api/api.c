/*
 *------------------------------------------------------------------
 * api.c - message handler registration
 *
 * Copyright (c) 2010-2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <pwd.h>
#include <grp.h>

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

#include <vnet/api_errno.h>
#include <vnet/vnet.h>

#include <vlib/log.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#undef BIHASH_TYPE
#undef __included_bihash_template_h__

#include <vnet/ip/format.h>

#include <vpp/api/vpe_msg_enum.h>
#include <vpp/api/types.h>

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs
#define vl_endianfun		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun
/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun
#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                                                   \
  _ (CONTROL_PING, control_ping)                                              \
  _ (CLI, cli)                                                                \
  _ (CLI_INBAND, cli_inband)                                                  \
  _ (GET_NODE_INDEX, get_node_index)                                          \
  _ (ADD_NODE_NEXT, add_node_next)                                            \
  _ (SHOW_VERSION, show_version)                                              \
  _ (SHOW_THREADS, show_threads)                                              \
  _ (GET_NODE_GRAPH, get_node_graph)                                          \
  _ (GET_NEXT_INDEX, get_next_index)                                          \
  _ (LOG_DUMP, log_dump)                                                      \
  _ (SHOW_VPE_SYSTEM_TIME, show_vpe_system_time)                              \
  _ (GET_F64_ENDIAN_VALUE, get_f64_endian_value)                              \
  _ (GET_F64_INCREMENT_BY_ONE, get_f64_increment_by_one)                      \
  _ (CONNECTION_INFO, connection_info)

#define QUOTE_(x) #x
#define QUOTE(x) QUOTE_(x)

typedef enum
{
  RESOLVE_IP4_ADD_DEL_ROUTE = 1,
  RESOLVE_IP6_ADD_DEL_ROUTE,
} resolve_t;

extern vpe_api_main_t vpe_api_main;

/* Clean up all registrations belonging to the indicated client */
static clib_error_t *
memclnt_delete_callback (u32 client_index)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vpe_client_registration_t *rp;
  uword *p;

#define _(a)                                                    \
    p = hash_get (vam->a##_registration_hash, client_index);    \
    if (p) {                                                    \
        rp = pool_elt_at_index (vam->a##_registrations, p[0]);  \
        pool_put (vam->a##_registrations, rp);                  \
        hash_unset (vam->a##_registration_hash, client_index);  \
    }
  foreach_registration_hash;
#undef _
  return 0;
}

VL_MSG_API_REAPER_FUNCTION (memclnt_delete_callback);

static void
vl_api_control_ping_t_handler (vl_api_control_ping_t * mp)
{
  vl_api_control_ping_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid());
  }));
  /* *INDENT-ON* */
}

static void
shmem_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
{
  u8 **shmem_vecp = (u8 **) arg;
  u8 *shmem_vec;
  void *oldheap;
  u32 offset;

  shmem_vec = *shmem_vecp;

  offset = vec_len (shmem_vec);

  oldheap = vl_msg_push_heap ();

  vec_validate (shmem_vec, offset + buffer_bytes - 1);

  clib_memcpy (shmem_vec + offset, buffer, buffer_bytes);

  vl_msg_pop_heap (oldheap);

  *shmem_vecp = shmem_vec;
}


static void
vl_api_cli_t_handler (vl_api_cli_t * mp)
{
  vl_api_cli_reply_t *rp;
  vl_api_registration_t *reg;
  vlib_main_t *vm = vlib_get_main ();
  unformat_input_t input;
  u8 *shmem_vec = 0;
  void *oldheap;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;;

  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = ntohs (VL_API_CLI_REPLY);
  rp->context = mp->context;

  unformat_init_vector (&input, (u8 *) (uword) mp->cmd_in_shmem);

  vlib_cli_input (vm, &input, shmem_cli_output, (uword) & shmem_vec);

  oldheap = vl_msg_push_heap ();
  vec_add1 (shmem_vec, 0);
  vl_msg_pop_heap (oldheap);

  rp->reply_in_shmem = (uword) shmem_vec;

  vl_api_send_msg (reg, (u8 *) rp);
}

static void
inband_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
{
  u8 **mem_vecp = (u8 **) arg;
  u8 *mem_vec = *mem_vecp;
  u32 offset = vec_len (mem_vec);

  vec_validate (mem_vec, offset + buffer_bytes - 1);
  clib_memcpy (mem_vec + offset, buffer, buffer_bytes);
  *mem_vecp = mem_vec;
}

static void
vl_api_cli_inband_t_handler (vl_api_cli_inband_t * mp)
{
  vl_api_cli_inband_reply_t *rmp;
  int rv = 0;
  vlib_main_t *vm = vlib_get_main ();
  unformat_input_t input;
  u8 *out_vec = 0;
  u8 *cmd_vec = 0;

  if (vl_msg_api_get_msg_length (mp) <
      vl_api_string_len (&mp->cmd) + sizeof (*mp))
    {
      rv = -1;
      goto error;
    }

  cmd_vec = vl_api_from_api_to_new_vec (mp, &mp->cmd);

  unformat_init_string (&input, (char *) cmd_vec,
			vl_api_string_len (&mp->cmd));
  rv = vlib_cli_input (vm, &input, inband_cli_output, (uword) & out_vec);
  unformat_free (&input);

error:
  /* *INDENT-OFF* */
  REPLY_MACRO3(VL_API_CLI_INBAND_REPLY, vec_len (out_vec),
  ({
    vl_api_vec_to_api_string(out_vec, &rmp->reply);
  }));
  /* *INDENT-ON* */
  vec_free (out_vec);
  vec_free (cmd_vec);
}

static void
vl_api_show_version_t_handler (vl_api_show_version_t * mp)
{
  vl_api_show_version_reply_t *rmp;
  int rv = 0;
  char *vpe_api_get_build_directory (void);
  char *vpe_api_get_version (void);
  char *vpe_api_get_build_date (void);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_VERSION_REPLY,
  ({
    strncpy ((char *) rmp->program, "vpe", ARRAY_LEN(rmp->program)-1);
    strncpy ((char *) rmp->build_directory, vpe_api_get_build_directory(),
             ARRAY_LEN(rmp->build_directory)-1);
    strncpy ((char *) rmp->version, vpe_api_get_version(),
             ARRAY_LEN(rmp->version)-1);
    strncpy ((char *) rmp->build_date, vpe_api_get_build_date(),
             ARRAY_LEN(rmp->build_date)-1);
  }));
  /* *INDENT-ON* */
}

/*
 * Get connection information from a running VPP instance
 */
static void
vl_api_connection_info_t_handler (vl_api_connection_info_t *mp)
{
  vl_api_connection_info_reply_t *rmp;
  int rv = 0;
  char *stat_get_socket_filename (void);
  char *unix_get_cli_socket_filename (void);

  char *cli_socket_name = unix_get_cli_socket_filename ();
  char *stat_socket_name = stat_get_socket_filename ();

  if (!cli_socket_name)
    cli_socket_name = "";
  if (!stat_socket_name)
    stat_socket_name = "";

  REPLY_MACRO2 (VL_API_CONNECTION_INFO_REPLY, ({
		  strncpy ((char *) rmp->cli_socket_filename, cli_socket_name,
			   ARRAY_LEN (rmp->cli_socket_filename) - 1);
		  strncpy ((char *) rmp->stat_socket_filename,
			   stat_socket_name,
			   ARRAY_LEN (rmp->stat_socket_filename) - 1);
		}));
}

static void
get_thread_data (vl_api_thread_data_t * td, int index)
{
  vlib_worker_thread_t *w = vlib_worker_threads + index;
  td->id = htonl (index);
  if (w->name)
    strncpy ((char *) td->name, (char *) w->name, ARRAY_LEN (td->name) - 1);
  if (w->registration)
    strncpy ((char *) td->type, (char *) w->registration->name,
	     ARRAY_LEN (td->type) - 1);
  td->pid = htonl (w->lwp);
  td->cpu_id = htonl (w->cpu_id);
  td->core = htonl (w->core_id);
  td->cpu_socket = htonl (w->numa_id);
}

static void
vl_api_show_threads_t_handler (vl_api_show_threads_t * mp)
{
  int count = 0;

#if !defined(__powerpc64__)
  vl_api_registration_t *reg;
  vl_api_show_threads_reply_t *rmp;
  vl_api_thread_data_t *td;
  int i, msg_size = 0;
  count = vec_len (vlib_worker_threads);
  if (!count)
    return;

  msg_size = sizeof (*rmp) + sizeof (rmp->thread_data[0]) * count;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = htons (VL_API_SHOW_THREADS_REPLY);
  rmp->context = mp->context;
  rmp->count = htonl (count);
  td = rmp->thread_data;

  for (i = 0; i < count; i++)
    {
      get_thread_data (&td[i], i);
    }

  vl_api_send_msg (reg, (u8 *) rmp);
#else

  /* unimplemented support */
  rv = -9;
  clib_warning ("power pc does not support show threads api");
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_THREADS_REPLY,
  ({
    rmp->count = htonl(count);
  }));
  /* *INDENT-ON* */
#endif
}

static void
vl_api_get_node_index_t_handler (vl_api_get_node_index_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_get_node_index_reply_t *rmp;
  vlib_node_t *n;
  int rv = 0;
  u32 node_index = ~0;

  n = vlib_get_node_by_name (vm, mp->node_name);

  if (n == 0)
    rv = VNET_API_ERROR_NO_SUCH_NODE;
  else
    node_index = n->index;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NODE_INDEX_REPLY,
  ({
    rmp->node_index = htonl(node_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_next_index_t_handler (vl_api_get_next_index_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_get_next_index_reply_t *rmp;
  vlib_node_t *node, *next_node;
  int rv = 0;
  u32 next_node_index = ~0, next_index = ~0;
  uword *p;

  node = vlib_get_node_by_name (vm, mp->node_name);

  if (node == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto out;
    }

  next_node = vlib_get_node_by_name (vm, mp->next_name);

  if (next_node == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE2;
      goto out;
    }
  else
    next_node_index = next_node->index;

  p = hash_get (node->next_slot_by_node, next_node_index);

  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }
  else
    next_index = p[0];

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NEXT_INDEX_REPLY,
  ({
    rmp->next_index = htonl(next_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_add_node_next_t_handler (vl_api_add_node_next_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_add_node_next_reply_t *rmp;
  vlib_node_t *n, *next;
  int rv = 0;
  u32 next_index = ~0;

  n = vlib_get_node_by_name (vm, mp->node_name);

  if (n == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE;
      goto out;
    }

  next = vlib_get_node_by_name (vm, mp->next_name);

  if (next == 0)
    rv = VNET_API_ERROR_NO_SUCH_NODE2;
  else
    next_index = vlib_node_add_next (vm, n->index, next->index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_ADD_NODE_NEXT_REPLY,
  ({
    rmp->next_index = htonl(next_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_node_graph_t_handler (vl_api_get_node_graph_t * mp)
{
  int rv = 0;
  u8 *vector = 0;
  vlib_main_t *vm = vlib_get_main ();
  void *oldheap;
  vl_api_get_node_graph_reply_t *rmp;
  static vlib_node_t ***node_dups;
  static vlib_main_t **stat_vms;

  oldheap = vl_msg_push_heap ();

  /*
   * Keep the number of memcpy ops to a minimum (e.g. 1).
   */
  vec_validate (vector, 16384);
  vec_reset_length (vector);

  vlib_node_get_nodes (vm, 0 /* main threads */ ,
		       0 /* include stats */ ,
		       1 /* barrier sync */ ,
		       &node_dups, &stat_vms);
  vector = vlib_node_serialize (vm, node_dups, vector, 1 /* include nexts */ ,
				1 /* include stats */ );

  vl_msg_pop_heap (oldheap);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NODE_GRAPH_REPLY,
  ({
    rmp->reply_in_shmem = (uword) vector;
  }));
  /* *INDENT-ON* */
}

static void
show_log_details (vl_api_registration_t * reg, u32 context,
		  f64 timestamp,
		  vl_api_log_level_t * level, u8 * msg_class, u8 * message)
{
  u32 msg_size;

  vl_api_log_details_t *rmp;
  int class_len =
    clib_min (vec_len (msg_class) + 1, ARRAY_LEN (rmp->msg_class));
  int message_len =
    clib_min (vec_len (message) + 1, ARRAY_LEN (rmp->message));
  msg_size = sizeof (*rmp) + class_len + message_len;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_LOG_DETAILS);

  rmp->context = context;
  rmp->timestamp = clib_host_to_net_f64 (timestamp);
  rmp->level = htonl (*level);

  memcpy (rmp->msg_class, msg_class, class_len - 1);
  memcpy (rmp->message, message, message_len - 1);
  /* enforced by memset() above */
  ASSERT (0 == rmp->msg_class[class_len - 1]);
  ASSERT (0 == rmp->message[message_len - 1]);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_log_dump_t_handler (vl_api_log_dump_t * mp)
{

  /* from log.c */
  vlib_log_main_t *lm = &log_main;
  vlib_log_entry_t *e;
  int i = last_log_entry ();
  int count = lm->count;
  f64 time_offset, start_time;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    return;

  start_time = clib_net_to_host_f64 (mp->start_timestamp);

  time_offset = (f64) lm->time_zero_timeval.tv_sec
    + (((f64) lm->time_zero_timeval.tv_usec) * 1e-6) - lm->time_zero;

  while (count--)
    {
      e = vec_elt_at_index (lm->entries, i);
      if (start_time <= e->timestamp + time_offset)
	show_log_details (reg, mp->context, e->timestamp + time_offset,
			  (vl_api_log_level_t *) & e->level,
			  format (0, "%U", format_vlib_log_class, e->class),
			  e->string);
      i = (i + 1) % lm->size;
    }

}

static void
vl_api_show_vpe_system_time_t_handler (vl_api_show_vpe_system_time_t * mp)
{
  int rv = 0;
  vl_api_show_vpe_system_time_reply_t *rmp;
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_SHOW_VPE_SYSTEM_TIME_REPLY,
  ({
    rmp->vpe_system_time = clib_host_to_net_f64 (unix_time_now ());
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_f64_endian_value_t_handler (vl_api_get_f64_endian_value_t * mp)
{
  int rv = 0;
  f64 one = 1.0;
  vl_api_get_f64_endian_value_reply_t *rmp;
  if (1.0 != clib_net_to_host_f64 (mp->f64_one))
    rv = VNET_API_ERROR_API_ENDIAN_FAILED;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_F64_ENDIAN_VALUE_REPLY,
  ({
    rmp->f64_one_result = clib_host_to_net_f64 (one);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_f64_increment_by_one_t_handler (vl_api_get_f64_increment_by_one_t *
					   mp)
{
  int rv = 0;
  vl_api_get_f64_increment_by_one_reply_t *rmp;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_F64_INCREMENT_BY_ONE_REPLY,
  ({
    rmp->f64_value = clib_host_to_net_f64 (clib_net_to_host_f64(mp->f64_value) + 1.0);
  }));
  /* *INDENT-ON* */
}

#define BOUNCE_HANDLER(nn)                                              \
static void vl_api_##nn##_t_handler (                                   \
    vl_api_##nn##_t *mp)                                                \
{                                                                       \
    vpe_client_registration_t *reg;                                     \
    vpe_api_main_t * vam = &vpe_api_main;                               \
    svm_queue_t * q;                                     \
                                                                        \
    /* One registration only... */                                      \
    pool_foreach (reg, vam->nn##_registrations)                          \
    ({                                                                  \
        q = vl_api_client_index_to_input_queue (reg->client_index);     \
        if (q) {                                                        \
            /*                                                          \
             * If the queue is stuffed, turf the msg and complain       \
             * It's unlikely that the intended recipient is             \
             * alive; avoid deadlock at all costs.                      \
             */                                                         \
            if (q->cursize == q->maxsize) {                             \
                clib_warning ("ERROR: receiver queue full, drop msg");  \
                vl_msg_api_free (mp);                                   \
                return;                                                 \
            }                                                           \
            vl_msg_api_send_shmem (q, (u8 *)&mp);                       \
            return;                                                     \
        }                                                               \
    }));                                                                \
    vl_msg_api_free (mp);                                               \
}

static void setup_message_id_table (api_main_t * am);

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../open-repo/vlib/memclnt_vlib.c:memclnt_process()
 */
static clib_error_t *
vpe_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Trace space for classifier mask+match
   */
  am->api_trace_cfg[VL_API_CLASSIFY_ADD_DEL_TABLE].size += 5 * sizeof (u32x4);
  am->api_trace_cfg[VL_API_CLASSIFY_ADD_DEL_SESSION].size +=
    5 * sizeof (u32x4);

  /*
   * Thread-safe API messages
   */
  am->is_mp_safe[VL_API_CONTROL_PING] = 1;
  am->is_mp_safe[VL_API_CONTROL_PING_REPLY] = 1;
  am->is_mp_safe[VL_API_IP_ROUTE_ADD_DEL] = 1;
  am->is_mp_safe[VL_API_GET_NODE_GRAPH] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (vpe_api_hookup);

clib_error_t *
vpe_api_init (vlib_main_t * vm)
{
  vpe_api_main_t *am = &vpe_api_main;

  am->vlib_main = vm;
  am->vnet_main = vnet_get_main ();
#define _(a)                                                    \
  am->a##_registration_hash = hash_create (0, sizeof (uword));
  foreach_registration_hash;
#undef _

  vl_set_memory_region_name ("/vpe-api");
  vl_mem_api_enable_disable (vm, 1 /* enable it */ );

  return 0;
}

static clib_error_t *
api_segment_config (vlib_main_t * vm, unformat_input_t * input)
{
  u8 *chroot_path;
  u64 baseva, size, pvt_heap_size;
  int uid, gid, rv;
  const int max_buf_size = 4096;
  char *s, *buf;
  struct passwd _pw, *pw;
  struct group _grp, *grp;
  clib_error_t *e;
  buf = vec_new (char, 128);
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "prefix %s", &chroot_path))
	{
	  vec_add1 (chroot_path, 0);
	  vl_set_memory_root_path ((char *) chroot_path);
	}
      else if (unformat (input, "uid %d", &uid))
	vl_set_memory_uid (uid);
      else if (unformat (input, "gid %d", &gid))
	vl_set_memory_gid (gid);
      else if (unformat (input, "baseva %llx", &baseva))
	vl_set_global_memory_baseva (baseva);
      else if (unformat (input, "global-size %lldM", &size))
	vl_set_global_memory_size (size * (1ULL << 20));
      else if (unformat (input, "global-size %lldG", &size))
	vl_set_global_memory_size (size * (1ULL << 30));
      else if (unformat (input, "global-size %lld", &size))
	vl_set_global_memory_size (size);
      else if (unformat (input, "global-pvt-heap-size %lldM", &pvt_heap_size))
	vl_set_global_pvt_heap_size (pvt_heap_size * (1ULL << 20));
      else if (unformat (input, "global-pvt-heap-size size %lld",
			 &pvt_heap_size))
	vl_set_global_pvt_heap_size (pvt_heap_size);
      else if (unformat (input, "api-pvt-heap-size %lldM", &pvt_heap_size))
	vl_set_api_pvt_heap_size (pvt_heap_size * (1ULL << 20));
      else if (unformat (input, "api-pvt-heap-size size %lld",
			 &pvt_heap_size))
	vl_set_api_pvt_heap_size (pvt_heap_size);
      else if (unformat (input, "api-size %lldM", &size))
	vl_set_api_memory_size (size * (1ULL << 20));
      else if (unformat (input, "api-size %lldG", &size))
	vl_set_api_memory_size (size * (1ULL << 30));
      else if (unformat (input, "api-size %lld", &size))
	vl_set_api_memory_size (size);
      else if (unformat (input, "uid %s", &s))
	{
	  /* lookup the username */
	  pw = NULL;
	  while (((rv =
		   getpwnam_r (s, &_pw, buf, vec_len (buf), &pw)) == ERANGE)
		 && (vec_len (buf) <= max_buf_size))
	    {
	      vec_resize (buf, vec_len (buf) * 2);
	    }
	  if (rv < 0)
	    {
	      e = clib_error_return_code (0, rv,
					  CLIB_ERROR_ERRNO_VALID |
					  CLIB_ERROR_FATAL,
					  "cannot fetch username %s", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  if (pw == NULL)
	    {
	      e =
		clib_error_return_fatal (0, "username %s does not exist", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  vec_free (s);
	  vl_set_memory_uid (pw->pw_uid);
	}
      else if (unformat (input, "gid %s", &s))
	{
	  /* lookup the group name */
	  grp = NULL;
	  while (((rv =
		   getgrnam_r (s, &_grp, buf, vec_len (buf),
			       &grp)) == ERANGE)
		 && (vec_len (buf) <= max_buf_size))
	    {
	      vec_resize (buf, vec_len (buf) * 2);
	    }
	  if (rv != 0)
	    {
	      e = clib_error_return_code (0, rv,
					  CLIB_ERROR_ERRNO_VALID |
					  CLIB_ERROR_FATAL,
					  "cannot fetch group %s", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  if (grp == NULL)
	    {
	      e = clib_error_return_fatal (0, "group %s does not exist", s);
	      vec_free (s);
	      vec_free (buf);
	      return e;
	    }
	  vec_free (s);
	  vec_free (buf);
	  vl_set_memory_gid (grp->gr_gid);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (api_segment_config, "api-segment");

void *
get_unformat_vnet_sw_interface (void)
{
  return (void *) &unformat_vnet_sw_interface;
}

#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_memclnt;
  foreach_vl_msg_name_crc_vpe;
#undef _

#define vl_api_version_tuple(n,mj, mi, p) \
  vl_msg_api_add_version (am, #n, mj, mi, p);
#include <vpp/api/vpe_all_api_h.h>
#undef vl_api_version_tuple
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
