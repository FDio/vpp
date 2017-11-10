/*
 *------------------------------------------------------------------
 * api.c - message handler registration
 *
 * Copyright (c) 2010-2016 Cisco and/or its affiliates.
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
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>

#include <vnet/api_errno.h>
#include <vnet/vnet.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#undef BIHASH_TYPE
#undef __included_bihash_template_h__

#include <vpp/stats/stats.h>

#include <vpp/api/vpe_msg_enum.h>

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
#define foreach_vpe_api_msg                                             \
_(CONTROL_PING, control_ping)                                           \
_(CLI, cli)                                                             \
_(CLI_INBAND, cli_inband)						\
_(GET_NODE_INDEX, get_node_index)                                       \
_(ADD_NODE_NEXT, add_node_next)						\
_(SHOW_VERSION, show_version)						\
_(GET_NODE_GRAPH, get_node_graph)                                       \
_(GET_NEXT_INDEX, get_next_index)                                       \

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
  int stats_memclnt_delete_callback (u32 client_index);

  stats_memclnt_delete_callback (client_index);

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
  api_main_t *am = &api_main;
  u32 offset;

  shmem_vec = *shmem_vecp;

  offset = vec_len (shmem_vec);

  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  vec_validate (shmem_vec, offset + buffer_bytes - 1);

  clib_memcpy (shmem_vec + offset, buffer, buffer_bytes);

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  *shmem_vecp = shmem_vec;
}


static void
vl_api_cli_t_handler (vl_api_cli_t * mp)
{
  vl_api_cli_reply_t *rp;
  unix_shared_memory_queue_t *q;
  vlib_main_t *vm = vlib_get_main ();
  api_main_t *am = &api_main;
  unformat_input_t input;
  u8 *shmem_vec = 0;
  void *oldheap;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = ntohs (VL_API_CLI_REPLY);
  rp->context = mp->context;

  unformat_init_vector (&input, (u8 *) (uword) mp->cmd_in_shmem);

  vlib_cli_input (vm, &input, shmem_cli_output, (uword) & shmem_vec);

  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  vec_add1 (shmem_vec, 0);

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  rp->reply_in_shmem = (uword) shmem_vec;

  vl_msg_api_send_shmem (q, (u8 *) & rp);
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

  unformat_init_string (&input, (char *) mp->cmd, ntohl (mp->length));
  vlib_cli_input (vm, &input, inband_cli_output, (uword) & out_vec);

  u32 len = vec_len (out_vec);
  /* *INDENT-OFF* */
  REPLY_MACRO3(VL_API_CLI_INBAND_REPLY, len,
  ({
    rmp->length = htonl (len);
    clib_memcpy (rmp->reply, out_vec, len);
  }));
  /* *INDENT-ON* */
  vec_free (out_vec);
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
    rmp->node_index = ntohl(node_index);
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
    rmp->next_index = ntohl(next_index);
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
  REPLY_MACRO2(VL_API_GET_NODE_INDEX_REPLY,
  ({
    rmp->next_index = ntohl(next_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_get_node_graph_t_handler (vl_api_get_node_graph_t * mp)
{
  int rv = 0;
  u8 *vector = 0;
  api_main_t *am = &api_main;
  vlib_main_t *vm = vlib_get_main ();
  void *oldheap;
  vl_api_get_node_graph_reply_t *rmp;

  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);

  /*
   * Keep the number of memcpy ops to a minimum (e.g. 1).
   */
  vec_validate (vector, 16384);
  vec_reset_length (vector);

  /* $$$$ FIXME */
  vector = vlib_node_serialize (&vm->node_main, vector,
				(u32) ~ 0 /* all threads */ ,
				1 /* include nexts */ ,
				1 /* include stats */ );

  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&am->vlib_rp->mutex);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GET_NODE_GRAPH_REPLY,
  ({
    rmp->reply_in_shmem = (uword) vector;
  }));
  /* *INDENT-ON* */
}

#define BOUNCE_HANDLER(nn)                                              \
static void vl_api_##nn##_t_handler (                                   \
    vl_api_##nn##_t *mp)                                                \
{                                                                       \
    vpe_client_registration_t *reg;                                     \
    vpe_api_main_t * vam = &vpe_api_main;                               \
    unix_shared_memory_queue_t * q;                                     \
                                                                        \
    /* One registration only... */                                      \
    pool_foreach(reg, vam->nn##_registrations,                          \
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
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../open-repo/vlib/memclnt_vlib.c:memclnt_process()
 */
static clib_error_t *
vpe_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

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
  am->api_trace_cfg[VL_API_CLASSIFY_ADD_DEL_SESSION].size
    += 5 * sizeof (u32x4);

  /*
   * Thread-safe API messages
   */
  am->is_mp_safe[VL_API_IP_ADD_DEL_ROUTE] = 1;
  am->is_mp_safe[VL_API_GET_NODE_GRAPH] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (vpe_api_hookup);

static clib_error_t *
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
  vl_enable_disable_memory_api (vm, 1 /* enable it */ );

  return 0;
}

VLIB_INIT_FUNCTION (vpe_api_init);


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
		   getgrnam_r (s, &_grp, buf, vec_len (buf), &grp)) == ERANGE)
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

static u8 *
format_arp_event (u8 * s, va_list * args)
{
  vl_api_ip4_arp_event_t *event = va_arg (*args, vl_api_ip4_arp_event_t *);

  s = format (s, "pid %d: ", ntohl (event->pid));
  s = format (s, "resolution for %U", format_ip4_address, &event->address);
  return s;
}

static u8 *
format_nd_event (u8 * s, va_list * args)
{
  vl_api_ip6_nd_event_t *event = va_arg (*args, vl_api_ip6_nd_event_t *);

  s = format (s, "pid %d: ", ntohl (event->pid));
  s = format (s, "resolution for %U", format_ip6_address, event->address);
  return s;
}

static clib_error_t *
show_ip_arp_nd_events_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_ip4_arp_event_t *arp_event;
  vl_api_ip6_nd_event_t *nd_event;

  if (pool_elts (am->arp_events) == 0 && pool_elts (am->nd_events) == 0 &&
      pool_elts (am->wc_ip4_arp_events_registrations) == 0 &&
      pool_elts (am->wc_ip6_nd_events_registrations) == 0)
    {
      vlib_cli_output (vm, "No active arp or nd event registrations");
      return 0;
    }

  /* *INDENT-OFF* */
  pool_foreach (arp_event, am->arp_events,
  ({
    vlib_cli_output (vm, "%U", format_arp_event, arp_event);
  }));

  vpe_client_registration_t *reg;
  pool_foreach(reg, am->wc_ip4_arp_events_registrations,
  ({
    vlib_cli_output (vm, "pid %d: bd mac/ip4 binding events",
                     ntohl (reg->client_pid));
  }));

  pool_foreach (nd_event, am->nd_events,
  ({
    vlib_cli_output (vm, "%U", format_nd_event, nd_event);
  }));

  pool_foreach(reg, am->wc_ip6_nd_events_registrations,
  ({
    vlib_cli_output (vm, "pid %d: bd mac/ip6 binding events",
                     ntohl (reg->client_pid));
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_arp_nd_events, static) = {
  .path = "show arp-nd-event registrations",
  .function = show_ip_arp_nd_events_fn,
  .short_help = "Show ip4 arp and ip6 nd event registrations",
};
/* *INDENT-ON* */

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
