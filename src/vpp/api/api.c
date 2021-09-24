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

#include <vpp/api/types.h>

#include <vpp/api/vpe.api_enum.h>
#include <vpp/api/vpe.api_types.h>

static u16 msg_id_base;
#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

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
vl_api_show_vpe_system_time_t_handler (vl_api_show_vpe_system_time_t *mp)
{
  int rv = 0;
  vl_api_show_vpe_system_time_reply_t *rmp;
  /* *INDENT-OFF* */
  REPLY_MACRO2 (
    VL_API_SHOW_VPE_SYSTEM_TIME_REPLY,
    ({ rmp->vpe_system_time = clib_host_to_net_f64 (unix_time_now ()); }));
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
  rmp->_vl_msg_id = ntohs (VL_API_LOG_DETAILS + msg_id_base);

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

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../open-repo/vlib/memclnt_vlib.c:memclnt_process()
 */
#include <vpp/api/vpe.api.c>
static clib_error_t *
vpe_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  msg_id_base = setup_message_id_table ();

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

/*
 * VPP binary client built into VPP.
 * The "binary-api-json <name> <JSON object>"
 * takes a API name and a JSON object as argument and returns one or more JSON
 * objects.
 */
u32 client_index = ~0;
svm_queue_t *vl_input_queue;
static void
maybe_register_api_client (void)
{
  vl_api_registration_t **regpp;
  vl_api_registration_t *regp;
  void *oldheap;
  api_main_t *am = vlibapi_get_main ();

  if (client_index != ~0)
    return;

  pool_get (am->vl_clients, regpp);

  oldheap = vl_msg_push_heap ();

  *regpp = clib_mem_alloc (sizeof (vl_api_registration_t));

  regp = *regpp;
  clib_memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_SHMEM;
  regp->vl_api_registration_pool_index = regpp - am->vl_clients;
  regp->vlib_rp = am->vlib_rp;
  regp->shmem_hdr = am->shmem_hdr;
  regp->nokeepalive = 1;

  /* Loopback connection */
  /* TODO: This will fail if VPP writes more than queue depth messages in a
   * single API call */
  vl_input_queue = svm_queue_alloc_and_init (1024, sizeof (uword), getpid ());

  regp->vl_input_queue = vl_input_queue;

  regp->name = format (0, "%s", "vpp-internal");
  vec_add1 (regp->name, 0);

  vl_msg_pop_heap (oldheap);

  client_index = vl_msg_api_handle_from_index_and_epoch (
    regp->vl_api_registration_pool_index, am->shmem_hdr->application_restarts);
}

typedef VL_API_PACKED (struct _vl_api_header {
  u16 _vl_msg_id;
  u32 client_index;
}) vl_api_header_t;

static clib_error_t *
print_template (vlib_main_t *vm, u16 id)
{
  api_main_t *am = vlibapi_get_main ();
  cJSON *(*fp) (void *);
  fp = (void *) am->msg_tojson_handlers[id];
  if (!fp)
    goto error;

  void *scratch = clib_mem_alloc (2048);
  if (!scratch)
    goto error;

  clib_memset (scratch, 0, 2048);
  cJSON *t = fp (scratch);
  if (!t)
    goto error;
  clib_mem_free (scratch);
  char *output = cJSON_Print (t);
  if (!output)
    goto error;

  cJSON_Delete (t);
  vlib_cli_output (vm, "%s\n", output);
  cJSON_free (output);

  return 0;

error:
  return clib_error_return (0, "error printing template for\n");
}

static clib_error_t *
api_command_json_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  uword c;
  u8 *cmdp, *argsp, *this_cmd;
  uword *p;
  u8 *inbuf = 0;
  maybe_register_api_client ();

  while (((c = unformat_get_input (input)) != '\n') &&
	 (c != UNFORMAT_END_OF_INPUT))
    vec_add1 (inbuf, c);

  /* Null-terminate the command */
  vec_add1 (inbuf, 0);

  /* In case no args given */
  vec_add1 (inbuf, 0);

  /* Split input into cmd + args */
  this_cmd = cmdp = inbuf;

  /* Skip leading whitespace */
  while (cmdp < (this_cmd + vec_len (this_cmd)))
    {
      if (*cmdp == ' ' || *cmdp == '\t' || *cmdp == '\n')
	{
	  cmdp++;
	}
      else
	break;
    }

  argsp = cmdp;

  /* Advance past the command */
  while (argsp < (this_cmd + vec_len (this_cmd)))
    {
      if (*argsp != ' ' && *argsp != '\t' && *argsp != '\n' && *argsp != 0)
	{
	  argsp++;
	}
      else
	break;
    }
  /* NULL terminate the command */
  *argsp++ = 0;

  /* No arguments? Ensure that argsp points to a proper (empty) string */
  if (argsp == (this_cmd + vec_len (this_cmd) - 1))
    argsp[0] = 0;
  else
    while (argsp < (this_cmd + vec_len (this_cmd)))
      {
	if (*argsp == ' ' || *argsp == '\t' || *argsp == '\n')
	  {
	    argsp++;
	  }
	else
	  break;
      }

  /* Blank input line? */
  if (*cmdp == 0)
    return 0;

  api_main_t *am = vlibapi_get_main ();
  p = hash_get_mem (am->msg_id_by_name, cmdp);
  if (p == 0)
    {
      return clib_error_return (0, "'%s': function not found\n", cmdp);
    }
  u16 id = p[0];

  /* Print help string */
  if (argsp[0] == '?')
    {
      print_template (vm, id);
      return 0;
    }

  cJSON *o = cJSON_Parse ((const char *) argsp);
  if (o == 0)
    {
      return clib_error_return (0, "'%s': does not parse as JSON\n", argsp);
    }

  vl_api_header_t *(*fromjsonfp) (cJSON *, int *len);
  fromjsonfp = (void *) am->msg_fromjson_handlers[id];

  int len = 0;

  vl_api_header_t *mp = fromjsonfp (o, &len);
  if (mp == 0)
    {
      return clib_error_return (
	0, "'%s': JSON to binary API conversion failed\n", cmdp);
    }
  mp->client_index = client_index;

  if (!am->is_autoendian[id])
    (*am->msg_endian_handlers[id]) (mp);
  (*am->msg_handlers[id]) (mp);
  clib_mem_free (mp);

  void *msg;
  cJSON *(*tojsonfp) (void *);
  while (!svm_queue_sub (vl_input_queue, (u8 *) &msg, SVM_Q_NOWAIT, 0))
    {
      VL_MSG_API_UNPOISON ((void *) msg);
      u16 id = ntohs (*((u16 *) msg));
      tojsonfp = (void *) am->msg_tojson_handlers[id];
      if (tojsonfp == 0)
	goto done;
      (*am->msg_endian_handlers[id]) (msg);
      cJSON *o = tojsonfp (msg);
      if (o == 0)
	goto done;
      char *output = cJSON_Print (o);
      cJSON_Delete (o);
      vlib_cli_output (vm, "%s\n", output);
      cJSON_free (output);
    done:
      vl_msg_api_free (msg);
    }

  vec_free (inbuf);
  return 0;
}

VLIB_CLI_COMMAND (api_command_json, static) = {
  .path = "binary-api-json",
  .short_help = "binary-api-json [help] <name> [<args>]",
  .function = api_command_json_fn,
  .is_mp_safe = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
