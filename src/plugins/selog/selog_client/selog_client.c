/*
 *------------------------------------------------------------------
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <vlibmemory/memclnt.api_enum.h>
#include <vlibmemory/memclnt.api_types.h>
#include <selog/selog_client/selog_client_internal.h>
#include <sys/mman.h>
#include <selog/selog.api_enum.h>
#include <selog/selog.api_types.h>

#ifndef SELOG_CLIENT_HEAPSIZE
#define SELOG_CLIENT_HEAPSIZE (16 * 1024 * 1024)
#endif

#define SELOG_REPLY_MSG_ID_BASE selog_msg_id_base

static u16 selog_msg_id_base;

static void
selog_client_init_mem (void)
{
  void *mem = 0;
  void *heap = 0;
  mem = mmap (0, SELOG_CLIENT_HEAPSIZE, PROT_READ | PROT_WRITE,
	      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED)
    {
      SELOG_LOG_ERROR ("mmap failed");
      abort ();
    }

  heap = clib_mem_init (mem, SELOG_CLIENT_HEAPSIZE);
  if (!heap)
    {
      SELOG_LOG_ERROR ("clib_mem_init_thread_safe failed");
      abort ();
    }
}

selog_client_ctx_t *
selog_client_ctx_alloc ()
{
  selog_client_main_t *scm = &selog_client_main;
  selog_client_internal_ctx_t *ictx;
  pool_get_zero (scm->internal_ctx, ictx);
  clib_spinlock_init (&ictx->lock);
  ictx->state = SELOG_CLIENT_INTERNAL_STATE_DISCONNECTED;
  elog_init (&ictx->private_em, 0);
  return &ictx->client_ctx;
}

void
selog_client_ctx_free (selog_client_ctx_t *ctx)
{
  selog_client_main_t *scm = &selog_client_main;
  selog_client_internal_ctx_t *ictx = SELOG_INTERNAL_CTX (ctx);
  if (ictx->bapi_sock_ctx.socket_fd != 0)
    {
      SELOG_LOG_ERROR ("Freeing a connected context, undefined behavior!");
      abort ();
    }
  clib_spinlock_free (&ictx->lock);
  pool_put (scm->internal_ctx, ictx);
}

#define foreach_selog_msg                                                     \
  _ (SELOG_GET_SHM_REPLY, selog_get_shm_reply)                                \
  _ (SELOG_GET_STRING_TABLE_REPLY, selog_get_string_table_reply)              \
  _ (SELOG_TRACK_DETAILS, selog_track_details)                                \
  _ (SELOG_EVENT_TYPE_DETAILS, selog_event_type_details)                      \
  _ (SELOG_EVENT_TYPE_STRING_DETAILS, selog_event_type_string_details)

#define foreach_memclnt_msg _ (CONTROL_PING_REPLY, control_ping_reply)

#define vl_endianfun /* define message structures */
#include <selog/selog.api.h>
#include <vlibmemory/memclnt.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <selog/selog.api.h>
#include <vlibmemory/memclnt.api.h>
#undef vl_calcsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include <selog/selog.api.h>
#include <vlibmemory/memclnt.api.h>
#undef vl_printfun

#define vl_api_version(n, v) static u32 selog_api_version = v;
#include <selog/selog.api.h>
#undef vl_api_version

/* all API message handlers */
static void
vl_api_selog_get_shm_reply_t_handler (vl_api_selog_get_shm_reply_t *mp)
{
  selog_client_internal_ctx_t *ictx;
  clib_error_t *err = 0;
  int rv = 0;
  ssvm_private_t *ssvm;
  int fd;

  vl_api_selog_get_shm_reply_t_endian (mp, 0 /* to host byte order */);
  ictx = pool_elt_at_index (selog_client_main.internal_ctx, mp->context);
  SELOG_LOG_DEBUG ("%s: vl_api_selog_get_shm_reply_t_handler",
		   ictx->client_ctx.client_name);
  if (mp->retval < 0)
    {
      SELOG_LOG_ERROR ("vl_api_selog_get_shm_reply_t_handler: error %d",
		       mp->retval);
      goto failed;
    }
  /* Receive fds */
  if ((err =
	 vl_socket_client_recv_fd_msg2 (&ictx->bapi_sock_ctx, &fd, 1, 1)) != 0)
    {
      SELOG_LOG_ERROR ("%s: vl_socket_client_recv_fd_msg2 failed",
		       ictx->client_ctx.client_name);
      clib_error_report (err);
      goto failed;
    }

  /* Connect the SSVM */
  ssvm = &ictx->ssvm;
  ssvm->my_pid = getpid ();
  ssvm->name =
    format (0, "selog_client_%s%c", ictx->client_ctx.client_name, 0);
  ssvm->requested_va = 0;
  ssvm->fd = fd;

  if ((rv = ssvm_client_init_memfd (ssvm)) != 0)
    {
      SELOG_LOG_ERROR ("%s: ssvm_client_init_memfd failed", ssvm->name);
      goto failed;
    }
  ictx->sh =
    (selog_shared_header_t *) ((u8 *) ssvm->sh + (uword) ssvm->sh->opaque[0]);

  /* Replace the private elog ring with the shared one */
  vec_free (ictx->private_em.event_ring);
  ictx->private_em.event_ring = ictx->sh->em.event_ring;
  ictx->private_em.event_ring_size = ictx->sh->em.event_ring_size;

  clib_atomic_store_rel_n (&ictx->state,
			   SELOG_CLIENT_INTERNAL_STATE_SHM_RECEIVED);
  return;
failed:
  clib_atomic_store_rel_n (&ictx->state, SELOG_CLIENT_INTERNAL_STATE_ERROR);
  return;
}

static void
vl_api_selog_get_string_table_reply_t_handler (
  vl_api_selog_get_string_table_reply_t *mp)
{
  selog_client_internal_ctx_t *ictx;
  u8 *string_tmp = 0;
  uword offset;
  vl_api_selog_get_string_table_reply_t_endian (mp,
						0 /* to host byte order */);
  ictx = pool_elt_at_index (selog_client_main.internal_ctx, mp->context);
  SELOG_LOG_DEBUG ("%s: vl_api_selog_get_string_table_reply_t_handler",
		   ictx->client_ctx.client_name);

  if (mp->retval < 0)
    {
      SELOG_LOG_ERROR (
	"%s: vl_api_selog_get_string_table_reply_t_handler: error %d",
	ictx->client_ctx.client_name, mp->retval);
      goto failed;
    }

  /* Check that the beginning of the string table matches the existing one */
  if (vl_api_string_len (&mp->s) && ictx->private_em.string_table &&
      clib_memcmp (mp->s.buf, ictx->private_em.string_table,
		   clib_min (vl_api_string_len (&mp->s),
			     vec_len (ictx->private_em.string_table))) != 0)
    {
      SELOG_LOG_ERROR ("%s: string table mismatch",
		       ictx->client_ctx.client_name);
      goto failed;
    }

  offset = vec_len (ictx->private_em.string_table);

  while (offset < vl_api_string_len (&mp->s))
    {
      u8 *s;
      s = (u8 *) mp->s.buf + offset;
      string_tmp = format (0, "%s%c", s, 0);
      vec_append (ictx->private_em.string_table, string_tmp);
      hash_set_mem (ictx->private_em.string_table_hash, string_tmp, offset);
      offset += clib_strnlen ((char *) s, vl_api_string_len (&mp->s)) + 1;
      string_tmp = 0;
    }
  clib_atomic_store_rel_n (&ictx->state,
			   SELOG_CLIENT_INTERNAL_STATE_STRING_TABLE_LOADED);
  return;
failed:
  clib_atomic_store_rel_n (&ictx->state, SELOG_CLIENT_INTERNAL_STATE_ERROR);
  return;
}

static void
vl_api_selog_track_details_t_handler (vl_api_selog_track_details_t *mp)
{
  selog_client_internal_ctx_t *ictx;
  vl_api_selog_track_details_t_endian (mp, 0 /* to host byte order */);
  ictx = pool_elt_at_index (selog_client_main.internal_ctx, mp->context);
  SELOG_LOG_DEBUG ("%s index %d: vl_api_selog_track_details_t_handler",
		   ictx->client_ctx.client_name, mp->index);
  if (mp->index >= vec_len (ictx->private_em.tracks))
    {
      elog_track_t track = { 0 };
      char *name;
      name = vl_api_from_api_to_new_c_string (&mp->name);
      track.name = name;
      elog_track_register (&ictx->private_em, &track);
      vec_free (name);
      ASSERT (mp->index == vec_len (ictx->private_em.tracks) - 1);
      SELOG_LOG_INFO ("%s: registered track index %d (%s)",
		      ictx->client_ctx.client_name, mp->index, track.name);
    }
  else
    SELOG_LOG_WARNING ("%s: track index %d already exists",
		       ictx->client_ctx.client_name, mp->index);
}

static char *
selog_client_parse_digits (char *s, char *end, u8 *value_parsed)
{
  u8 v = 0;
  *value_parsed = 0;
  while (s < end && *s >= '0' && *s <= '9')
    {
      v = v * 10 + (*s - '0');
      s++;
    }
  *value_parsed = v;
  return s;
}

static void
selog_client_parse_elog_type_for_strings (selog_client_internal_ctx_t *ictx,
					  uword type_index)
{
  elog_event_type_t *et =
    vec_elt_at_index (ictx->private_em.event_types, type_index);
  vec_validate (ictx->event_type_private, type_index);
  selog_type_private_t *st =
    vec_elt_at_index (ictx->event_type_private, type_index);
  char *s = (char *) et->format_args;
  u8 current_offset = 0;
  u8 var_size = 0;
  u8 digits_parsed;
  while (*s && s < vec_end (et->format_args))
    {
      switch (s[0])
	{
	case 'i':
	case 't':
	case 'f':
	case 's':
	  s += 1;
	  s = selog_client_parse_digits (s, vec_end (et->format_args),
					 &digits_parsed);
	  current_offset += digits_parsed;
	  if (digits_parsed == 0)
	    {
	      SELOG_LOG_DEBUG (
		"Variable size string detected in event type %s", et->format);
	      var_size = 1;
	    }
	  break;
	case 'T':
	  if (var_size)
	    {
	      SELOG_LOG_ERROR ("String after variable size string is not "
			       "supported by client %s",
			       et->format);
	      abort ();
	    }
	  s += 1;
	  s = selog_client_parse_digits (s, vec_end (et->format_args),
					 &digits_parsed);
	  vec_add1 (st->string_offset, current_offset);
	  current_offset += digits_parsed;
	  vec_add1 (st->string_size, digits_parsed);
	  break;
	default:
	  SELOG_LOG_ERROR ("Unknown format args '%s' in event type %s",
			   et->format_args, et->format);
	  abort ();
	}
    }
}

static void
vl_api_selog_event_type_details_t_handler (
  vl_api_selog_event_type_details_t *mp)
{
  selog_client_internal_ctx_t *ictx;
  vl_api_selog_event_type_details_t_endian (mp, 0 /* to host byte order */);
  ictx = pool_elt_at_index (selog_client_main.internal_ctx, mp->context);
  SELOG_LOG_DEBUG ("%s index %d: vl_api_selog_event_type_details_t_handler",
		   ictx->client_ctx.client_name, mp->index);
  if (mp->index >= vec_len (ictx->private_em.event_types))
    {
      elog_event_type_t event_type = { 0 };
      char *s = 0;
      event_type.format = vl_api_from_api_to_new_c_string (&mp->fmt);
      vec_validate (s, sizeof (mp->fmt_args) - 1);
      event_type.format_args = s;
      clib_strncpy (event_type.format_args, (char *) mp->fmt_args,
		    vec_len (event_type.format_args) - 1);
      uword l;
      l = elog_event_type_register (&ictx->private_em, &event_type);
      selog_client_parse_elog_type_for_strings (ictx, l);
      ASSERT (mp->index == l);
      SELOG_LOG_INFO (
	"%s: registered event type index %d for format %s and args %s",
	ictx->client_ctx.client_name, mp->index, event_type.format, s);
      vec_free (s);
    }
  else
    SELOG_LOG_WARNING ("%s: event type index %d already exists",
		       ictx->client_ctx.client_name, mp->index);
}

static void
vl_api_selog_event_type_string_details_t_handler (
  vl_api_selog_event_type_string_details_t *mp)
{
  selog_client_internal_ctx_t *ictx;
  elog_event_type_t *event_type;
  char *s;
  vl_api_selog_event_type_string_details_t_endian (mp,
						   0 /* to host byte order */);
  ictx = pool_elt_at_index (selog_client_main.internal_ctx, mp->context);
  event_type = vec_elt_at_index (ictx->private_em.event_types,
				 ictx->current_event_type_index);
  SELOG_LOG_DEBUG ("%s index %lu enum_string_index %d: "
		   "vl_api_selog_event_type_string_details_t_handler",
		   ictx->client_ctx.client_name,
		   ictx->current_event_type_index, mp->index);

  if (mp->index >= vec_len (event_type->enum_strings_vector))
    {
      s = vl_api_from_api_to_new_c_string (&mp->s);
      vec_validate (event_type->enum_strings_vector, mp->index);
      event_type->enum_strings_vector[mp->index] = s;
      ASSERT (mp->index == vec_len (event_type->enum_strings_vector) - 1);
      SELOG_LOG_INFO ("%s: registered event type index %lu enum string index "
		      "%d (%s)",
		      ictx->client_ctx.client_name,
		      ictx->current_event_type_index, mp->index, s);
    }
  else
    SELOG_LOG_WARNING (
      "%s: event type index %lu enum string index %d already exists",
      ictx->client_ctx.client_name, ictx->current_event_type_index, mp->index);
}

static void
vl_api_control_ping_reply_t_handler (vl_api_control_ping_reply_t *mp)
{
  selog_client_internal_ctx_t *ictx;
  vl_api_control_ping_reply_t_endian (mp, 0 /* to host byte order */);
  ictx = pool_elt_at_index (selog_client_main.internal_ctx, mp->context);
  SELOG_LOG_DEBUG ("%s: vl_api_control_ping_reply_t_handler",
		   ictx->client_ctx.client_name);

  clib_atomic_store_rel_n (&ictx->multipart_done, 1);
  return;
}
static void
selog_client_bapi_hookup (void)
{
  u8 *msg_base_lookup_name = format (0, "selog_%08x%c", selog_api_version, 0);

  SELOG_REPLY_MSG_ID_BASE =
    vl_client_get_first_plugin_msg_id ((char *) msg_base_lookup_name);

  vec_free (msg_base_lookup_name);

  if (SELOG_REPLY_MSG_ID_BASE == (u16) ~0)
    {
      SELOG_LOG_ERROR ("vl_client_get_first_plugin_msg_id failed for selog");
      abort ();
    }

#define _(N, n)                                                               \
  vl_msg_api_config (&(vl_msg_api_msg_config_t){                              \
    .id = SELOG_REPLY_MSG_ID_BASE + VL_API_##N,                               \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler,                                        \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof (vl_api_##n##_t),                                          \
    .traced = (u32) 1,                                                        \
    .tojson = vl_api_##n##_t_tojson,                                          \
    .fromjson = vl_api_##n##_t_fromjson,                                      \
    .calc_size = vl_api_##n##_t_calc_size,                                    \
  });
  foreach_selog_msg;
#undef _

#define _(N, n)                                                               \
  vl_msg_api_config (&(vl_msg_api_msg_config_t){                              \
    .id = VL_API_##N + 1,                                                     \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler,                                        \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof (vl_api_##n##_t),                                          \
    .traced = (u32) 1,                                                        \
    .tojson = vl_api_##n##_t_tojson,                                          \
    .fromjson = vl_api_##n##_t_fromjson,                                      \
    .calc_size = vl_api_##n##_t_calc_size,                                    \
  });
  foreach_memclnt_msg;
#undef _
}

static int
selog_client_ictx_wait_for_state_change (selog_client_internal_ctx_t *ictx,
					 u8 expected_state)
{
  f64 timeout = clib_time_now (&selog_client_main.time) + 5.0;
  int async_error = 0;

  while (clib_time_now (&selog_client_main.time) < timeout)
    {
      if (clib_atomic_load_acq_n (&ictx->state) == expected_state)
	return SELOG_CLIENT_ERROR_NONE;

      if (clib_atomic_load_acq_n (&ictx->state) ==
	  SELOG_CLIENT_INTERNAL_STATE_ERROR)
	{
	  SELOG_LOG_ERROR ("%s: in error state", ictx->client_ctx.client_name);
	  async_error = ictx->async_error;
	  ictx->async_error = 0;
	  return -async_error;
	}
    }
  SELOG_LOG_DEBUG ("%s: timeout waiting for state %s, current state %s",
		   ictx->client_ctx.client_name,
		   selog_client_internal_state_str (expected_state),
		   selog_client_internal_state_str (ictx->state));

  return -SELOG_CLIENT_ERROR_TIMEOUT;
}

static int
selog_client_ictx_wait_for_multipart_done (selog_client_internal_ctx_t *ictx)
{
  f64 timeout = clib_time_now (&selog_client_main.time) + 5.0;

  while (clib_time_now (&selog_client_main.time) < timeout)
    {
      if (clib_atomic_load_acq_n (&ictx->multipart_done) == 1)
	{
	  ictx->multipart_done = 0;
	  if (ictx->state ==
	      SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_ALL_TRACKS)
	    clib_atomic_store_rel_n (
	      &ictx->state, SELOG_CLIENT_INTERNAL_STATE_ALL_TRACKS_LOADED);
	  else if (ictx->state ==
		   SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_ALL_EVENT_TYPES)
	    clib_atomic_store_rel_n (
	      &ictx->state,
	      SELOG_CLIENT_INTERNAL_STATE_ALL_EVENT_TYPES_LOADED);
	  else if (ictx->state ==
		   SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_ENUM_STRINGS)
	    clib_atomic_store_rel_n (
	      &ictx->state, SELOG_CLIENT_INTERNAL_STATE_ENUM_STRINGS_LOADED);
	  else
	    {
	      SELOG_LOG_ERROR ("%s: unexpected state %s on multipart done",
			       ictx->client_ctx.client_name,
			       selog_client_internal_state_str (ictx->state));
	      abort ();
	    }
	  return SELOG_CLIENT_ERROR_NONE;
	}
    }
  SELOG_LOG_DEBUG ("%s: timeout waiting for multipart done",
		   ictx->client_ctx.client_name);
  ictx->multipart_done = 0;
  return -SELOG_CLIENT_ERROR_TIMEOUT;
}

static void
selog_client_ictx_want_multipart_done (selog_client_internal_ctx_t *ictx)
{
  vl_api_control_ping_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    {
      SELOG_LOG_ERROR ("vl_msg_api_alloc failed");
      return;
    }
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = VL_API_CONTROL_PING + 1;
  mp->client_index = ictx->api_client_handle;
  mp->context = ictx - selog_client_main.internal_ctx;
  vl_api_control_ping_t_endian (mp, 1 /* to net byte order */);

  ASSERT (ictx->multipart_done == 0);
  vl_msg_api_send_shmem (ictx->vl_input_queue, (u8 *) &mp);
}

static int32_t
selog_client_ictx_retrieve_shm (selog_client_internal_ctx_t *ictx)
{
  vl_api_selog_get_shm_t *mp;
  int rv = SELOG_CLIENT_ERROR_NONE;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    {
      SELOG_LOG_ERROR ("vl_msg_api_alloc failed");
      return -SELOG_CLIENT_ERROR_INVALID_ARG;
    }

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = SELOG_REPLY_MSG_ID_BASE + VL_API_SELOG_GET_SHM;
  mp->client_index = ictx->api_client_handle;
  mp->context = ictx - selog_client_main.internal_ctx;
  vl_api_selog_get_shm_t_endian (mp, 1 /* to net byte order */);
  ictx->state = SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_SHM;
  vl_msg_api_send_shmem (ictx->vl_input_queue, (u8 *) &mp);
  rv = selog_client_ictx_wait_for_state_change (
    ictx, SELOG_CLIENT_INTERNAL_STATE_SHM_RECEIVED);

  return rv;
}

static int32_t
selog_client_ictx_retrieve_string_table (selog_client_internal_ctx_t *ictx)
{
  vl_api_selog_get_string_table_t *mp;
  int rv = SELOG_CLIENT_ERROR_NONE;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    {
      SELOG_LOG_ERROR ("vl_msg_api_alloc failed");
      return -SELOG_CLIENT_ERROR_INVALID_ARG;
    }

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = SELOG_REPLY_MSG_ID_BASE + VL_API_SELOG_GET_STRING_TABLE;
  mp->client_index = ictx->api_client_handle;
  mp->context = ictx - selog_client_main.internal_ctx;
  vl_api_selog_get_string_table_t_endian (mp, 1 /* to net byte order */);
  ictx->state = SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_STRING_TABLE;
  vl_msg_api_send_shmem (ictx->vl_input_queue, (u8 *) &mp);
  rv = selog_client_ictx_wait_for_state_change (
    ictx, SELOG_CLIENT_INTERNAL_STATE_STRING_TABLE_LOADED);

  return rv;
}

static int32_t
selog_client_ictx_retrieve_all_tracks (selog_client_internal_ctx_t *ictx)
{
  vl_api_selog_track_dump_t *mp;
  int rv = SELOG_CLIENT_ERROR_NONE;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    {
      SELOG_LOG_ERROR ("vl_msg_api_alloc failed");
      return -SELOG_CLIENT_ERROR_INVALID_ARG;
    }
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = SELOG_REPLY_MSG_ID_BASE + VL_API_SELOG_TRACK_DUMP;
  mp->client_index = ictx->api_client_handle;
  mp->context = ictx - selog_client_main.internal_ctx;
  vl_api_selog_track_dump_t_endian (mp, 1 /* to net byte order */);
  ictx->state = SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_ALL_TRACKS;
  vl_msg_api_send_shmem (ictx->vl_input_queue, (u8 *) &mp);
  selog_client_ictx_want_multipart_done (ictx);
  rv = selog_client_ictx_wait_for_multipart_done (ictx);

  return rv;
}

static int32_t
selog_client_ictx_retrieve_all_event_types (selog_client_internal_ctx_t *ictx)
{
  vl_api_selog_event_type_dump_t *mp;
  int rv = SELOG_CLIENT_ERROR_NONE;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    {
      SELOG_LOG_ERROR ("vl_msg_api_alloc failed");
      return -SELOG_CLIENT_ERROR_INVALID_ARG;
    }

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = SELOG_REPLY_MSG_ID_BASE + VL_API_SELOG_EVENT_TYPE_DUMP;
  mp->client_index = ictx->api_client_handle;
  mp->context = ictx - selog_client_main.internal_ctx;
  vl_api_selog_event_type_dump_t_endian (mp, 1 /* to net byte order */);
  ictx->state = SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_ALL_EVENT_TYPES;
  vl_msg_api_send_shmem (ictx->vl_input_queue, (u8 *) &mp);
  selog_client_ictx_want_multipart_done (ictx);
  rv = selog_client_ictx_wait_for_multipart_done (ictx);

  return rv;
}

static int32_t
selog_client_ictx_retrieve_enum_strings_for_event_type (
  selog_client_internal_ctx_t *ictx, u32 event_type_index)
{
  vl_api_selog_event_type_string_dump_t *mp;
  int rv = SELOG_CLIENT_ERROR_NONE;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    {
      SELOG_LOG_ERROR ("vl_msg_api_alloc failed");
      return -SELOG_CLIENT_ERROR_INVALID_ARG;
    }

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    SELOG_REPLY_MSG_ID_BASE + VL_API_SELOG_EVENT_TYPE_STRING_DUMP;
  mp->client_index = ictx->api_client_handle;
  mp->context = ictx - selog_client_main.internal_ctx;
  mp->event_type_index = event_type_index;
  vl_api_selog_event_type_string_dump_t_endian (mp, 1 /* to net byte order */);
  ictx->current_event_type_index = event_type_index;
  ictx->state = SELOG_CLIENT_INTERNAL_STATE_WAITING_FOR_ENUM_STRINGS;
  vl_msg_api_send_shmem (ictx->vl_input_queue, (u8 *) &mp);
  selog_client_ictx_want_multipart_done (ictx);
  rv = selog_client_ictx_wait_for_multipart_done (ictx);

  return rv;
}

int32_t
selog_client_connect_to_vpp (selog_client_ctx_t *ctx)
{
  selog_client_internal_ctx_t *ictx = SELOG_INTERNAL_CTX (ctx);
  api_main_t *am;
  int rv = SELOG_CLIENT_ERROR_NONE;
  int i;

  clib_spinlock_lock_if_init (&ictx->lock);

  vlibapi_set_main (&ictx->bapi_api_ctx);
  vlibapi_set_memory_client_main (&ictx->bapi_mem_ctx);

  if (ctx->sock_name == 0)
    {
      rv = -SELOG_CLIENT_ERROR_INVALID_ARG;
      SELOG_LOG_ERROR ("No socket name specified");
      goto done;
    }

  if (ctx->client_name == 0)
    {
      rv = -SELOG_CLIENT_ERROR_INVALID_ARG;
      SELOG_LOG_ERROR ("No client name specified");
      goto done;
    }

  if (vl_socket_client_connect2 (&ictx->bapi_sock_ctx, (char *) ctx->sock_name,
				 (char *) ctx->client_name,
				 0 /* default rx/tx buffer */))
    {
      rv = -SELOG_CLIENT_ERROR_CONNECT_FAIL;
      SELOG_LOG_ERROR ("vl_socket_client_connect2 failed");
      goto done;
    }

  if (vl_socket_client_init_shm2 (&ictx->bapi_sock_ctx, 0,
				  1 /* want_pthread */))
    {
      SELOG_LOG_ERROR ("%s: vl_socket_client_init_shm2 failed",
		       ctx->client_name);
      rv = -SELOG_CLIENT_ERROR_CONNECT_FAIL;
      goto done;
    }

  selog_client_bapi_hookup ();

  am = vlibapi_get_main ();
  ictx->vl_input_queue = am->shmem_hdr->vl_input_queue;
  ictx->api_client_handle = (u32) am->my_client_index;

  SELOG_LOG_DEBUG ("%s: connected to vpp", ctx->client_name);

  /* Retrieve the SHM from VPP */
  rv = selog_client_ictx_retrieve_shm (ictx);
  if (rv < 0)
    {
      SELOG_LOG_ERROR ("%s: selog_client_ctx_retrieve_shm failed",
		       ctx->client_name);
      goto done;
    }

  /* Retrieve string table */
  rv = selog_client_ictx_retrieve_string_table (ictx);
  if (rv < 0)
    {
      SELOG_LOG_ERROR ("%s: selog_client_ictx_retrieve_string_table failed",
		       ctx->client_name);
      goto done;
    }

  /* Retrieve all tracks */
  rv = selog_client_ictx_retrieve_all_tracks (ictx);
  if (rv < 0)
    {
      SELOG_LOG_ERROR ("%s: selog_client_ictx_retrieve_all_tracks failed",
		       ctx->client_name);
      goto done;
    }

  /* Retrieve all event types */
  rv = selog_client_ictx_retrieve_all_event_types (ictx);
  if (rv < 0)
    {
      SELOG_LOG_ERROR ("%s: selog_client_ictx_retrieve_all_event_types failed",
		       ctx->client_name);
      goto done;
    }

  /* Retrieve enum strings for each event type */
  vec_foreach_index (i, ictx->private_em.event_types)
    {
      rv = selog_client_ictx_retrieve_enum_strings_for_event_type (ictx, i);
      if (rv < 0)
	{
	  SELOG_LOG_ERROR (
	    "%s: selog_client_ictx_retrieve_enum_strings_for_event_type "
	    "failed for event type index %u",
	    ctx->client_name, i);
	  goto done;
	}
    }

  ictx->state = SELOG_CLIENT_INTERNAL_STATE_CONNECTED;

done:
  clib_spinlock_unlock_if_init (&ictx->lock);
  return rv;
}

int32_t
selog_client_disconnect_from_vpp (selog_client_ctx_t *ctx)
{
  selog_client_internal_ctx_t *ictx = SELOG_INTERNAL_CTX (ctx);
  int rv = SELOG_CLIENT_ERROR_NONE;

  clib_spinlock_lock_if_init (&ictx->lock);
  if (ictx->bapi_sock_ctx.socket_fd == 0)
    {
      SELOG_LOG_ERROR ("Not connected");
      rv = -SELOG_CLIENT_ERROR_INVALID_ARG;
      goto done;
    }

  vl_socket_client_disconnect2 (&ictx->bapi_sock_ctx);

  ictx->vl_input_queue = 0;
  ictx->api_client_handle = ~0;

  SELOG_LOG_DEBUG ("%s: disconnected from vpp", ctx->client_name);

done:
  clib_spinlock_unlock_if_init (&ictx->lock);
  return rv;
}

int32_t
selog_client_poll_event (selog_client_ctx_t *ctx, selog_event_t *event,
			 uint32_t max_events)
{
  selog_client_internal_ctx_t *ictx = SELOG_INTERNAL_CTX (ctx);
  clib_spinlock_lock_if_init (&ictx->lock);
  uword n_total_events = ictx->sh->em.n_total_events;
  uword next_event = ictx->next_event;
  word n_events = n_total_events - next_event;

  /* If more events than the ring size, it means some were missed */
  if (n_events > ictx->sh->em.event_ring_size)
    {
      SELOG_LOG_WARNING ("%s: missed %ld events", ctx->client_name,
			 n_events - ictx->sh->em.event_ring_size);
      next_event = n_total_events - ictx->sh->em.event_ring_size;
      n_events = ictx->sh->em.event_ring_size;
    }

  n_events = clib_min (n_events, max_events);
  for (word i = 0; i < n_events; i++)
    {
      uword e = (next_event + i) & (ictx->sh->em.event_ring_size - 1);
      elog_event_t *src_event = &ictx->sh->em.event_ring[e];
      elog_event_t edata = src_event[0];
      edata.time = (edata.time_cycles - ictx->sh->em.init_time.cpu) *
		   ictx->sh->em.cpu_timer.seconds_per_clock;
      clib_memcpy_fast (&event[i], &edata, sizeof (edata));
    }
  ictx->next_event = next_event + n_events;
  clib_spinlock_unlock_if_init (&ictx->lock);
  return n_events;
}

static void
selog_client_scan_and_update_events (selog_client_internal_ctx_t *ictx,
				     selog_event_t *events, uint32_t n_events)
{
  u32 n_event_type_index = vec_len (ictx->private_em.event_types);
  u32 n_track_index = vec_len (ictx->private_em.tracks);

  for (uint32_t i = 0; i < n_events; i++)
    {
      selog_event_t *e = &events[i];
      if (e->event_type >= n_event_type_index)
	{
	  SELOG_LOG_DEBUG ("%s: event %d has invalid event type index %d",
			   ictx->client_ctx.client_name, i, e->event_type);
	  SELOG_LOG_DEBUG ("%s: fetching all event types",
			   ictx->client_ctx.client_name);
	  selog_client_ictx_retrieve_all_event_types (ictx);
	}
      if (e->track >= n_track_index)
	{
	  SELOG_LOG_DEBUG ("%s: event %d has invalid track index %d",
			   ictx->client_ctx.client_name, i, e->track);
	  SELOG_LOG_DEBUG ("%s: fetching all tracks",
			   ictx->client_ctx.client_name);
	  selog_client_ictx_retrieve_all_tracks (ictx);
	}
    }
  /* For each event, look for unknown string, if anyone is found, refetch
   * string table */
  for (uint32_t i = 0; i < n_events; i++)
    {
      selog_event_t *e = &events[i];
      selog_type_private_t *set =
	vec_elt_at_index (ictx->event_type_private, e->event_type);
      uword j;
      vec_foreach_index (j, set->string_offset)
	{
	  uword string_index;
	  if (set->string_size[j] == 1)
	    string_index = (e->data + set->string_offset[j])[0];
	  else if (set->string_size[j] == 2)
	    string_index =
	      clib_mem_unaligned (e->data + set->string_offset[j], u16);
	  else if (set->string_size[j] == 4)
	    string_index =
	      clib_mem_unaligned (e->data + set->string_offset[j], u32);
	  else if (set->string_size[j] == 8)
	    string_index =
	      clib_mem_unaligned (e->data + set->string_offset[j], u64);
	  else
	    {
	      SELOG_LOG_ERROR ("Unsupported string size %d in event type %d",
			       set->string_size[j], e->event_type);
	      abort ();
	    }
	  if (string_index >= vec_len (ictx->private_em.string_table))
	    {
	      SELOG_LOG_DEBUG ("%s: event %d has unknown string index %lu",
			       ictx->client_ctx.client_name, i, string_index);
	      SELOG_LOG_DEBUG ("%s: fetching all string table",
			       ictx->client_ctx.client_name);
	      selog_client_ictx_retrieve_string_table (ictx);
	    }
	}
    }
}
void
selog_client_format_events (selog_client_ctx_t *ctx, selog_event_t *events,
			    uint32_t n_events, char **result)
{
  selog_client_internal_ctx_t *ictx = SELOG_INTERNAL_CTX (ctx);
  clib_spinlock_lock_if_init (&ictx->lock);
  u8 *s = 0;
  elog_main_t *em = &ictx->private_em;
  selog_client_scan_and_update_events (ictx, events, n_events);
  for (uint32_t i = 0; i < n_events; i++)
    {
      s = format (0, "%U%c", format_elog_event, em, &events[i], 0);
      result[i] = (char *) s;
    }
  clib_spinlock_unlock_if_init (&ictx->lock);
}

void
selog_client_free_formatted_events (char **result, uint32_t n_events)
{
  for (uint32_t i = 0; i < n_events; i++)
    vec_free (result[i]);
}

__clib_constructor static void
selog_client_init (void)
{
  char *envvar;
  /* First init memory */
  selog_client_init_mem ();

  clib_time_init (&selog_client_main.time);

  /* Default log level */
  if ((envvar = getenv ("SELOG_CLIENT_LOG_LEVEL")) != 0)
    {
      selog_client_main.log_lvl = atoi (envvar);
    }
  else
    selog_client_main.log_lvl = SELOG_LOG_LEVEL_ERROR;
}

selog_client_main_t selog_client_main;
