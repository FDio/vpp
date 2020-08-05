/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <fcntl.h>
#include <unistd.h>

#include <vnet/vnet.h>

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibmemory/memory_api.h>


/* define message IDs */
#include <vnet/format_fns.h>
#include <vlibmemory/vlib_api.api_enum.h>
#include <vlibmemory/vlib_api.api_types.h>

#define REPLY_MSG_ID_BASE (vlibapi_get_main ()->msg_id_base)
#include <vlibapi/api_helper_macros.h>

#define VL_API_TRACE_DEFAULT_DIR "/tmp"

/**
 * @brief Message handler for api_trace_save API.
 * @param mp vl_api_api_trace_save_t * mp the api message
 */
void
vl_api_api_trace_save_t_handler (vl_api_api_trace_save_t * mp)
{
  vl_api_api_trace_save_reply_t *rmp;
  int rv;
  FILE *fp;
  u8 *filename = 0;
  u8 *chroot_filename = 0;
  api_main_t *am = vlibapi_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  filename = (u8 *) vl_api_from_api_to_new_c_string (&mp->filename);
  if (filename == 0)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  /* Relative path not allowed */
  if (strstr ((char *) filename, ".."))
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  if (index ((char *) filename, '/'))
    chroot_filename = format (0, "%s%c", filename, 0);
  else
    chroot_filename =
      format (0, "%s/%s%c", VL_API_TRACE_DEFAULT_DIR, filename, 0);

  vec_free (filename);

  fp = fopen ((char *) chroot_filename, "w");
  if (fp == NULL)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto reply;
    }

  vlib_worker_thread_barrier_sync (vm);
  rv = vl_msg_api_trace_save (am, VL_API_TRACE_RX, fp);
  vlib_worker_thread_barrier_release (vm);
  fclose (fp);
  if (rv < 0)
    {
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto reply;
    }

reply:
  vec_free (filename);
  REPLY_MACRO (VL_API_API_TRACE_SAVE_REPLY);
}

static int
vl_api_api_trace_replay (vlib_main_t * vm, u8 * filename,
			 u32 first_index, u32 last_index)
{
  vl_api_trace_file_header_t *hp;
  int i, fd;
  struct stat statb;
  size_t file_size;
  u8 *msg;
  api_main_t *am = vlibapi_get_main ();
  u8 *tmpbuf = 0;
  u32 nitems, nitems_msgtbl;
  void **saved_print_handlers = 0;

  fd = open ((char *) filename, O_RDONLY);

  if (fd < 0)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (fstat (fd, &statb) < 0)
    {
      close (fd);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (!(statb.st_mode & S_IFREG) || (statb.st_size < sizeof (*hp)))
    {
      close (fd);
      return VNET_API_ERROR_SYSCALL_ERROR_2;
    }

  file_size = statb.st_size;
  file_size = (file_size + 4095) & ~(4095);

  hp = mmap (0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

  if (hp == (vl_api_trace_file_header_t *) MAP_FAILED)
    {
      close (fd);
      return VNET_API_ERROR_SYSCALL_ERROR_3;
    }
  close (fd);

  CLIB_MEM_UNPOISON (hp, file_size);

  nitems = ntohl (hp->nitems);

  if (last_index == (u32) ~ 0)
    {
      last_index = nitems - 1;
    }

  if (first_index >= nitems || last_index >= nitems)
    {
      munmap (hp, file_size);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  msg = (u8 *) (hp + 1);

  u16 *msgid_vec = 0;
  serialize_main_t _sm, *sm = &_sm;
  u32 msgtbl_size = ntohl (hp->msgtbl_size);
  u8 *name_and_crc;

  unserialize_open_data (sm, msg, msgtbl_size);
  unserialize_integer (sm, &nitems_msgtbl, sizeof (u32));

  for (i = 0; i < nitems_msgtbl; i++)
    {
      u16 msg_index = unserialize_likely_small_unsigned_integer (sm);
      unserialize_cstring (sm, (char **) &name_and_crc);
      u16 msg_index2 = vl_msg_api_get_msg_index (name_and_crc);
      vec_validate (msgid_vec, msg_index);
      msgid_vec[msg_index] = msg_index2;
    }

  msg += msgtbl_size;

  for (i = 0; i < first_index; i++)
    {
      trace_cfg_t *cfgp;
      int size;
      u16 msg_id;

      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      msg_id = ntohs (*((u16 *) msg));
      if (msg_id < vec_len (msgid_vec))
	msg_id = msgid_vec[msg_id];
      cfgp = am->api_trace_cfg + msg_id;
      if (!cfgp)
	{
	  munmap (hp, file_size);
	  return VNET_API_ERROR_FEATURE_DISABLED;
	}
      msg += size;
    }

  am->replay_in_progress = 1;

  for (; i <= last_index; i++)
    {
      trace_cfg_t *cfgp;
      u16 msg_id;
      int size;

      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      msg_id = ntohs (*((u16 *) msg));
      if (msg_id < vec_len (msgid_vec))
	{
	  msg_id = msgid_vec[msg_id];
	}

      cfgp = am->api_trace_cfg + msg_id;
      if (!cfgp)
	{
	  munmap (hp, file_size);
	  vec_free (tmpbuf);
	  am->replay_in_progress = 0;
	  return VNET_API_ERROR_FEATURE_DISABLED;
	}

      /* Copy the buffer (from the read-only mmap'ed file) */
      vec_validate (tmpbuf, size - 1 + sizeof (uword));
      clib_memcpy (tmpbuf + sizeof (uword), msg, size);
      clib_memset (tmpbuf, 0xf, sizeof (uword));

      /* msg_id always in network byte order */
      if (clib_arch_is_little_endian)
	{
	  u16 *msg_idp = (u16 *) (tmpbuf + sizeof (uword));
	  *msg_idp = msg_id;
	}

      if (msg_id < vec_len (am->msg_print_handlers) &&
	  am->msg_print_handlers[msg_id] && cfgp->replay_enable)
	{
	  void (*handler) (void *, vlib_main_t *);

	  handler = (void *) am->msg_handlers[msg_id];

	  if (!am->is_mp_safe[msg_id])
	    vl_msg_api_barrier_sync ();
	  (*handler) (tmpbuf + sizeof (uword), vm);
	  if (!am->is_mp_safe[msg_id])
	    vl_msg_api_barrier_release ();
	}

      _vec_len (tmpbuf) = 0;
      msg += size;
    }

  if (saved_print_handlers)
    {
      clib_memcpy (am->msg_print_handlers, saved_print_handlers,
		   vec_len (am->msg_print_handlers) * sizeof (void *));
      vec_free (saved_print_handlers);
    }

  munmap (hp, file_size);
  vec_free (tmpbuf);
  am->replay_in_progress = 0;

  return 0;
}

/**
 * @brief Message handler for api_trace_replay API.
 * @param mp vl_api_api_trace_replay_t * mp the api message
 */
void
vl_api_api_trace_replay_t_handler (vl_api_api_trace_replay_t * mp)
{
  vl_api_api_trace_replay_reply_t *rmp;
  int rv = 0;
  u8 *filename = 0;
  u8 *chroot_filename = 0;
  vlib_main_t *vm = vlib_get_main ();

  filename = (u8 *) vl_api_from_api_to_new_c_string (&mp->filename);
  if (filename == 0)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  /* Relative path not allowed */
  if (strstr ((char *) filename, ".."))
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  if (index ((char *) filename, '/'))
    chroot_filename = format (0, "%s%c", filename, 0);
  else
    chroot_filename =
      format (0, "%s/%s%c", VL_API_TRACE_DEFAULT_DIR, filename, 0);

  vec_free (filename);

  rv = vl_api_api_trace_replay (vm, chroot_filename, ntohl (mp->first_index),
				ntohl (mp->last_index));

reply:
  REPLY_MACRO (VL_API_API_TRACE_REPLAY_REPLY);
}

static int
vl_api_api_trace_type_to_which (vl_api_api_trace_type_t type,
				vl_api_trace_which_t * which)
{
  switch (type)
    {
    case API_TRACE_TX:
      (*which) = VL_API_TRACE_TX;
      return 0;
    case API_TRACE_RX:
      (*which) = VL_API_TRACE_RX;
      return 0;
    default:
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
}

/**
 * @brief Message handler for api_trace_enable_disable API.
 * @param mp vl_api_api_trace_enable_disable_t * mp the api message
 */
void
vl_api_api_trace_enable_disable_t_handler (vl_api_api_trace_enable_disable_t *
					   mp)
{
  vl_api_api_trace_enable_disable_reply_t *rmp;
  int rv;
  api_main_t *am = vlibapi_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vl_api_trace_which_t which;

  rv = vl_api_api_trace_type_to_which (mp->type, &which);
  if (rv < 0)
    goto reply;

  vlib_worker_thread_barrier_sync (vm);
  vl_msg_api_trace_onoff (am, which, mp->enabled);
  vlib_worker_thread_barrier_release (vm);

reply:
  REPLY_MACRO (VL_API_API_TRACE_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Message handler for api_trace_status API.
 * @param mp vl_api_api_trace_status_t * mp the api message
 */
void
vl_api_api_trace_status_t_handler (vl_api_api_trace_status_t * mp)
{
  vl_api_api_trace_status_reply_t *rmp;
  int rv;
  api_main_t *am = vlibapi_get_main ();
  vl_api_trace_which_t which;
  vl_api_trace_t *tp;
  char *trace_name;

  rv = vl_api_api_trace_type_to_which (mp->type, &which);
  if (rv < 0)
    goto error_reply;

  switch (which)
    {
    case VL_API_TRACE_TX:
      tp = am->tx_trace;
      trace_name = "TX trace";
      break;

    case VL_API_TRACE_RX:
      tp = am->rx_trace;
      trace_name = "RX trace";
      break;

    default:
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto error_reply;
    }

  if (tp == NULL)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto error_reply;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_API_TRACE_STATUS_REPLY,
    ({
      rmp->traces = htonl (vec_len (tp->traces));
      rmp->nitems = htonl (tp->nitems);
      rmp->enabled = tp->enabled;
      rmp->wrapped = tp->wrapped;

      strncpy ((char *) rmp->trace_name, trace_name, sizeof (rmp->trace_name));
    }));
  /* *INDENT-ON* */

  return;

error_reply:
  REPLY_MACRO (VL_API_API_TRACE_STATUS_REPLY);
}

/**
 * @brief Message handler for api_trace_free API.
 * @param mp vl_api_api_trace_free_t * mp the api message
 */
void
vl_api_api_trace_free_t_handler (vl_api_api_trace_free_t * mp)
{
  vl_api_api_trace_free_reply_t *rmp;
  int rv;
  api_main_t *am = vlibapi_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  vl_api_trace_which_t which;

  rv = vl_api_api_trace_type_to_which (mp->type, &which);
  if (rv < 0)
    goto reply;

  vlib_worker_thread_barrier_sync (vm);
  vl_msg_api_trace_onoff (am, which, 0);
  vl_msg_api_trace_free (am, which);
  vlib_worker_thread_barrier_release (vm);

reply:
  REPLY_MACRO (VL_API_API_TRACE_FREE_REPLY);
}

#include <vlibmemory/vlib_api.api.c>
clib_error_t *
vlib_api_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  /* Ask for a correctly-sized block of API message decode slots */
  am->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (vlib_api_api_hookup);
