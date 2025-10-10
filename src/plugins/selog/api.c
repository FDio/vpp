/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlibmemory/api.h>
#include <vnet/api_errno.h>
#include <selog/selog.h>
#include <selog/selog.api_enum.h>
#include <selog/selog.api_types.h>

#define REPLY_MSG_ID_BASE	  selog_main.msg_id_base
#define SELOG_MAX_FORMAT_STR_SIZE (1ULL << 30)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_selog_get_shm_t_handler (vl_api_selog_get_shm_t *mp)
{
  vl_api_selog_get_shm_reply_t *rmp;
  selog_main_t *sm = &selog_main;
  vl_api_registration_t *reg;
  int rv = 0;
  u32 file_index;

  reg = vl_api_client_index_to_registration (mp->client_index);

  if (!reg)
    return;

  if ((file_index = vl_api_registration_file_index (reg)) == VL_API_INVALID_FI)
    rv = VNET_API_ERROR_UNIMPLEMENTED;

  REPLY_MACRO (VL_API_SELOG_GET_SHM_REPLY);
  if (rv == 0)
    {
      clib_error_t *error = vl_api_send_fd_msg (reg, &sm->ssvm.fd, 1);
      if (error)
	clib_error_report (error);
    }
}

static void
vl_api_selog_get_string_table_t_handler (vl_api_selog_get_string_table_t *mp)
{
  selog_main_t *sm = &selog_main;
  elog_main_t *em = sm->em;
  vl_api_registration_t *reg;
  vl_api_selog_get_string_table_reply_t *rmp;
  int rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  REPLY_MACRO3 (
    VL_API_SELOG_GET_STRING_TABLE_REPLY, vec_len (em->string_table),
    { vl_api_vec_to_api_string ((u8 *) em->string_table, &rmp->s); });
}

static void
vl_api_selog_track_dump_t_handler (vl_api_selog_track_dump_t *mp)
{
  selog_main_t *sm = &selog_main;
  elog_main_t *em = sm->em;
  vl_api_selog_track_details_t *rmp;
  elog_track_t *track;

  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (track, em->tracks)
    {
      rmp = vl_msg_api_alloc (sizeof (*rmp) + vec_len (track->name));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->context = mp->context;
      rmp->_vl_msg_id =
	clib_host_to_net_u16 (VL_API_SELOG_TRACK_DETAILS + REPLY_MSG_ID_BASE);
      rmp->index = clib_host_to_net_u32 (track - em->tracks);
      vl_api_vec_to_api_string ((u8 *) track->name, &rmp->name);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_selog_event_type_dump_t_handler (vl_api_selog_event_type_dump_t *mp)
{
  selog_main_t *sm = &selog_main;
  elog_main_t *em = sm->em;
  vl_api_selog_event_type_details_t *rmp;
  elog_event_type_t *event_type;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (event_type, em->event_types)
    {
      rmp = vl_msg_api_alloc (
	sizeof (*rmp) +
	clib_strnlen (event_type->format, SELOG_MAX_FORMAT_STR_SIZE));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->context = mp->context;
      rmp->_vl_msg_id = clib_host_to_net_u16 (VL_API_SELOG_EVENT_TYPE_DETAILS +
					      REPLY_MSG_ID_BASE);
      rmp->index = clib_host_to_net_u32 (event_type - em->event_types);
      vl_api_c_string_to_api_string (event_type->format, &rmp->fmt);
      clib_strncpy ((char *) rmp->fmt_args, event_type->format_args,
		    sizeof (rmp->fmt_args));
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_selog_event_type_string_dump_t_handler (
  vl_api_selog_event_type_string_dump_t *mp)
{
  selog_main_t *sm = &selog_main;
  elog_main_t *em = sm->em;
  vl_api_registration_t *reg;
  vl_api_selog_event_type_string_details_t *rmp;
  elog_event_type_t *event_type;
  u32 eti;
  char **s;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  eti = clib_net_to_host_u32 (mp->event_type_index);
  event_type = vec_elt_at_index (em->event_types, eti);
  vec_foreach (s, event_type->enum_strings_vector)
    {
      rmp = vl_msg_api_alloc (sizeof (*rmp) + vec_len (*s));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->context = mp->context;
      rmp->_vl_msg_id = clib_host_to_net_u16 (
	VL_API_SELOG_EVENT_TYPE_STRING_DETAILS + REPLY_MSG_ID_BASE);
      rmp->index = clib_host_to_net_u32 (s - event_type->enum_strings_vector);
      vl_api_vec_to_api_string ((u8 *) *s, &rmp->s);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

#include <selog/selog.api.c>
static clib_error_t *
selog_api_hookup (vlib_main_t *vm)
{
  selog_main_t *sm = &selog_main;

  sm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (selog_api_hookup);