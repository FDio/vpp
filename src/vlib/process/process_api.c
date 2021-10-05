/*
 *------------------------------------------------------------------
 * process_api.c - vlib process api
 *
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlib/process/process.h>

/* define message IDs */
#include <vlib/process/process.api_enum.h>
#include <vlib/process/process.api_types.h>

/**
 * Base message ID fot the process APIs
 */
static u32 process_base_msg_id;
#define REPLY_MSG_ID_BASE process_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
vl_api_set_process_privileges_t_handler (vl_api_set_process_privileges_t * mp)
{
  vl_api_set_process_privileges_reply_t *rmp;
  u32 uid;
  u32 gid;
  int rv;
  u8 *chroot_dir = 0;

  uid = ntohl (mp->uid);
  gid = ntohl (mp->gid);
  if(mp->do_chroot){
      chroot_dir = vl_api_from_api_to_new_vec (mp, &mp->chroot_dir);
      vec_add1 (chroot_dir, 0);	/* Ensure it's a C string for strcasecmp() */
  }
  rv = vlib_process_drop_privileges (uid, gid, (char *)chroot_dir);
  REPLY_MACRO (VL_API_SET_PROCESS_PRIVILEGES_REPLY);
  vec_free (chroot_dir);
}

static void
vl_api_set_process_capabilities_t_handler (vl_api_set_process_capabilities_t * mp)
{
  vl_api_set_process_capabilities_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main();
  u64 capabilities;
  int rv;

  capabilities = ntohl (mp->capabilities);
  rv = vlib_process_set_capabilities (vm, capabilities);
  REPLY_MACRO (VL_API_SET_PROCESS_CAPABILITIES_REPLY);
}

#include <vlib/process/process.api.c>
static clib_error_t *
process_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  process_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (process_api_hookup);