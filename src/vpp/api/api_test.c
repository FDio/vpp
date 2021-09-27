/*
 *------------------------------------------------------------------
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp/api/types.h>

#include <vpp/api/vpe.api_enum.h>
#include <vpp/api/vpe.api_types.h>

#define __plugin_msg_base vpe_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} vpe_test_main_t;

vpe_test_main_t vpe_test_main;

static int
api_show_version (vat_main_t *vam)
{
  vl_api_show_version_t *mp;
  int ret;

  M (SHOW_VERSION, mp);

  S (mp);
  W (ret);
  return ret;
}

static int
api_log_dump (vat_main_t *vam)
{
  /* Not yet implemented */
  return -1;
}

static int
api_show_vpe_system_time (vat_main_t *vam)
{
  /* Not yet implemented */
  return -1;
}

static void
vl_api_show_version_reply_t_handler (vl_api_show_version_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval >= 0)
    {
      errmsg ("        program: %s", mp->program);
      errmsg ("        version: %s", mp->version);
      errmsg ("     build date: %s", mp->build_date);
      errmsg ("build directory: %s", mp->build_directory);
    }
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
vl_api_log_details_t_handler (vl_api_log_details_t *mp)
{
  /* Not yet implemented */
}

static void
vl_api_show_vpe_system_time_reply_t_handler (
  vl_api_show_vpe_system_time_reply_t *mp)
{
  /* Not yet implemented */
}

#include <vpp/api/vpe.api_test.c>
