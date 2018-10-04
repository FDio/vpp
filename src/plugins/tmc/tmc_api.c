/*
 * tmc.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>	/* VLIB_PLUGIN_REGISTER */
#include <tmc/tmc.h>
#include <tmc/tmc.api_enum.h>
#include <tmc/tmc.api_types.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>	/* VPP_BUILD_VER */


#define REPLY_MSG_ID_BASE tm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handler */
static void vl_api_tmc_enable_disable_t_handler
  (vl_api_tmc_enable_disable_t * mp)
{
  tmc_main_t *tm = &tmc_main;
  vl_api_tmc_enable_disable_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = tmc_enable_disable (ntohl (mp->sw_if_index), 0 /* ipv4 */ ,
			   mp->ipv4_direction, ntohs (mp->ipv4_mss));
  if (rv == 0)
    rv = tmc_enable_disable (ntohl (mp->sw_if_index), 1 /* ipv6 */ ,
			     mp->ipv6_direction, ntohs (mp->ipv6_mss));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_TMC_ENABLE_DISABLE_REPLY);
}

static void
send_tmc_mss_details (u32 sw_if_index, vl_api_registration_t * rp,
		      u32 context)
{
  tmc_main_t *tm = &tmc_main;
  vl_api_tmc_mss_details_t *rmp;
  u16 mss4, mss6;
  u8 dir4, dir6;
  int rv4, rv6;

  mss4 = mss6 = 0;
  dir4 = dir6 = TMC_DIR_NONE;
  rv4 = tmc_get_mss (sw_if_index, 0 /* ipv4 */ , &dir4, &mss4);
  rv6 = tmc_get_mss (sw_if_index, 1 /* ipv6 */ , &dir6, &mss6);
  if (rv4 == VNET_API_ERROR_FEATURE_DISABLED
      && rv6 == VNET_API_ERROR_FEATURE_DISABLED)
    return;

  /* *INDENT-OFF* */
  REPLY_MACRO_DETAILS4 (VL_API_TMC_MSS_DETAILS, rp, context,
  ({
    rmp->sw_if_index = htonl (sw_if_index);
    rmp->ipv4_mss = htons (mss4);
    rmp->ipv6_mss = htons (mss6);
    rmp->ipv4_direction = dir4;
    rmp->ipv6_direction = dir6;
  }));
  /* *INDENT-ON* */
}

static void
vl_api_tmc_get_mss_t_handler (vl_api_tmc_get_mss_t * mp)
{
  tmc_main_t *tm = &tmc_main;
  vl_api_tmc_get_mss_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (sw_if_index == ~0)
    {
      if (vec_len (tm->dir_enabled4) == 0)
	return;

    /* *INDENT-OFF* */
    REPLY_AND_DETAILS_MACRO (VL_API_TMC_GET_MSS_REPLY, tm->dir_enabled4,
    ({
      send_tmc_mss_details (cursor, reg, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      VALIDATE_SW_IF_INDEX (mp);
      send_tmc_mss_details (sw_if_index, reg, mp->context);

      BAD_SW_IF_INDEX_LABEL;
    /* *INDENT-OFF* */
    REPLY_MACRO2 (VL_API_TMC_GET_MSS_REPLY,
    ({
      rmp->cursor = ~0;
    }));
    /* *INDENT-ON* */
    }
}

static void
vl_api_tmc_mss_dump_t_handler (vl_api_tmc_mss_dump_t * mp)
{
  tmc_main_t *tm = &tmc_main;
  vl_api_registration_t *reg;
  u32 i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach_index (i, tm->dir_enabled4)
    send_tmc_mss_details (i, reg, mp->context);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <tmc/tmc.api.c>

/* Set up the API message handling tables */
static clib_error_t *
tmc_api_hookup (vlib_main_t * vm)
{
  tmc_main_t *tm = &tmc_main;

  tm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (tmc_api_hookup);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "TCP MSS clamping (tmc) plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
