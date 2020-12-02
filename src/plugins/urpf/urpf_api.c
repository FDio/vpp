/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <urpf/urpf.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <urpf/urpf.api_enum.h>
#include <urpf/urpf.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 urpf_base_msg_id;
#define REPLY_MSG_ID_BASE urpf_base_msg_id

#include <vlibapi/api_helper_macros.h>

static int
urpf_mode_decode (vl_api_urpf_mode_t in, urpf_mode_t * out)
{
  if (0)
    ;
#define _(a,b)                                  \
  else if (URPF_API_MODE_##a == in)             \
    {                                           \
      *out = URPF_MODE_##a;                     \
      return (0);                               \
    }
  foreach_urpf_mode
#undef _
    return (VNET_API_ERROR_INVALID_VALUE);
}

static void
vl_api_urpf_update_t_handler (vl_api_urpf_update_t * mp)
{
  vl_api_urpf_update_reply_t *rmp;
  ip_address_family_t af;
  urpf_mode_t mode;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = urpf_mode_decode (mp->mode, &mode);

  if (rv)
    goto done;

  rv = ip_address_family_decode (mp->af, &af);

  if (rv)
    goto done;

  urpf_update (mode, htonl (mp->sw_if_index), af,
	       (mp->is_input ? IP_FEATURE_INPUT : IP_FEATURE_OUTPUT));

  BAD_SW_IF_INDEX_LABEL;
done:
  REPLY_MACRO (VL_API_URPF_UPDATE_REPLY);
}

static void
vl_api_urpf_update_v2_t_handler (vl_api_urpf_update_v2_t * mp)
{
  vl_api_urpf_update_v2_reply_t *rmp;
  ip_feature_location_t loc;
  ip_address_family_t af;
  urpf_mode_t mode;
  u32 sw_if_index;
  int rv = 0;

  rv = urpf_mode_decode (mp->mode, &mode);

  if (rv)
    goto done;

  rv = ip_feature_location_decode (mp->location, &loc);

  if (rv)
    goto done;

  if (~0 == mp->sw_if_index || 0 == mp->sw_if_index)
    {
      if (IP_FEATURE_LOCAL != loc)
	{
	  rv = VNET_API_ERROR_FEATURE_DISABLED;
	  goto done;
	}
      sw_if_index = 0;
    }
  else
    {
      VALIDATE_SW_IF_INDEX (mp);
      sw_if_index = htonl (mp->sw_if_index);
    }

  rv = ip_address_family_decode (mp->af, &af);

  if (rv)
    goto done;

  urpf_update (mode, sw_if_index, af, loc);

  BAD_SW_IF_INDEX_LABEL;
done:
  REPLY_MACRO (VL_API_URPF_UPDATE_V2_REPLY);
}

#include <urpf/urpf.api.c>

static clib_error_t *
urpf_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  urpf_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (urpf_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Unicast Reverse Path Forwarding (uRPF)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
