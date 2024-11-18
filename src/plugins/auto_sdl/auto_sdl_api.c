/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlibmemory/api.h>
#include <vnet/session/session.h>
#include <vnet/session/session_sdl.h>
#include <vnet/tcp/tcp_sdl.h>
#include <auto_sdl/auto_sdl.h>
#include <auto_sdl/auto_sdl.api_enum.h>
#include <auto_sdl/auto_sdl.api_types.h>

static u16 msg_id_base;

#define REPLY_MSG_ID_BASE msg_id_base

#include <vlibapi/api_helper_macros.h>

static void
vl_api_auto_sdl_config_t_handler (vl_api_auto_sdl_config_t *mp)
{
  vl_api_auto_sdl_config_reply_t *rmp;
  auto_sdl_config_args_t args;
  int rv = 0;

  if ((session_sdl_is_enabled () == 0))
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto done;
    }

  args.threshold = clib_host_to_net_u32 (mp->threshold);
  args.remove_timeout = clib_host_to_net_u32 (mp->remove_timeout);
  args.enable = mp->enable;
  auto_sdl_config (&args);

done:
  REPLY_MACRO (VL_API_AUTO_SDL_CONFIG_REPLY);
}

#include <auto_sdl/auto_sdl.api.c>
static clib_error_t *
auto_sdl_api_hookup (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_AUTO_SDL_CONFIG,
			      1);
  vl_api_set_msg_thread_safe (
    am, REPLY_MSG_ID_BASE + VL_API_AUTO_SDL_CONFIG_REPLY, 1);
  return 0;
}

VLIB_API_INIT_FUNCTION (auto_sdl_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
