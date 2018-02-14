/*
 *------------------------------------------------------------------
 * l2e_api.c - layer 2 emulation api
 *
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vpp/app/version.h>

#include <l2e/l2e.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <l2e/l2e_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <l2e/l2e_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <l2e/l2e_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <l2e/l2e_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <l2e/l2e_all_api_h.h>
#undef vl_api_version

#include <vlibapi/api_helper_macros.h>

#define foreach_l2e_api_msg                                 \
_(L2_EMULATION, l2_emulation)

/**
 * L2 Emulation Main
 */
typedef struct l2_emulation_main_t_
{
  u16 msg_id_base;
} l2_emulation_main_t;

static l2_emulation_main_t l2_emulation_main;

#define L2E_MSG_BASE l2_emulation_main.msg_id_base

static void
vl_api_l2_emulation_t_handler (vl_api_l2_emulation_t * mp)
{
  vl_api_l2_emulation_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (mp->enable)
    l2_emulation_enable (sw_if_index);
  else
    l2_emulation_disable (sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_EMULATION_REPLY + L2E_MSG_BASE);
}

/*
 * l2_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <l2e/l2e_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc)                                     \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + L2E_MSG_BASE);
  foreach_vl_msg_name_crc_l2e;
#undef _
}

static void
l2e_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N + L2E_MSG_BASE,          \
                            #n,                                 \
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_l2e_api_msg;
#undef _
}

static clib_error_t *
l2e_init (vlib_main_t * vm)
{
  api_main_t *am = &api_main;
  l2_emulation_main_t *l2em = &l2_emulation_main;
  u8 *name = format (0, "l2e_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  l2em->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
					      VL_MSG_FIRST_AVAILABLE);

  l2e_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (am);

  vec_free (name);
  return (NULL);
}

VLIB_API_INIT_FUNCTION (l2e_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "L2 Emulation",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
