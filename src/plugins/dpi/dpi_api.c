/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Intel, Travelping and/or its affiliates.
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
*
*/

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <dpi/dpi.h>


#define vl_msg_id(n,h) n,
typedef enum
{
#include <dpi/dpi.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <dpi/dpi.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <dpi/dpi.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <dpi/dpi.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <dpi/dpi.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <dpi/dpi.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE dm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (dpi_main_t * dm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + dm->msg_id_base);
  foreach_vl_msg_name_crc_dpi;
#undef _
}

#define foreach_dpi_plugin_api_msg                          \
_(DPI_APP_ADD_DEL, dpi_app_add_del)                         \
_(DPI_FLOW_ADD_DEL, dpi_flow_add_del)               \
_(DPI_APP_RULE_ADD_DEL, dpi_app_rule_add_del)


/* API message handler */
static void
vl_api_dpi_app_add_del_t_handler (vl_api_dpi_app_add_del_t * mp)
{
  vl_api_dpi_app_add_del_reply_t *rmp = NULL;
  dpi_main_t *dm = &dpi_main;
  int rv = 0;

  rv = dpi_app_add_del (mp->name, (u8) (mp->is_add));

  REPLY_MACRO (VL_API_DPI_APP_ADD_DEL_REPLY);
}

/* API message handler */
static void
vl_api_dpi_flow_add_del_t_handler (vl_api_dpi_flow_add_del_t * mp)
{
  vl_api_dpi_flow_add_del_reply_t *rmp = NULL;
  dpi_main_t *dm = &dpi_main;
  int rv = 0;
  u32 fib_index;
  u32 flow_id = ~0;

  fib_index = fib_table_find (fib_ip_proto (mp->is_ipv6), ntohl (mp->vrf_id));
  if (fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  dpi_add_del_flow_args_t a = {
    .is_add = mp->is_add,
    .is_ipv6 = mp->is_ipv6,
    .src_ip = to_ip46 (mp->is_ipv6, mp->src_ip),
    .dst_ip = to_ip46 (mp->is_ipv6, mp->dst_ip),
    .src_port = ntohs (mp->src_port),
    .dst_port = ntohs (mp->dst_port),
    .protocol = mp->protocol,
    .fib_index = fib_index,
  };

  /* Check src ip and dst ip are different */
  if (ip46_address_cmp (&a.dst_ip, &a.src_ip) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }

  rv = dpi_flow_add_del (&a, &flow_id);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_DPI_FLOW_ADD_DEL_REPLY,
  ({
    rmp->flow_id = htonl (flow_id);
  }));
  /* *INDENT-ON* */
}

/* API message handler */
static void vl_api_dpi_app_rule_add_del_t_handler
  (vl_api_dpi_app_rule_add_del_t * mp)
{
  vl_api_dpi_app_rule_add_del_reply_t *rmp = NULL;
  dpi_rule_args_t args = { };
  dpi_main_t *dm = &dpi_main;
  int rv = 0;

  args.host = mp->host;
  args.pattern = mp->pattern;
  rv = dpi_rule_add_del (mp->app, mp->id, (u8) (mp->is_add), &args);

  REPLY_MACRO (VL_API_DPI_APP_RULE_ADD_DEL_REPLY);
}

static clib_error_t *
dpi_api_hookup (vlib_main_t * vm)
{
  dpi_main_t *dm = &dpi_main;

  u8 *name = format (0, "dpi_%08x%c", api_version, 0);
  dm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + dm->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_dpi_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (dm, &api_main);

  return 0;
}

VLIB_API_INIT_FUNCTION (dpi_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
