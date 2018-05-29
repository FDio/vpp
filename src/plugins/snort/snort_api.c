/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <snort/snort.h>

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <snort/snort_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <snort/snort_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <snort/snort_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <snort/snort_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <snort/snort_all_api_h.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <snort/snort_all_api_h.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE snort_get_main ()->msg_id_base
#include <vlibapi/api_helper_macros.h>

void
vl_api_snort_enable_disable_t_handler (vl_api_snort_enable_disable_t * mp)
{
  vl_api_snort_enable_disable_reply_t *rmp;
  clib_error_t *error;
  int rv = 0;

  snort_enable_disable_args_t args = {
      .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
      .is_en = mp->is_enable,
  };
  error = snort_enable_disable (&args);
  if (error)
    {
      clib_error_report(error);
      rv = -1;
    }

  REPLY_MACRO (VL_API_SNORT_ENABLE_DISABLE_REPLY);
}

void
vl_api_snort_interface_add_del_t_handler (
    vl_api_snort_interface_add_del_t * mp)
{
  vl_api_snort_interface_add_del_reply_t *rmp;
  clib_error_t *error;
  int rv = 0;

  snort_interface_add_del_args_t args = {
      .sw_if_index = clib_net_to_host_u32 (mp->sw_if_index),
      .is_add = mp->is_add,
  };

  error = snort_interface_add_del (&args);
  if (error)
    {
      clib_error_report (error);
      rv = -1;
    }
  REPLY_MACRO (VL_API_SNORT_INTERFACE_ADD_DEL_REPLY);
}

void
vl_api_snort_interface_flow_add_del_t_handler (
    vl_api_snort_interface_flow_add_del_t * mp)
{
  vl_api_snort_interface_flow_add_del_reply_t *rmp;
  snort_interface_flow_add_del_args_t args;
  ip46_address_t *saddr, *daddr;
  clib_error_t *error;
  int rv = 0;

  args.flow_id.is_ip4 = mp->is_ip4;
  saddr = (ip46_address_t *)mp->src;
  daddr = (ip46_address_t *)mp->dst;

  if (mp->is_ip4)
    {
      args.flow_id.v4.src.as_u32 = saddr->ip4.as_u32;
      args.flow_id.v4.dst.as_u32 = daddr->ip4.as_u32;
      args.flow_id.v4.proto = mp->proto;
      args.flow_id.v4.src_port = mp->src_port;
      args.flow_id.v4.dst_port = mp->dst_port;
    }
  else
    {
      clib_memcpy (&args.flow_id.v6.src, saddr, sizeof (*saddr));
      clib_memcpy (&args.flow_id.v6.dst, daddr, sizeof (*daddr));
      args.flow_id.v6.proto = mp->proto;
      args.flow_id.v6.src_port = mp->src_port;
      args.flow_id.v6.dst_port = mp->dst_port;
    }
  args.is_add = mp->is_add;
  args.sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  args.action = mp->action == 1 ? SNORT_ACTION_FWD : SNORT_ACTION_DROP;
  error = snort_interface_flow_add_del (&args);
  if (error)
    {
      clib_error_report (error);
      rv = -1;
      /* Send reply only if we have an error */
      REPLY_MACRO (VL_API_SNORT_INTERFACE_FLOW_ADD_DEL_REPLY);
    }
}

#define foreach_snort_plugin_api_msg				\
_(SNORT_ENABLE_DISABLE, snort_enable_disable)			\
_(SNORT_INTERFACE_ADD_DEL, snort_interface_add_del)		\
_(SNORT_INTERFACE_FLOW_ADD_DEL, snort_interface_flow_add_del)	\

static void
setup_message_id_table (snort_main_t * mm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_snort;
#undef _
}

/* Set up the API message handling tables */
clib_error_t *
snort_plugin_api_hookup (vlib_main_t * vm)
{
  snort_main_t *sm = snort_get_main ();
  api_main_t *am = &api_main;
  u8 *name;

  name = format (0, "snort_%08x%c", api_version, 0);
  sm->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
	                                    VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_snort_plugin_api_msg
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (sm, am);
  vec_free (name);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
