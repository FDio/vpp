/*
 * bi32.c - skeleton vpp engine plug-in
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
#include <vnet/plugin/plugin.h>
#include <bi32/bi32.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <bi32/bi32_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <bi32/bi32_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <bi32/bi32_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <bi32/bi32_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <bi32/bi32_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

bi32_main_t bi32_main;

#include <vppinfra/bihash_template.c>

/* List of message types that this plugin understands */

#define foreach_bi32_plugin_api_msg                           \
_(BI32_ENABLE_DISABLE, bi32_enable_disable)

/* Action function shared between message handler and debug CLI */

int
bi32_enable_disable (bi32_main_t * sm, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "bi32",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
bi32_enable_disable_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  bi32_main_t *sm = &bi32_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 sm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = bi32_enable_disable (sm, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "bi32_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bi32_enable_disable_command, static) =
{
  .path = "bi32 enable-disable",
  .short_help =
  "bi32 enable-disable <interface-name> [disable]",
  .function = bi32_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_bi32_enable_disable_t_handler
  (vl_api_bi32_enable_disable_t * mp)
{
  vl_api_bi32_enable_disable_reply_t *rmp;
  bi32_main_t *sm = &bi32_main;
  int rv;

  rv = bi32_enable_disable (sm, ntohl (mp->sw_if_index),
			    (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_BI32_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
bi32_plugin_api_hookup (vlib_main_t * vm)
{
  bi32_main_t *sm = &bi32_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_bi32_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <bi32/bi32_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (bi32_main_t * sm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_bi32;
#undef _
}

/*
 * Accept connection on the socket and exchange the fd for the shared
 * memory segment.
 */
static clib_error_t *
bi32_socket_accept_ready (clib_file_t * uf)
{
  bi32_main_t *bm = &bi32_main;
  clib_error_t *err;
  clib_socket_t client = { 0 };

  err = clib_socket_accept (bm->socket, &client);
  if (err)
    {
      clib_error_report (err);
      return err;
    }

  /* Send the fd across and close */
  err = clib_socket_sendmsg (&client, 0, 0, &bm->memfd_fd, 1);
  if (err)
    clib_error_report (err);
  clib_socket_close (&client);

  return 0;
}

static clib_error_t *
bi32_segment_socket_init (vlib_main_t * vm)
{
  bi32_main_t *bm = &bi32_main;
  clib_error_t *error = 0;
  clib_socket_t *s = clib_mem_alloc (sizeof (clib_socket_t));

  s->config = "/tmp/bi32.sock";
  s->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_SEQPACKET |
    CLIB_SOCKET_F_ALLOW_GROUP_WRITE | CLIB_SOCKET_F_PASSCRED;
  if ((error = clib_socket_init (s)))
    return error;

  clib_file_t template = { 0 };
  clib_file_main_t *fm = &file_main;
  template.read_function = bi32_socket_accept_ready;
  template.file_descriptor = s->fd;
  template.description = format (0, "bi32 segment listener /tmp/bi32.sock");
  clib_file_add (fm, &template);

  bm->socket = s;

  return error;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (bi32_segment_socket_init);

static void
bi32_table_init (bi32_main_t * bm)
{
  int i;
  BVT (clib_bihash) * h;
  BVT (clib_bihash_kv) kv;

  h = &bm->hash;

  BV (clib_bihash_master_init_svm) (h, "test", 64 /* nbuckets */ ,
				    0x10000000 /* base_addr */ ,
				    64 << 20);

  bm->memfd_fd = h->memfd;
}


static clib_error_t *
show_bi32_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bi32_main_t *bm = &bi32_main;

  vlib_cli_output (vm, "%U", BV (format_bihash), &bm->hash, 1 /*verbose */ );

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_bi32_command, static) =
{
  .path = "show bi32",
  .short_help = "show bi32",
  .function = show_bi32_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_bi32_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bi32_main_t *bm = &bi32_main;
  int i, nitems;
  int is_add = 1;
  BVT (clib_bihash_kv) kv;
  BVT (clib_bihash) * h;

  h = &bm->hash;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "delete %d", &nitems))
	is_add = 0;
      else if (unformat (input, "add %d", &nitems))
	is_add = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  for (i = 0; i < nitems; i++)
    {
      kv.key[0] = i + 1;
      kv.key[1] = i + 101;
      kv.value = i + 201;

      BV (clib_bihash_add_del) (h, &kv, is_add);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_bi32_command, static) =
{
  .path = "test bi32",
  .short_help = "test bi32",
  .function = test_bi32_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
bi32_init (vlib_main_t * vm)
{
  bi32_main_t *bm = &bi32_main;
  clib_error_t *error = 0;
  u8 *name;

  bm->vlib_main = vm;
  bm->vnet_main = vnet_get_main ();

  name = format (0, "bi32_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  bm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = bi32_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (bm, &api_main);

  vec_free (name);

  bi32_table_init (bm);

  return error;
}

VLIB_INIT_FUNCTION (bi32_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (bi32, static) =
{
  .arc_name = "device-input",
  .node_name = "bi32",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "bihash 32/64 test plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
