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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <abt/abt.h>
#include <vnet/mpls/mpls_types.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <abt/abt_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <abt/abt_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <abt/abt_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <abt/abt_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <abt/abt_all_api_h.h>
#undef vl_api_version

/**
 * Base message ID fot the plugin
 */
static u32 abt_base_msg_id;

#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_abt_plugin_api_msg                    \
_(ABT_ITF_ATTACH_ADD_DEL, abt_itf_attach_add_del)


static void
vl_api_abt_itf_attach_add_del_t_handler (vl_api_abt_itf_attach_add_del_t * mp)
{
  vl_api_abt_itf_attach_add_del_reply_t *rmp;
  fib_protocol_t fproto = (mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_add)
    {
      u32 *acls = NULL;
      u8 ii;

      if (mp->n_acls == 0)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto done;
	}

      for (ii = 0; ii < mp->n_acls; ii++)
	vec_add1 (acls, ntohl (mp->acls[ii]));

      abt_attach (ntohl (mp->sw_if_index), fproto, acls);

      vec_free (acls);
    }
  else
    {
      abt_detach (ntohl (mp->sw_if_index), fproto);
    }

done:
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_ABT_ITF_ATTACH_ADD_DEL_REPLY + abt_base_msg_id);
}

#define vl_msg_name_crc_list
#include <abt/abt_all_api_h.h>
#undef vl_msg_name_crc_list

/* Set up the API message handling tables */
static clib_error_t *
abt_plugin_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + abt_base_msg_id),     \
                            #n,					\
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_abt_plugin_api_msg;
#undef _

  return 0;
}

static void
setup_message_id_table (api_main_t * apim)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (apim, #n "_" #crc, id + abt_base_msg_id);
  foreach_vl_msg_name_crc_abt;
#undef _
}

static clib_error_t *
abt_api_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  u8 *name = format (0, "abt_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  abt_base_msg_id = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = abt_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (&api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (abt_api_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
