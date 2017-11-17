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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <abf/abf.h>
#include <vnet/mpls/mpls_types.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <abf/abf_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <abf/abf_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <abf/abf_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <abf/abf_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <abf/abf_all_api_h.h>
#undef vl_api_version

/**
 * Base message ID fot the plugin
 */
static u32 abf_base_msg_id;

#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_abf_plugin_api_msg                    \
_(ABF_PLUGIN_GET_VERSION, abf_plugin_get_version)     \
_(ABF_POLICY_ADD_DEL, abf_policy_add_del)             \
_(ABF_ATTACH_ADD_DEL, abf_attach_add_del)             \
_(ABF_POLICY_DUMP, abf_policy_dump)                   \
_(ABF_ATTACH_DUMP, abf_attach_dump)

static void
vl_api_abf_plugin_get_version_t_handler (vl_api_abf_plugin_get_version_t * mp)
{
  vl_api_abf_plugin_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_ABF_PLUGIN_GET_VERSION_REPLY + abf_base_msg_id);
  rmp->context = mp->context;
  rmp->major = htonl (ABF_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (ABF_PLUGIN_VERSION_MINOR);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_abf_policy_add_del_t_handler (vl_api_abf_policy_add_del_t * mp)
{
  vl_api_abf_policy_add_del_reply_t *rmp;
  fib_route_path_t *paths = NULL;
  int rv = 0;
  u8 pi;

  for (pi = 0; pi < mp->details.n_paths; pi++)
    {
      fib_route_path_flags_t path_flags = FIB_ROUTE_PATH_FLAG_NONE;
      fib_route_path_t path = {
	.frp_proto = mp->details.paths[pi].next_hop_afi,
	.frp_sw_if_index = ntohl (mp->details.paths[pi].next_hop_sw_if_index),
	.frp_weight = mp->details.paths[pi].next_hop_weight,
	.frp_preference = mp->details.paths[pi].next_hop_preference,
      };
      mpls_label_t *label_stack = NULL;
      u32 n_labels;

      if ((MPLS_LABEL_INVALID !=
	   ntohl (mp->details.paths[pi].next_hop_via_label))
	  && (0 != mp->details.paths[pi].next_hop_via_label))
	{
	  path.frp_proto = DPO_PROTO_MPLS;
	  path.frp_local_label =
	    ntohl (mp->details.paths[pi].next_hop_via_label);
	  path.frp_eos = MPLS_NON_EOS;
	}
      if (mp->details.paths[pi].is_udp_encap)
	{
	  path_flags |= FIB_ROUTE_PATH_UDP_ENCAP;
	  path.frp_udp_encap_id = ntohl (mp->details.paths[pi].next_hop_id);
	}
      path.frp_flags = path_flags;

      if (DPO_PROTO_IP4 == mp->details.paths[pi].next_hop_afi)
	{
	  memcpy (&path.frp_addr.ip4,
		  mp->details.paths[pi].next_hop, sizeof (path.frp_addr.ip4));
	}
      else
	{
	  memcpy (&path.frp_addr.ip6,
		  mp->details.paths[pi].next_hop, sizeof (path.frp_addr.ip6));
	}

      n_labels = mp->details.paths[pi].next_hop_n_out_labels;
      if (n_labels == 0)
	;
      else if (1 == n_labels)
	vec_add1 (label_stack,
		  ntohl (mp->details.paths[pi].next_hop_out_label_stack[0]));
      else
	{
	  u8 mi;
	  vec_validate (label_stack, n_labels - 1);
	  for (mi = 0; mi < n_labels; mi++)
	    label_stack[mi] =
	      ntohl (mp->details.paths[pi].next_hop_out_label_stack[mi]);
	}
      path.frp_label_stack = label_stack;

      vec_add1 (paths, path);
    }

  if (mp->is_add)
    {
      abf_policy_update (ntohl (mp->details.policy_id),
			 ntohl (mp->details.acl_index), paths);
    }
  else
    {
      abf_policy_delete (ntohl (mp->details.policy_id), paths);
    }

  vec_free (paths);

  REPLY_MACRO (VL_API_ABF_POLICY_ADD_DEL_REPLY + abf_base_msg_id);
}

static void
vl_api_abf_attach_add_del_t_handler (vl_api_abf_attach_add_del_t * mp)
{
  vl_api_abf_attach_add_del_reply_t *rmp;
  fib_protocol_t fproto = (mp->details.is_ipv6 ?
			   FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  int rv = 0;

  if (mp->is_add)
    {
      abf_attach (fproto,
		  ntohl (mp->details.policy_id),
		  ntohl (mp->details.priority),
		  ntohl (mp->details.sw_if_index));
    }
  else
    {
      abf_detach (fproto,
		  ntohl (mp->details.policy_id),
		  ntohl (mp->details.sw_if_index));
    }

  REPLY_MACRO (VL_API_ABF_ATTACH_ADD_DEL_REPLY + abf_base_msg_id);
}

static void
vl_api_abf_policy_dump_t_handler (vl_api_abf_policy_dump_t * mp)
{
}

static void
vl_api_abf_attach_dump_t_handler (vl_api_abf_attach_dump_t * mp)
{
}

/* Set up the API message handling tables */
static clib_error_t *
abf_plugin_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + abf_base_msg_id),     \
                            #n,					\
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_abf_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <abf/abf_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * apim)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (apim, #n "_" #crc, id + abf_base_msg_id);
  foreach_vl_msg_name_crc_abf;
#undef _
}

static clib_error_t *
abf_api_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  u8 *name = format (0, "abf_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  abf_base_msg_id = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = abf_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (&api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (abf_api_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
