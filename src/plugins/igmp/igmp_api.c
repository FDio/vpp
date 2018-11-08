/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <igmp/igmp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <igmp/igmp_ssm_range.h>

/* define message IDs */
#include <igmp/igmp_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <igmp/igmp_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <igmp/igmp_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <igmp/igmp_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <igmp/igmp_all_api_h.h>
#undef vl_api_version

#include <vlibapi/api_helper_macros.h>

#define IGMP_MSG_ID(_id) (_id + igmp_main.msg_id_base)

#define foreach_igmp_plugin_api_msg                                            \
_(IGMP_LISTEN, igmp_listen)                                                    \
_(IGMP_ENABLE_DISABLE, igmp_enable_disable)                                    \
_(IGMP_PROXY_DEVICE_ADD_DEL, igmp_proxy_device_add_del)                        \
_(IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE, igmp_proxy_device_add_del_interface)    \
_(IGMP_DUMP, igmp_dump)                                                        \
_(IGMP_CLEAR_INTERFACE, igmp_clear_interface)                                  \
_(IGMP_CLEAR_INTERFACE, igmp_clear_interface)                                  \
_(IGMP_GROUP_PREFIX_SET, igmp_group_prefix_set)                                \
_(IGMP_GROUP_PREFIX_DUMP, igmp_group_prefix_dump)                              \
_(WANT_IGMP_EVENTS, want_igmp_events)                                          \

static void
vl_api_igmp_listen_t_handler (vl_api_igmp_listen_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_igmp_listen_reply_t *rmp;
  int ii, rv = 0;
  ip46_address_t gaddr, *saddrs = NULL;

  VALIDATE_SW_IF_INDEX (&mp->group);

  if ((vnet_sw_interface_get_flags (vnm, ntohl (mp->group.sw_if_index)) &&
       VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    {
      // FIXME - don't we clear this state on interface down ...
      rv = VNET_API_ERROR_UNEXPECTED_INTF_STATE;
      goto done;
    }

  memset (&gaddr, 0, sizeof (gaddr));
  clib_memcpy (&gaddr.ip4, &mp->group.gaddr, sizeof (ip4_address_t));

  vec_validate (saddrs, mp->group.n_srcs - 1);

  vec_foreach_index (ii, saddrs)
  {
    clib_memcpy (&saddrs[ii].ip4,
		 &mp->group.saddrs[ii], sizeof (ip4_address_t));
  }

  rv = igmp_listen (vm,
		    (mp->group.filter ?
		     IGMP_FILTER_MODE_INCLUDE :
		     IGMP_FILTER_MODE_EXCLUDE),
		    ntohl (mp->group.sw_if_index), saddrs, &gaddr);

  vec_free (saddrs);

  BAD_SW_IF_INDEX_LABEL;
done:;
  REPLY_MACRO (IGMP_MSG_ID (VL_API_IGMP_LISTEN_REPLY));
}

static void
vl_api_igmp_enable_disable_t_handler (vl_api_igmp_enable_disable_t * mp)
{
  vl_api_igmp_enable_disable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = igmp_enable_disable (ntohl (mp->sw_if_index),
			    mp->enable,
			    (mp->mode ? IGMP_MODE_HOST : IGMP_MODE_ROUTER));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (IGMP_MSG_ID (VL_API_IGMP_ENABLE_DISABLE_REPLY));
}

static void
vl_api_igmp_proxy_device_add_del_t_handler (vl_api_igmp_proxy_device_add_del_t
					    * mp)
{
  vl_api_igmp_proxy_device_add_del_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    igmp_proxy_device_add_del (ntohl (mp->vrf_id), ntohl (mp->sw_if_index),
			       mp->add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (IGMP_MSG_ID (VL_API_IGMP_PROXY_DEVICE_ADD_DEL_REPLY));
}

static void
  vl_api_igmp_proxy_device_add_del_interface_t_handler
  (vl_api_igmp_proxy_device_add_del_interface_t * mp)
{
  vl_api_igmp_proxy_device_add_del_interface_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    igmp_proxy_device_add_del_interface (ntohl (mp->vrf_id),
					 ntohl (mp->sw_if_index), mp->add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (IGMP_MSG_ID
	       (VL_API_IGMP_PROXY_DEVICE_ADD_DEL_INTERFACE_REPLY));
}

static void
send_igmp_details (unix_shared_memory_queue_t * q, igmp_main_t * im,
		   igmp_config_t * config, igmp_group_t * group,
		   igmp_src_t * src, u32 context)
{
  vl_api_igmp_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (IGMP_MSG_ID (VL_API_IGMP_DETAILS));
  mp->context = context;
  mp->sw_if_index = htonl (config->sw_if_index);
  clib_memcpy (mp->saddr.address, &src->key->ip4, sizeof (src->key->ip4));
  clib_memcpy (mp->gaddr.address, &group->key->ip4, sizeof (group->key->ip4));

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
igmp_config_dump (igmp_main_t * im,
		  unix_shared_memory_queue_t * q,
		  u32 context, igmp_config_t * config)
{
  igmp_group_t *group;
  igmp_src_t *src;

  /* *INDENT-OFF* */
  FOR_EACH_GROUP (group, config,
    ({
      FOR_EACH_SRC (src, group, IGMP_FILTER_MODE_INCLUDE,
        ({
          send_igmp_details (q, im, config, group, src, context);
        }));
    }));
  /* *INDENT-ON* */
}

static void
vl_api_igmp_dump_t_handler (vl_api_igmp_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  igmp_main_t *im = &igmp_main;
  igmp_config_t *config;
  u32 sw_if_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  sw_if_index = ntohl (mp->sw_if_index);
  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (config, im->configs,
        ({
          igmp_config_dump(im, q, mp->context, config);
        }));
      /* *INDENT-ON* */
    }
  else
    {
      config = igmp_config_lookup (sw_if_index);
      if (config)
	{
	  igmp_config_dump (im, q, mp->context, config);
	}
    }
}

static void
vl_api_igmp_clear_interface_t_handler (vl_api_igmp_clear_interface_t * mp)
{
  vl_api_igmp_clear_interface_reply_t *rmp;
  igmp_config_t *config;
  int rv = 0;

  config = igmp_config_lookup (ntohl (mp->sw_if_index));
  if (config)
    igmp_clear_config (config);

  REPLY_MACRO (IGMP_MSG_ID (VL_API_IGMP_CLEAR_INTERFACE_REPLY));
}

static vl_api_group_prefix_type_t
igmp_group_type_int_to_api (igmp_group_prefix_type_t t)
{
  switch (t)
    {
    case IGMP_GROUP_PREFIX_TYPE_ASM:
      return (htonl (ASM));
    case IGMP_GROUP_PREFIX_TYPE_SSM:
      return (htonl (SSM));
    }

  return (SSM);
}

static igmp_group_prefix_type_t
igmp_group_type_api_to_int (vl_api_group_prefix_type_t t)
{
  switch (htonl (t))
    {
    case ASM:
      return (IGMP_GROUP_PREFIX_TYPE_ASM);
    case SSM:
      return (IGMP_GROUP_PREFIX_TYPE_SSM);
    }

  return (IGMP_GROUP_PREFIX_TYPE_SSM);
}

static void
vl_api_igmp_group_prefix_set_t_handler (vl_api_igmp_group_prefix_set_t * mp)
{
  vl_api_igmp_group_prefix_set_reply_t *rmp;
  fib_prefix_t pfx;
  int rv = 0;

  ip_prefix_decode (&mp->gp.prefix, &pfx);
  igmp_group_prefix_set (&pfx, igmp_group_type_api_to_int (mp->gp.type));

  REPLY_MACRO (IGMP_MSG_ID (VL_API_IGMP_GROUP_PREFIX_SET_REPLY));
}

typedef struct igmp_ssm_range_walk_ctx_t_
{
  unix_shared_memory_queue_t *q;
  u32 context;
} igmp_ssm_range_walk_ctx_t;

static walk_rc_t
igmp_ssm_range_walk_dump (const fib_prefix_t * pfx,
			  igmp_group_prefix_type_t type, void *args)
{
  igmp_ssm_range_walk_ctx_t *ctx = args;
  vl_api_igmp_group_prefix_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (IGMP_MSG_ID (VL_API_IGMP_DETAILS));
  mp->context = ctx->context;
  mp->gp.type = igmp_group_type_int_to_api (type);
  ip_prefix_encode (pfx, &mp->gp.prefix);

  vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);

  return (WALK_CONTINUE);
}

static void
vl_api_igmp_group_prefix_dump_t_handler (vl_api_igmp_dump_t * mp)
{
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  igmp_ssm_range_walk_ctx_t ctx = {
    .q = q,
    .context = mp->context,
  };

  igmp_ssm_range_walk (igmp_ssm_range_walk_dump, &ctx);
}

static vpe_client_registration_t *
igmp_api_client_lookup (igmp_main_t * im, u32 client_index)
{
  uword *p;
  vpe_client_registration_t *api_client = NULL;

  p = hash_get (im->igmp_api_client_by_client_index, client_index);
  if (p)
    api_client = vec_elt_at_index (im->api_clients, p[0]);

  return api_client;
}

static void
vl_api_want_igmp_events_t_handler (vl_api_want_igmp_events_t * mp)
{
  igmp_main_t *im = &igmp_main;
  vpe_client_registration_t *api_client;
  vl_api_want_igmp_events_reply_t *rmp;
  int rv = 0;

  api_client = igmp_api_client_lookup (im, mp->client_index);
  if (api_client)
    {
      if (mp->enable)
	{
	  rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  goto done;
	}
      hash_unset (im->igmp_api_client_by_client_index,
		  api_client->client_index);
      pool_put (im->api_clients, api_client);
      goto done;
    }
  if (mp->enable)
    {
      pool_get (im->api_clients, api_client);
      memset (api_client, 0, sizeof (vpe_client_registration_t));
      api_client->client_index = mp->client_index;
      api_client->client_pid = mp->pid;
      hash_set (im->igmp_api_client_by_client_index,
		mp->client_index, api_client - im->api_clients);
      goto done;
    }
  rv = VNET_API_ERROR_INVALID_REGISTRATION;

done:;
  REPLY_MACRO (VL_API_WANT_IGMP_EVENTS_REPLY + im->msg_id_base);
}

static clib_error_t *
want_igmp_events_reaper (u32 client_index)
{
  igmp_main_t *im = &igmp_main;
  vpe_client_registration_t *api_client;
  uword *p;

  p = hash_get (im->igmp_api_client_by_client_index, client_index);

  if (p)
    {
      api_client = pool_elt_at_index (im->api_clients, p[0]);
      pool_put (im->api_clients, api_client);
      hash_unset (im->igmp_api_client_by_client_index, client_index);
    }
  return (NULL);
}

VL_MSG_API_REAPER_FUNCTION (want_igmp_events_reaper);

void
send_igmp_event (unix_shared_memory_queue_t * q,
		 u32 context,
		 igmp_filter_mode_t filter,
		 u32 sw_if_index,
		 const ip46_address_t * saddr, const ip46_address_t * gaddr)
{
  vl_api_igmp_event_t *mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs ((VL_API_IGMP_EVENT) + igmp_main.msg_id_base);
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->filter = htonl (filter);
  clib_memcpy (&mp->saddr, &saddr->ip4, sizeof (ip4_address_t));
  clib_memcpy (&mp->gaddr, &gaddr->ip4, sizeof (ip4_address_t));

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

void
igmp_event (igmp_filter_mode_t filter,
	    u32 sw_if_index,
	    const ip46_address_t * saddr, const ip46_address_t * gaddr)
{
  vpe_client_registration_t *api_client;
  unix_shared_memory_queue_t *q;
  igmp_main_t *im;

  im = &igmp_main;

  IGMP_DBG ("event: (%U, %U) %U %U",
	    format_ip46_address, saddr, IP46_TYPE_ANY,
	    format_ip46_address, saddr, IP46_TYPE_ANY,
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), sw_if_index, format_igmp_filter_mode, filter);


  /* *INDENT-OFF* */
  pool_foreach (api_client, im->api_clients,
    ({
      q = vl_api_client_index_to_input_queue (api_client->client_index);
      if (q)
        send_igmp_event (q, 0, filter, sw_if_index, saddr, gaddr);
    }));
  /* *INDENT-ON* */
}

#define vl_msg_name_crc_list
#include <igmp/igmp_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (igmp_main_t * im, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + im->msg_id_base);
  foreach_vl_msg_name_crc_igmp;
#undef _
}

/* Set up the API message handling tables */
static clib_error_t *
igmp_plugin_api_hookup (vlib_main_t * vm)
{
  igmp_main_t *im = &igmp_main;
  api_main_t *am = &api_main;
  u8 *name;

  /* Construct the API name */
  name = format (0, "igmp_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  im->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + im->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_igmp_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (im, am);

  vec_free (name);
  return 0;
}

VLIB_API_INIT_FUNCTION (igmp_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
