/*
 *------------------------------------------------------------------
 * gtpu_api.c - gtpu api
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <gtpu/gtpu.h>


#define vl_msg_id(n,h) n,
typedef enum
{
#include <gtpu/gtpu.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <gtpu/gtpu.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <gtpu/gtpu.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <gtpu/gtpu.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <gtpu/gtpu.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <gtpu/gtpu.api.h>
#undef vl_msg_name_crc_list

/* move to gtpu.h
#define REPLY_MSG_ID_BASE gtm->msg_id_base
#include <vlibapi/api_helper_macros.h>
*/
static void
setup_message_id_table (gtpu_main_t * gtm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + gtm->msg_id_base);
  foreach_vl_msg_name_crc_gtpu;
#undef _
}

#define foreach_gtpu_plugin_api_msg                             \
_(SW_INTERFACE_SET_GTPU_BYPASS, sw_interface_set_gtpu_bypass)         \
_(GTPU_ADD_DEL_TUNNEL, gtpu_add_del_tunnel)                           \
_(GTPU_TUNNEL_DUMP, gtpu_tunnel_dump)                   \
_(WANT_GTPU_EVENTS, want_gtpu_events)

static void
  vl_api_sw_interface_set_gtpu_bypass_t_handler
  (vl_api_sw_interface_set_gtpu_bypass_t * mp)
{
  vl_api_sw_interface_set_gtpu_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  gtpu_main_t *gtm = &gtpu_main;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_gtpu_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY);
}

static void vl_api_gtpu_add_del_tunnel_t_handler
  (vl_api_gtpu_add_del_tunnel_t * mp)
{
  vl_api_gtpu_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  ip4_main_t *im = &ip4_main;
  gtpu_main_t *gtm = &gtpu_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_gtpu_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .is_ip6 = mp->is_ipv6,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .encap_fib_index = p[0],
    .decap_next_index = ntohl (mp->decap_next_index),
    .teid_in = ntohl (mp->teid_in),
    .teid_out = ntohl (mp->teid_out),
    .dst = to_ip46 (mp->is_ipv6, mp->dst_address),
    .src = to_ip46 (mp->is_ipv6, mp->src_address),
  };

  /* Check src & dst are different */
  if (ip46_address_cmp (&a.dst, &a.src) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  if (ip46_address_is_multicast (&a.dst) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  u32 sw_if_index = ~0;
  rv = vnet_gtpu_add_del_tunnel (&a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GTPU_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_gtpu_tunnel_details
  (gtpu_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_gtpu_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->dst);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_GTPU_TUNNEL_DETAILS);
  if (is_ipv6)
    {
      memcpy (rmp->src_address, t->src.ip6.as_u8, 16);
      memcpy (rmp->dst_address, t->dst.ip6.as_u8, 16);
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);
    }
  else
    {
      memcpy (rmp->src_address, t->src.ip4.as_u8, 4);
      memcpy (rmp->dst_address, t->dst.ip4.as_u8, 4);
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
    }
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->teid_in = htonl (t->teid_in);
  rmp->teid_out = htonl (t->teid_out);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->is_ipv6 = is_ipv6;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_gtpu_tunnel_dump_t_handler (vl_api_gtpu_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gtm->tunnels,
      ({
        send_gtpu_tunnel_details(t, reg, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (gtm->tunnel_index_by_sw_if_index)) ||
	  (~0 == gtm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &gtm->tunnels[gtm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_gtpu_tunnel_details (t, reg, mp->context);
    }
}


static vpe_client_registration_t *
get_gtpu_client (u32 client_index)
{
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_client_registration_t *registrations;
  uword *p;

  /* If there is, is our client_index one of them */
  registrations = &gtm->registrations;
  p = hash_get (registrations->client_hash, client_index);

  /* get fail */
  if (!p)
    return 0;

  return pool_elt_at_index (registrations->clients, p[0]);
}

static int
clear_gtpu_client (u32 client_index)
{
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_client_registration_t *registrations;
  vpe_client_registration_t *client;
  uword *p;
  int elts = 0;

  /* If there is, is our client_index one of them */
  registrations = &gtm->registrations;
  p = hash_get (registrations->client_hash, client_index);

  if (!p)
    goto exit;

  client = pool_elt_at_index (registrations->clients, p[0]);
  hash_unset (registrations->client_hash, client->client_index);
  pool_put (registrations->clients, client);

exit:
  /* Now check if that was the last item in any of the listened to gtpu */
  elts += pool_elts (registrations->clients);
  return elts;
}

static int
set_gtpu_client (vpe_client_registration_t * client)
{
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_client_registration_t *registrations;
  vpe_client_registration_t *cr;
  uword *p;

  registrations = &gtm->registrations;

  /* Is there anything listening */
  p = hash_get (registrations->client_hash, client->client_index);

  if (!p)
    {
      pool_get (registrations->clients, cr);
      cr->client_index = client->client_index;
      cr->client_pid = client->client_pid;
      hash_set (registrations->client_hash, cr->client_index,
		cr - registrations->clients);
    }

  return 1;
}

static void
vl_api_want_gtpu_events_t_handler (vl_api_want_gtpu_events_t * mp)
{
  gtpu_main_t *gtm = &gtpu_main;
  vpe_client_registration_t *rp, _rp;
  vl_api_registration_t *reg;
  vl_api_want_gtpu_events_reply_t *rmp;
  i32 retval = 0;

  rp = get_gtpu_client (mp->client_index);

  /* Disable case */
  if (mp->enable_disable == 0)
    {
      if (!rp)			/* No client to disable */
	{
	  clib_warning ("pid %d: already disabled for stats...",
			mp->client_pid);
	  goto out;
	}
      gtm->registrations.enable_poller = clear_gtpu_client (mp->client_index);
      goto out;
    }

  /* Enable case */
  if (!rp)
    {
      rp = &_rp;
      rp->client_index = mp->client_index;
      rp->client_pid = mp->client_pid;
      gtm->registrations.enable_poller = set_gtpu_client (rp);
    }

out:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      gtm->registrations.enable_poller = clear_gtpu_client (mp->client_index);
      return;
    }

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id =
    htons ((VL_API_WANT_GTPU_EVENTS_REPLY) + (REPLY_MSG_ID_BASE));
  rmp->context = mp->context;
  rmp->retval = htonl (retval);

  vl_api_send_msg (reg, (u8 *) rmp);
}


static clib_error_t *
gtpu_api_hookup (vlib_main_t * vm)
{
  gtpu_main_t *gtm = &gtpu_main;

  u8 *name = format (0, "gtpu_%08x%c", api_version, 0);
  gtm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + gtm->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_gtpu_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (gtm, &api_main);

  return 0;
}

VLIB_API_INIT_FUNCTION (gtpu_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
