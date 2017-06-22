/*
 *------------------------------------------------------------------
 * vxlan_gpe_api.c - vxlan_gpe api
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
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/fib/fib_table.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(SW_INTERFACE_SET_VXLAN_GPE_BYPASS, sw_interface_set_vxlan_gpe_bypass)         \
_(VXLAN_GPE_ADD_DEL_TUNNEL, vxlan_gpe_add_del_tunnel)                   \
_(VXLAN_GPE_TUNNEL_DUMP, vxlan_gpe_tunnel_dump)

static void
  vl_api_sw_interface_set_vxlan_gpe_bypass_t_handler
  (vl_api_sw_interface_set_vxlan_gpe_bypass_t * mp)
{
  vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_vxlan_gpe_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VXLAN_GPE_BYPASS_REPLY);
}

static void
  vl_api_vxlan_gpe_add_del_tunnel_t_handler
  (vl_api_vxlan_gpe_add_del_tunnel_t * mp)
{
  vl_api_vxlan_gpe_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, *a = &_a;
  u32 encap_fib_index, decap_fib_index;
  u8 protocol;
  uword *p;
  ip4_main_t *im = &ip4_main;
  u32 sw_if_index = ~0;


  p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  encap_fib_index = p[0];

  protocol = mp->protocol;

  /* Interpret decap_vrf_id as an opaque if sending to other-than-ip4-input */
  if (protocol == VXLAN_GPE_INPUT_NEXT_IP4_INPUT)
    {
      p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
      if (!p)
	{
	  rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
	  goto out;
	}
      decap_fib_index = p[0];
    }
  else
    {
      decap_fib_index = ntohl (mp->decap_vrf_id);
    }

  /* Check src & dst are different */
  if ((mp->is_ipv6 && memcmp (mp->local, mp->remote, 16) == 0) ||
      (!mp->is_ipv6 && memcmp (mp->local, mp->remote, 4) == 0))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;
  a->is_ip6 = mp->is_ipv6;
  /* ip addresses sent in network byte order */
  if (a->is_ip6)
    {
      clib_memcpy (&(a->local.ip6), mp->local, 16);
      clib_memcpy (&(a->remote.ip6), mp->remote, 16);
    }
  else
    {
      clib_memcpy (&(a->local.ip4), mp->local, 4);
      clib_memcpy (&(a->remote.ip4), mp->remote, 4);
    }
  a->mcast_sw_if_index = ntohl (mp->mcast_sw_if_index);
  a->encap_fib_index = encap_fib_index;
  a->decap_fib_index = decap_fib_index;
  a->protocol = protocol;
  a->vni = ntohl (mp->vni);
  rv = vnet_vxlan_gpe_add_del_tunnel (a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_vxlan_gpe_tunnel_details
  (vxlan_gpe_tunnel_t * t, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_vxlan_gpe_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !(t->flags & VXLAN_GPE_TUNNEL_IS_IPV4);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VXLAN_GPE_TUNNEL_DETAILS);
  if (is_ipv6)
    {
      memcpy (rmp->local, &(t->local.ip6.as_u8), 16);
      memcpy (rmp->remote, &(t->remote.ip6.as_u8), 16);
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      memcpy (rmp->local, &(t->local.ip4.as_u8), 4);
      memcpy (rmp->remote, &(t->remote.ip4.as_u8), 4);
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
    }
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->vni = htonl (t->vni);
  rmp->protocol = t->protocol;
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->is_ipv6 = is_ipv6;
  rmp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void vl_api_vxlan_gpe_tunnel_dump_t_handler
  (vl_api_vxlan_gpe_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vxlan_gpe_main_t *vgm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t;
  u32 sw_if_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, vgm->tunnels,
      ({
        send_vxlan_gpe_tunnel_details(t, q, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (vgm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vgm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vgm->tunnels[vgm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_gpe_tunnel_details (t, q, mp->context);
    }
}


/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_vxlan_gpe;
#undef _
}

static clib_error_t *
vxlan_gpe_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  am->api_trace_cfg[VL_API_VXLAN_GPE_ADD_DEL_TUNNEL].size +=
    17 * sizeof (u32);

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (vxlan_gpe_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
