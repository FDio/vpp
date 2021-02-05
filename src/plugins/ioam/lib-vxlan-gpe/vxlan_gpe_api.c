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
/*
 *------------------------------------------------------------------
 * vxlan_gpe_api.c - iOAM VxLAN-GPE related APIs to create
 *               and maintain profiles
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h>
#include <vlibapi/api_helper_macros.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/udp/udp_local.h>

/* define message IDs */
#include <ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api_enum.h>
#include <ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api_types.h>

static void vl_api_vxlan_gpe_ioam_enable_t_handler
  (vl_api_vxlan_gpe_ioam_enable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_enable_reply_t *rmp;
  clib_error_t *error;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error =
    vxlan_gpe_ioam_enable (mp->trace_enable, mp->pow_enable, mp->trace_ppc);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_disable_t_handler
  (vl_api_vxlan_gpe_ioam_disable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_disable_reply_t *rmp;
  clib_error_t *error;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error = vxlan_gpe_ioam_disable (0, 0, 0);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_vni_enable_t_handler
  (vl_api_vxlan_gpe_ioam_vni_enable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_vni_enable_reply_t *rmp;
  clib_error_t *error;
  vxlan4_gpe_tunnel_key_t key4;
  uword *p = NULL;
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  u32 vni;


  if (clib_net_to_host_u32 (mp->local.af) == ADDRESS_IP4 &&
      clib_net_to_host_u32 (mp->remote.af) == ADDRESS_IP4)
    {
      clib_memcpy (&key4.local, &mp->local.un.ip4, sizeof (key4.local));
      clib_memcpy (&key4.remote, &mp->remote.un.ip4, sizeof (key4.remote));
      vni = clib_net_to_host_u32 (mp->vni);
      key4.vni = clib_host_to_net_u32 (vni << 8);
      key4.port = (u32) clib_host_to_net_u16 (UDP_DST_PORT_VXLAN_GPE);

      p = hash_get_mem (gm->vxlan4_gpe_tunnel_by_key, &key4);
    }
  else
    {
      return;
    }

  if (!p)
    return;

  t = pool_elt_at_index (gm->tunnels, p[0]);

  error = vxlan_gpe_ioam_set (t, hm->has_trace_option,
			      hm->has_pot_option,
			      hm->has_ppc_option, 0 /* is_ipv6 */ );


  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY);
}


static void vl_api_vxlan_gpe_ioam_vni_disable_t_handler
  (vl_api_vxlan_gpe_ioam_vni_disable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_vni_enable_reply_t *rmp;
  clib_error_t *error;
  vxlan4_gpe_tunnel_key_t key4;
  uword *p = NULL;
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  u32 vni;


  if (clib_net_to_host_u32 (mp->local.af) == ADDRESS_IP4 &&
      clib_net_to_host_u32 (mp->remote.af) == ADDRESS_IP4)
    {
      clib_memcpy (&key4.local, &mp->local, sizeof (key4.local));
      clib_memcpy (&key4.remote, &mp->remote, sizeof (key4.remote));
      vni = clib_net_to_host_u32 (mp->vni);
      key4.vni = clib_host_to_net_u32 (vni << 8);
      key4.port = (u32) clib_host_to_net_u16 (UDP_DST_PORT_VXLAN_GPE);

      p = hash_get_mem (gm->vxlan4_gpe_tunnel_by_key, &key4);
    }
  else
    {
      return;
    }

  if (!p)
    return;

  t = pool_elt_at_index (gm->tunnels, p[0]);

  error = vxlan_gpe_ioam_clear (t, 0, 0, 0, 0);


  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }


  REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_transit_enable_t_handler
  (vl_api_vxlan_gpe_ioam_transit_enable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_transit_enable_reply_t *rmp;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  ip46_address_t dst_addr;

  ip_address_decode (&mp->dst_addr, &dst_addr);
  bool is_ip6 = clib_net_to_host_u32 (mp->dst_addr.af) == ADDRESS_IP6;
  rv = vxlan_gpe_enable_disable_ioam_for_dest (sm->vlib_main,
					       dst_addr,
					       ntohl (mp->outer_fib_index),
					       is_ip6, 1 /* is_add */ );

  REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_transit_disable_t_handler
  (vl_api_vxlan_gpe_ioam_transit_disable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_transit_disable_reply_t *rmp;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  ip46_address_t dst_addr;

  ip_address_decode (&mp->dst_addr, &dst_addr);
  bool is_ip6 = clib_net_to_host_u32 (mp->dst_addr.af) == ADDRESS_IP6;
  rv = vxlan_gpe_ioam_disable_for_dest (sm->vlib_main,
					dst_addr,
					ntohl (mp->outer_fib_index), is_ip6);
  REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY);
}

#include <ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api.c>
static clib_error_t *
ioam_vxlan_gpe_init (vlib_main_t * vm)
{
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  u32 encap_node_index = vxlan_gpe_encap_ioam_v4_node.index;
  u32 decap_node_index = vxlan_gpe_decap_ioam_v4_node.index;
  vlib_node_t *vxlan_gpe_encap_node = NULL;
  vlib_node_t *vxlan_gpe_decap_node = NULL;
  uword next_node = 0;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();
  sm->unix_time_0 = (u32) time (0);	/* Store starting time */
  sm->vlib_time_0 = vlib_time_now (vm);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = setup_message_id_table ();

  /* Hook the ioam-encap node to vxlan-gpe-encap */
  vxlan_gpe_encap_node = vlib_get_node_by_name (vm, (u8 *) "vxlan-gpe-encap");
  sm->encap_v4_next_node =
    vlib_node_add_next (vm, vxlan_gpe_encap_node->index, encap_node_index);

  vxlan_gpe_decap_node =
    vlib_get_node_by_name (vm, (u8 *) "vxlan4-gpe-input");
  next_node =
    vlib_node_add_next (vm, vxlan_gpe_decap_node->index, decap_node_index);
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_IOAM, next_node);

  vec_new (vxlan_gpe_ioam_sw_interface_t, pool_elts (sm->sw_interfaces));
  sm->dst_by_ip4 = hash_create_mem (0, sizeof (fib_prefix_t), sizeof (uword));

  sm->dst_by_ip6 = hash_create_mem (0, sizeof (fib_prefix_t), sizeof (uword));

  vxlan_gpe_ioam_interface_init ();

  return 0;
}

VLIB_INIT_FUNCTION (ioam_vxlan_gpe_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
