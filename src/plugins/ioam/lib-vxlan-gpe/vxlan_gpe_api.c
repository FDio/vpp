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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <ioam/lib-vxlan-gpe/vxlan_gpe_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/lib-vxlan-gpe/vxlan_gpe_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ioam/lib-vxlan-gpe/vxlan_gpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ioam/lib-vxlan-gpe/vxlan_gpe_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/lib-vxlan-gpe/vxlan_gpe_all_api_h.h>
#undef vl_api_version

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define VXLAN_GPE_REPLY_MACRO(t)                                \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

/* *INDENT-OFF* */
#define VXLAN_GPE_REPLY_MACRO2(t, body)                         \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t));                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);
/* *INDENT-ON* */

/* List of message types that this plugin understands */

#define foreach_vxlan_gpe_plugin_api_msg                               \
_(VXLAN_GPE_IOAM_ENABLE, vxlan_gpe_ioam_enable)                        \
_(VXLAN_GPE_IOAM_DISABLE, vxlan_gpe_ioam_disable)                      \
_(VXLAN_GPE_IOAM_VNI_ENABLE, vxlan_gpe_ioam_vni_enable)                \
_(VXLAN_GPE_IOAM_VNI_DISABLE, vxlan_gpe_ioam_vni_disable)              \
_(VXLAN_GPE_IOAM_TRANSIT_ENABLE, vxlan_gpe_ioam_transit_enable)        \
_(VXLAN_GPE_IOAM_TRANSIT_DISABLE, vxlan_gpe_ioam_transit_disable)      \


static void vl_api_vxlan_gpe_ioam_enable_t_handler
  (vl_api_vxlan_gpe_ioam_enable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_enable_reply_t *rmp;
  clib_error_t *error;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error =
    vxlan_gpe_ioam_enable (mp->trace_enable, mp->pow_enable, mp->trace_ppc);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  VXLAN_GPE_REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_disable_t_handler
  (vl_api_vxlan_gpe_ioam_disable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_disable_reply_t *rmp;
  clib_error_t *error;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error = vxlan_gpe_ioam_disable (0, 0, 0);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  VXLAN_GPE_REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_vni_enable_t_handler
  (vl_api_vxlan_gpe_ioam_vni_enable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_vni_enable_reply_t *rmp;
  clib_error_t *error;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  vxlan4_gpe_tunnel_key_t key4;
  uword *p = NULL;
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  u32 vni;


  if (!mp->is_ipv6)
    {
      clib_memcpy (&key4.local, &mp->local, sizeof (key4.local));
      clib_memcpy (&key4.remote, &mp->remote, sizeof (key4.remote));
      vni = clib_net_to_host_u32 (mp->vni);
      key4.vni = clib_host_to_net_u32 (vni << 8);
      key4.pad = 0;

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
			      hm->has_ppc_option, mp->is_ipv6);


  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  VXLAN_GPE_REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY);
}


static void vl_api_vxlan_gpe_ioam_vni_disable_t_handler
  (vl_api_vxlan_gpe_ioam_vni_disable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_vni_enable_reply_t *rmp;
  clib_error_t *error;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  vxlan4_gpe_tunnel_key_t key4;
  uword *p = NULL;
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  u32 vni;


  if (!mp->is_ipv6)
    {
      clib_memcpy (&key4.local, &mp->local, sizeof (key4.local));
      clib_memcpy (&key4.remote, &mp->remote, sizeof (key4.remote));
      vni = clib_net_to_host_u32 (mp->vni);
      key4.vni = clib_host_to_net_u32 (vni << 8);
      key4.pad = 0;

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


  VXLAN_GPE_REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_transit_enable_t_handler
  (vl_api_vxlan_gpe_ioam_transit_enable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_transit_enable_reply_t *rmp;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  ip46_address_t dst_addr;

  memset (&dst_addr.ip4, 0, sizeof (dst_addr.ip4));
  if (!mp->is_ipv6)
    {
      clib_memcpy (&dst_addr.ip4, &mp->dst_addr, sizeof (dst_addr.ip4));
    }
  rv = vxlan_gpe_enable_disable_ioam_for_dest (sm->vlib_main,
					       dst_addr,
					       ntohl (mp->outer_fib_index),
					       mp->is_ipv6 ? 0 : 1,
					       1 /* is_add */ );

  VXLAN_GPE_REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY);
}

static void vl_api_vxlan_gpe_ioam_transit_disable_t_handler
  (vl_api_vxlan_gpe_ioam_transit_disable_t * mp)
{
  int rv = 0;
  vl_api_vxlan_gpe_ioam_transit_disable_reply_t *rmp;
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  ip46_address_t dst_addr;

  memset (&dst_addr.ip4, 0, sizeof (dst_addr.ip4));
  if (!mp->is_ipv6)
    {
      clib_memcpy (&dst_addr.ip4, &mp->dst_addr, sizeof (dst_addr.ip4));
    }

  rv = vxlan_gpe_ioam_disable_for_dest (sm->vlib_main,
					dst_addr,
					ntohl (mp->outer_fib_index),
					mp->is_ipv6 ? 0 : 1);
  VXLAN_GPE_REPLY_MACRO (VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
vxlan_gpe_plugin_api_hookup (vlib_main_t * vm)
{
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vxlan_gpe_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ioam/lib-vxlan-gpe/vxlan_gpe_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (vxlan_gpe_ioam_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_ioam_vxlan_gpe;
#undef _
}

static clib_error_t *
vxlan_gpe_init (vlib_main_t * vm)
{
  vxlan_gpe_ioam_main_t *sm = &vxlan_gpe_ioam_main;
  clib_error_t *error = 0;
  u8 *name;
  u32 encap_node_index = vxlan_gpe_encap_ioam_v4_node.index;
  u32 decap_node_index = vxlan_gpe_decap_ioam_v4_node.index;
  vlib_node_t *vxlan_gpe_encap_node = NULL;
  vlib_node_t *vxlan_gpe_decap_node = NULL;
  uword next_node = 0;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();
  sm->unix_time_0 = (u32) time (0);	/* Store starting time */
  sm->vlib_time_0 = vlib_time_now (vm);

  name = format (0, "ioam_vxlan_gpe_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = vxlan_gpe_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

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
  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (vxlan_gpe_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
