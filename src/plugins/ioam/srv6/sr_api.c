/*
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
 */
/*
 *------------------------------------------------------------------
 * sr_api.c - iOAM VxLAN-GPE related APIs to create
 *               and maintain profiles
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/srv6/sr.h>
#include <ioam/srv6/sr_ioam.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <ioam/srv6/sr_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_api_version

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define SR_REPLY_MACRO(t)                                \
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
#define SR_REPLY_MACRO2(t, body)                         \
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

#define foreach_sr_plugin_api_msg                               \
_(SR_IOAM_ENABLE, sr_ioam_enable)                        \
_(SR_IOAM_DISABLE, sr_ioam_disable)


static void
vl_api_sr_ioam_enable_t_handler (vl_api_sr_ioam_enable_t * mp)
{
  int rv = 0;
  vl_api_sr_ioam_enable_reply_t *rmp;
  clib_error_t *error;
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error = sr_ioam_enable (mp->trace_enable, mp->pow_enable, mp->trace_ppc);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  SR_REPLY_MACRO (VL_API_SR_IOAM_ENABLE_REPLY);
}

static void
vl_api_sr_ioam_disable_t_handler (vl_api_sr_ioam_disable_t * mp)
{
  int rv = 0;
  vl_api_sr_ioam_disable_reply_t *rmp;
  clib_error_t *error;
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;

  /* Ignoring the profile id as currently a single profile
   * is supported */
  error = sr_ioam_disable (0, 0, 0);
  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  SR_REPLY_MACRO (VL_API_SR_IOAM_DISABLE_REPLY);
}

#if 0
static void vl_api_sr_ioam_vni_enable_t_handler
  (vl_api_sr_ioam_vni_enable_t * mp)
{
  int rv = 0;
  vl_api_sr_ioam_vni_enable_reply_t *rmp;
  clib_error_t *error;
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;
  vxlan4_gpe_tunnel_key_t key4;
  uword *p = NULL;
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  ip6_sr_tlv_main_t *hm = &ip6_sr_tlv_main;
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

  error = sr_ioam_set (t, hm->has_trace_option,
		       hm->has_pot_option, hm->has_ppc_option, mp->is_ipv6);


  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }

  SR_REPLY_MACRO (VL_API_SR_IOAM_VNI_ENABLE_REPLY);
}


static void vl_api_sr_ioam_vni_disable_t_handler
  (vl_api_sr_ioam_vni_disable_t * mp)
{
  int rv = 0;
  vl_api_sr_ioam_vni_enable_reply_t *rmp;
  clib_error_t *error;
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;
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

  error = sr_ioam_clear (t, 0, 0, 0, 0);


  if (error)
    {
      clib_error_report (error);
      rv = clib_error_get_code (error);
    }


  SR_REPLY_MACRO (VL_API_SR_IOAM_VNI_DISABLE_REPLY);
}

static void vl_api_sr_ioam_transit_enable_t_handler
  (vl_api_sr_ioam_transit_enable_t * mp)
{
  int rv = 0;
  vl_api_sr_ioam_transit_enable_reply_t *rmp;
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;
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

  SR_REPLY_MACRO (VL_API_SR_IOAM_TRANSIT_ENABLE_REPLY);
}

static void vl_api_sr_ioam_transit_disable_t_handler
  (vl_api_sr_ioam_transit_disable_t * mp)
{
  int rv = 0;
  vl_api_sr_ioam_transit_disable_reply_t *rmp;
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;
  ip46_address_t dst_addr;

  memset (&dst_addr.ip4, 0, sizeof (dst_addr.ip4));
  if (!mp->is_ipv6)
    {
      clib_memcpy (&dst_addr.ip4, &mp->dst_addr, sizeof (dst_addr.ip4));
    }

  rv = sr_ioam_disable_for_dest (sm->vlib_main,
				 dst_addr,
				 ntohl (mp->outer_fib_index),
				 mp->is_ipv6 ? 0 : 1);
  SR_REPLY_MACRO (VL_API_SR_IOAM_TRANSIT_DISABLE_REPLY);
}
#endif

/* Set up the API message handling tables */
static clib_error_t *
sr_plugin_api_hookup (vlib_main_t * vm)
{
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sr_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (ip6_sr_tlv_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_ioam_sr;
#undef _
}

extern u8 *sr_ioam_compute_rewrite_insert (u8 * rewrite_buf, u8 tlv_type1);
extern u8 *sr_ioam_compute_rewrite_encap (u8 * rewrite_buf, u8 tlv_type1);
static clib_error_t *
ioam_sr_init (vlib_main_t * vm)
{
  ip6_sr_tlv_main_t *sm = &ip6_sr_tlv_main;
  clib_error_t *error = 0;
  u8 *name;
  u32 sr_node_index = sr_ioam_localsid_node.index;
  u32 sr_policy_node_index = sr_ioam_policy_rewrite_insert_node.index;
  vlib_node_t *sr_localsid_node = NULL;
  vlib_node_t *sr_policy_node = NULL;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();
  sm->unix_time_0 = (u32) time (0);	/* Store starting time */
  sm->vlib_time_0 = vlib_time_now (vm);

  name = format (0, "ioam_sr_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = sr_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  /* Hook the ioam-encap node to SR */
  sr_localsid_node = vlib_get_node_by_name (vm, (u8 *) "sr-localsid");
  sm->sid_next_node =
    vlib_node_add_next (vm, sr_localsid_node->index, sr_node_index);

  sr_oam_register_localsid_function (vm, sm->sid_next_node, NULL, NULL);

  sr_policy_node = vlib_get_node_by_name (vm, (u8 *) "sr-pl-rewrite-insert");
  sm->policy_next_node =
    vlib_node_add_next (vm, sr_policy_node->index, sr_policy_node_index);

  sr_policy_node = vlib_get_node_by_name (vm, (u8 *) "sr-pl-rewrite-encaps");
  sm->policy_next_node =
    vlib_node_add_next (vm, sr_policy_node->index, sr_policy_node_index);


  sr_oam_register_policy_function (vm, sm->policy_next_node,
				   sr_ioam_compute_rewrite_insert, NULL,
				   sr_ioam_compute_rewrite_encap, NULL);

  sr_ioam_interface_init ();
  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (ioam_sr_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
