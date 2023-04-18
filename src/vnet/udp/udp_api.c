/*
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
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
#include <vlibmemory/api.h>

#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_encap.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/udp/udp.h>

#include <vnet/format_fns.h>
#include <vnet/udp/udp.api_enum.h>
#include <vnet/udp/udp.api_types.h>

#define REPLY_MSG_ID_BASE udp_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
send_udp_encap_details (index_t uei, vl_api_registration_t *reg, u32 context)
{
  vl_api_udp_encap_details_t *mp;
  udp_encap_t *ue;

  if (!udp_encap_is_valid (uei))
    return;
  ue = udp_encap_get (uei);

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_UDP_ENCAP_DETAILS);
  mp->context = context;

  if (FIB_PROTOCOL_IP4 == ue->ue_ip_proto)
    {
      clib_memcpy (&mp->udp_encap.src_ip.un.ip4,
		   &ue->ue_hdrs.ip4.ue_ip4.src_address, 4);
      clib_memcpy (&mp->udp_encap.dst_ip.un.ip4,
		   &ue->ue_hdrs.ip4.ue_ip4.dst_address, 4);
      mp->udp_encap.dst_ip.af = ip_address_family_encode (AF_IP4);
      mp->udp_encap.src_ip.af = ip_address_family_encode (AF_IP4);

      /* ports aren't byte swapped because they are stored in network
       * byte order */
      mp->udp_encap.src_port = ue->ue_hdrs.ip4.ue_udp.src_port;
      mp->udp_encap.dst_port = ue->ue_hdrs.ip4.ue_udp.dst_port;
    }
  else
    {
      clib_memcpy (&mp->udp_encap.src_ip.un.ip6,
		   &ue->ue_hdrs.ip6.ue_ip6.src_address, 16);
      clib_memcpy (&mp->udp_encap.dst_ip.un.ip6,
		   &ue->ue_hdrs.ip6.ue_ip6.dst_address, 16);
      mp->udp_encap.dst_ip.af = ip_address_family_encode (AF_IP6);
      mp->udp_encap.src_ip.af = ip_address_family_encode (AF_IP6);

      /* ports aren't byte swapped because they are stored in network
       * byte order */
      mp->udp_encap.src_port = ue->ue_hdrs.ip6.ue_udp.src_port;
      mp->udp_encap.dst_port = ue->ue_hdrs.ip6.ue_udp.dst_port;
    }

  mp->udp_encap.table_id =
    htonl (fib_table_get_table_id (ue->ue_fib_index, ue->ue_ip_proto));
  mp->udp_encap.id = htonl (uei);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_udp_encap_dump_t_handler (vl_api_udp_encap_dump_t *mp)
{
  vl_api_registration_t *reg;
  index_t uei;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach_index (uei, udp_encap_pool)
    {
      send_udp_encap_details (uei, reg, mp->context);
    }
  /* *INDENT-ON* */
}

static void
vl_api_udp_encap_add_t_handler (vl_api_udp_encap_add_t *mp)
{
  vl_api_udp_encap_add_reply_t *rmp;
  ip46_address_t src_ip, dst_ip;
  udp_encap_fixup_flags_t flags;
  u32 fib_index, table_id;
  fib_protocol_t fproto;
  ip46_type_t itype;
  index_t uei;
  int rv = 0;

  uei = INDEX_INVALID;
  table_id = ntohl (mp->udp_encap.table_id);

  itype = ip_address_decode (&mp->udp_encap.src_ip, &src_ip);
  itype = ip_address_decode (&mp->udp_encap.dst_ip, &dst_ip);
  fproto = fib_proto_from_ip46 (itype);
  fib_index = fib_table_find (fproto, table_id);

  if (~0 == fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_TABLE;
      goto done;
    }

  flags = UDP_ENCAP_FIXUP_NONE;
  if (mp->udp_encap.src_port == 0)
    flags |= UDP_ENCAP_FIXUP_UDP_SRC_PORT_ENTROPY;

  uei = udp_encap_add_and_lock (fproto, fib_index, &src_ip, &dst_ip,
				ntohs (mp->udp_encap.src_port),
				ntohs (mp->udp_encap.dst_port), flags);

done:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_UDP_ENCAP_ADD_REPLY,
  ({
    rmp->id = ntohl (uei);
  }));
  /* *INDENT-ON* */

}

static void
vl_api_udp_encap_del_t_handler (vl_api_udp_encap_del_t *mp)
{
  vl_api_udp_encap_del_reply_t *rmp;
  index_t uei = ntohl (mp->id);
  int rv = 0;

  if (!udp_encap_is_valid (uei))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto done;
    }

  udp_encap_unlock (uei);

done:
  REPLY_MACRO (VL_API_UDP_ENCAP_DEL_REPLY);
}

u32
udp_api_decap_proto_to_index (vlib_main_t *vm,
			      vl_api_udp_decap_next_proto_t iproto)
{
  switch (iproto)
    {
    case UDP_API_DECAP_PROTO_IP4:
      return vlib_get_node_by_name (vm, (u8 *) "ip4-input")->index;
    case UDP_API_DECAP_PROTO_IP6:
      return vlib_get_node_by_name (vm, (u8 *) "ip6-input")->index;
    case UDP_API_DECAP_PROTO_MPLS:
      return vlib_get_node_by_name (vm, (u8 *) "mpls-input")->index;
    }
  return ~0;
}

static void
vl_api_udp_decap_add_del_t_handler (vl_api_udp_decap_add_del_t *mp)
{
  vl_api_udp_decap_add_del_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  int rv = 0;

  if (mp->is_add)
    {
      u32 node_index =
	udp_api_decap_proto_to_index (vm, ntohl (mp->udp_decap.next_proto));
      if (node_index == ~0)
	rv = VNET_API_ERROR_INVALID_PROTOCOL;
      else
	udp_register_dst_port (vm, ntohs (mp->udp_decap.port), node_index,
			       mp->udp_decap.is_ip4);
    }
  else
    udp_unregister_dst_port (vm, ntohs (mp->udp_decap.port),
			     mp->udp_decap.is_ip4);
  REPLY_MACRO (VL_API_UDP_DECAP_ADD_DEL_REPLY);
}

#include <vnet/udp/udp.api.c>
static clib_error_t *
udp_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  /* Mark these APIs as mp safe */
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_UDP_ENCAP_ADD, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_UDP_ENCAP_DEL, 1);
  vl_api_set_msg_thread_safe (am, REPLY_MSG_ID_BASE + VL_API_UDP_ENCAP_DUMP,
			      1);

  return 0;
}

VLIB_API_INIT_FUNCTION (udp_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
