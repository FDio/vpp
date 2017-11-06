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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/udp/udp_encap.h>
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


#define foreach_udp_api_msg                      \
  _(UDP_ENCAP_ADD_DEL, udp_encap_add_del)        \
_(UDP_ENCAP_DUMP, udp_encap_dump)

static void
send_udp_encap_details (const udp_encap_t * ue,
			unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_udp_encap_details_t *mp;
  fib_table_t *fib_table;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_UDP_ENCAP_DETAILS);
  mp->context = context;

  mp->is_ip6 = (ue->ue_ip_proto == FIB_PROTOCOL_IP6);

  if (FIB_PROTOCOL_IP4 == ue->ue_ip_proto)
    {
      clib_memcpy (mp->src_ip, &ue->ue_hdrs.ip4.ue_ip4.src_address, 4);
      clib_memcpy (mp->dst_ip, &ue->ue_hdrs.ip4.ue_ip4.dst_address, 4);
      mp->src_port = htons (ue->ue_hdrs.ip4.ue_udp.src_port);
      mp->dst_port = htons (ue->ue_hdrs.ip4.ue_udp.dst_port);
    }
  else
    {
      clib_memcpy (mp->src_ip, &ue->ue_hdrs.ip6.ue_ip6.src_address, 16);
      clib_memcpy (mp->dst_ip, &ue->ue_hdrs.ip6.ue_ip6.dst_address, 16);
      mp->src_port = htons (ue->ue_hdrs.ip6.ue_udp.src_port);
      mp->dst_port = htons (ue->ue_hdrs.ip6.ue_udp.dst_port);
    }

  fib_table = fib_table_get (ue->ue_fib_index, ue->ue_ip_proto);
  mp->table_id = htonl (fib_table->ft_table_id);
  mp->id = htonl (ue->ue_id);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_udp_encap_dump_t_handler (vl_api_udp_encap_dump_t * mp,
				 vlib_main_t * vm)
{
  unix_shared_memory_queue_t *q;
  udp_encap_t *ue;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach(ue, udp_encap_pool,
  ({
    send_udp_encap_details(ue, q, mp->context);
  }));
  /* *INDENT-OFF* */
}

static void
vl_api_udp_encap_add_del_t_handler (vl_api_udp_encap_add_del_t * mp,
                                    vlib_main_t * vm)
{
  vl_api_udp_encap_add_del_reply_t *rmp;
  ip46_address_t src_ip, dst_ip;
  u32 fib_index, table_id, ue_id;
  fib_protocol_t fproto;
  int rv = 0;

  ue_id = ntohl(mp->id);
  table_id = ntohl(mp->table_id);
  fproto = (mp->is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);

  fib_index = fib_table_find(fproto, table_id);

  if (~0 == fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_TABLE;
      goto done;
    }

  if (FIB_PROTOCOL_IP4 == fproto)
    {
      clib_memcpy(&src_ip.ip4, mp->src_ip, 4);
      clib_memcpy(&dst_ip.ip4, mp->dst_ip, 4);
    }
  else
    {
      clib_memcpy(&src_ip.ip6, mp->src_ip, 16);
      clib_memcpy(&dst_ip.ip6, mp->dst_ip, 16);
    }

  if (mp->is_add)
    {
      udp_encap_add_and_lock(ue_id, fproto, fib_index,
                             &src_ip, &dst_ip,
                             ntohs(mp->src_port),
                             ntohs(mp->dst_port),
                             UDP_ENCAP_FIXUP_NONE);
    }
  else
    {
      udp_encap_unlock(ue_id);
    }

 done:
  REPLY_MACRO (VL_API_UDP_ENCAP_ADD_DEL_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/udp/udp.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_udp;
#undef _
}

static clib_error_t *
udp_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_udp_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

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
