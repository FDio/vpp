/*
 *------------------------------------------------------------------
 * flow_api.c - flow api
 *
 * Copyright (c) 2020 Intel and/or its affiliates.
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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/flow/flow.h>
#include <vnet/fib/fib_table.h>
#include <vnet/tunnel/tunnel_types_api.h>
#include <vnet/ip/ip_types_api.h>
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

#define foreach_vpe_api_msg         \
_(FLOW_ADD, flow_add)               \
_(FLOW_DEL, flow_del)               \
_(FLOW_ENABLE, flow_enable)         \
_(FLOW_DISABLE, flow_disable)

static inline void
ipv4_addr_convert (vl_api_ip4_address_t * vat_addr, ip4_address_t * vnet_addr)
{
  clib_memcpy (vnet_addr, vat_addr, sizeof (*vnet_addr));
}

static inline void
ipv6_addr_convert (vl_api_ip6_address_t * vat_addr, ip6_address_t * vnet_addr)
{
  clib_memcpy (vnet_addr, vat_addr, sizeof (*vnet_addr));
}

static inline void
ipv4_addr_and_mask_convert (vl_api_ip4_address_and_mask_t * vat_addr,
			    ip4_address_and_mask_t * vnet_addr)
{
  clib_memcpy (vnet_addr, vat_addr, sizeof (*vnet_addr));
}

static inline void
ipv6_addr_and_mask_convert (vl_api_ip6_address_and_mask_t * vat_addr,
			    ip6_address_and_mask_t * vnet_addr)
{
  clib_memcpy (vnet_addr, vat_addr, sizeof (*vnet_addr));
}

static inline void
port_and_mask_convert (vl_api_ip_port_and_mask_t * vat_port,
		       ip_port_and_mask_t * vnet_port)
{
  vnet_port->port = ntohs (vat_port->port);
  vnet_port->mask = ntohs (vat_port->mask);
}

static inline void
ethernet_flow_convert (vl_api_flow_ethernet_t * vat_flow,
		       vnet_flow_ethernet_t * f)
{
  clib_memcpy (f->eth_hdr.dst_address, vat_flow->dst_addr,
	       sizeof (f->eth_hdr.dst_address));
  clib_memcpy (f->eth_hdr.src_address, vat_flow->src_addr,
	       sizeof (f->eth_hdr.src_address));

  f->eth_hdr.type = ntohs (vat_flow->type);
}

static inline void
ipv4_n_tuple_flow_convert (vl_api_flow_ip4_n_tuple_t * vat_flow,
			   vnet_flow_ip4_n_tuple_t * f)
{
  ipv4_addr_and_mask_convert (&vat_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vat_flow->dst_addr, &f->dst_addr);

  port_and_mask_convert (&vat_flow->src_port, &f->src_port);
  port_and_mask_convert (&vat_flow->dst_port, &f->dst_port);

  f->protocol = vat_flow->protocol;
}

static void
ipv6_n_tuple_flow_convert (vl_api_flow_ip6_n_tuple_t * vat_flow,
			   vnet_flow_ip6_n_tuple_t * f)
{
  ipv6_addr_and_mask_convert (&vat_flow->src_addr, &f->src_addr);
  ipv6_addr_and_mask_convert (&vat_flow->dst_addr, &f->dst_addr);

  port_and_mask_convert (&vat_flow->src_port, &f->src_port);
  port_and_mask_convert (&vat_flow->dst_port, &f->dst_port);

  f->protocol = vat_flow->protocol;
}

static inline void
ipv4_n_tuple_tagged_flow_convert (vl_api_flow_ip4_n_tuple_tagged_t * vat_flow,
				  vnet_flow_ip4_n_tuple_tagged_t * f)
{
  return ipv4_n_tuple_flow_convert ((vl_api_flow_ip4_n_tuple_t *) vat_flow,
				    (vnet_flow_ip4_n_tuple_t *) f);
}

static inline void
ipv6_n_tuple_tagged_flow_convert (vl_api_flow_ip6_n_tuple_tagged_t * vat_flow,
				  vnet_flow_ip6_n_tuple_tagged_t * f)
{
  return ipv6_n_tuple_flow_convert ((vl_api_flow_ip6_n_tuple_t *) vat_flow,
				    (vnet_flow_ip6_n_tuple_t *) f);
}

static inline void
ipv4_l2tpv3oip_flow_convert (vl_api_flow_ip4_l2tpv3oip_t * vat_flow,
			     vnet_flow_ip4_l2tpv3oip_t * f)
{
  ipv4_addr_and_mask_convert (&vat_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vat_flow->dst_addr, &f->dst_addr);

  f->protocol = vat_flow->protocol;
  f->session_id = ntohl (vat_flow->session_id);
}

static inline void
ipv4_ipsec_esp_flow_convert (vl_api_flow_ip4_ipsec_esp_t * vat_flow,
			     vnet_flow_ip4_ipsec_esp_t * f)
{
  ipv4_addr_and_mask_convert (&vat_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vat_flow->dst_addr, &f->dst_addr);

  f->protocol = vat_flow->protocol;
  f->spi = ntohl (vat_flow->spi);
}

static inline void
ipv4_ipsec_ah_flow_convert (vl_api_flow_ip4_ipsec_ah_t * vat_flow,
			    vnet_flow_ip4_ipsec_ah_t * f)
{
  ipv4_addr_and_mask_convert (&vat_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vat_flow->dst_addr, &f->dst_addr);

  f->protocol = vat_flow->protocol;
  f->spi = ntohl (vat_flow->spi);
}

static inline void
ipv4_vxlan_flow_convert (vl_api_flow_ip4_vxlan_t * vat_flow,
			 vnet_flow_ip4_vxlan_t * f)
{
  ipv4_addr_convert (&vat_flow->src_addr, &f->src_addr);
  ipv4_addr_convert (&vat_flow->dst_addr, &f->dst_addr);

  f->dst_port = ntohs (vat_flow->dst_port);
  f->vni = ntohl (vat_flow->vni);
}

static inline void
ipv6_vxlan_flow_convert (vl_api_flow_ip6_vxlan_t * vat_flow,
			 vnet_flow_ip6_vxlan_t * f)
{
  ipv6_addr_convert (&vat_flow->src_addr, &f->src_addr);
  ipv6_addr_convert (&vat_flow->dst_addr, &f->dst_addr);

  f->dst_port = ntohs (vat_flow->dst_port);
  f->vni = ntohs (vat_flow->vni);
}

static inline void
ipv4_gtpu_flow_convert (vl_api_flow_ip4_gtpu_t * vat_flow,
			vnet_flow_ip4_gtpu_t * f)
{
  ipv4_addr_and_mask_convert (&vat_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vat_flow->dst_addr, &f->dst_addr);

  port_and_mask_convert (&vat_flow->src_port, &f->src_port);
  port_and_mask_convert (&vat_flow->dst_port, &f->dst_port);

  f->protocol = vat_flow->protocol;
  f->teid = ntohl (vat_flow->teid);
}

static inline void
ipv4_gtpc_flow_convert (vl_api_flow_ip4_gtpc_t * vat_flow,
			vnet_flow_ip4_gtpc_t * f)
{
  ipv4_addr_and_mask_convert (&vat_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vat_flow->dst_addr, &f->dst_addr);

  port_and_mask_convert (&vat_flow->src_port, &f->src_port);
  port_and_mask_convert (&vat_flow->dst_port, &f->dst_port);

  f->protocol = vat_flow->protocol;
  f->teid = ntohl (vat_flow->teid);
}

static void
vl_api_flow_add_t_handler (vl_api_flow_add_t * mp)
{
  vl_api_flow_add_reply_t *rmp;
  int rv = 0;
  vnet_flow_t flow;
  u32 flow_index = ~0;
  vl_api_vat_flow_t *f = &mp->flow;

  vnet_main_t *vnm = vnet_get_main ();

  flow.type = ntohl (f->type);
  flow.actions = ntohl (f->actions);
  flow.mark_flow_id = ntohl (f->mark_flow_id);
  flow.redirect_node_index = ntohl (f->redirect_node_index);
  flow.redirect_device_input_next_index =
    ntohl (f->redirect_device_input_next_index);
  flow.redirect_queue = ntohl (f->redirect_queue);
  flow.buffer_advance = ntohl (f->buffer_advance);

  switch (flow.type)
    {
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
      ipv4_n_tuple_flow_convert (&f->flows.ip4_n_tuple, &flow.ip4_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
      ipv6_n_tuple_flow_convert (&f->flows.ip6_n_tuple, &flow.ip6_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED:
      ipv4_n_tuple_tagged_flow_convert (&f->flows.ip4_n_tuple_tagged,
					&flow.ip4_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED:
      ipv6_n_tuple_tagged_flow_convert (&f->flows.ip6_n_tuple_tagged,
					&flow.ip6_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
      ipv4_l2tpv3oip_flow_convert (&f->flows.ip4_l2tpv3oip,
				   &flow.ip4_l2tpv3oip);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
      ipv4_ipsec_esp_flow_convert (&f->flows.ip4_ipsec_esp,
				   &flow.ip4_ipsec_esp);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
      ipv4_ipsec_ah_flow_convert (&f->flows.ip4_ipsec_ah, &flow.ip4_ipsec_ah);
      break;
    case VNET_FLOW_TYPE_IP4_GTPU:
      ipv4_gtpu_flow_convert (&f->flows.ip4_gtpu, &flow.ip4_gtpu);
      break;
    case VNET_FLOW_TYPE_IP4_GTPC:
      ipv4_gtpc_flow_convert (&f->flows.ip4_gtpc, &flow.ip4_gtpc);
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto out;
      break;

    }

  rv = vnet_flow_add (vnm, &flow, &flow_index);

  goto out;
out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_FLOW_ADD_REPLY,
  ({
    rmp->flow_index = ntohl (flow_index);
  }));
}

static void
vl_api_flow_del_t_handler (vl_api_flow_del_t * mp)
{
  vl_api_flow_add_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main();
  rv = vnet_flow_del(vnm, ntohl(mp->flow_index));

  REPLY_MACRO (VL_API_FLOW_DEL_REPLY);
}

static void
vl_api_flow_enable_t_handler (vl_api_flow_enable_t * mp)
{
  vl_api_flow_add_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main();
  rv = vnet_flow_enable(vnm, ntohl(mp->flow_index), ntohl(mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_ENABLE_REPLY);
}

static void
vl_api_flow_disable_t_handler (vl_api_flow_disable_t * mp)
{
  vl_api_flow_add_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main();
  rv = vnet_flow_disable(vnm, ntohl(mp->flow_index), ntohl(mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_DISABLE_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/flow/flow.api.h>
#undef vl_msg_name_crc_list

/*
 * flow_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */


static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_flow;
#undef _
}

static clib_error_t *
hw_flow_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (hw_flow_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
