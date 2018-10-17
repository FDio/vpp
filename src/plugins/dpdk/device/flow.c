/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vlib/unix/cj.h>
#include <assert.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/vxlan/vxlan.h>
#include <dpdk/device/dpdk.h>

#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

/* constant structs */
static const struct rte_flow_attr ingress = {.ingress = 1 };
static const struct rte_flow_item_eth any_eth[2] = { };
static const struct rte_flow_item_vlan any_vlan[2] = { };

static int
dpdk_flow_add (dpdk_device_t * xd, vnet_flow_t * f, dpdk_flow_entry_t * fe)
{
  struct rte_flow_item_ipv4 ip4[2] = { };
  struct rte_flow_item_ipv6 ip6[2] = { };
  struct rte_flow_item_udp udp[2] = { };
  struct rte_flow_item_tcp tcp[2] = { };
  struct rte_flow_action_mark mark = { 0 };
  struct rte_flow_item *item, *items = 0;
  struct rte_flow_action *action, *actions = 0;

  enum
  {
    vxlan_hdr_sz = sizeof (vxlan_header_t),
    raw_sz = sizeof (struct rte_flow_item_raw)
  };

  union
  {
    struct rte_flow_item_raw item;
    u8 val[raw_sz + vxlan_hdr_sz];
  } raw[2];

  u16 src_port, dst_port, src_port_mask, dst_port_mask;
  u8 protocol;
  int rv = 0;

  if (f->actions & (~xd->supported_flow_actions))
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Match items */
  /* Ethernet */
  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_ETH;
  item->spec = any_eth;
  item->mask = any_eth + 1;

  /* VLAN */
  if (f->type != VNET_FLOW_TYPE_IP4_VXLAN)
    {
      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_VLAN;
      item->spec = any_vlan;
      item->mask = any_vlan + 1;
    }

  /* IP */
  vec_add2 (items, item, 1);
  if (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE)
    {
      vnet_flow_ip6_n_tuple_t *t6 = &f->ip6_n_tuple;
      clib_memcpy (ip6[0].hdr.src_addr, &t6->src_addr.addr, 16);
      clib_memcpy (ip6[1].hdr.src_addr, &t6->src_addr.mask, 16);
      clib_memcpy (ip6[0].hdr.dst_addr, &t6->dst_addr.addr, 16);
      clib_memcpy (ip6[1].hdr.dst_addr, &t6->dst_addr.mask, 16);
      item->type = RTE_FLOW_ITEM_TYPE_IPV6;
      item->spec = ip6;
      item->mask = ip6 + 1;

      src_port = t6->src_port.port;
      dst_port = t6->dst_port.port;
      src_port_mask = t6->src_port.mask;
      dst_port_mask = t6->dst_port.mask;
      protocol = t6->protocol;
    }
  else if (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE)
    {
      vnet_flow_ip4_n_tuple_t *t4 = &f->ip4_n_tuple;
      ip4[0].hdr.src_addr = t4->src_addr.addr.as_u32;
      ip4[1].hdr.src_addr = t4->src_addr.mask.as_u32;
      ip4[0].hdr.dst_addr = t4->dst_addr.addr.as_u32;
      ip4[1].hdr.dst_addr = t4->dst_addr.mask.as_u32;
      item->type = RTE_FLOW_ITEM_TYPE_IPV4;
      item->spec = ip4;
      item->mask = ip4 + 1;

      src_port = t4->src_port.port;
      dst_port = t4->dst_port.port;
      src_port_mask = t4->src_port.mask;
      dst_port_mask = t4->dst_port.mask;
      protocol = t4->protocol;
    }
  else if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
    {
      vnet_flow_ip4_vxlan_t *v4 = &f->ip4_vxlan;
      ip4[0].hdr.src_addr = v4->src_addr.as_u32;
      ip4[1].hdr.src_addr = -1;
      ip4[0].hdr.dst_addr = v4->dst_addr.as_u32;
      ip4[1].hdr.dst_addr = -1;
      item->type = RTE_FLOW_ITEM_TYPE_IPV4;
      item->spec = ip4;
      item->mask = ip4 + 1;

      dst_port = v4->dst_port;
      dst_port_mask = -1;
      src_port = 0;
      src_port_mask = 0;
      protocol = IP_PROTOCOL_UDP;
    }
  else
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* Layer 4 */
  vec_add2 (items, item, 1);
  if (protocol == IP_PROTOCOL_UDP)
    {
      udp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
      udp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
      udp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
      udp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);
      item->type = RTE_FLOW_ITEM_TYPE_UDP;
      item->spec = udp;
      item->mask = udp + 1;
    }
  else if (protocol == IP_PROTOCOL_TCP)
    {
      tcp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
      tcp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
      tcp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
      tcp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);
      item->type = RTE_FLOW_ITEM_TYPE_TCP;
      item->spec = tcp;
      item->mask = tcp + 1;
    }
  else
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* Tunnel header match */
  if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
    {
      u32 vni = f->ip4_vxlan.vni;
      vxlan_header_t spec_hdr = {
	.flags = VXLAN_FLAGS_I,
	.vni_reserved = clib_host_to_net_u32 (vni << 8)
      };
      vxlan_header_t mask_hdr = {
	.flags = 0xff,
	.vni_reserved = clib_host_to_net_u32 (((u32) - 1) << 8)
      };

      clib_memset (raw, 0, sizeof raw);
      raw[0].item.relative = 1;
      raw[0].item.length = vxlan_hdr_sz;

      clib_memcpy (raw[0].val + raw_sz, &spec_hdr, vxlan_hdr_sz);
      raw[0].item.pattern = raw[0].val + raw_sz;
      clib_memcpy (raw[1].val + raw_sz, &mask_hdr, vxlan_hdr_sz);
      raw[1].item.pattern = raw[1].val + raw_sz;

      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_RAW;
      item->spec = raw;
      item->mask = raw + 1;
    }

  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_END;

  /* Actions */
  vec_add2 (actions, action, 1);
  action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;

  vec_add2 (actions, action, 1);
  mark.id = fe->mark;
  action->type = RTE_FLOW_ACTION_TYPE_MARK;
  action->conf = &mark;

  vec_add2 (actions, action, 1);
  action->type = RTE_FLOW_ACTION_TYPE_END;

  fe->handle = rte_flow_create (xd->device_index, &ingress, items, actions,
				&xd->last_flow_error);

  if (!fe->handle)
    rv = VNET_FLOW_ERROR_NOT_SUPPORTED;

done:
  vec_free (items);
  vec_free (actions);
  return rv;
}

int
dpdk_flow_ops_fn (vnet_main_t * vnm, vnet_flow_dev_op_t op, u32 dev_instance,
		  u32 flow_index, uword * private_data)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle = 0;
  int rv;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 &&
      xd->parked_loop_count != dm->vlib_main->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->flow_lookup_entries);
    }

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      ASSERT (*private_data >= vec_len (xd->flow_entries));

      fe = vec_elt_at_index (xd->flow_entries, *private_data);

      if ((rv = rte_flow_destroy (xd->device_index, fe->handle,
				  &xd->last_flow_error)))
	return VNET_FLOW_ERROR_INTERNAL;

      if (fe->mark)
	{
	  /* make sure no action is taken for in-flight (marked) packets */
	  fle = pool_elt_at_index (xd->flow_lookup_entries, fe->mark);
	  clib_memset (fle, -1, sizeof (*fle));
	  vec_add1 (xd->parked_lookup_indexes, fe->mark);
	  xd->parked_loop_count = dm->vlib_main->main_loop_count;
	}

      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);

      goto disable_rx_offload;
    }

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  pool_get (xd->flow_entries, fe);
  fe->flow_index = flow->index;

  if (flow->actions == 0)
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* if we need to mark packets, assign one mark */
  if (flow->actions & (VNET_FLOW_ACTION_MARK |
		       VNET_FLOW_ACTION_REDIRECT_TO_NODE |
		       VNET_FLOW_ACTION_BUFFER_ADVANCE))
    {
      /* reserve slot 0 */
      if (xd->flow_lookup_entries == 0)
	pool_get_aligned (xd->flow_lookup_entries, fle,
			  CLIB_CACHE_LINE_BYTES);
      pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
      fe->mark = fle - xd->flow_lookup_entries;

      /* install entry in the lookup table */
      clib_memset (fle, -1, sizeof (*fle));
      if (flow->actions & VNET_FLOW_ACTION_MARK)
	fle->flow_id = flow->mark_flow_id;
      if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	fle->next_index = flow->redirect_device_input_next_index;
      if (flow->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
	fle->buffer_advance = flow->buffer_advance;
    }
  else
    fe->mark = 0;

  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) == 0)
    {
      xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  switch (flow->type)
    {
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_VXLAN:
      if ((rv = dpdk_flow_add (xd, flow, fe)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  *private_data = fe - xd->flow_entries;

done:
  if (rv)
    {
      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
      if (fle)
	{
	  clib_memset (fle, -1, sizeof (*fle));
	  pool_put (xd->flow_lookup_entries, fle);
	}
    }
disable_rx_offload:
  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) != 0
      && pool_elts (xd->flow_entries) == 0)
    {
      xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  return rv;
}

u8 *
format_dpdk_flow (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 flow_index = va_arg (*args, u32);
  uword private_data = va_arg (*args, uword);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;

  if (flow_index == ~0)
    {
      s = format (s, "%-25s: %U\n", "supported flow actions",
		  format_flow_actions, xd->supported_flow_actions);
      s = format (s, "%-25s: %d\n", "last DPDK error type",
		  xd->last_flow_error.type);
      s = format (s, "%-25s: %s\n", "last DPDK error message",
		  xd->last_flow_error.message ? xd->last_flow_error.message :
		  "n/a");
      return s;
    }

  if (private_data >= vec_len (xd->flow_entries))
    return format (s, "unknown flow");

  fe = vec_elt_at_index (xd->flow_entries, private_data);
  s = format (s, "mark %u", fe->mark);
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
