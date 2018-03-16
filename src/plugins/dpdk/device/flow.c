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
#include <dpdk/device/dpdk.h>

#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

/* constant structs */
static const struct rte_flow_attr ingress = {.ingress = 1 };
static const struct rte_flow_item_eth any_eth[2] = { 0 };
static const struct rte_flow_item_vlan any_vlan[2] = { 0 };

static int
dpdk_flow_add_n_touple (dpdk_device_t * xd, vnet_flow_t * f,
			dpdk_flow_entry_t * fe)
{
  struct rte_flow_item_ipv4 ip4[2] = { 0 };
  struct rte_flow_item_ipv6 ip6[2] = { 0 };
  struct rte_flow_item_udp udp[2] = { 0 };
  struct rte_flow_item_tcp tcp[2] = { 0 };
  struct rte_flow_action_mark mark = { 0 };
  struct rte_flow_item *item, *items = 0;
  struct rte_flow_action *action, *actions = 0;
  u16 src_port, dst_port, src_port_mask, dst_port_mask;
  u8 protocol;
  int rv = 0;

  if (f->actions & (~xd->supported_flow_actions))
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Ethernet */
  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_ETH;
  item->spec = any_eth;
  item->mask = any_eth + 1;

  /* VLAN */
  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_VLAN;
  item->spec = any_vlan;
  item->mask = any_vlan + 1;

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
  else
    {
      vnet_flow_ip4_n_tuple_t *t4 = &f->ip4_n_tuple;
      ASSERT (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE);
      ip4[0].hdr.src_addr = t4->src_addr.mask.as_u32;
      ip4[1].hdr.src_addr = t4->src_addr.mask.as_u32;
      ip4[0].hdr.dst_addr = t4->dst_addr.addr.as_u32;
      ip4[1].hdr.dst_addr = t4->dst_addr.mask.as_u32;
      item->type = RTE_FLOW_ITEM_TYPE_IPV4;
      item->spec = ip4;
      item->mask = ip4 + 1;

      src_port = t4->src_port.port;
      dst_port = t4->dst_port.mask;
      src_port_mask = t4->src_port.mask;
      dst_port_mask = t4->dst_port.mask;
      protocol = t4->protocol;
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

  /* The End */
  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_END;

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

static dpdk_flow_entry_t *
dpdk_get_flow_entry_by_flow_id (dpdk_device_t * xd, u32 flow_id)
{
  uword *p = hash_get (xd->flow_mark_by_flow_id, flow_id);
  if (p)
    return pool_elt_at_index (xd->flow_entries, p[0] - 1);
  return 0;
}

int
dpdk_flow_ops_fn (vnet_flow_dev_op_t op, u32 dev_instance, void *data)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_flow_t *flow = (vnet_flow_t *) data;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle;
  int rv;

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fe = dpdk_get_flow_entry_by_flow_id (xd, flow->id);

      if (fe == 0)
	return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

      if ((rv = rte_flow_destroy (xd->device_index, fe->handle,
				  &xd->last_flow_error)))
	return VNET_FLOW_ERROR_INTERNAL;

      hash_unset (xd->flow_mark_by_flow_id, flow->id);
      memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
      return 0;
    }

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  pool_get (xd->flow_entries, fe);
  fe->mark = fe - xd->flow_entries + 1;
  fe->flow_id = flow->id;

  if (flow->actions == 0)
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  switch (flow->type)
    {
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
      if ((rv = dpdk_flow_add_n_touple (xd, flow, fe)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }


  hash_set (xd->flow_mark_by_flow_id, flow->id, fe->mark);

  /* install entry in the lookup table */
  vec_validate_aligned (xd->flow_lookup_entries, fe->mark,
			CLIB_CACHE_LINE_BYTES);
  fle = vec_elt_at_index (xd->flow_lookup_entries, fe->mark);
  fle->flow_id = flow->id;

done:
  if (rv)
    {
      memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
    }
  return rv;
}

u8 *
format_dpdk_flow (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 flow_id = va_arg (*args, u32);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe = dpdk_get_flow_entry_by_flow_id (xd, flow_id);

  if (flow_id == 0)
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

  if (!fe)
    return format (s, "unknown flow");

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
