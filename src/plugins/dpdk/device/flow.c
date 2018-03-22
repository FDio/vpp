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

#include <rte_flow.h>

typedef struct
{
  uword *flows_by_id;
} dpdk_device_flows_t;

typedef struct
{
  dpdk_device_flows_t *flows_by_hw_if_index;
} dpdk_flows_main_t;

dpdk_flows_main_t dpdk_flows_main;

uword
dpdk_create_vxlan_flow (dpdk_device_t * xd, vnet_device_flow_t * f, u32 mark)
{
  ASSERT (f->type += VNET_DEVICE_FLOW_TYPE_IP4_VXLAN);

    /* *INDENT-OFF* */
  /* Select match items based on pmd type */
  enum rte_flow_item_type vxlan_item_type =
    (xd->pmd == VNET_DPDK_PMD_MLX5) ? RTE_FLOW_ITEM_TYPE_VXLAN : RTE_FLOW_ITEM_TYPE_VOID;
  enum rte_flow_item_type raw_item_type =
    (xd->pmd == VNET_DPDK_PMD_I40E) ? RTE_FLOW_ITEM_TYPE_RAW : RTE_FLOW_ITEM_TYPE_VOID;

  /* Flow match items */
  struct rte_flow_item_eth eth_spec, eth_mask;
  memset(&eth_spec, 0, sizeof eth_spec);
  memset(&eth_mask, 0, sizeof eth_mask);

  struct rte_flow_item_ipv4
    ip4_spec = { .hdr.dst_addr = f->ip4_vxlan.src_addr.as_u32, .hdr.src_addr = f->ip4_vxlan.dst_addr.as_u32 },
    ip4_mask = { .hdr.dst_addr = -1, .hdr.src_addr = -1 };

  struct rte_flow_item_udp
    udp_spec = { .hdr.dst_port = clib_host_to_net_u16 (f->ip4_vxlan.dst_port) },
    udp_mask = { .hdr.dst_port = -1 };

  u32 vni = f->ip4_vxlan.vni;
  struct rte_flow_item_vxlan
    vxlan_spec = { .vni = { [0] = (vni >> 16) & 0xff, [1] = (vni >> 8) & 0xff, [2] = vni & 0xff, } },
    vxlan_mask = { .vni = { [0 ... 2] = 0xff } };

  enum { vxlan_hdr_sz = sizeof (vxlan_header_t), raw_sz = sizeof (struct rte_flow_item_raw) };
  union {
    struct rte_flow_item_raw flow;
    u8 val[raw_sz + vxlan_hdr_sz];
  } vxlan_hdr_spec = { .flow = { .relative = 1, .length = vxlan_hdr_sz,} },
    vxlan_hdr_mask = { .val = { 0 } }; //[raw_sz - 1 ... raw_sz + vxlan_hdr_sz - 1] = 0xff } };

  vxlan_header_t spec_hdr = { .flags = VXLAN_FLAGS_I, .vni_reserved = clib_host_to_net_u32 (vni<<8) };
  clib_memcpy (vxlan_hdr_spec.val+raw_sz, &spec_hdr, vxlan_hdr_sz);
  vxlan_header_t mask_hdr = { .flags = 0xff, .vni_reserved = clib_host_to_net_u32 (((u32)-1)<<8) };
  clib_memcpy (vxlan_hdr_mask.val+raw_sz, &mask_hdr, vxlan_hdr_sz);;

  struct rte_flow_item match[] = {
    { .type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &eth_spec, .mask = &eth_mask },
    { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip4_spec, .mask = &ip4_mask },
    { .type = RTE_FLOW_ITEM_TYPE_UDP, .spec = &udp_spec, .mask = &udp_mask },
    { .type = vxlan_item_type, .spec = &vxlan_spec, .mask = &vxlan_mask },
    { .type = raw_item_type, .spec = &vxlan_hdr_spec, .mask = &vxlan_hdr_mask },
    { .type = RTE_FLOW_ITEM_TYPE_END }
  };

//XXX todo limit mark number of bits
  struct rte_flow_action_mark id_mark = { .id = mark };

  struct rte_flow_action actions[] = {
    { .type = RTE_FLOW_ACTION_TYPE_PASSTHRU },
    { .type = RTE_FLOW_ACTION_TYPE_MARK, .conf = &id_mark },
    { .type = RTE_FLOW_ACTION_TYPE_END }
  };

  /* *INDENT-ON* */
  static const struct rte_flow_attr ingress = {.ingress = 1 };
  struct rte_flow_error flow_err;
  void *p =
    rte_flow_create (xd->device_index, &ingress, match, actions, &flow_err);
  if (!p)
    clib_warning ("dpdk_flow_create failed (type:%d message:%s)",
		  flow_err.type, flow_err.message);
  return pointer_to_uword (p);
}

void
dpdk_device_flow_cb (vnet_device_flow_action_t action,
		     vnet_device_flow_t * flow,
		     u32 hw_if_index, u32 flow_index)
{
  if (flow->type != VNET_DEVICE_FLOW_TYPE_IP4_VXLAN)
    return;

  dpdk_main_t *dm = &dpdk_main;
  vxlan_main_t *vxm = &vxlan_main;
  vnet_hw_interface_t *hw_if =
    vnet_get_hw_interface (vxm->vnet_main, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hw_if->dev_instance);
  xd->flags |= DPDK_DEVICE_FLAG_FLOW;

  dpdk_flows_main_t *dfm = &dpdk_flows_main;

  vec_validate (dfm->flows_by_hw_if_index, hw_if_index);
  dpdk_device_flows_t *df = &dfm->flows_by_hw_if_index[hw_if_index];
  if (action == VNET_DEVICE_FLOW_DEL)
    {
      uword *old_flow = hash_get (df->flows_by_id, flow->id);
      if (old_flow == 0)
	return;			//clib_error_return (0, "flow not found");
      ASSERT (*old_flow != 0);

      struct rte_flow_error flow_err;
      clib_warning ("hw_if_index %d destroy flow %p", hw_if_index,
		    uword_to_pointer (*old_flow, void *));
      if (rte_flow_destroy
	  (xd->device_index, uword_to_pointer (*old_flow, void *),
	   &flow_err) != 0)
	  clib_warning ("rte_flow_destroy failed (type:%d message:%s)",
			flow_err.type, flow_err.message);
      hash_unset (df->flows_by_id, flow->id);
    }

  if (action != VNET_DEVICE_FLOW_ADD)
    return;

  uword new_flow = dpdk_create_vxlan_flow (xd, flow, flow_index);
  clib_warning ("hw_if_index %d created flow %p", hw_if_index,
		uword_to_pointer (new_flow, void *));
  if (new_flow == 0)
    return;			//clib_error_return (0, "flow not created");
  hash_set (df->flows_by_id, flow->id, new_flow);	//pointer_to_uword(new_flow));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
