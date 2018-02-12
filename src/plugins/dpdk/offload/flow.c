#include <vnet/vnet.h>
#include <vnet/vxlan/vxlan.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <dpdk/device/dpdk.h>

#include <rte_flow.h>

static clib_error_t *
dpdk_add_remove_vxlan_flow (u32 hw_if_index, u32 sw_if_index, int is_add)
{
  vxlan_main_t *vxm = &vxlan_main;
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vxm->vnet_main, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  //if (xd->vxlan_rx.queues.count == 0)
   // return clib_error_return (0, "no vxlan offload queues configured");

  vec_validate_init_empty (xd->vxlan_rx.flows, sw_if_index, 0);
  void *old_flow = xd->vxlan_rx.flows[sw_if_index];

  if (!is_add)
    {
      if (old_flow == 0)
	      return clib_error_return (0, "flow not found");
      xd->vxlan_rx.flows[sw_if_index] = 0;
      rte_flow_destroy (xd->device_index, old_flow, 0);
      clib_warning ("flow deleted");
      return 0;
    }

  if (is_add && old_flow != 0)
    return clib_error_return (0, "flow exists");

  //tunnel exists?
  u32 idx = (sw_if_index > vec_len (vxm->tunnel_index_by_sw_if_index)) ?
	  ~0 : vxm->tunnel_index_by_sw_if_index[sw_if_index];
  if (idx == ~0)
    return clib_error_return (0, "sw_if_index:%d is not a vxlan tunnel", sw_if_index);

  vxlan_tunnel_t *t = &vxm->tunnels[idx];

  //same fib index?
  u32 rx_fib_index = vec_elt (ip4_main.fib_index_by_sw_if_index, hw->sw_if_index);
  if (t->encap_fib_index != rx_fib_index)
    return clib_error_return (0, "encap_fib_index:%u and rx_fib_index:%u", t->encap_fib_index, rx_fib_index);

  /* *INDENT-OFF* */
#if 1
  struct rte_flow_item_eth eth_spec = { 0 }, eth_mask = { 0 };
#else
  struct rte_flow_item_eth eth_spec = { 0 },
                           eth_mask = { .dst.addr_bytes = { [0 ... 5] = 0xff } };

  clib_memcpy (eth_spec.dst.addr_bytes, hw->hw_address, sizeof eth_spec.dst.addr_bytes);
#endif

  struct rte_flow_item_ipv4
    ip4_spec = { .hdr.dst_addr = t->src.ip4.as_u32, .hdr.src_addr = t->dst.ip4.as_u32 },
    ip4_mask = { .hdr.dst_addr = -1, .hdr.src_addr = -1 };

  struct rte_flow_item_udp
    udp_spec = { .hdr.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan) },
    udp_mask = { .hdr.dst_port = -1 };

  struct rte_flow_item_vxlan
    vxlan_spec = { .vni = { [0] = (t->vni >> 16) & 0xff, [1] = (t->vni >> 8) & 0xff, [2] = t->vni & 0xff, } },
    vxlan_mask = { .vni = { [0 ... 2] = 0xff } };

  enum { vxlan_hdr_sz = sizeof (vxlan_header_t), raw_sz = sizeof (struct rte_flow_item_raw) };
  union {
    struct rte_flow_item_raw flow;
    u8 val[raw_sz + vxlan_hdr_sz];
  } vxlan_hdr_spec = { .flow = { .relative = 1, .length = sizeof (vxlan_header_t),} },
    vxlan_hdr_mask = { .val = { 0 } }; //[raw_sz - 1 ... raw_sz + vxlan_hdr_sz - 1] = 0xff } };

  *(vxlan_header_t *)(vxlan_hdr_spec.val+raw_sz) = (vxlan_header_t) { .flags = VXLAN_FLAGS_I, .vni_reserved =clib_host_to_net_u32 (t->vni<<8) };
  *(vxlan_header_t *)(vxlan_hdr_mask.val+raw_sz) = (vxlan_header_t) { .flags = 0xff, .vni_reserved = clib_host_to_net_u32 (((u32)-1)<<8) };

  enum rte_flow_item_type vxlan_item_type =
    (xd->pmd == VNET_DPDK_PMD_MLX5) ? RTE_FLOW_ITEM_TYPE_VXLAN : RTE_FLOW_ITEM_TYPE_VOID;
  enum rte_flow_item_type raw_item_type =
    (xd->pmd == VNET_DPDK_PMD_I40E) ? RTE_FLOW_ITEM_TYPE_RAW : RTE_FLOW_ITEM_TYPE_VOID;

  struct rte_flow_item match[] = {
    { .type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &eth_spec, .mask = &eth_mask },
    { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip4_spec, .mask = &ip4_mask },
    { .type = RTE_FLOW_ITEM_TYPE_UDP, .spec = &udp_spec, .mask = &udp_mask },
    { .type = vxlan_item_type, .spec = &vxlan_spec, .mask = &vxlan_mask },
    { .type = raw_item_type, .spec = &vxlan_hdr_spec, .mask = &vxlan_hdr_mask },
    { .type = RTE_FLOW_ITEM_TYPE_END }
  };

  /* Actions */
  struct rte_eth_rss_conf rss_conf = { .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_VXLAN };
  struct rte_flow_action_rss rss = { .rss_conf = &rss_conf, .num = xd->vxlan_rx.queues.count };

  int q;
  for (q = 0; q < rss.num; q++)
    rss.queue[q] = xd->vxlan_rx.queues.first + q;

  struct rte_flow_action_queue queue = { .index = xd->vxlan_rx.queues.first };
  struct rte_flow_action_mark tid_mark = { .id = sw_if_index };

  //select action based on number of queues
  enum rte_flow_action_type rss_act_type = (xd->vxlan_rx.queues.count > 1) ? RTE_FLOW_ACTION_TYPE_RSS : RTE_FLOW_ACTION_TYPE_VOID,
    queue_act_type = (xd->vxlan_rx.queues.count == 1) ? RTE_FLOW_ACTION_TYPE_QUEUE : RTE_FLOW_ACTION_TYPE_VOID,
    passthru_act_type = (xd->vxlan_rx.queues.count == 0) ? RTE_FLOW_ACTION_TYPE_PASSTHRU : RTE_FLOW_ACTION_TYPE_VOID;

  struct rte_flow_action actions[] = {
    { .type = rss_act_type, .conf = &rss },
    { .type = queue_act_type, .conf = &queue },
    { .type = passthru_act_type },
    { .type = RTE_FLOW_ACTION_TYPE_MARK, .conf = &tid_mark },
    { .type = RTE_FLOW_ACTION_TYPE_END }
  };

  /* *INDENT-ON* */
  static const struct rte_flow_attr ingress = { .ingress = 1 };
  struct rte_flow_error flow_err;
  void * p = rte_flow_create (xd->device_index, &ingress, match, actions, &flow_err);
  if (!p)
	  return clib_error_return (0, "rte_flow_create failed (type:%d message:%s)", flow_err.type, flow_err.message);
  xd->vxlan_rx.flows[sw_if_index] = p;

  return 0;
}

clib_error_t *
dpdk_enable_disable_vxlan_flow (u32 hw_if_index, u32 sw_if_index, int is_add)
{
  clib_error_t * err =  dpdk_add_remove_vxlan_flow(hw_if_index, sw_if_index, is_add);
  if (err != 0)
    return err;

  vxlan_main_t *vxm = &vxlan_main;
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vxm->vnet_main, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  xd->vxlan_rx.enabled =
    clib_bitmap_set (xd->vxlan_rx.enabled, sw_if_index, is_add);

  u32 last = xd->vxlan_rx.count;
  xd->vxlan_rx.count = clib_bitmap_count_set_bits (xd->vxlan_rx.enabled);
  int enable = last == 0 && xd->vxlan_rx.count == 1;
  int disable = last > 0 && xd->vxlan_rx.count == 0;

  if (enable || disable)
  {
    vlib_node_state_t state = enable ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;

    int q;
    for (q = 0; q < xd->vxlan_rx.queues.count; q++)
    {
      int queue_id = xd->vxlan_rx.queues.first + q;
      int thread_index = hw->input_node_thread_index_by_queue[queue_id];
      vlib_main_t *vm = vlib_mains[thread_index];
      vlib_node_set_state (vm, dpdk_vxlan_offload_input_node.index, state);
    }
  }

  return 0;
}

static clib_error_t *
offload_swif_flow_disable_deleted (struct vnet_main_t * vnm, u32 if_index, u32 is_create)
{
  if (is_create)
    return 0;
  clib_warning("XXX deleted");

  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  vec_foreach (xd, dm->devices)
    {
      int enabled = clib_bitmap_get(xd->vxlan_rx.enabled, if_index);
      if (enabled == 0)
        continue;
      clib_error_t * err = dpdk_enable_disable_vxlan_flow(xd->hw_if_index, if_index, 0);
      if (err != 0)
        return err;
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(offload_swif_flow_disable_deleted);

