#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vxlan/vxlan.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <dpdk/device/dpdk.h>

#include <rte_flow.h>
#include "offload.h"

static dpdk_main_t *
dpdk_get_main_(void)
{
  static dpdk_main_t * (*dpdk_get_main__) (void) = 0;
  if (!dpdk_get_main__)
  {
    dpdk_get_main__ = vlib_get_plugin_symbol ("dpdk_plugin.so", "dpdk_get_main");
    if (!dpdk_get_main__)
      return 0;
  }
  return dpdk_get_main__();
}

static clib_error_t *
dpdk_offload_add_remove_vxlan_flow (dpdk_device_t *xd, u32 sw_if_index, int is_add)
{
  vxlan_main_t *vxm = &vxlan_main;
  dpdk_offload_device_config_t * conf = dpdk_offload_get_device_config (xd);
  if (!conf)
    return clib_error_return (0, "no hardware offload configued");
  if (conf->vxlan_rx.q_range.count == 0)
    return clib_error_return (0, "no vxlan offload queues configured");
  vec_validate_init_empty (conf->vxlan_rx.flows, sw_if_index, 0);
  void *old_flow = conf->vxlan_rx.flows[sw_if_index];

  if (!is_add)
    {
      if (old_flow == 0)
	      return clib_error_return (0, "flow not found");
      void * (* dpdk_flow_destroy)(dpdk_device_t *, void *) = vlib_get_plugin_symbol ("dpdk_plugin.so", "dpdk_flow_destroy");
      if (!dpdk_flow_destroy)
        return clib_error_return (0, "missing dpdk_flow_destroy");
      dpdk_flow_destroy (xd, old_flow);
      conf->vxlan_rx.flows[sw_if_index] = 0;
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
  u32 rx_fib_index = vec_elt (ip4_main.fib_index_by_sw_if_index, xd->vlib_sw_if_index);
  if (t->encap_fib_index != rx_fib_index)
    return clib_error_return (0, "encap_fib_index:%u and rx_fib_index:%u", t->encap_fib_index, rx_fib_index);

  /* *INDENT-OFF* */
  /* Select match items based on pmd type */
  enum rte_flow_item_type vxlan_item_type =
    (xd->pmd == VNET_DPDK_PMD_MLX5) ? RTE_FLOW_ITEM_TYPE_VXLAN : RTE_FLOW_ITEM_TYPE_VOID;
  enum rte_flow_item_type raw_item_type =
    (xd->pmd == VNET_DPDK_PMD_I40E) ? RTE_FLOW_ITEM_TYPE_RAW : RTE_FLOW_ITEM_TYPE_VOID;

  /* Flow items */
#if 1
  //struct rte_flow_item_eth eth_spec = { 0 }, eth_mask = { 0 };
  struct rte_flow_item_eth eth_spec, eth_mask;
  memset(&eth_spec, 0, sizeof eth_spec);
  memset(&eth_mask, 0, sizeof eth_mask);
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

#if 0
  *(vxlan_header_t *)(vxlan_hdr_spec.val+raw_sz) = (vxlan_header_t) { .flags = VXLAN_FLAGS_I, .vni_reserved =clib_host_to_net_u32 (t->vni<<8) };
  *(vxlan_header_t *)(vxlan_hdr_mask.val+raw_sz) = (vxlan_header_t) { .flags = 0xff, .vni_reserved = clib_host_to_net_u32 (((u32)-1)<<8) };
#else
  vxlan_header_t spec_hdr = { .flags = VXLAN_FLAGS_I, .vni_reserved = clib_host_to_net_u32 (t->vni<<8) };
  clib_memcpy (vxlan_hdr_spec.val+raw_sz, &spec_hdr, vxlan_hdr_sz);
  vxlan_header_t mask_hdr = { .flags = 0xff, .vni_reserved = clib_host_to_net_u32 (((u32)-1)<<8) };
  clib_memcpy (vxlan_hdr_mask.val+raw_sz, &mask_hdr, vxlan_hdr_sz);;
#endif

  struct rte_flow_item match[] = {
    { .type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &eth_spec, .mask = &eth_mask },
    { .type = RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip4_spec, .mask = &ip4_mask },
    { .type = RTE_FLOW_ITEM_TYPE_UDP, .spec = &udp_spec, .mask = &udp_mask },
    { .type = vxlan_item_type, .spec = &vxlan_spec, .mask = &vxlan_mask },
    { .type = raw_item_type, .spec = &vxlan_hdr_spec, .mask = &vxlan_hdr_mask },
    { .type = RTE_FLOW_ITEM_TYPE_END }
  };

  /* select action based on number of queues */
  enum rte_flow_action_type rss_act_type = (conf->vxlan_rx.q_range.count > 1) ? RTE_FLOW_ACTION_TYPE_RSS : RTE_FLOW_ACTION_TYPE_VOID,
    queue_act_type = (conf->vxlan_rx.q_range.count == 1) ? RTE_FLOW_ACTION_TYPE_QUEUE : RTE_FLOW_ACTION_TYPE_VOID;

  /* Actions */
  struct rte_eth_rss_conf rss_conf = { .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_VXLAN };
  struct rte_flow_action_rss rss = { .rss_conf = &rss_conf, .num = conf->vxlan_rx.q_range.count };

  int q;
  for (q = 0; q < rss.num; q++)
    rss.queue[q] = conf->vxlan_rx.q_range.first + q;

  struct rte_flow_action_queue queue = { .index = conf->vxlan_rx.q_range.first };
  struct rte_flow_action_mark tid_mark = { .id = sw_if_index };

  struct rte_flow_action actions[] = {
    { .type = rss_act_type, .conf = &rss },
    { .type = queue_act_type, .conf = &queue },
    { .type = RTE_FLOW_ACTION_TYPE_MARK, .conf = &tid_mark },
    { .type = RTE_FLOW_ACTION_TYPE_END }
  };

  /* *INDENT-ON* */
  static const struct rte_flow_attr ingress = { .ingress = 1 };
  struct rte_flow_error flow_err;
  void * (* dpdk_flow_create)(dpdk_device_t * xd,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error) = vlib_get_plugin_symbol ("dpdk_plugin.so", "dpdk_flow_create");
  if (!dpdk_flow_create)
    return clib_error_return (0, "missing dpdk_flow_create");
  void * p = dpdk_flow_create (xd, &ingress, match, actions, &flow_err);
  if (!p)
	  return clib_error_return (0, "dpdk_flow_create failed (type:%d message:%s)", flow_err.type, flow_err.message);
  conf->vxlan_rx.flows[sw_if_index] = p;

  return 0;
}

static void
dpdk_offload_adjust_node_state (vnet_hw_interface_t * hw, dpdk_offload_state_t * state, u32 node_index)
{
  u32 last = state->n_enabled;
  state->n_enabled = clib_bitmap_count_set_bits (state->enabled);
  // enable or disable offload input node
  int enable = last == 0 && state->n_enabled > 0;
  int disable = last > 0 && state->n_enabled == 0;

  if (enable || disable)
  {
    vlib_node_state_t nstate = enable ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;

    int q;
    for (q = 0; q < state->q_range.count; q++)
    {
      int queue_id = state->q_range.first + q;
      int thread_index = hw->rx_queues[queue_id].thread_index;
      vlib_main_t *vm = vlib_mains[thread_index];
      vlib_node_set_state (vm, node_index, nstate);
    }
  }
}

clib_error_t *
dpdk_enable_disable_vxlan_flow (u32 hw_if_index, u32 sw_if_index, int is_enable)
{
  vxlan_main_t *vxm = &vxlan_main;
  dpdk_main_t * dm = dpdk_get_main_();
  if (!dm)
    return clib_error_return (0, "missing dpdk_get_main");
  vnet_hw_interface_t * hw = vnet_get_hw_interface (vxm->vnet_main, hw_if_index);
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  clib_error_t * err =  dpdk_offload_add_remove_vxlan_flow(xd, sw_if_index, is_enable);
  if (err != 0)
    return err;

  dpdk_offload_device_config_t * conf = dpdk_offload_get_device_config (xd);
  if (!conf)
    return clib_error_return (0, "missing conf");

  conf->vxlan_rx.enabled =
    clib_bitmap_set (conf->vxlan_rx.enabled, sw_if_index, is_enable);

  offload_main_t * om = &offload_main;;
  hash_set(om->hw_if_index_by_sw_if_index, sw_if_index,
      is_enable ? hw_if_index : ~0);

  dpdk_offload_adjust_node_state (hw, &conf->vxlan_rx, dpdk_vxlan_offload_input_node.index);

  return 0;
}

static clib_error_t *
dpdk_offload_swif_deleted (struct vnet_main_t * vnm, u32 if_index, u32 is_create)
{
  if (is_create)
    return 0;

  offload_main_t * om = &offload_main;;
  dpdk_main_t * dm = dpdk_get_main_();
  if (!dm)
    return clib_error_return (0, "missing dpdk_get_main");
  //look for flow on all dpdk devices
  uword * hw_if_index = hash_get(om->hw_if_index_by_sw_if_index, if_index);
  if (hw_if_index == 0 || *hw_if_index == ~0)
    return 0;
  return dpdk_enable_disable_vxlan_flow(*hw_if_index, if_index, 0);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(dpdk_offload_swif_deleted);

