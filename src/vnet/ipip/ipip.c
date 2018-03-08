/*
 * ipip.c: ipip
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or aipiped to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/ipip/ipip.h>
#include <vnet/vnet.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/format.h>
#include <vnet/ipip/ipip.h>

ipip_main_t ipip_main;

/* Packet trace structure */
typedef struct {
  u32 tunnel_id;
  u32 length;
  ip46_address_t src;
  ip46_address_t dst;
} ipip_tx_trace_t;

u8 *format_ipip_tx_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  ipip_tx_trace_t *t = va_arg(*args, ipip_tx_trace_t *);

  s = format(s, "IPIP: tunnel %d len %d src %U dst %U", t->tunnel_id, t->length,
             format_ip46_address, &t->src, IP46_TYPE_ANY, format_ip46_address,
             &t->dst, IP46_TYPE_ANY);
  return s;
}

static u8 *ipip_build_rewrite(vnet_main_t *vnm, u32 sw_if_index,
                             vnet_link_t link_type, const void *dst_address) {
  ipip_main_t *gm = &ipip_main;
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  u8 *rewrite = NULL;
  ipip_tunnel_t *t;
  u32 ti;

  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];

  if (ti == ~0)
    /* not one of ours */
    return (0);

  t = pool_elt_at_index(gm->tunnels, ti);

  switch (t->transport) {
  case IPIP_TRANSPORT_IP4:
    vec_validate(rewrite, sizeof(*ip4) - 1);
    ip4 = (ip4_header_t *)rewrite;
    ip4->ip_version_and_header_length = 0x45;
    ip4->ttl = 64;
    /* fixup ip4 header length, protocol and checksum after-the-fact */
    ip4->src_address.as_u32 = t->tunnel_src.ip4.as_u32;
    ip4->dst_address.as_u32 = t->tunnel_dst.ip4.as_u32;
    ip4->checksum = ip4_header_checksum(ip4);
    break;

  case IPIP_TRANSPORT_IP6:
    vec_validate(rewrite, sizeof(*ip6) - 1);
    ip6 = (ip6_header_t *)rewrite;
    ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32(6 << 28);
    ip6->hop_limit = 64;
    /* fixup ip6 header length and protocol after-the-fact */
    ip6->src_address.as_u64[0] = t->tunnel_src.ip6.as_u64[0];
    ip6->src_address.as_u64[1] = t->tunnel_src.ip6.as_u64[1];
    ip6->dst_address.as_u64[0] = t->tunnel_dst.ip6.as_u64[0];
    ip6->dst_address.as_u64[1] = t->tunnel_dst.ip6.as_u64[1];
    break;
  default:
    /* pass through */
    ;
  }
  return (rewrite);
}

static void ipip4_fixup(vlib_main_t *vm, ip_adjacency_t *adj, vlib_buffer_t *b0,
			const void *data) {
  ip4_header_t *ip0;

  ip0 = vlib_buffer_get_current(b0);
  ip0->length = clib_host_to_net_u16(vlib_buffer_length_in_chain(vm, b0));
  ip0->protocol = adj->ia_link == VNET_LINK_IP6 ? IP_PROTOCOL_IPV6 : IP_PROTOCOL_IP_IN_IP;
  ip0->checksum = ip4_header_checksum(ip0);
}

static void ipip6_fixup(vlib_main_t *vm, ip_adjacency_t *adj, vlib_buffer_t *b0,
			const void *data) {
  ip6_header_t *ip0;

  ip0 = vlib_buffer_get_current(b0);

  ip0->payload_length = clib_host_to_net_u16(vlib_buffer_length_in_chain(vm, b0)) - sizeof(*ip0);
  ip0->protocol = adj->ia_link == VNET_LINK_IP6 ? IP_PROTOCOL_IPV6 : IP_PROTOCOL_IP_IN_IP;
}

static void ipip_tunnel_stack(adj_index_t ai) {
  ipip_main_t *gm = &ipip_main;
  ip_adjacency_t *adj;
  ipip_tunnel_t *gt;
  u32 sw_if_index;

  adj = adj_get(ai);
  sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len(gm->tunnel_index_by_sw_if_index) < sw_if_index) ||
      (~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
    return;

  gt = pool_elt_at_index(gm->tunnels,
                         gm->tunnel_index_by_sw_if_index[sw_if_index]);

  if ((vnet_hw_interface_get_flags(vnet_get_main(), gt->hw_if_index) &
       VNET_HW_INTERFACE_FLAG_LINK_UP) == 0) {
    adj_nbr_midchain_unstack(ai);
    return;
  }

  dpo_id_t tmp = DPO_INVALID;
  fib_forward_chain_type_t fib_fwd = (FIB_PROTOCOL_IP6 == adj->ia_nh_proto)
                                         ? FIB_FORW_CHAIN_TYPE_UNICAST_IP6
                                         : FIB_FORW_CHAIN_TYPE_UNICAST_IP4;

  fib_entry_contribute_forwarding(gt->fib_entry_index, fib_fwd, &tmp);
  if (DPO_LOAD_BALANCE == tmp.dpoi_type) {
    /*
     * post IPIP rewrite we will load-balance. However, the IPIP encap
     * is always the same for this adjacency/tunnel and hence the IP/IPIP
     * src,dst hash is always the same result too. So we do that hash now and
     * stack on the choice.
     * If the choice is an incomplete adj then we will need a poke when
     * it becomes complete. This happens since the adj update walk propagates
     * as far a recursive paths.
     */
    const dpo_id_t *choice;
    load_balance_t *lb;
    int hash;

    lb = load_balance_get(tmp.dpoi_index);

    if (fib_fwd == FIB_FORW_CHAIN_TYPE_UNICAST_IP4)
      hash = ip4_compute_flow_hash((ip4_header_t *)adj_get_rewrite(ai),
                                   lb->lb_hash_config);
    else
      hash = ip6_compute_flow_hash((ip6_header_t *)adj_get_rewrite(ai),
                                   lb->lb_hash_config);
    choice = load_balance_get_bucket_i(lb, hash & lb->lb_n_buckets_minus_1);
    dpo_copy(&tmp, choice);
  }

  adj_nbr_midchain_stack(ai, &tmp);
  dpo_reset(&tmp);
}

static adj_walk_rc_t ipip_adj_walk_cb(adj_index_t ai, void *ctx) {
  ipip_tunnel_stack(ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void ipip_tunnel_restack(ipip_tunnel_t *gt) {
  fib_protocol_t proto;

  /*
   * walk all the adjacencies on th IPIP interface and restack them
   */
  FOR_EACH_FIB_IP_PROTOCOL(proto) {
    adj_nbr_walk(gt->sw_if_index, proto, ipip_adj_walk_cb, NULL);
  }
}

void ipip_update_adj(vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai) {
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;
  u32 ti;
  adj_midchain_fixup_t f;

  ti = gm->tunnel_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index(gm->tunnels, ti);
  f = t->transport == IPIP_TRANSPORT_IP6 ? ipip6_fixup : ipip4_fixup;

  adj_nbr_midchain_update_rewrite(ai, f, NULL,
				  (VNET_LINK_ETHERNET == adj_get_link_type(ai) ? ADJ_FLAG_MIDCHAIN_NO_COUNT
				   : ADJ_FLAG_NONE),
				  ipip_build_rewrite(vnm, sw_if_index, adj_get_link_type(ai), NULL));
  ipip_tunnel_stack(ai);
}

static u8 *format_ipip_tunnel_name(u8 *s, va_list *args) {
  u32 dev_instance = va_arg(*args, u32);
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;

  if (dev_instance >= vec_len(gm->tunnels))
    return format(s, "<improperly-referenced>");

  t = pool_elt_at_index(gm->tunnels, dev_instance);
  return format(s, "ipip%d", t->user_instance);
}

static u8 *format_ipip_device(u8 *s, va_list *args) {
  u32 dev_instance = va_arg(*args, u32);
  CLIB_UNUSED(int verbose) = va_arg(*args, int);

  s = format(s, "IPIP tunnel: id %d\n", dev_instance);
  return s;
}

static clib_error_t *ipip_interface_admin_up_down(vnet_main_t *vnm, u32 hw_if_index,
						  u32 flags) {
  ipip_main_t *gm = &ipip_main;
  vnet_hw_interface_t *hi;
  ipip_tunnel_t *t;
  u32 ti;

  hi = vnet_get_hw_interface(vnm, hw_if_index);

  if (NULL == gm->tunnel_index_by_sw_if_index ||
      hi->sw_if_index >= vec_len(gm->tunnel_index_by_sw_if_index))
    return (NULL);

  ti = gm->tunnel_index_by_sw_if_index[hi->sw_if_index];

  if (~0 == ti)
    /* not one of ours */
    return (NULL);

  t = pool_elt_at_index(gm->tunnels, ti);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags(vnm, hw_if_index,
                                VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags(vnm, hw_if_index, 0 /* down */);

  ipip_tunnel_restack(t);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS(ipip_device_class) = {
    .name = "IPIP tunnel device",
    .format_device_name = format_ipip_tunnel_name,
    .format_device = format_ipip_device,
    .format_tx_trace = format_ipip_tx_trace,
    .admin_up_down_function = ipip_interface_admin_up_down,
#ifdef SOON
    .clear counter = 0;
#endif
};

VNET_HW_INTERFACE_CLASS(ipip_hw_interface_class) = {
    .name = "IPIP",
    //.format_header = format_ipip_header_with_length,
    //.unformat_header = unformat_ipip_header,
    .build_rewrite = ipip_build_rewrite,
    .update_adjacency = ipip_update_adj,
    .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

ipip_main_t *ipip_get_main(vlib_main_t *vm) {
  vlib_call_init_function(vm, ipip_init);
  return &ipip_main;
}

static u8 *format_ipip_tunnel(u8 *s, va_list *args) {
  ipip_tunnel_t *t = va_arg(*args, ipip_tunnel_t *);

  ip46_type_t type = (t->transport == IPIP_TRANSPORT_IP4) ? IP46_TYPE_IP4 : IP46_TYPE_IP6;
  s = format(s, "[%d] instance %d src %U dst %U fib-idx %d sw-if-idx %d ",
             t->dev_instance, t->user_instance, format_ip46_address,
             &t->tunnel_src, type, format_ip46_address,
             &t->tunnel_dst, type, t->outer_fib_index,
             t->sw_if_index);

  return s;
}

static ipip_tunnel_t *
ipip_tunnel_db_find(ipip_tunnel_key_t *key) {
  ipip_main_t *gm = &ipip_main;
  uword *p;

  p = hash_get_mem(gm->tunnel_by_key, key);
  if (!p)
    return (NULL);
  return (pool_elt_at_index(gm->tunnels, p[0]));
}

static void ipip_tunnel_db_add(ipip_tunnel_t *t, ipip_tunnel_key_t *key) {
  ipip_main_t *gm = &ipip_main;

  t->key = clib_mem_alloc(sizeof(*t->key));
  clib_memcpy(t->key, key, sizeof(*key));
  hash_set_mem(gm->tunnel_by_key, t->key, t->dev_instance);
}

static void ipip_tunnel_db_remove(ipip_tunnel_t *t) {
  ipip_main_t *gm = &ipip_main;

  hash_unset_mem(gm->tunnel_by_key, t->key);
  clib_mem_free(t->key);
  t->key = NULL;
}

static ipip_tunnel_t *ipip_tunnel_from_fib_node(fib_node_t *node) {
  ipip_main_t *gm = &ipip_main;
  ASSERT(gm->fib_node_type == node->fn_type);
  return ((ipip_tunnel_t *)(((char *)node) - offsetof(ipip_tunnel_t, node)));
}

static fib_node_back_walk_rc_t
ipip_tunnel_back_walk(fib_node_t *node, fib_node_back_walk_ctx_t *ctx) {
  ipip_tunnel_restack(ipip_tunnel_from_fib_node(node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

static fib_node_t *ipip_tunnel_fib_node_get(fib_node_index_t index) {
  ipip_tunnel_t *gt;
  ipip_main_t *gm;

  gm = &ipip_main;
  gt = pool_elt_at_index(gm->tunnels, index);

  return (&gt->node);
}

static void ipip_tunnel_last_lock_gone(fib_node_t *node) {
  /*
   * The MPLS IPIP tunnel is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT(0);
}

/*
 * Virtual function table registered by IPIP tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t ipip_vft = {
    .fnv_get = ipip_tunnel_fib_node_get,
    .fnv_last_lock = ipip_tunnel_last_lock_gone,
    .fnv_back_walk = ipip_tunnel_back_walk,
};

static void ipip_fib_add (ipip_tunnel_t *t)
{
  ipip_main_t *gm = &ipip_main;
  fib_prefix_t dst = { .fp_len = t->transport == IPIP_TRANSPORT_IP6 ? 128 : 32,
		       .fp_proto = t->transport == IPIP_TRANSPORT_IP6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4,
		       .fp_addr = t->tunnel_dst
  };

  t->fib_entry_index = fib_table_entry_special_add(t->outer_fib_index, &dst, FIB_SOURCE_RR, FIB_ENTRY_FLAG_NONE);
  t->sibling_index = fib_entry_child_add(t->fib_entry_index, gm->fib_node_type, t->dev_instance);
}

static void ipip_fib_delete (ipip_tunnel_t *t)
{
  fib_entry_child_remove(t->fib_entry_index, t->sibling_index);
  fib_table_entry_delete_index(t->fib_entry_index, FIB_SOURCE_RR);
  fib_node_deinit(&t->node);
}

static int vnet_ipip_tunnel_add(vnet_ipip_add_del_tunnel_args_t *a,
                                u32 outer_fib_index, u32 *sw_if_indexp) {
  ipip_main_t *gm = &ipip_main;
  vnet_main_t *vnm = gm->vnet_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  ipip_tunnel_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, sw_if_index;
  ipip_tunnel_key_t key = { .type = a->transport == IPIP_TRANSPORT_IP6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
			    .fib_index = a->outer_fib_id,
			    .src = a->src,
			    .dst = a->dst };

  t = ipip_tunnel_db_find(&key);
  if (NULL != t)
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  pool_get_aligned(gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  memset(t, 0, sizeof(*t));

  /* Reconcile the real dev_instance and a possible requested instance */
  u32 t_idx = t - gm->tunnels; /* tunnel index (or instance) */
  u32 u_idx = a->instance;     /* user specified instance */
  if (u_idx == ~0)
    u_idx = t_idx;
  if (hash_get(gm->instance_used, u_idx)) {
    pool_put(gm->tunnels, t);
    return VNET_API_ERROR_INSTANCE_IN_USE;
  }
  hash_set(gm->instance_used, u_idx, 1);

  t->dev_instance = t_idx;  /* actual */
  t->user_instance = u_idx; /* name */
  fib_node_init(&t->node, gm->fib_node_type);

  hw_if_index = vnet_register_interface(vnm, ipip_device_class.index, t_idx,
                                        ipip_hw_interface_class.index, t_idx);

  hi = vnet_get_hw_interface(vnm, hw_if_index);
  sw_if_index = hi->sw_if_index;

  t->hw_if_index = hw_if_index;
  t->outer_fib_index = outer_fib_index;
  t->sw_if_index = sw_if_index;

  t->transport = a->transport;
  vec_validate_init_empty(gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = t_idx;

  if (t->transport == IPIP_TRANSPORT_IP4) {
    vec_validate(im4->fib_index_by_sw_if_index, sw_if_index);
    hi->min_packet_bytes = 64 + sizeof(ip4_header_t);
  } else {
    vec_validate(im6->fib_index_by_sw_if_index, sw_if_index);
    hi->min_packet_bytes = 64 + sizeof(ip6_header_t);
  }

  hi->per_packet_overhead_bytes = /* preamble */ 8 + /* inter frame gap */ 12;

  /* Standard default ipip MTU. */
  // XXX: FIX!!! Should be outgoing interface MTU minus overhead.
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;

  t->tunnel_src = a->src;
  t->tunnel_dst = a->dst;

  ipip_tunnel_db_add(t, &key);

  /*
   * Source the FIB entry for the tunnel's destination and become a
   * child thereof. The tunnel will then get poked when the forwarding
   * for the entry updates, and the tunnel can re-stack accordingly
   */
  ipip_fib_add(t);
  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  // XXX: Split this on v4 and v6?
  if (!gm->protocol_registered) {
    ip4_register_protocol(IP_PROTOCOL_IP_IN_IP, ipip4_input_node.index);
    ip6_register_protocol(IP_PROTOCOL_IP_IN_IP, ipip6_input_node.index);
    ip4_register_protocol(IP_PROTOCOL_IPV6, ipip4_input_node.index);
    ip6_register_protocol(IP_PROTOCOL_IPV6, ipip6_input_node.index);
    gm->protocol_registered = true;
  }

  return 0;
}

static int vnet_ipip_tunnel_delete(vnet_ipip_add_del_tunnel_args_t *a,
                                   u32 outer_fib_index, u32 *sw_if_indexp) {
  ipip_main_t *gm = &ipip_main;
  vnet_main_t *vnm = gm->vnet_main;
  ipip_tunnel_t *t;
  u32 sw_if_index;
  ipip_tunnel_key_t key = { .type = a->transport == IPIP_TRANSPORT_IP6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
			    .fib_index = a->outer_fib_id,
			    .src = a->src,
			    .dst = a->dst };

  t = ipip_tunnel_db_find(&key);
  if (t == NULL)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sw_if_index = t->sw_if_index;
  vnet_sw_interface_set_flags(vnm, sw_if_index, 0 /* down */);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;
  vnet_delete_hw_interface(vnm, t->hw_if_index);
  ipip_fib_delete(t);
  hash_unset(gm->instance_used, t->user_instance);
  ipip_tunnel_db_remove(t);
  pool_put(gm->tunnels, t);
  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

int vnet_ipip_add_del_tunnel(vnet_ipip_add_del_tunnel_args_t *a,
                             u32 *sw_if_indexp) {
  u32 outer_fib_index;

  if (a->transport == IPIP_TRANSPORT_IP4)
    outer_fib_index = ip4_fib_index_from_table_id(a->outer_fib_id);
  else
    outer_fib_index = ip6_fib_index_from_table_id(a->outer_fib_id);

  if (~0 == outer_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (a->is_add)
    return (vnet_ipip_tunnel_add(a, outer_fib_index, sw_if_indexp));
  else
    return (vnet_ipip_tunnel_delete(a, outer_fib_index, sw_if_indexp));
}

static clib_error_t *create_ipip_tunnel_command_fn(vlib_main_t *vm,
                                                   unformat_input_t *input,
                                                   vlib_cli_command_t *cmd) {
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_ipip_add_del_tunnel_args_t _a, *a = &_a;
  ip46_address_t src = {0}, dst = {0};
  u32 instance = ~0;
  u32 outer_fib_id = 0;
  int rv;
  u32 num_m_args = 0;
  u32 sw_if_index;
  clib_error_t *error = NULL;
  bool is_add = true, ipv4_set = false, ipv6_set = false;

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "del"))
      is_add = 0;
    else if (unformat(line_input, "instance %d", &instance))
      ;
    else if (unformat(line_input, "src %U", unformat_ip4_address, &src.ip4)) {
      num_m_args++;
      ipv4_set = true;
    } else if (unformat(line_input, "dst %U", unformat_ip4_address, &dst.ip4)) {
      num_m_args++;
      ipv4_set = true;
    } else if (unformat(line_input, "src %U", unformat_ip6_address, &src.ip6)) {
      num_m_args++;
      ipv6_set = true;
    } else if (unformat(line_input, "dst %U", unformat_ip6_address, &dst.ip6)) {
      num_m_args++;
      ipv6_set = true;
    } else if (unformat(line_input, "outer-fib-id %d", &outer_fib_id))
      ;
    else {
      error = clib_error_return(0, "unknown input `%U'", format_unformat_error,
                                line_input);
      goto done;
    }
  }

  if (num_m_args < 2) {
    error = clib_error_return(0, "mandatory argument(s) missing");
    goto done;
  }

  if ((ipv4_set && memcmp(&src.ip4, &dst.ip4, sizeof(src.ip4)) == 0) ||
      (ipv6_set && memcmp(&src.ip6, &dst.ip6, sizeof(src.ip6)) == 0)) {
    error = clib_error_return(0, "src and dst are identical");
    goto done;
  }

  if (ipv4_set && ipv6_set)
    return clib_error_return(0, "both IPv4 and IPv6 addresses specified");

  if ((ipv4_set && memcmp(&dst.ip4, &zero_addr.ip4, sizeof(dst.ip4)) == 0) ||
      (ipv6_set && memcmp(&dst.ip6, &zero_addr.ip6, sizeof(dst.ip6)) == 0)) {
    error = clib_error_return(0, "dst address cannot be zero");
    goto done;
  }

  memset(a, 0, sizeof(*a));
  a->is_add = is_add;
  a->outer_fib_id = outer_fib_id;
  a->transport = ipv6_set ? IPIP_TRANSPORT_IP6 : IPIP_TRANSPORT_IP4;
  a->instance = instance;
  a->src = src;
  a->dst = dst;

  rv = vnet_ipip_add_del_tunnel(a, &sw_if_index);

  switch (rv) {
  case 0:
    vlib_cli_output(vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main(),
                    sw_if_index);
    break;
  case VNET_API_ERROR_IF_ALREADY_EXISTS:
    error = clib_error_return(0, "IPIP tunnel already exists...");
    goto done;
  case VNET_API_ERROR_NO_SUCH_FIB:
    error =
        clib_error_return(0, "outer fib ID %d doesn't exist\n", outer_fib_id);
    goto done;
  case VNET_API_ERROR_NO_SUCH_ENTRY:
    error = clib_error_return(0, "IPIP tunnel doesn't exist");
    goto done;
  case VNET_API_ERROR_INSTANCE_IN_USE:
    error = clib_error_return(0, "Instance is in use");
    goto done;
  default:
    error = clib_error_return(0, "vnet_ipip_add_del_tunnel returned %d", rv);
    goto done;
  }

done:
  unformat_free(line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(create_ipip_tunnel_command, static) = {
    .path = "create ipip tunnel",
    .short_help = "create ipip tunnel src <addr> dst <addr> [instance <n>] "
                  "[outer-fib-id <fib>] [del]",
    .function = create_ipip_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *show_ipip_tunnel_command_fn(vlib_main_t *vm,
                                                 unformat_input_t *input,
                                                 vlib_cli_command_t *cmd) {
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;
  u32 ti = ~0;

  if (pool_elts(gm->tunnels) == 0)
    vlib_cli_output(vm, "No IPIP tunnels configured...");

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "%d", &ti))
      ;
    else
      break;
  }

  if (ti == ~0) {
    /* *INDENT-OFF* */
    pool_foreach(t, gm->tunnels, ({ vlib_cli_output(vm, "%U", format_ipip_tunnel, t); }));
    /* *INDENT-ON* */
  } else {
    t = pool_elt_at_index(gm->tunnels, ti);
    if (t)
      vlib_cli_output(vm, "%U", format_ipip_tunnel, t);
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_ipip_tunnel_command, static) = {
    .path = "show ipip tunnel",
    .function = show_ipip_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *ipip_init(vlib_main_t *vm) {
  ipip_main_t *gm = &ipip_main;

  memset(gm, 0, sizeof(gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main();
  gm->tunnel_by_key = hash_create_mem(0, sizeof(ipip_tunnel_key_t), sizeof(uword));
  gm->fib_node_type = fib_node_register_new_type(&ipip_vft);

  return 0;
}

VLIB_INIT_FUNCTION(ipip_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
