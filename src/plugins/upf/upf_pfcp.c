/*
 * Copyright (c) 2017 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <rte_config.h>
#include <rte_common.h>
#include <rte_acl.h>

#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <inttypes.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/pool.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <search.h>
#include <netinet/ip.h>

#include "pfcp.h"
#include "upf.h"
#include "upf_pfcp.h"
#include "upf_pfcp_api.h"

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

upf_main_t upf_main;

#define SESS_CREATE 0
#define SESS_MODIFY 1
#define SESS_DEL 2

#define OFF_ETHHEAD     (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m)     \
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m)     \
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV62PROTO)

static void sx_add_del_vrf_ip(const void *vrf_ip, void *si, int is_add);
static void sx_add_del_v4_teid(const void *teid, void *si, int is_add);
static void sx_add_del_v6_teid(const void *teid, void *si, int is_add);
static void sx_acl_free(upf_acl_ctx_t *ctx);

/* DPDK ACL defines */

enum {
  PROTO_FIELD_IPV4,
  SRC_FIELD_IPV4,
  DST_FIELD_IPV4,
  SRCP_FIELD_IPV4,
  DSTP_FIELD_IPV4,
  GTP_TEID_IPV4
};

enum {
  RTE_ACL_IPV4VLAN_PROTO,
  RTE_ACL_IPV4VLAN_VLAN,
  RTE_ACL_IPV4VLAN_SRC,
  RTE_ACL_IPV4VLAN_DST,
  RTE_ACL_IPV4VLAN_PORTS,
  RTE_ACL_IPV4_GTP_TEID
};

struct rte_acl_field_def ipv4_defs[] = {
  [PROTO_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = PROTO_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_PROTO,
    .offset = offsetof(ip4_header_t, protocol),
  },
  [SRC_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_SRC,
    .offset = offsetof(ip4_header_t, src_address),
  },
  [DST_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_DST,
    .offset = offsetof(ip4_header_t, dst_address),
  },
  [SRCP_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = SRCP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_PORTS,
    .offset = sizeof(ip4_header_t),
  },
  [DSTP_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = DSTP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_PORTS,
    .offset = sizeof(ip4_header_t) + sizeof(uint16_t),
  },
  [GTP_TEID_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(u32),
    .field_index = GTP_TEID_IPV4,
    .input_index = RTE_ACL_IPV4_GTP_TEID,
    .offset = sizeof(ip4_header_t) + sizeof(udp_header_t),
  }
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));

enum {
  PROTO_FIELD_IPV6,
  SRC1_FIELD_IPV6,
  SRC2_FIELD_IPV6,
  SRC3_FIELD_IPV6,
  SRC4_FIELD_IPV6,
  DST1_FIELD_IPV6,
  DST2_FIELD_IPV6,
  DST3_FIELD_IPV6,
  DST4_FIELD_IPV6,
  SRCP_FIELD_IPV6,
  DSTP_FIELD_IPV6,
  GTP_TEID_IPV6
};

struct rte_acl_field_def ipv6_defs[] = {
  [PROTO_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = PROTO_FIELD_IPV6,
    .input_index = PROTO_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, protocol),
  },
  [SRC1_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC1_FIELD_IPV6,
    .input_index = SRC1_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[0]),
  },
  [SRC2_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC2_FIELD_IPV6,
    .input_index = SRC2_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[1]),
  },
  [SRC3_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC3_FIELD_IPV6,
    .input_index = SRC3_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[2]),
  },
  [SRC4_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC4_FIELD_IPV6,
    .input_index = SRC4_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[3]),
  },
  [DST1_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST1_FIELD_IPV6,
    .input_index = DST1_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[0]),
  },
  [DST2_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST2_FIELD_IPV6,
    .input_index = DST2_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[1]),
  },
  [DST3_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST3_FIELD_IPV6,
    .input_index = DST3_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[2]),
  },
  [DST4_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST4_FIELD_IPV6,
    .input_index = DST4_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[3]),
  },
  [SRCP_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = SRCP_FIELD_IPV6,
    .input_index = SRCP_FIELD_IPV6,
    .offset = sizeof(ip6_header_t),
  },
  [DSTP_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = DSTP_FIELD_IPV6,
    .input_index = SRCP_FIELD_IPV6,
    .offset = sizeof(ip6_header_t) + sizeof(uint16_t),
  },
  [GTP_TEID_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(u32),
    .field_index = GTP_TEID_IPV6,
    .input_index = GTP_TEID_IPV6,
    .offset = sizeof(ip6_header_t) + sizeof(udp_header_t),
  }
};

RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

#define vec_bsearch(k, v, compar)				\
	bsearch((k), (v), vec_len((v)), sizeof((v)[0]), compar)

static u8 *
format_upf_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "upf_session%d", dev_instance);
}

static clib_error_t *
upf_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (gtpu_device_class,static) = {
  .name = "GTPU",
  .format_device_name = format_upf_name,
  .format_tx_trace = format_upf_encap_trace,
  .admin_up_down_function = upf_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_gtpu_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (gtpu_hw_class) =
{
  .name = "GTPU",
  .format_header = format_gtpu_header_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static int sx_pdr_id_compare(const void *p1, const void *p2)
{
	const upf_pdr_t *a = (upf_pdr_t *)p1;
	const upf_pdr_t *b = (upf_pdr_t *)p2;

	/* compare rule_ids */
	return intcmp(a->id, b->id);
}

#define vec_diff(new, old, compar, add_del, user)			\
  do {									\
    size_t _i = 0, _j = 0;						\
									\
    if (new)								\
      vec_sort_with_function(new,compar);				\
    if (old)								\
      vec_sort_with_function(old,compar);				\
    if (new && old)							\
      while (_i < vec_len(new) && _j < vec_len(old)) {			\
	int r = compar(&vec_elt(new, _i), &vec_elt(old, _j));		\
	if (r == 0) {							\
	  _i++;;							\
	  _j++;								\
	} else if (r < 0) {						\
	  /* insert new entry */					\
	  add_del(&vec_elt(new, _i), user, 1);				\
	  _i++;								\
	} else {							\
	  /* remove old entry */					\
	  add_del(&vec_elt(old, _j), user, 0);				\
	  _j++;								\
	}								\
      }									\
									\
    if (new)								\
      for (;_i < vec_len(new); _i++)					\
	/* insert new entry */						\
	add_del(&vec_elt(new, _i), user, 1);				\
    if (old)								\
      for (;_j < vec_len(old); _j++)					\
	/* remove old entry */						\
	add_del(&vec_elt(old, _j), user, 0);				\
  } while (0)

static int sx_far_id_compare(const void *p1, const void *p2)
{
	const upf_far_t *a = (upf_far_t *)p1;
	const upf_far_t *b = (upf_far_t *)p2;

	/* compare rule_ids */
	return intcmp(a->id, b->id);
}

static int sx_urr_id_compare(const void *p1, const void *p2)
{
	const upf_urr_t *a = (upf_urr_t *)p1;
	const upf_urr_t *b = (upf_urr_t *)p2;

	/* compare rule_ids */
	return intcmp(a->id, b->id);
}

upf_node_assoc_t *sx_get_association(pfcp_node_id_t *node_id)
{
  upf_main_t *gtm = &upf_main;
  uword *p = NULL;

  switch (node_id->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      p = hash_get_mem (gtm->node_index_by_ip, &node_id->ip);
      break;

    case NID_FQDN:
      p = hash_get_mem (gtm->node_index_by_fqdn, node_id->fqdn);
      break;
    }

  if (!p)
    return 0;

  return pool_elt_at_index (gtm->nodes, p[0]);
}

upf_node_assoc_t *
sx_new_association(u32 fib_index, ip46_address_t *lcl_addr,
		   ip46_address_t *rmt_addr, pfcp_node_id_t *node_id)
{
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;

  pool_get_aligned (gtm->nodes, n, CLIB_CACHE_LINE_BYTES);
  memset (n, 0, sizeof (*n));
  n->sessions = ~0;
  n->node_id = *node_id;
  n->fib_index = fib_index;
  n->lcl_addr = *lcl_addr;
  n->rmt_addr = *rmt_addr;

  switch (node_id->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      hash_set_mem_alloc (&gtm->node_index_by_ip, &node_id->ip, n - gtm->nodes);
      break;

    case NID_FQDN:
      n->node_id.fqdn = vec_dup(node_id->fqdn);
      hash_set_mem (gtm->node_index_by_fqdn, n->node_id.fqdn, n - gtm->nodes);
      break;
    }

  return n;
}

void sx_release_association(upf_node_assoc_t *n)
{
  sx_server_main_t *sxsm = &sx_server_main;
  upf_main_t *gtm = &upf_main;
  u32 node_id = n - gtm->nodes;
  u32 idx = n->sessions;
  u32 * msgs = NULL;
  sx_msg_t * msg;
  u32 * m;

  switch (n->node_id.type)
    {
    case NID_IPv4:
    case NID_IPv6:
      hash_unset_mem_free (&gtm->node_index_by_ip, &n->node_id.ip);
      break;

    case NID_FQDN:
      hash_unset_mem (gtm->node_index_by_fqdn, n->node_id.fqdn);
      vec_free(n->node_id.fqdn);
      break;
    }

  clib_warning("sx_release_association idx: %u");

  while (idx != ~0)
    {
      upf_session_t * sx = pool_elt_at_index (gtm->sessions, idx);

      ASSERT(sx->assoc.node == node_id);

      idx = sx->assoc.next;

      if (sx_disable_session(sx) != 0)
	  clib_error("failed to remove UPF session 0x%016" PRIx64, sx->cp_seid);
      sx_free_session(sx);
    }

  ASSERT(n->sessions == ~0);

  pool_foreach (msg, sxsm->msg_pool,
    ({
      if (msg->node == node_id)
	vec_add1(msgs, msg - sxsm->msg_pool);
    }));
  vec_foreach (m, msgs)
    {
      msg = pool_elt_at_index(sxsm->msg_pool, *m);
      hash_unset (sxsm->request_q, msg->seq_no);
      upf_pfcp_server_stop_timer(msg->timer);
      sx_msg_free(sxsm, msg);
    }
}

static void node_assoc_attach_session(upf_node_assoc_t *n, upf_session_t *sx)
{
  upf_main_t *gtm = &upf_main;
  u32 sx_idx = sx - gtm->sessions;

  sx->assoc.node = n - gtm->nodes;
  sx->assoc.prev = ~0;

  if (n->sessions != ~0)
    {
      upf_session_t *prev = pool_elt_at_index (gtm->sessions, n->sessions);

      ASSERT(prev->assoc.prev == ~0);
      ASSERT(prev->assoc.node == sx->assoc.node);
      ASSERT(!pool_is_free_index (gtm->sessions, n->sessions));

      prev->assoc.prev = sx_idx;
    }

  sx->assoc.next = n->sessions;
  n->sessions = sx_idx;
}

static void node_assoc_detach_session(upf_session_t *sx)
{
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;

  ASSERT(sx->assoc.node != ~0);
  ASSERT(!pool_is_free_index (gtm->nodes, sx->assoc.node));

  if (sx->assoc.prev != ~0)
    {
      upf_session_t *prev = pool_elt_at_index (gtm->sessions, sx->assoc.prev);

      ASSERT(prev->assoc.node == sx->assoc.node);

      prev->assoc.next = sx->assoc.next;
    }
  else
    {
      n = pool_elt_at_index (gtm->nodes, sx->assoc.node);
      ASSERT(n->sessions != ~0);

      n->sessions = sx->assoc.next;
    }

  if (sx->assoc.next != ~0)
    {
      upf_session_t *next = pool_elt_at_index (gtm->sessions, sx->assoc.next);

      ASSERT(next->assoc.node == sx->assoc.node);

      next->assoc.prev = sx->assoc.prev;
    }

  sx->assoc.node = sx->assoc.prev = sx->assoc.next = ~0;
}

upf_session_t *sx_create_session(upf_node_assoc_t *assoc, int sx_fib_index,
				 const ip46_address_t *up_address, uint64_t cp_seid,
				 const ip46_address_t *cp_address)
{
  sx_server_main_t *sxsm = &sx_server_main;
  vnet_main_t *vnm = upf_main.vnet_main;
  l2input_main_t *l2im = &l2input_main;
  upf_main_t *gtm = &upf_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  upf_session_t *sx;

  clib_warning("CP F-SEID: 0x%016" PRIx64 " @ %U\n"
	       "UP F-SEID: 0x%016" PRIx64 " @ %U\n",
	       cp_seid, format_ip46_address, cp_address, IP46_TYPE_ANY,
	       cp_seid, format_ip46_address, up_address, IP46_TYPE_ANY);

  pool_get_aligned (gtm->sessions, sx, CLIB_CACHE_LINE_BYTES);
  memset (sx, 0, sizeof (*sx));

  sx->fib_index = sx_fib_index;
  sx->up_address = *up_address;
  sx->cp_seid = cp_seid;
  sx->cp_address = *cp_address;

  sx->unix_time_start = sxsm->now;

  clib_spinlock_init(&sx->lock);

  //TODO sx->up_f_seid = sx - gtm->sessions;
  node_assoc_attach_session(assoc, sx);
  hash_set (gtm->session_by_id, cp_seid, sx - gtm->sessions);

  vnet_hw_interface_t *hi;

  if (vec_len (gtm->free_session_hw_if_indices) > 0)
  {
    vnet_interface_main_t *im = &vnm->interface_main;
    hw_if_index = gtm->free_session_hw_if_indices
      [vec_len (gtm->free_session_hw_if_indices) - 1];
    _vec_len (gtm->free_session_hw_if_indices) -= 1;

    hi = vnet_get_hw_interface (vnm, hw_if_index);
    hi->dev_instance = sx - gtm->sessions;
    hi->hw_instance = hi->dev_instance;

    /* clear old stats of freed session before reuse */
    sw_if_index = hi->sw_if_index;
    vnet_interface_counter_lock (im);
    vlib_zero_combined_counter
      (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX], sw_if_index);
    vlib_zero_combined_counter
      (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX], sw_if_index);
    vlib_zero_simple_counter
      (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
    vnet_interface_counter_unlock (im);
  }
  else
    {
      hw_if_index = vnet_register_interface
	(vnm, gtpu_device_class.index, sx - gtm->sessions,
	 gtpu_hw_class.index, sx - gtm->sessions);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
    }

  /* Set GTP-U tunnel output node */
  vnet_set_interface_output_node (vnm, hw_if_index, upf_if_input_node.index);

  sx->hw_if_index = hw_if_index;
  sx->sw_if_index = sw_if_index = hi->sw_if_index;

  vec_validate_init_empty (gtm->session_index_by_sw_if_index, sw_if_index, ~0);
  gtm->session_index_by_sw_if_index[sw_if_index] = sx - gtm->sessions;

  /* setup l2 input config with l2 feature and bd 0 to drop packet */
  vec_validate (l2im->configs, sw_if_index);
  l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
  l2im->configs[sw_if_index].bd_index = 0;

  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /*
   * L3 enable the interface
   */
  ip4_sw_interface_enable_disable (sw_if_index, 1);
  ip6_sw_interface_enable_disable (sw_if_index, 1);

  vnet_get_sw_interface (vnet_get_main (), sw_if_index)->flood_class =
	  VNET_FLOOD_CLASS_TUNNEL_NORMAL;

  return sx;
}

void sx_update_session(upf_session_t *sx)
{
	// TODO: do we need some kind of update lock ?
}

static void
upf_peer_restack_dpo (upf_peer_t * p)
{
  dpo_id_t dpo = DPO_INVALID;

  fib_entry_contribute_forwarding (p->fib_entry_index, p->forw_type, &dpo);
  dpo_stack_from_node (p->encap_index, &p->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static upf_peer_t *
upf_peer_from_fib_node (fib_node_t * node)
{
  return ((upf_peer_t *) (((char *) node) -
			    STRUCT_OFFSET_OF (upf_peer_t, node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of GTPU DIP to encap node.
 */
static fib_node_back_walk_rc_t
upf_peer_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  upf_peer_restack_dpo (upf_peer_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
upf_peer_fib_node_get (fib_node_index_t index)
{
  upf_main_t *gtm = &upf_main;
  upf_peer_t *p;

  p = pool_elt_at_index (gtm->peers, index);

  return (&p->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
upf_peer_last_lock_gone (fib_node_t * node)
{
  /*
   * The GTP peer is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by GTPU tunnels
 * for participation in the FIB object graph.
 */
const fib_node_vft_t upf_vft = {
  .fnv_get = upf_peer_fib_node_get,
  .fnv_last_lock = upf_peer_last_lock_gone,
  .fnv_back_walk = upf_peer_back_walk,
};

static uword
peer_addr_ref (const upf_far_forward_t * fwd)
{
  u8 is_ip4 = !!(fwd->outer_header_creation.description & OUTER_HEADER_CREATION_IP4);
  upf_main_t *gtm = &upf_main;
  ip46_address_fib_t key;
  upf_peer_t * p;
  uword *peer;

  memset(&key, 0, sizeof(key));

  if (is_ip4)
    {
      ip46_address_set_ip4(&key.addr, &fwd->outer_header_creation.ip4);
      key.fib_index = ip4_fib_table_get_index_for_sw_if_index(fwd->dst_sw_if_index);
    }
  else
    {
      key.addr.ip6 = fwd->outer_header_creation.ip6;
      key.fib_index = ip6_fib_table_get_index_for_sw_if_index(fwd->dst_sw_if_index);
    }

  peer = hash_get_mem (gtm->peer_index_by_ip, &key);
  if (peer)
    {
      p = pool_elt_at_index (gtm->peers, peer[0]);
      p->ref_cnt++;
      return peer[0];
    }

  pool_get_aligned (gtm->peers, p, CLIB_CACHE_LINE_BYTES);
  memset (p, 0, sizeof (*p));
  p->ref_cnt = 1;
  p->encap_fib_index = key.fib_index;

  if (is_ip4)
    {
      p->encap_index = upf4_encap_node.index;
      p->forw_type = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;
    }
  else
    {
      p->encap_index = upf6_encap_node.index;
      p->forw_type = FIB_FORW_CHAIN_TYPE_UNICAST_IP6;
    }

  hash_set_mem_alloc (&gtm->peer_index_by_ip, &key, p - gtm->peers);

  fib_node_init (&p->node, gtm->fib_node_type);
  fib_prefix_t tun_dst_pfx;
  fib_prefix_from_ip46_addr (&key.addr, &tun_dst_pfx);

  p->fib_entry_index = fib_table_entry_special_add
    (p->encap_fib_index, &tun_dst_pfx, FIB_SOURCE_RR,
     FIB_ENTRY_FLAG_NONE);
  p->sibling_index = fib_entry_child_add
    (p->fib_entry_index, gtm->fib_node_type, p - gtm->peers);
  upf_peer_restack_dpo (p);

  return p - gtm->peers;
}

static uword
peer_addr_unref (const upf_far_forward_t * fwd)
{
  u8 is_ip4 = !!(fwd->outer_header_creation.description & OUTER_HEADER_CREATION_IP4);
  upf_main_t *gtm = &upf_main;
  ip46_address_fib_t key;
  upf_peer_t * p;
  uword *peer;

  memset(&key, 0, sizeof(key));

  if (is_ip4)
    {
      ip46_address_set_ip4(&key.addr, &fwd->outer_header_creation.ip4);
      key.fib_index = ip4_fib_table_get_index_for_sw_if_index(fwd->dst_sw_if_index);
    }
  else
    {
      key.addr.ip6 = fwd->outer_header_creation.ip6;
      key.fib_index = ip6_fib_table_get_index_for_sw_if_index(fwd->dst_sw_if_index);
    }

  peer = hash_get_mem (gtm->peer_index_by_ip, &key);
  ASSERT (peer);

  p = pool_elt_at_index (gtm->peers, peer[0]);
  if (--(p->ref_cnt) != 0)
    return p->ref_cnt;

  hash_unset_mem_free (&gtm->peer_index_by_ip, &key);

  fib_entry_child_remove (p->fib_entry_index, p->sibling_index);
  fib_table_entry_delete_index (p->fib_entry_index, FIB_SOURCE_RR);
  fib_node_deinit (&p->node);
  pool_put (gtm->peers, p);

  return 0;
}

static int make_pending_pdr(upf_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);

  if (pending->pdr)
    return 0;

  if (active->pdr)
    {
      size_t i;

      pending->pdr = vec_dup(active->pdr);
      vec_foreach_index (i, active->pdr)
	{
	  vec_elt(pending->pdr, i).urr_ids =
	    vec_dup(vec_elt(active->pdr, i).urr_ids);
	}
    }

  return 0;
}

static int make_pending_far(upf_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);

  if (pending->far)
    return 0;

  if (active->far)
    {
      size_t i;

      pending->far = vec_dup(active->far);
      vec_foreach_index (i, active->far)
	{
	  upf_far_t *far = vec_elt_at_index(active->far, i);

	  if (!(far->apply_action & FAR_FORWARD) || far->forward.rewrite == NULL)
	    continue;

	  vec_elt(pending->far, i).forward.rewrite = vec_dup(far->forward.rewrite);
	}
    }

  return 0;
}

static int make_pending_urr(upf_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);
  upf_urr_t *urr;

  if (pending->urr)
    return 0;

  if (active->urr)
    {
      pending->urr = vec_dup(active->urr);
      vec_foreach (urr, pending->urr)
	{
	  urr->update_flags = 0;
	  memset(&urr->volume.measure, 0, sizeof(urr->volume.measure));
	}
    }

  return 0;
}

static void sx_free_rules(upf_session_t *sx, int rule)
{
  struct rules *rules = sx_get_rules(sx, rule);
  upf_pdr_t *pdr;
  upf_far_t *far;

  vec_foreach (pdr, rules->pdr)
    vec_free(pdr->urr_ids);
  vec_free(rules->pdr);
  vec_foreach (far, rules->far)
    {
      if (far->forward.outer_header_creation.description != 0)
	peer_addr_unref(&far->forward);

      vec_free(far->forward.rewrite);
    }
  vec_free(rules->far);
  vec_free(rules->urr);
  for (size_t i = 0; i < ARRAY_LEN(rules->sdf); i++)
    sx_acl_free(&rules->sdf[i]);
  vec_free(rules->vrf_ip);
  vec_free(rules->v4_teid);
  vec_free(rules->v6_teid);

  hash_free(rules->wildcard_teid);

  memset(rules, 0, sizeof(*rules));
}

struct rcu_session_info {
  struct rcu_head rcu_head;
  uword idx;
};

static void rcu_free_sx_session_info(struct rcu_head *head)
{
  struct rcu_session_info *si = caa_container_of(head, struct rcu_session_info, rcu_head);
  upf_main_t *gtm = &upf_main;
  upf_session_t *sx;

  sx = pool_elt_at_index (gtm->sessions, si->idx);

  for (size_t i = 0; i < ARRAY_LEN(sx->rules); i++)
    sx_free_rules(sx, i);

  clib_spinlock_free(&sx->lock);

  vec_add1 (gtm->free_session_hw_if_indices, sx->hw_if_index);

  pool_put_index (gtm->sessions, si->idx);
  clib_mem_free(si);
}

int sx_disable_session(upf_session_t *sx)
{
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);
  vnet_main_t *vnm = upf_main.vnet_main;
  upf_main_t *gtm = &upf_main;
  ip46_address_fib_t *vrf_ip;
  gtpu4_tunnel_key_t *v4_teid;
  gtpu6_tunnel_key_t *v6_teid;
  upf_urr_t *urr;

  hash_unset (gtm->session_by_id, sx->cp_seid);
  vec_foreach (v4_teid, active->v4_teid)
    sx_add_del_v4_teid(v4_teid, sx, 0);
  vec_foreach (v6_teid, active->v6_teid)
    sx_add_del_v6_teid(v6_teid, sx, 0);
  vec_foreach (vrf_ip, active->vrf_ip)
    sx_add_del_vrf_ip(vrf_ip, sx, 0);

  node_assoc_detach_session(sx);

  //TODO: free DL fifo...

  /* disable tunnel if */
  vnet_sw_interface_set_flags (vnm, sx->sw_if_index, 0 /* down */ );
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sx->sw_if_index);
  si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

  /* make sure session is removed from l2 bd or xconnect */
  set_int_l2_mode (gtm->vlib_main, vnm, MODE_L3, sx->sw_if_index, 0, 0, 0, 0);
  gtm->session_index_by_sw_if_index[sx->sw_if_index] = ~0;

  /* stop all timers */
  vec_foreach (urr, active->urr)
    {
      upf_pfcp_session_stop_urr_time(&urr->measurement_period);
      upf_pfcp_session_stop_urr_time(&urr->monitoring_time);
      upf_pfcp_session_stop_urr_time(&urr->time_threshold);
      upf_pfcp_session_stop_urr_time(&urr->time_quota);
    }

  return 0;
}

void sx_free_session(upf_session_t *sx)
{
  upf_main_t *gtm = &upf_main;
  struct rcu_session_info *si;

  si = clib_mem_alloc_no_fail (sizeof(*si));
  si->idx = sx - gtm->sessions;

  call_rcu(&si->rcu_head, rcu_free_sx_session_info);
}

#define sx_rule_vector_fns(t)						\
upf_##t##_t * sx_get_##t##_by_id(struct rules *rules,			\
				   typeof (((upf_##t##_t *)0)->id) t##_id) \
{									\
  upf_##t##_t r = { .id = t##_id };					\
									\
  return vec_bsearch(&r, rules->t, sx_##t##_id_compare);		\
}									\
									\
upf_##t##_t *sx_get_##t(upf_session_t *sx, int rule,		\
			  typeof (((upf_##t##_t *)0)->id) t##_id)	\
{									\
  struct rules *rules = sx_get_rules(sx, rule);				\
  upf_##t##_t r = { .id = t##_id };					\
									\
  if (rule == SX_PENDING)						\
    if (make_pending_##t(sx) != 0)					\
      return NULL;							\
									\
  printf("LOOKUP t##: %u\n", t##_id);					\
  return vec_bsearch(&r, rules->t, sx_##t##_id_compare);		\
}									\
									\
int sx_create_##t(upf_session_t *sx, upf_##t##_t *t)		\
{									\
  struct rules *rules = sx_get_rules(sx, SX_PENDING);			\
									\
  if (make_pending_##t(sx) != 0)					\
    return -1;								\
									\
  vec_add1(rules->t, *t);						\
  vec_sort_with_function(rules->t, sx_##t##_id_compare);		\
  return 0;								\
}									\
									\
int sx_delete_##t(upf_session_t *sx, u32 t##_id)			\
{									\
  struct rules *rules = sx_get_rules(sx, SX_PENDING);			\
  upf_##t##_t r = { .id = t##_id };					\
  upf_##t##_t *p;							\
									\
  if (make_pending_##t(sx) != 0)					\
    return -1;								\
									\
  if (!(p = vec_bsearch(&r, rules->t, sx_##t##_id_compare)))		\
    return -1;								\
									\
  vec_del1(rules->t, p - rules->t);					\
  return 0;								\
}

sx_rule_vector_fns(pdr)
sx_rule_vector_fns(far)
sx_rule_vector_fns(urr)

void sx_send_end_marker(upf_session_t *sx, u16 id)
{
  struct rules *rules = sx_get_rules(sx, SX_PENDING);

  vec_add1(rules->send_end_marker, id);
}

static int ip46_address_fib_cmp(const void *a0, const void *b0)
{
  const ip46_address_fib_t *a = a0;
  const ip46_address_fib_t *b = b0;
  int r;

  if ((r = intcmp(a->fib_index, b->fib_index)) != 0)
    return r;

  return ip46_address_cmp(&a->addr, &b->addr);
}

static int v4_teid_cmp(const void *a, const void *b)
{
  return memcmp(a, b, sizeof(gtpu4_tunnel_key_t));
}

static int v6_teid_cmp(const void *a, const void *b)
{
  return memcmp(a, b, sizeof(gtpu6_tunnel_key_t));
}

//TODO: instead of using the UE IP, we should use the DL SDF dst fields
static void sx_add_del_vrf_ip(const void *ip, void *si, int is_add)
{
  const ip46_address_fib_t *vrf_ip = ip;
  upf_session_t *sess = si;
  fib_prefix_t pfx;

  memset (&pfx, 0, sizeof (pfx));

  if (ip46_address_is_ip4(&vrf_ip->addr))
    {
      pfx.fp_addr.ip4.as_u32 = vrf_ip->addr.ip4.as_u32;
      pfx.fp_len = 32;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      pfx.fp_addr.ip6.as_u64[0] = vrf_ip->addr.ip6.as_u64[0];
      pfx.fp_addr.ip6.as_u64[1] = vrf_ip->addr.ip6.as_u64[1];
      pfx.fp_len = 64;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
    }

  if (is_add)
    {
      /* add reverse route for client ip */
      fib_table_entry_path_add (vrf_ip->fib_index, &pfx,
				FIB_SOURCE_PLUGIN_HI, FIB_ENTRY_FLAG_ATTACHED,
				fib_proto_to_dpo (pfx.fp_proto),
				NULL, sess->sw_if_index, ~0,
				1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      /* delete reverse route for client ip */
      fib_table_entry_path_remove (vrf_ip->fib_index, &pfx,
				   FIB_SOURCE_PLUGIN_HI,
				   fib_proto_to_dpo (pfx.fp_proto),
				   NULL, sess->sw_if_index, ~0, 1,
				   FIB_ROUTE_PATH_FLAG_NONE);
    }
}

static void sx_add_del_v4_teid(const void *teid, void *si, int is_add)
{
  upf_main_t *gtm = &upf_main;
  upf_session_t *sess = si;
  const gtpu4_tunnel_key_t *v4_teid = teid;
  clib_bihash_kv_8_8_t kv;

  kv.key = v4_teid->as_u64;
  kv.value = sess - gtm->sessions;

  gtp_debug("upf_pfcp: is_add: %d, TEID: 0x%08x, IP:%U, Session:%p, idx: %p.",
	    is_add, v4_teid->teid,
	    format_ip4_address, &v4_teid->dst, sess,
	    sess - gtm->sessions);

  clib_bihash_add_del_8_8(&gtm->v4_tunnel_by_key, &kv, is_add);
}

static void sx_add_del_v6_teid(const void *teid, void *si, int is_add)
{
  upf_main_t *gtm = &upf_main;
  upf_session_t *sess = si;
  const gtpu6_tunnel_key_t *v6_teid = teid;
  clib_bihash_kv_24_8_t kv;

  kv.key[0] = v6_teid->dst.as_u64[0];
  kv.key[1] = v6_teid->dst.as_u64[1];
  kv.key[2] = v6_teid->teid;
  kv.value = sess - gtm->sessions;

  gtp_debug("upf_pfcp: is_add: %d, TEID: 0x%08x, IP:%U, Session:%p, idx: %p.",
	    is_add, v6_teid->teid,
	    format_ip6_address, &v6_teid->dst, sess,
	    sess - gtm->sessions);

  clib_bihash_add_del_24_8(&gtm->v6_tunnel_by_key, &kv, is_add);
}

/* Format an IP4 address. */
static u8 *format_ip4_address_host (u8 * s, va_list * args)
{
  u32 *a = va_arg (*args, u32 *);
  ip4_address_t ip4;

  ip4.as_u32 = clib_host_to_net_u32(*a);
  return format (s, "%d.%d.%d.%d", ip4.as_u8[0], ip4.as_u8[1], ip4.as_u8[2], ip4.as_u8[3]);
}

static u8 *
format_acl4 (u8 * s, va_list * args)
{
  struct acl4_rule *rule = va_arg (*args, struct acl4_rule *);

  s = format(s, "%U/%d %U/%d %hu : %hu %hu : %hu 0x%hhx/0x%hhx 0x%08x/0x%08x 0x%x-0x%x-0x%x",
	     format_ip4_address_host, &rule->field[SRC_FIELD_IPV4].value.u32,
	     rule->field[SRC_FIELD_IPV4].mask_range.u32,
	     format_ip4_address_host, &rule->field[DST_FIELD_IPV4].value.u32,
	     rule->field[DST_FIELD_IPV4].mask_range.u32,
	     rule->field[SRCP_FIELD_IPV4].value.u16,
	     rule->field[SRCP_FIELD_IPV4].mask_range.u16,
	     rule->field[DSTP_FIELD_IPV4].value.u16,
	     rule->field[DSTP_FIELD_IPV4].mask_range.u16,
	     rule->field[PROTO_FIELD_IPV4].value.u8,
	     rule->field[PROTO_FIELD_IPV4].mask_range.u8,
	     rule->field[GTP_TEID_IPV4].value.u32,
	     rule->field[GTP_TEID_IPV4].mask_range.u32,
	     rule->data.category_mask,
	     rule->data.priority,
	     rule->data.userdata);

  return s;
}

static u8 *
format_acl_ip6_address (u8 * s, va_list * args)
{
  struct rte_acl_field * field = va_arg (*args, struct rte_acl_field *);
  ip6_address_t addr;

  for (int i = 0; i < 4; i ++)
    addr.as_u32[i] = clib_host_to_net_u32(field[i].value.u32);

  return format(s, "%U", format_ip6_address, &addr);
}

static u8 *
format_acl6 (u8 * s, va_list * args)
{
  struct acl6_rule *rule = va_arg (*args, struct acl6_rule *);

  s = format(s, "%U/%u ",
	     format_acl_ip6_address, &rule->field[SRC1_FIELD_IPV6],
	     rule->field[SRC1_FIELD_IPV6].mask_range.u32
	     + rule->field[SRC2_FIELD_IPV6].mask_range.u32
	     + rule->field[SRC3_FIELD_IPV6].mask_range.u32
	     + rule->field[SRC4_FIELD_IPV6].mask_range.u32);

  s = format(s, "%U/%u ",
	     format_acl_ip6_address, &rule->field[DST1_FIELD_IPV6],
	     rule->field[DST1_FIELD_IPV6].mask_range.u32
	     + rule->field[DST2_FIELD_IPV6].mask_range.u32
	     + rule->field[DST3_FIELD_IPV6].mask_range.u32
	     + rule->field[DST4_FIELD_IPV6].mask_range.u32);

  s = format(s, "%hu : %hu %hu : %hu 0x%hhx/0x%hhx 0x%08x/0x%08x 0x%x-0x%x-0x%x",
	     rule->field[SRCP_FIELD_IPV6].value.u16,
	     rule->field[SRCP_FIELD_IPV6].mask_range.u16,
	     rule->field[DSTP_FIELD_IPV6].value.u16,
	     rule->field[DSTP_FIELD_IPV6].mask_range.u16,
	     rule->field[PROTO_FIELD_IPV6].value.u8,
	     rule->field[PROTO_FIELD_IPV6].mask_range.u8,
	     rule->field[GTP_TEID_IPV6].value.u32,
	     rule->field[GTP_TEID_IPV6].mask_range.u32,
	     rule->data.category_mask,
	     rule->data.priority,
	     rule->data.userdata);

  return s;
}

static void rte_acl_set_port(struct rte_acl_field * field, const ipfilter_port_t * port)
{
  field->value.u16 = port->min;
  field->mask_range.u16 = port->max;
}

static void rte_acl_set_proto(struct rte_acl_field * field, u8 proto, u8 mask)
{
  field->value.u8 = proto;
  field->mask_range.u8 = mask;
}

static void acl_set_ue_ip4(struct acl4_rule *ip4, int field, const upf_pdr_t *pdr)
{
  if ((pdr->pdi.fields & F_PDI_UE_IP_ADDR) &&
      pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
    {
      ip4->field[field].value.u32 = clib_net_to_host_u32(pdr->pdi.ue_addr.ip4.as_u32);
      ip4->field[field].mask_range.u32 = 32;
    }
  else
    {
      ip4->field[field].value.u32 = 0;
      ip4->field[field].mask_range.u32 = 0;
    }
}

static void ip4_assign_src_address(struct acl4_rule *ip4,
				   int field, const upf_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.src_address, ACL_FROM_ANY) == 0)
    {
      ip4->field[field].value.u32 = 0;
      ip4->field[field].mask_range.u32 = 0;
    }
  else
    {
      ip4->field[field].value.u32 =
	clib_net_to_host_u32(pdr->pdi.acl.src_address.address.ip4.as_u32);
      ip4->field[field].mask_range.u32 = pdr->pdi.acl.src_address.mask;
    }
}

static void ip4_assign_dst_address(struct acl4_rule *ip4,
				   int field, const upf_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.dst_address, ACL_TO_ASSIGNED) == 0)
    acl_set_ue_ip4(ip4, field, pdr);
  else
    {
      ip4->field[field].value.u32 =
	clib_net_to_host_u32(pdr->pdi.acl.dst_address.address.ip4.as_u32);
      ip4->field[field].mask_range.u32 = pdr->pdi.acl.dst_address.mask;
    }
}

static void ip4_assign_src_port(struct acl4_rule *ip4,
				int field, const upf_pdr_t *pdr)
{
  rte_acl_set_port(&ip4->field[field], &pdr->pdi.acl.src_port);
}

static void ip4_assign_dst_port(struct acl4_rule *ip4,
				int field, const upf_pdr_t *pdr)
{
  rte_acl_set_port(&ip4->field[field], &pdr->pdi.acl.dst_port);
}

static int add_ip4_sdf(struct rte_acl_ctx *ctx, const upf_pdr_t *pdr,
		       u32 pdr_idx)
{
  struct acl4_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV4] = {
      .value.u8 = 0,
      .mask_range.u8 = 0,
    },

    .field[PROTO_FIELD_IPV4] = {
      .value.u8 = pdr->pdi.acl.proto,
      .mask_range.u8 = ~0,
    },
  };

  if (pdr->pdi.acl.proto == (u8)~0)
    rte_acl_set_proto(&r.field[PROTO_FIELD_IPV4], 0, 0);

  if ((!acl_is_from_any(&pdr->pdi.acl.src_address) &&
       !ip46_address_is_ip4(&pdr->pdi.acl.src_address.address)) ||
      (!acl_is_to_assigned(&pdr->pdi.acl.dst_address) &&
       !ip46_address_is_ip4(&pdr->pdi.acl.dst_address.address)))
    return 0;

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      ip4_assign_src_address(&r, DST_FIELD_IPV4, pdr);
      ip4_assign_dst_address(&r, SRC_FIELD_IPV4, pdr);
      ip4_assign_src_port(&r, DSTP_FIELD_IPV4, pdr);
      ip4_assign_dst_port(&r, SRCP_FIELD_IPV4, pdr);
      break;

    default:
      ip4_assign_src_address(&r, SRC_FIELD_IPV4, pdr);
      ip4_assign_dst_address(&r, DST_FIELD_IPV4, pdr);
      ip4_assign_src_port(&r, SRCP_FIELD_IPV4, pdr);
      ip4_assign_dst_port(&r, DSTP_FIELD_IPV4, pdr);
      break;
    }

  gtp_debug("PDR %d, IPv4 %s SDF (%p): %U\n", pdr->id,
	    (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	    ctx, format_acl4, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP6 add rules failed\n");

  return 0;
}

static u32 ip6_mask (u8 pos, u8 pref_len)
{
  if (pref_len >= (pos + 1) * 32)
    return 32;
  else
    return pref_len > (pos * 32) ? pref_len - (pos * 32) : 0;
}

static void acl_set_ue_ip6(struct acl6_rule *ip6, int field, const upf_pdr_t *pdr)
{
  if ((pdr->pdi.fields & F_PDI_UE_IP_ADDR) &&
      pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
    {
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 = clib_net_to_host_u32(pdr->pdi.ue_addr.ip6.as_u32[i]);
	ip6->field[field + i].mask_range.u32 = ip6_mask(i, 64);
      }
    }
  else
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 = 0;
	ip6->field[field + i].mask_range.u32 = 0;
      }
}

static void ip6_assign_src_address(struct acl6_rule *ip6,
				   int field, const upf_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.src_address, ACL_FROM_ANY) == 0)
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 = 0;
	ip6->field[field + i].mask_range.u32 = 0;
      }
  else
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 =
	  clib_net_to_host_u32(pdr->pdi.acl.src_address.address.ip6.as_u32[i]);
	ip6->field[field + i].mask_range.u32 = ip6_mask(i, pdr->pdi.acl.src_address.mask);
      }
}

static void ip6_assign_dst_address(struct acl6_rule *ip6,
				   int field, const upf_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.dst_address, ACL_TO_ASSIGNED) == 0)
    acl_set_ue_ip6(ip6, field, pdr);
  else
    for (int i = 0; i < 4; i++)
      ip6->field[field + i] = (struct rte_acl_field){
	.value.u32 = clib_net_to_host_u32(pdr->pdi.acl.dst_address.address.ip6.as_u32[i]),
	.mask_range.u32 = ip6_mask(i, pdr->pdi.acl.dst_address.mask),
      };
}

static void ip6_assign_src_port(struct acl6_rule *ip6,
				int field, const upf_pdr_t *pdr)
{
  rte_acl_set_port(&ip6->field[field], &pdr->pdi.acl.src_port);
}

static void ip6_assign_dst_port(struct acl6_rule *ip6,
				int field, const upf_pdr_t *pdr)
{
  rte_acl_set_port(&ip6->field[field], &pdr->pdi.acl.dst_port);
}

static int add_ip6_sdf(struct rte_acl_ctx *ctx, const upf_pdr_t *pdr,
		       u32 pdr_idx)
{
  struct acl6_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV6] = {
      .value.u32 = 0,
      .mask_range.u32 = 0,
    },

    .field[PROTO_FIELD_IPV6] = {
      .value.u8 = pdr->pdi.acl.proto,
      .mask_range.u8 = ~0,
    },
  };

  if (pdr->pdi.acl.proto == (u8)~0)
    rte_acl_set_proto(&r.field[PROTO_FIELD_IPV6], 0, 0);

  if ((!acl_is_from_any(&pdr->pdi.acl.src_address) &&
       ip46_address_is_ip4(&pdr->pdi.acl.src_address.address)) ||
      (!acl_is_to_assigned(&pdr->pdi.acl.dst_address) &&
       ip46_address_is_ip4(&pdr->pdi.acl.dst_address.address)))
    return 0;

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      ip6_assign_src_address(&r, DST1_FIELD_IPV6, pdr);
      ip6_assign_dst_address(&r, SRC1_FIELD_IPV6, pdr);
      ip6_assign_src_port(&r, DSTP_FIELD_IPV6, pdr);
      ip6_assign_dst_port(&r, SRCP_FIELD_IPV6, pdr);
      break;

    default:
      ip6_assign_src_address(&r, SRC1_FIELD_IPV6, pdr);
      ip6_assign_dst_address(&r, DST1_FIELD_IPV6, pdr);
      ip6_assign_src_port(&r, SRCP_FIELD_IPV6, pdr);
      ip6_assign_dst_port(&r, DSTP_FIELD_IPV6, pdr);
      break;
    }

  gtp_debug("PDR %d, IPv6 %s SDF (%p): %U\n", pdr->id,
	    (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	    ctx, format_acl6, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP6 add rules failed\n");

  return 0;
}

static int add_wildcard_teid(struct rules *rules, const u8 src_intf,
			     const pfcp_f_teid_t teid, u32 pdr_idx)
{
  gtpu_intf_tunnel_key_t key;

  key.src_intf = src_intf;
  key.teid = teid.teid;

  hash_set (rules->wildcard_teid, key.as_u64, pdr_idx);

  return 0;
}

static int add_wildcard_ip4_sdf(struct rte_acl_ctx *ctx, const upf_pdr_t *pdr,
				u32 pdr_idx)
{
  struct acl4_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV4]    = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[PROTO_FIELD_IPV4] = {.value.u8 = 0, .mask_range.u8 = 0,},
    .field[SRC_FIELD_IPV4]   = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[DST_FIELD_IPV4]   = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[SRCP_FIELD_IPV4]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
    .field[DSTP_FIELD_IPV4]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
  };

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      acl_set_ue_ip4(&r, SRC_FIELD_IPV4, pdr);
      break;

    default:
      acl_set_ue_ip4(&r, DST_FIELD_IPV4, pdr);
      break;
    }

  gtp_debug("PDR %d, IPv4 %s wildcard SDF (%p): %U\n", pdr->id,
	    (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	    ctx, format_acl4, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP4 add rules failed\n");

  return 0;
}

static int add_wildcard_ip6_sdf(struct rte_acl_ctx *ctx, const upf_pdr_t *pdr,
				u32 pdr_idx)
{
  struct acl6_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV6]    = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[PROTO_FIELD_IPV6] = {.value.u8 = 0, .mask_range.u8 = 0,},
    .field[SRC1_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRC2_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRC3_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRC4_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST1_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST2_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST3_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST4_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRCP_FIELD_IPV6]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
    .field[DSTP_FIELD_IPV6]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
  };

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      acl_set_ue_ip6(&r, SRC1_FIELD_IPV6, pdr);
      break;

    default:
      acl_set_ue_ip6(&r, DST1_FIELD_IPV6, pdr);
      break;
    }

  gtp_debug("PDR %d, IPv6 %s wildcard SDF (%p): %U\n", pdr->id,
	    (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	    ctx, format_acl6, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP6 add rules failed\n");

  return 0;
}

static int sx_acl_create(u64 cp_seid, struct rules *rules, int direction)
{
  /*
   * Check numa socket enable or disable based on
   * get or set socketid.
   */
  upf_acl_ctx_t *ctx = &rules->sdf[direction];

  char name[RTE_ACL_NAMESIZE];
  struct rte_acl_param ip4acl = {
    .name = name,
    .socket_id = 0,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
    .max_rule_num = vec_len(rules->pdr),
  };

  struct rte_acl_param ip6acl = {
    .name = name,
    .socket_id = 0,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs)),
    .max_rule_num = vec_len(rules->pdr),
  };

  if (rules->flags & SX_SDF_IPV4)
    {
      snprintf(name, sizeof(name), "sx_%"PRIu64"_sdf_ip4_%d",
	       cp_seid, direction);
      ctx->ip4 = rte_acl_create(&ip4acl);
      if (!ctx->ip4)
	rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
    }

  if (rules->flags & SX_SDF_IPV6)
    {
      snprintf(name, sizeof(name), "sx_%"PRIu64"_sdf_ip6_%d",
	       cp_seid, direction);
      ctx->ip6 = rte_acl_create(&ip6acl);
      if (!ctx->ip6)
	rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
    }
  return 0;
}

static int sx_acl_build(struct rules *rules, int direction)
{
  upf_acl_ctx_t *ctx = &rules->sdf[direction];

  if (ctx->ip4)
    {
      struct rte_acl_config cfg = {
	.num_categories = 1,
	.num_fields = RTE_DIM(ipv4_defs),
      };
      memcpy(&cfg.defs, ipv4_defs, sizeof(ipv4_defs));

      /* Perform builds */
      if (rte_acl_build(ctx->ip4, &cfg) != 0)
	{
	  // TODO: ctx without rules will fail, find some other way to handle that
	  gtp_debug("RTE ACL %s IPv4 build failed, no need to worry!",
		    direction == UL_SDF ? "UL" : "DL");
	  rte_acl_free(ctx->ip4);
	  ctx->ip4 = NULL;
	}
      else
	{
	  gtp_debug("RTE ACL %s IPv4 build SUCCEEDED!",
		    direction == UL_SDF ? "UL" : "DL");
	  rte_acl_dump(ctx->ip4);
	}
    }

  if (ctx->ip6)
    {
      struct rte_acl_config cfg = {
	.num_categories = 1,
	.num_fields = RTE_DIM(ipv6_defs),
      };
      memcpy(&cfg.defs, ipv6_defs, sizeof(ipv6_defs));

      /* Perform builds */
      if (rte_acl_build(ctx->ip6, &cfg) != 0)
	{
	  // TODO: ctx without rules will fail, find some other way to handle that
	  gtp_debug("RTE ACL %s IPv6 build failed, no need to worry!",
		    direction == UL_SDF ? "UL" : "DL");
	  rte_acl_free(ctx->ip6);
	  ctx->ip6 = NULL;
	}
      else
	{
	  rte_acl_dump(ctx->ip6);
	  gtp_debug("RTE ACL %s IPv6 build SUCCEEDED!",
		    direction == UL_SDF ? "UL" : "DL");
	}
    }
  return 0;
}

static void sx_acl_free(upf_acl_ctx_t *ctx)
{
  rte_acl_free(ctx->ip4);
  rte_acl_free(ctx->ip6);
}

static void rules_add_v4_teid(struct rules * r, const ip4_address_t * addr, u32 teid)
{
  gtpu4_tunnel_key_t key;

  key.teid = teid;
  key.dst = addr->as_u32;

  vec_add1(r->v4_teid, key);
}

static void rules_add_v6_teid(struct rules * r, const ip6_address_t * addr, u32 teid)
{
  gtpu6_tunnel_key_t key;

  key.teid = teid;
  key.dst = *addr;

  vec_add1(r->v6_teid, key);
}

#define sdf_src_address_type(acl)					\
  ipfilter_address_cmp_const(&(acl)->src_address, ACL_FROM_ANY) == 0	\
    ? 0 :								\
    (ip46_address_is_ip4(&(acl)->src_address.address) ? SX_SDF_IPV4 : SX_SDF_IPV6)

#define sdf_dst_address_type(acl)					\
  ipfilter_address_cmp_const(&(acl)->dst_address, ACL_TO_ASSIGNED) == 0	\
    ? 0 :								\
    (ip46_address_is_ip4(&(acl)->dst_address.address) ? SX_SDF_IPV4 : SX_SDF_IPV6)

static int build_sx_rules(upf_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  uint64_t cp_seid = sx->cp_seid;
  upf_pdr_t *pdr;

  pending->flags &= ~(SX_SDF_IPV4 | SX_SDF_IPV6);

  vec_foreach (pdr, pending->pdr) {
    printf("PDR Scan: %d\n", pdr->id);

    /*
     * From 3GPP TS 29.244 version 14.3.0, Table 7.5.2.2-2
     *
     * NOTE 2: When a Local F-TEID is provisioned in the PDI, the
     *         Network Instance shall relate to the IP address of
     *         the F-TEID. Otherwise, the Network Instance shall
     *         relate to the UE IP address.
     */
    if (!(pdr->pdi.fields & F_PDI_LOCAL_F_TEID) &&
	pdr->pdi.fields & F_PDI_UE_IP_ADDR)
      {
	ip46_address_fib_t *vrf_ip;

	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
	  {
	    pending->flags |= SX_SDF_IPV4;

	    vec_alloc(pending->vrf_ip, 1);
	    vrf_ip = vec_end(pending->vrf_ip);
	    ip46_address_set_ip4(&vrf_ip->addr, &pdr->pdi.ue_addr.ip4);
	    vrf_ip->fib_index =
		    ip4_fib_table_get_index_for_sw_if_index(pdr->pdi.src_sw_if_index);

	    _vec_len(pending->vrf_ip)++;
	  }

	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
	  {
	    pending->flags |= SX_SDF_IPV6;

	    vec_alloc(pending->vrf_ip, 1);
	    vrf_ip = vec_end(pending->vrf_ip);
	    vrf_ip->addr.ip6 = pdr->pdi.ue_addr.ip6;
	    vrf_ip->fib_index =
		    ip6_fib_table_get_index_for_sw_if_index(pdr->pdi.src_sw_if_index);

	    _vec_len(pending->vrf_ip)++;
	  }
      }

    if (pdr->pdi.fields & F_PDI_SDF_FILTER)
      {
	pending->flags |= sdf_src_address_type(&pdr->pdi.acl);
	pending->flags |= sdf_dst_address_type(&pdr->pdi.acl);
      }

    if (pdr->pdi.fields & F_PDI_LOCAL_F_TEID)
      {
	if (pdr->pdi.teid.flags & F_TEID_V4)
	  rules_add_v4_teid(pending, &pdr->pdi.teid.ip4, pdr->pdi.teid.teid);

	if (pdr->pdi.teid.flags & F_TEID_V6)
	  rules_add_v6_teid(pending, &pdr->pdi.teid.ip6, pdr->pdi.teid.teid);
      }
  }
  if (vec_len(pending->pdr) == 0)
    return 0;

  sx_acl_create(cp_seid, pending, UL_SDF);
  sx_acl_create(cp_seid, pending, DL_SDF);

  vec_foreach (pdr, pending->pdr)
    {
      int direction = (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? UL_SDF : DL_SDF;
      upf_acl_ctx_t *ctx = &pending->sdf[direction];

      if (!(pdr->pdi.fields & F_PDI_SDF_FILTER))
	{
	  if ((pdr->pdi.fields & F_PDI_LOCAL_F_TEID) &&
	      !(pdr->pdi.fields & F_PDI_UE_IP_ADDR))
	    add_wildcard_teid(pending, pdr->pdi.src_intf, pdr->pdi.teid, pdr - pending->pdr);

	  if (pdr->pdi.src_intf != SRC_INTF_ACCESS &&
	      !(pdr->pdi.fields & F_PDI_UE_IP_ADDR))
	    /* wildcard DL SDF only if UE IP is set */
	    continue;

	  if (pending->flags & SX_SDF_IPV4)
	    add_wildcard_ip4_sdf(ctx->ip4, pdr, pdr - pending->pdr);
	  if (pending->flags & SX_SDF_IPV6)
	    add_wildcard_ip6_sdf(ctx->ip6, pdr, pdr - pending->pdr);
	  continue;
	}

      if (pending->flags & SX_SDF_IPV4)
	if (add_ip4_sdf(ctx->ip4, pdr, pdr - pending->pdr) < 0)
	  return -1;
      if (pending->flags & SX_SDF_IPV6)
	if (add_ip6_sdf(ctx->ip6, pdr, pdr - pending->pdr) < 0)
	  return -1;
    }

  sx_acl_build(pending, UL_SDF);
  sx_acl_build(pending, DL_SDF);

  return 0;
}

int sx_update_apply(upf_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);
  int pending_pdr, pending_far, pending_urr;
  sx_server_main_t *sxsm = &sx_server_main;
  upf_main_t *gtm = &upf_main;
  u32 si = sx - gtm->sessions;
  f64 now = sxsm->now;
  upf_urr_t *urr;

  if (!pending->pdr && !pending->far && !pending->urr)
    return 0;

  pending_pdr = !!pending->pdr;
  pending_far = !!pending->far;
  pending_urr = !!pending->urr;

  if (pending_pdr)
    {
      if (build_sx_rules(sx) != 0)
	return -1;
    }
  else
    {
      pending->pdr = active->pdr;

      pending->vrf_ip = active->vrf_ip;
      active->vrf_ip = NULL;

      pending->v4_teid = active->v4_teid;
      active->v4_teid = NULL;
      pending->v6_teid = active->v6_teid;
      active->v6_teid = NULL;

      pending->wildcard_teid = active->wildcard_teid;
      active->wildcard_teid = NULL;

      memcpy(&pending->sdf, &active->sdf, sizeof(active->sdf));
      memset(&active->sdf, 0, sizeof(active->sdf));

      pending->flags = active->flags;
    }

  if (pending_far)
    {
      upf_far_t *far;

      vec_foreach (far, pending->far)
	if (far->forward.outer_header_creation.description != 0)
	  {
	    far->forward.peer_idx = peer_addr_ref(&far->forward);

	    if (far->forward.outer_header_creation.description
		& OUTER_HEADER_CREATION_GTP_IP4)
	      {
		rules_add_v4_teid(pending, &far->forward.outer_header_creation.ip4,
				  far->forward.outer_header_creation.teid);
	      }
	    else if (far->forward.outer_header_creation.description
		     & OUTER_HEADER_CREATION_GTP_IP6)
	      {
		rules_add_v6_teid(pending, &far->forward.outer_header_creation.ip6,
				  far->forward.outer_header_creation.teid);
	      }
	  }
    }
  else
    pending->far = active->far;

  if (!pending_urr)
    pending->urr = active->urr;

  if (pending_pdr)
    {
      sx->flags |= SX_UPDATING;

      /* make sure all processing nodes see the update op */
      synchronize_rcu();

      /* update UE addresses and TEIDs */
      vec_diff(pending->vrf_ip, active->vrf_ip, ip46_address_fib_cmp,
	       sx_add_del_vrf_ip, sx);
      vec_diff(pending->v4_teid, active->v4_teid, v4_teid_cmp, sx_add_del_v4_teid, sx);
      vec_diff(pending->v6_teid, active->v6_teid, v6_teid_cmp, sx_add_del_v6_teid, sx);

      // TODO: add SDF rules to global table
    }

  /* flip the switch */
  sx->active ^= SX_PENDING;
  sx->flags &= ~SX_UPDATING;

  if (pending->send_end_marker)
    {
      u16 * send_em;

      vec_foreach (send_em, pending->send_end_marker)
	{
	  upf_far_t *far;
	  upf_far_t r = { .id = *send_em };

	  if (!(far = vec_bsearch(&r, active->far, sx_far_id_compare)))
	    continue;

	  gtp_debug("TODO: send_end_marker for FAR %d", far->id);
	  gtpu_send_end_marker(&far->forward);
	}
      vec_free(pending->send_end_marker);
    }

  pending = sx_get_rules(sx, SX_PENDING);
  active = sx_get_rules(sx, SX_ACTIVE);


  vec_foreach (urr, active->urr)
    {
      if (urr->update_flags & SX_URR_UPDATE_MEASUREMENT_PERIOD)
	{
	  upf_pfcp_session_start_stop_urr_time
	    (si, now, &urr->measurement_period,
	     !!(urr->triggers & REPORTING_TRIGGER_PERIODIC_REPORTING));
	}

      if (urr->update_flags & SX_URR_UPDATE_MONITORING_TIME)
	{
	  upf_pfcp_session_start_stop_urr_time_abs
	    (si, now, &urr->monitoring_time);
	}

      if ((urr->methods & SX_URR_TIME))
	{
	  if (urr->update_flags & SX_URR_UPDATE_TIME_THRESHOLD)
	    {
	      upf_pfcp_session_start_stop_urr_time
		(si, now, &urr->time_threshold,
		 !!(urr->triggers & REPORTING_TRIGGER_TIME_THRESHOLD));
	    }
	  if (urr->update_flags & SX_URR_UPDATE_TIME_QUOTA)
	    {
	      urr->time_quota.base =
		(urr->time_threshold.base != 0) ? urr->time_threshold.base : now;
	      upf_pfcp_session_start_stop_urr_time
		(si, now, &urr->time_quota,
		 !!(urr->triggers & REPORTING_TRIGGER_TIME_QUOTA));
	    }
	}
    }

  if (!pending_pdr) pending->pdr = NULL;
  if (!pending_far) pending->far = NULL;
  if (pending_urr)
    {
      clib_spinlock_lock (&sx->lock);

      /* copy rest traffic from old active (now pending) to current
       * new URR was initialized with zero, simply add the old values */
      vec_foreach (urr, pending->urr)
	{
	  upf_urr_t * new_urr = sx_get_urr_by_id(active, urr->id);

	  if (!new_urr)
	    {
	      /* stop all timers */
	      upf_pfcp_session_stop_urr_time(&urr->measurement_period);
	      upf_pfcp_session_stop_urr_time(&urr->monitoring_time);
	      upf_pfcp_session_stop_urr_time(&urr->time_threshold);
	      upf_pfcp_session_stop_urr_time(&urr->time_quota);

	      continue;
	    }

	  if ((new_urr->methods & SX_URR_VOLUME))
	    {
	      urr_volume_t *old_volume = &urr->volume;
	      urr_volume_t *new_volume = &new_urr->volume;

#define combine_volume_type(Dst, Src, T, D)		\
	      (Dst)->measure.T.D += (Src)->measure.T.D
#define combine_volume(Dst, Src, T)				\
	      do {						\
		combine_volume_type((Dst), (Src), T, ul);	\
		combine_volume_type((Dst), (Src), T, dl);	\
		combine_volume_type((Dst), (Src), T, total);	\
	      } while (0)

	      combine_volume(new_volume, old_volume, packets);
	      combine_volume(new_volume, old_volume, bytes);

	      if (new_urr->update_flags & SX_URR_UPDATE_VOLUME_QUOTA)
		new_volume->measure.consumed = new_volume->measure.bytes;
	      else
		combine_volume(new_volume, old_volume, consumed);

#undef combine_volume
#undef combine_volume_type
	    }
	}

      clib_spinlock_unlock (&sx->lock);
    }
  else
    pending->urr = NULL;

  return 0;
}

void sx_update_finish(upf_session_t *sx)
{
  sx_free_rules(sx, SX_PENDING);
}

/******************** Sx Session functions **********************/

/**
 * @brief Function to return session info entry address.
 *
 */
upf_session_t *sx_lookup(uint64_t sess_id)
{
  upf_main_t *gtm = &upf_main;
  uword *p;

  p = hash_get (gtm->session_by_id, sess_id);
  if (!p)
    return NULL;

  return pool_elt_at_index (gtm->sessions, p[0]);
}

static int urr_increment_and_check_counter(u64 * packets, u64 * bytes, u64 * consumed,
					   u64 threshold, u64 quota, u64 n_bytes)
{
  int r = URR_OK;

  if (quota != 0 &&
      unlikely(*consumed < quota && *consumed + n_bytes >= quota))
    r |= URR_QUOTA_EXHAUSTED;
  *consumed += n_bytes;

  if (threshold != 0 &&
      unlikely(*bytes < threshold && *bytes + n_bytes >= threshold))
    r |= URR_THRESHOLD_REACHED;
  *bytes += n_bytes;

  *packets += 1;

  return r;
}

u32 process_urrs(vlib_main_t *vm, upf_session_t *sess,
		 struct rules *r,
		 upf_pdr_t *pdr, vlib_buffer_t * b,
		 u8 is_dl, u8 is_ul, u32 next)
{
  u16 *urr_id;

  clib_warning("DL: %d, UL: %d\n", is_dl, is_ul);

  vec_foreach (urr_id, pdr->urr_ids)
    {
      upf_urr_t * urr = sx_get_urr_by_id(r, *urr_id);
      int r = URR_OK;

      if (!urr)
	continue;

      clib_spinlock_lock (&sess->lock);

      if ((urr->methods & SX_URR_VOLUME) &&
	  !(urr->status & URR_OVER_QUOTA))
	{
#define urr_incr_and_check(V, D, L)					\
	  urr_increment_and_check_counter(&V.measure.packets.D,		\
					  &V.measure.bytes.D,		\
					  &V.measure.consumed.D,	\
					  V.threshold.D,		\
					  V.quota.D,			\
					  (L))

	  if (is_ul)
	    r |= urr_incr_and_check(urr->volume, ul, vlib_buffer_length_in_chain (vm, b));
	  if (is_dl)
	    r |= urr_incr_and_check(urr->volume, dl, vlib_buffer_length_in_chain (vm, b));

	  r |= urr_incr_and_check(urr->volume, total, vlib_buffer_length_in_chain (vm, b));

	  if (unlikely(r & URR_QUOTA_EXHAUSTED))
	    urr->status |= URR_OVER_QUOTA;
	}

      clib_spinlock_unlock (&sess->lock);

      if (unlikely(urr->status & URR_OVER_QUOTA))
	next = UPF_PROCESS_NEXT_DROP;

      if (unlikely(r != URR_OK))
	upf_pfcp_server_session_usage_report(sess);
    }

  return next;
}

static const char *apply_action_flags[] = {
  "DROP",
  "FORWARD",
  "BUFFER",
  "NOTIFY_CP",
  "DUPLICATE",
  NULL
};

static const char *urr_method_flags[] = {
  "TIME",
  "VOLUME",
  "EVENT",
  NULL
};

static const char *urr_trigger_flags[] = {
  "PERIODIC REPORTING",
  "VOLUME THRESHOLD",
  "TIME THRESHOLD",
  "QUOTA HOLDING TIME",
  "START OF TRAFFIC",
  "STOP OF TRAFFIC",
  "DROPPED DL TRAFFIC THRESHOLD",
  "LINKED USAGE REPORTING",
  "VOLUME QUOTA",
  "TIME QUOTA",
  "ENVELOPE CLOSURE",
  NULL
};

static const char *urr_status_flags[] = {
  "OVER QUOTA",
  "AFTER MONITORING TIME",
  NULL
};

static const char * source_intf_name[] = {
  "Access",
  "Core",
  "SGi-LAN",
  "CP-function"
};

static const char * outer_header_removal_str[] = {
  "GTP-U/UDP/IPv4",
  "GTP-U/UDP/IPv6",
  "UDP/IPv4",
  "UDP/IPv6"
};

static u8 *
format_urr_counter(u8 * s, va_list * args)
{
  void *m = va_arg (*args, void *);
  void *t = va_arg (*args, void *);
  off_t offs = va_arg (*args, off_t);

  return format(s, "Measured: %20"PRIu64", Theshold: %20"PRIu64", Pkts: %10"PRIu64,
		*(u64 *)(m + offsetof(urr_measure_t, bytes) + offs),
		*(u64 *)(t + offs),
		*(u64 *)(m + offsetof(urr_measure_t, packets) + offs));
}

static u8 *
format_urr_quota(u8 * s, va_list * args)
{
  void *m = va_arg (*args, void *);
  void *q = va_arg (*args, void *);
  off_t offs = va_arg (*args, off_t);

  return format(s, "Consumed: %20"PRIu64", Quota:    %20"PRIu64,
		*(u64 *)(m + offsetof(urr_measure_t, consumed) + offs),
		*(u64 *)(q + offs));
}

static u8 *
format_urr_time(u8 * s, va_list * args)
{
  urr_time_t *t = va_arg (*args, urr_time_t *);
  f64 now = unix_time_now ();

  return format(s, "%20"PRIu64" secs @ %U, in %9.3f secs, handle 0x%08x",
		t->period,
		/* VPP does not support ISO dates... */
		format_time_float, 0, t->base + (f64)t->period,
		((f64)t->period) - (now - t->base), t->handle);
}

static u8 *
format_urr_time_abs(u8 * s, va_list * args)
{
  urr_time_t *t = va_arg (*args, urr_time_t *);
  f64 now = unix_time_now ();

  return format(s, "%U, in %9.3f secs, handle 0x%08x",
		/* VPP does not support ISO dates... */
		format_time_float, 0, t->base,
		t->base - now, t->handle);
}

u8 *
format_sx_session(u8 * s, va_list * args)
{
  upf_session_t *sx = va_arg (*args, upf_session_t *);
  int rule = va_arg (*args, int);
  struct rules *rules = sx_get_rules(sx, rule);
  upf_main_t *gtm = &upf_main;
  upf_pdr_t *pdr;
  upf_far_t *far;
  upf_urr_t *urr;

  s = format(s,
	     "CP F-SEID: 0x%016" PRIx64 " (%" PRIu64 ") @ %U\n"
	     "UP F-SEID: 0x%016" PRIx64 " (%" PRIu64 ") @ %U\n",
	     sx->cp_seid, sx->cp_seid, format_ip46_address, &sx->cp_address, IP46_TYPE_ANY,
	     sx->cp_seid, sx->cp_seid, format_ip46_address, &sx->up_address, IP46_TYPE_ANY,
	     sx);

  s = format(s, "  Pointer: %p\n  PDR: %p\n  FAR: %p\n",
	     sx, rules->pdr, rules->far);

  s = format(s, "  Sx Association: %u (prev:%u,next:%u)\n",
	     sx->assoc.node, sx->assoc.prev, sx->assoc.next);

  vec_foreach (pdr, rules->pdr) {
    upf_nwi_t * nwi = NULL;
    size_t j;

    if (!pool_is_free_index (gtm->nwis, pdr->pdi.nwi))
      nwi = pool_elt_at_index (gtm->nwis, pdr->pdi.nwi);

    s = format(s, "PDR: %u @ %p\n"
	       "  Precedence: %u\n"
	       "  PDI:\n"
	       "    Fields: %08x\n",
	       pdr->id, pdr,
	       pdr->precedence,
	       pdr->pdi.fields);

    if (pdr->pdi.src_intf < ARRAY_LEN (source_intf_name))
      s = format(s, "    Source Interface: %s\n", source_intf_name[pdr->pdi.src_intf]);
    else
      s = format(s, "    Source Interface: %d\n", pdr->pdi.src_intf);

    s = format(s, "    Network Instance: %U\n",
	       format_network_instance, nwi ? nwi->name : NULL);

    if (pdr->pdi.fields & F_PDI_LOCAL_F_TEID)
      {
	s = format(s, "    Local F-TEID: %u (0x%08x)\n",
		   pdr->pdi.teid.teid, pdr->pdi.teid.teid);
	if (pdr->pdi.teid.flags & F_TEID_V4)
	  s = format(s, "            IPv4: %U\n",
		     format_ip4_address, &pdr->pdi.teid.ip4);
	if (pdr->pdi.teid.flags & F_TEID_V6)
	  s = format(s, "            IPv6: %U\n",
		     format_ip6_address, &pdr->pdi.teid.ip6);
      }
    if (pdr->pdi.fields & F_PDI_UE_IP_ADDR)
      {
	s = format(s, "    UE IP address:\n");
	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
	  s = format(s, "      IPv4 address: %U\n",
		     format_ip4_address, &pdr->pdi.ue_addr.ip4);
	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
	  s = format(s, "      IPv6 address: %U\n",
		     format_ip6_address, &pdr->pdi.ue_addr.ip6);
      }
    if (pdr->pdi.fields & F_PDI_SDF_FILTER) {
      s = format(s, "    SDF Filter:\n");
      s = format(s, "      %U\n", format_ipfilter, &pdr->pdi.acl);
    }
    s = format(s, "  Outer Header Removal: %s\n"
	       "  FAR Id: %u\n"
	       "  URR Ids: [",
	       (pdr->outer_header_removal >= ARRAY_LEN(outer_header_removal_str))
	       ? "no" : outer_header_removal_str[pdr->outer_header_removal],
	       pdr->far_id);
    vec_foreach_index (j, pdr->urr_ids)
      s = format(s, "%s%u", j != 0 ? "," : "", vec_elt(pdr->urr_ids, j));
    s = format(s, "] @ %p\n", pdr->urr_ids);
  }

  vec_foreach (far, rules->far) {
    upf_nwi_t * nwi = NULL;

    if (!pool_is_free_index (gtm->nwis, far->forward.nwi))
      nwi = pool_elt_at_index (gtm->nwis, far->forward.nwi);

    s = format(s, "FAR: %u\n"
	       "  Apply Action: %08x == %U\n",
	       far->id, far->apply_action,
	       format_flags, far->apply_action, apply_action_flags);

    if (far->apply_action & FAR_FORWARD)
      {
	s = format(s, "  Forward:\n"
		   "    Network Instance: %U\n"
		   "    Destination Interface: %u\n",
		   format_network_instance, nwi ? nwi->name : NULL,
		   far->forward.dst_intf);
	if (far->forward.flags & FAR_F_OUTER_HEADER_CREATION)
	  s = format(s, "    Outer Header Creation: %U\n",
		     format_outer_header_creation, &far->forward.outer_header_creation);
      }
  }

  vec_foreach (urr, rules->urr)
    {
      s = format(s, "URR: %u\n"
		 "  Measurement Method: %04x == %U\n"
		 "  Reporting Triggers: %04x == %U\n"
		 "  Status: %d == %U\n",
		 urr->id,
		 urr->methods, format_flags, (u64)urr->methods, urr_method_flags,
		 urr->triggers, format_flags, (u64)urr->triggers, urr_trigger_flags,
		 urr->status, format_flags, (u64)urr->status, urr_status_flags);
      s = format(s, "  Start Time: %U\n", format_time_float, 0, urr->start_time);
      if (urr->methods & SX_URR_VOLUME)
	{
	  urr_volume_t *v = &urr->volume;

	  s = format(s, "  Volume\n"
		     "    Up:    %U\n           %U\n"
		     "    Down:  %U\n           %U\n"
		     "    Total: %U\n           %U\n",
		     format_urr_counter, &v->measure, &v->threshold, offsetof(urr_counter_t, ul),
		     format_urr_quota,   &v->measure, &v->quota, offsetof(urr_counter_t, ul),
		     format_urr_counter, &v->measure, &v->threshold, offsetof(urr_counter_t, dl),
		     format_urr_quota,   &v->measure, &v->quota, offsetof(urr_counter_t, dl),
		     format_urr_counter, &v->measure, &v->threshold, offsetof(urr_counter_t, total),
		     format_urr_quota,   &v->measure, &v->quota, offsetof(urr_counter_t, total));
	}
      if (urr->measurement_period.base != 0)
	{
	  s = format(s, "  Measurement Period: %U\n",
		     format_urr_time, &urr->measurement_period);
	}

      if (urr->methods & SX_URR_TIME)
	{
	  s = format(s, "  Time\n    Quota:     %U\n    Threshold: %U\n",
		     format_urr_time, &urr->time_quota,
		     format_urr_time, &urr->time_threshold);
	}
      if (urr->monitoring_time.base != 0)
	{
	  s = format(s, "  Monitoring Time: %U\n",
		     format_urr_time_abs, &urr->monitoring_time);

	  if (urr->status & URR_AFTER_MONITORING_TIME)
	    {
	      s = format(s, "  Usage Before Monitoring Time\n");
	      if (urr->methods & SX_URR_VOLUME)
		{
		  urr_measure_t *v = &urr->usage_before_monitoring_time.volume;

		  s = format(s, "    Volume\n"
			     "      Up:    %20"PRIu64", Pkts: %10"PRIu64"\n"
			     "      Down:  %20"PRIu64", Pkts: %10"PRIu64"\n"
			     "      Total: %20"PRIu64", Pkts: %10"PRIu64"\n",
			     v->bytes.ul, v->packets.ul,
			     v->bytes.dl, v->packets.dl,
			     v->bytes.total, v->packets.total);
		}
	      if (urr->methods & SX_URR_TIME)
		{
		  s = format(s, "    Start Time %U, End Time %U, %9.3f secs\n",
			     format_time_float, 0, urr->usage_before_monitoring_time.start_time,
			     format_time_float, 0, urr->start_time,
			     urr->start_time - urr->usage_before_monitoring_time.start_time);
		}
	    }
	}
    }
  return s;
}

static u8 * format_time_stamp(u8 * s, va_list * args)
{
  u32 *v = va_arg (*args, u32 *);
  struct timeval tv = { .tv_sec = *v, .tv_usec = 0};

  return format (s, "%U", format_timeval, 0, &tv);
}

u8 *
format_sx_node_association(u8 * s, va_list * args)
{
  upf_node_assoc_t *node = va_arg (*args, upf_node_assoc_t *);
  u8 verbose = va_arg (*args, int);
  upf_main_t *gtm = &upf_main;
  u32 idx = node->sessions;
  u32 i = 0;

  s = format(s,
	     "Node: %U\n"
	     "  Recovery Time Stamp: %U\n"
	     "  Sessions: ",
	     format_node_id, &node->node_id,
	     format_time_stamp, &node->recovery_time_stamp);

  while (idx != ~0)
    {
      upf_session_t * sx = pool_elt_at_index (gtm->sessions, idx);

      if (verbose)
	{
	  if (i > 0 && (i % 8) == 0)
	    s = format(s, "\n            ");

	  s = format(s, " 0x%016" PRIx64, sx->cp_seid);
	}

      i++;
      idx = sx->assoc.next;
    }

  if (verbose)
    s = format(s, "\n  %u Session(s)\n", i);
  else
    s = format(s, "%u\n", i);

  return s;
}

u8 *
format_pfcp_endpoint(u8 * s, va_list * args)
{
  upf_pfcp_endpoint_t *ep = va_arg (*args, upf_pfcp_endpoint_t *);

  s = format(s, "%U [@%u]",
	     format_ip46_address, &ep->key.addr, IP46_TYPE_ANY,
	     ep->key.fib_index);

  return s;
}

void sx_session_dump_tbls()
{
#if 0
	//TODO: implement
	const void *next_key;
	void *next_data;
	uint32_t iter;

	printf("Sx Session Hash:\n");
	iter = 0;
	while (rte_hash_iterate(rte_sx_hash, &next_key, &next_data, &iter) >= 0)
		printf("  CP F-SEID: %" PRIu64 " @ %p\n", *(uint64_t *)next_key, next_data);

	printf("Sx TEID Hash:\n");
	iter = 0;
	while (rte_hash_iterate(rte_sx_teid_hash, &next_key, &next_data, &iter) >= 0)
		printf("  CP F-SEID: %u (0x%08x) @ %p\n",
		       *(uint32_t *)next_key, *(uint32_t *)next_key, next_data);
#endif
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
