/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/netlink.h>
#include <rdma/common.h>
#include <errno.h>

static const struct
{
  vnet_dev_rss_class_t class;
  rdma_flow_match_t match;
  u16 priority;
} rss_qps[] = {
#define _(n, s, c, e, l4, pr, t, ie, il4, p)                                                       \
  [RDMA_RSS_##n] = {                                                                               \
    .class = VNET_DEV_RSS_CLASS_##c,                                                               \
    .match = {                                                                                     \
      .ether_type = (e),                                                                           \
      .l4_spec_type = (l4),                                                                        \
      .ip_proto = (pr),                                                                            \
      .tunnel = RDMA_TUNNEL_##t,                                                                   \
      .inner_ether_type = (ie),                                                                    \
      .inner_l4_spec_type = (il4),                                                                 \
    },                                                                                             \
    .priority = (p),                                                                               \
  },
  foreach_rdma_rss_qp
#undef _
};

/* hash fields of a qp, with inner those of the inner headers for qps which match them */
static u64
rss_hash_fields (u32 qp, vnet_dev_rss_fields_t f)
{
  const rdma_flow_match_t *m = &rss_qps[qp].match;
  u8 inner = f.inner && m->inner_ether_type;
  u8 ip6 = (inner ? m->inner_ether_type : m->ether_type) == ETHERNET_TYPE_IP6;
  u8 l4 = inner ? m->inner_l4_spec_type : m->l4_spec_type;
  u64 h = 0;

  if (f.src_ip)
    h |= ip6 ? IBV_RX_HASH_SRC_IPV6 : IBV_RX_HASH_SRC_IPV4;
  if (f.dst_ip)
    h |= ip6 ? IBV_RX_HASH_DST_IPV6 : IBV_RX_HASH_DST_IPV4;
  if (f.src_port && l4 == IBV_FLOW_SPEC_TCP)
    h |= IBV_RX_HASH_SRC_PORT_TCP;
  if (f.dst_port && l4 == IBV_FLOW_SPEC_TCP)
    h |= IBV_RX_HASH_DST_PORT_TCP;
  if (f.src_port && l4 == IBV_FLOW_SPEC_UDP)
    h |= IBV_RX_HASH_SRC_PORT_UDP;
  if (f.dst_port && l4 == IBV_FLOW_SPEC_UDP)
    h |= IBV_RX_HASH_DST_PORT_UDP;
  if (inner && h)
    h |= IBV_RX_HASH_INNER;

  return h;
}

/* a qp which can't hash on its addresses, or on the inner ones if it matches inner headers, is
 * not created, its traffic goes to the qp it falls back to */
static int
rss_qp_supported (u32 qp, u64 hash_fields_mask)
{
  vnet_dev_rss_fields_t f = { .as_u32 = VNET_DEV_RSS_FIELDS_2_TUPLE };

  f.inner = rss_qps[qp].match.inner_ether_type != 0;
  return qp == RDMA_RSS_IP4 || (rss_hash_fields (qp, f) & ~hash_fields_mask) == 0;
}

static int
rss_match_equal (const rdma_flow_match_t *a, const rdma_flow_match_t *b)
{
  return a->ether_type == b->ether_type && a->l4_spec_type == b->l4_spec_type &&
	 a->ip_proto == b->ip_proto && a->tunnel == b->tunnel &&
	 a->inner_ether_type == b->inner_ether_type &&
	 a->inner_l4_spec_type == b->inner_l4_spec_type;
}

/* the qp which takes the traffic of a qp when it doesn't exist, it comes earlier in the table */
static u32
rss_qp_fallback (u32 qp)
{
  rdma_flow_match_t m = rss_qps[qp].match;

  if (m.inner_l4_spec_type)
    m.inner_l4_spec_type = 0;
  else if (m.inner_ether_type && m.tunnel != RDMA_TUNNEL_NONE)
    m.inner_ether_type = 0;
  else if (m.tunnel == RDMA_TUNNEL_VXLAN)
    m = (rdma_flow_match_t) { .ether_type = m.ether_type, .l4_spec_type = m.l4_spec_type };
  else if (m.ether_type == ETHERNET_TYPE_IP6 && (m.l4_spec_type || m.ip_proto || m.tunnel))
    return RDMA_RSS_IP6;
  else
    return RDMA_RSS_IP4;

  for (u32 i = 0; i < qp; i++)
    if (rss_match_equal (&rss_qps[i].match, &m))
      return i;

  ASSERT (0);
  return RDMA_RSS_IP4;
}

static int
rss_class_covers (vnet_dev_rss_class_t class, vnet_dev_rss_class_t c)
{
  while (c != class && c != VNET_DEV_RSS_CLASS_DEFAULT)
    c = vnet_dev_rss_class_parent (c);
  return c == class;
}

/* a class offers the fields its qps can hash: addresses, ports of qps which match a transport
 * and inner for qps which match inner headers. Any combination works, a class without fields
 * uses a one entry table */
vnet_dev_rss_caps_t
rdma_rss_dev_caps (u64 hash_fields_mask, u32 hash_function)
{
  vnet_dev_rss_fields_t ip = { .as_u32 = VNET_DEV_RSS_FIELDS_2_TUPLE };
  u32 fields[VNET_DEV_RSS_N_CLASSES] = {};
  vnet_dev_rss_caps_t caps = {};

  if ((hash_function & IBV_RX_HASH_FUNC_TOEPLITZ) == 0 ||
      (rss_hash_fields (RDMA_RSS_IP4, ip) & ~hash_fields_mask))
    return caps;

  for (u32 i = 0; i < RDMA_RSS_N_QP; i++)
    {
      const rdma_flow_match_t *m = &rss_qps[i].match;
      vnet_dev_rss_fields_t f = ip;

      if (!rss_qp_supported (i, hash_fields_mask))
	continue;

      f.inner = m->inner_ether_type != 0;
      if (m->l4_spec_type || m->inner_l4_spec_type)
	{
	  vnet_dev_rss_fields_t p = f;

	  p.src_port = p.dst_port = 1;
	  if ((rss_hash_fields (i, p) & ~hash_fields_mask) == 0)
	    f = p;
	}

      for (u32 c = 0; c < VNET_DEV_RSS_N_CLASSES; c++)
	if (rss_class_covers (c, rss_qps[i].class))
	  fields[c] |= f.as_u32;
    }

  /* default, non-IP traffic, is not hashed */
  for (u32 c = 0; c < VNET_DEV_RSS_N_CLASSES; c++)
    if (fields[c] && c != VNET_DEV_RSS_CLASS_DEFAULT)
      caps.classes[c] = (vnet_dev_rss_class_caps_t) VNET_DEV_RSS_CLASS_CAPS_ANY (fields[c], 1);

  caps.functions = VNET_DEV_RSS_FUNCTION (TOEPLITZ);
  return caps;
}

void
rdma_rss_init (rdma_rss_t *rss)
{
  *rss = (rdma_rss_t) {};
  for (u32 i = 0; i < ARRAY_LEN (rss->qp); i++)
    {
      rss->qp[i].promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      rss->qp[i].mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
    }
}

void
rdma_rss_disable (rdma_rss_t *rss)
{
  for (u32 i = 0; i < ARRAY_LEN (rss->qp); i++)
    {
      rdma_rss_qp_t *q = rss->qp + i;

      rdma_rxq_destroy_flows (&q->flows);
      vec_free (q->ucast_flows);
      q->promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      q->mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
      if (q->qp)
	ibv_destroy_qp (q->qp);
      q->qp = 0;
    }

  if (rss->rwq_ind_tbl)
    ibv_destroy_rwq_ind_table (rss->rwq_ind_tbl);
  rss->rwq_ind_tbl = 0;
  if (rss->rwq_ind_tbl_first)
    ibv_destroy_rwq_ind_table (rss->rwq_ind_tbl_first);
  rss->rwq_ind_tbl_first = 0;
}

static struct ibv_qp *
rdma_rss_qp_create (struct ibv_rwq_ind_table *ind_tbl, const rdma_rss_caps_t *caps,
		    const vnet_dev_rss_config_t *cfg, u64 hash_fields)
{
  struct ibv_qp_init_attr_ex qpia = {
    .qp_type = IBV_QPT_RAW_PACKET,
    .comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_IND_TABLE | IBV_QP_INIT_ATTR_RX_HASH,
    .pd = caps->pd,
    .rwq_ind_tbl = ind_tbl,
    .rx_hash_conf = {
      .rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ,
      .rx_hash_key_len = cfg->key_len,
      .rx_hash_key = (u8 *) cfg->key,
      .rx_hash_fields_mask = hash_fields,
    },
  };

  if (caps->create_qp)
    return caps->create_qp (caps->ctx, &qpia);
  return ibv_create_qp_ex (caps->ctx, &qpia);
}

vnet_dev_rv_t
rdma_rss_enable (rdma_rss_t *rss, const rdma_rss_caps_t *caps, struct ibv_wq **wqs,
		 const vnet_dev_rss_config_t *cfg)
{
  struct ibv_wq **ind_tbl = 0;
  struct ibv_rwq_ind_table_init_attr rwqia = {};
  u64 effective[RDMA_RSS_N_QP];
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 n_ind, n_rxq = vec_len (wqs);
  u8 use_lut = cfg->set_lut;

  if (use_lut)
    for (u32 i = 0; i < cfg->lut_len; i++)
      if (cfg->lut[i] >= n_rxq || wqs[cfg->lut[i]] == 0)
	use_lut = 0;

  if (n_rxq == 0)
    return VNET_DEV_ERR_INVALID_NUM_RX_QUEUES;

  if (n_rxq == 1)
    n_ind = 1;
  else if (use_lut)
    n_ind = cfg->lut_len;
  else
    n_ind = clib_min (1 << max_log2 (n_rxq * 16), VNET_DEV_RSS_LUT_MAX_SIZE);
  n_ind = clib_min (n_ind, caps->max_ind_tbl_size);

  vec_validate (ind_tbl, n_ind - 1);
  for (u32 i = 0; i < n_ind; i++)
    ind_tbl[i] = use_lut ? wqs[cfg->lut[i]] : wqs[i % n_rxq];

  rwqia.log_ind_tbl_size = min_log2 (n_ind);
  rwqia.ind_tbl = ind_tbl;
  rss->rwq_ind_tbl = ibv_create_rwq_ind_table (caps->ctx, &rwqia);
  if (rss->rwq_ind_tbl == 0)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  if (n_rxq == 1)
    {
      rss->qp[RDMA_RSS_IP4].qp = rdma_rss_qp_create (rss->rwq_ind_tbl, caps, cfg, 0);
      if (rss->qp[RDMA_RSS_IP4].qp == 0)
	rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }

  if ((caps->hash_function & IBV_RX_HASH_FUNC_TOEPLITZ) == 0)
    {
      errno = EOPNOTSUPP;
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  for (u32 i = 0; i < RDMA_RSS_N_QP; i++)
    {
      u64 h = rss_hash_fields (i, vnet_dev_rss_class_fields (cfg, rss_qps[i].class));

      /* a qp is only needed if it hashes differently than the qp taking its traffic otherwise */
      if (i != RDMA_RSS_IP4 && (!rss_qp_supported (i, caps->hash_fields_mask) ||
				(i != RDMA_RSS_IP6 && h == effective[rss_qp_fallback (i)])))
	{
	  effective[i] = effective[rss_qp_fallback (i)];
	  continue;
	}

      effective[i] = h;

      if (h & ~caps->hash_fields_mask)
	{
	  errno = EOPNOTSUPP;
	  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
	  goto done;
	}

      /* mlx5 doesn't take a qp without hash fields on a table with more than one entry */
      if (h == 0 && rss->rwq_ind_tbl_first == 0)
	{
	  rwqia.log_ind_tbl_size = 0;
	  rss->rwq_ind_tbl_first = ibv_create_rwq_ind_table (caps->ctx, &rwqia);
	  if (rss->rwq_ind_tbl_first == 0)
	    {
	      rv = VNET_DEV_ERR_INIT_FAILED;
	      goto done;
	    }
	}

      rss->qp[i].qp =
	rdma_rss_qp_create (h ? rss->rwq_ind_tbl : rss->rwq_ind_tbl_first, caps, cfg, h);
      if (rss->qp[i].qp == 0)
	{
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto done;
	}
    }

done:
  if (rv != VNET_DEV_OK)
    rdma_rss_disable (rss);
  vec_free (ind_tbl);
  return rv;
}

vnet_dev_rv_t
rdma_rss_program_flows (rdma_rss_t *rss, vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_hw_addr_t *addrs = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 promisc = port->promisc;

  if (req && req->type == VNET_DEV_PORT_CFG_PROMISC_MODE)
    promisc = req->promisc;

  if (promisc == 0)
    rdma_port_collect_addrs (port, req, &addrs);

  for (u32 i = 0; i < ARRAY_LEN (rss->qp) && rv == VNET_DEV_OK; i++)
    {
      rdma_rss_qp_t *q = rss->qp + i;

      if (q->qp == 0)
	continue;
      rv = rdma_program_flow_state (q->qp, &q->flows, &q->ucast_flows, &q->promisc_flow_index,
				    &q->mcast_flow_index, addrs, promisc, port->port_id,
				    &rss_qps[i].match, rss_qps[i].priority, i == RDMA_RSS_IP4);
    }

  vec_free (addrs);
  return rv;
}

vnet_dev_rv_t
rdma_rss_cfg_validate (const rdma_rss_caps_t *caps, const vnet_dev_rss_config_t *req)
{
  if ((req->set_key && req->key_len != RDMA_RSS_KEY_SIZE) ||
      (req->set_lut && !is_pow2 (req->lut_len)))
    return VNET_DEV_ERR_INVALID_DATA;
  if (req->set_lut && req->lut_len > caps->max_ind_tbl_size)
    return VNET_DEV_ERR_INVALID_VALUE;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
rdma_netdev_set_mtu (u32 ifindex, u32 max_rx_frame_size, clib_error_t **errp)
{
  u32 mtu = max_rx_frame_size - RDMA_NETDEV_MTU_OVERHEAD, cur_mtu = 0;
  clib_error_t *err;

  err = vnet_netlink_get_link_mtu (ifindex, &cur_mtu);
  if (err == 0 && cur_mtu == mtu)
    return VNET_DEV_OK;
  clib_error_free (err);

  *errp = vnet_netlink_set_link_mtu (ifindex, mtu);
  return *errp ? VNET_DEV_ERR_INTERNAL : VNET_DEV_OK;
}
