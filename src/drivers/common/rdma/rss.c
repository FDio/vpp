/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/netlink.h>
#include <rdma/common.h>
#include <errno.h>

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
}

static struct ibv_qp *
rdma_rss_qp_create (rdma_rss_t *rss, const rdma_rss_caps_t *caps, const vnet_dev_rss_config_t *cfg,
		    u64 hash_fields)
{
  struct ibv_qp_init_attr_ex qpia = {
    .qp_type = IBV_QPT_RAW_PACKET,
    .comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_IND_TABLE | IBV_QP_INIT_ATTR_RX_HASH,
    .pd = caps->pd,
    .rwq_ind_tbl = rss->rwq_ind_tbl,
    .rx_hash_conf = {
      .rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ,
      .rx_hash_key_len = cfg->key_len,
      .rx_hash_key = (u8 *) cfg->key,
      .rx_hash_fields_mask = hash_fields,
    },
  };

  return ibv_create_qp_ex (caps->ctx, &qpia);
}

vnet_dev_rv_t
rdma_rss_enable (rdma_rss_t *rss, const rdma_rss_caps_t *caps, struct ibv_wq **wqs,
		 const vnet_dev_rss_config_t *cfg)
{
  struct ibv_wq **ind_tbl = 0;
  struct ibv_rwq_ind_table_init_attr rwqia = {};
  u64 ip4 = IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4;
  u64 ip6 = IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 n_ind, n_rxq = vec_len (wqs);
  u8 use_lut = cfg->set_lut;

  if (use_lut)
    for (u32 i = 0; i < cfg->lut_len; i++)
      if (cfg->lut[i] >= n_rxq || wqs[cfg->lut[i]] == 0)
	use_lut = 0;

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
    rss->qp[RDMA_RSS_DEFAULT].qp = rdma_rss_qp_create (rss, caps, cfg, 0);
  else
    {
      if ((caps->hash_function & IBV_RX_HASH_FUNC_TOEPLITZ) == 0 ||
	  (caps->hash_fields_mask & ip4) != ip4)
	{
	  errno = EOPNOTSUPP;
	  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
	  goto done;
	}
      rss->qp[RDMA_RSS_DEFAULT].qp = rdma_rss_qp_create (rss, caps, cfg, ip4);
      if ((caps->hash_fields_mask & ip6) == ip6)
	{
	  rss->qp[RDMA_RSS_IP6].qp = rdma_rss_qp_create (rss, caps, cfg, ip6);
	  if (rss->qp[RDMA_RSS_IP6].qp == 0)
	    rv = VNET_DEV_ERR_INIT_FAILED;
	}
    }

  if (rss->qp[RDMA_RSS_DEFAULT].qp == 0)
    rv = VNET_DEV_ERR_INIT_FAILED;

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
      u8 ip6 = i == RDMA_RSS_IP6;

      if (q->qp == 0)
	continue;
      rv = rdma_program_flow_state (q->qp, &q->flows, &q->ucast_flows, &q->promisc_flow_index,
				    &q->mcast_flow_index, addrs, promisc, port->port_id,
				    ip6 ? ETHERNET_TYPE_IP6 : 0, ip6 ? 0 : 1, ip6 == 0);
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

void
rdma_rss_cfg_merge (vnet_dev_rss_config_t *cfg, const vnet_dev_rss_config_t *req)
{
  if (req->set_key)
    {
      clib_memcpy (cfg->key, req->key, sizeof (cfg->key));
      cfg->key_len = req->key_len;
    }
  if (req->set_lut)
    {
      clib_memcpy (cfg->lut, req->lut, sizeof (cfg->lut));
      cfg->lut_len = req->lut_len;
      cfg->set_lut = 1;
    }
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
