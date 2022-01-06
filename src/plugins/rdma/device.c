/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>

#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>

#include <rdma/rdma.h>

/* Default RSS hash key (from DPDK MLX driver) */
static u8 rdma_rss_hash_key[] = {
  0x2c, 0xc6, 0x81, 0xd1,
  0x5b, 0xdb, 0xf4, 0xf7,
  0xfc, 0xa2, 0x83, 0x19,
  0xdb, 0x1a, 0x3e, 0x94,
  0x6b, 0x9e, 0x38, 0xd9,
  0x2c, 0x9c, 0x03, 0xd1,
  0xad, 0x99, 0x44, 0xa7,
  0xd9, 0x56, 0x3d, 0x59,
  0x06, 0x3c, 0x25, 0xf3,
  0xfc, 0x1f, 0xdc, 0x2a,
};

rdma_main_t rdma_main;

/* (dev) is of type (rdma_device_t *) */
#define rdma_log__(lvl, dev, f, ...)                                          \
  do                                                                          \
    {                                                                         \
      vlib_log ((lvl), rdma_main.log_class, "%s: " f, (dev)->name,            \
		##__VA_ARGS__);                                               \
    }                                                                         \
  while (0)

#define rdma_log(lvl, dev, f, ...) \
   rdma_log__((lvl), (dev), "%s (%d): " f, strerror(errno), errno, ##__VA_ARGS__)

static struct ibv_flow *
rdma_rxq_init_flow (const rdma_device_t * rd, struct ibv_qp *qp,
		    const mac_address_t * mac, const mac_address_t * mask,
		    u16 ether_type, u32 flags)
{
  struct ibv_flow *flow;
  struct raw_eth_flow_attr
  {
    struct ibv_flow_attr attr;
    struct ibv_flow_spec_eth spec_eth;
  } __attribute__ ((packed)) fa;

  memset (&fa, 0, sizeof (fa));
  fa.attr.num_of_specs = 1;
  fa.attr.port = 1;
  fa.attr.flags = flags;
  fa.spec_eth.type = IBV_FLOW_SPEC_ETH;
  fa.spec_eth.size = sizeof (struct ibv_flow_spec_eth);

  memcpy (fa.spec_eth.val.dst_mac, mac, sizeof (fa.spec_eth.val.dst_mac));
  memcpy (fa.spec_eth.mask.dst_mac, mask, sizeof (fa.spec_eth.mask.dst_mac));

  if (ether_type)
    {
      fa.spec_eth.val.ether_type = ether_type;
      fa.spec_eth.mask.ether_type = 0xffff;
    }

  flow = ibv_create_flow (qp, &fa.attr);
  if (!flow)
    rdma_log (VLIB_LOG_LEVEL_ERR, rd, "ibv_create_flow() failed");
  return flow;
}

static u32
rdma_rxq_destroy_flow (const rdma_device_t * rd, struct ibv_flow **flow)
{
  if (!*flow)
    return 0;

  if (ibv_destroy_flow (*flow))
    {
      rdma_log (VLIB_LOG_LEVEL_ERR, rd, "ibv_destroy_flow() failed");
      return ~0;
    }

  *flow = 0;
  return 0;
}

static u32
rdma_dev_set_promisc (rdma_device_t * rd)
{
  const mac_address_t all = {.bytes = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0} };
  int err;

  err = rdma_rxq_destroy_flow (rd, &rd->flow_mcast6);
  err |= rdma_rxq_destroy_flow (rd, &rd->flow_ucast6);
  err |= rdma_rxq_destroy_flow (rd, &rd->flow_mcast4);
  err |= rdma_rxq_destroy_flow (rd, &rd->flow_ucast4);
  if (err)
    return ~0;

  rd->flow_ucast6 =
    rdma_rxq_init_flow (rd, rd->rx_qp6, &all, &all, ntohs (ETH_P_IPV6), 0);
  rd->flow_ucast4 = rdma_rxq_init_flow (rd, rd->rx_qp4, &all, &all, 0, 0);
  if (!rd->flow_ucast6 || !rd->flow_ucast4)
    return ~0;

  rd->flags |= RDMA_DEVICE_F_PROMISC;
  return 0;
}

static u32
rdma_dev_set_ucast (rdma_device_t * rd)
{
  const mac_address_t ucast = {.bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
  };
  const mac_address_t mcast = {.bytes = {0x1, 0x0, 0x0, 0x0, 0x0, 0x0} };
  int err;

  err = rdma_rxq_destroy_flow (rd, &rd->flow_mcast6);
  err |= rdma_rxq_destroy_flow (rd, &rd->flow_ucast6);
  err |= rdma_rxq_destroy_flow (rd, &rd->flow_mcast4);
  err |= rdma_rxq_destroy_flow (rd, &rd->flow_ucast4);
  if (err)
    return ~0;

  rd->flow_ucast6 =
    rdma_rxq_init_flow (rd, rd->rx_qp6, &rd->hwaddr, &ucast,
			ntohs (ETH_P_IPV6), 0);
  rd->flow_mcast6 =
    rdma_rxq_init_flow (rd, rd->rx_qp6, &mcast, &mcast, ntohs (ETH_P_IPV6),
			IBV_FLOW_ATTR_FLAGS_DONT_TRAP
			/* let others receive mcast packet too (eg. Linux) */
    );
  rd->flow_ucast4 =
    rdma_rxq_init_flow (rd, rd->rx_qp4, &rd->hwaddr, &ucast, 0, 0);
  rd->flow_mcast4 =
    rdma_rxq_init_flow (rd, rd->rx_qp4, &mcast, &mcast, 0,
			IBV_FLOW_ATTR_FLAGS_DONT_TRAP
			/* let others receive mcast packet too (eg. Linux) */
    );
  if (!rd->flow_ucast6 || !rd->flow_mcast6 || !rd->flow_ucast4
      || !rd->flow_mcast4)
    return ~0;

  rd->flags &= ~RDMA_DEVICE_F_PROMISC;
  return 0;
}

static clib_error_t *
rdma_mac_change (vnet_hw_interface_t * hw, const u8 * old, const u8 * new)
{
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, hw->dev_instance);
  mac_address_from_bytes (&rd->hwaddr, new);
  if (!(rd->flags & RDMA_DEVICE_F_PROMISC) && rdma_dev_set_ucast (rd))
    {
      mac_address_from_bytes (&rd->hwaddr, old);
      return clib_error_return_unix (0, "MAC update failed");
    }
  return 0;
}

static clib_error_t *
rdma_set_mtu (vnet_main_t *vnm, vnet_hw_interface_t *hw, u32 mtu)
{
  return vnet_error (VNET_ERR_UNSUPPORTED, 0);
}

static u32
rdma_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, hw->dev_instance);

  switch (flags)
    {
    case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
      return rdma_dev_set_ucast (rd);
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      return rdma_dev_set_promisc (rd);
    }

  rdma_log__ (VLIB_LOG_LEVEL_ERR, rd, "unknown flag %x requested", flags);
  return ~0;
}

static void
rdma_update_state (vnet_main_t * vnm, rdma_device_t * rd, int port)
{
  struct ibv_port_attr attr;
  u32 width = 0;
  u32 speed = 0;

  if (ibv_query_port (rd->ctx, port, &attr))
    {
      vnet_hw_interface_set_link_speed (vnm, rd->hw_if_index, 0);
      vnet_hw_interface_set_flags (vnm, rd->hw_if_index, 0);
      return;
    }

  /* update state */
  switch (attr.state)
    {
    case IBV_PORT_ACTIVE:	/* fallthrough */
    case IBV_PORT_ACTIVE_DEFER:
      rd->flags |= RDMA_DEVICE_F_LINK_UP;
      vnet_hw_interface_set_flags (vnm, rd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      break;
    default:
      rd->flags &= ~RDMA_DEVICE_F_LINK_UP;
      vnet_hw_interface_set_flags (vnm, rd->hw_if_index, 0);
      break;
    }

  /* update speed */
  switch (attr.active_width)
    {
    case 1:
      width = 1;
      break;
    case 2:
      width = 4;
      break;
    case 4:
      width = 8;
      break;
    case 8:
      width = 12;
      break;
    }
  switch (attr.active_speed)
    {
    case 1:
      speed = 2500000;
      break;
    case 2:
      speed = 5000000;
      break;
    case 4:			/* fallthrough */
    case 8:
      speed = 10000000;
      break;
    case 16:
      speed = 14000000;
      break;
    case 32:
      speed = 25000000;
      break;
    }
  vnet_hw_interface_set_link_speed (vnm, rd->hw_if_index, width * speed);
}

static clib_error_t *
rdma_async_event_error_ready (clib_file_t * f)
{
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, f->private_data);
  return clib_error_return (0, "RDMA: %s: async event error", rd->name);
}

static clib_error_t *
rdma_async_event_read_ready (clib_file_t * f)
{
  vnet_main_t *vnm = vnet_get_main ();
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, f->private_data);
  int ret;
  struct ibv_async_event event;
  ret = ibv_get_async_event (rd->ctx, &event);
  if (ret < 0)
    return clib_error_return_unix (0, "ibv_get_async_event() failed");

  switch (event.event_type)
    {
    case IBV_EVENT_PORT_ACTIVE:
      rdma_update_state (vnm, rd, event.element.port_num);
      break;
    case IBV_EVENT_PORT_ERR:
      rdma_update_state (vnm, rd, event.element.port_num);
      break;
    case IBV_EVENT_DEVICE_FATAL:
      rd->flags &= ~RDMA_DEVICE_F_LINK_UP;
      vnet_hw_interface_set_flags (vnm, rd->hw_if_index, 0);
      vlib_log_emerg (rm->log_class, "%s: fatal error", rd->name);
      break;
    default:
      rdma_log__ (VLIB_LOG_LEVEL_ERR, rd, "unhandeld RDMA async event %d",
		  event.event_type);
      break;
    }

  ibv_ack_async_event (&event);
  return 0;
}

static clib_error_t *
rdma_async_event_init (rdma_device_t * rd)
{
  clib_file_t t = { 0 };
  int ret;

  /* make RDMA async event fd non-blocking */
  ret = fcntl (rd->ctx->async_fd, F_GETFL);
  if (ret < 0)
    return clib_error_return_unix (0, "fcntl(F_GETFL) failed");

  ret = fcntl (rd->ctx->async_fd, F_SETFL, ret | O_NONBLOCK);
  if (ret < 0)
    return clib_error_return_unix (0, "fcntl(F_SETFL, O_NONBLOCK) failed");

  /* register RDMA async event fd */
  t.read_function = rdma_async_event_read_ready;
  t.file_descriptor = rd->ctx->async_fd;
  t.error_function = rdma_async_event_error_ready;
  t.private_data = rd->dev_instance;
  t.description = format (0, "%v async event", rd->name);

  rd->async_event_clib_file_index = clib_file_add (&file_main, &t);
  return 0;
}

static void
rdma_async_event_cleanup (rdma_device_t * rd)
{
  clib_file_del_by_index (&file_main, rd->async_event_clib_file_index);
}

static clib_error_t *
rdma_register_interface (vnet_main_t * vnm, rdma_device_t * rd)
{
  vnet_eth_interface_registration_t eir = {};

  eir.dev_class_index = rdma_device_class.index;
  eir.dev_instance = rd->dev_instance;
  eir.address = rd->hwaddr.bytes;
  eir.cb.flag_change = rdma_flag_change;
  eir.cb.set_mtu = rdma_set_mtu;
  rd->hw_if_index = vnet_eth_register_interface (vnm, &eir);
  /* Indicate ability to support L3 DMAC filtering and
   * initialize interface to L3 non-promisc mode */
  vnet_hw_if_set_caps (vnm, rd->hw_if_index, VNET_HW_IF_CAP_MAC_FILTER);
  ethernet_set_flags (vnm, rd->hw_if_index,
		      ETHERNET_INTERFACE_FLAG_DEFAULT_L3);
  return 0;
}

static void
rdma_unregister_interface (vnet_main_t * vnm, rdma_device_t * rd)
{
  vnet_hw_interface_set_flags (vnm, rd->hw_if_index, 0);
  ethernet_delete_interface (vnm, rd->hw_if_index);
}

static void
rdma_dev_cleanup (rdma_device_t * rd)
{
  rdma_main_t *rm = &rdma_main;
  rdma_rxq_t *rxq;
  rdma_txq_t *txq;

#define _(fn, arg) if (arg) \
  { \
    int rv; \
    if ((rv = fn (arg))) \
       rdma_log (VLIB_LOG_LEVEL_DEBUG, rd, #fn "() failed (rv = %d)", rv); \
  }

  _(ibv_destroy_flow, rd->flow_mcast6);
  _(ibv_destroy_flow, rd->flow_ucast6);
  _(ibv_destroy_flow, rd->flow_mcast4);
  _(ibv_destroy_flow, rd->flow_ucast4);
  _(ibv_dereg_mr, rd->mr);
  vec_foreach (txq, rd->txqs)
  {
    _(ibv_destroy_qp, txq->qp);
    _(ibv_destroy_cq, txq->cq);
  }
  vec_foreach (rxq, rd->rxqs)
  {
    _(ibv_destroy_wq, rxq->wq);
    _(ibv_destroy_cq, rxq->cq);
  }
  _(ibv_destroy_rwq_ind_table, rd->rx_rwq_ind_tbl);
  _(ibv_destroy_qp, rd->rx_qp6);
  _(ibv_destroy_qp, rd->rx_qp4);
  _(ibv_dealloc_pd, rd->pd);
  _(ibv_close_device, rd->ctx);
#undef _

  clib_error_free (rd->error);

  vec_free (rd->rxqs);
  vec_free (rd->txqs);
  vec_free (rd->name);
  vlib_pci_free_device_info (rd->pci);
  pool_put (rm->devices, rd);
}

static clib_error_t *
rdma_rxq_init (vlib_main_t * vm, rdma_device_t * rd, u16 qid, u32 n_desc,
	       u8 no_multi_seg, u16 max_pktlen)
{
  rdma_rxq_t *rxq;
  struct ibv_wq_init_attr wqia;
  struct ibv_cq_init_attr_ex cqa = { };
  struct ibv_wq_attr wqa;
  struct ibv_cq_ex *cqex;
  struct mlx5dv_wq_init_attr dv_wqia = { };
  int is_mlx5dv = ! !(rd->flags & RDMA_DEVICE_F_MLX5DV);
  int is_striding = ! !(rd->flags & RDMA_DEVICE_F_STRIDING_RQ);

  vec_validate_aligned (rd->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (rd->rxqs, qid);
  rxq->size = n_desc;
  rxq->log_wqe_sz = 0;
  rxq->buf_sz = vlib_buffer_get_default_data_size (vm);
  vec_validate_aligned (rxq->bufs, n_desc - 1, CLIB_CACHE_LINE_BYTES);

  cqa.cqe = n_desc;
  if (is_mlx5dv)
    {
      struct mlx5dv_cq_init_attr dvcq = { };
      dvcq.comp_mask = MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE;
      dvcq.cqe_comp_res_format = MLX5DV_CQE_RES_FORMAT_HASH;

      if ((cqex = mlx5dv_create_cq (rd->ctx, &cqa, &dvcq)) == 0)
	return clib_error_return_unix (0, "Create mlx5dv rx CQ Failed");
    }
  else
    {
      if ((cqex = ibv_create_cq_ex (rd->ctx, &cqa)) == 0)
	return clib_error_return_unix (0, "Create CQ Failed");
    }

  rxq->cq = ibv_cq_ex_to_cq (cqex);

  memset (&wqia, 0, sizeof (wqia));
  wqia.wq_type = IBV_WQT_RQ;
  wqia.max_wr = n_desc;
  wqia.max_sge = 1;
  wqia.pd = rd->pd;
  wqia.cq = rxq->cq;
  if (is_mlx5dv)
    {
      if (is_striding)
	{
	  /* In STRIDING_RQ mode, map a descriptor to a stride, not a full WQE buffer */
	  uword data_seg_log2_sz =
	    min_log2 (vlib_buffer_get_default_data_size (vm));
	  rxq->buf_sz = 1 << data_seg_log2_sz;
	  /* The trick is also to map a descriptor to a data segment in the WQE SG list
	     The number of strides per WQE and the size of a WQE (in 16-bytes words) both
	     must be powers of two.
	     Moreover, in striding RQ mode, WQEs must include the SRQ header, which occupies
	     one 16-bytes word. That is why WQEs have 2*RDMA_RXQ_MAX_CHAIN_SZ 16-bytes words:
	     - One for the SRQ Header
	     - RDMA_RXQ_MAX_CHAIN_SZ for the different data segments (each mapped to
	     a stride, and a vlib_buffer)
	     - RDMA_RXQ_MAX_CHAIN_SZ-1 null data segments
	   */
	  int max_chain_log_sz =
	    max_pktlen ? max_log2 ((max_pktlen /
				    (rxq->buf_sz)) +
				   1) : RDMA_RXQ_MAX_CHAIN_LOG_SZ;
	  max_chain_log_sz = clib_max (max_chain_log_sz, 3);
	  wqia.max_sge = 1 << max_chain_log_sz;
	  dv_wqia.comp_mask = MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ;
	  dv_wqia.striding_rq_attrs.two_byte_shift_en = 0;
	  dv_wqia.striding_rq_attrs.single_wqe_log_num_of_strides =
	    max_chain_log_sz;
	  dv_wqia.striding_rq_attrs.single_stride_log_num_of_bytes =
	    data_seg_log2_sz;
	  wqia.max_wr >>= max_chain_log_sz;
	  rxq->log_wqe_sz = max_chain_log_sz + 1;
	  rxq->log_stride_per_wqe = max_chain_log_sz;
	}
      else
	{
	  /* In non STRIDING_RQ mode and if multiseg is not disabled, each WQE is a SG list of data
	     segments, each pointing to a vlib_buffer.  */
	  if (no_multi_seg)
	    {
	      wqia.max_sge = 1;
	      rxq->log_wqe_sz = 0;
	      rxq->n_ds_per_wqe = 1;
	    }
	  else
	    {
	      int max_chain_sz =
		max_pktlen ? (max_pktlen /
			      (rxq->buf_sz)) +
		1 : RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ;
	      int max_chain_log_sz = max_log2 (max_chain_sz);
	      wqia.max_sge = 1 << max_chain_log_sz;
	      rxq->log_wqe_sz = max_chain_log_sz;
	      rxq->n_ds_per_wqe = max_chain_sz;
	    }

	}

      if ((rxq->wq = mlx5dv_create_wq (rd->ctx, &wqia, &dv_wqia)))
	{
	  rxq->wq->events_completed = 0;
	  pthread_mutex_init (&rxq->wq->mutex, NULL);
	  pthread_cond_init (&rxq->wq->cond, NULL);
	}
      else
	return clib_error_return_unix (0, "Create WQ Failed");
    }
  else if ((rxq->wq = ibv_create_wq (rd->ctx, &wqia)) == 0)
    return clib_error_return_unix (0, "Create WQ Failed");

  memset (&wqa, 0, sizeof (wqa));
  wqa.attr_mask = IBV_WQ_ATTR_STATE;
  wqa.wq_state = IBV_WQS_RDY;
  if (ibv_modify_wq (rxq->wq, &wqa) != 0)
    return clib_error_return_unix (0, "Modify WQ (RDY) Failed");

  if (is_mlx5dv)
    {
      struct mlx5dv_obj obj = { };
      struct mlx5dv_cq dv_cq;
      struct mlx5dv_rwq dv_rwq;
      u64 qw0;
      u64 qw0_nullseg;
      u32 wqe_sz_mask = (1 << rxq->log_wqe_sz) - 1;

      obj.cq.in = rxq->cq;
      obj.cq.out = &dv_cq;
      obj.rwq.in = rxq->wq;
      obj.rwq.out = &dv_rwq;

      if ((mlx5dv_init_obj (&obj, MLX5DV_OBJ_CQ | MLX5DV_OBJ_RWQ)))
	return clib_error_return_unix (0, "mlx5dv: failed to init rx obj");

      if (dv_cq.cqe_size != sizeof (mlx5dv_cqe_t))
	return clib_error_return_unix (0, "mlx5dv: incompatible rx CQE size");

      rxq->log2_cq_size = max_log2 (dv_cq.cqe_cnt);
      rxq->cqes = (mlx5dv_cqe_t *) dv_cq.buf;
      rxq->cq_db = (volatile u32 *) dv_cq.dbrec;
      rxq->cqn = dv_cq.cqn;

      rxq->wqes = (mlx5dv_wqe_ds_t *) dv_rwq.buf;
      rxq->wq_db = (volatile u32 *) dv_rwq.dbrec;
      rxq->wq_stride = dv_rwq.stride;
      rxq->wqe_cnt = dv_rwq.wqe_cnt;

      qw0 = clib_host_to_net_u32 (rxq->buf_sz);
      qw0_nullseg = 0;
      qw0 |= (u64) clib_host_to_net_u32 (rd->lkey) << 32;
      qw0_nullseg |= (u64) clib_host_to_net_u32 (rd->lkey) << 32;

/* Prefill the different 16 bytes words of the WQ.
        - If not in striding RQ mode, for each WQE, init with qw0 the first
            RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ, and init the rest of the WQE
            with null segments.
        - If in striding RQ mode, for each WQE, the RDMA_RXQ_MAX_CHAIN_SZ + 1
        first 16-bytes words are initialised with qw0, the rest are null segments */

      for (int i = 0; i < rxq->wqe_cnt << rxq->log_wqe_sz; i++)
	if ((!is_striding
	     && ((i & wqe_sz_mask) < rxq->n_ds_per_wqe))
	    || (is_striding
		&& ((i == 0)
		    || !(((i - 1) >> rxq->log_stride_per_wqe) & 0x1))))
	  rxq->wqes[i].dsz_and_lkey = qw0;
	else
	  rxq->wqes[i].dsz_and_lkey = qw0_nullseg;

      for (int i = 0; i < (1 << rxq->log2_cq_size); i++)
	rxq->cqes[i].opcode_cqefmt_se_owner = 0xff;

      if (!is_striding)
	{
	  vec_validate_aligned (rxq->second_bufs, n_desc - 1,
				CLIB_CACHE_LINE_BYTES);
	  vec_validate_aligned (rxq->n_used_per_chain, n_desc - 1,
				CLIB_CACHE_LINE_BYTES);
	  rxq->n_total_additional_segs = n_desc * (rxq->n_ds_per_wqe - 1);
	  for (int i = 0; i < n_desc; i++)
	    rxq->n_used_per_chain[i] = rxq->n_ds_per_wqe - 1;
	}
    }

  return 0;
}

static uint64_t
rdma_rss42ibv (const rdma_rss4_t rss4)
{
  switch (rss4)
    {
    case RDMA_RSS4_IP:
      return IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4;
    case RDMA_RSS4_IP_UDP:
      return IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4 |
	     IBV_RX_HASH_SRC_PORT_UDP | IBV_RX_HASH_DST_PORT_UDP;
    case RDMA_RSS4_AUTO: /* fallthrough */
    case RDMA_RSS4_IP_TCP:
      return IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4 |
	     IBV_RX_HASH_SRC_PORT_TCP | IBV_RX_HASH_DST_PORT_TCP;
    }
  ASSERT (0);
  return 0;
}

static uint64_t
rdma_rss62ibv (const rdma_rss6_t rss6)
{
  switch (rss6)
    {
    case RDMA_RSS6_IP:
      return IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6;
    case RDMA_RSS6_IP_UDP:
      return IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6 |
	     IBV_RX_HASH_SRC_PORT_UDP | IBV_RX_HASH_DST_PORT_UDP;
    case RDMA_RSS6_AUTO: /* fallthrough */
    case RDMA_RSS6_IP_TCP:
      return IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6 |
	     IBV_RX_HASH_SRC_PORT_TCP | IBV_RX_HASH_DST_PORT_TCP;
    }
  ASSERT (0);
  return 0;
}

static clib_error_t *
rdma_rxq_finalize (vlib_main_t *vm, rdma_device_t *rd)
{
  struct ibv_rwq_ind_table_init_attr rwqia;
  struct ibv_qp_init_attr_ex qpia;
  struct ibv_wq **ind_tbl;
  const u32 rxq_sz = vec_len (rd->rxqs);
  u32 ind_tbl_sz = rxq_sz;
  u32 i;

  if (!is_pow2 (ind_tbl_sz))
    {
      /* in case we do not have a power-of-2 number of rxq, we try to use the
       * maximum supported to minimize the imbalance */
      struct ibv_device_attr_ex attr;
      if (ibv_query_device_ex (rd->ctx, 0, &attr))
	return clib_error_return_unix (0, "device query failed");
      ind_tbl_sz = attr.rss_caps.max_rwq_indirection_table_size;
      if (ind_tbl_sz < rxq_sz)
	return clib_error_create ("too many rxqs requested (%d) compared to "
				  "max indirection table size (%d)",
				  rxq_sz, ind_tbl_sz);
    }

  ind_tbl = vec_new (struct ibv_wq *, ind_tbl_sz);
  vec_foreach_index (i, ind_tbl)
    vec_elt (ind_tbl, i) = vec_elt (rd->rxqs, i % rxq_sz).wq;
  memset (&rwqia, 0, sizeof (rwqia));
  ASSERT (is_pow2 (vec_len (ind_tbl)));
  rwqia.log_ind_tbl_size = min_log2 (vec_len (ind_tbl));
  rwqia.ind_tbl = ind_tbl;
  if ((rd->rx_rwq_ind_tbl = ibv_create_rwq_ind_table (rd->ctx, &rwqia)) == 0)
    return clib_error_return_unix (0, "RWQ indirection table create failed");
  vec_free (ind_tbl);

  memset (&qpia, 0, sizeof (qpia));
  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.comp_mask =
    IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_IND_TABLE |
    IBV_QP_INIT_ATTR_RX_HASH;
  qpia.pd = rd->pd;
  qpia.rwq_ind_tbl = rd->rx_rwq_ind_tbl;
  STATIC_ASSERT_SIZEOF (rdma_rss_hash_key, 40);
  qpia.rx_hash_conf.rx_hash_key_len = sizeof (rdma_rss_hash_key);
  qpia.rx_hash_conf.rx_hash_key = rdma_rss_hash_key;
  qpia.rx_hash_conf.rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ;

  qpia.rx_hash_conf.rx_hash_fields_mask = rdma_rss42ibv (rd->rss4);
  if ((rd->rx_qp4 = ibv_create_qp_ex (rd->ctx, &qpia)) == 0)
    return clib_error_return_unix (0, "IPv4 Queue Pair create failed");

  qpia.rx_hash_conf.rx_hash_fields_mask = rdma_rss62ibv (rd->rss6);
  if ((rd->rx_qp6 = ibv_create_qp_ex (rd->ctx, &qpia)) == 0)
    return clib_error_return_unix (0, "IPv6 Queue Pair create failed");

  if (rdma_dev_set_ucast (rd))
    return clib_error_return_unix (0, "Set unicast mode failed");

  return 0;
}

static clib_error_t *
rdma_txq_init (vlib_main_t * vm, rdma_device_t * rd, u16 qid, u32 n_desc)
{
  rdma_txq_t *txq;
  struct ibv_qp_init_attr qpia;
  struct ibv_qp_attr qpa;
  int qp_flags;

  vec_validate_aligned (rd->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (rd->txqs, qid);
  ASSERT (is_pow2 (n_desc));
  txq->bufs_log2sz = min_log2 (n_desc);
  vec_validate_aligned (txq->bufs, n_desc - 1, CLIB_CACHE_LINE_BYTES);

  if ((txq->cq = ibv_create_cq (rd->ctx, n_desc, NULL, NULL, 0)) == 0)
    return clib_error_return_unix (0, "Create CQ Failed");

  memset (&qpia, 0, sizeof (qpia));
  qpia.send_cq = txq->cq;
  qpia.recv_cq = txq->cq;
  qpia.cap.max_send_wr = n_desc;
  qpia.cap.max_send_sge = 1;
  qpia.qp_type = IBV_QPT_RAW_PACKET;

  if ((txq->qp = ibv_create_qp (rd->pd, &qpia)) == 0)
    return clib_error_return_unix (0, "Queue Pair create failed");

  memset (&qpa, 0, sizeof (qpa));
  qp_flags = IBV_QP_STATE | IBV_QP_PORT;
  qpa.qp_state = IBV_QPS_INIT;
  qpa.port_num = 1;
  if (ibv_modify_qp (txq->qp, &qpa, qp_flags) != 0)
    return clib_error_return_unix (0, "Modify QP (init) Failed");

  memset (&qpa, 0, sizeof (qpa));
  qp_flags = IBV_QP_STATE;
  qpa.qp_state = IBV_QPS_RTR;
  if (ibv_modify_qp (txq->qp, &qpa, qp_flags) != 0)
    return clib_error_return_unix (0, "Modify QP (receive) Failed");

  memset (&qpa, 0, sizeof (qpa));
  qp_flags = IBV_QP_STATE;
  qpa.qp_state = IBV_QPS_RTS;
  if (ibv_modify_qp (txq->qp, &qpa, qp_flags) != 0)
    return clib_error_return_unix (0, "Modify QP (send) Failed");

  txq->ibv_cq = txq->cq;
  txq->ibv_qp = txq->qp;

  if (rd->flags & RDMA_DEVICE_F_MLX5DV)
    {
      rdma_mlx5_wqe_t *tmpl = (void *) txq->dv_wqe_tmpl;
      struct mlx5dv_cq dv_cq;
      struct mlx5dv_qp dv_qp;
      struct mlx5dv_obj obj = { };

      obj.cq.in = txq->cq;
      obj.cq.out = &dv_cq;
      obj.qp.in = txq->qp;
      obj.qp.out = &dv_qp;

      if (mlx5dv_init_obj (&obj, MLX5DV_OBJ_CQ | MLX5DV_OBJ_QP))
	return clib_error_return_unix (0, "DV init obj failed");

      if (RDMA_TXQ_BUF_SZ (txq) > dv_qp.sq.wqe_cnt
	  || !is_pow2 (dv_qp.sq.wqe_cnt)
	  || sizeof (rdma_mlx5_wqe_t) != dv_qp.sq.stride
	  || (uword) dv_qp.sq.buf % sizeof (rdma_mlx5_wqe_t))
	return clib_error_return (0, "Unsupported DV SQ parameters");

      if (RDMA_TXQ_BUF_SZ (txq) > dv_cq.cqe_cnt
	  || !is_pow2 (dv_cq.cqe_cnt)
	  || sizeof (struct mlx5_cqe64) != dv_cq.cqe_size
	  || (uword) dv_cq.buf % sizeof (struct mlx5_cqe64))
	return clib_error_return (0, "Unsupported DV CQ parameters");

      /* get SQ and doorbell addresses */
      txq->dv_sq_wqes = dv_qp.sq.buf;
      txq->dv_sq_dbrec = dv_qp.dbrec;
      txq->dv_sq_db = dv_qp.bf.reg;
      txq->dv_sq_log2sz = min_log2 (dv_qp.sq.wqe_cnt);

      /* get CQ and doorbell addresses */
      txq->dv_cq_cqes = dv_cq.buf;
      txq->dv_cq_dbrec = dv_cq.dbrec;
      txq->dv_cq_log2sz = min_log2 (dv_cq.cqe_cnt);

      /* init tx desc template */
      STATIC_ASSERT_SIZEOF (txq->dv_wqe_tmpl, sizeof (*tmpl));
      mlx5dv_set_ctrl_seg (&tmpl->ctrl, 0, MLX5_OPCODE_SEND, 0,
			   txq->qp->qp_num, 0, RDMA_MLX5_WQE_DS, 0,
			   RDMA_TXQ_DV_INVALID_ID);
      tmpl->eseg.inline_hdr_sz = htobe16 (MLX5_ETH_L2_INLINE_HEADER_SIZE);
      mlx5dv_set_data_seg (&tmpl->dseg, 0, rd->lkey, 0);
    }

  return 0;
}

static clib_error_t *
rdma_dev_init (vlib_main_t * vm, rdma_device_t * rd,
	       rdma_create_if_args_t * args)
{
  clib_error_t *err;
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 rxq_num = args->rxq_num;
  u32 rxq_size = args->rxq_size;
  u32 txq_size = args->txq_size;
  u32 i;

  if (rd->ctx == 0)
    return clib_error_return_unix (0, "Device Open Failed");

  if ((rd->pd = ibv_alloc_pd (rd->ctx)) == 0)
    return clib_error_return_unix (0, "PD Alloc Failed");

  if ((rd->mr = ibv_reg_mr (rd->pd, (void *) bm->buffer_mem_start,
			    bm->buffer_mem_size,
			    IBV_ACCESS_LOCAL_WRITE)) == 0)
    return clib_error_return_unix (0, "Register MR Failed");

  rd->lkey = rd->mr->lkey;	/* avoid indirection in datapath */

  ethernet_mac_address_generate (rd->hwaddr.bytes);

  rd->rss4 = args->rss4;
  rd->rss6 = args->rss6;

  /*
   * /!\ WARNING /!\ creation order is important
   * We *must* create TX queues *before* RX queues, otherwise we will receive
   * the broacast packets we sent
   */
  for (i = 0; i < tm->n_vlib_mains; i++)
    if ((err = rdma_txq_init (vm, rd, i, txq_size)))
      return err;

  for (i = 0; i < rxq_num; i++)
    if ((err =
	 rdma_rxq_init (vm, rd, i, rxq_size,
			args->no_multi_seg, args->max_pktlen)))
      return err;
  if ((err = rdma_rxq_finalize (vm, rd)))
    return err;

  return 0;
}

static uword
sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t * addr)
{
  uword rv;
  unformat_input_t in;
  u8 *s;

  s = clib_sysfs_link_to_name (path);
  if (!s)
    return 0;

  unformat_init_string (&in, (char *) s, strlen ((char *) s));
  rv = unformat (&in, "%U", unformat_vlib_pci_addr, addr);
  unformat_free (&in);
  vec_free (s);
  return rv;
}

void
rdma_create_if (vlib_main_t * vm, rdma_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd;
  vlib_pci_addr_t pci_addr;
  struct ibv_device **dev_list;
  int n_devs;
  u8 *s;
  u16 qid;
  int i;

  args->rxq_size = args->rxq_size ? args->rxq_size : 1024;
  args->txq_size = args->txq_size ? args->txq_size : 1024;
  args->rxq_num = args->rxq_num ? args->rxq_num : 2;

  if (args->rxq_size < VLIB_FRAME_SIZE || args->txq_size < VLIB_FRAME_SIZE ||
      args->rxq_size > 65535 || args->txq_size > 65535 ||
      !is_pow2 (args->rxq_size) || !is_pow2 (args->txq_size))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error = clib_error_return (0,
				       "queue size must be a power of two "
				       "between %d and 65535",
				       VLIB_FRAME_SIZE);
      goto err0;
    }

  dev_list = ibv_get_device_list (&n_devs);
  if (n_devs == 0)
    {
      args->error =
	clib_error_return_unix (0,
				"no RDMA devices available. Is the ib_uverbs module loaded?");
      goto err0;
    }

  /* get PCI address */
  s = format (0, "/sys/class/net/%s/device%c", args->ifname, 0);
  if (sysfs_path_to_pci_addr ((char *) s, &pci_addr) == 0)
    {
      args->error =
	clib_error_return (0, "cannot find PCI address for device ");
      goto err1;
    }

  pool_get_zero (rm->devices, rd);
  rd->dev_instance = rd - rm->devices;
  rd->per_interface_next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  rd->linux_ifname = format (0, "%s", args->ifname);

  if (!args->name || 0 == args->name[0])
    rd->name = format (0, "%s/%d", args->ifname, rd->dev_instance);
  else
    rd->name = format (0, "%s", args->name);

  rd->pci = vlib_pci_get_device_info (vm, &pci_addr, &args->error);
  if (!rd->pci)
    goto err2;

  /* if we failed to parse NUMA node, default to 0 */
  if (-1 == rd->pci->numa_node)
    rd->pci->numa_node = 0;

  rd->pool = vlib_buffer_pool_get_default_for_numa (vm, rd->pci->numa_node);

  if (strncmp ((char *) rd->pci->driver_name, "mlx5_core", 9))
    {
      args->error =
	clib_error_return (0,
			   "invalid interface (only mlx5 supported for now)");
      goto err2;
    }

  for (i = 0; i < n_devs; i++)
    {
      vlib_pci_addr_t addr;

      vec_reset_length (s);
      s = format (s, "%s/device%c", dev_list[i]->dev_path, 0);

      if (sysfs_path_to_pci_addr ((char *) s, &addr) == 0)
	continue;

      if (addr.as_u32 != rd->pci->addr.as_u32)
	continue;

      if ((rd->ctx = ibv_open_device (dev_list[i])))
	break;
    }

  if (args->mode != RDMA_MODE_IBV)
    {
      struct mlx5dv_context mlx5dv_attrs = { };
      mlx5dv_attrs.comp_mask |= MLX5DV_CONTEXT_MASK_STRIDING_RQ;

      if (mlx5dv_query_device (rd->ctx, &mlx5dv_attrs) == 0)
	{
	  uword data_seg_log2_sz =
	    min_log2 (vlib_buffer_get_default_data_size (vm));

	  if ((mlx5dv_attrs.flags & MLX5DV_CONTEXT_FLAGS_CQE_V1))
	    rd->flags |= RDMA_DEVICE_F_MLX5DV;

/* Enable striding RQ if neither multiseg nor striding rq
are explicitly disabled, and if the interface supports it.*/
	  if (!args->no_multi_seg && !args->disable_striding_rq
	      && data_seg_log2_sz <=
	      mlx5dv_attrs.striding_rq_caps.max_single_stride_log_num_of_bytes
	      && data_seg_log2_sz >=
	      mlx5dv_attrs.striding_rq_caps.min_single_stride_log_num_of_bytes
	      && RDMA_RXQ_MAX_CHAIN_LOG_SZ >=
	      mlx5dv_attrs.striding_rq_caps.min_single_wqe_log_num_of_strides
	      && RDMA_RXQ_MAX_CHAIN_LOG_SZ <=
	      mlx5dv_attrs.striding_rq_caps.max_single_wqe_log_num_of_strides)
	    rd->flags |= RDMA_DEVICE_F_STRIDING_RQ;
	}
      else
	{
	  if (args->mode == RDMA_MODE_DV)
	    {
	      args->error = clib_error_return (0, "Direct Verbs mode not "
					       "supported on this interface");
	      goto err2;
	    }
	}
    }

  if ((args->error = rdma_dev_init (vm, rd, args)))
    goto err2;

  if ((args->error = rdma_register_interface (vnm, rd)))
    goto err2;

  if ((args->error = rdma_async_event_init (rd)))
    goto err3;

  rdma_update_state (vnm, rd, 1);

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, rd->hw_if_index);
  args->sw_if_index = rd->sw_if_index = sw->sw_if_index;
  /*
   * FIXME: add support for interrupt mode
   * vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, rd->hw_if_index);
   * hw->caps |= VNET_HW_IF_CAP_INT_MODE;
   */
  vnet_hw_if_set_input_node (vnm, rd->hw_if_index, rdma_input_node.index);

  vec_foreach_index (qid, rd->rxqs)
    {
      u32 queue_index = vnet_hw_if_register_rx_queue (
	vnm, rd->hw_if_index, qid, VNET_HW_IF_RXQ_THREAD_ANY);
      rd->rxqs[qid].queue_index = queue_index;
    }
  vnet_hw_if_update_runtime_data (vnm, rd->hw_if_index);
  vec_free (s);
  return;

err3:
  rdma_unregister_interface (vnm, rd);
err2:
  rdma_dev_cleanup (rd);
err1:
  ibv_free_device_list (dev_list);
  vec_free (s);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
err0:
  vlib_log_err (rm->log_class, "%U", format_clib_error, args->error);
}

void
rdma_delete_if (vlib_main_t * vm, rdma_device_t * rd)
{
  rdma_async_event_cleanup (rd);
  rdma_unregister_interface (vnet_get_main (), rd);
  rdma_dev_cleanup (rd);
}

static clib_error_t *
rdma_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  rdma_main_t *rm = &rdma_main;
  rdma_device_t *rd = vec_elt_at_index (rm->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (rd->flags & RDMA_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, rd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      rd->flags |= RDMA_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, rd->hw_if_index, 0);
      rd->flags &= ~RDMA_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static void
rdma_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  rdma_main_t *rm = &rdma_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  rdma_device_t *rd = pool_elt_at_index (rm->devices, hw->dev_instance);
  rd->per_interface_next_index =
    ~0 ==
    node_index ? VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT :
    vlib_node_add_next (vlib_get_main (), rdma_input_node.index, node_index);
}

static char *rdma_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_rdma_tx_func_error
#undef _
};

VNET_DEVICE_CLASS (rdma_device_class) =
{
  .name = "RDMA interface",
  .format_device = format_rdma_device,
  .format_device_name = format_rdma_device_name,
  .admin_up_down_function = rdma_interface_admin_up_down,
  .rx_redirect_to_node = rdma_set_interface_next_node,
  .tx_function_n_errors = RDMA_TX_N_ERROR,
  .tx_function_error_strings = rdma_tx_func_error_strings,
  .mac_addr_change_function = rdma_mac_change,
};

clib_error_t *
rdma_init (vlib_main_t * vm)
{
  rdma_main_t *rm = &rdma_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  rm->log_class = vlib_log_register_class ("rdma", 0);

  /* vlib_buffer_t template */
  vec_validate_aligned (rm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  for (int i = 0; i < tm->n_vlib_mains; i++)
    {
      rdma_per_thread_data_t *ptd = vec_elt_at_index (rm->per_thread_data, i);
      clib_memset (&ptd->buffer_template, 0, sizeof (vlib_buffer_t));
      ptd->buffer_template.flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
      ptd->buffer_template.ref_count = 1;
      vnet_buffer (&ptd->buffer_template)->sw_if_index[VLIB_TX] = (u32) ~ 0;
    }

  return 0;
}

VLIB_INIT_FUNCTION (rdma_init) =
{
  .runs_after = VLIB_INITS ("pci_bus_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
