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

#define rdma_log_debug(dev, f, ...) \
{                                                                   \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, rdma_main.log_class, "%U: " f,      \
	   format_vlib_pci_addr, &rd->pci_addr, ##__VA_ARGS__);     \
};

static u32
rdma_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  rdma_main_t *rm = &rdma_main;
  vlib_log_warn (rm->log_class, "TODO");
  return 0;
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
  return clib_error_return (0, "RDMA async event error for device %U",
			    format_vlib_pci_addr, &rd->pci_addr);
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
    {
      return clib_error_return_unix (0, "ibv_get_async_event() failed");
    }

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
      vlib_log_emerg (rm->log_class, "Fatal RDMA error for device %U",
		      format_vlib_pci_addr, &rd->pci_addr);
      break;
    default:
      vlib_log_warn (rm->log_class,
		     "Unhandeld RDMA async event %i for device %U",
		     event.event_type, format_vlib_pci_addr, &rd->pci_addr);
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
    {
      return clib_error_return_unix (0, "fcntl(F_GETFL) failed");
    }
  ret = fcntl (rd->ctx->async_fd, F_SETFL, ret | O_NONBLOCK);
  if (ret < 0)
    {
      return clib_error_return_unix (0, "fcntl(F_SETFL, O_NONBLOCK) failed");
    }

  /* register RDMA async event fd */
  t.read_function = rdma_async_event_read_ready;
  t.file_descriptor = rd->ctx->async_fd;
  t.error_function = rdma_async_event_error_ready;
  t.private_data = rd->dev_instance;
  t.description =
    format (0, "RMDA %U async event", format_vlib_pci_addr, &rd->pci_addr);

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
  return ethernet_register_interface (vnm, rdma_device_class.index,
				      rd->dev_instance, rd->hwaddr.bytes,
				      &rd->hw_if_index, rdma_flag_change);
}

static void
rdma_unregister_interface (vnet_main_t * vnm, rdma_device_t * rd)
{
  vnet_hw_interface_set_flags (vnm, rd->hw_if_index, 0);
  vnet_hw_interface_unassign_rx_thread (vnm, rd->hw_if_index, 0);
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
       rdma_log_debug (rd, #fn "() failed (rv = %d)", rv); \
  }

  _(ibv_destroy_flow, rd->flow_mcast);
  _(ibv_destroy_flow, rd->flow_ucast);
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
  _(ibv_destroy_qp, rd->rx_qp);
  _(ibv_dealloc_pd, rd->pd);
  _(ibv_close_device, rd->ctx);
#undef _

  clib_error_free (rd->error);

  vec_free (rd->rxqs);
  vec_free (rd->txqs);
  vec_free (rd->name);
  pool_put (rm->devices, rd);
}

static clib_error_t *
rdma_rxq_init_flow (struct ibv_flow **flow, struct ibv_qp *qp,
		    const mac_address_t * mac, const mac_address_t * mask,
		    u32 flags)
{
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

  if ((*flow = ibv_create_flow (qp, &fa.attr)) == 0)
    return clib_error_return_unix (0, "create Flow Failed");

  return 0;
}

static clib_error_t *
rdma_rxq_init (vlib_main_t * vm, rdma_device_t * rd, u16 qid, u32 n_desc)
{
  rdma_rxq_t *rxq;
  struct ibv_wq_init_attr wqia;
  struct ibv_wq_attr wqa;

  vec_validate_aligned (rd->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (rd->rxqs, qid);
  rxq->size = n_desc;

  if ((rxq->cq = ibv_create_cq (rd->ctx, n_desc, NULL, NULL, 0)) == 0)
    return clib_error_return_unix (0, "Create CQ Failed");

  memset (&wqia, 0, sizeof (wqia));
  wqia.wq_type = IBV_WQT_RQ;
  wqia.max_wr = n_desc;
  wqia.max_sge = 1;
  wqia.pd = rd->pd;
  wqia.cq = rxq->cq;
  if ((rxq->wq = ibv_create_wq (rd->ctx, &wqia)) == 0)
    return clib_error_return_unix (0, "Create WQ Failed");

  memset (&wqa, 0, sizeof (wqa));
  wqa.attr_mask = IBV_WQ_ATTR_STATE;
  wqa.wq_state = IBV_WQS_RDY;
  if (ibv_modify_wq (rxq->wq, &wqa) != 0)
    return clib_error_return_unix (0, "Modify WQ (RDY) Failed");

  return 0;
}

static clib_error_t *
rdma_rxq_finalize (vlib_main_t * vm, rdma_device_t * rd)
{
  struct ibv_rwq_ind_table_init_attr rwqia;
  struct ibv_qp_init_attr_ex qpia;
  const mac_address_t ucast = {.bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
  };
  const mac_address_t mcast = {.bytes = {0x1, 0x0, 0x0, 0x0, 0x0, 0x0} };
  struct ibv_wq **ind_tbl;
  clib_error_t *err;
  u32 i;

  ASSERT (is_pow2 (vec_len (rd->rxqs))
	  && "rxq number should be a power of 2");

  ind_tbl = vec_new (struct ibv_wq *, vec_len (rd->rxqs));
  vec_foreach_index (i, rd->rxqs)
    ind_tbl[i] = vec_elt_at_index (rd->rxqs, i)->wq;
  memset (&rwqia, 0, sizeof (rwqia));
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
  qpia.rx_hash_conf.rx_hash_fields_mask =
    IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4;
  if ((rd->rx_qp = ibv_create_qp_ex (rd->ctx, &qpia)) == 0)
    return clib_error_return_unix (0, "Queue Pair create failed");

  /* receive only packets with src = our MAC */
  if ((err =
       rdma_rxq_init_flow (&rd->flow_ucast, rd->rx_qp, &rd->hwaddr, &ucast,
			   0)) != 0)
    return err;
  /* receive multicast packets */
  return rdma_rxq_init_flow (&rd->flow_mcast, rd->rx_qp, &mcast, &mcast,
			     IBV_FLOW_ATTR_FLAGS_DONT_TRAP
			     /* let others receive mcast packet too (eg. Linux) */
    );
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
  txq->size = n_desc;

  if ((txq->cq = ibv_create_cq (rd->ctx, n_desc, NULL, NULL, 0)) == 0)
    return clib_error_return_unix (0, "Create CQ Failed");

  memset (&qpia, 0, sizeof (qpia));
  qpia.send_cq = txq->cq;
  qpia.recv_cq = txq->cq;
  qpia.cap.max_send_wr = n_desc;
  qpia.cap.max_send_sge = 1;
  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.sq_sig_all = 1;

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
  return 0;
}

static clib_error_t *
rdma_dev_init (vlib_main_t * vm, rdma_device_t * rd, u32 rxq_size,
	       u32 txq_size, u32 rxq_num)
{
  clib_error_t *err;
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 i;

  if (rd->ctx == 0)
    return clib_error_return_unix (0, "Device Open Failed");

  if ((rd->pd = ibv_alloc_pd (rd->ctx)) == 0)
    return clib_error_return_unix (0, "PD Alloc Failed");

  ethernet_mac_address_generate (rd->hwaddr.bytes);

  for (i = 0; i < rxq_num; i++)
    if ((err = rdma_rxq_init (vm, rd, i, rxq_size)))
      return err;
  if ((err = rdma_rxq_finalize (vm, rd)))
    return err;

  for (i = 0; i < tm->n_vlib_mains; i++)
    if ((err = rdma_txq_init (vm, rd, i, txq_size)))
      return err;

  if ((rd->mr = ibv_reg_mr (rd->pd, (void *) bm->buffer_mem_start,
			    bm->buffer_mem_size,
			    IBV_ACCESS_LOCAL_WRITE)) == 0)
    return clib_error_return_unix (0, "Register MR Failed");

  return 0;
}

static uword
sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t * addr)
{
  uword rv;
  unformat_input_t in;
  u8 *s;

  s = clib_sysfs_link_to_name (path);
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
  rdma_device_t *rd = 0;
  struct ibv_device **dev_list = 0;
  int n_devs;
  u8 *s = 0, *s2 = 0;
  u16 qid;

  args->rxq_size = args->rxq_size ? args->rxq_size : 2 * VLIB_FRAME_SIZE;
  args->txq_size = args->txq_size ? args->txq_size : 2 * VLIB_FRAME_SIZE;
  args->rxq_num = args->rxq_num ? args->rxq_num : 1;

  if (!is_pow2 (args->rxq_num))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (0, "rx queue number must be a power of two");
      return;
    }

  if (!is_pow2 (args->rxq_size) || !is_pow2 (args->txq_size))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (0, "queue size must be a power of two");
      return;
    }

  pool_get_zero (rm->devices, rd);
  rd->dev_instance = rd - rm->devices;
  rd->per_interface_next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  rd->name = vec_dup (args->name);

  /* check if device exist and if it is bound to mlx5_core */
  s = format (s, "/sys/class/net/%s/device/driver/module%c", args->ifname, 0);
  s2 = clib_sysfs_link_to_name ((char *) s);

  if (s2 == 0 || strncmp ((char *) s2, "mlx5_core", 9) != 0)
    {
      args->error =
	clib_error_return (0,
			   "invalid interface (only mlx5 supported for now)");
      goto err0;
    }

  /* extract PCI address */
  vec_reset_length (s);
  s = format (s, "/sys/class/net/%s/device%c", args->ifname, 0);
  if (sysfs_path_to_pci_addr ((char *) s, &rd->pci_addr) == 0)
    {
      args->error = clib_error_return (0, "cannot find PCI address");
      goto err0;
    }

  dev_list = ibv_get_device_list (&n_devs);
  if (n_devs == 0)
    {
      args->error =
	clib_error_return_unix (0,
				"no RDMA devices available, errno = %d. "
				"Is the ib_uverbs module loaded?", errno);
      goto err1;
    }

  for (int i = 0; i < n_devs; i++)
    {
      vlib_pci_addr_t addr;

      vec_reset_length (s);
      s = format (s, "%s/device%c", dev_list[i]->dev_path, 0);

      if (sysfs_path_to_pci_addr ((char *) s, &addr) == 0)
	continue;

      if (addr.as_u32 != rd->pci_addr.as_u32)
	continue;

      if ((rd->ctx = ibv_open_device (dev_list[i])))
	break;
    }

  if ((args->error =
       rdma_dev_init (vm, rd, args->rxq_size, args->txq_size, args->rxq_num)))
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
   * hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
   */
  vnet_hw_interface_set_input_node (vnm, rd->hw_if_index,
				    rdma_input_node.index);
  vec_foreach_index (qid, rd->rxqs)
    vnet_hw_interface_assign_rx_thread (vnm, rd->hw_if_index, qid, ~0);
  return;

err3:
  rdma_unregister_interface (vnm, rd);
err2:
  rdma_dev_cleanup (rd);
err1:
  ibv_free_device_list (dev_list);
err0:
  vec_free (s2);
  vec_free (s);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
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

  /* Shut off redirection */
  if (node_index == ~0)
    {
      rd->per_interface_next_index = node_index;
      return;
    }

  rd->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), rdma_input_node.index, node_index);
}

static char *rdma_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_rdma_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (rdma_device_class,) =
{
  .name = "RDMA interface",
  .format_device = format_rdma_device,
  .format_device_name = format_rdma_device_name,
  .admin_up_down_function = rdma_interface_admin_up_down,
  .rx_redirect_to_node = rdma_set_interface_next_node,
  .tx_function_n_errors = RDMA_TX_N_ERROR,
  .tx_function_error_strings = rdma_tx_func_error_strings,
};
/* *INDENT-ON* */

clib_error_t *
rdma_init (vlib_main_t * vm)
{
  rdma_main_t *rm = &rdma_main;

  rm->log_class = vlib_log_register_class ("rdma", 0);

  return 0;
}

VLIB_INIT_FUNCTION (rdma_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
