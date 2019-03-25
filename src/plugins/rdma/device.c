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
				      rd->dev_instance, rd->hwaddr,
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
    _(ibv_destroy_qp, rxq->qp);
    _(ibv_destroy_cq, rxq->cq);
  }
  _(ibv_dealloc_pd, rd->pd);
  _(ibv_close_device, rd->ctx);
#undef _

  clib_error_free (rd->error);

  vec_free (rd->rxqs);
  vec_free (rd->txqs);
  pool_put (rm->devices, rd);
}

static clib_error_t *
rdma_rxq_init (vlib_main_t * vm, rdma_device_t * rd, u16 qid, u32 n_desc)
{
  rdma_rxq_t *rxq;
  struct ibv_qp_init_attr qpia;
  struct ibv_qp_attr qpa;
  int qp_flags;

  vec_validate_aligned (rd->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (rd->rxqs, qid);
  rxq->size = n_desc;

  if ((rxq->cq = ibv_create_cq (rd->ctx, n_desc, NULL, NULL, 0)) == 0)
    return clib_error_return_unix (0, "Create CQ Failed");

  memset (&qpia, 0, sizeof (qpia));
  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.send_cq = rxq->cq;
  qpia.recv_cq = rxq->cq;
  qpia.cap.max_recv_wr = n_desc;
  qpia.cap.max_recv_sge = 1;

  if ((rxq->qp = ibv_create_qp (rd->pd, &qpia)) == 0)
    return clib_error_return_unix (0, "Queue Pair create failed");

  memset (&qpa, 0, sizeof (qpa));
  qp_flags = IBV_QP_STATE | IBV_QP_PORT;
  qpa.qp_state = IBV_QPS_INIT;
  qpa.port_num = 1;
  if (ibv_modify_qp (rxq->qp, &qpa, qp_flags) != 0)
    return clib_error_return_unix (0, "Modify QP (init) Failed");

  memset (&qpa, 0, sizeof (qpa));
  qp_flags = IBV_QP_STATE;
  qpa.qp_state = IBV_QPS_RTR;
  if (ibv_modify_qp (rxq->qp, &qpa, qp_flags) != 0)
    return clib_error_return_unix (0, "Modify QP (receive) Failed");

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
  txq->size = n_desc;

  if ((txq->cq = ibv_create_cq (rd->ctx, n_desc, NULL, NULL, 0)) == 0)
    return clib_error_return_unix (0, "Create CQ Failed");

  memset (&qpia, 0, sizeof (qpia));
  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.send_cq = txq->cq;
  qpia.recv_cq = txq->cq;
  qpia.cap.max_send_wr = n_desc;
  qpia.cap.max_send_sge = 1;

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
rdma_dev_init (vlib_main_t * vm, rdma_device_t * rd)
{
  clib_error_t *err;
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u16 i;

  if (rd->ctx == 0)
    return clib_error_return_unix (0, "Device Open Failed");

  if ((rd->pd = ibv_alloc_pd (rd->ctx)) == 0)
    return clib_error_return_unix (0, "PD Alloc Failed");

  if ((err = rdma_rxq_init (vm, rd, 0, 512)))
    return err;

  for (i = 0; i < tm->n_vlib_mains; i++)
    if ((err = rdma_txq_init (vm, rd, i, 512)))
      return err;

  if ((rd->mr = ibv_reg_mr (rd->pd, (void *) bm->buffer_mem_start,
			    bm->buffer_mem_size,
			    IBV_ACCESS_LOCAL_WRITE)) == 0)
    return clib_error_return_unix (0, "Register MR Failed");

  ethernet_mac_address_generate (rd->hwaddr);

  /*
   * restrict packets steering to our MAC
   * allows to share a single HW NIC with multiple RDMA ifaces
   * and/or Linux
   */
  struct raw_eth_flow_attr
  {
    struct ibv_flow_attr attr;
    struct ibv_flow_spec_eth spec_eth;
  } __attribute__ ((packed)) fa;
  memset (&fa, 0, sizeof (fa));
  fa.attr.num_of_specs = 1;
  fa.attr.port = 1;
  fa.spec_eth.type = IBV_FLOW_SPEC_ETH;
  fa.spec_eth.size = sizeof (struct ibv_flow_spec_eth);
  memcpy (fa.spec_eth.val.dst_mac, rd->hwaddr,
	  sizeof (fa.spec_eth.val.dst_mac));
  memset (fa.spec_eth.mask.dst_mac, 0xff, sizeof (fa.spec_eth.mask.dst_mac));
  if ((rd->flow_ucast = ibv_create_flow (rd->rxqs[0].qp, &fa.attr)) == 0)
    return clib_error_return_unix (0, "create Flow Failed");

  /* receive multicast packets too */
  memset (&fa, 0, sizeof (fa));
  fa.attr.num_of_specs = 1;
  fa.attr.port = 1;
  fa.attr.flags = IBV_FLOW_ATTR_FLAGS_DONT_TRAP;	/* let others receive them too */
  fa.spec_eth.type = IBV_FLOW_SPEC_ETH;
  fa.spec_eth.size = sizeof (struct ibv_flow_spec_eth);
  fa.spec_eth.val.dst_mac[0] = 1;
  fa.spec_eth.mask.dst_mac[0] = 1;
  if ((rd->flow_mcast = ibv_create_flow (rd->rxqs[0].qp, &fa.attr)) == 0)
    return clib_error_return_unix (0, "create Flow Failed");

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

  pool_get_zero (rm->devices, rd);
  rd->dev_instance = rd - rm->devices;
  rd->per_interface_next_index = ~0;

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
				"no RDMA devices available, errno = %d. Is the ib_uverbs module loaded?",
				errno);
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

  if ((args->error = rdma_dev_init (vm, rd)))
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
  vnet_hw_interface_assign_rx_thread (vnm, rd->hw_if_index, 0, ~0);
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
