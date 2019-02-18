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

#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>

#include <vppinfra/linux/sysfs.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <rdma/rdma.h>

rdma_main_t rdma_main;

static u32
rdma_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  rdma_main_t *am = &rdma_main;
  vlib_log_warn (am->log_class, "TODO");
  return 0;
}

#define rdma_log_debug(dev, f, ...) \
{                                                                   \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, rdma_main.log_class, "%U: " f,      \
	   format_vlib_pci_addr, &md->pci_addr, ##__VA_ARGS__);     \
};


void
rdma_delete_if (vlib_main_t * vm, rdma_device_t * md)
{
  vnet_main_t *vnm = vnet_get_main ();
  rdma_main_t *axm = &rdma_main;
  rdma_rxq_t *rxq;
  rdma_txq_t *txq;

  if (md->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, md->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, md->hw_if_index, 0);
      ethernet_delete_interface (vnm, md->hw_if_index);
    }
#define _(fn, arg) if (arg) \
  { \
    int rv; \
    if ((rv = fn (arg))) \
       rdma_log_debug (md, #fn "() failed (rv = %d)", rv); \
  }

  _(ibv_destroy_flow, md->flow);
  _(ibv_dereg_mr, md->mr);
  vec_foreach (txq, md->txqs)
  {
    _(ibv_destroy_qp, txq->qp);
    _(ibv_destroy_cq, txq->cq);
  }
  vec_foreach (rxq, md->rxqs)
  {
    _(ibv_destroy_qp, rxq->qp);
    _(ibv_destroy_cq, rxq->cq);
  }
  _(ibv_dealloc_pd, md->pd);
  _(ibv_close_device, md->ctx);
#undef _

  clib_error_free (md->error);

  vec_free (md->rxqs);
  vec_free (md->txqs);
  pool_put (axm->devices, md);
}

static clib_error_t *
rdma_rxq_init (vlib_main_t * vm, rdma_device_t * md, u16 qid, u32 n_desc)
{
  rdma_rxq_t *rxq;
  struct ibv_qp_init_attr qpia;
  struct ibv_qp_attr qpa;
  int qp_flags;

  vec_validate_aligned (md->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (md->rxqs, qid);
  rxq->size = n_desc;

  if ((rxq->cq = ibv_create_cq (md->ctx, n_desc, NULL, NULL, 0)) == 0)
    return clib_error_return_unix (0, "Create CQ Failed");

  memset (&qpia, 0, sizeof (qpia));
  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.send_cq = rxq->cq;
  qpia.recv_cq = rxq->cq;
  qpia.cap.max_recv_wr = n_desc;
  qpia.cap.max_recv_sge = 1;

  if ((rxq->qp = ibv_create_qp (md->pd, &qpia)) == 0)
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
rdma_txq_init (vlib_main_t * vm, rdma_device_t * md, u16 qid, u32 n_desc)
{
  rdma_txq_t *txq;
  struct ibv_qp_init_attr qpia;
  struct ibv_qp_attr qpa;
  int qp_flags;

  vec_validate_aligned (md->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (md->txqs, qid);
  txq->size = n_desc;

  if ((txq->cq = ibv_create_cq (md->ctx, n_desc, NULL, NULL, 0)) == 0)
    return clib_error_return_unix (0, "Create CQ Failed");

  memset (&qpia, 0, sizeof (qpia));
  qpia.qp_type = IBV_QPT_RAW_PACKET;
  qpia.send_cq = txq->cq;
  qpia.recv_cq = txq->cq;
  qpia.cap.max_send_wr = n_desc;
  qpia.cap.max_send_sge = 1;

  if ((txq->qp = ibv_create_qp (md->pd, &qpia)) == 0)
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
rdma_dev_init (vlib_main_t * vm, rdma_device_t * md)
{
  clib_error_t *err;
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u16 i;

  if (md->ctx == 0)
    return clib_error_return_unix (0, "Device Open Failed");

  if ((md->pd = ibv_alloc_pd (md->ctx)) == 0)
    return clib_error_return_unix (0, "PD Alloc Failed");

  if ((err = rdma_rxq_init (vm, md, 0, 512)))
    return err;

  for (i = 0; i < tm->n_vlib_mains; i++)
    if ((err = rdma_txq_init (vm, md, i, 512)))
      return err;

  if ((md->mr = ibv_reg_mr (md->pd, (void *) bm->buffer_mem_start,
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
  rdma_main_t *mm = &rdma_main;
  rdma_device_t *md = 0;
  struct ibv_device **dev_list = 0;
  int n_devs;
  u8 *s = 0, *s2 = 0;

  pool_get_zero (mm->devices, md);
  md->dev_instance = md - mm->devices;
  md->per_interface_next_index = ~0;

  /* check if device exist and if it is bound to mlx5_core */
  s = format (s, "/sys/class/net/%s/device/driver/module%c", args->ifname, 0);
  s2 = clib_sysfs_link_to_name ((char *) s);

  if (s2 == 0 || strncmp ((char *) s2, "mlx5_core", 9) != 0)
    {
      args->error = clib_error_return (0, "invalid interface");
      goto error;
    }

  /* extract PCI address */
  vec_reset_length (s);
  s = format (s, "/sys/class/net/%s/device%c", args->ifname, 0);
  if (sysfs_path_to_pci_addr ((char *) s, &md->pci_addr) == 0)
    {
      args->error = clib_error_return (0, "cannot find PCI address");
      goto error;
    }

  dev_list = ibv_get_device_list (&n_devs);
  if (n_devs == 0)
    {
      args->error =
	clib_error_return_unix (0, "no RDMA devices available, errno = %d",
				errno);
      goto error;
    }

  for (int i = 0; i < n_devs; i++)
    {
      vlib_pci_addr_t addr;

      vec_reset_length (s);
      s = format (s, "%s/device%c", dev_list[i]->dev_path, 0);

      if (sysfs_path_to_pci_addr ((char *) s, &addr) == 0)
	continue;

      if (addr.as_u32 != md->pci_addr.as_u32)
	continue;

      if ((md->ctx = ibv_open_device (dev_list[i])))
	break;
    }

  if ((args->error = rdma_dev_init (vm, md)))
    goto error;

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

  if ((md->flow = ibv_create_flow (md->rxqs[0].qp, &fa.attr)) == 0)
    {
      args->error = clib_error_return_unix (0, "create Flow Failed");
      goto error;
    }

  /* create interface */
  ethernet_mac_address_generate (md->hwaddr);
  if ((args->error =
       ethernet_register_interface (vnm, rdma_device_class.index,
				    md->dev_instance, md->hwaddr,
				    &md->hw_if_index, rdma_flag_change)))
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, md->hw_if_index);
  args->sw_if_index = md->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, md->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, md->hw_if_index,
				    rdma_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, md->hw_if_index, 0, ~0);

error:
  if (args->error)
    {
      rdma_delete_if (vm, md);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      vlib_log_err (mm->log_class, "%U", format_clib_error, args->error);
    }
  vec_free (s);
  vec_free (s2);
  if (dev_list)
    ibv_free_device_list (dev_list);
}

static clib_error_t *
rdma_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  rdma_main_t *am = &rdma_main;
  rdma_device_t *ad = vec_elt_at_index (am->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & RDMA_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= RDMA_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~RDMA_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static void
rdma_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  rdma_main_t *am = &rdma_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  rdma_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
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
  .name = "MLX interface",
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
  rdma_main_t *am = &rdma_main;

  am->log_class = vlib_log_register_class ("rdma", 0);

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
