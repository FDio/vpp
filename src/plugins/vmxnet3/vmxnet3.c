/*
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
 */

#include <vppinfra/types.h>
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <vmxnet3/vmxnet3.h>

#define PCI_VENDOR_ID_VMWARE				0x15ad
#define PCI_DEVICE_ID_VMWARE_VMXNET3			0x07b0

vmxnet3_main_t vmxnet3_main;

static pci_device_id_t vmxnet3_pci_device_ids[] = {
  {
   .vendor_id = PCI_VENDOR_ID_VMWARE,
   .device_id = PCI_DEVICE_ID_VMWARE_VMXNET3},
  {0},
};

static clib_error_t *
vmxnet3_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				 u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd = vec_elt_at_index (vmxm->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (vd->flags & VMXNET3_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      vd->flags |= VMXNET3_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
      vd->flags &= ~VMXNET3_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static clib_error_t *
vmxnet3_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
				  vnet_hw_interface_rx_mode mode)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vmxnet3_device_t *vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);
  vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, qid);

  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    rxq->int_mode = 0;
  else
    rxq->int_mode = 1;

  return 0;
}

static void
vmxnet3_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				 u32 node_index)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vmxnet3_device_t *vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      vd->per_interface_next_index = node_index;
      return;
    }

  vd->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), vmxnet3_input_node.index,
			node_index);
}

static char *vmxnet3_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_vmxnet3_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vmxnet3_device_class,) =
{
  .name = "VMXNET3 interface",
  .format_device = format_vmxnet3_device,
  .format_device_name = format_vmxnet3_device_name,
  .admin_up_down_function = vmxnet3_interface_admin_up_down,
  .rx_mode_change_function = vmxnet3_interface_rx_mode_change,
  .rx_redirect_to_node = vmxnet3_set_interface_next_node,
  .tx_function_n_errors = VMXNET3_TX_N_ERROR,
  .tx_function_error_strings = vmxnet3_tx_func_error_strings,
};
/* *INDENT-ON* */

static u32
vmxnet3_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  return 0;
}

static void
vmxnet3_write_mac (vmxnet3_device_t * vd)
{
  u32 val;

  memcpy (&val, vd->mac_addr, 4);
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_MACL, val);

  val = 0;
  memcpy (&val, vd->mac_addr + 4, 2);
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_MACH, val);
}

static clib_error_t *
vmxnet3_provision_driver_shared (vlib_main_t * vm, vmxnet3_device_t * vd)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_shared *shared;
  vmxnet3_queues *q;
  u64 shared_dma;
  clib_error_t *error;
  u16 qid = 0, rid;
  vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, qid);
  vmxnet3_txq_t *txq = vec_elt_at_index (vd->txqs, qid);

  vd->dma = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					sizeof (*vd->dma), 512);
  if (error)
    return error;

  clib_memset (vd->dma, 0, sizeof (*vd->dma));

  q = &vd->dma->queues;
  q->tx.cfg.desc_address = vmxnet3_dma_addr (vm, vd, txq->tx_desc);
  q->tx.cfg.comp_address = vmxnet3_dma_addr (vm, vd, txq->tx_comp);
  q->tx.cfg.num_desc = txq->size;
  q->tx.cfg.num_comp = txq->size;
  for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
    {
      q->rx.cfg.desc_address[rid] = vmxnet3_dma_addr (vm, vd,
						      rxq->rx_desc[rid]);
      q->rx.cfg.num_desc[rid] = rxq->size;
    }
  q->rx.cfg.comp_address = vmxnet3_dma_addr (vm, vd, rxq->rx_comp);
  q->rx.cfg.num_comp = rxq->size;

  shared = &vd->dma->shared;
  shared->magic = VMXNET3_SHARED_MAGIC;
  shared->misc.version = VMXNET3_VERSION_MAGIC;
  if (sizeof (void *) == 4)
    shared->misc.guest_info = VMXNET3_GOS_BITS_32;
  else
    shared->misc.guest_info = VMXNET3_GOS_BITS_64;
  shared->misc.guest_info |= VMXNET3_GOS_TYPE_LINUX;
  shared->misc.version_support = VMXNET3_VERSION_SELECT;
  shared->misc.upt_version_support = VMXNET3_UPT_VERSION_SELECT;
  shared->misc.queue_desc_address = vmxnet3_dma_addr (vm, vd, q);
  shared->misc.queue_desc_len = sizeof (*q);
  shared->misc.mtu = VMXNET3_MTU;
  shared->misc.num_tx_queues = vd->num_tx_queues;
  shared->misc.num_rx_queues = vd->num_rx_queues;
  shared->interrupt.num_intrs = vd->num_intrs;
  shared->interrupt.event_intr_index = 1;
  shared->interrupt.control = VMXNET3_IC_DISABLE_ALL;
  shared->rx_filter.mode = VMXNET3_RXMODE_UCAST | VMXNET3_RXMODE_BCAST |
    VMXNET3_RXMODE_ALL_MULTI;
  shared_dma = vmxnet3_dma_addr (vm, vd, shared);

  vmxnet3_reg_write (vd, 1, VMXNET3_REG_DSAL, shared_dma);
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_DSAH, shared_dma >> 32);

  return 0;
}

static inline void
vmxnet3_enable_interrupt (vmxnet3_device_t * vd)
{
  int i;
  vmxnet3_shared *shared = &vd->dma->shared;

  shared->interrupt.control &= ~VMXNET3_IC_DISABLE_ALL;
  for (i = 0; i < vd->num_intrs; i++)
    vmxnet3_reg_write (vd, 0, VMXNET3_REG_IMR + i * 8, 0);
}

static inline void
vmxnet3_disable_interrupt (vmxnet3_device_t * vd)
{
  int i;
  vmxnet3_shared *shared = &vd->dma->shared;

  shared->interrupt.control |= VMXNET3_IC_DISABLE_ALL;
  for (i = 0; i < vd->num_intrs; i++)
    vmxnet3_reg_write (vd, 0, VMXNET3_REG_IMR + i * 8, 1);
}

static clib_error_t *
vmxnet3_rxq_init (vlib_main_t * vm, vmxnet3_device_t * vd, u16 qid, u16 qsz)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_rxq_t *rxq;
  clib_error_t *error;
  u16 rid;

  vec_validate_aligned (vd->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (vd->rxqs, qid);
  clib_memset (rxq, 0, sizeof (*rxq));
  rxq->size = qsz;
  for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
    {
      rxq->rx_desc[rid] =
	vlib_physmem_alloc_aligned (vm, vmxm->physmem_region,
				    &error, qsz * sizeof (*rxq->rx_desc[rid]),
				    512);
      if (error)
	return error;
      clib_memset (rxq->rx_desc[rid], 0, qsz * sizeof (*rxq->rx_desc[rid]));
    }
  rxq->rx_comp = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					     qsz * sizeof (*rxq->rx_comp),
					     512);
  if (error)
    return error;
  clib_memset (rxq->rx_comp, 0, qsz * sizeof (*rxq->rx_comp));
  for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
    {
      vmxnet3_rx_ring *ring;

      ring = &rxq->rx_ring[rid];
      ring->gen = VMXNET3_RXF_GEN;
      ring->rid = rid;
      vec_validate_aligned (ring->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
    }
  rxq->rx_comp_ring.gen = VMXNET3_RXCF_GEN;

  return 0;
}

static clib_error_t *
vmxnet3_txq_init (vlib_main_t * vm, vmxnet3_device_t * vd, u16 qid, u16 qsz)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_txq_t *txq;
  clib_error_t *error;

  if (qid >= vd->num_tx_queues)
    {
      qid = qid % vd->num_tx_queues;
      txq = vec_elt_at_index (vd->txqs, qid);
      if (txq->lock == 0)
	clib_spinlock_init (&txq->lock);
      vd->flags |= VMXNET3_DEVICE_F_SHARED_TXQ_LOCK;
      return 0;
    }

  vec_validate_aligned (vd->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (vd->txqs, qid);
  clib_memset (txq, 0, sizeof (*txq));
  txq->size = qsz;
  txq->tx_desc = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					     qsz * sizeof (*txq->tx_desc),
					     512);
  if (error)
    return error;
  clib_memset (txq->tx_desc, 0, qsz * sizeof (*txq->tx_desc));
  txq->tx_comp = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					     qsz * sizeof (*txq->tx_comp),
					     512);
  if (error)
    return error;
  clib_memset (txq->tx_comp, 0, qsz * sizeof (*txq->tx_comp));
  vec_validate_aligned (txq->tx_ring.bufs, txq->size, CLIB_CACHE_LINE_BYTES);
  txq->tx_ring.gen = VMXNET3_TXF_GEN;
  txq->tx_comp_ring.gen = VMXNET3_TXCF_GEN;

  return 0;
}

static clib_error_t *
vmxnet3_device_init (vlib_main_t * vm, vmxnet3_device_t * vd,
		     vmxnet3_create_if_args_t * args)
{
  clib_error_t *error = 0;
  u32 ret, i;
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vd->num_tx_queues = 1;
  vd->num_rx_queues = 1;
  vd->num_intrs = 2;

  /* Quiesce the device */
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_QUIESCE_DEV);
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret != 0)
    {
      error = clib_error_return (0, "error on quisecing device rc (%u)", ret);
      return error;
    }

  /* Reset the device */
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_RESET_DEV);
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret != 0)
    {
      error = clib_error_return (0, "error on resetting device rc (%u)", ret);
      return error;
    }

  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_VRRS);
  vd->version = count_leading_zeros (ret);
  vd->version = uword_bits - vd->version;

  if (vd->version == 0 || vd->version > 3)
    {
      error = clib_error_return (0, "unsupported hardware version %u",
				 vd->version);
      return error;
    }

  vmxnet3_reg_write (vd, 1, VMXNET3_REG_VRRS, 1 << (vd->version - 1));

  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_UVRS);
  if (ret & 1)
    vmxnet3_reg_write (vd, 1, VMXNET3_REG_UVRS, 1);
  else
    {
      error = clib_error_return (0, "unsupported upt version %u", ret);
      return error;
    }

  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_GET_LINK);
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret & 1)
    {
      vd->flags |= VMXNET3_DEVICE_F_LINK_UP;
      vd->link_speed = ret >> 16;
    }
  else
    {
      vd->flags &= ~VMXNET3_DEVICE_F_LINK_UP;
    }

  /* Get the mac address */
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_MACL);
  clib_memcpy (vd->mac_addr, &ret, 4);
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_MACH);
  clib_memcpy (vd->mac_addr + 4, &ret, 2);

  if (vmxm->physmem_region_alloc == 0)
    {
      u32 flags = VLIB_PHYSMEM_F_INIT_MHEAP | VLIB_PHYSMEM_F_HUGETLB;
      error =
	vlib_physmem_region_alloc (vm, "vmxnet3 descriptors", 4 << 20, 0,
				   flags, &vmxm->physmem_region);
      if (error)
	return error;
      vmxm->physmem_region_alloc = 1;
    }

  error = vmxnet3_rxq_init (vm, vd, 0, args->rxq_size);
  if (error)
    return error;

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      error = vmxnet3_txq_init (vm, vd, i, args->txq_size);
      if (error)
	return error;
    }

  error = vmxnet3_provision_driver_shared (vm, vd);
  if (error)
    return error;

  vmxnet3_write_mac (vd);

  /* Activate device */
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_ACTIVATE_DEV);
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret != 0)
    {
      error =
	clib_error_return (0, "error on activating device rc (%u)", ret);
      return error;
    }

  /* Disable interrupts */
  vmxnet3_disable_interrupt (vd);

  vec_foreach_index (i, vd->rxqs)
  {
    vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, i);

    vmxnet3_rxq_refill_ring0 (vm, vd, rxq);
    vmxnet3_rxq_refill_ring1 (vm, vd, rxq);
  }
  vd->flags |= VMXNET3_DEVICE_F_INITIALIZED;

  vmxnet3_enable_interrupt (vd);

  return error;
}

static void
vmxnet3_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  vmxnet3_device_t *vd = pool_elt_at_index (vmxm->devices, pd);
  u16 qid = line;

  if (vec_len (vd->rxqs) > qid && vd->rxqs[qid].int_mode != 0)
    vnet_device_input_set_interrupt_pending (vnm, vd->hw_if_index, qid);
}

static void
vmxnet3_irq_1_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  vmxnet3_device_t *vd = pool_elt_at_index (vmxm->devices, pd);
  u32 ret;

  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_GET_LINK);
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret & 1)
    {
      vd->flags |= VMXNET3_DEVICE_F_LINK_UP;
      vd->link_speed = ret >> 16;
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vd->flags &= ~VMXNET3_DEVICE_F_LINK_UP;
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
    }
}

static u8
vmxnet3_queue_size_valid (u16 qsz)
{
  if (qsz < 64 || qsz > 4096)
    return 0;
  if ((qsz % 64) != 0)
    return 0;
  return 1;
}

void
vmxnet3_create_if (vlib_main_t * vm, vmxnet3_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;

  if (args->rxq_size == 0)
    args->rxq_size = VMXNET3_NUM_RX_DESC;
  if (args->txq_size == 0)
    args->txq_size = VMXNET3_NUM_TX_DESC;

  if (!vmxnet3_queue_size_valid (args->rxq_size) ||
      !vmxnet3_queue_size_valid (args->txq_size))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error,
			   "queue size must be <= 4096, >= 64, "
			   "and multiples of 64");
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (vd, vmxm->devices, ({
    if (vd->pci_addr.as_u32 == args->addr.as_u32)
      {
	args->rv = VNET_API_ERROR_INVALID_VALUE;
	args->error =
	  clib_error_return (error, "PCI address in use");
	return;
      }
  }));
  /* *INDENT-ON* */

  pool_get (vmxm->devices, vd);
  vd->dev_instance = vd - vmxm->devices;
  vd->per_interface_next_index = ~0;
  vd->pci_addr = args->addr;

  if (args->enable_elog)
    vd->flags |= VMXNET3_DEVICE_F_ELOG;

  if ((error =
       vlib_pci_device_open (vm, &args->addr, vmxnet3_pci_device_ids, &h)))
    {
      pool_put (vmxm->devices, vd);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error =
	clib_error_return (error, "pci-addr %U", format_vlib_pci_addr,
			   &args->addr);
      return;
    }
  vd->pci_dev_handle = h;

  vlib_pci_set_private_data (vm, h, vd->dev_instance);

  if ((error = vlib_pci_bus_master_enable (vm, h)))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 0, (void **) &vd->bar[0])))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 1, (void **) &vd->bar[1])))
    goto error;

  if ((error = vlib_pci_register_msix_handler (vm, h, 0, 1,
					       &vmxnet3_irq_0_handler)))
    goto error;

  if ((error = vlib_pci_register_msix_handler (vm, h, 1, 1,
					       &vmxnet3_irq_1_handler)))
    goto error;

  if ((error = vlib_pci_enable_msix_irq (vm, h, 0, 2)))
    goto error;

  if ((error = vlib_pci_intr_enable (vm, h)))
    goto error;

  if ((error = vmxnet3_device_init (vm, vd, args)))
    goto error;

  /* create interface */
  error = ethernet_register_interface (vnm, vmxnet3_device_class.index,
				       vd->dev_instance, vd->mac_addr,
				       &vd->hw_if_index, vmxnet3_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, vd->hw_if_index);
  vd->sw_if_index = sw->sw_if_index;
  args->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vd->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, vd->hw_if_index,
				    vmxnet3_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, vd->hw_if_index, 0, ~0);
  if (vd->flags & VMXNET3_DEVICE_F_LINK_UP)
    vnet_hw_interface_set_flags (vnm, vd->hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
  return;

error:
  vmxnet3_delete_if (vm, vd);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = error;
}

void
vmxnet3_delete_if (vlib_main_t * vm, vmxnet3_device_t * vd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  u32 i, bi;
  u16 desc_idx;

  /* Quiesce the device */
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_QUIESCE_DEV);

  /* Reset the device */
  vmxnet3_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_RESET_DEV);

  if (vd->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, vd->hw_if_index, 0);
      ethernet_delete_interface (vnm, vd->hw_if_index);
    }

  vlib_pci_device_close (vm, vd->pci_dev_handle);

  /* *INDENT-OFF* */
  vec_foreach_index (i, vd->rxqs)
    {
      vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, i);
      u16 mask = rxq->size - 1;
      u16 rid;

      for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
	{
	  vmxnet3_rx_ring *ring;

	  ring = &rxq->rx_ring[rid];
	  desc_idx = (ring->consume + 1) & mask;
	  vlib_buffer_free_from_ring (vm, ring->bufs, desc_idx, rxq->size,
				      ring->fill);
	  vec_free (ring->bufs);
	  vlib_physmem_free (vm, vmxm->physmem_region, rxq->rx_desc[rid]);
	}
      vlib_physmem_free (vm, vmxm->physmem_region, rxq->rx_comp);
    }
  /* *INDENT-ON* */
  vec_free (vd->rxqs);

  /* *INDENT-OFF* */
  vec_foreach_index (i, vd->txqs)
    {
      vmxnet3_txq_t *txq = vec_elt_at_index (vd->txqs, i);
      u16 mask = txq->size - 1;
      u16 end_idx;

      desc_idx = txq->tx_ring.consume;
      end_idx = txq->tx_ring.produce;
      while (desc_idx != end_idx)
	{
	  bi = txq->tx_ring.bufs[desc_idx];
	  vlib_buffer_free_no_next (vm, &bi, 1);
	  desc_idx++;
	  desc_idx &= mask;
	}
      clib_spinlock_free (&txq->lock);
      vec_free (txq->tx_ring.bufs);
      vlib_physmem_free (vm, vmxm->physmem_region, txq->tx_desc);
      vlib_physmem_free (vm, vmxm->physmem_region, txq->tx_comp);
    }
  /* *INDENT-ON* */
  vec_free (vd->txqs);

  vlib_physmem_free (vm, vmxm->physmem_region, vd->dma);

  clib_error_free (vd->error);
  clib_memset (vd, 0, sizeof (*vd));
  pool_put (vmxm->devices, vd);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
