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

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vmxnet3_device_class,) =
{
  .name = "VMXNET3 interface",
  .tx_function = vmxnet3_interface_tx,
  .format_device = format_vmxnet3_device,
  .format_device_name = format_vmxnet3_device_name,
  .admin_up_down_function = vmxnet3_interface_admin_up_down,
  .rx_mode_change_function = vmxnet3_interface_rx_mode_change,
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

  vd->dma = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					sizeof (*vd->dma), 512);
  if (error)
    return error;

  memset (vd->dma, 0, sizeof (*vd->dma));

  q = &vd->dma->queues;
  q->tx.cfg.desc_address = vmxnet3_dma_addr (vm, vd, &vd->dma->tx_desc);
  q->tx.cfg.comp_address = vmxnet3_dma_addr (vm, vd, &vd->dma->tx_comp);
  q->tx.cfg.num_desc = VMXNET3_NUM_TX_DESC;
  q->tx.cfg.num_comp = VMXNET3_NUM_TX_COMP;
  q->rx.cfg.desc_address[0] = vmxnet3_dma_addr (vm, vd, &vd->dma->rx_desc);
  q->rx.cfg.comp_address = vmxnet3_dma_addr (vm, vd, &vd->dma->rx_comp);
  q->rx.cfg.num_desc[0] = VMXNET3_NUM_RX_DESC;
  q->rx.cfg.num_comp = VMXNET3_NUM_RX_COMP;

  shared = &vd->dma->shared;
  shared->magic = VMXNET3_SHARED_MAGIC;
  shared->misc.version = VMXNET3_VERSION_MAGIC;
  shared->misc.version_support = VMXNET3_VERSION_SELECT;
  shared->misc.upt_version_support = VMXNET3_UPT_VERSION_SELECT;
  shared->misc.queue_desc_address = vmxnet3_dma_addr (vm, vd, q);
  shared->misc.queue_desc_len = sizeof (*q);
  shared->misc.mtu = VMXNET3_MTU;
  shared->misc.num_tx_queues = 1;
  shared->misc.num_rx_queues = 1;
  shared->interrupt.num_intrs = 1;
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
vmxnet3_rxq_init (vlib_main_t * vm, vmxnet3_device_t * vd, u16 qid)
{
  vmxnet3_rxq_t *rxq;
  vmxnet3_rx_desc *rxd;
  u32 orig_rx_prod = vd->count.rx_prod;
  u32 desc_idx;
  u32 generation;
  u16 n_refill, n_alloc, mask = VMXNET3_NUM_RX_DESC - 1;

  vec_validate_aligned (vd->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (vd->rxqs, qid);
  rxq->size = VMXNET3_NUM_RX_DESC;
  rxq->next = 0;
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);

  desc_idx = vd->count.rx_prod & mask;
  n_refill = rxq->size;
  n_alloc = vlib_buffer_alloc_to_ring (vm, rxq->bufs, desc_idx, rxq->size,
				       n_refill);
  if (n_alloc != n_refill)
    {
      if (n_alloc)
	vlib_buffer_free (vm, rxq->bufs + desc_idx, n_alloc);
      return clib_error_return (0, "buffer alloc failed");
    }

  while (vd->count.rx_fill < VMXNET3_RX_FILL)
    {
      desc_idx = vd->count.rx_prod & mask;
      if (vd->count.rx_prod & VMXNET3_NUM_RX_DESC)
	generation = 0;
      else
	generation = VMXNET3_RXF_GEN;

      vd->count.rx_prod++;
      vd->count.rx_fill++;

      rxd = &vd->dma->rx_desc[desc_idx];
      rxd->address =
	vlib_get_buffer_data_physical_address (vm, rxq->bufs[desc_idx]);
      rxd->flags = generation | VMXNET3_MTU;
    }

  if (vd->count.rx_prod != orig_rx_prod)
    vmxnet3_reg_write (vd, 0, VMXNET3_REG_RXPROD, vd->count.rx_prod & mask);

  return 0;
}

static clib_error_t *
vmxnet3_txq_init (vlib_main_t * vm, vmxnet3_device_t * vd, u16 qid)
{
  vmxnet3_txq_t *txq;

  vec_validate_aligned (vd->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (vd->txqs, qid);
  txq->size = VMXNET3_NUM_TX_DESC;
  txq->next = 0;
  vec_validate_aligned (txq->bufs, txq->size, CLIB_CACHE_LINE_BYTES);

  return 0;
}

static clib_error_t *
vmxnet3_device_init (vlib_main_t * vm, vmxnet3_device_t * vd)
{
  clib_error_t *error = 0;
  u32 ret;
  vmxnet3_main_t *vmxm = &vmxnet3_main;

  vd->num_tx_queues = 1;
  vd->num_rx_queues = 1;
  vd->num_intrs = 1;

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

  /* Get the mac address */
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_MACL);
  clib_memcpy (vd->mac_addr, &ret, 4);
  ret = vmxnet3_reg_read (vd, 1, VMXNET3_REG_MACH);
  clib_memcpy (vd->mac_addr + 4, &ret, 2);

  if (vmxm->physmem_region_alloc == 0)
    {
      u32 flags = VLIB_PHYSMEM_F_INIT_MHEAP | VLIB_PHYSMEM_F_HUGETLB;
      error = vlib_physmem_region_alloc (vm, "vmxnet3 descriptors", 4 << 20, 0,
					 flags, &vmxm->physmem_region);
      if (error)
	return error;
      vmxm->physmem_region_alloc = 1;
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
      error = clib_error_return (0, "error on activating device rc (%u)", ret);
      return error;
    }

  /* Disable interrupts */
  vmxnet3_disable_interrupt(vd);

  error = vmxnet3_rxq_init (vm, vd, 0);
  if (error)
    return error;

  error = vmxnet3_txq_init (vm, vd, 0);
  if (error)
    return error;

  vd->flags |= VMXNET3_DEVICE_F_INITIALIZED;

  vmxnet3_enable_interrupt (vd);

  return error;
}

static void
vmxnet3_irq_handler (vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  uword pd = vlib_pci_get_private_data (h);
  vmxnet3_device_t *vd = pool_elt_at_index (vmxm->devices, pd);
  u16 qid = line;

  if (vec_len (vd->rxqs) > qid && vd->rxqs[qid].int_mode != 0)
    vnet_device_input_set_interrupt_pending (vnm, vd->hw_if_index, qid);
}

void
vmxnet3_create_if (vlib_main_t * vm, vmxnet3_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vmxnet3_device_t *vd;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;

  pool_get (vmxm->devices, vd);
  vd->dev_instance = vd - vmxm->devices;
  vd->per_interface_next_index = ~0;

  if (args->enable_elog)
    vd->flags |= VMXNET3_DEVICE_F_ELOG;

  if ((error = vlib_pci_device_open (&args->addr, vmxnet3_pci_device_ids, &h)))
    {
      pool_put (vmxm->devices, vd);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error =
	clib_error_return (error, "pci-addr %U", format_vlib_pci_addr,
			   &args->addr);
      return;
    }
  vd->pci_dev_handle = h;

  vlib_pci_set_private_data (h, vd->dev_instance);

  if ((error = vlib_pci_bus_master_enable (h)))
    goto error;

  if ((error = vlib_pci_map_region (h, 0, (void **) &vd->bar[0])))
    goto error;

  if ((error = vlib_pci_map_region (h, 1, (void **) &vd->bar[1])))
    goto error;

  if ((error = vlib_pci_register_msix_handler (h, 0, 1,
					       &vmxnet3_irq_handler)))
    goto error;

  if ((error = vlib_pci_enable_msix_irq (h, 0, 1)))
    goto error;

  if ((error = vlib_pci_intr_enable (h)))
    goto error;

  if ((error = vmxnet3_device_init (vm, vd)))
    goto error;

  /* create interface */
  error = ethernet_register_interface (vnm, vmxnet3_device_class.index,
				       vd->dev_instance, vd->mac_addr,
				       &vd->hw_if_index, vmxnet3_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, vd->hw_if_index);
  vd->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vd->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, vd->hw_if_index,
				    vmxnet3_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, vd->hw_if_index, 0, ~0);
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
  u32 i;

  if (vd->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, vd->hw_if_index, 0);
      ethernet_delete_interface (vnm, vd->hw_if_index);
    }

  vlib_pci_device_close (vd->pci_dev_handle);

  /* *INDENT-OFF* */
  vec_foreach_index (i, vd->rxqs)
    {
      vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, i);
      // FIXME
      // vlib_buffer_free_from_ring (vm, rxq->bufs, rxq->next, rxq->size,
      //			  rxq->n_enqueued);
      vec_free (rxq->bufs);
    }
  /* *INDENT-ON* */
  vec_free (vd->rxqs);

  /* *INDENT-OFF* */
  vec_foreach_index (i, vd->txqs)
    {
      vmxnet3_txq_t *txq = vec_elt_at_index (vd->txqs, i);
      // FIXME
      // vlib_buffer_free_from_ring (vm, txq->bufs, first, txq->size,
      //			  txq->n_enqueued);
      vec_free (txq->bufs);
    }
  /* *INDENT-ON* */
  vec_free (vd->txqs);

  vlib_physmem_free (vm, vmxm->physmem_region, vd->dma);

  clib_error_free (vd->error);
  memset (vd, 0, sizeof (*vd));
  pool_put (vmxm->devices, vd);
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "vmxnet device plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
