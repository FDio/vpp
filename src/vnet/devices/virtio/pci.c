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

#include <fcntl.h>
#include <sys/ioctl.h>

#include <vppinfra/types.h>
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

#define PCI_VENDOR_ID_VIRTIO				0x1af4
#define PCI_DEVICE_ID_VIRTIO_NIC			0x1000
/* Don't support modern device */
#define PCI_DEVICE_ID_VIRTIO_NIC_MODERN			0x1041

#define PCI_CAPABILITY_LIST     0x34
#define PCI_CAP_ID_VNDR         0x09
#define PCI_CAP_ID_MSIX         0x11

virtio_pci_main_t virtio_pci_main;

static pci_device_id_t virtio_pci_device_ids[] = {
  {
   .vendor_id = PCI_VENDOR_ID_VIRTIO,
   .device_id = PCI_DEVICE_ID_VIRTIO_NIC},
  {
   .vendor_id = PCI_VENDOR_ID_VIRTIO,
   .device_id = PCI_DEVICE_ID_VIRTIO_NIC_MODERN},
  {0},
};

#define _(t)                                                    \
static_always_inline void                                       \
virtio_pci_reg_write_##t (virtio_if_t * vd, u32 addr, void *val)\
{                                                               \
  *(volatile t *) ((u8 *) vd->bar[0] + addr) = *((t *)val);     \
}

_(u32);
_(u16);
_(u8);

#undef _

#define _(t)                                                    \
static_always_inline t                                          \
virtio_pci_reg_read_##t (virtio_if_t * vd, u32 addr)            \
{                                                               \
  return *(volatile t *) (vd->bar[0] + addr);                   \
}

_(u32);
_(u16);
_(u8);

#undef _

static u64
legacy_get_features(virtio_if_t * vd)
{       
  u32 dst;

  dst = virtio_pci_reg_read_u32 (vd, VIRTIO_PCI_HOST_FEATURES);      
  return dst;
}

/*static void
legacy_set_features(virtio_if_t * vd, u64 features)
{       
  if ((features >> 32) != 0) {
    clib_warning("only 32 bit features are allowed for legacy virtio!");
      return;
    }
  virtio_pci_reg_write_u32 (vd, VIRTIO_PCI_GUEST_FEATURES, &features);
}
*/
static u8
legacy_get_status(virtio_if_t * vd)
{       
   return virtio_pci_reg_read_u8 (vd, VIRTIO_PCI_STATUS);
}
/*
static void
legacy_set_status(virtio_if_t * vd, u8 status)
{
  virtio_pci_reg_write_u8 (vd, VIRTIO_PCI_STATUS, &status);
}

static void
legacy_reset(virtio_if_t * vd)
{       
  legacy_set_status(vd, VIRTIO_CONFIG_STATUS_RESET);
}

static u8
legacy_get_isr(virtio_if_t * vd)
{
  return virtio_pci_reg_read_u8 (vd, VIRTIO_PCI_ISR);
}

/ Enable one vector (0) for Link State Intrerrupt /
static u16
legacy_set_config_irq(virtio_if_t * vd, u16 vec)
{       
        virtio_pci_reg_write_u16 (vd, VIRTIO_MSI_CONFIG_VECTOR, &vec);
        return virtio_pci_reg_read_u16 (vd, VIRTIO_MSI_CONFIG_VECTOR);
}
*/
/*

static u16
legacy_set_queue_irq(virtio_if_t * vd, struct virtqueue *vq, u16 vec)
{
virtio_pci_reg_write_u16 (vd, VIRTIO_PCI_QUEUE_SEL, &vq->vq_queue_index);
virtio_pci_reg_write_u16 (vd, VIRTIO_MSI_QUEUE_VECTOR, &vec);
return virtio_pci_reg_read_u16 (vd, VIRTIO_MSI_QUEUE_VECTOR);
}

static u16
legacy_get_queue_num(virtio_if_t * vd, u16 queue_id)
{
virtio_pci_reg_write_u16 (vd, VIRTIO_PCI_QUEUE_SEL, &queue_id);
return virtio_pci_reg_read_u16 (vd, VIRTIO_PCI_QUEUE_NUM);
}

static void
legacy_setup_queue(virtio_if_t * vd, struct virtqueue *vq)
{
        virtio_pci_reg_write_u16 (vd, VIRTIO_PCI_QUEUE_SEL, &vq->vq_queue_index);
        virtio_pci_reg_write_u32 (vd, VIRTIO_PCI_QUEUE_PFN, vq->vq_ring_mem >> VIRTIO_PCI_QUEUE_ADDR_SHIFT);
}

static void
legacy_del_queue(virtio_if_t * vd, struct virtqueue *vq)
{
p
    u32 src = 0;
         virtio_pci_reg_write_u16 (vd, VIRTIO_PCI_QUEUE_SEL, &vq->vq_queue_index);
virtio_pci_reg_write_u32 (vd, VIRTIO_PCI_QUEUE_PFN, &src);
}

static void
legacy_notify_queue(virtio_if_t * vd, struct virtqueue *vq)
{
  virtio_pci_reg_write_u16 (vd, VIRTIO_PCI_QUEUE_NOTIFY, &vq->vq_queue_index);
}
*/

/*
static clib_error_t *
virtio_pci_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				 u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  virtio_pci_device_t *vd = vec_elt_at_index (vmxm->devices, hi->dev_instance);
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
virtio_pci_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
				  vnet_hw_interface_rx_mode mode)
{
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_pci_device_t *vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);
  virtio_pci_rxq_t *rxq = vec_elt_at_index (vd->rxqs, qid);

  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    rxq->int_mode = 0;
  else
    rxq->int_mode = 1;

  return 0;
}

static void
virtio_pci_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				 u32 node_index)
{
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_pci_device_t *vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);

  / Shut off redirection /
  if (node_index == ~0)
    {
      vd->per_interface_next_index = node_index;
      return;
    }

  vd->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), virtio_pci_input_node.index,
			node_index);
}

static char *virtio_pci_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_virtio_pci_tx_func_error
#undef _
};
*/
/* *INDENT-OFF* */
/*VNET_DEVICE_CLASS (virtio_pci_device_class,) =
{
  .name = "VMXNET3 interface",
  .format_device = format_virtio_pci_device,
  .format_device_name = format_virtio_pci_device_name,
  .admin_up_down_function = virtio_pci_interface_admin_up_down,
  .rx_mode_change_function = virtio_pci_interface_rx_mode_change,
  .rx_redirect_to_node = virtio_pci_set_interface_next_node,
  .tx_function_n_errors = VMXNET3_TX_N_ERROR,
  .tx_function_error_strings = virtio_pci_tx_func_error_strings,
};*/
/* *INDENT-ON* */

static u32
virtio_pci_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw,
			u32 flags)
{
  return 0;
}

/*
static void
virtio_pci_write_mac (virtio_pci_device_t * vd)
{
  u32 val;

  memcpy (&val, vd->mac_addr, 4);
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_MACL, val);

  val = 0;
  memcpy (&val, vd->mac_addr + 4, 2);
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_MACH, val);
}

static clib_error_t *
virtio_pci_provision_driver_shared (vlib_main_t * vm, virtio_pci_device_t * vd)
{
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  virtio_pci_shared *shared;
  virtio_pci_queues *q;
  u64 shared_dma;
  clib_error_t *error;
  u16 qid = 0, rid;
  virtio_pci_rxq_t *rxq = vec_elt_at_index (vd->rxqs, qid);
  virtio_pci_txq_t *txq = vec_elt_at_index (vd->txqs, qid);

  vd->dma = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					sizeof (*vd->dma), 512);
  if (error)
    return error;

  memset (vd->dma, 0, sizeof (*vd->dma));

  q = &vd->dma->queues;
  q->tx.cfg.desc_address = virtio_pci_dma_addr (vm, vd, txq->tx_desc);
  q->tx.cfg.comp_address = virtio_pci_dma_addr (vm, vd, txq->tx_comp);
  q->tx.cfg.num_desc = txq->size;
  q->tx.cfg.num_comp = txq->size;
  for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
    {
      q->rx.cfg.desc_address[rid] = virtio_pci_dma_addr (vm, vd,
						      rxq->rx_desc[rid]);
      q->rx.cfg.num_desc[rid] = rxq->size;
    }
  q->rx.cfg.comp_address = virtio_pci_dma_addr (vm, vd, rxq->rx_comp);
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
  shared->misc.queue_desc_address = virtio_pci_dma_addr (vm, vd, q);
  shared->misc.queue_desc_len = sizeof (*q);
  shared->misc.mtu = VMXNET3_MTU;
  shared->misc.num_tx_queues = vd->num_tx_queues;
  shared->misc.num_rx_queues = vd->num_rx_queues;
  shared->interrupt.num_intrs = vd->num_intrs;
  shared->interrupt.event_intr_index = 1;
  shared->interrupt.control = VMXNET3_IC_DISABLE_ALL;
  shared->rx_filter.mode = VMXNET3_RXMODE_UCAST | VMXNET3_RXMODE_BCAST |
    VMXNET3_RXMODE_ALL_MULTI;
  shared_dma = virtio_pci_dma_addr (vm, vd, shared);

  virtio_pci_reg_write (vd, 1, VMXNET3_REG_DSAL, shared_dma);
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_DSAH, shared_dma >> 32);

  return 0;
}

static inline void
virtio_pci_enable_interrupt (virtio_pci_device_t * vd)
{
  int i;
  virtio_pci_shared *shared = &vd->dma->shared;

  shared->interrupt.control &= ~VMXNET3_IC_DISABLE_ALL;
  for (i = 0; i < vd->num_intrs; i++)
    virtio_pci_reg_write (vd, 0, VMXNET3_REG_IMR + i * 8, 0);
}

static inline void
virtio_pci_disable_interrupt (virtio_pci_device_t * vd)
{
  int i;
  virtio_pci_shared *shared = &vd->dma->shared;

  shared->interrupt.control |= VMXNET3_IC_DISABLE_ALL;
  for (i = 0; i < vd->num_intrs; i++)
    virtio_pci_reg_write (vd, 0, VMXNET3_REG_IMR + i * 8, 1);
}

static clib_error_t *
virtio_pci_rxq_init (vlib_main_t * vm, virtio_pci_device_t * vd, u16 qid, u16 qsz)
{
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  virtio_pci_rxq_t *rxq;
  clib_error_t *error;
  u16 rid;

  vec_validate_aligned (vd->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (vd->rxqs, qid);
  memset (rxq, 0, sizeof (*rxq));
  rxq->size = qsz;
  for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
    {
      rxq->rx_desc[rid] =
	vlib_physmem_alloc_aligned (vm, vmxm->physmem_region,
				    &error, qsz * sizeof (*rxq->rx_desc[rid]),
				    512);
      if (error)
	return error;
      memset (rxq->rx_desc[rid], 0, qsz * sizeof (*rxq->rx_desc[rid]));
    }
  rxq->rx_comp = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					     qsz * sizeof (*rxq->rx_comp),
					     512);
  if (error)
    return error;
  memset (rxq->rx_comp, 0, qsz * sizeof (*rxq->rx_comp));
  for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
    {
      virtio_pci_rx_ring *ring;

      ring = &rxq->rx_ring[rid];
      ring->gen = VMXNET3_RXF_GEN;
      vec_validate_aligned (ring->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
    }
  rxq->rx_comp_ring.gen = VMXNET3_RXCF_GEN;

  return 0;
}

static clib_error_t *
virtio_pci_txq_init (vlib_main_t * vm, virtio_pci_device_t * vd, u16 qid, u16 qsz)
{
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  virtio_pci_txq_t *txq;
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
  memset (txq, 0, sizeof (*txq));
  txq->size = qsz;
  txq->tx_desc = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					     qsz * sizeof (*txq->tx_desc),
					     512);
  if (error)
    return error;
  memset (txq->tx_desc, 0, qsz * sizeof (*txq->tx_desc));
  txq->tx_comp = vlib_physmem_alloc_aligned (vm, vmxm->physmem_region, &error,
					     qsz * sizeof (*txq->tx_comp),
					     512);
  if (error)
    return error;
  memset (txq->tx_comp, 0, qsz * sizeof (*txq->tx_comp));
  vec_validate_aligned (txq->tx_ring.bufs, txq->size, CLIB_CACHE_LINE_BYTES);
  txq->tx_ring.gen = VMXNET3_TXF_GEN;
  txq->tx_comp_ring.gen = VMXNET3_TXCF_GEN;

  return 0;
}

static clib_error_t *
virtio_pci_device_init (vlib_main_t * vm, virtio_pci_device_t * vd,
		     virtio_pci_create_if_args_t * args)
{
  clib_error_t *error = 0;
  u32 ret, i;
  virtio_pci_main_t *vmxm = &virtio_pci_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vd->num_tx_queues = 1;
  vd->num_rx_queues = 1;
  vd->num_intrs = 2;

  / Quiesce the device /
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_QUIESCE_DEV);
  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret != 0)
    {
      error = clib_error_return (0, "error on quisecing device rc (%u)", ret);
      return error;
    }

  / Reset the device /
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_RESET_DEV);
  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret != 0)
    {
      error = clib_error_return (0, "error on resetting device rc (%u)", ret);
      return error;
    }

  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_VRRS);
  vd->version = count_leading_zeros (ret);
  vd->version = uword_bits - vd->version;

  if (vd->version == 0 || vd->version > 3)
    {
      error = clib_error_return (0, "unsupported hardware version %u",
				 vd->version);
      return error;
    }

  virtio_pci_reg_write (vd, 1, VMXNET3_REG_VRRS, 1 << (vd->version - 1));

  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_UVRS);
  if (ret & 1)
    virtio_pci_reg_write (vd, 1, VMXNET3_REG_UVRS, 1);
  else
    {
      error = clib_error_return (0, "unsupported upt version %u", ret);
      return error;
    }

  virtio_pci_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_GET_LINK);
  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret & 1)
    {
      vd->flags |= VMXNET3_DEVICE_F_LINK_UP;
      vd->link_speed = ret >> 16;
    }
  else
    {
      vd->flags &= ~VMXNET3_DEVICE_F_LINK_UP;
    }

  / Get the mac address /
  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_MACL);
  clib_memcpy (vd->mac_addr, &ret, 4);
  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_MACH);
  clib_memcpy (vd->mac_addr + 4, &ret, 2);

  if (vmxm->physmem_region_alloc == 0)
    {
      u32 flags = VLIB_PHYSMEM_F_INIT_MHEAP | VLIB_PHYSMEM_F_HUGETLB;
      error =
	vlib_physmem_region_alloc (vm, "virtio_pci descriptors", 4 << 20, 0,
				   flags, &vmxm->physmem_region);
      if (error)
	return error;
      vmxm->physmem_region_alloc = 1;
    }

  error = virtio_pci_rxq_init (vm, vd, 0, args->rxq_size);
  if (error)
    return error;

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      error = virtio_pci_txq_init (vm, vd, i, args->txq_size);
      if (error)
	return error;
    }

  error = virtio_pci_provision_driver_shared (vm, vd);
  if (error)
    return error;

  virtio_pci_write_mac (vd);

  / Activate device /
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_ACTIVATE_DEV);
  ret = virtio_pci_reg_read (vd, 1, VMXNET3_REG_CMD);
  if (ret != 0)
    {
      error =
	clib_error_return (0, "error on activating device rc (%u)", ret);
      return error;
    }

  / Disable interrupts /
  virtio_pci_disable_interrupt (vd);

  vec_foreach_index (i, vd->rxqs)
  {
    virtio_pci_rxq_t *rxq = vec_elt_at_index (vd->rxqs, i);

    virtio_pci_rxq_refill_ring0 (vm, vd, rxq);
    virtio_pci_rxq_refill_ring1 (vm, vd, rxq);
  }
  vd->flags |= VMXNET3_DEVICE_F_INITIALIZED;

  virtio_pci_enable_interrupt (vd);

  return error;
}
*/
/*
static void
virtio_pci_irq_0_handler (vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vmxm = &virtio_main;
  uword pd = vlib_pci_get_private_data (h);
  virtio_if_t *vd = pool_elt_at_index (vmxm->interfaces, pd);
  u16 qid = line;

  if (vec_len (vd->rxqs) > qid && vd->rxqs[qid].int_mode != 0)
    vnet_device_input_set_interrupt_pending (vnm, vd->hw_if_index, qid);
}

static void
virtio_pci_irq_1_handler (vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vmxm = &virtio_main;
  uword pd = vlib_pci_get_private_data (h);
  virtio_if_t *vd = pool_elt_at_index (vmxm->interfaces, pd);
  u32 ret = 1;

**
 * FIXME: implement the virtio_net_config
 * Minimal driver: assumes link is up
 *

  if (ret & 1)
    {
      vd->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
      //vd->link_speed = ret >> 16;
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vd->flags &= ~VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
    }
}
*/
clib_error_t *
virtio_pci_read_caps (vlib_pci_dev_handle_t h, virtio_if_t * vd)
{
  clib_error_t *error = 0;
  struct virtio_pci_cap cap;
  u16 pos;

  if ((error = vlib_pci_read_config_u16 (h, PCI_CAPABILITY_LIST, &pos)))
    clib_error_return (error, "error here");
 
  //  pos = virtio_pci_reg_read_u8 (vd, PCI_CAPABILITY_LIST);
  while (pos)
    {
      if ((error =
	   vlib_pci_read_write_config (h, VLIB_READ, pos, &cap,
				       sizeof (cap))))
	clib_error_return (error, "error2 here");

      if (cap.cap_vndr == PCI_CAP_ID_MSIX)
	;
      if (cap.cap_vndr != PCI_CAP_ID_VNDR)
	;

      clib_warning ("[%2x] cfg type: %u, bar: %u, offset: %04x, len: %u/n",
	      pos, cap.cfg_type, cap.bar, cap.offset, cap.length);

      switch (cap.cfg_type)
	{
	case VIRTIO_PCI_CAP_COMMON_CFG:
	  clib_warning ("VIRTIO_PCI_CAP_COMMON_CFG");
	  //hw->common_cfg = get_cfg_addr(dev, &cap);
	  break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
	  //rte_pci_read_config(dev, &hw->notify_off_multiplier,
	  //                                4, pos + sizeof(cap));
	  //hw->notify_base = get_cfg_addr(dev, &cap);
	  clib_warning ("VIRTIO_PCI_CAP_NOTIFY_CFG");
	  break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
	  //hw->dev_cfg = get_cfg_addr(dev, &cap);
	  clib_warning ("VIRTIO_PCI_CAP_DEVICE_CFG");
	  break;
	case VIRTIO_PCI_CAP_ISR_CFG:
	  clib_warning ("VIRTIO_PCI_CAP_ISR_CFG");
	  //hw->isr = get_cfg_addr(dev, &cap);
	  break;
	}
      pos = cap.cap_next;
    }

  u64 device_features = legacy_get_features(vd);
  if (device_features & VIRTIO_NET_F_MTU)
    clib_warning("VIRTIO_NET_F_MTU");
  if (device_features & VIRTIO_NET_F_MAC)
    clib_warning("VIRTIO_NET_F_MAC");
  if (device_features & VIRTIO_NET_F_MRG_RXBUF)
    clib_warning("VIRTIO_NET_F_MRG_RXBUF");
  if (device_features & VIRTIO_NET_F_STATUS)
    clib_warning("VIRTIO_NET_F_STATUS");
  if (device_features & VIRTIO_NET_F_CTRL_VQ)
    clib_warning("VIRTIO_NET_F_CTRL_VQ");
  if (device_features & VIRTIO_NET_F_MQ)
    clib_warning("VIRTIO_NET_F_MQ");

  u8 device_status = legacy_get_status(vd);
  if (device_status & VIRTIO_CONFIG_STATUS_ACK)
    clib_warning("VIRTIO_CONFIG_STATUS_ACK");
  if (device_status & VIRTIO_CONFIG_STATUS_DRIVER)
    clib_warning("VIRTIO_CONFIG_STATUS_DRIVER");
  if (device_status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
    clib_warning("VIRTIO_CONFIG_STATUS_DRIVER_OK");
  if (device_status & VIRTIO_CONFIG_STATUS_FEATURES_OK)
    clib_warning("VIRTIO_CONFIG_STATUS_FEATURES_OK");

  return error;
}

static u8
virtio_pci_queue_size_valid (u16 qsz)
{
  if (qsz < 64 || qsz > 4096)
    return 0;
  if ((qsz % 64) != 0)
    return 0;
  return 1;
}

void
virtio_pci_create_if (vlib_main_t * vm, virtio_pci_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vmxm = &virtio_main;
  virtio_if_t *vd;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;

  if (args->rxq_size == 0)
    args->rxq_size = VIRTIO_NUM_RX_DESC;
  if (args->txq_size == 0)
    args->txq_size = VIRTIO_NUM_TX_DESC;

  if (!virtio_pci_queue_size_valid (args->rxq_size) ||
      !virtio_pci_queue_size_valid (args->txq_size))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error,
			   "queue size must be <= 4096, >= 64, "
			   "and multiples of 64");
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (vd, vmxm->interfaces, ({
    if (vd->pci_addr.as_u32 == args->addr.as_u32)
      {
	args->rv = VNET_API_ERROR_INVALID_VALUE;
	args->error =
	  clib_error_return (error, "PCI address in use");
	return;
      }
  }));
  /* *INDENT-ON* */

  pool_get (vmxm->interfaces, vd);
  vd->dev_instance = vd - vmxm->interfaces;
  vd->per_interface_next_index = ~0;
  vd->pci_addr.as_u32 =  args->addr.as_u32;

  if ((vd->fd = open ("/dev/vhost-net", O_RDWR | O_NONBLOCK)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      args->error = clib_error_return_unix (0, "open '/dev/vhost-net'");
      goto error;
    }

//  if (args->enable_elog)
//    vd->flags |= VIRTIO_DEVICE_F_ELOG;

  if ((error = vlib_pci_device_open (&args->addr, virtio_pci_device_ids, &h)))
    {
      pool_put (vmxm->interfaces, vd);
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
    if ((error = vlib_pci_map_region (h, 1, (void **) &vd->bar[0])))
      goto error;

//  linux_pci_device_t *lp = linux_pci_get_device (h);

//  vd->tap_fd = lp->fd;
  if ((error = virtio_pci_read_caps (h, vd)))
    goto error;
/*
  if ((error = vlib_pci_register_msix_handler (h, 0, 1,
					       &virtio_pci_irq_0_handler)))
    goto error;

  if ((error = vlib_pci_register_msix_handler (h, 1, 1,
					       &virtio_pci_irq_1_handler)))
    goto error;

  if ((error = vlib_pci_enable_msix_irq (h, 0, 2)))
    goto error;

  if ((error = vlib_pci_intr_enable (h)))
    goto error;
*/
  
//  if ((error = virtio_vring_init (vm, vd, 0, args->rxq_size)))
//    goto error;

//  if ((error = virtio_vring_init (vm, vd, 1, args->txq_size)))
//    goto error;

  f64 now = vlib_time_now (vm);
  u32 rnd;
  rnd = (u32) (now * 1e6);
  rnd = random_u32 (&rnd);

  memcpy (vd->mac_addr + 2, &rnd, sizeof (rnd));
  vd->mac_addr[0] = 2;
  vd->mac_addr[1] = 0xfe;

  vd->type = VIRTIO_IF_TYPE_PCI;
  /* create interface */
  error = ethernet_register_interface (vnm, virtio_device_class.index,
				       vd->dev_instance, vd->mac_addr,
				       &vd->hw_if_index,
				       virtio_pci_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, vd->hw_if_index);
  vd->sw_if_index = sw->sw_if_index;
  args->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vd->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, vd->hw_if_index,
				    virtio_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, vd->hw_if_index, 0, ~0);
  if (vd->flags & VIRTIO_IF_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, vd->hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
  return;

error:
  virtio_pci_delete_if (vm, vd);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = error;
}

void
virtio_pci_delete_if (vlib_main_t * vm, virtio_if_t * vd)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vmxm = &virtio_main;
//  u32 i, bi;
//  u16 desc_idx;

/*  / Quiesce the device /
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_QUIESCE_DEV);

  / Reset the device /
  virtio_pci_reg_write (vd, 1, VMXNET3_REG_CMD, VMXNET3_CMD_RESET_DEV);
*/
  if (vd->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, vd->hw_if_index, 0);
      ethernet_delete_interface (vnm, vd->hw_if_index);
    }

  vlib_pci_device_close (vd->pci_dev_handle);

  /* *INDENT-OFF* */
/*  vec_foreach_index (i, vd->rxqs)
    {
      virtio_pci_rxq_t *rxq = vec_elt_at_index (vd->rxqs, i);
      u16 mask = rxq->size - 1;
      u16 rid;

      for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
	{
	  virtio_pci_rx_ring *ring;

	  ring = &rxq->rx_ring[rid];
	  desc_idx = (ring->consume + 1) & mask;
	  vlib_buffer_free_from_ring (vm, ring->bufs, desc_idx, rxq->size,
				      ring->fill);
	  vec_free (ring->bufs);
	  vlib_physmem_free (vm, vmxm->physmem_region, rxq->rx_desc[rid]);
	}
      vlib_physmem_free (vm, vmxm->physmem_region, rxq->rx_comp);
    }*/
  /* *INDENT-ON* */
//  vec_free (vd->rxqs);

  /* *INDENT-OFF* */
/*  vec_foreach_index (i, vd->txqs)
    {
      virtio_pci_txq_t *txq = vec_elt_at_index (vd->txqs, i);
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
    }*/
  /* *INDENT-ON* */
/*  vec_free (vd->txqs);

  vlib_physmem_free (vm, vmxm->physmem_region, vd->dma);
*/
  if (vd->fd != -1)
    close (vd->fd);
  if (vd->tap_fd != -1)
    vd->tap_fd = -1;
  clib_error_free (vd->error);
  memset (vd, 0, sizeof (*vd));
  pool_put (vmxm->interfaces, vd);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
