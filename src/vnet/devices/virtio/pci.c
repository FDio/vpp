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
#include <linux/virtio_net.h>
#include <linux/virtio_ring.h>
#include <linux/vhost.h>
#include <sys/eventfd.h>
#if defined(__x86_64__)
#include <sys/io.h>
#endif

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

#define PCI_MSIX_ENABLE 0x8000

static u32 msix_enabled = 0;

#define PCI_CONFIG_SIZE ((msix_enabled == VIRTIO_MSIX_ENABLED) ? \
  24 : 20)

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

#if defined(__x86_64__)

#define _(t, x)                                                    \
static_always_inline void                                       \
virtio_pci_reg_write_##t (virtio_if_t * vd, u8 bar, u32 addr, void *val)\
{                                                               \
  x (*((t *)val), vd->bar[bar] + addr);     \
}

_(u32, outl_p);
_(u16, outw_p);
_(u8, outb_p);

#undef _

#define _(t, x)                                                    \
static_always_inline t                                          \
virtio_pci_reg_read_##t (virtio_if_t * vd, u8 bar, u32 addr)            \
{                                                               \
  return x (vd->bar[bar] + addr);                   \
}

_(u32, inl);
_(u16, inw);
_(u8, inb);

#undef _

#else

#define _(t)                                                    \
static_always_inline void                                       \
virtio_pci_reg_write_##t (virtio_if_t * vd, u8 bar, u32 addr, void *val)\
{                                                               \
  *(volatile t *) ((u8 *) vd->bar[bar] + addr) = *((t *)val);     \
}

_(u32);
_(u16);
_(u8);

#undef _

#define _(t)                                                    \
static_always_inline t                                          \
virtio_pci_reg_read_##t (virtio_if_t * vd, u8 bar,  u32 addr)            \
{                                                               \
  return *(volatile t *) (vd->bar[bar] + addr);                   \
}

_(u32);
_(u16);
_(u8);

#undef _

#endif

static void
virtio_pci_legacy_read_config (vlib_main_t * vm, virtio_if_t * vd, void *dst,
			       int len, u32 addr)
{
  u32 size = 0;
  vlib_pci_dev_handle_t h = vd->pci_dev_handle;

  while (len > 0)
    {
      if (len >= 4)
	{
	  size = 4;
	  vlib_pci_read_io_u32 (vm, h, PCI_CONFIG_SIZE + addr, dst);
	}
      else if (len >= 2)
	{
	  size = 2;
	  vlib_pci_read_io_u16 (vm, h, PCI_CONFIG_SIZE + addr, dst);
	}
      else
	{
	  size = 1;
	  vlib_pci_read_io_u8 (vm, h, PCI_CONFIG_SIZE + addr, dst);
	}
      dst = (u8 *) dst + size;
      addr += size;
      len -= size;
    }
}

static void
virtio_pci_legacy_write_config (vlib_main_t * vm, virtio_if_t * vd, void *src,
				int len, u32 addr)
{
  u32 size = 0;
  vlib_pci_dev_handle_t h = vd->pci_dev_handle;

  while (len > 0)
    {
      if (len >= 4)
	{
	  size = 4;
	  vlib_pci_write_io_u32 (vm, h, PCI_CONFIG_SIZE + addr, src);
	}
      else if (len >= 2)
	{
	  size = 2;
	  vlib_pci_write_io_u16 (vm, h, PCI_CONFIG_SIZE + addr, src);
	}
      else
	{
	  size = 1;
	  vlib_pci_write_io_u8 (vm, h, PCI_CONFIG_SIZE + addr, src);
	}
      src = (u8 *) src + size;
      addr += size;
      len -= size;
    }
}

static u64
virtio_pci_legacy_get_features (vlib_main_t * vm, virtio_if_t * vd)
{
  u32 features;
  vlib_pci_read_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_HOST_FEATURES,
			&features);
  return features;
}

static u32
virtio_pci_legacy_set_features (vlib_main_t * vm, virtio_if_t * vd,
				u64 features)
{
  if ((features >> 32) != 0)
    {
      clib_warning ("only 32 bit features are allowed for legacy virtio!");
    }
  u32 feature = 0, guest_features = (u32) features;
  vlib_pci_write_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			 &guest_features);
  vlib_pci_read_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			&feature);
  return feature;
}

static u8
virtio_pci_legacy_get_status (vlib_main_t * vm, virtio_if_t * vd)
{
  u8 status = 0;
  vlib_pci_read_io_u8 (vm, vd->pci_dev_handle, VIRTIO_PCI_STATUS, &status);
  return status;
}

static void
virtio_pci_legacy_set_status (vlib_main_t * vm, virtio_if_t * vd, u8 status)
{
  if (status != VIRTIO_CONFIG_STATUS_RESET)
    status |= virtio_pci_legacy_get_status (vm, vd);
  vlib_pci_write_io_u8 (vm, vd->pci_dev_handle, VIRTIO_PCI_STATUS, &status);
}

static u8
virtio_pci_legacy_reset (vlib_main_t * vm, virtio_if_t * vd)
{
  virtio_pci_legacy_set_status (vm, vd, VIRTIO_CONFIG_STATUS_RESET);
  return virtio_pci_legacy_get_status (vm, vd);
}

static u8
virtio_pci_legacy_get_isr (vlib_main_t * vm, virtio_if_t * vd)
{
  u8 isr = 0;
  vlib_pci_read_io_u8 (vm, vd->pci_dev_handle, VIRTIO_PCI_ISR, &isr);
  return isr;
}

/*
/ Enable one vector (0) for Link State Intrerrupt /
static u16
virtio_pci_legacy_set_config_irq(virtio_if_t * vd, u16 vec)
{
        virtio_pci_reg_write_u16 (vd, VIRTIO_MSI_CONFIG_VECTOR, &vec);
        return virtio_pci_reg_read_u16 (vd, VIRTIO_MSI_CONFIG_VECTOR);
}

static u16
virtio_pci_legacy_set_queue_irq(virtio_if_t * vd, struct virtqueue *vq, u16 vec)
{
virtio_pci_reg_write_u16 (vd, VIRTIO_PCI_QUEUE_SEL, &vq->vq_queue_index);
virtio_pci_reg_write_u16 (vd, VIRTIO_MSI_QUEUE_VECTOR, &vec);
return virtio_pci_reg_read_u16 (vd, VIRTIO_MSI_QUEUE_VECTOR);
}
*/

static u16
virtio_pci_legacy_get_queue_num (vlib_main_t * vm, virtio_if_t * vd,
				 u16 queue_id)
{
  u16 queue_num = 0;
  vlib_pci_write_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_read_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_NUM,
			&queue_num);
  return queue_num;
}


static void
virtio_pci_legacy_setup_queue (vlib_main_t * vm, virtio_if_t * vd,
			       u16 queue_id, void *p)
{
  u64 addr = vlib_physmem_get_pa (vm, p) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT;
  vlib_pci_write_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_write_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN,
			 (u32 *) & addr);
}

static void
virtio_pci_legacy_del_queue (vlib_main_t * vm, virtio_if_t * vd, u16 queue_id)
{
  u32 src = 0;
  vlib_pci_write_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_write_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN, &src);
}

inline void
virtio_pci_legacy_notify_queue (vlib_main_t * vm, virtio_if_t * vd,
				u16 queue_id)
{
  vlib_pci_write_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_NOTIFY,
			 &queue_id);
}

static u32
virtio_pci_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw,
			u32 flags)
{
  return 0;
}

static clib_error_t *
virtio_pci_get_max_virtqueue_pairs (vlib_main_t * vm, virtio_if_t * vd)
{
  virtio_net_config_t config;
  clib_error_t *error = 0;
  u16 max_queue_pairs = 1;

  if (vd->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
    {
      virtio_pci_legacy_read_config (vm, vd, &config.max_virtqueue_pairs,
				     sizeof (config.max_virtqueue_pairs), 8);
      max_queue_pairs = config.max_virtqueue_pairs;
    }

  if (max_queue_pairs < 1 || max_queue_pairs > 0x8000)
    clib_error_return (error, "max queue pair is %x", max_queue_pairs);

  vd->max_queue_pairs = max_queue_pairs;
  return error;
}

static void
virtio_pci_set_mac (vlib_main_t * vm, virtio_if_t * vd)
{
  virtio_pci_legacy_write_config (vm, vd, vd->mac_addr, sizeof (vd->mac_addr),
				  0);
}

static u32
virtio_pci_get_mac (vlib_main_t * vm, virtio_if_t * vd)
{
  if (vd->remote_features & VIRTIO_FEATURE (VIRTIO_NET_F_MAC))
    {
      virtio_pci_legacy_read_config (vm, vd, vd->mac_addr,
				     sizeof (vd->mac_addr), 0);
      return 0;
    }
  return 1;
}

static u16
virtio_pci_is_link_up (vlib_main_t * vm, virtio_if_t * vd)
{
  /*
   * Minimal driver: assumes link is up
   */
  u16 status = 1;
  if (vd->remote_features & VIRTIO_FEATURE (VIRTIO_NET_F_STATUS))
    virtio_pci_legacy_read_config (vm, vd, &status, sizeof (status),	/* mac */
				   6);
  return status;
}

static void
virtio_pci_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vmxm = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vd = pool_elt_at_index (vmxm->interfaces, pd);
  u16 qid = line;

  vnet_device_input_set_interrupt_pending (vnm, vd->hw_if_index, qid);
}

static void
virtio_pci_irq_1_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vmxm = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vd = pool_elt_at_index (vmxm->interfaces, pd);

  if (virtio_pci_is_link_up (vm, vd) & VIRTIO_NET_S_LINK_UP)
    {
      vd->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vd->flags &= ~VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
    }
}

static void
virtio_pci_irq_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  virtio_main_t *vmxm = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vd = pool_elt_at_index (vmxm->interfaces, pd);
  u8 isr = 0;
  u16 line = 0;

  isr = virtio_pci_legacy_get_isr (vm, vd);

  /*
   * If the lower bit is set: look through the used rings of
   * all virtqueues for the device, to see if any progress has
   * been made by the device which requires servicing.
   */
  if (isr & VIRTIO_PCI_ISR_INTR)
    virtio_pci_irq_0_handler (vm, h, line);

  if (isr & VIRTIO_PCI_ISR_CONFIG)
    virtio_pci_irq_1_handler (vm, h, line);
}

static_always_inline void
print_device_status (u8 device_status)
{
  clib_warning ("device_status %u", device_status);
  if (device_status & VIRTIO_CONFIG_STATUS_ACK)
    clib_warning ("VIRTIO_CONFIG_STATUS_ACK");
  if (device_status & VIRTIO_CONFIG_STATUS_DRIVER)
    clib_warning ("VIRTIO_CONFIG_STATUS_DRIVER");
  if (device_status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
    clib_warning ("VIRTIO_CONFIG_STATUS_DRIVER_OK");
  if (device_status & VIRTIO_CONFIG_STATUS_FEATURES_OK)
    clib_warning ("VIRTIO_CONFIG_STATUS_FEATURES_OK");
}

static_always_inline void
print_device_features (u64 device_features)
{
  clib_warning ("device_features 0x%llx", device_features);
  if (device_features & VIRTIO_FEATURE (VIRTIO_NET_F_MTU))
    clib_warning ("VIRTIO_NET_F_MTU");
  if (device_features & VIRTIO_FEATURE (VIRTIO_NET_F_MAC))
    clib_warning ("VIRTIO_NET_F_MAC");
  if (device_features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF))
    clib_warning ("VIRTIO_NET_F_MRG_RXBUF");
  if (device_features & VIRTIO_FEATURE (VIRTIO_NET_F_STATUS))
    clib_warning ("VIRTIO_NET_F_STATUS");
  if (device_features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
    clib_warning ("VIRTIO_NET_F_CTRL_VQ");
  if (device_features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
    clib_warning ("VIRTIO_NET_F_MQ");
  if (device_features & VIRTIO_FEATURE (VIRTIO_RING_F_EVENT_IDX))
    clib_warning ("VIRTIO_RING_F_EVENT_IDX");
}

static_always_inline void
print_device (virtio_if_t * vd)
{
  u32 data_u32;
  u16 data_u16;
  u8 data_u8;
  vlib_main_t *vm = vlib_get_main ();
  vlib_pci_read_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_HOST_FEATURES,
			&data_u32);
  clib_warning ("remote features 0x%lx", data_u32);
  vlib_pci_read_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			&data_u32);
  clib_warning ("guest features 0x%lx", data_u32);
  vlib_pci_read_io_u32 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN,
			&data_u32);
  clib_warning ("queue address 0x%lx", data_u32);
  vlib_pci_read_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_NUM,
			&data_u16);
  clib_warning ("queue size 0x%x", data_u16);
  vlib_pci_read_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			&data_u16);
  clib_warning ("queue select 0x%x", data_u16);
  vlib_pci_read_io_u16 (vm, vd->pci_dev_handle, VIRTIO_PCI_QUEUE_NOTIFY,
			&data_u16);
  clib_warning ("queue notify 0x%x", data_u16);
  vlib_pci_read_io_u8 (vm, vd->pci_dev_handle, VIRTIO_PCI_STATUS, &data_u8);
  clib_warning ("status 0x%x", data_u8);
  vlib_pci_read_io_u8 (vm, vd->pci_dev_handle, VIRTIO_PCI_ISR, &data_u8);
  clib_warning ("isr 0x%x", data_u8);

  u8 mac[6];
  virtio_pci_legacy_read_config (vm, vd, mac, sizeof (mac), 0);
  clib_warning ("mac %U", format_ethernet_address, mac);
  virtio_pci_legacy_read_config (vm, vd, &data_u16, sizeof (u16),	/* offset to status */
				 6);
  clib_warning ("link up/down status 0x%x", data_u16);
  virtio_pci_legacy_read_config (vm, vd, &data_u16, sizeof (u16),
				 /* offset to max_virtqueue */ 8);
  clib_warning ("num of virtqueue 0x%x", data_u16);
  virtio_pci_legacy_read_config (vm, vd, &data_u16, sizeof (u16),	/* offset to mtu */
				 10);
  clib_warning ("mtu 0x%x", data_u16);

  u32 i = PCI_CONFIG_SIZE + 12, a = 4;
  i += a;
  i &= ~a;
  for (; i < 64; i += 4)
    {
      u32 data = 0;
      vlib_pci_read_io_u32 (vm, vd->pci_dev_handle, i, &data);
      clib_warning ("0x%lx", data);
    }
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

clib_error_t *
virtio_pci_vring_init (vlib_main_t * vm, virtio_if_t * vd, u16 idx)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  struct vring vr;
  u32 i = 0;
  void *ptr;

  queue_size = virtio_pci_legacy_get_queue_num (vm, vd, idx);
  clib_warning ("queue size %u", queue_size);
  if (!virtio_pci_queue_size_valid (queue_size))
    clib_warning ("queue size is not valid");

  if (!is_pow2 (queue_size))
    return clib_error_return (0, "ring size must be power of 2");

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  vec_validate_aligned (vd->vrings, idx, CLIB_CACHE_LINE_BYTES);
  vring = vec_elt_at_index (vd->vrings, idx);

  i = vring_size (queue_size, VIRTIO_PCI_VRING_ALIGN);
  i = round_pow2 (i, VIRTIO_PCI_VRING_ALIGN);
  ptr = vlib_physmem_alloc_aligned (vm, i, VIRTIO_PCI_VRING_ALIGN);
  memset (ptr, 0, i);
  vring_init (&vr, queue_size, ptr, VIRTIO_PCI_VRING_ALIGN);
  vring->desc = vr.desc;
  vring->avail = vr.avail;
  vring->used = vr.used;
  vring->queue_id = idx;
  vring->avail->flags = VIRTIO_RING_FLAG_MASK_INT;

  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, queue_size, CLIB_CACHE_LINE_BYTES);
  ASSERT (vring->indirect_buffers == 0);
  vec_validate_aligned (vring->indirect_buffers, queue_size,
			CLIB_CACHE_LINE_BYTES);
  if (idx % 2)
    {
      u32 n_alloc = 0;
      do
	{
	  if (n_alloc < queue_size)
	    n_alloc =
	      vlib_buffer_alloc (vm, vring->indirect_buffers + n_alloc,
				 queue_size - n_alloc);
	}
      while (n_alloc != queue_size);
    }
  vring->size = queue_size;

  virtio_pci_legacy_setup_queue (vm, vd, idx, ptr);
  vring->kick_fd = -1;

  return error;
}

static void
virtio_negotiate_features (vlib_main_t * vm, virtio_if_t * vd,
			   u64 req_features)
{
  /*
   * if features are not requested
   * default: all supported features
   */
  if (req_features == 0)
    {
      req_features |= VIRTIO_FEATURE (VIRTIO_NET_F_MTU);
      req_features |= VIRTIO_FEATURE (VIRTIO_NET_F_MAC);
      req_features |= VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF);
      req_features |= VIRTIO_FEATURE (VIRTIO_NET_F_STATUS);
      req_features |= VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT);
      req_features |= VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC);
    }

  vd->features = req_features & vd->remote_features;

  if (vd->remote_features & vd->features & VIRTIO_FEATURE (VIRTIO_NET_F_MTU))
    {
      virtio_net_config_t config;
      virtio_pci_legacy_read_config (vm, vd, &config.mtu, sizeof (config.mtu),
				     10);
      if (config.mtu < 64)
	vd->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MTU);
    }

  vd->features = virtio_pci_legacy_set_features (vm, vd, vd->features);
}

void
virtio_pci_read_device_feature (vlib_main_t * vm, virtio_if_t * vd)
{
  vd->remote_features = virtio_pci_legacy_get_features (vm, vd);
  print_device_features (vd->remote_features);
}

int
virtio_pci_reset_device (vlib_main_t * vm, virtio_if_t * vd)
{
  u8 status = 0;

  /*
   * Reset the device
   */
  status = virtio_pci_legacy_reset (vm, vd);
  print_device_status (status);

  /*
   * Set the Acknowledge status bit
   */
  virtio_pci_legacy_set_status (vm, vd, VIRTIO_CONFIG_STATUS_ACK);

  /*
   * Set the Driver status bit
   */
  virtio_pci_legacy_set_status (vm, vd, VIRTIO_CONFIG_STATUS_DRIVER);

  /*
   * Read the status and verify it
   */
  status = virtio_pci_legacy_get_status (vm, vd);
  if (!
      ((status & VIRTIO_CONFIG_STATUS_ACK)
       && (status & VIRTIO_CONFIG_STATUS_DRIVER)))
    return -1;

  print_device_status (status);

  return 0;
}

clib_error_t *
virtio_pci_read_caps (vlib_main_t * vm, virtio_if_t * vd)
{
  clib_error_t *error = 0;
  struct virtio_pci_cap cap;
  u8 pos, common_cfg = 0, notify_base = 0, dev_cfg = 0, isr = 0;
  vlib_pci_dev_handle_t h = vd->pci_dev_handle;

  clib_warning ("bar address [%llx]", vd->bar[1]);

  if ((error = vlib_pci_read_config_u8 (vm, h, PCI_CAPABILITY_LIST, &pos)))
    clib_error_return (error, "error in reading capabilty list position");

  while (pos)
    {
      if ((error =
	   vlib_pci_read_write_config (vm, h, VLIB_READ, pos, &cap,
				       sizeof (cap))))
	clib_error_return (error, "error in reading the capability at [%2x]",
			   pos);

      if (cap.cap_vndr == PCI_CAP_ID_MSIX)
	{
	  u16 flags = ((u16 *) & cap)[1];

	  if (flags & PCI_MSIX_ENABLE)
	    msix_enabled = VIRTIO_MSIX_ENABLED;
	  else
	    msix_enabled = VIRTIO_MSIX_DISABLED;
	}

      if (cap.cap_vndr != PCI_CAP_ID_VNDR)
	{
	  clib_warning ("[%2x] skipping non VNDR cap id: %2x", pos,
			cap.cap_vndr);
	  goto next;
	}

      clib_warning ("[%4x] cfg type: %u, bar: %u, offset: %04x, len: %u",
		    pos, cap.cfg_type, cap.bar, cap.offset, cap.length);

      switch (cap.cfg_type)
	{
	case VIRTIO_PCI_CAP_COMMON_CFG:
	  clib_warning ("VIRTIO_PCI_CAP_COMMON_CFG");
	  common_cfg = 1;
	  break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
	  notify_base = 1;
	  clib_warning ("VIRTIO_PCI_CAP_NOTIFY_CFG");
	  break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
	  dev_cfg = 1;
	  clib_warning ("VIRTIO_PCI_CAP_DEVICE_CFG");
	  break;
	case VIRTIO_PCI_CAP_ISR_CFG:
	  isr = 1;
	  clib_warning ("VIRTIO_PCI_CAP_ISR_CFG");
	  break;
	}
    next:
      pos = cap.cap_next;
    }

  if (common_cfg == 0 || notify_base == 0 || dev_cfg == 0 || isr == 0)
    {
      clib_warning ("no modern virtio pci device found");
      return error;
    }

  return clib_error_return (error, "modern virtio pci device found");
}

static clib_error_t *
virtio_pci_device_init (vlib_main_t * vm, virtio_if_t * vd,
			virtio_pci_create_if_args_t * args)
{
  clib_error_t *error = 0;
  u8 status = 0;

  virtio_pci_read_caps (vm, vd);

  if (virtio_pci_reset_device (vm, vd) < 0)
    clib_error_return (error, "Failed to reset the device");

  /*
   * read device features and negotiate (user) requested features
   */
  virtio_pci_read_device_feature (vm, vd);
  virtio_negotiate_features (vm, vd, args->features);

  /*
   * After FEATURE_OK, driver should not accept new feature bits
   */
  virtio_pci_legacy_set_status (vm, vd, VIRTIO_CONFIG_STATUS_FEATURES_OK);
  status = virtio_pci_legacy_get_status (vm, vd);
  if (!(status & VIRTIO_CONFIG_STATUS_FEATURES_OK))
    clib_error_return (error, "Device doesn't support requested features");

  if (virtio_pci_get_mac (vm, vd))
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (vd->mac_addr + 2, &rnd, sizeof (rnd));
      vd->mac_addr[0] = 2;
      vd->mac_addr[1] = 0xfe;
      virtio_pci_set_mac (vm, vd);
    }

  virtio_set_net_hdr_size (vd);

  if ((error = virtio_pci_get_max_virtqueue_pairs (vm, vd)))
    goto error;

  if ((error = virtio_pci_vring_init (vm, vd, 0)))
    goto error;

  if ((error = virtio_pci_vring_init (vm, vd, 1)))
    goto error;

  virtio_pci_legacy_set_status (vm, vd, VIRTIO_CONFIG_STATUS_DRIVER_OK);

error:
  return error;
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
  vd->pci_addr.as_u32 = args->addr.as_u32;

  if ((vd->fd = open ("/dev/vhost-net", O_RDWR | O_NONBLOCK)) < 0)
    {
      args->rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      args->error = clib_error_return_unix (0, "open '/dev/vhost-net'");
      goto error;
    }

  if ((error =
       vlib_pci_device_open (vm, &args->addr, virtio_pci_device_ids, &h)))
    {
      pool_put (vmxm->interfaces, vd);
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

  void *bar[2];

  if ((error = vlib_pci_io_region (vm, h, 0)))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 1, (void **) &bar[1])))
    goto error;

  vd->bar[1] = ((u64) bar[1]);

  if ((error = virtio_pci_device_init (vm, vd, args)))
    goto error;

  if (msix_enabled == VIRTIO_MSIX_ENABLED)
    {
      if ((error = vlib_pci_register_msix_handler (vm, h, 0, 1,
						   &virtio_pci_irq_0_handler)))
	goto error;

      if ((error = vlib_pci_register_msix_handler (vm, h, 1, 1,
						   &virtio_pci_irq_1_handler)))
	goto error;

      if ((error = vlib_pci_enable_msix_irq (vm, h, 0, 2)))
	goto error;
    }
  else
    {
      vlib_pci_register_intx_handler (vm, h, &virtio_pci_irq_handler);
    }

  if ((error = vlib_pci_intr_enable (vm, h)))
    goto error;

  print_device (vd);

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

  if (virtio_pci_is_link_up (vm, vd) & VIRTIO_NET_S_LINK_UP)
    {
      vd->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
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
  u32 i = 0;

  vlib_pci_intr_disable (vm, vd->pci_dev_handle);

  virtio_pci_legacy_del_queue (vm, vd, 0);
  virtio_pci_legacy_del_queue (vm, vd, 1);

  virtio_pci_legacy_reset (vm, vd);

  if (vd->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, vd->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, vd->hw_if_index, 0);
      ethernet_delete_interface (vnm, vd->hw_if_index);
    }

  vlib_pci_device_close (vm, vd->pci_dev_handle);

  vec_foreach_index (i, vd->vrings)
  {
    virtio_vring_t *vring = vec_elt_at_index (vd->vrings, i);
    if (vring->kick_fd != -1)
      close (vring->kick_fd);
    if (vring->used)
      {
	if ((i & 1) == 1)
	  virtio_free_used_desc (vm, vring);
	else
	  virtio_free_rx_buffers (vm, vring);
      }
    if (vring->queue_id % 2)
      {
	vlib_buffer_free_no_next (vm, vring->indirect_buffers, vring->size);
      }
    vec_free (vring->buffers);
    vec_free (vring->indirect_buffers);
    vlib_physmem_free (vm, vring->desc);
  }

  vec_free (vd->vrings);

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
