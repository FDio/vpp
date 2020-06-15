/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/virtio_pci_modern.h>
#include <vnet/devices/virtio/pci.h>

static clib_error_t *
virtio_pci_modern_get_max_virtqueue_pairs (vlib_main_t * vm,
					   virtio_if_t * vif)
{
  clib_error_t *error = 0;
  u16 max_queue_pairs = 1;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
    max_queue_pairs = virtio_pci_modern_max_virtqueue_pairs (vif);

  virtio_log_debug (vif, "max queue pair is %x", max_queue_pairs);
  if (max_queue_pairs < 1 || max_queue_pairs > 0x8000)
    return clib_error_return (error, "max queue pair is %x,"
			      " should be in range [1, 0x8000]",
			      max_queue_pairs);

  vif->max_queue_pairs = max_queue_pairs;
  return error;
}

static void
virtio_pci_set_mac_modern (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_pci_modern_set_device_mac (vif);
}

static u32
virtio_pci_get_mac_modern (vlib_main_t * vm, virtio_if_t * vif)
{
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MAC))
    {
      virtio_pci_modern_device_mac (vif);
      return 0;
    }
  return 1;
}

static u16
virtio_pci_is_link_up (vlib_main_t * vm, virtio_if_t * vif)
{
  /*
   * Minimal driver: assumes link is up
   */
  u16 status = 1;
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_STATUS))
    status = virtio_pci_modern_device_status (vif);
  return status;
}

/*static void
virtio_pci_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, pd);
  u16 qid = line;

  vnet_device_input_set_interrupt_pending (vnm, vif->hw_if_index, qid);
}

static void
virtio_pci_irq_1_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, pd);

  if (virtio_pci_is_link_up (vm, vif) & VIRTIO_NET_S_LINK_UP)
    {
      vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vif->flags &= ~VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index, 0);
    }
}

static void
virtio_pci_irq_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  virtio_main_t *vim = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, pd);
  u8 isr = 0;
  u16 line = 0;

  isr = virtio_pci_modern_get_isr (vif);

  *
   * If the lower bit is set: look through the used rings of
   * all virtqueues for the device, to see if any progress has
   * been made by the device which requires servicing.
   *
  if (isr & VIRTIO_PCI_ISR_INTR)
    virtio_pci_irq_0_handler (vm, h, line);

  if (isr & VIRTIO_PCI_ISR_CONFIG)
    virtio_pci_irq_1_handler (vm, h, line);
}
*/

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
virtio_pci_control_vring_init (vlib_main_t * vm, virtio_if_t * vif,
			       u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  struct vring vr;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = virtio_pci_modern_get_queue_size (vif, queue_num);
  if (!virtio_pci_queue_size_valid (queue_size))
    clib_warning ("queue size is not valid");

  if (!is_pow2 (queue_size))
    return clib_error_return (0, "ring size must be power of 2");

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  vec_validate_aligned (vif->cxq_vring, 0, CLIB_CACHE_LINE_BYTES);
  vring = vec_elt_at_index (vif->cxq_vring, 0);
  i = vring_size (queue_size, VIRTIO_PCI_VRING_ALIGN);
  i = round_pow2 (i, VIRTIO_PCI_VRING_ALIGN);
  ptr =
    vlib_physmem_alloc_aligned_on_numa (vm, i, VIRTIO_PCI_VRING_ALIGN,
					vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);
  vring_init (&vr, queue_size, ptr, VIRTIO_PCI_VRING_ALIGN);
  vring->desc = vr.desc;
  vring->avail = vr.avail;
  vring->used = vr.used;
  vring->queue_id = queue_num;
  vring->avail->flags = VIRTIO_RING_FLAG_MASK_INT;

  ASSERT (vring->buffers == 0);

  vring->size = queue_size;
  virtio_log_debug (vif, "control-queue: number %u, size %u", queue_num,
		    queue_size);
  virtio_pci_modern_set_queue_desc (vif, queue_num,
				    pointer_to_uword (vr.desc));
  if (virtio_pci_modern_get_queue_desc (vif, queue_num) ==
      pointer_to_uword (vr.desc))
    return clib_error_return (0, "error in queue desc address setup");

  virtio_pci_modern_set_queue_driver (vif, queue_num,
				      pointer_to_uword (vr.avail));
  if (virtio_pci_modern_get_queue_driver (vif, queue_num) ==
      pointer_to_uword (vr.avail))
    return clib_error_return (0, "error in queue avail address setup");

  virtio_pci_modern_set_queue_device (vif, queue_num,
				      pointer_to_uword (vr.used));
  if (virtio_pci_modern_get_queue_device (vif, queue_num) ==
      pointer_to_uword (vr.used))
    return clib_error_return (0, "error in queue used address setup");
  vring->kick_fd = -1;

  return error;
}

clib_error_t *
virtio_pci_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  struct vring vr;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = virtio_pci_modern_get_queue_size (vif, queue_num);
  if (!virtio_pci_queue_size_valid (queue_size))
    clib_warning ("queue size is not valid");

  if (!is_pow2 (queue_size))
    return clib_error_return (0, "ring size must be power of 2");

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  if (queue_num % 2)
    {
      vec_validate_aligned (vif->txq_vrings, TX_QUEUE_ACCESS (queue_num),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS (queue_num));
      clib_spinlock_init (&vring->lockp);
    }
  else
    {
      vec_validate_aligned (vif->rxq_vrings, RX_QUEUE_ACCESS (queue_num),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (queue_num));
    }
  i = vring_size (queue_size, VIRTIO_PCI_VRING_ALIGN);
  i = round_pow2 (i, VIRTIO_PCI_VRING_ALIGN);
  ptr =
    vlib_physmem_alloc_aligned_on_numa (vm, i, VIRTIO_PCI_VRING_ALIGN,
					vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);
  vring_init (&vr, queue_size, ptr, VIRTIO_PCI_VRING_ALIGN);
  vring->desc = vr.desc;
  vring->avail = vr.avail;
  vring->used = vr.used;
  vring->queue_id = queue_num;
  vring->avail->flags = VIRTIO_RING_FLAG_MASK_INT;

  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, queue_size, CLIB_CACHE_LINE_BYTES);
  if (queue_num % 2)
    {
      virtio_log_debug (vif, "tx-queue: number %u, size %u", queue_num,
			queue_size);
      clib_memset_u32 (vring->buffers, ~0, queue_size);
    }
  else
    {
      virtio_log_debug (vif, "rx-queue: number %u, size %u", queue_num,
			queue_size);
    }
  vring->size = queue_size;
  virtio_pci_modern_set_queue_desc (vif, queue_num,
				    pointer_to_uword (vr.desc));
  if (virtio_pci_modern_get_queue_desc (vif, queue_num) ==
      pointer_to_uword (vr.desc))
    return clib_error_return (0, "error in queue desc address setup");

  virtio_pci_modern_set_queue_driver (vif, queue_num,
				      pointer_to_uword (vr.avail));
  if (virtio_pci_modern_get_queue_driver (vif, queue_num) ==
      pointer_to_uword (vr.avail))
    return clib_error_return (0, "error in queue avail address setup");

  virtio_pci_modern_set_queue_device (vif, queue_num,
				      pointer_to_uword (vr.used));
  if (virtio_pci_modern_get_queue_device (vif, queue_num) ==
      pointer_to_uword (vr.used))
    return clib_error_return (0, "error in queue used address setup");

  vring->kick_fd = -1;
  return error;
}

static void
virtio_negotiate_features_modern (vlib_main_t * vm, virtio_if_t * vif,
				  u64 req_features)
{
  /*
   * if features are not requested
   * default: all supported features
   */
  u64 supported_features = VIRTIO_FEATURE (VIRTIO_NET_F_CSUM)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM)
    | VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MTU)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MAC)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GSO)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_UFO)
    | VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO4)
    | VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO6)
    | VIRTIO_FEATURE (VIRTIO_NET_F_HOST_UFO)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF)
    | VIRTIO_FEATURE (VIRTIO_NET_F_STATUS)
    | VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MQ)
    | VIRTIO_FEATURE (VIRTIO_F_NOTIFY_ON_EMPTY)
    | VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT)
    | VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC)
    | VIRTIO_FEATURE (VIRTIO_F_VERSION_1);

  if (req_features == 0)
    {
      req_features = supported_features;
    }

  vif->features = req_features & vif->remote_features & supported_features;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MTU))
    {
      if (virtio_pci_modern_device_mtu (vif) < 64)
	vif->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MTU);
    }

  vif->features = virtio_pci_modern_set_driver_features (vif, vif->features);
}

void
virtio_pci_read_device_feature_modern (virtio_if_t * vif)
{
  vif->remote_features = virtio_pci_modern_get_device_features (vif);
}

int
virtio_pci_reset_device_modern (vlib_main_t * vm, virtio_if_t * vif)
{
  u8 status = 0;

  /*
   * Reset the device
   */
  status = virtio_pci_modern_reset (vif);

  /*
   * Set the Acknowledge status bit
   */
  virtio_pci_modern_set_status (vif, VIRTIO_CONFIG_STATUS_ACK);

  /*
   * Set the Driver status bit
   */
  virtio_pci_modern_set_status (vif, VIRTIO_CONFIG_STATUS_DRIVER);

  /*
   * Read the status and verify it
   */
  status = virtio_pci_modern_get_status (vif);
  if (!
      ((status & VIRTIO_CONFIG_STATUS_ACK)
       && (status & VIRTIO_CONFIG_STATUS_DRIVER)))
    return -1;
  vif->status = status;

  return 0;
}

clib_error_t *
virtio_pci_device_init_modern (vlib_main_t * vm, virtio_if_t * vif,
			       virtio_pci_create_if_args_t * args)
{
  clib_error_t *error = 0;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u8 status = 0;

  if (virtio_pci_reset_device_modern (vm, vif) < 0)
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      virtio_log_error (vif, "Failed to reset the device");
      clib_error_return (error, "Failed to reset the device");
    }
  /*
   * read device features and negotiate (user) requested features
   */
  virtio_pci_read_device_feature_modern (vif);
  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC)) ==
      0)
    {
      virtio_log_warning (vif, "error encountered: vhost-net backend doesn't "
			  "support VIRTIO_RING_F_INDIRECT_DESC features");
    }
  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF)) == 0)
    {
      virtio_log_warning (vif, "error encountered: vhost-net backend doesn't "
			  "support VIRTIO_NET_F_MRG_RXBUF features");
    }
  virtio_negotiate_features_modern (vm, vif, args->features);

  /*
   * After FEATURE_OK, driver should not accept new feature bits
   */
  virtio_pci_modern_set_status (vif, VIRTIO_CONFIG_STATUS_FEATURES_OK);
  status = virtio_pci_modern_get_status (vif);
  if (!(status & VIRTIO_CONFIG_STATUS_FEATURES_OK))
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      virtio_log_error (vif,
			"error encountered: Device doesn't support requested features");
      clib_error_return (error, "Device doesn't support requested features");
    }
  vif->status = status;

  /*
   * get or set the mac address
   */
  if (virtio_pci_get_mac_modern (vm, vif))
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (vif->mac_addr + 2, &rnd, sizeof (rnd));
      vif->mac_addr[0] = 2;
      vif->mac_addr[1] = 0xfe;
      virtio_pci_set_mac_modern (vm, vif);
    }

  virtio_set_net_hdr_size (vif);

  /*
   * Initialize the virtqueues
   */
  if ((error = virtio_pci_modern_get_max_virtqueue_pairs (vm, vif)))
    {
      args->rv = VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY;
      goto err;
    }

  for (int i = 0; i < vif->max_queue_pairs; i++)
    {
      if ((error = virtio_pci_vring_init (vm, vif, RX_QUEUE (i))))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  virtio_log_error (vif, "%s (%u) %s", "error in rxq-queue",
			    RX_QUEUE (i), "initialization");
	  clib_error_return (error, "%s (%u) %s", "error in rxq-queue",
			     RX_QUEUE (i), "initialization");
	}
      else
	{
	  vif->num_rxqs++;
	}

      if (i >= vtm->n_vlib_mains)
	{
	  /*
	   * There is 1:1 mapping between tx queue and vpp worker thread.
	   * tx queue 0 is bind with thread index 0, tx queue 1 on thread
	   * index 1 and so on.
	   * Multiple worker threads can poll same tx queue when number of
	   * workers are more than tx queues. In this case, 1:N mapping
	   * between tx queue and vpp worker thread.
	   */
	  virtio_log_debug (vif, "%s %u, %s", "tx-queue: number",
			    TX_QUEUE (i),
			    "no VPP worker thread is available");
	  continue;
	}

      if ((error = virtio_pci_vring_init (vm, vif, TX_QUEUE (i))))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  virtio_log_error (vif, "%s (%u) %s", "error in txq-queue",
			    TX_QUEUE (i), "initialization");
	  clib_error_return (error, "%s (%u) %s", "error in txq-queue",
			     TX_QUEUE (i), "initialization");
	}
      else
	{
	  vif->num_txqs++;
	}
    }

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
    {
      if ((error =
	   virtio_pci_control_vring_init (vm, vif, vif->max_queue_pairs * 2)))
	{
	  virtio_log_warning (vif, "%s (%u) %s", "error in control-queue",
			      vif->max_queue_pairs * 2, "initialization");
	  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
	    vif->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MQ);
	}
    }
  else
    {
      virtio_log_debug (vif, "control queue is not available");
      vif->cxq_vring = NULL;
    }

  /*
   * set the msix interrupts
   *
   if (vif->msix_enabled == VIRTIO_MSIX_ENABLED)
   {
   if (virtio_pci_legacy_set_config_irq (vm, vif, 1) ==
   VIRTIO_MSI_NO_VECTOR)
   virtio_log_warning (vif, "config vector 1 is not set");
   if (virtio_pci_legacy_set_queue_irq (vm, vif, 0, 0) ==
   VIRTIO_MSI_NO_VECTOR)
   virtio_log_warning (vif, "queue vector 0 is not set");
   }
   */
  /*
   * set the driver status OK
   */
  virtio_pci_modern_set_status (vif, VIRTIO_CONFIG_STATUS_DRIVER_OK);
  vif->status = virtio_pci_modern_get_status (vif);
err:
  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
