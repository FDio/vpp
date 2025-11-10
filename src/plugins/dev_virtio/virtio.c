/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <sys/types.h>
#include <vlib/vlib.h>

#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <dev_virtio/virtio.h>
#include <dev_virtio/inline.h>
#include <dev_virtio/pci.h>

VLIB_REGISTER_LOG_CLASS (virtio_log, static) = {
  .class_name = "virtio",
  .subclass_name = "init",
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t virtio_rx_node_counters[] = {
  foreach_virtio_rx_node_counter
};
vlib_error_desc_t virtio_tx_node_counters[] = {
  foreach_virtio_tx_node_counter
};
#undef _

vnet_dev_node_t virtio_rx_node = {
  .error_counters = virtio_rx_node_counters,
  .n_error_counters = ARRAY_LEN (virtio_rx_node_counters),
  .format_trace = format_virtio_rx_trace,
};

vnet_dev_node_t virtio_tx_node = {
  .error_counters = virtio_tx_node_counters,
  .n_error_counters = ARRAY_LEN (virtio_tx_node_counters),
  .format_trace = format_virtio_tx_trace,
};

virtio_main_t virtio_main;

u8 *
format_virtio_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  virtio_input_trace_t *t = va_arg (*args, virtio_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "virtio: hw_if_index %d next-index %d vring %u len %u",
	      t->hw_if_index, t->next_index, t->ring, t->len);
  s = format (s,
	      "\n%Uhdr: flags 0x%02x gso_type 0x%02x hdr_len %u "
	      "gso_size %u csum_start %u csum_offset %u num_buffers %u",
	      format_white_space, indent + 2, t->hdr.flags, t->hdr.gso_type,
	      t->hdr.hdr_len, t->hdr.gso_size, t->hdr.csum_start,
	      t->hdr.csum_offset, t->hdr.num_buffers);
  return s;
}

static void
virtio_free_buffers (vlib_main_t *vm, vnet_virtio_vring_t *vring)
{
  u16 used = vring->desc_in_use;
  u16 last = vring->last_used_idx;
  u16 mask = vring->queue_size - 1;

  while (used)
    {
      vlib_buffer_free (vm, &vring->buffers[last & mask], 1);
      last++;
      used--;
    }
}

void
virtio_vring_free_rx (vlib_main_t *vm, vnet_dev_t *dev,
		      vnet_virtio_vring_t *vring)
{
  if (vring->used)
    {
      virtio_free_buffers (vm, vring);
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
}

void
virtio_vring_free_tx (vlib_main_t *vm, vnet_dev_t *dev,
		      vnet_virtio_vring_t *vring)
{
  if (vring->used)
    {
      virtio_free_buffers (vm, vring);
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
  virtio_vring_buffering_free (vm, vring->buffering);
  clib_spinlock_free (&vring->lockp);
}

clib_error_t *
virtio_set_packet_buffering (vnet_dev_tx_queue_t *txq, u16 buffering_size)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_txq_t *vtq = vnet_dev_get_tx_queue_data (txq);
  vnet_virtio_vring_t *vring = &vtq->vring;
  u32 hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  clib_error_t *error;

  error = virtio_vring_buffering_init (&vring->buffering, hw->tx_node_index,
				       buffering_size);

  return error;
}

void
virtio_vring_fill (vlib_main_t *vm, virtio_if_t *vif,
		   vnet_virtio_vring_t *vring, vlib_node_runtime_t *node)
{
  if (vif->is_packed)
    virtio_refill_vring_packed (vm, vif, vring, vif->virtio_net_hdr_sz, node);
  else
    virtio_refill_vring_split (vm, vif, vring, vif->virtio_net_hdr_sz, node);
}

inline void
virtio_set_net_hdr_size (virtio_if_t *vif)
{
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF) ||
      vif->features & VIRTIO_FEATURE (VIRTIO_F_VERSION_1))
    vif->virtio_net_hdr_sz = sizeof (vnet_virtio_net_hdr_v1_t);
  else
    vif->virtio_net_hdr_sz = sizeof (vnet_virtio_net_hdr_t);
}

static vnet_dev_arg_t virtio_dev_args[] = {
  {
    .id = VIRTIO_DEV_ARG_BUFFERING,
    .name = "buffering",
    .desc = "enable buffering when no TX slots available",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = VIRTIO_DEV_ARG_BUFFERING_SIZE,
    .name = "buffering_size",
    .desc = "number of buffers to keep when no TX slots available",
    .type = VNET_DEV_ARG_TYPE_UINT32,
    .default_val.uint32 = 0,
  },
  {
    .id = VIRTIO_DEV_ARG_PACKED,
    .name = "packed",
    .desc = "enable packed ring",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = VIRTIO_DEV_ARG_RSS,
    .name = "rss",
    .desc = "enable RSS support",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = VIRTIO_DEV_ARG_GSO,
    .name = "gso",
    .desc = "enable GSO support",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = VIRTIO_DEV_ARG_CSUM,
    .name = "checksum",
    .desc = "enable checksum support",
    .type = VNET_DEV_ARG_TYPE_BOOL,
    .default_val.boolean = false,
  },
  {
    .id = VIRTIO_DEV_ARG_END,
    .name = "end",
    .desc = "Argument end",
    .type = VNET_DEV_ARG_END,
  },
};

static struct
{
  u16 device_id;
  char *desc;
} virtio_dev_types[] = {
  { PCI_DEVICE_ID_VIRTIO_NIC, "Virtio Legacy Device" },
  { PCI_DEVICE_ID_VIRTIO_NIC_MODERN, "Virtio Modern Device" },
};

static u8 *
virtio_device_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index,
		     void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;
  vlib_pci_addr_t pci = di->addr;

  if (di->vendor_id != PCI_VENDOR_ID_VIRTIO)
    return 0;

  if (vlib_pci_bind_to_uio (vm, &pci, (char *) "auto", VIRTIO_BIND_DEFAULT))
    return 0;

  FOREACH_ARRAY_ELT (dt, virtio_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->desc);
    }

  return 0;
}

static vnet_dev_rv_t
virtio_device_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);
  vnet_dev_rv_t rv;
  clib_error_t *error;
  void *bar[6];
  u16 queue_size, max_mtu, max_frame_sz;
  u32 n_threads = vlib_get_n_threads ();

  log_debug (dev, "init");

  for (u32 i = 0; i <= 5; i++)
    {
      rv = vnet_dev_pci_map_region (vm, dev, i, &bar[i]);
      log_debug (dev, "pci map region for bar %u at %p", i, bar[i]);
    }

  if ((error = vlib_pci_io_region (vm, vif->pci_dev_handle, 0)))
    {
      log_error (dev, "error encountered on pci io region: %s", error);
      return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
    }

  vif->n_rx_vectors =
    clib_min (n_threads, vnet_dev_get_pci_n_msix_interrupts (dev));

  // queue 0 is for link status
  vnet_dev_pci_msix_add_handler (vm, dev, &virtio_msix_n_handler, 1,
				 vif->n_rx_vectors);
  if (vnet_dev_pci_msix_enable (vm, dev, 1, vif->n_rx_vectors) == VNET_DEV_OK)
    vif->msix_enabled = VIRTIO_MSIX_ENABLED;

  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;

  foreach_vnet_dev_args (arg, dev)
    {
      switch (arg->id)
	{
	case VIRTIO_DEV_ARG_BUFFERING:
	  vif->packet_buffering = arg->val.boolean;
	  break;
	case VIRTIO_DEV_ARG_BUFFERING_SIZE:
	  vif->buffering_size = arg->val.uint32;
	  break;
	case VIRTIO_DEV_ARG_GSO:
	  vif->gso_enabled = arg->val.boolean;
	  break;
	case VIRTIO_DEV_ARG_CSUM:
	  vif->csum_offload_enabled = arg->val.boolean;
	  break;
	case VIRTIO_DEV_ARG_PACKED:
	  vif->is_packed = arg->val.boolean;
	  break;
	case VIRTIO_DEV_ARG_RSS:
	  vif->rss_enabled = arg->val.boolean;
	  break;
	default:
	  break;
	}
    }

  if ((error = virtio_pci_read_caps (vm, vif, bar)))
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  error = virtio_pci_device_init (vm, vif);
  if (error)
    return VNET_DEV_ERR_DEVICE_NO_REPLY;

  // rx-queue-size is fixed
  queue_size = virtio_pci_get_queue_size (vm, vif, RX_QUEUE (0));
  max_mtu = virtio_pci_get_mtu (vm, vif);
  if (max_mtu == 0 || max_mtu > ETHERNET_MAX_PACKET_BYTES)
    max_frame_sz = ETHERNET_MAX_PACKET_BYTES;
  else
    max_frame_sz = max_mtu + 14 /* ethernet header */ + 4 /* FCS */ +
		   2 * 4 /* two VLAN tags */;

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
	.max_rx_queues = vif->max_queue_pairs,
	.max_tx_queues = vif->max_queue_pairs,
        .max_supported_rx_frame_size = max_frame_sz,
        .caps = {
          .change_max_rx_frame_size = 1,
          .interrupt_mode = 1,
          .rss = 1,
          .mac_filter = 0,
        },
        .rx_offloads = {
          .ip4_cksum = 1,
        },
        .tx_offloads = {
          .ip4_cksum = 1,
          .tcp_gso = 1,
        },
      },
      .ops = {
        .init = virtio_port_init,
        .start = virtio_port_start,
        .stop = virtio_port_stop,
        .config_change = virtio_port_cfg_change,
        .config_change_validate = virtio_port_cfg_change_validate,
        .format_status = format_virtio_port_status,
      },
      .data_size = sizeof (virtio_port_t),
      .initial_data = 0,
    },
    .rx_node = &virtio_rx_node,
    .tx_node = &virtio_tx_node,
    .rx_queue = {
      .config = {
	.data_size = sizeof (virtio_rxq_t),
        .default_size = queue_size,
        .multiplier = 0,
        .min_size = queue_size,
        .max_size = queue_size,
	.size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = virtio_rx_queue_alloc,
        .free = virtio_rx_queue_free,
	.format_info = format_virtio_rx_queue_format_info,
      },
    },
    .tx_queue = {
      .config = {
	.data_size = sizeof (virtio_txq_t),
        .default_size =	256,
        .multiplier = 0,
        .min_size = 256,
        .max_size = 32768,
	.size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = virtio_tx_queue_alloc,
        .free = virtio_tx_queue_free,
	.format_info = format_virtio_tx_queue_format_info,
      },
    },
  };

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr,
				vif->mac_addr);

  return vnet_dev_port_add (vm, dev, 0, &port_add_args);
}

static void
virtio_device_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  virtio_main_t *vim = &virtio_main;
  virtio_if_t *vif;

  log_debug (dev, "free");

  vlib_worker_thread_barrier_sync (vlib_get_main ());
  vif = virtio_vnet_dev_get_if_valid (dev);
  if (vif)
    pool_put (vim->interfaces, vif);
  vlib_worker_thread_barrier_release (vlib_get_main ());
}

static vnet_dev_rv_t
virtio_device_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  virtio_device_t *vd = vnet_dev_get_data (dev);
  virtio_main_t *vim = &virtio_main;
  virtio_if_t *vif;

  log_debug (dev, "alloc");

  vlib_worker_thread_barrier_sync (vlib_get_main ());
  pool_get_zero (vim->interfaces, vif);

  vif->dev_index = dev->index;
  vif->pci_dev_handle = vnet_dev_get_pci_handle (dev);
  vif->numa_node = vlib_pci_get_numa_node (vm, vif->pci_dev_handle);

  vd->dev_instance = vif - vim->interfaces;
  vlib_worker_thread_barrier_release (vlib_get_main ());

  return VNET_DEV_OK;
}

static void
virtio_device_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);

  log_debug (dev, "deinit");

  if (vif->cxq_vring)
    {
      vnet_virtio_vring_t *vring = vec_elt_at_index (vif->cxq_vring, 0);
      if (vring->desc)
	vlib_physmem_free (vm, vif->cxq_vring->desc);
      vec_free (vif->cxq_vring);
    }
}

static vnet_dev_rv_t
virtio_device_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  virtio_if_t *vif = virtio_vnet_dev_get_if (dev);

  log_debug (dev, "reset");

  if (virtio_pci_device_init (vm, vif) != 0)
    return VNET_DEV_ERR_INTERNAL;

  return VNET_DEV_OK;
}

VNET_DEV_REGISTER_DRIVER (virtio) = {
  .name = "virtio",
  .bus = "pci",
  .device_data_sz = sizeof (virtio_device_t),
  .ops = {
    .probe = virtio_device_probe,
    .alloc = virtio_device_alloc,
    .init = virtio_device_init,
    .deinit = virtio_device_deinit,
    .free = virtio_device_free,
    .reset = virtio_device_reset,
  },
  .args = virtio_dev_args,
};

/* Plugin info */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_virtio",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
