/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/file.h>
#include <ibverbs.h>

#undef always_inline
#include <infiniband/verbs.h>

VLIB_REGISTER_LOG_CLASS (ibv_log, static) = {
  .class_name = "ibverbs",
  .subclass_name = "init",
};

#define _(f, n, s, d) { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t ibv_rx_node_counters[] = { foreach_ibv_rx_node_counter };
vlib_error_desc_t ibv_tx_node_counters[] = { foreach_ibv_tx_node_counter };
#undef _

vnet_dev_node_t ibv_rx_node = {
  .error_counters = ibv_rx_node_counters,
  .n_error_counters = ARRAY_LEN (ibv_rx_node_counters),
  .format_trace = format_ibv_rx_trace,
};
vnet_dev_node_t ibv_tx_node = {
  .error_counters = ibv_tx_node_counters,
  .n_error_counters = ARRAY_LEN (ibv_tx_node_counters),
  .format_trace = format_ibv_tx_trace,
};

static int
ibv_port_mac (vnet_dev_t *dev, struct ibv_context *ctx, u8 ibv_port, int gid_tbl_len,
	      vnet_dev_hw_addr_t *hw_addr)
{
  struct ibv_gid_entry gid_entry = {};
  u8 mac[6];
  int gid_index;
  int rv_ibv;

  log_debug (dev, "ibv_port_mac: port %u", ibv_port);

  for (gid_index = 0; gid_index < gid_tbl_len; gid_index++)
    {
      rv_ibv = ibv_query_gid_ex (ctx, ibv_port, gid_index, &gid_entry, 0);
      if (rv_ibv)
	{
	  log_err (dev, "ibv_query_gid_ex failed port %u index %d rv %d", ibv_port, gid_index,
		   rv_ibv);
	  continue;
	}
      log_debug (dev, "ibv_query_gid_ex ok port %u index %d", ibv_port, gid_index);
      if (gid_entry.gid_type != IBV_GID_TYPE_ROCE_V1 && gid_entry.gid_type != IBV_GID_TYPE_ROCE_V2)
	continue;
      if (!rdma_gid_to_mac (&gid_entry.gid, mac))
	continue;
      vnet_dev_set_hw_addr_eth_mac (hw_addr, mac);
      return 1;
    }

  return 0;
}

static vnet_dev_rv_t
ibv_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vlib_pci_addr_t addr = vnet_dev_get_pci_addr (dev);
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  struct ibv_device **dev_list = 0;
  struct ibv_device *ibv_dev = 0;
  struct ibv_context *ctx = 0;
  struct ibv_device_attr_ex dev_attr_ex = {};
  vlib_buffer_main_t *bm = vm->buffer_main;
  u32 buffer_size = vlib_buffer_get_default_data_size (vm);
  vlib_pci_addr_t ibv_addr = {};
  int n_devs = 0;
  int rv_ibv;
  u8 ip4_cksum_offload_cap = 0;
  u8 p;
  u8 *path = 0;

  log_debug (dev, "ibv_init");

  dev_list = ibv_get_device_list (&n_devs);
  if (!dev_list || n_devs <= 0)
    {
      if (!dev_list)
	log_err (dev, "ibv_get_device_list failed");
      else
	log_err (dev, "ibv_get_device_list returned %d devices", n_devs);
      if (dev_list)
	{
	  ibv_free_device_list (dev_list);
	  log_debug (dev, "ibv_free_device_list ok");
	}
      return VNET_DEV_ERR_NOT_READY;
    }
  log_debug (dev, "ibv_get_device_list ok n_devs %d", n_devs);

  for (u32 i = 0; i < n_devs; i++)
    {
      path = format (path, "%s/device%c", dev_list[i]->dev_path, 0);
      if (!rdma_sysfs_path_to_pci_addr ((char *) path, &ibv_addr))
	continue;

      vec_reset_length (path);

      if (ibv_addr.as_u32 != addr.as_u32)
	continue;

      ibv_dev = dev_list[i];
      break;
    }

  if (!ibv_dev)
    {
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  rd->ctx = ctx = ibv_open_device (ibv_dev);
  if (!ctx)
    {
      log_err (dev, "ibv_open_device failed");
      rv = VNET_DEV_ERR_BUS;
      goto done;
    }
  log_debug (dev, "ibv_open_device ok");

  rv_ibv = ibv_query_device_ex (ctx, 0, &dev_attr_ex);
  if (rv_ibv)
    {
      log_err (dev, "ibv_query_device_ex failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_BUS;
      goto done;
    }
  log_debug (dev, "ibv_query_device_ex ok");

  rd->pd = ibv_alloc_pd (ctx);
  if (rd->pd == 0)
    {
      log_err (dev, "ibv_alloc_pd failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }
  log_debug (dev, "ibv_alloc_pd ok");

  rd->mr =
    ibv_reg_mr (rd->pd, (void *) bm->buffer_mem_start, bm->buffer_mem_size, IBV_ACCESS_LOCAL_WRITE);
  if (rd->mr == 0)
    {
      log_err (dev, "ibv_reg_mr failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto done;
    }
  rd->lkey = rd->mr->lkey;
  log_debug (dev, "ibv_reg_mr ok lkey 0x%x", rd->lkey);

  rd->max_sge = dev_attr_ex.orig_attr.max_sge;

  log_debug (dev, "%U", format_rdma_dev_attr_ex, &dev_attr_ex);
  if (((dev_attr_ex.rss_caps.supported_qpts | dev_attr_ex.tso_caps.supported_qpts) &
       (1 << IBV_QPT_RAW_PACKET)) == 0)
    {
      log_err (dev, "raw packet qp type unsupported");
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  if (dev_attr_ex.rss_caps.max_rwq_indirection_table_size &&
      (dev_attr_ex.rss_caps.supported_qpts & (1 << IBV_QPT_RAW_PACKET)))
    {
      rd->rss = 1;
      rd->rss_max_ind_tbl_size = dev_attr_ex.rss_caps.max_rwq_indirection_table_size;
      rd->rss_hash_fields_mask = dev_attr_ex.rss_caps.rx_hash_fields_mask;
      rd->rss_hash_function = dev_attr_ex.rss_caps.rx_hash_function;
    }
  if (dev_attr_ex.raw_packet_caps & IBV_RAW_PACKET_CAP_IP_CSUM)
    ip4_cksum_offload_cap = 1;

  for (p = 1; p <= dev_attr_ex.orig_attr.phys_port_cnt; p++)
    {
      vnet_dev_port_id_t port_id = p;
      struct ibv_port_attr port_attr = {};
      u8 ibv_port = port_id;
      u32 max_queues = clib_min (dev_attr_ex.orig_attr.max_qp, dev_attr_ex.orig_attr.max_cq);
      u32 max_queue_size =
	clib_min (dev_attr_ex.orig_attr.max_cqe, dev_attr_ex.orig_attr.max_qp_wr);
      u32 max_sge = clib_min (IBV_RXQ_MAX_CHAIN_SZ, dev_attr_ex.orig_attr.max_sge);
      vnet_dev_port_add_args_t port;
      ibv_port_t port_data = {
	.promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID,
	.mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID,
      };

      if (!max_queues)
	{
	  log_err (dev, "ibv_add_port: no queues");
	  continue;
	}
      if (max_queue_size < VLIB_FRAME_SIZE)
	{
	  log_err (dev, "ibv_add_port: max_queue_size %u", max_queue_size);
	  continue;
	}

      max_queue_size = clib_min (max_queue_size, 32768);
      max_queues = clib_min (max_queues, 128);

      port = (vnet_dev_port_add_args_t){
		.port = {
		  .attr = {
	    .type = VNET_DEV_PORT_TYPE_ETHERNET,
	    .max_rx_queues = max_queues,
	    .max_tx_queues = max_queues,
		    .max_supported_rx_frame_size = max_sge * buffer_size,
		    .caps = {
		      .rss = rd->rss,
		      .interrupt_mode = 1,
		    },
	    .tx_offloads = {
	      .ip4_cksum = ip4_cksum_offload_cap,
	    },
	    .rx_offloads = {
	      .ip4_cksum = ip4_cksum_offload_cap,
	    },
	  },
		  .ops = {
	    .start = ibv_port_start,
	    .stop = ibv_port_stop,
	    .format_status = format_ibv_port_status,
	    .config_change_validate = ibv_port_cfg_change_validate,
	    .config_change = ibv_port_cfg_change,
		  },
		  .data_size = sizeof (ibv_port_t),
		  .initial_data = &port_data,
		},
	.rx_node = &ibv_rx_node,
	.tx_node = &ibv_tx_node,
	.rx_queue = {
	  .config = {
	    .data_size = sizeof (ibv_rxq_t),
	    .default_size = 2 * VLIB_FRAME_SIZE,
	    .max_size = max_queue_size,
	    .min_size = VLIB_FRAME_SIZE,
	    .size_is_power_of_two = 1,
	  },
		.ops = {
		  .alloc = ibv_rxq_alloc,
		  .free = ibv_rxq_free,
		  .format_info = format_ibv_rxq_info,
		},
	      },
	.tx_queue = {
	  .config = {
	    .data_size = sizeof (ibv_txq_t),
	    .default_size = 2 * VLIB_FRAME_SIZE,
	    .max_size = max_queue_size,
	    .min_size = VLIB_FRAME_SIZE,
	    .size_is_power_of_two = 1,
	  },
	  .ops = {
	    .alloc = ibv_txq_alloc,
	    .free = ibv_txq_free,
	    .format_info = format_ibv_txq_info,
	  },
	},
      };

      log_debug (dev, "ibv_add_port: port %u", port_id);

      rv_ibv = ibv_query_port (rd->ctx, ibv_port, &port_attr);
      if (rv_ibv)
	{
	  log_err (dev, "ibv_query_port failed port %u rv %d", ibv_port, rv_ibv);
	  continue;
	}
      log_debug (dev, "ibv_query_port ok port %u", ibv_port);

      log_debug (dev, "%U", format_rdma_port_attr, (u32) ibv_port, &port_attr);

      if (port_attr.link_layer != IBV_LINK_LAYER_ETHERNET)
	{
	  log_warn (dev, "ibv port %u non-ethernet link_layer %u, skipping", ibv_port,
		    port_attr.link_layer);
	  continue;
	}

      if (!ibv_port_mac (dev, rd->ctx, ibv_port, port_attr.gid_tbl_len, &port.port.attr.hw_addr))
	ethernet_mac_address_generate (port.port.attr.hw_addr.eth_mac);

      rv = vnet_dev_port_add (vm, dev, port_id, &port);
      if (rv != VNET_DEV_OK)
	goto done;
      {
	vnet_dev_port_t *vport = vnet_dev_get_port_by_id (dev, port_id);
	vnet_dev_port_state_changes_t changes = {};
	u32 speed = 0;

	if (vport)
	  {
	    if (port_attr.active_speed)
	      speed = rdma_port_speed (port_attr.active_speed);
	    if (speed)
	      {
		changes.change.link_speed = 1;
		changes.link_speed = speed;
	      }
	    changes.change.link_state = 1;
	    changes.link_state = port_attr.state == IBV_PORT_ACTIVE;
	    vnet_dev_port_state_change (vm, vport, changes);
	  }
      }
    }

  if (pool_elts (dev->ports) == 0)
    rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

done:
  if (rv != VNET_DEV_OK && rd->mr)
    {
      rv_ibv = ibv_dereg_mr (rd->mr);
      if (rv_ibv)
	log_err (dev, "ibv_dereg_mr failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dereg_mr ok");
      rd->mr = 0;
    }
  if (rv != VNET_DEV_OK && rd->pd)
    {
      rv_ibv = ibv_dealloc_pd (rd->pd);
      if (rv_ibv)
	log_err (dev, "ibv_dealloc_pd failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dealloc_pd ok");
      rd->pd = 0;
    }
  if (rv != VNET_DEV_OK && ctx)
    {
      rv_ibv = ibv_close_device (ctx);
      if (rv_ibv)
	log_err (dev, "ibv_close_device failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_close_device ok");
    }
  if (dev_list)
    {
      ibv_free_device_list (dev_list);
      log_debug (dev, "ibv_free_device_list ok");
    }
  vec_free (path);
  return rv;
}

static void
ibv_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ibv_dev_t *rd = vnet_dev_get_data (dev);
  int rv_ibv;

  log_debug (dev, "ibv_free");

  if (rd->mr)
    {
      rv_ibv = ibv_dereg_mr (rd->mr);
      if (rv_ibv)
	log_err (dev, "ibv_dereg_mr failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dereg_mr ok");
      rd->mr = 0;
    }
  if (rd->pd)
    {
      rv_ibv = ibv_dealloc_pd (rd->pd);
      if (rv_ibv)
	log_err (dev, "ibv_dealloc_pd failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_dealloc_pd ok");
      rd->pd = 0;
    }
  rv_ibv = ibv_close_device (rd->ctx);
  if (rv_ibv)
    log_err (dev, "ibv_close_device failed rv %d", rv_ibv);
  else
    log_debug (dev, "ibv_close_device ok");
}

static u8 *
ibv_probe (vlib_main_t *vm, vnet_dev_probe_args_t *a)
{
  vnet_dev_t *dev = 0;
  vnet_dev_bus_pci_device_info_t *di = a->device_info;
  struct ibv_device **dev_list;
  int n_devs = 0;
  int i;
  u8 *path = 0;
  u8 *s = 0;

  log_debug (dev, "ibv_probe");

  dev_list = ibv_get_device_list (&n_devs);
  if (!dev_list)
    return 0;

  for (i = 0; i < n_devs; i++)
    {
      vlib_pci_addr_t ibv_addr;

      path = format (path, "%s/device%c", dev_list[i]->dev_path, 0);
      if (rdma_sysfs_path_to_pci_addr ((char *) path, &ibv_addr) &&
	  ibv_addr.as_u32 == di->addr.as_u32)
	{
	  s = format (0, "%U - %U", format_dev_pci_vendor_name_from_ids, di->vendor_id,
		      format_dev_pci_device_name_from_ids, di->vendor_id, di->device_id);
	  break;
	}
      vec_reset_length (path);
    }

  ibv_free_device_list (dev_list);
  vec_free (path);

  return s;
}

VNET_DEV_REGISTER_DRIVER (ibv_generic) = {
  .name = "ibverbs",
  .bus = "pci",
  .passive = 1,
  .device = {
    .data_sz = sizeof (ibv_dev_t),
    .ops = {
      .init = ibv_init,
      .free = ibv_free,
      .probe = ibv_probe,
      .format_info = format_ibv_dev_info,
    },
  },
};
