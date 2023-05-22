/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/cache.h"
#include "vppinfra/format.h"
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>
#include "vpp/app/version.h"

VLIB_REGISTER_LOG_CLASS (ena_log) = {
  .class_name = "ena",
};

#include <ena/ena.h>
#include <ena/ena_inlines.h>
#include "ena/ena_defs.h"

ena_main_t ena_main;

static pci_device_id_t ena_pci_device_ids[] = {
  { .vendor_id = PCI_VENDOR_ID_AMAZON,
    .device_id = PCI_DEVICE_ID_AMAZON_ENA_PF },
  { .vendor_id = PCI_VENDOR_ID_AMAZON,
    .device_id = PCI_DEVICE_ID_AMAZON_ENA_PF_RSERV0 },
  { .vendor_id = PCI_VENDOR_ID_AMAZON,
    .device_id = PCI_DEVICE_ID_AMAZON_ENA_VF },
  { .vendor_id = PCI_VENDOR_ID_AMAZON,
    .device_id = PCI_DEVICE_ID_AMAZON_ENA_VF_RSERV0 },
  { 0 },
};

clib_error_t *
ena_physmem_alloc (vlib_main_t *vm, ena_device_t *ed, u32 sz, void **pp,
		   char *name)
{
  void *p;
  clib_error_t *err;

  p = vlib_physmem_alloc_aligned_on_numa (vm, sz, CLIB_CACHE_LINE_BYTES,
					  ed->numa_node);
  if (p == 0)
    return vlib_physmem_last_error (vm);

  clib_memset (p, 0, sz);

  *pp = p;

  if ((err = vlib_pci_map_dma (vm, ed->pci_dev_handle, p)))
    return err;

  ena_log_info (
    ed, "%s: allocated %u bytes at %p (PA: 0x%lx) on numa %u for '%s'",
    __func__, sz, p, ena_dma_addr (vm, ed, p), ed->numa_node, name);

  return 0;
}

clib_error_t *
ena_dev_reset (vlib_main_t *vm, ena_device_t *ed,
	       ena_reg_reset_reason_t reason)
{
  ena_reg_caps_t caps;
  ena_reg_dev_sts_t dev_sts;
  ena_reg_dev_ctl_t reset_start = { .dev_reset = 1, .reset_reason = reason };

  ena_reg_read (ed, ENA_REG_DEV_STS, &dev_sts);
  ena_reg_read (ed, ENA_REG_CAPS, &caps);

  if (caps.as_u32 == ~0 && dev_sts.as_u32 == ~0)
    return clib_error_return (0,
			      "register BAR read failed, device reset failed");

  if (dev_sts.ready == 0)
    return clib_error_return (0, "device not ready, device reset failed");

  ena_log_debug (ed, "%s: reset timeout is %u", __func__, caps.reset_timeout);

  ena_reg_write (ed, ENA_REG_DEV_CTL, &reset_start);

  ena_set_mmio_resp (vm, ed);

  while (1)
    {
      int i = 0;
      ena_reg_read (ed, ENA_REG_DEV_STS, &dev_sts);
      if (dev_sts.reset_in_progress)
	break;
      if (i++ == 20)
	return clib_error_return (0, "failed to initiate reset");
      vlib_process_suspend (vm, 0.001);
    }

  ena_reg_write (ed, ENA_REG_DEV_CTL, &(ena_reg_dev_ctl_t){});

  while (1)
    {
      int i = 0;
      ena_reg_read (ed, ENA_REG_DEV_STS, &dev_sts);
      if (dev_sts.reset_in_progress == 0)
	break;
      if (i++ == 20)
	return clib_error_return (0, "failed to complete reset");
      vlib_process_suspend (vm, 0.001);
    }

  return 0;
}

static void
ena_reg_set_dma_addr (vlib_main_t *vm, ena_device_t *ed, u32 rlo, u32 rhi,
		      void *p)
{
  uword pa = ena_dma_addr (vm, ed, p);
  u32 reg = (u32) pa;
  ena_reg_write (ed, rlo, &reg);
  reg = pa >> 32;
  ena_reg_write (ed, rhi, &reg);
}

void
ena_destroy_rx_queue (vlib_main_t *vm, ena_device_t *ed, u32 queue_index)
{
  ena_rxq_t *rxq = pool_elt_at_index (ed->rxqs, queue_index);
  clib_error_t *err;

  if (rxq->sq_created)
    {
      ena_admin_destroy_sq_cmd_t cmd = { .sq_idx = rxq->sq_idx,
					 .sq_direction =
					   ENA_ADMIN_SQ_DIRECTION_RX };

      if ((err = ena_admin_destroy_sq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
    };

  if (rxq->cq_created)
    {
      ena_admin_destroy_cq_cmd_t cmd = { .cq_idx = rxq->cq_idx };
      if ((err = ena_admin_destroy_cq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
    };

  if (rxq->n_enq)
    vlib_buffer_free_from_ring_no_next (vm, rxq->buffers,
					rxq->next & (rxq->n_desc - 1),
					rxq->n_desc, rxq->n_enq);
  vec_free (rxq->buffers);
  vlib_physmem_free (vm, rxq->cqes);
  vlib_physmem_free (vm, rxq->sqes);
  pool_put_index (ed->rxqs, queue_index);
}

void
ena_destroy_tx_queue (vlib_main_t *vm, ena_device_t *ed, u32 queue_index)
{
  ena_txq_t *txq = pool_elt_at_index (ed->txqs, queue_index);
  clib_error_t *err;

  if (txq->sq_created)
    {
      ena_admin_destroy_sq_cmd_t cmd = { .sq_idx = txq->sq_idx,
					 .sq_direction =
					   ENA_ADMIN_SQ_DIRECTION_TX };

      if ((err = ena_admin_destroy_sq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
    };

  if (txq->cq_created)
    {
      ena_admin_destroy_cq_cmd_t cmd = { .cq_idx = txq->cq_idx };
      if ((err = ena_admin_destroy_cq (vm, ed, &cmd)))
	{
	  ena_log_err (ed, "destroy_rx_queue: %U", format_clib_error, err);
	  clib_error_free (err);
	}
    };

  if (txq->n_enq)
    vlib_buffer_free_from_ring_no_next (
      vm, txq->buffers, (txq->next - txq->n_enq) & (txq->n_desc - 1),
      txq->n_desc, txq->n_enq);
  vec_free (txq->buffers);
  vlib_physmem_free (vm, txq->cqes);
  vlib_physmem_free (vm, txq->sqes);
  pool_put_index (ed->txqs, queue_index);
}

void
ena_delete_if (vlib_main_t *vm, u32 dev_instance)
{
  ena_main_t *em = &ena_main;
  ena_device_t *ed = pool_elt_at_index (em->devices, dev_instance)[0];
  u32 i;

  pool_foreach_index (i, ed->rxqs)
    ena_destroy_rx_queue (vm, ed, i);
  pool_free (ed->rxqs);

  pool_foreach_index (i, ed->txqs)
    ena_destroy_tx_queue (vm, ed, i);
  pool_free (ed->txqs);

  if (ed->pci_dev_handle != ~0)
    vlib_pci_device_close (vm, ed->pci_dev_handle);

  vec_free (ed->name);
  vlib_physmem_free (vm, ed->mmio_resp);
  vlib_physmem_free (vm, ed->admin_sq_entries);
  vlib_physmem_free (vm, ed->admin_cq_entries);
  vlib_physmem_free (vm, ed->aenq_entries);
  vlib_physmem_free (vm, ed->host_info);
  vlib_physmem_free (vm, ed->debug_area);
  clib_mem_free (ed);
  pool_put_index (em->devices, dev_instance);

  if (pool_elts (em->devices) == 0)
    vlib_process_signal_event (vm, ena_process_node.index,
			       ENA_PROCESS_EVENT_STOP, 0);
}

clib_error_t *
ena_create_rx_queue (vlib_main_t *vm, ena_device_t *ed, u16 n_desc)
{
  clib_error_t *err;
  ena_rxq_t *rxq;
  u16 buffer_size = vlib_buffer_get_default_data_size (vm);

  ena_admin_create_cq_cmd_t cqcmd = {
    .interrupt_mode_enabled = 1,
    .cq_entry_size_words = sizeof (ena_rx_cdesc_t) / 4,
    .cq_depth = n_desc,
    .msix_vector = ~0,
  };

  ena_admin_create_sq_cmd_t sqcmd = {
    .sq_direction = ENA_ADMIN_SQ_DIRECTION_RX,
    .placement_policy = ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST,
    .completion_policy = ENA_ADMIN_SQ_COMPLETION_POLICY_DESC,
    .is_physically_contiguous = 1,
    .sq_depth = n_desc,
  };

  ena_admin_create_cq_resp_t cqresp;
  ena_admin_create_sq_resp_t sqresp;

  pool_get_zero (ed->rxqs, rxq);

  if ((err = ena_physmem_alloc (vm, ed, n_desc * sizeof (ena_rx_cdesc_t),
				(void **) &rxq->cqes, "rx queue cqe")))
    goto done;

  if ((err = ena_physmem_alloc (vm, ed, n_desc * sizeof (ena_rx_desc_t),
				(void **) &rxq->sqes, "rx queue sqe")))
    goto done;

  /* Create Completion Queue */
  ena_set_mem_addr (vm, ed, &cqcmd.cq_ba, rxq->cqes);
  if ((err = ena_admin_create_cq (vm, ed, &cqcmd, &cqresp)))
    goto done;

  rxq->cq_created = 1;
  rxq->cq_idx = cqresp.cq_idx;

  /* Create Submission Queue */
  sqcmd.cq_idx = cqresp.cq_idx;
  ena_set_mem_addr (vm, ed, &sqcmd.sq_ba, rxq->sqes);
  if ((err = ena_admin_create_sq (vm, ed, &sqcmd, &sqresp)))
    goto done;

  rxq->sq_created = 1;
  rxq->sq_idx = sqresp.sq_idx;
  rxq->sq_db = (u32 *) ((u8 *) ed->reg_bar + sqresp.sq_doorbell_offset);

  /* Enqueue Buffers */
  vec_validate_aligned (rxq->buffers, n_desc - 1, CLIB_CACHE_LINE_BYTES);
  rxq->n_enq =
    vlib_buffer_alloc_on_numa (vm, rxq->buffers, n_desc, ed->numa_node);

  if (rxq->n_enq == 0)
    {
      err = clib_error_return (
	0, "Unable to allocate at least one buffer for rx queue");
      goto done;
    }

  for (int i = 0; i < rxq->n_enq; i++)
    {
      u64 pa = vlib_buffer_get_pa (vm, vlib_get_buffer (vm, rxq->buffers[i]));
      ena_rx_desc_t *d = rxq->sqes + i;
      d->length = buffer_size;
      d->phase = 1;
      d->buff_addr_lo = pa;
      d->buff_addr_hi = pa >> 32;
      d->comp_req = 1;
    }

  __atomic_store_n (rxq->sq_db, 1, __ATOMIC_RELEASE);

done:
  if (err)
    ena_destroy_rx_queue (vm, ed, rxq - ed->rxqs);
  return err;
}

clib_error_t *
ena_create_tx_queue (vlib_main_t *vm, ena_device_t *ed, u16 n_desc)
{
  clib_error_t *err;
  ena_txq_t *txq;

  ena_admin_create_cq_cmd_t cqcmd = {
    .interrupt_mode_enabled = 1,
    .cq_entry_size_words = sizeof (ena_tx_cdesc_t) / 4,
    .cq_depth = n_desc,
    .msix_vector = ~0,
  };

  ena_admin_create_sq_cmd_t sqcmd = {
    .sq_direction = ENA_ADMIN_SQ_DIRECTION_TX,
    .placement_policy = ENA_ADMIN_SQ_PLACEMENT_POLICY_HOST,
    .completion_policy = ENA_ADMIN_SQ_COMPLETION_POLICY_DESC,
    .is_physically_contiguous = 1,
    .sq_depth = n_desc,
  };

  ena_admin_create_cq_resp_t cqresp;
  ena_admin_create_sq_resp_t sqresp;

  pool_get_zero (ed->txqs, txq);
  txq->n_desc = n_desc;

  if ((err = ena_physmem_alloc (vm, ed, n_desc * sizeof (ena_tx_cdesc_t),
				(void **) &txq->cqes, "tx queue cqe")))
    goto done;

  if ((err = ena_physmem_alloc (vm, ed, n_desc * sizeof (ena_tx_desc_t),
				(void **) &txq->sqes, "tx queue sqe")))
    goto done;

  /* Create Completion Queue */
  ena_set_mem_addr (vm, ed, &cqcmd.cq_ba, txq->cqes);
  if ((err = ena_admin_create_cq (vm, ed, &cqcmd, &cqresp)))
    goto done;

  txq->cq_created = 1;
  txq->cq_idx = cqresp.cq_idx;

  /* Create Submission Queue */
  sqcmd.cq_idx = cqresp.cq_idx;
  ena_set_mem_addr (vm, ed, &sqcmd.sq_ba, txq->sqes);
  if ((err = ena_admin_create_sq (vm, ed, &sqcmd, &sqresp)))
    goto done;

  txq->sq_created = 1;
  txq->sq_idx = sqresp.sq_idx;
  txq->sq_db = (u32 *) ((u8 *) ed->reg_bar + sqresp.sq_doorbell_offset);

done:
  if (err)
    ena_destroy_tx_queue (vm, ed, txq - ed->txqs);
  return err;
}

clib_error_t *
ena_create_if (vlib_main_t *vm, ena_create_if_args_t *args)
{
  ena_main_t *em = &ena_main;
  ena_device_t *ed, **edp;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_pci_dev_handle_t h;
  clib_error_t *err = 0, *err2;
  vnet_eth_interface_registration_t eir = {};
  ena_reg_version_t ver;
  ena_reg_controller_version_t ctrl_ver;
  u8 revision_id;
  int i;

  pool_get_zero (em->devices, edp);
  ed = clib_mem_alloc_aligned (sizeof (ena_device_t), CLIB_CACHE_LINE_BYTES);
  edp[0] = ed;
  clib_memset (ed, 0, sizeof (ena_device_t));
  ed->dev_instance = edp - em->devices;
  ed->per_interface_next_index = ~0;
  ed->name = vec_dup (args->name);
  ed->pci_dev_handle = ~0;
  ed->pci_addr.as_u32 = args->addr.as_u32;

  if ((err2 = vlib_pci_device_open (vm, &args->addr, ena_pci_device_ids, &h)))
    {
      err = vnet_error (
	VNET_ERR_INVALID_INTERFACE,
	"unable to open ENA device with PCI address %U (error: %U)",
	format_vlib_pci_addr, &args->addr, format_clib_error, err2);
      clib_error_free (err2);
      goto done;
    }

  ed->pci_dev_handle = h;
  ed->numa_node = vlib_pci_get_numa_node (vm, h);

  if (vlib_pci_supports_virtual_addr_dma (vm, h))
    ed->va_dma = 1;

  vlib_pci_set_private_data (vm, h, ed->dev_instance);

  if ((err = vlib_pci_bus_master_enable (vm, h)))
    goto done;

  if ((err = vlib_pci_read_config_u8 (vm, h, 8, &revision_id)))
    goto done;

  ena_log_debug (ed, "revision_id 0x%x", revision_id);

  if ((err = vlib_pci_map_region (vm, h, 0, &ed->reg_bar)))
    goto done;

  ena_log_debug (ed, "BAR0 mapped at %p", ed->reg_bar);

  if ((err = ena_physmem_alloc (
	 vm, ed, round_pow2 (sizeof (ena_mmio_resp_t), CLIB_CACHE_LINE_BYTES),
	 (void **) &ed->mmio_resp, "mmio resp")))
    goto done;

  if ((err = ena_physmem_alloc (
	 vm, ed, sizeof (ena_admin_sq_entry_t) * ENA_ADMIN_QUEUE_DEPTH,
	 (void **) &ed->admin_sq_entries, "admin sq entries")))
    goto done;

  if ((err = ena_physmem_alloc (
	 vm, ed, sizeof (ena_admin_cq_entry_t) * ENA_ADMIN_QUEUE_DEPTH,
	 (void **) &ed->admin_cq_entries, "admin cq entries")))
    goto done;

  if ((err = ena_physmem_alloc (
	 vm, ed, sizeof (ena_aenq_entry_t) * ENA_ASYNC_QUEUE_DEPTH,
	 (void **) &ed->aenq_entries, "aenq entries")))
    goto done;

  if ((err = ena_physmem_alloc (vm, ed, 4096, (void **) &ed->host_info,
				"host info")))
    goto done;

  if ((err = ena_physmem_alloc (vm, ed, 4096, (void **) &ed->debug_area,
				"debug area")))
    goto done;

  ena_set_mmio_resp (vm, ed);

  if ((revision_id & 1) == 0)
    ed->readless = 1;

  if ((err = ena_dev_reset (vm, ed, ENA_REG_RESET_REASON_NORMAL)))
    goto done;

  ena_reg_read (ed, ENA_REG_VERSION, &ver);
  ena_reg_read (ed, ENA_REG_CONTROLLER_VERSION, &ctrl_ver);

  ena_log_info (ed, "version %u.%u controller_version %u.%u.%u impl_id %u\n",
		ver.major, ver.minor, ctrl_ver.major, ctrl_ver.minor,
		ctrl_ver.subminor, ctrl_ver.impl_id);

  ena_reg_set_dma_addr (vm, ed, ENA_REG_AQ_BASE_LO, ENA_REG_AQ_BASE_HI,
			ed->admin_sq_entries);
  ena_reg_set_dma_addr (vm, ed, ENA_REG_ACQ_BASE_LO, ENA_REG_ACQ_BASE_HI,
			ed->admin_cq_entries);
  ena_reg_set_dma_addr (vm, ed, ENA_REG_AENQ_BASE_LO, ENA_REG_AENQ_BASE_HI,
			ed->aenq_entries);

  ena_reg_write (
    ed, ENA_REG_AQ_CAPS,
    &(ena_reg_aq_caps_t){ .depth = ENA_ADMIN_QUEUE_DEPTH,
			  .entry_size = sizeof (ena_admin_sq_entry_t) });
  ena_reg_write (
    ed, ENA_REG_ACQ_CAPS,
    &(ena_reg_aq_caps_t){ .depth = ENA_ADMIN_QUEUE_DEPTH,
			  .entry_size = sizeof (ena_admin_cq_entry_t) });
  ena_reg_write (
    ed, ENA_REG_AENQ_CAPS,
    &(ena_reg_aq_caps_t){ .depth = ENA_ASYNC_QUEUE_DEPTH,
			  .entry_size = sizeof (ena_aenq_entry_t) });

  ena_log_debug (ed, "regs:\n%U", format_ena_regs, ed, -1);

  /* host info */
  ena_admin_host_info_t *hi = ed->host_info;
  hi->os_type = 3; /* DPDK */
  hi->kernel_ver = 23 * 16 + 5;
  hi->os_dist = 23 * 16 + 5;
  hi->driver_version.sub_minor = 1;
  hi->num_cpus = vlib_get_n_threads ();
  hi->ena_spec_version = 512;
  // hi->driver_supported_features.rss_configurable_function_key = 1;
  snprintf ((char *) hi->kernel_ver_str, sizeof (hi->kernel_ver_str), "%s",
	    VPP_BUILD_VER);
  snprintf ((char *) hi->os_dist_str, sizeof (hi->os_dist_str), "%s",
	    VPP_BUILD_VER);

  ena_admin_device_attr_feature_desc_t dev_attr;
  ena_admin_max_queue_ext_feature_desc_t max_q_ext;
  ena_admin_aenq_config_feature_desc_t aenq;
  ena_admin_stateless_offload_config_feature_desc_t offload;
  ena_admin_host_attr_config_feature_desc_t host_attr = {};
  ena_admin_llq_feature_desc_t llq;

  // host_attr.debug_area_size = 4096;
  ena_set_mem_addr (vm, ed, &host_attr.os_info_ba, ed->host_info);
  // ena_set_mem_addr (vm, ed, &host_attr.debug_ba, ed->debug_area);

  if ((err = ena_admin_set_feature (vm, ed, ENA_ADMIN_FEAT_ID_HOST_ATTR_CONFIG,
				    &host_attr)))
    goto done;

  if ((err = ena_admin_get_feature (
	 vm, ed, ENA_ADMIN_FEAT_ID_DEVICE_ATTRIBUTES, &dev_attr)))
    goto done;

  ed->supported_feat_id = dev_attr.supported_features;

  if (!ena_admin_feature_is_supported (ed, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT))
    {
      err = clib_error_return (
	0, "Device is uable to provide MAX_QUEUES_EXT feature");
      goto done;
    }
  else if ((err = ena_admin_get_feature (
	      vm, ed, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT, &max_q_ext)))
    goto done;

  aenq.enabled_groups.as_u32 = 0xff;
  aenq.supported_groups.as_u32 = 0xff;
  if ((err =
	 ena_admin_get_feature (vm, ed, ENA_ADMIN_FEAT_ID_AENQ_CONFIG, &aenq)))
    goto done;

  aenq.enabled_groups.as_u32 = 0;
  aenq.enabled_groups.link_change = 1;
  aenq.enabled_groups.fatal_error = 1;
  aenq.enabled_groups.warning = 1;
  aenq.enabled_groups.notification = 1;
  // aenq.enabled_groups.keep_alive = 1;
  aenq.enabled_groups.as_u32 &= aenq.supported_groups.as_u32;
  aenq.supported_groups.as_u32 = 0;

  if ((err =
	 ena_admin_set_feature (vm, ed, ENA_ADMIN_FEAT_ID_AENQ_CONFIG, &aenq)))
    goto done;

  ed->aenq_head = ENA_ASYNC_QUEUE_DEPTH;
  ena_reg_write (ed, ENA_REG_AENQ_HEAD_DB, &(u32){ ENA_ASYNC_QUEUE_DEPTH });

  if (ena_admin_feature_is_supported (
	ed, ENA_ADMIN_FEAT_ID_STATELESS_OFFLOAD_CONFIG))
    if ((err = ena_admin_get_feature (
	   vm, ed, ENA_ADMIN_FEAT_ID_STATELESS_OFFLOAD_CONFIG, &offload)))
      goto done;

  if (ena_admin_feature_is_supported (ed, ENA_ADMIN_FEAT_ID_LLQ))
    if ((err = ena_admin_get_feature (vm, ed, ENA_ADMIN_FEAT_ID_LLQ, &llq)))
      goto done;

  if ((err = ena_create_rx_queue (vm, ed, 512)))
    goto done;

  if ((err = ena_create_tx_queue (vm, ed, 512)))
    goto done;

  /* create interface */
  eir.dev_class_index = ena_device_class.index;
  eir.dev_instance = ed->dev_instance;
  eir.address = dev_attr.mac_addr;
  // FIXME eir.cb.flag_change = ena_flag_change;
  ed->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  ethernet_set_flags (vnm, ed->hw_if_index,
		      ETHERNET_INTERFACE_FLAG_DEFAULT_L3);

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ed->hw_if_index);
  args->sw_if_index = ed->sw_if_index = sw->sw_if_index;

  vnet_hw_if_set_input_node (vnm, ed->hw_if_index, ena_input_node.index);

  /* set hw interface caps */
  vnet_hw_if_set_caps (vnm, ed->hw_if_index,
		       VNET_HW_IF_CAP_INT_MODE | VNET_HW_IF_CAP_MAC_FILTER |
			 VNET_HW_IF_CAP_TX_CKSUM | VNET_HW_IF_CAP_TCP_GSO);

  pool_foreach_index (i, ed->rxqs)
    {
      u32 qi;
      qi = vnet_hw_if_register_rx_queue (vnm, ed->hw_if_index, i,
					 VNET_HW_IF_RXQ_THREAD_ANY);
      ed->rxqs[i].queue_index = qi;
    }

  pool_foreach_index (i, ed->txqs)
    {
      u32 qi = vnet_hw_if_register_tx_queue (vnm, ed->hw_if_index, i);
      ed->txqs[i].queue_index = qi;
    }

  for (int i = 0; i < vlib_get_n_threads (); i++)
    {
      u32 qi = ed->txqs[i % pool_elts (ed->txqs)].queue_index;
      vnet_hw_if_tx_queue_assign_thread (vnm, qi, i);
    }

  vnet_hw_if_update_runtime_data (vnm, ed->hw_if_index);

  ed->initialized = 1;

  if (pool_elts (em->devices) == 1)
    vlib_process_signal_event (vm, ena_process_node.index,
			       ENA_PROCESS_EVENT_START, 0);

done:
  if (err)
    ena_delete_if (vm, ed->dev_instance);
  return err;
}

static clib_error_t *
ena_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  ena_device_t *ad = ena_get_device (hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->error)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->admin_up = 1;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->admin_up = 0;
    }
  return 0;
}

static void
ena_set_interface_next_node (vnet_main_t *vnm, u32 hw_if_index, u32 node_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ena_device_t *ad = ena_get_device (hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), ena_input_node.index, node_index);
}

static clib_error_t *
ena_add_del_mac_address (vnet_hw_interface_t *hw, const u8 *address, u8 is_add)
{
  return 0;
}

static char *ena_tx_func_error_strings[] = {
#define _(n, s) s,
  foreach_ena_tx_func_error
#undef _
};

static void
ena_clear_hw_interface_counters (u32 instance)
{
}

VNET_DEVICE_CLASS (ena_device_class, ) = {
  .name = "Amazon Elastic Network Adapter (ENA) interface",
  .clear_counters = ena_clear_hw_interface_counters,
  .format_device = format_ena_device,
  .format_device_name = format_ena_device_name,
  .admin_up_down_function = ena_interface_admin_up_down,
  .rx_redirect_to_node = ena_set_interface_next_node,
  .mac_addr_add_del_function = ena_add_del_mac_address,
  .tx_function_n_errors = ENA_TX_N_ERROR,
  .tx_function_error_strings = ena_tx_func_error_strings,
};

clib_error_t *
ena_init (vlib_main_t *vm)
{
  ena_main_t *em = &ena_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (em->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

VLIB_INIT_FUNCTION (ena_init) = {
  .runs_after = VLIB_INITS ("pci_bus_init"),
};
