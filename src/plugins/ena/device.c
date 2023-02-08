/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include "ena/ena_aq_defs.h"
#include "vpp/app/version.h"
#include "vppinfra/cache.h"
#include "vppinfra/clib.h"
#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>
#include "ena/ena_defs.h"

#define ENA_ADMIN_QUEUE_LOG2_DEPTH 5
#define ENA_ADMIN_QUEUE_DEPTH	   (1 << ENA_ADMIN_QUEUE_LOG2_DEPTH)
#define ENA_ASYNC_QUEUE_DEPTH	   16

VLIB_REGISTER_LOG_CLASS (ena_log) = {
  .class_name = "ena",
};

VLIB_REGISTER_LOG_CLASS (ena_stats_log) = {
  .class_name = "ena",
  .subclass_name = "stats",
};

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

void
ena_delete_if (vlib_main_t *vm, u32 dev_instance)
{
  ena_main_t *em = &ena_main;
  ena_device_t *ed = pool_elt_at_index (em->devices, dev_instance)[0];

  vec_free (ed->rxqs);
  vec_free (ed->txqs);
  vec_free (ed->name);

  if (ed->pci_dev_handle != ~0)
    vlib_pci_device_close (vm, ed->pci_dev_handle);

  for (int i = 0; i < vec_len (ed->physmem_allocations); i++)
    vlib_physmem_free (vm, ed->physmem_allocations[i]);
  vec_free (ed->physmem_allocations);

  clib_mem_free (ed);
  pool_put_index (em->devices, dev_instance);
}

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
  vec_add1 (ed->physmem_allocations, p);

  *pp = p;

  if ((err = vlib_pci_map_dma (vm, ed->pci_dev_handle, p)))
    return err;

  ena_log_debug (
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

clib_error_t *
ena_aq_req (vlib_main_t *vm, ena_device_t *ed, ena_aq_entry_t *req,
	    ena_acq_entry_t *resp)
{
  u32 next = ed->aq_next++;
  u32 index = next & pow2_mask (ENA_ADMIN_QUEUE_DEPTH);
  ena_aq_entry_t *e = ed->aq_entries + index;

  u8 ena_aq_feat_ver[] = {
#define _(v, ver, n) [v] = (ver),
    foreach_ena_aq_feat_id
#undef _
  };

  clib_memcpy_fast (e, req, sizeof (ena_aq_entry_t));
  e->command_id = index;
  e->phase = ~(next >> ENA_ADMIN_QUEUE_LOG2_DEPTH);

  if (e->opcode == ENA_AQ_OPCODE_GET_FEATURE)
    e->get_feat.feature_version = ena_aq_feat_ver[e->get_feat.feature_id];
  else if (e->opcode == ENA_AQ_OPCODE_SET_FEATURE)
    e->set_feat.feature_version = ena_aq_feat_ver[e->set_feat.feature_id];

  ena_reg_write (ed, ENA_REG_AQ_DB, &ed->aq_next);
  vlib_process_suspend (vm, 0.2);
  fformat (stderr, "\n %U\n", format_hexdump, ed->aq_entries + index, 64);
  fformat (stderr, "\n %U\n", format_hexdump, ed->acq_entries + index, 64);
  clib_memcpy_fast (resp, ed->acq_entries + index, sizeof (ena_acq_entry_t));
  return 0;
}

clib_error_t *
ena_aq_set_feat_host_attr (vlib_main_t *vm, ena_device_t *ed)
{
  clib_error_t *err;
  ena_acq_entry_t r;
  ena_aq_entry_t e = { .opcode = ENA_AQ_OPCODE_SET_FEATURE,
		       .set_feat.feature_id = ENA_AQ_FEAT_ID_HOST_ATTR_CONFIG,
		       .set_feat.host_attr.debug_area_size = 4096 };

  ena_set_mem_addr (vm, ed, &e.set_feat.host_attr.os_info_ba, ed->host_info);
  ena_set_mem_addr (vm, ed, &e.set_feat.host_attr.debug_ba, ed->debug_area);

  if ((err = ena_aq_req (vm, ed, &e, &r)))
    return err;

  return 0;
}

clib_error_t *
ena_aq_get_feat_device_attr (vlib_main_t *vm, ena_device_t *ed)
{
  clib_error_t *err;
  ena_acq_entry_t r;
  ena_aq_entry_t e = { .opcode = ENA_AQ_OPCODE_GET_FEATURE,
		       .get_feat.feature_id =
			 ENA_AQ_FEAT_ID_DEVICE_ATTRIBUTES };
  typeof (r.dev_attr) *d = &r.dev_attr;

  if ((err = ena_aq_req (vm, ed, &e, &r)))
    return err;

  ed->supported_feat_id = d->supported_features;
  clib_memcpy_fast (ed->mac_addr, d->mac_addr, sizeof (ed->mac_addr));

  ena_log_debug (
    ed,
    "device_attr: impl_id %u device_version %u supported_feat "
    "0x%x\nphy_addr_width %u virt_addr_width %u\nmac_addr %U max_mtu %u",
    d->impl_id, d->device_version, d->supported_features, d->phys_addr_width,
    d->virt_addr_width, format_ethernet_address, d->mac_addr, d->max_mtu);

  return 0;
}

clib_error_t *
ena_aq_get_feat_max_queues_ext (vlib_main_t *vm, ena_device_t *ed)
{
  clib_error_t *err;
  ena_acq_entry_t r;
  ena_aq_entry_t e = { .opcode = ENA_AQ_OPCODE_GET_FEATURE,
		       .get_feat.feature_id = ENA_AQ_FEAT_ID_MAX_QUEUES_EXT };
  typeof (r.max_queue_ext) *d = &r.max_queue_ext;

  if ((err = ena_aq_req (vm, ed, &e, &r)))
    return err;

  ena_log_debug (ed,
		 "max_queues_ext: version %u, tx_header_size %u"
		 "\nmax rx(sq/cq): num %u/%u depth %u/%u per_packet_desc %u"
		 "\nmax tx(sq/cq): num %u/%u depth %u/%u per_packet_desc %u",
		 d->version, d->max_tx_header_size, d->max_rx_sq_num,
		 d->max_rx_cq_num, d->max_rx_sq_depth, d->max_rx_cq_depth,
		 d->max_per_packet_rx_descs, d->max_tx_sq_num,
		 d->max_tx_cq_num, d->max_tx_sq_depth, d->max_tx_cq_depth,
		 d->max_per_packet_tx_descs);

  return 0;
}

clib_error_t *
ena_aq_get_feat_aenq_config (vlib_main_t *vm, ena_device_t *ed)
{
  clib_error_t *err;
  ena_acq_entry_t r;
  ena_aq_entry_t e = { .opcode = ENA_AQ_OPCODE_GET_FEATURE,
		       .get_feat.feature_id = ENA_AQ_FEAT_ID_AENQ_CONFIG };
  typeof (r.aenq) *d = &r.aenq;

  if ((err = ena_aq_req (vm, ed, &e, &r)))
    return err;

  ena_log_debug (ed, "aenq_config: supported_groups 0x%x enabled_groups 0x%x",
		 d->supported_groups, d->enabled_groups);

  return 0;
}

clib_error_t *
ena_aq_get_feat_stateless_offload_config (vlib_main_t *vm, ena_device_t *ed)
{
  clib_error_t *err;
  ena_acq_entry_t r;
  ena_aq_entry_t e = { .opcode = ENA_AQ_OPCODE_GET_FEATURE,
		       .get_feat.feature_id =
			 ENA_AQ_FEAT_ID_STATELESS_OFFLOAD_CONFIG };
  typeof (r.offload) *d = &r.offload;

  if ((err = ena_aq_req (vm, ed, &e, &r)))
    return err;

  ena_log_debug (ed, "aenq_config: rx supported 0x%x rx enabled 0x%x tx 0x%x",
		 d->rx_supported, d->rx_enabled, d->tx);

  return 0;
}

clib_error_t *
ena_create_if (vlib_main_t *vm, ena_create_if_args_t *args)
{
  ena_main_t *em = &ena_main;
  ena_device_t *ed, **edp;
  vlib_pci_dev_handle_t h;
  clib_error_t *err = 0, *err2;
  ena_reg_version_t ver;
  ena_reg_controller_version_t ctrl_ver;
  u8 revision_id;

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

  if ((err = vlib_pci_map_region (vm, h, 0, &ed->bar0)))
    goto done;

  ena_log_debug (ed, "BAR0 mapped at %p", ed->bar0);

  if ((err = ena_physmem_alloc (
	 vm, ed, round_pow2 (sizeof (ena_mmio_resp_t), CLIB_CACHE_LINE_BYTES),
	 (void **) &ed->mmio_resp, "mmio resp")))
    goto done;

  if ((err = ena_physmem_alloc (
	 vm, ed, sizeof (ena_aq_entry_t) * ENA_ADMIN_QUEUE_DEPTH,
	 (void **) &ed->aq_entries, "aq entries")))
    goto done;

  if ((err = ena_physmem_alloc (
	 vm, ed, sizeof (ena_acq_entry_t) * ENA_ADMIN_QUEUE_DEPTH,
	 (void **) &ed->acq_entries, "acq entries")))
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
			ed->aq_entries);
  ena_reg_set_dma_addr (vm, ed, ENA_REG_ACQ_BASE_LO, ENA_REG_ACQ_BASE_HI,
			ed->acq_entries);
  ena_reg_set_dma_addr (vm, ed, ENA_REG_AENQ_BASE_LO, ENA_REG_AENQ_BASE_HI,
			ed->aenq_entries);

  ena_reg_write (
    ed, ENA_REG_AQ_CAPS,
    &(ena_reg_aq_caps_t){ .depth = ENA_ADMIN_QUEUE_DEPTH,
			  .entry_size = sizeof (ena_aq_entry_t) });
  ena_reg_write (
    ed, ENA_REG_ACQ_CAPS,
    &(ena_reg_aq_caps_t){ .depth = ENA_ADMIN_QUEUE_DEPTH,
			  .entry_size = sizeof (ena_acq_entry_t) });
  ena_reg_write (
    ed, ENA_REG_AENQ_CAPS,
    &(ena_reg_aq_caps_t){ .depth = ENA_ASYNC_QUEUE_DEPTH,
			  .entry_size = sizeof (ena_aenq_entry_t) });

  ena_log_debug (ed, "regs:\n%U", format_ena_regs, ed, -1);

  /* host info */
  ena_host_info_t *hi = ed->host_info;
  hi->os_type = 3; /* DPDK */
  hi->kernel_ver = 23 * 16 + 5;
  hi->os_dist = 23 * 16 + 5;
  hi->driver_version.sub_minor = 1;
  hi->num_cpus = vlib_get_n_threads ();
  // hi->driver_supported_features.rss_configurable_function_key = 1;
  snprintf ((char *) hi->kernel_ver_str, sizeof (hi->kernel_ver_str), "%s",
	    VPP_BUILD_VER);
  snprintf ((char *) hi->os_dist_str, sizeof (hi->os_dist_str), "%s",
	    VPP_BUILD_VER);

  if ((err = ena_aq_set_feat_host_attr (vm, ed)))
    goto done;

  if ((err = ena_aq_get_feat_device_attr (vm, ed)))
    goto done;

  if ((ed->supported_feat_id & (1U << ENA_AQ_FEAT_ID_MAX_QUEUES_EXT)) == 0)
    {
      err = clib_error_return (
	0, "Device is uable to provide MAX_QUEUES_EXT feature");
      goto done;
    }
  else if ((err = ena_aq_get_feat_max_queues_ext (vm, ed)))
    goto done;

  if ((err = ena_aq_get_feat_aenq_config (vm, ed)))
    goto done;

  if ((err = ena_aq_get_feat_stateless_offload_config (vm, ed)))
    goto done;
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

static clib_error_t *
ena_interface_rx_mode_change (vnet_main_t *vnm, u32 hw_if_index, u32 qid,
			      vnet_hw_if_rx_mode mode)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ena_device_t *ad = ena_get_device (hw->dev_instance);
  ena_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);

  if (mode == VNET_HW_IF_RX_MODE_POLLING)
    {
      if (rxq->int_mode == 0)
	return 0;
      rxq->int_mode = 0;
    }
  else
    {
      if (rxq->int_mode == 1)
	return 0;
      rxq->int_mode = 1;
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
  .rx_mode_change_function = ena_interface_rx_mode_change,
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
