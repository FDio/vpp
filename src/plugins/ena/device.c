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
  .subclass_name = "device",
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

static ena_admin_host_info_t host_info = {
  .os_type = 3, /* DPDK */
  .kernel_ver_str = VPP_BUILD_VER,
  .os_dist_str = VPP_BUILD_VER,
  .driver_version = { .major = 16, .minor = 0, .sub_minor = 0 },
  .ena_spec_version = { .major = 2, .minor = 0 },
  .driver_supported_features = { .rx_offset = 1,
				 .rss_configurable_function_key = 1 }
};

void
ena_delete_if (vlib_main_t *vm, u32 dev_instance)
{
  ena_main_t *em = &ena_main;
  ena_device_t *ed = pool_elt_at_index (em->devices, dev_instance)[0];
  u32 i;

  pool_foreach_index (i, ed->rxqs)
    ena_rx_queue_disable (vm, ed, i);

  pool_foreach_index (i, ed->txqs)
    ena_tx_queue_disable (vm, ed, i);

  pool_foreach_index (i, ed->rxqs)
    ena_rx_queue_free (vm, ed, i);

  pool_foreach_index (i, ed->txqs)
    ena_tx_queue_free (vm, ed, i);

  if (ed->pci_dev_handle != ~0)
    vlib_pci_device_close (vm, ed->pci_dev_handle);

  vec_free (ed->name);
  vlib_physmem_free (vm, ed->mmio_resp);
  vlib_physmem_free (vm, ed->admin_sq_entries);
  vlib_physmem_free (vm, ed->admin_cq_entries);
  vlib_physmem_free (vm, ed->aenq_entries);
  vlib_physmem_free (vm, ed->host_info);
  clib_mem_free (ed);
  pool_put_index (em->devices, dev_instance);

  if (pool_elts (em->devices) == 0)
    {
      vlib_process_signal_event (vm, ena_process_node.index,
				 ENA_PROCESS_EVENT_STOP, 0);
      vec_foreach_index (i, em->per_thread_data)
	vec_free (em->per_thread_data[i].buffer_indices);
      vec_free (em->per_thread_data);
    }
}

static clib_error_t *
ena_device_set_max_frame_size (vnet_main_t *vnm, vnet_hw_interface_t *hw,
			       u32 frame_size)
{
  ena_main_t *em = &ena_main;
  ena_admin_feat_mtu_t mtu = { .mtu =
				 frame_size - sizeof (ethernet_header_t) };

  return ena_admin_set_feature (vlib_get_main (),
				em->devices[hw->dev_instance],
				ENA_ADMIN_FEAT_ID_MTU, &mtu);
}

static void
ena_device_link_or_admin_state_change (vlib_main_t *vm, ena_device_t *ed,
				       int link_state, int admin_state)
{
  vnet_main_t *vnm = vnet_get_main ();
  link_state = link_state == -1 ? ed->link_up : link_state != 0;
  admin_state = admin_state == -1 ? ed->admin_up : admin_state != 0;
  u32 i;

  if (link_state == ed->link_up && admin_state == ed->admin_up)
    {
      ena_log_debug (
	ed, "link_or_admin_state_change: no change (link %s, admin %s)",
	ed->link_up ? "up" : "down", ed->admin_up ? "up" : "down");
      return;
    }

  ena_log_debug (ed,
		 "link_or_admin_state_change: from (link %s, admin %s) to "
		 "(link %s, admin %s)",
		 ed->link_up ? "up" : "down", ed->admin_up ? "up" : "down",
		 link_state ? "up" : "down", admin_state ? "up" : "down");

  if (link_state && admin_state)
    {
      pool_foreach_index (i, ed->rxqs)
	ena_rx_queue_enable (vm, ed, i);

      pool_foreach_index (i, ed->txqs)
	ena_tx_queue_enable (vm, ed, i);
      vnet_hw_interface_set_flags (vnm, ed->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ed->hw_if_index, 0);
      u32 *indices = 0;

      pool_foreach_index (i, ed->txqs)
	vec_add1 (indices, i);

      while (vec_len (indices))
	ena_tx_queue_disable (vm, ed, vec_pop (indices));

      vec_reset_length (indices);

      pool_foreach_index (i, ed->rxqs)
	vec_add1 (indices, i);

      while (vec_len (indices))
	ena_rx_queue_disable (vm, ed, vec_pop (indices));

      vec_free (indices);
    }

  ed->link_up = link_state;
  ed->admin_up = admin_state;
}

static clib_error_t *
ena_device_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  ena_device_t *ed = ena_get_device (hi->dev_instance);
  int is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  ena_device_link_or_admin_state_change (vlib_get_main (), ed, -1, is_up);
  return 0;
}

void
ena_device_set_link_state (vlib_main_t *vm, ena_device_t *ed, int state)
{
  ena_device_link_or_admin_state_change (vm, ed, state != 0, -1);
}

clib_error_t *
ena_device_init (vlib_main_t *vm, ena_device_t *ed,
		 ena_reset_reason_t reset_reason)
{
  clib_error_t *err;
  ena_admin_feat_host_attr_config_t host_attr = {};
  u32 my_process_index = vlib_get_current_process_node_index (vm);

  if (my_process_index != ena_process_node.index)
    {
      uword event, *event_data = 0;

      ena_process_event_data_t ev_data = {
	.calling_process_index = my_process_index,
	.ed = ed,
	.device_init.reset_reason = reset_reason,
      };

      vlib_process_signal_event_pointer (
	vm, ena_process_node.index, ENA_PROCESS_EVENT_DEVICE_INIT, &ev_data);
      vlib_process_wait_for_event_or_clock (vm, 5.0);
      event = vlib_process_get_events (vm, &event_data);

      if (event != ENA_PROCESS_EVENT_DEVICE_INIT)
	{
	  char *str;
	  if (event == ~0)
	    str = "timeout waiting for process node to respond";
	  else
	    str = "unexpected event received";
	  ev_data.err =
	    vnet_error (VNET_ERR_BUG, "ena_device_reset failed, %s", str);
	  ena_log_err (ed, "ena_device_reset failed, %s", str);
	}

      vec_free (event_data);
      return ev_data.err;
    }

  /* reset */
  if ((err = ena_reg_reset (vm, ed, reset_reason)))
    return err;
  ;

  if ((err = ena_reg_init_aq (vm, ed, ENA_ADMIN_QUEUE_DEPTH)))
    return err;

  *ed->host_info = host_info;
  ed->host_info->bdf.bus = ed->pci_addr.bus;
  ed->host_info->bdf.device = ed->pci_addr.domain;
  ed->host_info->bdf.function = ed->pci_addr.function;
  ed->host_info->num_cpus = vlib_get_n_threads ();

  ena_set_mem_addr (vm, ed, &host_attr.os_info_ba, ed->host_info);

  if ((err = ena_admin_set_feature (vm, ed, ENA_ADMIN_FEAT_ID_HOST_ATTR_CONFIG,
				    &host_attr)))
    return err;

  if ((err = ena_admin_get_feature (
	 vm, ed, ENA_ADMIN_FEAT_ID_DEVICE_ATTRIBUTES, &ed->dev_attr)))
    return err;

  if (ena_admin_feature_is_supported (ed, ENA_ADMIN_FEAT_ID_AENQ_CONFIG))
    {
      ena_admin_feat_aenq_config_t aenq;

      if ((err = ena_admin_get_feature (vm, ed, ENA_ADMIN_FEAT_ID_AENQ_CONFIG,
					&aenq)))
	return err;

      aenq.enabled_groups.link_change = 1;
      aenq.enabled_groups.fatal_error = 1;
      aenq.enabled_groups.warning = 1;
      aenq.enabled_groups.notification = 1;
      // aenq.enabled_groups.keep_alive = 1;
      aenq.enabled_groups.as_u32 &= aenq.supported_groups.as_u32;
      aenq.supported_groups.as_u32 = 0;

      if ((err = ena_admin_set_feature (vm, ed, ENA_ADMIN_FEAT_ID_AENQ_CONFIG,
					&aenq)))
	return err;
    }

  if ((err = ena_reg_init_aenq (vm, ed, ENA_ASYNC_QUEUE_DEPTH)))
    return err;

  return 0;
}

clib_error_t *
ena_reset_if (vlib_main_t *vm, u32 dev_index)
{
  ena_device_t *ed = pool_elt_at_index (ena_main.devices, dev_index)[0];
  ena_log_notice (ed, "device reset initiated");
  ena_device_set_link_state (vm, ed, 0);
  return ena_device_init (vm, ed, ENA_RESET_REASON_USER_TRIGGER);
}

clib_error_t *
ena_create_if (vlib_main_t *vm, ena_create_if_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  ena_main_t *em = &ena_main;
  ena_device_t *ed, **edp;
  vlib_pci_dev_handle_t h;
  clib_error_t *err = 0, *err2;
  vnet_eth_interface_registration_t eir = {};
  u16 log2_rxq_sz, log2_txq_sz, n_rxq, n_txq;
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
  else
    {
      u8 revision_id;
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

      if ((revision_id & 1) == 0)
	ed->readless = 1;
    }

  if (ed->readless)
    {
      if (ed->mmio_resp == 0)
	ed->mmio_resp = vlib_physmem_alloc_aligned_on_numa (
	  vm, round_pow2 (sizeof (ena_mmio_resp_t), CLIB_CACHE_LINE_BYTES),
	  CLIB_CACHE_LINE_BYTES, ed->numa_node);

      if (ed->mmio_resp == 0)
	return vlib_physmem_last_error (vm);
    }

  ed->host_info =
    vlib_physmem_alloc_aligned_on_numa (vm, 4096, 4096, ed->numa_node);

  if (ed->host_info == 0)
    return vlib_physmem_last_error (vm);

  if ((err = ena_device_init (vm, ed, ENA_RESET_REASON_NORMAL)))
    goto done;

  /* initialize queues */
  if (ena_admin_feature_is_supported (ed, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT))
    {
      ena_admin_feat_max_queue_ext_t max_q_ext;
      u16 max_rxq_sz = 1ULL << ENA_MAX_LOG2_RXQ_SIZE;
      u16 max_txq_sz = 1ULL << ENA_MAX_LOG2_TXQ_SIZE;
      u16 max_rxq_n, max_txq_n;

      if ((err = ena_admin_get_feature (
	     vm, ed, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT, &max_q_ext)))
	goto done;

      max_rxq_sz = clib_min (max_rxq_sz, max_q_ext.max_rx_cq_depth);
      max_rxq_sz = clib_min (max_rxq_sz, max_q_ext.max_rx_sq_depth);
      max_txq_sz = clib_min (max_txq_sz, max_q_ext.max_tx_cq_depth);
      max_txq_sz = clib_min (max_txq_sz, max_q_ext.max_tx_sq_depth);
      max_rxq_n = clib_min (max_q_ext.max_rx_cq_num, max_q_ext.max_rx_sq_num);
      max_txq_n = clib_min (max_q_ext.max_tx_cq_num, max_q_ext.max_tx_sq_num);

      if (args->rxq_size)
	{
	  if (count_set_bits (args->rxq_size) > 1)
	    err = clib_error_return (0, "queue size must be power of 2");
	  else if (args->rxq_size > max_rxq_sz)
	    err = clib_error_return (
	      0, "maximum supported rx queue size is %u", max_rxq_sz);

	  if (err)
	    goto done;

	  log2_rxq_sz = get_lowest_set_bit_index (args->rxq_size);
	}
      else
	log2_rxq_sz = clib_min (get_lowest_set_bit_index (max_rxq_sz),
				ENA_DEFAULT_LOG2_RXQ_SIZE);

      if (args->txq_size)
	{
	  if (count_set_bits (args->txq_size) > 1)
	    err = clib_error_return (0, "queue size must be power of 2");
	  else if (args->txq_size > max_txq_sz)
	    err = clib_error_return (
	      0, "maximum supported tx queue size is %u", max_txq_sz);

	  if (err)
	    goto done;

	  log2_txq_sz = get_lowest_set_bit_index (args->txq_size);
	}
      else
	log2_txq_sz = clib_min (get_lowest_set_bit_index (max_txq_sz),
				ENA_DEFAULT_LOG2_TXQ_SIZE);

      if (args->rxq_num)
	{
	  n_rxq = args->rxq_num;
	  if (n_rxq > max_rxq_n)
	    err = clib_error_return (
	      0, "maximum supported number of rx queues is %u", max_rxq_n);
	  goto done;
	}
      else
	n_rxq = 1;

      if (args->txq_num)
	{
	  n_txq = args->txq_num;
	  if (n_txq > max_txq_n)
	    err = clib_error_return (
	      0, "maximum supported number of tx queues is %u", max_txq_n);
	  goto done;
	}
      else
	n_txq = vlib_get_n_threads ();
    }
  else
    {
      err = clib_error_return (
	0, "Device is uable to provide MAX_QUEUES_EXT feature");
      goto done;
    }

  /* create interface */
  eir.dev_class_index = ena_device_class.index;
  eir.dev_instance = ed->dev_instance;
  eir.address = ed->dev_attr.mac_addr;
  eir.max_frame_size = ed->dev_attr.max_mtu + sizeof (ethernet_header_t);
  eir.cb.set_max_frame_size = ena_device_set_max_frame_size;
  // FIXME eir.cb.flag_change = ena_flag_change;
  ed->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  ethernet_set_flags (vnm, ed->hw_if_index,
		      ETHERNET_INTERFACE_FLAG_DEFAULT_L3);

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ed->hw_if_index);
  args->sw_if_index = ed->sw_if_index = sw->sw_if_index;

  /* initialize buffer template */
  ed->buffer_template.buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, ed->numa_node);
  ed->buffer_template.ref_count = 1;
  ed->buffer_template.flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
  vnet_buffer (&ed->buffer_template)->sw_if_index[VLIB_RX] = ed->sw_if_index;
  vnet_buffer (&ed->buffer_template)->sw_if_index[VLIB_TX] = ~0U;

  vnet_hw_if_set_input_node (vnm, ed->hw_if_index, ena_input_node.index);

  /* set hw interface caps */
  vnet_hw_if_set_caps (vnm, ed->hw_if_index,
		       VNET_HW_IF_CAP_INT_MODE | VNET_HW_IF_CAP_MAC_FILTER |
			 VNET_HW_IF_CAP_TX_CKSUM | VNET_HW_IF_CAP_TCP_GSO);

  for (u16 i = 0; i < n_rxq; i++)
    if ((err = ena_rx_queue_alloc (vm, ed, log2_rxq_sz, 0)))
      goto done;

  for (u16 i = 0; i < n_txq; i++)
    if ((err = ena_tx_queue_alloc (vm, ed, log2_txq_sz, 0)))
      goto done;

  pool_foreach_index (i, ed->rxqs)
    {
      u32 qi;
      qi = vnet_hw_if_register_rx_queue (vnm, ed->hw_if_index, i,
					 VNET_HW_IF_RXQ_THREAD_ANY);
      ed->rxqs[i]->queue_index = qi;
    }

  pool_foreach_index (i, ed->txqs)
    {
      u32 qi = vnet_hw_if_register_tx_queue (vnm, ed->hw_if_index, i);
      ed->txqs[i]->queue_index = qi;
    }

  for (int i = 0; i < vlib_get_n_threads (); i++)
    {
      u32 qi = ed->txqs[i % pool_elts (ed->txqs)]->queue_index;
      vnet_hw_if_tx_queue_assign_thread (vnm, qi, i);
    }

  vnet_hw_if_update_runtime_data (vnm, ed->hw_if_index);

  if (pool_elts (em->devices) == 1)
    {
      vlib_thread_main_t *tm = vlib_get_thread_main ();

      vec_validate_aligned (em->per_thread_data, tm->n_vlib_mains - 1,
			    CLIB_CACHE_LINE_BYTES);
      vlib_process_signal_event (vm, ena_process_node.index,
				 ENA_PROCESS_EVENT_START, 0);
    }

  vec_foreach_index (i, em->per_thread_data)
    {
      u32 max_depth = 1U << clib_max (log2_txq_sz, log2_rxq_sz);
      vec_validate_aligned (em->per_thread_data[i].buffer_indices,
			    max_depth - 1, CLIB_CACHE_LINE_BYTES);
    }

  ed->initialized = 1;

done:
  if (err)
    ena_delete_if (vm, ed->dev_instance);
  return err;
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
  .admin_up_down_function = ena_device_admin_up_down,
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
