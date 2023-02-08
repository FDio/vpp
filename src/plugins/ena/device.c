/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <ena/ena.h>

#define ENA_ADMIN_QUEUE_DEPTH 32

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

  vlib_physmem_free (vm, ed->aq_entries);
  vlib_physmem_free (vm, ed->acq_entries);
  clib_mem_free (ed);
  pool_put_index (em->devices, dev_instance);
}

void
ena_reg_read (ena_device_t *ed, ena_reg_t reg, const void *v)
{
  *(u32 *) v =
    __atomic_load_n ((u32 *) ((u8 *) ed->bar0 + reg), __ATOMIC_SEQ_CST);
  ena_log_debug (ed, "%s: offset 0x%02x value 0x%08x", __func__, reg,
		 *(u32 *) v);
}

void
ena_reg_write (ena_device_t *ed, ena_reg_t reg, void *v)
{
  ena_log_debug (ed, "%s: offset 0x%02x value 0x%u8x", __func__, reg,
		 *(u32 *) v);
  __atomic_store_n ((u32 *) ((u8 *) ed->bar0 + reg), *(u32 *) v,
		    __ATOMIC_SEQ_CST);
}

static inline uword
ena_dma_addr (vlib_main_t *vm, ena_device_t *ad, void *p)
{
  return (ad->flags & ENA_DEVICE_F_VA_DMA) ? pointer_to_uword (p) :
					     vlib_physmem_get_pa (vm, p);
}

clib_error_t *
ena_physmem_alloc (vlib_main_t *vm, ena_device_t *ed, u32 sz, void **pp,
		   char *name)
{
  void *p;

  p = vlib_physmem_alloc_aligned_on_numa (vm, sz, CLIB_CACHE_LINE_BYTES,
					  ed->numa_node);
  if (p == 0)
    return vlib_physmem_last_error (vm);

  clib_memset (p, 0, sz);
  *pp = p;

  ena_log_debug (ed,
		 "%s: allocated %u bytes of physmem memory at %p (PA: 0x%x) "
		 "on numa %u for '%s'",
		 __func__, sz, p, ena_dma_addr (vm, ed, p), ed->numa_node,
		 name);

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
  uword pa;
  u32 reg;

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
    ed->flags |= ENA_DEVICE_F_VA_DMA;

  vlib_pci_set_private_data (vm, h, ed->dev_instance);

  if ((err = vlib_pci_bus_master_enable (vm, h)))
    goto done;

  if ((err = vlib_pci_map_region (vm, h, 0, &ed->bar0)))
    goto done;

  ena_reg_read (ed, ENA_REG_VERSION, &ver);
  ena_reg_read (ed, ENA_REG_CONTROLLER_VERSION, &ctrl_ver);

  ena_log_info (ed, "version %u.%u controller_version %u.%u.%u impl_id %u\n",
		ver.major, ver.minor, ctrl_ver.major, ctrl_ver.minor,
		ctrl_ver.subminor, ctrl_ver.impl_id);

  ena_log_debug (ed, "regs:\n%U", format_ena_regs, ed->bar0);

  if ((err = ena_physmem_alloc (
	 vm, ed, sizeof (ena_aq_entry_t) * ENA_ADMIN_QUEUE_DEPTH,
	 (void **) &ed->aq_entries, "aq entries")))
    goto done;

  if ((err = ena_physmem_alloc (
	 vm, ed, sizeof (ena_acq_entry_t) * ENA_ADMIN_QUEUE_DEPTH,
	 (void **) &ed->acq_entries, "acq entries")))
    goto done;

  pa = ena_dma_addr (vm, ed, ed->aq_entries);
  reg = (u32) pa;
  ena_reg_write (ed, ENA_REG_AQ_BASE_LO, &reg);
  reg = pa >> 32;
  ena_reg_write (ed, ENA_REG_AQ_BASE_HI, &reg);

  pa = ena_dma_addr (vm, ed, ed->acq_entries);
  reg = (u32) pa;
  ena_reg_write (ed, ENA_REG_ACQ_BASE_LO, &reg);
  reg = pa >> 32;
  ena_reg_write (ed, ENA_REG_ACQ_BASE_HI, &reg);

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

  if (ad->flags & ENA_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= ENA_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~ENA_DEVICE_F_ADMIN_UP;
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
