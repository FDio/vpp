/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <igb/igb.h>

#define IGB_RXQ_SZ 512
#define IGB_TXQ_SZ 512

#define PCI_VENDOR_ID_INTEL			0x8086
#define PCI_DEVICE_ID_INTEL_I211		0x1539

igb_main_t igb_main;

static pci_device_id_t igb_pci_device_ids[] = {
  {.vendor_id = PCI_VENDOR_ID_INTEL,.device_id = PCI_DEVICE_ID_INTEL_I211},
  {0},
};

clib_error_t *
igb_rxq_init (vlib_main_t * vm, igb_device_t * ad, u16 qid, u16 rxq_size)
{
  clib_error_t *err;
  igb_rxq_t *rxq;
  u32 n_alloc, i;

  vec_validate_aligned (ad->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (ad->rxqs, qid);
  rxq->size = rxq_size;
  rxq->next = 0;
  rxq->descs = vlib_physmem_alloc_aligned_on_numa (vm, rxq->size *
						   sizeof (igb_rx_desc_t),
						   2 * CLIB_CACHE_LINE_BYTES,
						   ad->numa_node);

  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, ad->numa_node);

  if (rxq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, ad->pci_dev_handle, (void *) rxq->descs)))
    return err;

  clib_memset ((void *) rxq->descs, 0, rxq->size * sizeof (igb_rx_desc_t));
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);

  n_alloc = vlib_buffer_alloc_from_pool (vm, rxq->bufs, rxq->size - 8,
					 rxq->buffer_pool_index);

  if (n_alloc == 0)
    return clib_error_return (0, "buffer allocation error");

  rxq->n_enqueued = n_alloc;
  igb_rx_desc_t *d = rxq->descs;
  for (i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->bufs[i]);
      if (ad->flags & IGB_DEVICE_F_VA_DMA)
	d->qword[0] = vlib_buffer_get_va (b);
      else
	d->qword[0] = vlib_buffer_get_pa (vm, b);
      d++;
    }

  return 0;
}

clib_error_t *
igb_txq_init (vlib_main_t * vm, igb_device_t * ad, u16 qid, u16 txq_size)
{
  clib_error_t *err;
  igb_txq_t *txq;


  vec_validate_aligned (ad->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (ad->txqs, qid);
  txq->size = txq_size;
  txq->next = 0;
  txq->descs = vlib_physmem_alloc_aligned_on_numa (vm, txq->size *
						   sizeof (igb_tx_desc_t),
						   2 * CLIB_CACHE_LINE_BYTES,
						   ad->numa_node);
  if (txq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, ad->pci_dev_handle, (void *) txq->descs)))
    return err;

  vec_validate_aligned (txq->bufs, txq->size, CLIB_CACHE_LINE_BYTES);
  return 0;
}


clib_error_t *
igb_device_init (vlib_main_t * vm, igb_main_t * am, igb_device_t * ad,
		 igb_create_if_args_t * args)
{
  clib_error_t *error = 0;

  return clib_error_return (0, "TODO");

  ad->flags |= IGB_DEVICE_F_INITIALIZED;
  return error;
}

void
igb_process_one_device (vlib_main_t * vm, igb_device_t * ad, int is_irq)
{
#if 0
  igb_main_t *am = &igb_main;
  vnet_main_t *vnm = vnet_get_main ();
  virtchnl_pf_event_t *e;
  u32 r;

  if (ad->flags & IGB_DEVICE_F_ERROR)
    return;

  if ((ad->flags & IGB_DEVICE_F_INITIALIZED) == 0)
    return;

  ASSERT (ad->error == 0);

  /* do not process device in reset state */
  r = igb_get_u32 (ad->bar0, IGBGEN_RSTAT);
  if (r != VIRTCHNL_VFR_VFACTIVE)
    return;

  r = igb_get_u32 (ad->bar0, IGB_ARQLEN);
  if ((r & 0xf0000000) != (1ULL << 31))
    {
      ad->error = clib_error_return (0, "arq not enabled, arqlen = 0x%x", r);
      igb_log_err (ad, "error: %U", format_clib_error, ad->error);
      goto error;
    }

  r = igb_get_u32 (ad->bar0, IGB_ATQLEN);
  if ((r & 0xf0000000) != (1ULL << 31))
    {
      ad->error = clib_error_return (0, "atq not enabled, atqlen = 0x%x", r);
      igb_log_err (ad, "error: %U", format_clib_error, ad->error);
      goto error;
    }

  return;

error:
  ad->flags |= IGB_DEVICE_F_ERROR;
  ASSERT (ad->error != 0);
  vlib_log_err (am->log_class, "%U", format_clib_error, ad->error);
#endif
}

static u32
igb_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  igb_main_t *am = &igb_main;
  igb_device_t *ad = vec_elt_at_index (am->devices, hw->dev_instance);
  if (ETHERNET_INTERFACE_FLAG_CONFIG_PROMISC (flags))
    {
      clib_error_t *error = 0;
      int promisc_enabled = (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL) != 0;
      u32 new_flags = promisc_enabled ?
	ad->flags | IGB_DEVICE_F_PROMISC : ad->flags & ~IGB_DEVICE_F_PROMISC;

      if (new_flags == ad->flags)
	return flags;

      //if ((error = igb_config_promisc_mode (vm, ad, promisc_enabled)))
	{
	  igb_log_err (ad, "%s: %U", format_clib_error, error);
	  clib_error_free (error);
	  return 0;
	}

      ad->flags = new_flags;
    }
  return 0;
}

static uword
igb_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  igb_main_t *am = &igb_main;
  igb_device_t *ad;
  uword *event_data = 0, event_type;
  int enabled = 0, irq;
  f64 last_run_duration = 0;
  f64 last_periodic_time = 0;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, 5.0 - last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);
      irq = 0;

      switch (event_type)
	{
	case ~0:
	  last_periodic_time = vlib_time_now (vm);
	  break;
	case IGB_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case IGB_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	case IGB_PROCESS_EVENT_AQ_INT:
	  irq = 1;
	  break;
	default:
	  ASSERT (0);
	}

      /* *INDENT-OFF* */
      pool_foreach (ad, am->devices,
        {
	  igb_process_one_device (vm, ad, irq);
        });
      /* *INDENT-ON* */
      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (igb_process_node, static)  = {
  .function = igb_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "igb-process",
};
/* *INDENT-ON* */

static void
igb_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  igb_main_t *am = &igb_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  igb_device_t *ad = pool_elt_at_index (am->devices, pd);

  if (ad->flags & IGB_DEVICE_F_ELOG)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (el) =
	{
	  .format = "igb[%d] irq 0: icr0 0x%x",
	  .format_args = "i4i4",
	};
      /* *INDENT-ON* */
      struct
      {
	u32 dev_instance;
	u32 icr0;
      } *ed;

      ed = ELOG_DATA (&vm->elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->icr0 = 0;
    }
}

void
igb_delete_if (vlib_main_t * vm, igb_device_t * ad)
{
  vnet_main_t *vnm = vnet_get_main ();
  igb_main_t *am = &igb_main;
  int i;

  if (ad->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
    }

  vlib_pci_device_close (vm, ad->pci_dev_handle);

  /* *INDENT-OFF* */
  vec_foreach_index (i, ad->rxqs)
    {
      igb_rxq_t *rxq = vec_elt_at_index (ad->rxqs, i);
      vlib_physmem_free (vm, (void *) rxq->descs);
      if (rxq->n_enqueued)
	vlib_buffer_free_from_ring (vm, rxq->bufs, rxq->next, rxq->size,
				    rxq->n_enqueued);
      vec_free (rxq->bufs);
    }
  /* *INDENT-ON* */
  vec_free (ad->rxqs);

  /* *INDENT-OFF* */
  vec_foreach_index (i, ad->txqs)
    {
      igb_txq_t *txq = vec_elt_at_index (ad->txqs, i);
      vlib_physmem_free (vm, (void *) txq->descs);
      if (txq->n_enqueued)
	{
	  u16 first = (txq->next - txq->n_enqueued) & (txq->size -1);
	  vlib_buffer_free_from_ring (vm, txq->bufs, first, txq->size,
				      txq->n_enqueued);
	}
      vec_free (txq->bufs);
      clib_ring_free (txq->rs_slots);
    }
  /* *INDENT-ON* */
  vec_free (ad->txqs);
  vec_free (ad->name);

  clib_error_free (ad->error);
  clib_memset (ad, 0, sizeof (*ad));
  pool_put (am->devices, ad);
}

void
igb_create_if (vlib_main_t * vm, igb_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  igb_main_t *am = &igb_main;
  igb_device_t *ad;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;
  int i;

  /* check input args */
  args->rxq_size = (args->rxq_size == 0) ? IGB_RXQ_SZ : args->rxq_size;
  args->txq_size = (args->txq_size == 0) ? IGB_TXQ_SZ : args->txq_size;

  if ((args->rxq_size & (args->rxq_size - 1))
      || (args->txq_size & (args->txq_size - 1)))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error, "queue size must be a power of two");
      return;
    }

  pool_get (am->devices, ad);
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;
  ad->name = vec_dup (args->name);

  if (args->enable_elog)
    ad->flags |= IGB_DEVICE_F_ELOG;

  if ((error = vlib_pci_device_open (vm, &args->addr, igb_pci_device_ids,
				     &h)))
    {
      pool_put (am->devices, ad);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error = clib_error_return (error, "pci-addr %U",
				       format_vlib_pci_addr, &args->addr);
      return;
    }
  ad->pci_dev_handle = h;
  ad->pci_addr = args->addr;
  ad->numa_node = vlib_pci_get_numa_node (vm, h);

  vlib_pci_set_private_data (vm, h, ad->dev_instance);

  if ((error = vlib_pci_bus_master_enable (vm, h)))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 0, &ad->bar0)))
    goto error;

  if ((error = vlib_pci_register_msix_handler (vm, h, 0, 1,
					       &igb_irq_0_handler)))
    goto error;

  if ((error = vlib_pci_enable_msix_irq (vm, h, 0, 1)))
    goto error;

  if ((error = vlib_pci_intr_enable (vm, h)))
    goto error;

  if (vlib_pci_supports_virtual_addr_dma (vm, h))
    ad->flags |= IGB_DEVICE_F_VA_DMA;

  if ((error = igb_device_init (vm, am, ad, args)))
    goto error;

  /* create interface */
  error = ethernet_register_interface (vnm, igb_device_class.index,
				       ad->dev_instance, ad->hwaddr,
				       &ad->hw_if_index, igb_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, ad->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, ad->hw_if_index,
				    igb_input_node.index);

  for (i = 0; i < ad->n_rx_queues; i++)
    vnet_hw_interface_assign_rx_thread (vnm, ad->hw_if_index, i, ~0);

  if (pool_elts (am->devices) == 1)
    vlib_process_signal_event (vm, igb_process_node.index,
			       IGB_PROCESS_EVENT_START, 0);

  return;

error:
  igb_delete_if (vm, ad);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = clib_error_return (error, "pci-addr %U",
				   format_vlib_pci_addr, &args->addr);
  igb_log_err (ad, "error: %U", format_clib_error, args->error);
}

static clib_error_t *
igb_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  igb_main_t *am = &igb_main;
  igb_device_t *ad = vec_elt_at_index (am->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & IGB_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= IGB_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~IGB_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static clib_error_t *
igb_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
			      vnet_hw_interface_rx_mode mode)
{
  igb_main_t *am = &igb_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  igb_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);
  igb_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);

  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    rxq->int_mode = 0;
  else
    rxq->int_mode = 1;

  return 0;
}

static void
igb_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			     u32 node_index)
{
  igb_main_t *am = &igb_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  igb_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), igb_input_node.index, node_index);
}

static char *igb_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_igb_tx_func_error
#undef _
};

static void
igb_clear_hw_interface_counters (u32 instance)
{
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (igb_device_class,) =
{
  .name = "Adaptive Virtual Function (IGB) interface",
  .clear_counters = igb_clear_hw_interface_counters,
  .format_device = format_igb_device,
  .format_device_name = format_igb_device_name,
  .admin_up_down_function = igb_interface_admin_up_down,
  .rx_mode_change_function = igb_interface_rx_mode_change,
  .rx_redirect_to_node = igb_set_interface_next_node,
  .tx_function_n_errors = IGB_TX_N_ERROR,
  .tx_function_error_strings = igb_tx_func_error_strings,
};
/* *INDENT-ON* */

clib_error_t *
igb_init (vlib_main_t * vm)
{
  igb_main_t *am = &igb_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (am->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  am->log_class = vlib_log_register_class ("igb", 0);
  vlib_log_debug (am->log_class, "initialized");

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (igb_init) =
{
  .runs_after = VLIB_INITS ("pci_bus_init"),
};
/* *INDENT-OFF* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
