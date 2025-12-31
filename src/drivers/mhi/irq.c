/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <mhi.h>

VLIB_REGISTER_LOG_CLASS (mhi_log, static) = {
  .class_name = "mhi",
  .subclass_name = "irq",
};

static void
mhi_intx_handler (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "INTx interrupt");
  vnet_dev_process_call_op_no_wait (vm, dev, mhi_process_events);
}

static void
mhi_irq_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 line)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);

  /* If we have fewer vectors than needed, line 0 is shared */
  /* How to know if shared? Check n_msix/msi enabled?
     We can check md->event_ctxt[0].msivec.
     If it is 0, then we are in shared mode.
  */

  if (md->event_ctxt[0].msivec == 0)
    {
      /* Shared Interrupt (BHI + Events) */
      if (line == 0)
	vnet_dev_process_call_op_no_wait (vm, dev, mhi_process_events);
      return;
    }

  if (line == 0)
    {
      log_debug (dev, "BHI interrupt");
    }
  else
    {
      log_debug (dev, "Event Ring %u interrupt", line - 1);
      vnet_dev_process_call_op_no_wait (vm, dev, mhi_process_events);
    }
}

vnet_dev_rv_t
mhi_irq_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u32 n_vectors;
  u32 n_msi;

  /* 1 vector for BHI + 1 per event ring */
  n_vectors = 1 + vec_len (md->event_rings);

  /* Try MSI-X */
  if (vnet_dev_get_pci_n_msix_interrupts (dev) >= n_vectors)
    {
      for (u16 i = 0; i < n_vectors; i++)
	{
	  rv = vnet_dev_pci_msix_add_handler (vm, dev, mhi_irq_handler, i, 1);
	  if (rv != VNET_DEV_OK)
	    goto fallback_intx;
	}

      rv = vnet_dev_pci_msix_enable (vm, dev, 0, n_vectors);
      if (rv == VNET_DEV_OK)
	return VNET_DEV_OK;
    }

  /* Try MSI */
  n_msi = vnet_dev_get_pci_n_msi_interrupts (dev);
  if (n_msi > 0)
    {
      u32 count = n_vectors;
      u32 i;

      /* If not enough MSI vectors, fall back to 1 (Shared MSI) */
      if (n_msi < n_vectors)
	count = 1;

      for (i = 0; i < count; i++)
	{
	  rv = vnet_dev_pci_msi_add_handler (vm, dev, mhi_irq_handler, i, 1);
	  if (rv != VNET_DEV_OK)
	    goto cleanup_msi;
	}

      rv = vnet_dev_pci_msi_enable (vm, dev, 0, count);
      if (rv == VNET_DEV_OK)
	{
	  if (count == 1)
	    {
	      log_info (dev, "Using shared MSI vector");
	      /* Update event contexts to use vector 0 */
	      for (i = 0; i < vec_len (md->event_rings); i++)
		md->event_ctxt[i].msivec = 0;
	    }
	  return VNET_DEV_OK;
	}

    cleanup_msi:
      for (i = 0; i < count; i++)
	vnet_dev_pci_msi_remove_handler (vm, dev, i, 1);
    }

fallback_intx:
  /* Cleanup partial MSI-X setup if any */
  if (vnet_dev_get_pci_n_msix_interrupts (dev) > 0)
    {
      for (u16 i = 0; i < n_vectors; i++)
	vnet_dev_pci_msix_remove_handler (vm, dev, i, 1);
    }

  log_warn (dev, "MSI/MSI-X setup failed, falling back to INTx");
  rv = vnet_dev_pci_intx_add_handler (vm, dev, mhi_intx_handler);
  if (rv == VNET_DEV_OK)
    {
      /* INTx is shared, so msivec should be 0 (or ignored) */
      /* Ensure msivec is 0 just in case */
      for (int i = 0; i < vec_len (md->event_rings); i++)
	md->event_ctxt[i].msivec = 0;
      return VNET_DEV_OK;
    }

  log_err (dev, "INTx enable failed");
  return rv;
}
