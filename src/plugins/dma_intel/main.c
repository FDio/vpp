/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/dma/dma.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dma_intel/dma_intel.h>

VLIB_REGISTER_LOG_CLASS (intel_dma_log, static) = {
  .class_name = "intel_dma",
};

static pci_device_id_t cbdma_pci_device_ids[] = {
  { .vendor_id = 0x8086, .device_id = 0x2021 },
  {},
};

intel_dma_main_t intel_dma_main;

#define INTEL_CBDMA_LOG2_N_COMPLETIONS 4

void
intel_cbdma_assign_channels (vlib_main_t *vm)
{
  intel_dma_main_t *dm = &intel_dma_main;
  intel_cbdma_channel_t *ch, **chv = 0;
  int n;

  vec_foreach_index (n, dm->channels)
    vec_append (chv, dm->channels[n]);

  if (vec_len (chv) == 0)
    {
      log_debug ("No CBDMA channels found");
      goto done;
    }

  vec_validate (dm->cbdma_threads, vlib_get_n_threads () - 1);

  if (vec_len (chv) == 1)
    {
      ch = chv[0];
      ch->n_threads = vlib_get_n_threads ();

      for (int i = 0; i < vlib_get_n_threads (); i++)
	{
	  vlib_main_t *tvm = vlib_get_main_by_index (i);
	  dm->cbdma_threads[i].ch = ch;
	  log_debug ("Assigning channel %u/%u to thread %u (numa %u)",
		     ch->numa, ch->func, i, tvm->numa_node);
	}

      goto done;
    }

  /* FIXME */
  ASSERT (0);

done:
  /* free */
  vec_free (chv);
}

clib_error_t *
intel_cbdma_add_channel (vlib_main_t *vm, vlib_pci_addr_t *addr)
{
  intel_dma_main_t *dm = &intel_dma_main;
  clib_error_t *err = 0;
  intel_cbdma_channel_t *ch;
  u32 n_alloc, n_comp_descs;
  volatile intel_cbdma_bar_t *regs;

  ch = clib_mem_alloc_aligned (sizeof (*ch), CLIB_CACHE_LINE_BYTES);
  *ch = (intel_cbdma_channel_t){};

  if ((err = vlib_pci_device_open (vm, addr, cbdma_pci_device_ids,
				   &ch->pci_handle)))
    goto error;

  if ((err = vlib_pci_bus_master_enable (vm, ch->pci_handle)))
    goto error;

  if ((err = vlib_pci_map_region (vm, ch->pci_handle, 0, (void **) &ch->regs)))
    goto error;
  regs = ch->regs;

  if (!vlib_pci_supports_virtual_addr_dma (vm, ch->pci_handle))
    {
      err = clib_error_return (0, "requires virtual address dma (IOMMU)");
      goto error;
    }

  log_debug ("chancnt %u ver %u.%u dmacapability 0x%x", regs->chancnt,
	     regs->cbver_major, regs->cbver_minor, regs->dmacapability);

  /* sanity check */
  if (regs->chancnt_num_chan != 1 || regs->cbver_major != 3)
    {
      err = clib_error_return (0, "unsupported CBDMA instance");
      goto error;
    }

  /* reset channel */
  if (regs->chanctrl & 0x100)
    {
      log_debug ("in-use bit set");
      regs->chanctrl = 0;
    }

  /* suspend */
  regs->chancmd = 1 << 2;

  for (f64 t = vlib_time_now (vm) + 0.001; vlib_time_now (vm) < t;)
    CLIB_PAUSE ();

  /* reset */
  regs->chancmd = 1 << 5;

  for (f64 t = vlib_time_now (vm) + 0.001; vlib_time_now (vm) < t;)
    CLIB_PAUSE ();

  for (int repeats = 0; regs->chancmd & (1 << 5); repeats++)
    {
      regs->chainaddr = 0;
      for (f64 t = vlib_time_now (vm) + 0.001; vlib_time_now (vm) < t;)
	CLIB_PAUSE ();

      if (repeats > 100)
	{
	  err = clib_error_return (0, "failed to recover from reset");
	  goto error;
	}
    }

  ch->numa = vlib_pci_get_numa_node (vm, ch->pci_handle);

  n_comp_descs = 1 << INTEL_CBDMA_LOG2_N_COMPLETIONS;
  n_alloc = (n_comp_descs + 1) * sizeof (intel_cbdma_desc_t);

  ch->comp_descs = vlib_physmem_alloc_aligned_on_numa (
    vm, n_alloc, CLIB_CACHE_LINE_BYTES, ch->numa);

  if ((err = vlib_pci_map_dma (vm, ch->pci_handle, ch->comp_descs)))
    goto error;

  ch->mask = pow2_mask (INTEL_CBDMA_LOG2_N_COMPLETIONS);

  /* set the completion address used to track which completion descriptors
   * are consumed*/
  ch->completion = (volatile void **) (ch->comp_descs + n_comp_descs);
  *ch->completion = 0;
  regs->chancmp = (void *) ch->completion;

  /* fill the completion desctiptor ring  with dtatic data */
  for (int i = 0; i < n_comp_descs; i++)
    ch->comp_descs[i] =
      (intel_cbdma_desc_t){ .null_transfer = 1, .comp_upd = 1 };

  /* set DMA chain address - this puts DMA channel into the armed state */
  regs->chainaddr = ch->comp_descs;

  vec_validate (dm->channels, ch->numa);
  vec_add1 (dm->channels[ch->numa], ch);
  intel_cbdma_assign_channels (vm);

error:
  if (err)
    {
      log_debug ("%U", format_clib_error, err);
      vlib_pci_device_close (vm, ch->pci_handle);
      vlib_physmem_free (vm, ch->comp_descs);
      clib_mem_free (ch);
    }
  return err;
}

clib_error_t *
intel_dma_init (vlib_main_t *vm)
{
  clib_error_t *err;
  vlib_pci_addr_t addr = { .slot = 4, .function = 0 };

  if ((err = vlib_dma_register_backend (vm, &intel_cbdma_backend)))
    goto done;

  if ((err = intel_cbdma_add_channel (vm, &addr)))
    goto done;

done:
  if (err)
    {
      fformat (stderr, "Unable to open pci device '%U': %U\n",
	       format_vlib_pci_addr, &addr, format_clib_error, err);
      clib_error_free (err);
    }
  return 0;
}

VLIB_INIT_FUNCTION (intel_dma_init);

clib_error_t *
intel_dma_num_workers_change (vlib_main_t *vm)
{
  intel_cbdma_assign_channels (vm);
  return 0;
}

VLIB_NUM_WORKERS_CHANGE_FN (intel_dma_num_workers_change);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Intel DMA Backend",
};
