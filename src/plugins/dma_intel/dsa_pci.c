/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Intel and/or its affiliates.
 */
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <dma_intel/dsa_pci.h>
#include <dma_intel/dsa_intel.h>

#define PCI_VENDOR_ID_INTEL   0x8086
#define PCI_DEVICE_ID_DSA_SPR 0x0B25

#define DSA_CMD_TIMEOUT (0.1)

static pci_device_id_t dsa_pci_device_ids[] = {
  { .vendor_id = PCI_VENDOR_ID_INTEL, .device_id = PCI_DEVICE_ID_DSA_SPR },
  { 0 },
};

static inline int
dsa_pci_command (intel_dsa_pci_common_t *pci, u8 wq_idx,
		 intel_dsa_command_t command)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 error;
  u16 qid = wq_idx;

  pci->regs->cmd = (command << DSA_CMD_SHIFT) | qid;
  if (command >= DSA_PCI_DISABLE_WQ && command <= DSA_PCI_RESET_WQ)
    qid = (1 << qid);

  f64 t = vlib_time_now (vm);
  do
    {
      CLIB_PAUSE ();
      error = pci->regs->cmdstatus;
      if ((vlib_time_now (vm) - t) > DSA_CMD_TIMEOUT)
	{
	  dsa_log_error ("DSA response timeout");
	  error &= CMDSTATUS_ERR_MASK;
	  return -error;
	}
    }
  while (error & CMDSTATUS_ACTIVE_MASK);

  error &= CMDSTATUS_ERR_MASK;
  return -error;
}

static u32 *
intel_dsa_get_wqcfg (intel_dsa_pci_common_t *pci, u8 wq_idx)
{
  return (u32 *) ((uintptr_t) pci->wq_regs_base +
		  ((uintptr_t) wq_idx << (5 + pci->wq_cfg_sz)));
}

static int
intel_dsa_wq_enabled (intel_dsa_pci_common_t *pci, u8 wq_idx)
{
  u32 state = intel_dsa_get_wqcfg (pci, wq_idx)[wq_state_idx];
  return ((state >> WQ_STATE_SHIFT) & WQ_STATE_MASK) == 0x1;
}

static int
intel_dsa_wq_start (intel_dsa_pci_common_t *pci, u8 wq_idx)
{
  u32 error;

  if (intel_dsa_wq_enabled (pci, wq_idx))
    {
      dsa_log_info ("work queue %d already enabled\n", wq_idx);
      return 0;
    }

  error = dsa_pci_command (pci, wq_idx, DSA_PCI_ENABLE_WQ);
  if (error || !intel_dsa_wq_enabled (pci, wq_idx))
    {
      dsa_log_error ("failed enabling work queue %d\n", wq_idx);
      return error == 0 ? -1 : -error;
    }

  return 0;
}

clib_error_t *
intel_dsa_add_pci_channel (vlib_main_t *vm, intel_dsa_channel_t *ch)
{
  clib_error_t *error = 0;
  intel_dsa_pci_common_t *pci_common;
  u8 nb_groups, nb_engines, nb_wqs;
  u16 grp_offset, wq_offset;
  u16 wq_size, total_wq_size;
  u8 lg2_max_batch, lg2_max_copy_size;
  int i;
  intel_dsa_main_t *dm = &intel_dsa_main;
  vlib_pci_device_info_t *di;
  intel_dsa_channel_t *wq_ch;

  ch->pci_common = clib_mem_alloc_aligned (sizeof (intel_dsa_pci_common_t),
					   CLIB_CACHE_LINE_BYTES);
  if (!ch->pci_common)
    return clib_error_return (0, "failed to allocate pci region");

  if ((error = vlib_pci_device_open (vm, &ch->addr, dsa_pci_device_ids,
				     &ch->pci_handle)))
    return clib_error_return (0, "failed to open pci-addr %U",
			      format_vlib_pci_addr, &ch->addr);

  di = vlib_pci_get_device_info (vm, &ch->addr, &error);
  if (!di)
    return clib_error_return (0, "failed to read pci-addr %U",
			      format_vlib_pci_addr, &ch->addr);
  ch->numa = di->numa_node;
  vlib_pci_free_device_info (di);

  if ((error = vlib_pci_bus_master_enable (vm, ch->pci_handle)))
    return error;

  pci_common = (intel_dsa_pci_common_t *) ch->pci_common;
  if ((error = vlib_pci_map_region (vm, ch->pci_handle, 0,
				    (void **) &pci_common->regs)))
    return error;

  if ((error =
	 vlib_pci_map_region (vm, ch->pci_handle, 2, (void **) &ch->portal)))
    return error;

  grp_offset = (u16) pci_common->regs->offsets[0];
  pci_common->grp_regs =
    (void *) ((uintptr_t) pci_common->regs + grp_offset * 0x100);
  wq_offset = (u16) (pci_common->regs->offsets[0] >> 16);
  pci_common->wq_regs_base =
    (u32 *) ((uintptr_t) pci_common->regs + wq_offset * 0x100);
  pci_common->wq_cfg_sz = (pci_common->regs->wqcap >> 24) & 0x0F;

  /* sanity check device status */
  if (pci_common->regs->gensts & GENSTS_DEV_STATE_MASK)
    return clib_error_return (0, "Device status is not disabled, cannot init");
  if (pci_common->regs->cmdstatus & CMDSTATUS_ACTIVE_MASK)
    return clib_error_return (0, "Device is busy, cannot init");

  /* read basic info about the hardware for configuration */
  nb_groups = (u8) pci_common->regs->grpcap;
  nb_engines = (u8) pci_common->regs->engcap;
  nb_wqs = (u8) (pci_common->regs->wqcap >> 16);
  total_wq_size = (u16) pci_common->regs->wqcap;
  lg2_max_copy_size = (u8) (pci_common->regs->gencap >> 16) & 0x1F;
  lg2_max_batch = (u8) (pci_common->regs->gencap >> 21) & 0x0F;
  dsa_log_debug ("dsa %U scanned out groups/engines/wqs %u/%u/%u",
		 format_vlib_pci_addr, &ch->addr, nb_groups, nb_engines,
		 nb_wqs);
  ch->max_transfers = (u16) 1 << lg2_max_batch;
  ch->max_transfer_size = (u32) 1 << lg2_max_copy_size;
  ch->block_on_fault = 0;
  /* zero out any old config */
  for (i = 0; i < nb_groups; i++)
    {
      pci_common->grp_regs[i].grpengcfg = 0;
      pci_common->grp_regs[i].grpwqcfg[0] = 0;
    }
  for (i = 0; i < nb_wqs; i++)
    intel_dsa_get_wqcfg (pci_common, i)[0] = 0;

  /* assign engine into a separate group */
  if (nb_groups > nb_engines)
    nb_groups = nb_engines;
  if (nb_groups < nb_engines)
    nb_engines = nb_groups;
  /* assign engines to groups, round-robin style */
  for (i = 0; i < nb_engines; i++)
    {
      dsa_log_debug ("dsa %U assign engine %u to group %u",
		     format_vlib_pci_addr, &ch->addr, i, i % nb_groups);
      pci_common->grp_regs[i % nb_groups].grpengcfg |= (1ULL << i);
    }
  wq_size = total_wq_size / nb_wqs;
  dsa_log_debug ("dsa %U work queue size %u, max batch 2^%u, max copy 2^%u",
		 format_vlib_pci_addr, &ch->addr, wq_size, lg2_max_batch,
		 lg2_max_copy_size);
  vec_validate (dm->channels, ch->numa);

  /* configure work queues and assign to groups */
  for (i = 0; i < nb_wqs; i++)
    {
      dsa_log_debug ("dsa %U assign work queue %u to group %u",
		     format_vlib_pci_addr, &ch->addr, i, i % nb_groups);
      pci_common->grp_regs[i % nb_groups].grpwqcfg[0] |= (1ULL << i);
      intel_dsa_get_wqcfg (pci_common, i)[wq_size_idx] = wq_size;
      intel_dsa_get_wqcfg (pci_common, i)[wq_mode_idx] =
	(1 << WQ_PRIORITY_SHIFT) | WQ_MODE_DEDICATED;
      intel_dsa_get_wqcfg (pci_common, i)[wq_sizes_idx] =
	lg2_max_copy_size | (lg2_max_batch << WQ_BATCH_SZ_SHIFT);
    }

  dsa_pci_command (pci_common, 0, DSA_PCI_ENABLE_DEVICE);
  for (i = 0; i < nb_wqs; i++)
    {
      wq_ch = clib_mem_alloc_aligned (sizeof (intel_dsa_channel_t),
				      CLIB_CACHE_LINE_BYTES);
      clib_memcpy_fast ((void *) wq_ch, (void *) ch,
			sizeof (intel_dsa_channel_t));
      wq_ch->portal = ch->portal + i * IDXD_PORTAL_SIZE;
      wq_ch->did = 0;
      wq_ch->qid = i;
      vec_add1 (dm->channels[ch->numa], wq_ch);
      wq_ch->size = wq_size;
      intel_dsa_wq_start (pci_common, i);
      dsa_log_info ("dsa %U work queue %d enabled", format_vlib_pci_addr,
		    &ch->addr, i);
    }

  return error;
}