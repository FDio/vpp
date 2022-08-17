/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Intel and/or its affiliates.
 */
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/dma/dma.h>
#include <vnet/plugin/plugin.h>
#include <dma_intel/dsa_intel.h>

u8 *
format_intel_dsa_addr (u8 *s, va_list *va)
{
  intel_dsa_channel_t *ch = va_arg (*va, intel_dsa_channel_t *);
  return format (s, "wq%d.%d", ch->did, ch->qid);
}
