/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/dma/dma.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dma_intel/dma_intel.h>

VLIB_REGISTER_LOG_CLASS (intel_dma_log) = {
  .class_name = "intel_dma",
};

#define foreach_cbdma_reg                                                     \
  _ (0x00, 4, 0, CHANCNT, num_chan)                                           \
  _ (0x01, 4, 0, XFERCAP, trans_size)                                         \
  _ (0x03, 3, 3, INTRCTRL, MSIX_VECCTRL)                                      \
  _ (0x03, 2, 2, INTRCTRL, intp)                                              \
  _ (0x03, 1, 1, INTRCTRL, intp_sts)                                          \
  _ (0x03, 0, 0, INTRCTRL, Mstr_intp_En)                                      \
  _ (0x04, 0, 0, ATTNSTATUS, ChanAttn)                                        \
  _ (0x08, 7, 4, CBVER, mjrver)                                               \
  _ (0x08, 3, 0, CBVER, mnrver)                                               \
  _ (0x0c, 15, 15, INTRDELAY, Interrupt_Coalescing_Supported)                 \
  _ (0x0c, 13, 0, INTRDELAY, Interrupt_Delay_Time)                            \
  _ (0x0e, 3, 3, CS_STATUS, Address_Remapping)                                \
  _ (0x0e, 2, 2, CS_STATUS, Memory_Bypass)                                    \
  _ (0x0e, 1, 1, CS_STATUS, MMIO_Restriction)                                 \
  _ (0x10, 27, 27, DMACAPABILITY, InterVM_Supported)                          \
  _ (0x10, 25, 25, DMACAPABILITY, BlockFill_NULL_Supported)                   \
  _ (0x10, 24, 24, DMACAPABILITY, NoST)                                       \
  _ (0x10, 10, 10, DMACAPABILITY, DIF)                                        \
  _ (0x10, 9, 9, DMACAPABILITY, XOR_RAID6)                                    \
  _ (0x10, 8, 8, DMACAPABILITY, XOR_RAID5)                                    \
  _ (0x10, 7, 7, DMACAPABILITY, Extended_APIC_ID)                             \
  _ (0x10, 6, 6, DMACAPABILITY, Block_Fill)                                   \
  _ (0x10, 5, 5, DMACAPABILITY, Move_CRC)                                     \
  _ (0x10, 4, 4, DMACAPABILITY, DCA)                                          \
  _ (0x10, 3, 3, DMACAPABILITY, XOR)                                          \
  _ (0x10, 2, 2, DMACAPABILITY, Marker_Skipping)                              \
  _ (0x10, 1, 1, DMACAPABILITY, CRC)                                          \
  _ (0x10, 0, 0, DMACAPABILITY, Page_Break)                                   \
  _ (0x14, 15, 0, DCAOFFSET, DCAREGPTR)                                       \
  _ (0x100, 7, 4, DCA_VER, Major_Revision)                                    \
  _ (0x100, 3, 0, DCA_VER, Minor_Revision)

static inline u32
cbdma_get_bits (void *start, int offset, int first, int last)
{
  u32 value = *((u32 *) ((u8 *) start + offset));
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

u8 *
format_cbdma_registers (u8 *s, va_list *args)
{
  void *bar = va_arg (*args, void *);
  u32 val;
#define _(off, msb, lsb, reg, field)                                          \
  val = cbdma_get_bits (bar, off, msb, lsb);                                  \
  s = format (s, "%-40s0x%x\n", #reg "." #field, val);
  foreach_cbdma_reg
#undef _
    return s;
}

u8 *
format_cbdma_descs (u8 *s, va_list *args)
{
  intel_cbdma_desc_t *d = va_arg (*args, intel_cbdma_desc_t *);
  u32 count = va_arg (*args, u32);

  while (count--)
    {
      s = format (s, "%p: %p -> %p, size %u, flags 0x%x, next %p", d, d->src,
		  d->dst, d->size, d->desc_control, d->next);
      if (count)
	vec_add1 (s, '\n');
      d++;
    }

  return s;
}
