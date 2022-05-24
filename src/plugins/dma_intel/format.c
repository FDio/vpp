/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/dma/dma.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dma_intel/dma_intel.h>

u8 *
format_cbdma_descs (u8 *s, va_list *args)
{
  intel_cbdma_desc_t *d = va_arg (*args, intel_cbdma_desc_t *);
  u32 count = va_arg (*args, u32);

  while (count--)
    {
      intel_cbdma_desc_t tmp = { .desc_control = d->desc_control };

      s = format (s, "%p: %p -> %p, next %p, size %u, type ", d, d->src,
		  d->dst, d->next, d->size);
      switch (d->op_type)
	{
	case 0:
	  s = format (s, "copy");
	  break;
	case 1:
	  s = format (s, "fill");
	  break;
	default:
	  s = format (s, "unknown (0x%x)", d->op_type);
	}
      tmp.op_type = 0;

#define _(f)                                                                  \
  if (tmp.f)                                                                  \
    {                                                                         \
      s = format (s, ", " #f);                                                \
      tmp.f = 0;                                                              \
    }
      _ (null_transfer)
      _ (fence)
      _ (int_comp)
      _ (source_snoop)
      _ (dst_snoop)
      _ (comp_upd)
      _ (src_pg_break)
      _ (dst_pg_break)
      _ (bundle)
      _ (dst_dca_ena)
      _ (buffer_hint)
#undef _

      if (tmp.desc_control)
	s = format (s, ", unknown (0x%x)", tmp.desc_control);

      if (count)
	vec_add1 (s, '\n');
      d++;
    }

  return s;
}
