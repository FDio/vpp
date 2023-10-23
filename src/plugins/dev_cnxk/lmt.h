/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _CNXK_LMT_H_
#define _CNXK_LMT_H_

#include <vppinfra/clib.h>
#include <roc/base/roc_api.h>

typedef struct
{
  u64 ioaddr;
  void *lmt_base_addr;
  u16 lmt_id;
} cnxk_lmt_ctx_t;

static_always_inline cnxk_lmt_ctx_t
cnxk_lmt_ctx (u16 core, u64 ioaddr, void *lmt_addr)
{
  u16 lmt_id = core << ROC_LMT_LINES_PER_CORE_LOG2;

  return (cnxk_lmt_ctx_t){
    .ioaddr = ioaddr & ~0x7fULL,
    .lmt_id = lmt_id,
    .lmt_base_addr = lmt_addr + ((u64) lmt_id << ROC_LMT_LINE_SIZE_LOG2),
  };
}

static_always_inline void
cnxk_lmt_store (cnxk_lmt_ctx_t ctx, const u128 *line_data,
		const u8 *dwords_per_line, u8 n_lines)
{
  u64 lmt_arg = ctx.lmt_id;
  void *line_addr = ctx.lmt_base_addr;
  u64 dpl = *dwords_per_line;
  u64 io_addr = ctx.ioaddr | (dpl - 1) << 4;

  cnxk_wmb ();
  roc_lmt_mov_seg (line_addr, line_data, dpl);

  if (n_lines > 1)
    {
      lmt_arg |= (--n_lines) << 12;

      for (u8 bit_off = 19; n_lines; n_lines--, bit_off += 3)
	{
	  line_addr += 1ULL << ROC_LMT_LINE_SIZE_LOG2;
	  line_data += dpl;
	  dwords_per_line++;
	  dpl = dwords_per_line[0];
	  roc_lmt_mov_seg (line_addr, line_data, dpl);
	  lmt_arg |= (dpl - 1) << bit_off;
	}
    }

  roc_lmt_submit_steorl (lmt_arg, io_addr);
}

#endif /* _CNXK_LMT_H_ */
