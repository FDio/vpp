/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_INLINES_H_
#define _ENA_INLINES_H_

#include "ena/ena_defs.h"
#include "vppinfra/lock.h"
#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <ena/ena.h>

static_always_inline void
ena_reg_write (ena_device_t *ed, ena_reg_t reg, void *v)
{
  u32 *p = (u32 *) ((u8 *) ed->bar0 + reg);
  u32 val = *(u32 *) v;
  ena_log_debug (ed, "%s: reg %U (0x%02x) value 0x%08x", __func__,
		 format_ena_reg_name, reg, reg, val);
  __atomic_store_n (p, val, __ATOMIC_RELEASE);
}

static_always_inline void
ena_reg_read (ena_device_t *ed, ena_reg_t reg, const void *v)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 rv;
  f64 dt = 0, t0;

  if (ed->readless == 0)
    {
      rv = __atomic_load_n ((u32 *) ((u8 *) ed->bar0 + reg), __ATOMIC_SEQ_CST);
    }
  else
    {
      u32 *p = (u32 *) ((u8 *) ed->bar0 + ENA_REG_MMIO_REG_READ);

      ena_reg_mmio_reg_read_t rr = { .reg_off = reg, .req_id = 1 };
      ed->mmio_resp->req_id = 0;
      ed->mmio_resp->reg_val = ~0;

      __atomic_store_n (p, rr.as_u32, __ATOMIC_RELEASE);

      t0 = vlib_time_now (vm);
      while (ed->mmio_resp->req_id == 0 && dt < 0.2)
	{
	  CLIB_PAUSE ();
	  dt = vlib_time_now (vm) - t0;
	}

      rv = ed->mmio_resp->reg_val;
    }

  ena_log_debug (ed, "%s: reg %U (0x%02x) value 0x%08x dt %.3fs", __func__,
		 format_ena_reg_name, reg, reg, rv, dt);
  *(u32 *) v = rv;
}

static_always_inline uword
ena_dma_addr (vlib_main_t *vm, ena_device_t *ad, void *p)
{
  return ad->va_dma ? pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}

static_always_inline void
ena_set_mmio_resp (vlib_main_t *vm, ena_device_t *ed)
{
  uword pa = ena_dma_addr (vm, ed, (void *) ed->mmio_resp);
  u32 reg;

  reg = (u32) pa;
  ena_reg_write (ed, ENA_REG_MMIO_RESP_LO, &reg);
  reg = pa >> 32;
  ena_reg_write (ed, ENA_REG_MMIO_RESP_HI, &reg);
}

#endif /* ENA_INLINES_H */
