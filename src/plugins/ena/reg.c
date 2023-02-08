/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "reg",
};

static u8 *
format_ena_reg_name (u8 *s, va_list *args)
{
  int offset = va_arg (*args, int);

  char *reg_names[] = {
#define _(o, r, rn, m) [(o) >> 2] = #rn,
    foreach_ena_reg
#undef _
  };

  offset >>= 2;

  if (offset < 0 || offset >= ARRAY_LEN (reg_names) || reg_names[offset] == 0)
    return format (s, "(unknown)");
  return format (s, "%s", reg_names[offset]);
}

void
ena_reg_write (ena_device_t *ed, ena_reg_t reg, void *v)
{
  u32 *p = (u32 *) ((u8 *) ed->reg_bar + reg);
  u32 val = *(u32 *) v;
  ena_log_debug (ed, "%s: reg %U (0x%02x) value 0x%08x", __func__,
		 format_ena_reg_name, reg, reg, val);
  __atomic_store_n (p, val, __ATOMIC_RELEASE);
}

void
ena_reg_read (ena_device_t *ed, ena_reg_t reg, const void *v)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 rv;
  f64 dt = 0, t0;

  if (ed->readless == 0)
    {
      rv =
	__atomic_load_n ((u32 *) ((u8 *) ed->reg_bar + reg), __ATOMIC_SEQ_CST);
    }
  else
    {
      u32 *p = (u32 *) ((u8 *) ed->reg_bar + ENA_REG_MMIO_REG_READ);

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

void
ena_set_mmio_resp (vlib_main_t *vm, ena_device_t *ed)
{
  uword pa = ena_dma_addr (vm, ed, (void *) ed->mmio_resp);
  u32 reg;

  reg = (u32) pa;
  ena_reg_write (ed, ENA_REG_MMIO_RESP_LO, &reg);
  reg = pa >> 32;
  ena_reg_write (ed, ENA_REG_MMIO_RESP_HI, &reg);
}
