/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>

#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "reg",
};

static vnet_dev_rv_t
ena_err (vnet_dev_t *dev, vnet_dev_rv_t rv, char *fmt, ...)
{
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  ena_log_err (dev, "%v", s);
  vec_free (s);
  return rv;
}

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
ena_reg_write (vnet_dev_t *dev, ena_reg_t reg, void *v)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  u32 *p = (u32 *) ((u8 *) ed->reg_bar + reg);
  u32 val = *(u32 *) v;
  ena_log_debug (dev, "%s: reg %U (0x%02x) value 0x%08x", __func__,
		 format_ena_reg_name, reg, reg, val);
  __atomic_store_n (p, val, __ATOMIC_RELEASE);
}

void
ena_reg_set_dma_addr (vlib_main_t *vm, vnet_dev_t *dev, u32 rlo, u32 rhi,
		      void *p)
{
  uword pa = vnet_dev_get_dma_addr (vm, dev, p);
  u32 reg = (u32) pa;
  ena_reg_write (dev, rlo, &reg);
  reg = pa >> 32;
  ena_reg_write (dev, rhi, &reg);
}

void
ena_reg_read (vnet_dev_t *dev, ena_reg_t reg, const void *v)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
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

  ena_log_debug (dev, "%s: reg %U (0x%02x) value 0x%08x dt %.3fs", __func__,
		 format_ena_reg_name, reg, reg, rv, dt);
  *(u32 *) v = rv;
}

vnet_dev_rv_t
ena_reg_reset (vlib_main_t *vm, vnet_dev_t *dev, ena_reset_reason_t reason)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  ena_reg_version_t ver;
  ena_reg_controller_version_t ctrl_ver;
  ena_reg_caps_t caps;
  ena_reg_dev_sts_t dev_sts;
  ena_reg_dev_ctl_t reset_start = { .dev_reset = 1, .reset_reason = reason };

  if (ed->readless)
    ena_reg_set_dma_addr (vm, dev, ENA_REG_MMIO_RESP_LO, ENA_REG_MMIO_RESP_HI,
			  ed->mmio_resp);

  ena_reg_read (dev, ENA_REG_DEV_STS, &dev_sts);
  ena_reg_read (dev, ENA_REG_CAPS, &caps);

  if (caps.as_u32 == ~0 && dev_sts.as_u32 == ~0)
    return ena_err (dev, VNET_DEV_ERR_BUS, "failed to read regs");

  if (dev_sts.ready == 0)
    return VNET_DEV_ERR_NOT_READY;

  ena_log_debug (dev, "reg_reset: reset timeout is %u", caps.reset_timeout);

  ena_reg_write (dev, ENA_REG_DEV_CTL, &reset_start);

  if (ed->readless)
    ena_reg_set_dma_addr (vm, dev, ENA_REG_MMIO_RESP_LO, ENA_REG_MMIO_RESP_HI,
			  ed->mmio_resp);

  while (1)
    {
      int i = 0;
      ena_reg_read (dev, ENA_REG_DEV_STS, &dev_sts);
      if (dev_sts.reset_in_progress)
	break;
      if (i++ == 20)
	return ena_err (dev, VNET_DEV_ERR_BUS, "failed to initiate reset");
      vlib_process_suspend (vm, 0.001);
    }

  ena_reg_write (dev, ENA_REG_DEV_CTL, &(ena_reg_dev_ctl_t){});

  return 0;
  while (1)
    {
      int i = 0;
      ena_reg_read (dev, ENA_REG_DEV_STS, &dev_sts);
      if (dev_sts.reset_in_progress == 0)
	break;
      if (i++ == 20)
	return ena_err (dev, VNET_DEV_ERR_BUS, "failed to complete reset");
      vlib_process_suspend (vm, 0.001);
    }

  ena_reg_read (dev, ENA_REG_VERSION, &ver);
  ena_reg_read (dev, ENA_REG_CONTROLLER_VERSION, &ctrl_ver);

  ena_log_info (dev, "version %u.%u controller_version %u.%u.%u impl_id %u\n",
		ver.major, ver.minor, ctrl_ver.major, ctrl_ver.minor,
		ctrl_ver.subminor, ctrl_ver.impl_id);

  return 0;
}
