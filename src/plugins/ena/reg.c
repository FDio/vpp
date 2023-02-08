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

static void
ena_reg_set_dma_addr (vlib_main_t *vm, ena_device_t *ed, u32 rlo, u32 rhi,
		      void *p)
{
  uword pa = ena_dma_addr (vm, ed, p);
  u32 reg = (u32) pa;
  ena_reg_write (ed, rlo, &reg);
  reg = pa >> 32;
  ena_reg_write (ed, rhi, &reg);
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

clib_error_t *
ena_reg_reset (vlib_main_t *vm, ena_device_t *ed, ena_reset_reason_t reason)
{
  ena_reg_version_t ver;
  ena_reg_controller_version_t ctrl_ver;
  ena_reg_caps_t caps;
  ena_reg_dev_sts_t dev_sts;
  ena_reg_dev_ctl_t reset_start = { .dev_reset = 1, .reset_reason = reason };

  if (ed->readless)
    ena_reg_set_dma_addr (vm, ed, ENA_REG_MMIO_RESP_LO, ENA_REG_MMIO_RESP_HI,
			  ed->mmio_resp);

  ena_reg_read (ed, ENA_REG_DEV_STS, &dev_sts);
  ena_reg_read (ed, ENA_REG_CAPS, &caps);

  if (caps.as_u32 == ~0 && dev_sts.as_u32 == ~0)
    return clib_error_return (0,
			      "register BAR read failed, device reset failed");

  if (dev_sts.ready == 0)
    return clib_error_return (0, "device not ready, device reset failed");

  ena_log_debug (ed, "%s: reset timeout is %u", __func__, caps.reset_timeout);

  ena_reg_write (ed, ENA_REG_DEV_CTL, &reset_start);

  if (ed->readless)
    ena_reg_set_dma_addr (vm, ed, ENA_REG_MMIO_RESP_LO, ENA_REG_MMIO_RESP_HI,
			  ed->mmio_resp);

  while (1)
    {
      int i = 0;
      ena_reg_read (ed, ENA_REG_DEV_STS, &dev_sts);
      if (dev_sts.reset_in_progress)
	break;
      if (i++ == 20)
	return clib_error_return (0, "failed to initiate reset");
      vlib_process_suspend (vm, 0.001);
    }

  ena_reg_write (ed, ENA_REG_DEV_CTL, &(ena_reg_dev_ctl_t){});

  while (1)
    {
      int i = 0;
      ena_reg_read (ed, ENA_REG_DEV_STS, &dev_sts);
      if (dev_sts.reset_in_progress == 0)
	break;
      if (i++ == 20)
	return clib_error_return (0, "failed to complete reset");
      vlib_process_suspend (vm, 0.001);
    }

  ena_reg_read (ed, ENA_REG_VERSION, &ver);
  ena_reg_read (ed, ENA_REG_CONTROLLER_VERSION, &ctrl_ver);

  ena_log_info (ed, "version %u.%u controller_version %u.%u.%u impl_id %u\n",
		ver.major, ver.minor, ctrl_ver.major, ctrl_ver.minor,
		ctrl_ver.subminor, ctrl_ver.impl_id);

  return 0;
}

clib_error_t *
ena_reg_init_aq (vlib_main_t *vm, ena_device_t *ed, u16 depth)
{
  u32 sq_alloc_sz = sizeof (ena_admin_sq_entry_t) * depth;
  u32 cq_alloc_sz = sizeof (ena_admin_cq_entry_t) * depth;

  ena_reg_aq_caps_t aq_caps = { .depth = depth,
				.entry_size = sizeof (ena_admin_sq_entry_t) };
  ena_reg_acq_caps_t acq_caps = { .depth = depth,
				  .entry_size =
				    sizeof (ena_admin_cq_entry_t) };

  sq_alloc_sz = round_pow2 (sq_alloc_sz, CLIB_CACHE_LINE_BYTES);
  cq_alloc_sz = round_pow2 (cq_alloc_sz, CLIB_CACHE_LINE_BYTES);

  if (ed->admin_sq_entries == 0)
    ed->admin_sq_entries = vlib_physmem_alloc_aligned_on_numa (
      vm, sq_alloc_sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

  if (ed->admin_sq_entries == 0)
    return vlib_physmem_last_error (vm);

  if (ed->admin_cq_entries == 0)
    ed->admin_cq_entries = vlib_physmem_alloc_aligned_on_numa (
      vm, cq_alloc_sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

  if (ed->admin_cq_entries == 0)
    return vlib_physmem_last_error (vm);

  clib_memset (ed->admin_sq_entries, 0, sq_alloc_sz);
  clib_memset (ed->admin_cq_entries, 0, cq_alloc_sz);
  ed->admin_sq_next = 0;
  ed->admin_cq_head = 0;

  ena_reg_set_dma_addr (vm, ed, ENA_REG_AQ_BASE_LO, ENA_REG_AQ_BASE_HI,
			ed->admin_sq_entries);
  ena_reg_set_dma_addr (vm, ed, ENA_REG_ACQ_BASE_LO, ENA_REG_ACQ_BASE_HI,
			ed->admin_cq_entries);

  ena_reg_write (ed, ENA_REG_AQ_CAPS, &aq_caps);
  ena_reg_write (ed, ENA_REG_ACQ_CAPS, &acq_caps);

  return 0;
}

clib_error_t *
ena_reg_init_aenq (vlib_main_t *vm, ena_device_t *ed, u16 depth)
{
  u32 aenq_alloc_sz = sizeof (ena_aenq_entry_t) * depth;
  ena_reg_aenq_caps_t aenq_caps = { .depth = depth,
				    .entry_size = sizeof (ena_aenq_entry_t) };

  aenq_alloc_sz = round_pow2 (aenq_alloc_sz, CLIB_CACHE_LINE_BYTES);

  if (ed->aenq_entries == 0)
    ed->aenq_entries = vlib_physmem_alloc_aligned_on_numa (
      vm, aenq_alloc_sz, CLIB_CACHE_LINE_BYTES, ed->numa_node);

  if (ed->aenq_entries == 0)
    return vlib_physmem_last_error (vm);

  clib_memset (ed->aenq_entries, 0, aenq_alloc_sz);

  ena_reg_set_dma_addr (vm, ed, ENA_REG_AENQ_BASE_LO, ENA_REG_AENQ_BASE_HI,
			ed->aenq_entries);

  ena_reg_write (ed, ENA_REG_AENQ_CAPS, &aenq_caps);
  ena_reg_write (ed, ENA_REG_AENQ_HEAD_DB, &(u32){ depth });

  ed->aenq_head = depth;

  return 0;
}
