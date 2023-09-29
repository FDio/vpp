/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <vnet/ethernet/ethernet.h>

#define AVF_AQ_POLL_INTERVAL	 0.1
#define AVF_AQ_ENQ_SUSPEND_TIME	 50e-6
#define AVF_AQ_ENQ_MAX_WAIT_TIME 250e-3
#define AVF_AQ_BUF_SIZE		 4096
#define AVF_RESET_SUSPEND_TIME	 20e-3
#define AVF_RESET_MAX_WAIT_TIME	 1
#define AVF_AQ_ATQ_LEN		 4
#define AVF_AQ_ARQ_LEN		 32
#define AVF_AQ_ATQ_BUF_SZ	 256
#define AVF_AQ_ARQ_BUF_SZ	 256
#define AVF_AQ_LARGE_BUF	 512

struct avf_adminq_dma_mem
{
  avf_aq_desc_t atq[AVF_AQ_ATQ_LEN];
  avf_aq_desc_t arq[AVF_AQ_ARQ_LEN];
  struct
  {
    u8 data[AVF_AQ_ATQ_BUF_SZ];
  } atq_bufs[AVF_AQ_ATQ_LEN];
  struct
  {
    u8 data[AVF_AQ_ARQ_BUF_SZ];
  } arq_bufs[AVF_AQ_ARQ_LEN];
};

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
  .subclass_name = "adminq",
};

static_always_inline int
avf_aq_desc_is_done (avf_aq_desc_t *d)
{
  avf_aq_desc_flags_t flags;
  flags.as_u16 = __atomic_load_n (&d->flags.as_u16, __ATOMIC_ACQUIRE);
  return flags.dd;
}

vnet_dev_rv_t
avf_aq_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  return vnet_dev_dma_mem_alloc (vm, dev, sizeof (avf_adminq_dma_mem_t), 0,
				 (void **) &ad->aq_mem);
}

void
avf_aq_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_dma_mem_free (vm, dev, ad->aq_mem);
}

static void
avf_aq_arq_slot_init (vlib_main_t *vm, vnet_dev_t *dev, u16 slot)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  u64 pa = vnet_dev_get_dma_addr (vm, dev, ad->aq_mem->arq_bufs + slot);
  ad->aq_mem->arq[slot] = (avf_aq_desc_t){
    .flags.buf = 1,
    .flags.lb = AVF_AQ_ARQ_BUF_SZ > AVF_AQ_LARGE_BUF,
    .datalen = sizeof (ad->aq_mem->arq_bufs[0].data),
    .addr_hi = (u32) (pa >> 32),
    .addr_lo = (u32) pa,
  };
}

static vnet_dev_rv_t
avf_aq_poll (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_aq_desc_t *d = ad->aq_mem->atq + ad->atq_next_slot;
  if (d->flags.as_u16)
    log_debug (dev, "poll[%u] flags %x", ad->atq_next_slot, d->flags.as_u16);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
avf_aq_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  uword pa;
  u32 len;

  /* disable both tx and rx adminq queue */
  avf_reg_write (ad, AVF_ATQLEN, 0);
  avf_reg_write (ad, AVF_ARQLEN, 0);

  len = AVF_AQ_ATQ_LEN;
  pa = vnet_dev_get_dma_addr (vm, dev, &ad->aq_mem->atq);
  avf_reg_write (ad, AVF_ATQT, 0);		      /* Tail */
  avf_reg_write (ad, AVF_ATQH, 0);		      /* Head */
  avf_reg_write (ad, AVF_ATQBAL, (u32) pa);	      /* Base Address Low */
  avf_reg_write (ad, AVF_ATQBAH, (u32) (pa >> 32));   /* Base Address High */
  avf_reg_write (ad, AVF_ATQLEN, len | (1ULL << 31)); /* len & ena */

  len = AVF_AQ_ARQ_LEN;
  pa = vnet_dev_get_dma_addr (vm, dev, ad->aq_mem->arq);
  avf_reg_write (ad, AVF_ARQT, 0);		      /* Tail */
  avf_reg_write (ad, AVF_ARQH, 0);		      /* Head */
  avf_reg_write (ad, AVF_ARQBAL, (u32) pa);	      /* Base Address Low */
  avf_reg_write (ad, AVF_ARQBAH, (u32) (pa >> 32));   /* Base Address High */
  avf_reg_write (ad, AVF_ARQLEN, len | (1ULL << 31)); /* len & ena */

  for (int i = 0; i < len; i++)
    avf_aq_arq_slot_init (vm, dev, i);
  avf_reg_write (ad, AVF_ARQT, len - 1); /* Tail */

  ad->atq_next_slot = 0;
  ad->arq_next_slot = 0;
  ad->adminq_active = 1;
  vnet_dev_poll_dev_add (vm, dev, AVF_AQ_POLL_INTERVAL, avf_aq_poll);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
avf_aq_atq_enq (vlib_main_t *vm, vnet_dev_t *dev, avf_aq_desc_t *desc,
		u8 *data, u16 len, f64 timeout)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_aq_desc_t *d = ad->aq_mem->atq + ad->atq_next_slot;
  u8 *buf = ad->aq_mem->atq_bufs[ad->atq_next_slot].data;

  *d = *desc;

  if (len)
    {
      u64 pa = vnet_dev_get_dma_addr (vm, dev, buf);
      d->datalen = len;
      d->addr_hi = (u32) (pa >> 32);
      d->addr_lo = (u32) pa;
      d->flags.buf = 1;
      d->flags.rd = 1;
      d->flags.lb = len > AVF_AQ_LARGE_BUF;
      clib_memcpy_fast (buf, data, len);
    }

  log_debug (dev, "atq_desc_enq: slot %u, opcode 0x%04x flags 0x%04x\n%U\n%U",
	     ad->atq_next_slot, d->opcode, d->flags.as_u16, format_hexdump_u32,
	     (u32 *) d, 8, format_hexdump, buf, len);

  ad->atq_next_slot = (ad->atq_next_slot + 1) % AVF_AQ_ATQ_LEN;
  avf_reg_write (ad, AVF_ATQT, ad->atq_next_slot);
  avf_reg_flush (ad);

  if (timeout > 0)
    {
      f64 suspend_time = 20e-3;
      f64 t0 = vlib_time_now (vm);
      avf_aq_desc_flags_t flags;

      while (1)
	{
	  flags.as_u16 = __atomic_load_n (&d->flags.as_u16, __ATOMIC_ACQUIRE);

	  if (flags.err)
	    {
	      log_err (dev, "adminq enqueue error [opcode 0x%x, retval %d]",
		       d->opcode, d->retval);
	      return VNET_DEV_ERR_BUG;
	    }

	  if (flags.dd && flags.cmp)
	    return VNET_DEV_OK;

	  if (vlib_time_now (vm) - t0 > AVF_AQ_ENQ_MAX_WAIT_TIME)
	    {
	      log_err (dev, "adminq enqueue timeout [opcode 0x%x]", d->opcode);
	      return VNET_DEV_ERR_TIMEOUT;
	    }

	  vlib_process_suspend (vm, suspend_time);
	  suspend_time *= 2;
	}
    }

  return VNET_DEV_OK;
}

void
avf_aq_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  if (ad->adminq_active)
    {
      avf_aq_desc_t d = {
	.opcode = AVF_AQ_DESC_OP_QUEUE_SHUTDOWN,
	.driver_unloading = 1,
	.flags = { .si = 1 },
      };
      log_debug (dev, "adminq queue shutdown");
      avf_aq_atq_enq (vm, dev, &d, 0, 0, 0);
      ad->adminq_active = 0;
      vnet_dev_poll_dev_remove (vm, dev, avf_aq_poll);
    }
}

int
avf_aq_arq_next_acq (vlib_main_t *vm, vnet_dev_t *dev, avf_aq_desc_t **dp,
		     u8 **bp, f64 timeout)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_aq_desc_t *d = ad->aq_mem->arq + ad->arq_next_slot;

  if (timeout)
    {
      f64 suspend_time = timeout / 62;
      f64 t0 = vlib_time_now (vm);

      while (!avf_aq_desc_is_done (d))
	{
	  if (vlib_time_now (vm) - t0 > timeout)
	    return 0;

	  vlib_process_suspend (vm, suspend_time);

	  suspend_time *= 2;
	}
    }
  else if (!avf_aq_desc_is_done (d))
    return 0;

  *dp = d;
  *bp = ad->aq_mem->arq_bufs[ad->arq_next_slot].data;
  return 1;
}

void
avf_aq_arq_next_rel (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  ASSERT (avf_aq_desc_is_done (ad->aq_mem->arq + ad->arq_next_slot));
  avf_aq_arq_slot_init (vm, dev, ad->arq_next_slot);
  avf_reg_write (ad, AVF_ARQT, ad->arq_next_slot);
  avf_reg_flush (ad);
  ad->arq_next_slot = (ad->arq_next_slot + 1) % AVF_AQ_ARQ_LEN;
}
