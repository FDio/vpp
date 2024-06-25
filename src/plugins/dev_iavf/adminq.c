/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <ctype.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <dev_iavf/iavf.h>
#include <dev_iavf/iavf_regs.h>
#include <dev_iavf/virtchnl.h>
#include <vnet/ethernet/ethernet.h>

#define IIAVF_AQ_LARGE_BUF 512
#define IIAVF_AQ_ATQ_LEN   4
#define IIAVF_AQ_ARQ_LEN   16

VLIB_REGISTER_LOG_CLASS (iavf_log, static) = {
  .class_name = "iavf",
  .subclass_name = "adminq",
};

struct iavf_adminq_dma_mem
{
  iavf_aq_desc_t atq[IIAVF_AQ_ATQ_LEN];
  iavf_aq_desc_t arq[IIAVF_AQ_ARQ_LEN];
  struct
  {
    u8 data[IIAVF_AQ_BUF_SIZE];
  } atq_bufs[IIAVF_AQ_ATQ_LEN];
  struct
  {
    u8 data[IIAVF_AQ_BUF_SIZE];
  } arq_bufs[IIAVF_AQ_ARQ_LEN];
};

static const iavf_dyn_ctl dyn_ctl0_disable = {
  .itr_indx = 3,
};

static const iavf_dyn_ctl dyn_ctl0_enable = {
  .intena = 1,
  .clearpba = 1,
  .itr_indx = 3,
};

static const iavf_vfint_icr0_ena1 icr0_ena1_aq_enable = {
  .adminq = 1,
};

static inline void
iavf_irq_0_disable (iavf_device_t *ad)
{
  iavf_reg_write (ad, IAVF_VFINT_ICR0_ENA1, 0);
  iavf_reg_write (ad, IAVF_VFINT_DYN_CTL0, dyn_ctl0_disable.as_u32);
  iavf_reg_flush (ad);
}

static inline void
iavf_irq_0_enable (iavf_device_t *ad)
{
  iavf_reg_write (ad, IAVF_VFINT_ICR0_ENA1, icr0_ena1_aq_enable.as_u32);
  iavf_reg_write (ad, IAVF_VFINT_DYN_CTL0, dyn_ctl0_enable.as_u32);
  iavf_reg_flush (ad);
}

static_always_inline int
iavf_aq_desc_is_done (iavf_aq_desc_t *d)
{
  iavf_aq_desc_flags_t flags;
  flags.as_u16 = __atomic_load_n (&d->flags.as_u16, __ATOMIC_ACQUIRE);
  return flags.dd;
}

static u8 *
format_iavf_aq_desc_flags (u8 *s, va_list *args)
{
  iavf_aq_desc_flags_t f = va_arg (*args, iavf_aq_desc_flags_t);
  int i = 0;

#define _(n, v)                                                               \
  if (f.v)                                                                    \
    {                                                                         \
      char str[] = #v, *sp = str;                                             \
      if (i++)                                                                \
	{                                                                     \
	  vec_add1 (s, ',');                                                  \
	  vec_add1 (s, ' ');                                                  \
	}                                                                     \
      while (sp[0])                                                           \
	vec_add1 (s, (u8) toupper (sp++[0]));                                 \
    }
  foreach_iavf_aq_desc_flag
#undef _
    return s;
}

static u8 *
format_iavf_aq_desc_retval (u8 *s, va_list *args)
{
  iavf_aq_desc_retval_t rv = va_arg (*args, u32);

  char *retvals[] = {
#define _(a, b) [a] = #b,
    foreach_iavf_aq_desc_retval
#undef _
  };

  if (rv >= ARRAY_LEN (retvals) || retvals[rv] == 0)
    return format (s, "UNKNOWN(%d)", rv);

  return format (s, "%s", retvals[rv]);
}

static u8 *
format_iavf_aq_desc (u8 *s, va_list *args)
{
  iavf_aq_desc_t *d = va_arg (*args, iavf_aq_desc_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "opcode 0x%04x datalen %u retval %U (%u) flags %U", d->opcode,
	      d->datalen, format_iavf_aq_desc_retval, d->retval, d->retval,
	      format_iavf_aq_desc_flags, d->flags);

  if (d->opcode == IIAVF_AQ_DESC_OP_SEND_TO_PF ||
      d->opcode == IIAVF_AQ_DESC_OP_MESSAGE_FROM_PF)
    {
      s =
	format (s, "\n%Uv_opcode %U (%u) v_retval %U (%d) buf_dma_addr 0x%lx",
		format_white_space, indent, format_virtchnl_op_name,
		d->v_opcode, d->v_opcode, format_virtchnl_status, d->v_retval,
		d->v_retval, (uword) d->param2 << 32 | d->param3);
    }
  else
    {
      s = format (
	s, "\n%Ucookie_hi 0x%x cookie_lo 0x%x params %08x %08x %08x %08x",
	format_white_space, indent, d->cookie_hi, d->cookie_lo, d->param0,
	d->param1, d->param2, d->param3);
    }
  return s;
}

vnet_dev_rv_t
iavf_aq_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  return vnet_dev_dma_mem_alloc (vm, dev, sizeof (iavf_adminq_dma_mem_t), 0,
				 (void **) &ad->aq_mem);
}

void
iavf_aq_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_dma_mem_free (vm, dev, ad->aq_mem);
}

static void
iavf_aq_arq_slot_init (vlib_main_t *vm, vnet_dev_t *dev, u16 slot)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  u64 pa = vnet_dev_get_dma_addr (vm, dev, ad->aq_mem->arq_bufs + slot);
  ad->aq_mem->arq[slot] = (iavf_aq_desc_t){
    .flags.buf = 1,
    .flags.lb = IIAVF_AQ_BUF_SIZE > IIAVF_AQ_LARGE_BUF,
    .datalen = sizeof (ad->aq_mem->arq_bufs[0].data),
    .addr_hi = (u32) (pa >> 32),
    .addr_lo = (u32) pa,
  };
}

static void
iavf_aq_poll (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_aq_desc_t *d;
  u8 *b;

  while (iavf_aq_arq_next_acq (vm, dev, &d, &b, 0))
    {

      log_debug (dev, "poll[%u] flags %x %U op %u v_op %u", ad->arq_next_slot,
		 d->flags.as_u16, format_iavf_aq_desc_flags, d->flags,
		 d->opcode, d->v_opcode);
      if ((d->datalen != sizeof (virtchnl_pf_event_t)) ||
	  ((d->flags.buf) == 0))
	{
	  log_err (dev, "event message error");
	}

      vec_add1 (ad->events, *(virtchnl_pf_event_t *) b);
      iavf_aq_arq_next_rel (vm, dev);
    }

  if (vec_len (ad->events))
    {
      virtchnl_pf_event_t *e;
      char *virtchnl_event_names[] = {
#define _(v, n) [v] = #n,
	foreach_virtchnl_event_code
#undef _
      };

      vec_foreach (e, ad->events)
	{
	  log_debug (dev, "event %s (%u) sev %d",
		     virtchnl_event_names[e->event], e->event, e->severity);

	  if (e->event == VIRTCHNL_EVENT_LINK_CHANGE)
	    {
	      vnet_dev_port_state_changes_t changes = {};
	      vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

	      if (port)
		{
		  iavf_port_t *ap = vnet_dev_get_port_data (port);
		  int link_up;
		  u32 speed = 0;

		  if (ap->vf_cap_flags & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		    {
		      link_up = e->event_data.link_event_adv.link_status;
		      speed = e->event_data.link_event_adv.link_speed;
		    }
		  else
		    {
		      const u32 speed_table[8] = { 100,	  1000,	 10000, 40000,
						   20000, 25000, 2500,	5000 };

		      link_up = e->event_data.link_event.link_status;
		      speed = e->event_data.link_event.link_speed;

		      if (count_set_bits (speed) == 1 && speed &&
			  pow2_mask (8))
			speed = speed_table[get_lowest_set_bit_index (speed)];
		      else
			{
			  if (link_up)
			    log_warn (dev,
				      "unsupported link speed value "
				      "received (0x%x)",
				      speed);
			  speed = 0;
			}
		    }

		  log_debug (dev, "LINK_CHANGE speed %u state %u", speed,
			     link_up);

		  if (port->link_up != link_up)
		    {
		      changes.change.link_state = 1;
		      changes.link_state = link_up;
		      log_debug (dev, "link state changed to %s",
				 link_up ? "up" : "down");
		    }

		  if (port->speed != speed * 1000)
		    {
		      changes.change.link_speed = 1;
		      changes.link_speed = speed * 1000;
		      log_debug (dev, "link speed changed to %u Mbps", speed);
		    }

		  if (changes.change.any)
		    vnet_dev_port_state_change (vm, port, changes);
		}
	    }
	}
      vec_reset_length (ad->events);
    }
}

static void
iavf_adminq_msix_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 line)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_reg_write (ad, IAVF_VFINT_DYN_CTL0, dyn_ctl0_enable.as_u32);
  log_debug (dev, "MSI-X interrupt %u received", line);
  vnet_dev_process_call_op_no_wait (vm, dev, iavf_aq_poll);
}

static void
iavf_adminq_intx_handler (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_adminq_msix_handler (vm, dev, 0);
}

void
iavf_aq_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  uword pa;
  u32 len;

  /* disable both tx and rx adminq queue */
  iavf_reg_write (ad, IAVF_ATQLEN, 0);
  iavf_reg_write (ad, IAVF_ARQLEN, 0);

  len = IIAVF_AQ_ATQ_LEN;
  pa = vnet_dev_get_dma_addr (vm, dev, &ad->aq_mem->atq);
  iavf_reg_write (ad, IAVF_ATQT, 0);			/* Tail */
  iavf_reg_write (ad, IAVF_ATQH, 0);			/* Head */
  iavf_reg_write (ad, IAVF_ATQBAL, (u32) pa);		/* Base Address Low */
  iavf_reg_write (ad, IAVF_ATQBAH, (u32) (pa >> 32));	/* Base Address High */
  iavf_reg_write (ad, IAVF_ATQLEN, len | (1ULL << 31)); /* len & ena */

  len = IIAVF_AQ_ARQ_LEN;
  pa = vnet_dev_get_dma_addr (vm, dev, ad->aq_mem->arq);
  iavf_reg_write (ad, IAVF_ARQT, 0);			/* Tail */
  iavf_reg_write (ad, IAVF_ARQH, 0);			/* Head */
  iavf_reg_write (ad, IAVF_ARQBAL, (u32) pa);		/* Base Address Low */
  iavf_reg_write (ad, IAVF_ARQBAH, (u32) (pa >> 32));	/* Base Address High */
  iavf_reg_write (ad, IAVF_ARQLEN, len | (1ULL << 31)); /* len & ena */

  for (int i = 0; i < len; i++)
    iavf_aq_arq_slot_init (vm, dev, i);
  iavf_reg_write (ad, IAVF_ARQT, len - 1); /* Tail */

  ad->atq_next_slot = 0;
  ad->arq_next_slot = 0;
  ad->adminq_active = 1;
}

void
iavf_aq_poll_on (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);

  vnet_dev_poll_dev_add (vm, dev, IIAVF_AQ_POLL_INTERVAL, iavf_aq_poll);

  if (vnet_dev_get_pci_n_msix_interrupts (dev) > 0)
    {
      vnet_dev_pci_msix_add_handler (vm, dev, iavf_adminq_msix_handler, 0, 1);
      vnet_dev_pci_msix_enable (vm, dev, 0, 1);
    }
  else
    vnet_dev_pci_intx_add_handler (vm, dev, iavf_adminq_intx_handler);

  iavf_irq_0_enable (ad);
}

void
iavf_aq_poll_off (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);

  iavf_irq_0_disable (ad);

  vnet_dev_poll_dev_remove (vm, dev, iavf_aq_poll);

  if (vnet_dev_get_pci_n_msix_interrupts (dev) > 0)
    {
      vnet_dev_pci_msix_disable (vm, dev, 0, 1);
      vnet_dev_pci_msix_remove_handler (vm, dev, 0, 1);
    }
  else
    vnet_dev_pci_intx_remove_handler (vm, dev);
}

vnet_dev_rv_t
iavf_aq_atq_enq (vlib_main_t *vm, vnet_dev_t *dev, iavf_aq_desc_t *desc,
		 const u8 *data, u16 len, f64 timeout)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_aq_desc_t *d = ad->aq_mem->atq + ad->atq_next_slot;
  u8 *buf = ad->aq_mem->atq_bufs[ad->atq_next_slot].data;

  ASSERT (len <= IIAVF_AQ_BUF_SIZE);

  *d = *desc;

  if (len)
    {
      u64 pa = vnet_dev_get_dma_addr (vm, dev, buf);
      d->datalen = len;
      d->addr_hi = (u32) (pa >> 32);
      d->addr_lo = (u32) pa;
      d->flags.buf = 1;
      d->flags.rd = 1;
      d->flags.lb = len > IIAVF_AQ_LARGE_BUF;
      clib_memcpy_fast (buf, data, len);
    }

  log_debug (dev, "slot %u\n  %U", ad->atq_next_slot, format_iavf_aq_desc, d);

  ad->atq_next_slot = (ad->atq_next_slot + 1) % IIAVF_AQ_ATQ_LEN;
  iavf_reg_write (ad, IAVF_ATQT, ad->atq_next_slot);
  iavf_reg_flush (ad);

  if (timeout > 0)
    {
      f64 suspend_time = timeout / 62;
      f64 t0 = vlib_time_now (vm);
      iavf_aq_desc_flags_t flags;

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

	  if (vlib_time_now (vm) - t0 > timeout)
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
iavf_aq_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  if (ad->adminq_active)
    {
      iavf_aq_desc_t d = {
	.opcode = IIAVF_AQ_DESC_OP_QUEUE_SHUTDOWN,
	.driver_unloading = 1,
	.flags = { .si = 1 },
      };
      log_debug (dev, "adminq queue shutdown");
      iavf_aq_atq_enq (vm, dev, &d, 0, 0, 0);
      ad->adminq_active = 0;
    }
}

int
iavf_aq_arq_next_acq (vlib_main_t *vm, vnet_dev_t *dev, iavf_aq_desc_t **dp,
		      u8 **bp, f64 timeout)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_aq_desc_t *d = ad->aq_mem->arq + ad->arq_next_slot;

  if (timeout)
    {
      f64 suspend_time = timeout / 62;
      f64 t0 = vlib_time_now (vm);

      while (!iavf_aq_desc_is_done (d))
	{
	  if (vlib_time_now (vm) - t0 > timeout)
	    return 0;

	  vlib_process_suspend (vm, suspend_time);

	  suspend_time *= 2;
	}
    }
  else if (!iavf_aq_desc_is_done (d))
    return 0;

  log_debug (dev, "arq desc acquired in slot %u\n  %U", ad->arq_next_slot,
	     format_iavf_aq_desc, d);
  *dp = d;
  *bp = ad->aq_mem->arq_bufs[ad->arq_next_slot].data;
  return 1;
}

void
iavf_aq_arq_next_rel (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  ASSERT (iavf_aq_desc_is_done (ad->aq_mem->arq + ad->arq_next_slot));
  iavf_aq_arq_slot_init (vm, dev, ad->arq_next_slot);
  iavf_reg_write (ad, IAVF_ARQT, ad->arq_next_slot);
  iavf_reg_flush (ad);
  ad->arq_next_slot = (ad->arq_next_slot + 1) % IIAVF_AQ_ARQ_LEN;
}
