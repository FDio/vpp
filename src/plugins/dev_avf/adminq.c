/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <ctype.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <vnet/ethernet/ethernet.h>

#define AVF_AQ_POLL_INTERVAL 0.2
#define AVF_AQ_BUF_SIZE	     4096
#define AVF_AQ_ATQ_LEN	     4
#define AVF_AQ_ATQ_BUF_SZ    4096
#define AVF_AQ_ARQ_LEN	     32
#define AVF_AQ_ARQ_BUF_SZ    256
#define AVF_AQ_LARGE_BUF     512

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

static u8 *
format_avf_aq_desc_flags (u8 *s, va_list *args)
{
  avf_aq_desc_flags_t f = va_arg (*args, avf_aq_desc_flags_t);
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
  foreach_avf_aq_desc_flag
#undef _
    return s;
}

static u8 *
format_avf_aq_desc_retval (u8 *s, va_list *args)
{
  avf_aq_desc_retval_t rv = va_arg (*args, u32);

  char *retvals[] = {
#define _(a, b) [a] = #b,
    foreach_avf_aq_desc_retval
#undef _
  };

  if (rv >= ARRAY_LEN (retvals) || retvals[rv] == 0)
    return format (s, "UNKNOWN(%d)", rv);

  return format (s, "%s", retvals[rv]);
}

static u8 *
format_avf_aq_desc (u8 *s, va_list *args)
{
  avf_aq_desc_t *d = va_arg (*args, avf_aq_desc_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "opcode 0x%04x datalen %u retval %U (%u) flags %U", d->opcode,
	      d->datalen, format_avf_aq_desc_retval, d->retval, d->retval,
	      format_avf_aq_desc_flags, d->flags);

  if (d->opcode == AVF_AQ_DESC_OP_SEND_TO_PF ||
      d->opcode == AVF_AQ_DESC_OP_MESSAGE_FROM_PF)
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
  avf_aq_desc_t *d;
  u8 *b;

  while (avf_aq_arq_next_acq (vm, dev, &d, &b, 0))
    {

      log_debug (dev, "poll[%u] flags %x %U op %u v_op %u", ad->arq_next_slot,
		 d->flags.as_u16, format_avf_aq_desc_flags, d->flags,
		 d->opcode, d->v_opcode);
      if ((d->datalen != sizeof (virtchnl_pf_event_t)) ||
	  ((d->flags.buf) == 0))
	{
	  log_err (dev, "event message error");
	  return VNET_DEV_ERR_BUG;
	}

      vec_add1 (ad->events, *(virtchnl_pf_event_t *) b);
      avf_aq_arq_next_rel (vm, dev);
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
	  log_debug (dev, "event: %s (%u) sev %d",
		     virtchnl_event_names[e->event], e->event, e->severity);

	  if (e->event == VIRTCHNL_EVENT_LINK_CHANGE)
	    {
	      vnet_dev_port_state_changes_t changes = {};
	      vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);
	      avf_port_t *ap = vnet_dev_get_port_data (port);
	      int link_up;
	      u32 speed = 0;

	      if (ap->vf_cap_flags & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		{
		  link_up = e->event_data.link_event_adv.link_status;
		  speed = e->event_data.link_event_adv.link_speed;
		}
	      else
		{
		  const u32 speed_table[8] = { 100,   1000,  10000, 40000,
					       20000, 25000, 2500,  5000 };

		  link_up = e->event_data.link_event.link_status;
		  speed = e->event_data.link_event.link_speed;

		  if (count_set_bits (speed) == 1 && speed && pow2_mask (8))
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

	      if (ap->link_up != link_up)
		{
		  changes.change.link_state = 1;
		  changes.link_state = link_up;
		  ap->link_up = link_up;
		  log_debug (dev, "port_poll: link state changed to %s",
			     link_up ? "up" : "down");
		}

	      if (ap->speed != speed)
		{
		  changes.change.link_speed = 1;
		  changes.link_speed = speed * 1000;
		  ap->speed = speed;
		  log_debug (dev, "port_poll: link speed changed to %u Mbps",
			     speed);
		}

	      if (changes.change.any)
		vnet_dev_port_state_change (vm, port, changes);
	    }
	}
      vec_reset_length (ad->events);
    }
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
		const u8 *data, u16 len, f64 timeout)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_aq_desc_t *d = ad->aq_mem->atq + ad->atq_next_slot;
  u8 *buf = ad->aq_mem->atq_bufs[ad->atq_next_slot].data;

  ASSERT (len <= AVF_AQ_ATQ_BUF_SZ);

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

  log_debug (dev, "atq_desc_enq: slot %u\n  %U", ad->atq_next_slot,
	     format_avf_aq_desc, d);

  ad->atq_next_slot = (ad->atq_next_slot + 1) % AVF_AQ_ATQ_LEN;
  avf_reg_write (ad, AVF_ATQT, ad->atq_next_slot);
  avf_reg_flush (ad);

  if (timeout > 0)
    {
      f64 suspend_time = timeout / 62;
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

  log_debug (dev, "arq desc acquired in slot %u\n  %U", ad->arq_next_slot,
	     format_avf_aq_desc, d);
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
