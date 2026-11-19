/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/sfp.h>
#include <vppinfra/format_table.h>

u8 *
format_vnet_dev_rv (u8 *s, va_list *args)
{
  vnet_dev_rv_t rv = va_arg (*args, vnet_dev_rv_t);
  u32 index = -rv;

  char *strings[] = { [0] = "OK",
#define _(n, d) [-VNET_DEV_ERR_##n] = d,
		      foreach_vnet_dev_rv_type
#undef _
  };

  if (index >= ARRAY_LEN (strings))
    return format (s, "unknown return value (%d)", rv);
  return format (s, "%s", strings[index]);
}

typedef struct
{
  u8 *s;
  char *fmt;
  va_list *va;
} vnet_dev_format_in_process_args_t;

static vnet_dev_rv_t
vnet_dev_format_in_process_op (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  vnet_dev_format_in_process_args_t *fa = p;
  fa->s = va_format (fa->s, fa->fmt, fa->va);
  return VNET_DEV_OK;
}

/* bus and driver format functions may access the hardware */
u8 *
vnet_dev_format_in_process (u8 *s, vnet_dev_t *dev, char *fmt, ...)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_format_in_process_args_t fa = { .s = s, .fmt = fmt };
  vnet_dev_rv_t rv;
  va_list va;

  if (!vlib_in_process_context (vm))
    return format (s, "not available outside of process context");

  va_start (va, fmt);
  fa.va = &va;
  rv = vnet_dev_process_call_op_with_ptr (vm, dev, vnet_dev_format_in_process_op, &fa);
  va_end (va);

  if (rv != VNET_DEV_OK)
    return format (fa.s, "not available: %U", format_vnet_dev_rv, rv);

  return fa.s;
}

typedef struct
{
  styled_text_t *st;
  styled_format_fn_t *fn;
  va_list *va;
} vnet_dev_styled_format_in_process_args_t;

static vnet_dev_rv_t
vnet_dev_styled_format_in_process_op (vlib_main_t *vm, vnet_dev_t *dev, void *p)
{
  vnet_dev_styled_format_in_process_args_t *fa = p;
  fa->fn (fa->st, fa->va);
  return VNET_DEV_OK;
}

/* calls the styled function in the device process, va are its arguments */
static void
vnet_dev_styled_add_in_process (styled_text_t *st, vnet_dev_t *dev, styled_format_fn_t *fn,
				va_list *va)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_styled_format_in_process_args_t fa = { .st = st, .fn = fn, .va = va };
  vnet_dev_rv_t rv;

  if (!vlib_in_process_context (vm))
    {
      styled_text_add (st, "not available outside of process context");
      return;
    }

  rv = vnet_dev_process_call_op_with_ptr (vm, dev, vnet_dev_styled_format_in_process_op, &fa);
  if (rv != VNET_DEV_OK)
    styled_text_add (st, "not available: %U", format_vnet_dev_rv, rv);
}

static void
vnet_dev_styled_add_device_info (styled_text_t *st, vnet_dev_t *dev, styled_format_fn_t *fn, ...)
{
  va_list va;

  va_start (va, fn);
  vnet_dev_styled_add_in_process (st, dev, fn, &va);
  va_end (va);
}

static styled_text_t
vnet_dev_styled_text (vnet_dev_format_args_t *a)
{
  styled_text_t st = { .width = a->width };

  if (a->plain_text)
    st.output = ST_O_PLAIN;

  return st;
}

/*
 * The same as vnet_dev_format_in_process () for a styled function of a bus or a
 * driver, the arguments after fn are the ones the function gets.
 */
u8 *
vnet_dev_styled_format_in_process (u8 *s, vnet_dev_format_args_t *a, vnet_dev_t *dev,
				   styled_format_fn_t *fn, ...)
{
  styled_text_t st = vnet_dev_styled_text (a);
  va_list va;

  va_start (va, fn);
  vnet_dev_styled_add_in_process (&st, dev, fn, &va);
  va_end (va);

  s = format (s, "%U", format_styled_text, &st);
  styled_text_free (&st);

  return s;
}

static void
vnet_dev_styled_new_line (styled_text_t *st)
{
  if (vec_len (st->string))
    styled_text_add (st, "\n");
}

/* appends the text of st to the output which starts at s[start], and empties st */
static u8 *
vnet_dev_styled_flush (u8 *s, u32 start, u32 indent, styled_text_t *st)
{
  styled_text_t empty = {
    .profile = st->profile,
    .output = st->output,
    .width = st->width,
  };

  if (vec_len (st->string) == 0)
    return s;

  if (vec_len (s) > start)
    s = format_newline (s, indent);

  s = format (s, "%U", format_styled_text, st);
  styled_text_free (st);
  *st = empty;

  return s;
}

/* a title on a line of its own, for output which is appended below it */
static u8 *
vnet_dev_styled_block (u8 *s, u32 start, u32 indent, styled_text_t *st, char *title)
{
  vnet_dev_styled_new_line (st);
  styled_text_add (st, "%s:", title);
  s = vnet_dev_styled_flush (s, start, indent, st);

  return format_newline (s, indent + 2);
}

/* %U with vnet_dev_format_args_t *, a format string and its arguments */
u8 *
format_vnet_dev_value (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  char *fmt = va_arg (*args, char *);
  styled_text_t st = vnet_dev_styled_text (a);
  u8 *value = va_format (0, fmt, args);

  styled_text_add_role (&st, ST_R_VALUE, "%v", value);
  s = format (s, "%U", format_styled_text, &st);
  styled_text_free (&st);
  vec_free (value);

  return s;
}

u8 *
format_vnet_dev_addr (u8 *s, va_list *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_bus_t *bus;

  if (dev == 0)
    return 0;

  bus = pool_elt_at_index (dm->buses, dev->bus_index);
  s = format (s, "%U", bus->ops.format_device_addr, dev);

  return s;
}

u8 *
format_vnet_dev_interface_name (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  vnet_dev_instance_t *di = vnet_dev_get_dev_instance (i);
  vnet_dev_port_interface_t *si;
  vnet_dev_port_t *p = di->port;

  if (di->is_primary_if)
    return format (s, "%s", p->interfaces->primary_interface.name);

  si = vnet_dev_port_get_sec_if_by_index (p, di->sec_if_index);
  return format (s, "%s", si->name);
}

u8 *
format_vnet_dev_port_primary_intf_name (u8 *s, va_list *args)
{
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);

  if (port == 0 || port->interfaces == 0)
    return format (s, "(none)");

  u8 *name = (u8 *) port->interfaces->primary_interface.name;
  if (name[0] == 0)
    return format (s, "(unnamed)");

  return format (s, "%s", name);
}

u8 *
format_vnet_dev_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, dev->driver_index);
  vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, dev->bus_index);
  styled_text_t st = vnet_dev_styled_text (a);
  u32 indent = format_get_indent (s), start = vec_len (s);

  styled_text_add_marked (&st, ST_R_VALUE, "Driver is '%{%s%}', bus is '%{%s%}'",
			  dr->registration->name, bus->registration->name);

  if (dev->description)
    {
      styled_text_add_marked (&st, ST_R_VALUE, ", description is '%{%v%}'", dev->description);
    }

  if (bus->ops.styled_format_device_info)
    {
      styled_text_add (&st, "\n");
      vnet_dev_styled_add_device_info (&st, dev, bus->ops.styled_format_device_info, a, dev);
    }
  else if (bus->ops.format_device_info)
    {
      u8 *t = vnet_dev_format_in_process (0, dev, "%U", bus->ops.format_device_info, a, dev);

      styled_text_add (&st, "\n%v", t);
      vec_free (t);
    }

  styled_text_add_marked (&st, ST_R_VALUE, "\nAssigned process node is '%{%U%}'",
			  format_vlib_node_name, vm, dev->process_node_index);

  if (dev->args)
    {
      vnet_dev_styled_new_line (&st);
      styled_text_add (&st, "Device Specific Arguments:\n  %T", styled_format_clib_args, dev->args);
    }

  if (a->debug && vec_len (dev->dma_allocs))
    {
      table_t t = {};
      vnet_dev_dma_mem_alloc_t *alloc;
      u32 row = 0;

      table_add_hdr_row (&t, 5, "Virtual Addr", "DMA Addr", "Size", "Alignment", "Description");
      table_set_cell_align (&t, -1, 4, TTAA_LEFT);
      vec_foreach (alloc, dev->dma_allocs)
	{
	  if (alloc->va == 0)
	    continue;
	  table_format_cell (&t, row, 0, "%p", alloc->va);
	  table_format_cell (&t, row, 1, "0x%lx", alloc->pa);
	  table_format_cell (&t, row, 2, "%u", alloc->size);
	  table_format_cell (&t, row, 3, "%u", alloc->align);
	  table_format_cell (&t, row, 4, "%v", alloc->description);
	  table_set_cell_align (&t, row, 4, TTAA_LEFT);
	  row++;
	}

      if (row)
	{
	  vnet_dev_styled_new_line (&st);
	  styled_text_add (&st, "DMA Memory Allocations:\n  %T", format_styled_table, &t);
	}

      table_free (&t);
    }

  if (dev->ops.styled_format_info || dev->ops.format_info)
    {
      s = vnet_dev_styled_block (s, start, indent, &st, "Device Specific Info");

      if (dev->ops.styled_format_info)
	s = vnet_dev_styled_format_in_process (s, a, dev, dev->ops.styled_format_info, a, dev);
      else
	s = vnet_dev_format_in_process (s, dev, "%U", dev->ops.format_info, a, dev);
    }

  s = vnet_dev_styled_flush (s, start, indent, &st);
  styled_text_free (&st);

  return s;
}

u8 *
format_vnet_dev_hw_addr (u8 *s, va_list *args)
{
  vnet_dev_hw_addr_t *addr = va_arg (*args, vnet_dev_hw_addr_t *);
  return format (s, "%U", format_ethernet_address, addr->eth_mac);
}

u8 *
format_vnet_dev_port_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  styled_text_t st = vnet_dev_styled_text (a);
  u32 indent = format_get_indent (s), start = vec_len (s);

  styled_text_add_marked (
    &st, ST_R_VALUE,
    "Hardware Address is %{%U%}, %{%u%} RX queues (max %u), %{%u%} TX queues (max "
    "%u)\nLink state is ",
    format_vnet_dev_hw_addr, &port->primary_hw_addr, pool_elts (port->rx_queues),
    port->attr.max_rx_queues, pool_elts (port->tx_queues), port->attr.max_tx_queues);
  styled_text_add_marked (&st, ST_R_VALUE, "%{%s%}, speed is %{%U%}", port->link_up ? "up" : "down",
			  format_vnet_hw_interface_link_speed, port->speed);

  if (pool_elts (port->secondary_hw_addr))
    {
      vnet_dev_hw_addr_t *addr;
      u32 i = 0;

      styled_text_add (&st, "\nSecondary Hardware Address%s:",
		       pool_elts (port->secondary_hw_addr) > 1 ? "es are" : " is");
      pool_foreach (addr, port->secondary_hw_addr)
	{
	  if (i++ % 6 == 0)
	    styled_text_add (&st, "\n ");

	  styled_text_add_marked (&st, ST_R_VALUE, " %{%U%}", format_vnet_dev_hw_addr, addr);
	}
    }

  if (port->rss_config.set_key)
    {
      styled_text_add_marked (&st, ST_R_VALUE, "\nRSS Key is %{%U%}", format_hex_bytes_no_wrap,
			      port->rss_config.key, port->rss_config.key_len);
    }

  if (port->rss_config.set_lut)
    {
      table_t table = {};

      for (u32 row = 0; row * 16 < port->rss_config.lut_len; row++)
	for (u32 column = 0; column < 16 && row * 16 + column < port->rss_config.lut_len; column++)
	  table_format_cell (&table, row, column, "%u", port->rss_config.lut[row * 16 + column]);
      vnet_dev_styled_new_line (&st);
      styled_text_add (&st, "RSS LUT:\n  %T", format_styled_table, &table);
      table_free (&table);
    }

  vnet_dev_styled_new_line (&st);
  styled_text_add_marked (&st, ST_R_VALUE, "Max RX frame size is %{%u%} (max supported %u)",
			  port->max_rx_frame_size, port->attr.max_supported_rx_frame_size);
  styled_text_add_marked (&st, ST_R_VALUE, "\nCaps: %{%U%}", format_vnet_dev_port_caps,
			  &port->attr.caps);
  styled_text_add_marked (&st, ST_R_VALUE, "\nRX Offloads: %{%U%}",
			  format_vnet_dev_port_rx_offloads, &port->attr.rx_offloads);
  styled_text_add_marked (&st, ST_R_VALUE, "\nTX Offloads: %{%U%}",
			  format_vnet_dev_port_tx_offloads, &port->attr.tx_offloads);

  if (port->port_ops.styled_format_status || port->port_ops.format_status)
    {
      s = vnet_dev_styled_block (s, start, indent, &st, "Device Specific Port Status");

      if (port->port_ops.styled_format_status)
	s = vnet_dev_styled_format_in_process (s, a, port->dev, port->port_ops.styled_format_status,
					       a, port);
      else
	s = vnet_dev_format_in_process (s, port->dev, "%U", port->port_ops.format_status, a, port);
    }

  if (port->port_ops.get_module_eeprom)
    {
      vnet_interface_eeprom_t eeprom = {};
      vnet_dev_rv_t rv = vnet_dev_port_get_module_eeprom (vm, port, &eeprom);

      if (rv == VNET_DEV_OK)
	{
	  vnet_dev_styled_new_line (&st);
	  styled_text_add (&st, "Module Base Information:\n  %T", styled_format_sfp_eeprom_module,
			   &eeprom, /* is_terse */ 0);
	}
      else
	{
	  vnet_dev_styled_new_line (&st);
	  styled_text_add_marked (&st, ST_R_VALUE, "Transceiver not present or unreadable: %{%U%}",
				  format_vnet_dev_rv, rv);
	}
    }

  if (port->args)
    {
      vnet_dev_styled_new_line (&st);
      styled_text_add (&st, "Device Specific Port Arguments:\n  %T", styled_format_clib_args,
		       port->args);
    }

  vnet_dev_styled_new_line (&st);
  styled_text_add (&st, "Interface ");

  if (port->interfaces)
    {
      styled_text_add_marked (
	&st, ST_R_VALUE, "assigned, primary interface name is '%{%U%}', RX node is '%{%U%}'",
	format_vnet_sw_if_index_name, vnm, port->interfaces->primary_interface.sw_if_index,
	format_vlib_node_name, vm, vnet_dev_get_port_rx_node_index (port));
      pool_foreach_pointer (sif, port->interfaces->secondary_interfaces)
	{
	  vnet_dev_styled_new_line (&st);
	  styled_text_add_marked (&st, ST_R_VALUE, "Secondary interface '%{%U%}'",
				  format_vnet_sw_if_index_name, vnm, sif->sw_if_index);

	  if (sif->args)
	    {
	      vnet_dev_styled_new_line (&st);
	      styled_text_add (&st, "Secondary Interface Arguments:\n  %T", styled_format_clib_args,
			       sif->args);
	    }
	}
    }
  else
    styled_text_add (&st, "not assigned");

  s = vnet_dev_styled_flush (s, start, indent, &st);
  styled_text_free (&st);

  return s;
}

u8 *
format_vnet_dev_rx_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  styled_text_t st = vnet_dev_styled_text (a);
  u32 indent = format_get_indent (s), start = vec_len (s);

  styled_text_add_marked (&st, ST_R_VALUE, "Size is %{%u%}, buffer pool index is %{%u%}", rxq->size,
			  vnet_dev_get_rx_queue_buffer_pool_index (rxq));
  styled_text_add_marked (
    &st, ST_R_VALUE, "\nPolling thread is %{%u%}, %{%s%}, %{%s%}, %{%s%} mode",
    rxq->rx_thread_index, rxq->enabled ? "enabled" : "disabled",
    rxq->started ? "started" : "not-started", rxq->interrupt_mode ? "interrupt" : "polling");
  s = vnet_dev_styled_flush (s, start, indent, &st);
  styled_text_free (&st);

  if (rxq->port->rx_queue_ops.styled_format_info)
    {
      s = format_newline (s, indent);
      s = vnet_dev_styled_format_in_process (s, a, rxq->port->dev,
					     rxq->port->rx_queue_ops.styled_format_info, a, rxq);
    }
  else if (rxq->port->rx_queue_ops.format_info)
    {
      s = format_newline (s, indent);
      s = vnet_dev_format_in_process (s, rxq->port->dev, "%U", rxq->port->rx_queue_ops.format_info,
				      a, rxq);
    }

  return s;
}

u8 *
format_vnet_dev_tx_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  styled_text_t st = vnet_dev_styled_text (a);
  u32 indent = format_get_indent (s), start = vec_len (s);
  u32 n;

  styled_text_add_marked (&st, ST_R_VALUE, "Size is %{%u%}\n", txq->size);
  n = clib_bitmap_count_set_bits (txq->assigned_threads);
  if (n == 0)
    styled_text_add (&st, "Not used by any thread");
  else
    {
      styled_text_add_marked (&st, ST_R_VALUE, "Used by thread%s %{%U%}", n > 1 ? "s" : "",
			      format_bitmap_list, txq->assigned_threads);
    }
  s = vnet_dev_styled_flush (s, start, indent, &st);
  styled_text_free (&st);

  if (txq->port->tx_queue_ops.styled_format_info)
    {
      s = format_newline (s, indent);
      s = vnet_dev_styled_format_in_process (s, a, txq->port->dev,
					     txq->port->tx_queue_ops.styled_format_info, a, txq);
    }
  else if (txq->port->tx_queue_ops.format_info)
    {
      s = format_newline (s, indent);
      s = vnet_dev_format_in_process (s, txq->port->dev, "%U", txq->port->tx_queue_ops.format_info,
				      a, txq);
    }

  return s;
}

u8 *
format_vnet_dev_interface_info (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  vnet_dev_format_args_t fa = { .plain_text = vlib_unix_cli_plain_text_only () }, *a = &fa;
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (i);
  vnet_dev_t *dev = port->dev;
  u32 indent = format_get_indent (s);

  s = format (s, "Device:");
  s = format (s, "\n%U%U", format_white_space, indent + 2, format_vnet_dev_info, a, dev);

  s = format (s, "\n%UPort %U:", format_white_space, indent, format_vnet_dev_value, a, "%u",
	      port->port_id);
  s = format (s, "\n%U%U", format_white_space, indent + 2, format_vnet_dev_port_info, a, port);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      s = format (s, "\n%URX queue %U:", format_white_space, indent + 2, format_vnet_dev_value, a,
		  "%u", q->queue_id);
      s = format (s, "\n%U%U", format_white_space, indent + 4, format_vnet_dev_rx_queue_info, a, q);
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      s = format (s, "\n%UTX queue %U:", format_white_space, indent + 2, format_vnet_dev_value, a,
		  "%u", q->queue_id);
      s = format (s, "\n%U%U", format_white_space, indent + 4,
		  format_vnet_dev_tx_queue_info, a, q);
    }
  return s;
}

static u64
unformat_flags (unformat_input_t *input, char *names[], u64 val[], u32 n_flags)
{
  u64 rv = 0;
  uword c = 0;
  u8 *s = 0;

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      switch (c)
	{
	case 'a' ... 'z':
	  c -= 'a' - 'A';
	case '0' ... '9':
	case 'A' ... 'Z':
	  vec_add1 (s, c);
	  break;
	case '-':
	  vec_add1 (s, '_');
	  break;
	case ',':
	  vec_add1 (s, 0);
	  break;
	default:
	  goto end_of_string;
	}
    }
end_of_string:

  if (s == 0)
    return 0;

  vec_add1 (s, 0);

  for (u8 *p = s, *end = vec_end (s); p < end; p += strlen ((char *) p) + 1)
    {
      for (c = 0; c < n_flags; c++)
	if (strcmp (names[c], (char *) p) == 0)
	  {
	    rv |= val[c];
	    break;
	  }
      if (c == n_flags)
	goto done;
    }

done:
  vec_free (s);
  return rv;
}

uword
unformat_vnet_dev_flags (unformat_input_t *input, va_list *args)
{
  vnet_dev_flags_t *fp = va_arg (*args, vnet_dev_flags_t *);
  u64 val;

  char *names[] = {
#define _(b, n, d) #n,
    foreach_vnet_dev_flag
#undef _
  };
  u64 vals[] = {
#define _(b, n, d) 1ull << (b)
    foreach_vnet_dev_flag
#undef _
  };

  val = unformat_flags (input, names, vals, ARRAY_LEN (names));

  if (!val)
    return 0;

  fp->n = val;
  return 1;
}

uword
unformat_vnet_dev_port_flags (unformat_input_t *input, va_list *args)
{
  vnet_dev_port_flags_t *fp = va_arg (*args, vnet_dev_port_flags_t *);
  u64 val;

  char *flag_names[] = {
#define _(b, n, d) #n,
    foreach_vnet_dev_port_flag
#undef _
  };
  u64 flag_values[] = {
#define _(b, n, d) 1ull << (b),
    foreach_vnet_dev_port_flag
#undef _
  };

  val =
    unformat_flags (input, flag_names, flag_values, ARRAY_LEN (flag_names));

  if (!val)
    return 0;

  fp->n = val;
  return 1;
}

uword
unformat_vnet_dev_rx_queue_assignment (unformat_input_t *input, va_list *args)
{
  vnet_dev_rx_queue_assignment_t *a = va_arg (*args, vnet_dev_rx_queue_assignment_t *);

  if (unformat (input, "round-robin"))
    *a = VNET_DEV_RX_QUEUE_ASSIGNMENT_ROUND_ROBIN;
  else if (unformat (input, "queue-per-thread"))
    *a = VNET_DEV_RX_QUEUE_ASSIGNMENT_QUEUE_PER_THREAD;
  else if (unformat (input, "main-thread-only"))
    *a = VNET_DEV_RX_QUEUE_ASSIGNMENT_MAIN_THREAD_ONLY;
  else
    return 0;

  return 1;
}

static u8 *
format_flags (u8 *s, u64 val, char *flag_names[], u64 flag_values[],
	      u32 n_flags)
{
  u32 n = 0;
  for (int i = 0; i < n_flags; i++)
    {
      if ((val & flag_values[i]) == 0)
	continue;

      if (n++)
	vec_add1 (s, ' ');

      for (char *c = flag_names[i]; c[0] != 0; c++)
	{
	  switch (c[0])
	    {
	    case 'A' ... 'Z':
	      vec_add1 (s, c[0] + 'a' - 'A');
	      break;
	    case '_':
	      vec_add1 (s, '-');
	      break;
	    default:
	      vec_add1 (s, c[0]);
	    }
	}
    }

  return s;
}

u8 *
format_vnet_dev_flags (u8 *s, va_list *args)
{
  vnet_dev_flags_t *fp = va_arg (*args, vnet_dev_flags_t *);
  char *flag_names[] = {
#define _(b, n, d) #n,
    foreach_vnet_dev_flag
#undef _
  };
  u64 flag_values[] = {
#define _(b, n, d) 1ull << (b)
    foreach_vnet_dev_flag
#undef _
  };

  return format_flags (s, fp->n, flag_names, flag_values,
		       ARRAY_LEN (flag_names));
}

u8 *
format_vnet_dev_port_flags (u8 *s, va_list *args)
{
  vnet_dev_port_flags_t *fp = va_arg (*args, vnet_dev_port_flags_t *);
  char *flag_names[] = {
#define _(b, n, d) #n,
    foreach_vnet_dev_port_flag
#undef _
  };
  u64 flag_values[] = {
#define _(b, n, d) 1ull << (b),
    foreach_vnet_dev_port_flag
#undef _
  };

  return format_flags (s, fp->n, flag_names, flag_values,
		       ARRAY_LEN (flag_names));
}

u8 *
format_vnet_dev_log (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  char *func = va_arg (*args, char *);

  if (dev)
    s = format (s, "%U", format_vnet_dev_addr, dev);
  if (dev && func)
    vec_add1 (s, ' ');
  if (func)
    s = format (s, "%s", func);
  vec_add1 (s, ':');
  vec_add1 (s, ' ');
  return s;
}

u8 *
format_vnet_dev_port_caps (u8 *s, va_list *args)
{
  vnet_dev_port_caps_t *c = va_arg (*args, vnet_dev_port_caps_t *);
  u32 line = 0;

  if (c->as_number == 0)
    return s;

#define _(n)                                                                  \
  if (c->n)                                                                   \
    {                                                                         \
      if (line++)                                                             \
	vec_add1 (s, ' ');                                                    \
      for (char *str = #n; *str; str++)                                       \
	vec_add1 (s, *str == '_' ? '-' : *str);                               \
    }
  foreach_vnet_dev_port_caps;
#undef _

  return s;
}

u8 *
format_vnet_dev_port_rx_offloads (u8 *s, va_list *args)
{
  vnet_dev_port_rx_offloads_t *c =
    va_arg (*args, vnet_dev_port_rx_offloads_t *);
  u32 line = 0;

  if (c->as_number == 0)
    return s;

#define _(n)                                                                  \
  if (c->n)                                                                   \
    {                                                                         \
      if (line++)                                                             \
	vec_add1 (s, ' ');                                                    \
      for (char *str = #n; *str; str++)                                       \
	vec_add1 (s, *str == '_' ? '-' : *str);                               \
    }
  foreach_vnet_dev_port_rx_offloads;
#undef _

  return s;
}

u8 *
format_vnet_dev_port_tx_offloads (u8 *s, va_list *args)
{
  vnet_dev_port_tx_offloads_t *c =
    va_arg (*args, vnet_dev_port_tx_offloads_t *);
  u32 line = 0;

  if (c->as_number == 0)
    return s;

#define _(n)                                                                  \
  if (c->n)                                                                   \
    {                                                                         \
      if (line++)                                                             \
	vec_add1 (s, ' ');                                                    \
      for (char *str = #n; *str; str++)                                       \
	vec_add1 (s, *str == '_' ? '-' : *str);                               \
    }
  foreach_vnet_dev_port_tx_offloads;
#undef _

  return s;
}

u8 *
format_vnet_dev_flow (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 flow_index = va_arg (*args, u32);
  uword private_data = va_arg (*args, uword);
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (dev_instance);

  if (port->port_ops.styled_format_flow)
    {
      vnet_dev_format_args_t a = { .plain_text = vlib_unix_cli_plain_text_only () };

      s = vnet_dev_styled_format_in_process (s, &a, port->dev, port->port_ops.styled_format_flow,
					     port, flow_index, private_data);
    }
  else if (port->port_ops.format_flow)
    s = vnet_dev_format_in_process (s, port->dev, "%U", port->port_ops.format_flow, port,
				    flow_index, private_data);

  return s;
}

uword
unformat_vnet_dev_rss_key (unformat_input_t *input, va_list *args)
{
  vnet_dev_rss_config_t *config = va_arg (*args, vnet_dev_rss_config_t *);
  u8 *v;
  u32 len;

  if (!(unformat_user (input, unformat_hex_string, &v)))
    return 0;

  len = vec_len (v);
  if (len > sizeof (config->key))
    {
      vec_free (v);
      return 0;
    }

  clib_memcpy (config->key, v, len);
  config->key_len = len;
  config->set_key = 1;
  vec_free (v);
  return 1;
}

uword
unformat_vnet_dev_rss_lut (unformat_input_t *input, va_list *args)
{
  vnet_dev_rss_config_t *config = va_arg (*args, vnet_dev_rss_config_t *);
  u32 entry;

  if (!unformat (input, "%u", &entry))
    return 0;

  while (1)
    {
      if (entry > CLIB_U16_MAX || config->lut_len == ARRAY_LEN (config->lut))
	return 0;
      config->lut[config->lut_len++] = entry;
      if (!unformat (input, ",%u", &entry))
	break;
    }
  config->set_lut = 1;
  return 1;
}
uword
unformat_vnet_dev_vector (unformat_input_t *in, va_list *args)
{
  vnet_dev_t *dev, ***devs = va_arg (*args, vnet_dev_t ***);
  u8 *s = 0;
  uword rv = 0;

  while (unformat (in, "%s", &s))
    {
      dev = vnet_dev_by_id ((char *) s);
      if (!dev)
	break;

      vec_add1 (*devs, dev);
      vec_reset_length (s);
      rv++;
    }

  vec_free (s);
  return rv;
}
