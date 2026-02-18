/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>

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

  u32 indent = format_get_indent (s);
  s = format (s, "Driver is '%s', bus is '%s'", dr->registration->name,
	      bus->registration->name);

  if (dev->description)
    s = format (s, ", description is '%v'", dev->description);

  if (bus->ops.format_device_info)
    s = format (s, "\n%U%U", format_white_space, indent,
		bus->ops.format_device_info, a, dev);

  s = format (s, "\n%UAssigned process node is '%U'", format_white_space,
	      indent, format_vlib_node_name, vm, dev->process_node_index);
  if (dev->args)
    s = format (s, "\n%UDevice Specific Arguments:\n%U%U", format_white_space,
		indent, format_white_space, indent + 2, format_clib_args,
		dev->args);
  if (dev->ops.format_info)
    s =
      format (s, "\n%UDevice Specific Info:\n%U%U", format_white_space, indent,
	      format_white_space, indent + 2, dev->ops.format_info, a, dev);
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

  u32 indent = format_get_indent (s);

  s = format (s, "Hardware Address is %U", format_vnet_dev_hw_addr,
	      &port->primary_hw_addr);
  s = format (s, ", %u RX queues (max %u), %u TX queues (max %u)",
	      pool_elts (port->rx_queues), port->attr.max_rx_queues,
	      pool_elts (port->tx_queues), port->attr.max_tx_queues);
  if (pool_elts (port->secondary_hw_addr))
    {
      u32 i = 0;
      vnet_dev_hw_addr_t *a;
      s = format (s, "\n%USecondary Hardware Address%s:", format_white_space,
		  indent,
		  pool_elts (port->secondary_hw_addr) > 1 ? "es are" : " is");
      pool_foreach (a, port->secondary_hw_addr)
	{
	  if (i++ % 6 == 0)
	    s = format (s, "\n%U", format_white_space, indent + 1);
	  s = format (s, " %U", format_vnet_dev_hw_addr, a);
	}
    }
  if (port->rss_config && port->rss_config->key.length)
    s = format (s, "\n%URSS Key is %U", format_white_space, indent, format_hex_bytes_no_wrap,
		port->rss_config->key.key, port->rss_config->key.length);
  s = format (s, "\n%UMax RX frame size is %u (max supported %u)",
	      format_white_space, indent, port->max_rx_frame_size,
	      port->attr.max_supported_rx_frame_size);
  s = format (s, "\n%UCaps: %U", format_white_space, indent,
	      format_vnet_dev_port_caps, &port->attr.caps);
  s = format (s, "\n%URX Offloads: %U", format_white_space, indent,
	      format_vnet_dev_port_rx_offloads, &port->attr.rx_offloads);
  s = format (s, "\n%UTX Offloads: %U", format_white_space, indent,
	      format_vnet_dev_port_tx_offloads, &port->attr.tx_offloads);
  if (port->port_ops.format_status)
    s = format (s, "\n%UDevice Specific Port Status:\n%U%U",
		format_white_space, indent, format_white_space, indent + 2,
		port->port_ops.format_status, a, port);
  if (port->args)
    s = format (s, "\n%UDevice Specific Port Arguments:\n%U%U",
		format_white_space, indent, format_white_space, indent + 2,
		format_clib_args, port->args);

  s = format (s, "\n%UInterface ", format_white_space, indent);
  if (port->interfaces)
    {
      s = format (
	s, "assigned, primary interface name is '%U', RX node is '%U'",
	format_vnet_sw_if_index_name, vnm,
	port->interfaces->primary_interface.sw_if_index, format_vlib_node_name,
	vm, vnet_dev_get_port_rx_node_index (port));
      pool_foreach_pointer (sif, port->interfaces->secondary_interfaces)
	{
	  s = format (s, "\n%USecondary interface '%U'", format_white_space,
		      indent, format_vnet_sw_if_index_name, vnm,
		      sif->sw_if_index);
	  if (sif->args)
	    s = format (s, "\n%U args '%U", format_white_space, indent,
			format_clib_args, sif->args);
	}
    }
  else
    s = format (s, "not assigned");
  return s;
}

u8 *
format_vnet_dev_rx_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "Size is %u, buffer pool index is %u", rxq->size,
	      vnet_dev_get_rx_queue_buffer_pool_index (rxq));
  s = format (s, "\n%UPolling thread is %u, %sabled, %sstarted, %s mode",
	      format_white_space, indent, rxq->rx_thread_index,
	      rxq->enabled ? "en" : "dis", rxq->started ? "" : "not-",
	      rxq->interrupt_mode ? "interrupt" : "polling");
  if (rxq->port->rx_queue_ops.format_info)
    s = format (s, "\n%U%U", format_white_space, indent,
		rxq->port->rx_queue_ops.format_info, a, rxq);

  return s;
}

u8 *
format_vnet_dev_tx_queue_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  u32 indent = format_get_indent (s);
  u32 n;

  s = format (s, "Size is %u", txq->size);
  s = format (s, "\n%U", format_white_space, indent);
  n = clib_bitmap_count_set_bits (txq->assigned_threads);
  if (n == 0)
    s = format (s, "Not used by any thread");
  else
    s = format (s, "Used by thread%s %U", n > 1 ? "s" : "", format_bitmap_list,
		txq->assigned_threads);
  if (txq->port->tx_queue_ops.format_info)
    s = format (s, "\n%U%U", format_white_space, indent,
		txq->port->tx_queue_ops.format_info, a, txq);

  return s;
}

u8 *
format_vnet_dev_interface_info (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  vnet_dev_format_args_t fa = {}, *a = &fa;
  vnet_dev_port_t *port = vnet_dev_get_port_from_dev_instance (i);
  vnet_dev_t *dev = port->dev;
  u32 indent = format_get_indent (s);

  s = format (s, "Device:");
  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_vnet_dev_info, a, dev);

  s = format (s, "\n%UPort %u:", format_white_space, indent, port->port_id);
  s = format (s, "\n%U%U", format_white_space, indent + 2,
	      format_vnet_dev_port_info, a, port);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      s = format (s, "\n%URX queue %u:", format_white_space, indent + 2,
		  q->queue_id);
      s = format (s, "\n%U%U", format_white_space, indent + 4,
		  format_vnet_dev_rx_queue_info, a, q);
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      s = format (s, "\n%UTX queue %u:", format_white_space, indent + 2,
		  q->queue_id);
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

  if (port->port_ops.format_flow)
    s = format (s, "%U", port->port_ops.format_flow, port, flow_index,
		private_data);

  return s;
}

uword
unformat_vnet_dev_rss_key (unformat_input_t *input, va_list *args)
{
  vnet_dev_rss_key_t *k = va_arg (*args, vnet_dev_rss_key_t *);
  u8 *v;
  u32 len;

  if (!(unformat_user (input, unformat_hex_string, &v)))
    return 0;

  len = vec_len (v);
  if (len > sizeof (k->key))
    {
      vec_free (v);
      return 0;
    }

  clib_memcpy (k->key, v, len);
  k->length = len;
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
