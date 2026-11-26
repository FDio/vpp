/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/flow/flow.h>
#include <vnet/interface/cli_types.h>

uword
unformat_ip_port_and_mask (unformat_input_t * input, va_list * args)
{
  ip_port_and_mask_t *pm = va_arg (*args, ip_port_and_mask_t *);
  u32 port = 0, mask = 0;

  if (unformat (input, "any"))
    ;
  else if (unformat (input, "%u/%u", &port, &mask))
    ;
  else if (unformat (input, "%u/0x%x", &port, &mask))
    ;
  else if (unformat (input, "%u", &port))
    mask = 0xffff;
  else
    return 0;

  if (port > 0xffff || mask > 0xffff)
    return 0;

  pm->port = port;
  pm->mask = mask;
  return 1;
}

u8 *
format_ip_port_and_mask (u8 * s, va_list * args)
{
  ip_port_and_mask_t *pm = va_arg (*args, ip_port_and_mask_t *);

  if (pm->port == 0 && pm->mask == 0)
    return format (s, "any");

  if (pm->mask == 0xffff)
    return format (s, "%u", pm->port);

  return format (s, "%u/0x%x", pm->port, pm->mask);
}

uword
unformat_ip_protocol_and_mask (unformat_input_t * input, va_list * args)
{
  ip_prot_and_mask_t *pm = va_arg (*args, ip_prot_and_mask_t *);
  u32 prot = 0, mask = 0;

  if (unformat (input, "any"))
    ;
  else if (unformat (input, "%U", unformat_ip_protocol, &prot))
    mask = 0xFF;
  else if (unformat (input, "%u", &prot))
    mask = 0xFF;
  else
    return 0;

  if (prot > 0XFF || mask > 0xFF)
    return 0;

  pm->prot = prot;
  pm->mask = mask;
  return 1;
}

u8 *
format_ip_protocol_and_mask (u8 * s, va_list * args)
{
  ip_prot_and_mask_t *pm = va_arg (*args, ip_prot_and_mask_t *);

  if (pm->prot == 0 && pm->mask == 0)
    return format (s, "any");

  return format (s, "%U", format_ip_protocol, pm->prot);
}

u8 *
format_flow_error (u8 * s, va_list * args)
{
  int error = va_arg (*args, int);

  if (error == 0)
    return format (s, "no error");

#define _(v,n,str) if (error == v) return format (s, #str);
  foreach_flow_error;
#undef _

  return format (s, "unknown error (%d)", error);
}

u8 *
format_flow_actions (u8 * s, va_list * args)
{
  u32 actions = va_arg (*args, u32);
  u8 *t = 0;

#define _(a, b, c) if (actions & (1 << a)) \
  t = format (t, "%s%s", t ? " ":"", c);
  foreach_flow_action
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_flow_enabled_hw (u8 * s, va_list * args)
{
  u32 flow_index = va_arg (*args, u32);
  vnet_flow_t *f = vnet_get_flow (flow_index);
  if (f == 0)
    return format (s, "not found");

  vnet_main_t *vnm = vnet_get_main ();
  if (IS_FLOW_ENABLED (f))
    s = format (s, "%U", format_vnet_hw_if_index_name, vnm, f->driver_data.hw_if_index);
  return s;
}

u8 *
format_rss_function (u8 * s, va_list * args)
{
  vnet_rss_function_t func = va_arg (*args, vnet_rss_function_t);

  if (0)
    ;
#undef _
#define _(f, n) \
      else if (func == VNET_RSS_FUNC_##f) \
        return format (s, n);

  foreach_rss_function
#undef _
    return format (s, "unknown");
}

u8 *
format_rss_types (u8 * s, va_list * args)
{
  u64 type = va_arg (*args, u64);

#undef _
#define _(a,b,c)     \
  if (type & (1UL<<a)) \
    s = format (s, "%s ", c);

  foreach_flow_rss_types
#undef _
    return s;
}

static const char *flow_type_strings[] = { 0,
#define _(a,b,c) c,
  foreach_flow_type
#undef _
};

static int
flow_iter_yield (vlib_main_t *vm, f64 *start, int with_barrier)
{
  /* yields for 2 clock ticks every 1 tick to avoid blocking the main thread
   * when dumping huge data structures */
  f64 now = vlib_time_now (vm);
  if (now - *start > 11e-6)
    {
      if (with_barrier)
	vlib_worker_thread_barrier_release (vm);

      vlib_process_suspend (vm, 21e-6);

      if (with_barrier)
	vlib_worker_thread_barrier_sync (vm);

      *start = vlib_time_now (vm);
      return 1;
    }

  return 0;
}

static void
copy_flow (vnet_flow_t *dst, generic_pattern_t *dst_generic, vnet_flow_t *src)
{
  clib_memcpy (dst, src, sizeof (*src));
  if (src->type == VNET_FLOW_TYPE_GENERIC && src->generic_pattern != NULL)
    {
      clib_memcpy (dst_generic, src->generic_pattern, sizeof (*dst_generic));
      dst->generic_pattern = dst_generic;
    }
}

static clib_error_t *
show_one_flow (vlib_main_t *vm, vlib_pool_cache_t *flow_pool, u32 index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_t *f;
  vnet_flow_t snapshot;
  u8 *driver_format = 0;
  generic_pattern_t snapshot_generic;

  /* snapshot under the barrier */
  vlib_worker_thread_barrier_sync (vm);

  if (pool_cache_is_free_index (flow_pool, index))
    {
      vlib_worker_thread_barrier_release (vm);
      return clib_error_return (0, "no such flow");
    }

  f = pool_cache_elt_at_index (flow_pool, index);
  copy_flow (&snapshot, &snapshot_generic, f);

  /* avoid the driver opaque to become stale when we release the barrier, so format here */
  if (IS_FLOW_ENABLED (f))
    {
      hi = vnet_get_hw_interface (vnm, f->driver_data.hw_if_index);
      dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
      if (dev_class->format_flow)
	{
	  driver_format = format (driver_format, "%U", dev_class->format_flow, hi->dev_instance,
				  snapshot.index, snapshot.driver_data.opaque);
	}
    }

  vlib_worker_thread_barrier_release (vm);

  vlib_cli_output (vm, "%-10s: %u", "index", snapshot.index);
  vlib_cli_output (vm, "%-10s: %s", "type", flow_type_strings[snapshot.type]);
  vlib_cli_output (vm, "%-10s: %U", "match", format_flow, &snapshot);

  if (IS_FLOW_ENABLED (&snapshot))
    {
      vlib_cli_output (vm, "interface %U\n", format_vnet_hw_if_index_name, vnm,
		       snapshot.driver_data.hw_if_index);

      if (driver_format)
	vlib_cli_output (vm, "  %v\n", driver_format);
    }

  vec_free (driver_format);
  return 0;
}

static clib_error_t *
show_multiple_flows (vlib_main_t *vm, vlib_pool_cache_t *flow_pool, u32 max)
{
  const u32 batch_size = 1024;
  vnet_flow_t *f;
  vnet_flow_t *snapshot;
  generic_pattern_t *snapshot_generic;
  f64 start;
  u32 batch_index = 0;
  __clib_unused u32 pool_index;
  u32 pool_cap = pool_cache_count_capacity (flow_pool);
  u32 total_free =
    pool_cache_count_global_free (flow_pool) + pool_cache_count_cached_free (flow_pool);
  u32 total = pool_cap > total_free ? pool_cap - total_free : 0;
  u32 n_shown = 0;

  /* snapshots can take few MiB, avoid to put them on the stack */
  snapshot =
    (vnet_flow_t *) clib_mem_alloc_aligned (batch_size * sizeof (*snapshot), CLIB_CACHE_LINE_BYTES);
  snapshot_generic = (generic_pattern_t *) clib_mem_alloc_aligned (
    batch_size * sizeof (*snapshot_generic), CLIB_CACHE_LINE_BYTES);

  vlib_worker_thread_barrier_sync (vm);

  /* start counting when we got the barrier */
  start = vlib_time_now (vm);
  vlib_foreach_pool_cache (f, pool_index, flow_pool, {
    if (n_shown >= max)
      break;

    /* skip pre-allocated/cached entries not yet assigned to a flow */
    if (f->type == VNET_FLOW_TYPE_UNKNOWN)
      continue;

    copy_flow (&snapshot[batch_index], &snapshot_generic[batch_index], f);

    n_shown++;
    batch_index++;

    if (batch_index >= batch_size)
      {
	/* don't hold the barrier while printing the snapshot */
	vlib_worker_thread_barrier_release (vm);

	for (int i = 0; i < batch_index; i++)
	  {
	    flow_iter_yield (vm, &start, 0 /*with_barrier=*/);
	    vlib_cli_output (vm, "%U\n", format_flow, &snapshot[i]);
	  }

	vlib_worker_thread_barrier_sync (vm);

	batch_index = 0;
	continue;
      }

    flow_iter_yield (vm, &start, 1 /*with_barrier=*/);
  });

  vlib_worker_thread_barrier_release (vm);

  /* print any remaining flow */
  for (int i = 0; i < batch_index; i++)
    {
      flow_iter_yield (vm, &start, 0 /*with_barrier=*/);
      vlib_cli_output (vm, "%U\n", format_flow, &snapshot[i]);
    }

  clib_mem_free (snapshot);
  clib_mem_free (snapshot_generic);

  vlib_cli_output (vm, "Displayed %u flows (%u total flows)", n_shown, total);
  if (total > max)
    vlib_cli_output (vm, "Use 'max <N>' to see more flows");

  return 0;
}

static clib_error_t *
show_flow_pool (vlib_main_t *vm, cli_ctx_t *ctx, vlib_pool_cache_t *flow_pool)
{
  u32 index = cli_u64 (ctx, "index", ~0);

  if (index != ~0)
    return show_one_flow (vm, flow_pool, index);

  return show_multiple_flows (vm, flow_pool, cli_u64 (ctx, "max", 20));
}

static const cli_arg_t show_flow_pool_args[] = {
  CLI_OPT_KEYWORD ("index", cli_type_u32, .help = "show one flow"),
  CLI_OPT_KEYWORD ("max", cli_type_u32, .help = "number of flows to show, default 20"),
  {},
};

static clib_error_t *
show_flow_entry (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_flow_main_t *fm = &flow_main;
  return show_flow_pool (vm, ctx, &fm->flows);
}

VLIB_CLI_COMMAND (show_flow_entry_command, static) = {
  .path = "show flow entry",
  .short_help = "Show the flows",
  .args = show_flow_pool_args,
  .handler = show_flow_entry,
  .is_mp_safe = 1,
};

static clib_error_t *
show_flow_ranges (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *r = 0;

  vlib_cli_output (vm, "%8s  %8s  %s", "Start", "Count", "Owner");

  vec_foreach (r, fm->ranges)
    {
      vlib_cli_output (vm, "%8u  %8u  %s", r->start, r->count, r->owner);
    };
  return 0;
}

VLIB_CLI_COMMAND (show_flow_ranges_command, static) = {
  .path = "show flow ranges",
  .short_help = "Show the flow index ranges",
  .handler = show_flow_ranges,
};

static clib_error_t *
show_flow_template (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_flow_main_t *fm = &flow_main;
  return show_flow_pool (vm, ctx, &fm->flow_templates);
}

VLIB_CLI_COMMAND (show_flow_template_command, static) = {
  .path = "show flow template",
  .short_help = "Show the flow templates",
  .args = show_flow_pool_args,
  .handler = show_flow_template,
  .is_mp_safe = 1,
};

static clib_error_t *
show_flow_interface (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;

  hi = vnet_get_hw_interface (vnm, cli_index (ctx, "interface"));
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  if (dev_class->format_flow == 0)
    return clib_error_return (0, "not supported");

  vlib_cli_output (vm, "%U", dev_class->format_flow, hi->dev_instance, ~0, 0);
  return 0;
}

VLIB_CLI_COMMAND (show_flow_interface_command, static) = {
  .path = "show flow interface",
  .short_help = "Show the flow information of an interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface)),
  .handler = show_flow_interface,
};

/* the value of these types is the structure the unformat function fills in */
static u8 *
parse_flow_value (u8 *tok, cli_value_t *v, unformat_function_t *f, u32 size, char *what)
{
  unformat_input_t in;
  u8 *value = 0;
  int ok;

  vec_validate (value, size - 1);
  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%U", f, value) && unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);

  if (!ok)
    {
      vec_free (value);
      return format (0, "'%v' is not %s", tok, what);
    }

  v->str = value;

  return 0;
}

static u8 *
parse_flow_ip4 (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_flow_value (tok, v, unformat_ip4_address_and_mask, sizeof (ip4_address_and_mask_t),
			   "an IPv4 address, address/mask or 'any'");
}

static u8 *
parse_flow_ip6 (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_flow_value (tok, v, unformat_ip6_address_and_mask, sizeof (ip6_address_and_mask_t),
			   "an IPv6 address, address/mask or 'any'");
}

static u8 *
parse_flow_port (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_flow_value (tok, v, unformat_ip_port_and_mask, sizeof (ip_port_and_mask_t),
			   "a port, port/mask or 'any'");
}

static u8 *
parse_flow_protocol (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_flow_value (tok, v, unformat_ip_protocol_and_mask, sizeof (ip_prot_and_mask_t),
			   "an IP protocol or 'any'");
}

static u8 *
parse_flow_ethernet_type (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_flow_value (tok, v, unformat_ethernet_type_host_byte_order, sizeof (u16),
			   "an ethernet type");
}

static u8 *
parse_flow_int (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  i32 value;
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%d", &value) && unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);

  if (!ok)
    return format (0, "'%v' is not a number", tok);

  v->u64 = (u32) value;

  return 0;
}

CLIB_CLI_TYPE (cli_type_flow_ip4, static) = {
  .name = "ip4-address[/mask]",
  .help = "IPv4 address, address/mask or 'any'",
  .owns_str = 1,
  .parse = parse_flow_ip4,
};

CLIB_CLI_TYPE (cli_type_flow_ip6, static) = {
  .name = "ip6-address[/mask]",
  .help = "IPv6 address, address/mask or 'any'",
  .owns_str = 1,
  .parse = parse_flow_ip6,
};

CLIB_CLI_TYPE (cli_type_flow_port, static) = {
  .name = "port[/mask]",
  .help = "port, port/mask or 'any'",
  .owns_str = 1,
  .parse = parse_flow_port,
};

CLIB_CLI_TYPE (cli_type_flow_protocol, static) = {
  .name = "ip-protocol",
  .help = "IP protocol name or number, or 'any'",
  .owns_str = 1,
  .parse = parse_flow_protocol,
};

CLIB_CLI_TYPE (cli_type_flow_ethernet_type, static) = {
  .name = "ethernet-type",
  .help = "ethernet type name or number",
  .owns_str = 1,
  .parse = parse_flow_ethernet_type,
};

CLIB_CLI_TYPE (cli_type_flow_int, static) = {
  .name = "number",
  .help = "signed integer",
  .parse = parse_flow_int,
};

static const cli_choice_t flow_rss_function_choices[] = {
#define _(f, s) { s, 0, VNET_RSS_FUNC_##f },
  foreach_rss_function
#undef _
  {},
};

static const cli_choice_t flow_rss_type_choices[] = {
#define _(a, b, c) { c, 0, a },
  foreach_flow_rss_types
#undef _
  {},
};

/* copies the value of an argument of one of the types above, if it was given */
static int
flow_cli_value (cli_ctx_t *ctx, const char *name, void *dst, u32 size)
{
  cli_value_t *v = cli_get (ctx, name);

  if (v == 0)
    return 0;

  clib_memcpy (dst, v->str, size);

  return 1;
}

/* position of the last of the two arguments on the line, -1 if none of them was given */
static int
flow_cli_position (cli_ctx_t *ctx, const char *a, const char *b)
{
  cli_value_t *va = cli_get (ctx, a);
  cli_value_t *vb = b ? cli_get (ctx, b) : 0;
  int position = -1;

  if (va)
    position = va->tok;

  if (vb)
    position = clib_max (position, (int) vb->tok);

  return position;
}

static clib_error_t *
flow_cli_add (vlib_main_t *vm, cli_ctx_t *ctx, int is_template)
{
  vnet_flow_t flow;
  vnet_main_t *vnm = vnet_get_main ();
  enum
  {
    FLOW_UNKNOWN_CLASS,
    FLOW_ETHERNET_CLASS,
    FLOW_IPV4_CLASS,
    FLOW_IPV6_CLASS,
  } flow_class = FLOW_UNKNOWN_CLASS;

  u32 flow_index = ~0, template_index = ~0;
  clib_error_t *error = 0;
  int rv, position, last = -1;
  u32 teid = cli_u64 (ctx, "teid", 0), session_id = cli_u64 (ctx, "id", 0);
  u32 spi = cli_u64 (ctx, "spi", 0), vni = cli_u64 (ctx, "vni", 0);
  vnet_flow_type_t type = VNET_FLOW_TYPE_UNKNOWN;
  ip4_address_and_mask_t ip4s = {}, in_ip4s = {};
  ip4_address_and_mask_t ip4d = {}, in_ip4d = {};
  ip6_address_and_mask_t ip6s = {}, in_ip6s = {};
  ip6_address_and_mask_t ip6d = {}, in_ip6d = {};
  ip_port_and_mask_t sport = {}, in_sport = {};
  ip_port_and_mask_t dport = {}, in_dport = {};
  ip_prot_and_mask_t protocol = {}, in_proto = {};
  generic_pattern_t generic = {};
  u16 eth_type = 0;
  bool inner_ip4_set = false, inner_ip6_set = false;
  bool tcp_udp_port_set = false, inner_port_set = false;
  bool gtpc_set = cli_flag (ctx, "gtpc");
  bool gtpu_set = cli_flag (ctx, "gtpu");
  bool vni_set = cli_flag (ctx, "vxlan");
  bool l2tpv3oip_set = false;
  bool ipsec_esp_set = false, ipsec_ah_set = false;
  bool generic_spec_set = false, generic_mask_set = false;
  cli_value_t *v, *end;

  clib_memset (&flow, 0, sizeof (vnet_flow_t));
  flow.index = ~0;
  flow.actions = 0;

  if ((v = cli_get (ctx, "spec")))
    {
      if (vec_len (v->str) > sizeof (generic.spec))
	return clib_error_return (0, "generic spec too large, max size of %u",
				  sizeof (generic.spec));
      clib_memcpy (&generic.spec, v->str, vec_len (v->str));
      generic_spec_set = true;
    }

  if ((v = cli_get (ctx, "mask")))
    {
      if (vec_len (v->str) > sizeof (generic.mask))
	return clib_error_return (0, "generic mask too large, max size of %u",
				  sizeof (generic.mask));
      clib_memcpy (&generic.mask, v->str, vec_len (v->str));
      generic_mask_set = true;
    }

  /* the match which is given last on the line decides the class of the flow */
  if (flow_cli_value (ctx, "eth-type", &eth_type, sizeof (eth_type)))
    {
      flow_class = FLOW_ETHERNET_CLASS;
      last = flow_cli_position (ctx, "eth-type", 0);
    }

  flow_cli_value (ctx, "src-ip", &ip4s, sizeof (ip4s));
  flow_cli_value (ctx, "dst-ip", &ip4d, sizeof (ip4d));
  position = flow_cli_position (ctx, "src-ip", "dst-ip");
  if (position > last)
    {
      flow_class = FLOW_IPV4_CLASS;
      last = position;
    }

  flow_cli_value (ctx, "ip6-src-ip", &ip6s, sizeof (ip6s));
  flow_cli_value (ctx, "ip6-dst-ip", &ip6d, sizeof (ip6d));
  position = flow_cli_position (ctx, "ip6-src-ip", "ip6-dst-ip");
  if (position > last)
    flow_class = FLOW_IPV6_CLASS;

  inner_ip4_set |= flow_cli_value (ctx, "in-src-ip", &in_ip4s, sizeof (in_ip4s));
  inner_ip4_set |= flow_cli_value (ctx, "in-dst-ip", &in_ip4d, sizeof (in_ip4d));
  inner_ip6_set |= flow_cli_value (ctx, "in-ip6-src-ip", &in_ip6s, sizeof (in_ip6s));
  inner_ip6_set |= flow_cli_value (ctx, "in-ip6-dst-ip", &in_ip6d, sizeof (in_ip6d));
  tcp_udp_port_set |= flow_cli_value (ctx, "src-port", &sport, sizeof (sport));
  tcp_udp_port_set |= flow_cli_value (ctx, "dst-port", &dport, sizeof (dport));
  inner_port_set |= flow_cli_value (ctx, "in-src-port", &in_sport, sizeof (in_sport));
  inner_port_set |= flow_cli_value (ctx, "in-dst-port", &in_dport, sizeof (in_dport));
  flow_cli_value (ctx, "proto", &protocol, sizeof (protocol));
  flow_cli_value (ctx, "in-proto", &in_proto, sizeof (in_proto));

  if (cli_flag (ctx, "session") && protocol.prot == IP_PROTOCOL_L2TP)
    l2tpv3oip_set = true;

  if (cli_flag (ctx, "spi"))
    {
      if (protocol.prot == IP_PROTOCOL_IPSEC_ESP)
	ipsec_esp_set = true;
      else if (protocol.prot == IP_PROTOCOL_IPSEC_AH)
	ipsec_ah_set = true;
    }

  if ((v = cli_get (ctx, "next-node")))
    {
      flow.redirect_node_index = v->index;
      flow.actions |= VNET_FLOW_ACTION_REDIRECT_TO_NODE;
    }

  if ((v = cli_get (ctx, "mark")))
    {
      flow.mark_flow_id = v->u64;
      flow.actions |= VNET_FLOW_ACTION_MARK;
    }

  if ((v = cli_get (ctx, "buffer-advance")))
    {
      flow.buffer_advance = v->u64;
      flow.actions |= VNET_FLOW_ACTION_BUFFER_ADVANCE;
    }

  if ((v = cli_get (ctx, "redirect-to-queue")))
    {
      flow.redirect_queue = v->u64;
      flow.actions |= VNET_FLOW_ACTION_REDIRECT_TO_QUEUE;
    }

  if (cli_flag (ctx, "drop"))
    flow.actions |= VNET_FLOW_ACTION_DROP;

  if (cli_flag (ctx, "rss"))
    flow.actions |= VNET_FLOW_ACTION_RSS;

  cli_foreach (v, ctx, "function") flow.rss_fun = v->index;

  cli_foreach (v, ctx, "types") flow.rss_types |= 1ULL << v->index;
  cli_foreach (v, ctx, "use") flow.rss_types |= 1ULL << v->index;
  cli_foreach (v, ctx, "and") flow.rss_types |= 1ULL << v->index;

  end = cli_get (ctx, "to");
  cli_foreach (v, ctx, "queues")
  {
    flow.queue_index = v->u64;
    flow.queue_num = end->u64 - v->u64 + 1;
    end = cli_get_next (ctx, end);
  }

  if (flow.actions == 0)
    return clib_error_return (0, "Please specify at least one action");

  /* Adjust the flow type */
  switch (flow_class)
    {
    case FLOW_ETHERNET_CLASS:
      type = VNET_FLOW_TYPE_ETHERNET;
      break;
    case FLOW_IPV4_CLASS:
      if (gtpc_set)
	{
	  type = VNET_FLOW_TYPE_IP4_GTPC;
	  protocol.prot = IP_PROTOCOL_UDP;
	}
      else if (gtpu_set)
	{
	  type = VNET_FLOW_TYPE_IP4_GTPU;
	  protocol.prot = IP_PROTOCOL_UDP;
	}
      else if (vni_set)
	{
	  type = VNET_FLOW_TYPE_IP4_VXLAN;
	  protocol.prot = IP_PROTOCOL_UDP;
	}
      else if (l2tpv3oip_set)
	type = VNET_FLOW_TYPE_IP4_L2TPV3OIP;
      else if (ipsec_esp_set)
	type = VNET_FLOW_TYPE_IP4_IPSEC_ESP;
      else if (ipsec_ah_set)
	type = VNET_FLOW_TYPE_IP4_IPSEC_AH;
      else if (tcp_udp_port_set)
	type = VNET_FLOW_TYPE_IP4_N_TUPLE;
      else if (inner_ip4_set)
	{
	  if (inner_port_set)
	    type = VNET_FLOW_TYPE_IP4_IP4_N_TUPLE;
	  else
	    type = VNET_FLOW_TYPE_IP4_IP4;
	  protocol.prot = IP_PROTOCOL_IP_IN_IP;
	}
      else if (inner_ip6_set)
	{
	  if (inner_port_set)
	    type = VNET_FLOW_TYPE_IP4_IP6_N_TUPLE;
	  else
	    type = VNET_FLOW_TYPE_IP4_IP6;
	  protocol.prot = IP_PROTOCOL_IPV6;
	}
      else
	type = VNET_FLOW_TYPE_IP4;
      break;
    case FLOW_IPV6_CLASS:
      if (tcp_udp_port_set)
	type = VNET_FLOW_TYPE_IP6_N_TUPLE;
      else if (vni_set)
	type = VNET_FLOW_TYPE_IP6_VXLAN;
      else if (inner_ip4_set)
	{
	  if (inner_port_set)
	    type = VNET_FLOW_TYPE_IP6_IP4_N_TUPLE;
	  else
	    type = VNET_FLOW_TYPE_IP6_IP4;
	  protocol.prot = IP_PROTOCOL_IP_IN_IP;
	}
      else if (inner_ip6_set)
	{
	  if (inner_port_set)
	    type = VNET_FLOW_TYPE_IP6_IP6_N_TUPLE;
	  else
	    type = VNET_FLOW_TYPE_IP6_IP6;
	  protocol.prot = IP_PROTOCOL_IPV6;
	}
      else
	type = VNET_FLOW_TYPE_IP6;
      break;

    default:
      if (generic_spec_set && generic_mask_set)
	{
	  type = VNET_FLOW_TYPE_GENERIC;
	  flow.generic_pattern = &generic;
	  break;
	}
      return clib_error_return (0, "Please specify a supported flow type");
    }

      /* Assign specific field values per flow type */
      if (flow_class == FLOW_ETHERNET_CLASS)
	{
	  flow.pattern.ethernet.eth_hdr.type = eth_type;
	}
      else if (flow_class == FLOW_IPV4_CLASS)
	{
	  vnet_flow_ip4_t *ip4_ptr = &flow.pattern.ip4;

	  clib_memcpy (&ip4_ptr->src_addr, &ip4s,
		       sizeof (ip4_address_and_mask_t));
	  clib_memcpy (&ip4_ptr->dst_addr, &ip4d,
		       sizeof (ip4_address_and_mask_t));
	  ip4_ptr->protocol.prot = protocol.prot;

	  /* In this cli, we use the protocol.mask only when the flow type is
	   * VNET_FLOW_TYPE_IP4/IP6. For other cases, the IP protocol is just
	   * used to identify the next layer type: e.g. UDP/TCP or IPSEC_ESP
	   */
	  if (type == VNET_FLOW_TYPE_IP4)
	    ip4_ptr->protocol.mask = protocol.mask;

	  switch (protocol.prot)
	    {
	      /* ip4-n-tuple */
	    case IP_PROTOCOL_TCP:
	    case IP_PROTOCOL_UDP:
	      flow.pattern.ip4_n_tuple.src_port = sport;
	      flow.pattern.ip4_n_tuple.dst_port = dport;

	      if (type == VNET_FLOW_TYPE_IP4_GTPC)
		flow.pattern.ip4_gtpc.teid = teid;
	      else if (type == VNET_FLOW_TYPE_IP4_GTPU)
		flow.pattern.ip4_gtpu.teid = teid;
	      else if (type == VNET_FLOW_TYPE_IP4_VXLAN)
		flow.pattern.ip4_vxlan.vni = vni;
	      break;
	    case IP_PROTOCOL_L2TP:
	      flow.pattern.ip4_l2tpv3oip.session_id = session_id;
	      break;
	    case IP_PROTOCOL_IPSEC_ESP:
	      flow.pattern.ip4_ipsec_esp.spi = spi;
	      break;
	    case IP_PROTOCOL_IPSEC_AH:
	      flow.pattern.ip4_ipsec_ah.spi = spi;
	      break;
	    case IP_PROTOCOL_IP_IN_IP:
	      clib_memcpy (&flow.pattern.ip4_ip4.in_src_addr, &in_ip4s,
			   sizeof (ip4_address_and_mask_t));
	      clib_memcpy (&flow.pattern.ip4_ip4.in_dst_addr, &in_ip4d,
			   sizeof (ip4_address_and_mask_t));
	      if (type == VNET_FLOW_TYPE_IP4_IP4_N_TUPLE)
		{
		  flow.pattern.ip4_ip4.in_protocol.prot = in_proto.prot;
		  flow.pattern.ip4_ip4_n_tuple.in_src_port = in_sport;
		  flow.pattern.ip4_ip4_n_tuple.in_dst_port = in_dport;
		}
	      break;
	    case IP_PROTOCOL_IPV6:
	      clib_memcpy (&flow.pattern.ip4_ip6.in_src_addr, &in_ip6s,
			   sizeof (ip6_address_and_mask_t));
	      clib_memcpy (&flow.pattern.ip4_ip6.in_dst_addr, &in_ip6d,
			   sizeof (ip6_address_and_mask_t));
	      if (type == VNET_FLOW_TYPE_IP4_IP6_N_TUPLE)
		{
		  flow.pattern.ip4_ip6.in_protocol.prot = in_proto.prot;
		  flow.pattern.ip4_ip6_n_tuple.in_src_port = in_sport;
		  flow.pattern.ip4_ip6_n_tuple.in_dst_port = in_dport;
		}
	      break;
	    default:
	      break;
	    }
	}
      else if (flow_class == FLOW_IPV6_CLASS)
	{
	  vnet_flow_ip6_t *ip6_ptr = &flow.pattern.ip6;

	  clib_memcpy (&flow.pattern.ip6_n_tuple.src_addr, &ip6s, sizeof (ip6_address_and_mask_t));
	  clib_memcpy (&flow.pattern.ip6_n_tuple.dst_addr, &ip6d, sizeof (ip6_address_and_mask_t));

	  ip6_ptr->protocol.prot = protocol.prot;

	  /* In this cli, we use the protocol.mask only when the flow type is
	   * VNET_FLOW_TYPE_IP4/IP6. For other cases, the IP protocol is just
	   * used to identify the next layer type: e.g. UDP/TCP or IPSEC_ESP
	   */
	  if (type == VNET_FLOW_TYPE_IP6)
	    ip6_ptr->protocol.mask = protocol.mask;

	  switch (protocol.prot)
	    {
	      /* ip6-n-tuple */
	    case IP_PROTOCOL_TCP:
	    case IP_PROTOCOL_UDP:
	      flow.pattern.ip6_n_tuple.src_port = sport;
	      flow.pattern.ip6_n_tuple.dst_port = dport;

	      if (type == VNET_FLOW_TYPE_IP6_VXLAN)
		flow.pattern.ip6_vxlan.vni = vni;
	      break;
	    case IP_PROTOCOL_IP_IN_IP:
	      clib_memcpy (&flow.pattern.ip6_ip4.in_src_addr, &in_ip4s,
			   sizeof (ip4_address_and_mask_t));
	      clib_memcpy (&flow.pattern.ip6_ip4.in_dst_addr, &in_ip4d,
			   sizeof (ip4_address_and_mask_t));
	      if (type == VNET_FLOW_TYPE_IP6_IP4_N_TUPLE)
		{
		  flow.pattern.ip6_ip4.in_protocol.prot = in_proto.prot;
		  flow.pattern.ip6_ip4_n_tuple.in_src_port = in_sport;
		  flow.pattern.ip6_ip4_n_tuple.in_dst_port = in_dport;
		}
	      break;
	    case IP_PROTOCOL_IPV6:
	      clib_memcpy (&flow.pattern.ip6_ip6.in_src_addr, &in_ip6s,
			   sizeof (ip6_address_and_mask_t));
	      clib_memcpy (&flow.pattern.ip6_ip6.in_dst_addr, &in_ip6d,
			   sizeof (ip6_address_and_mask_t));
	      if (type == VNET_FLOW_TYPE_IP6_IP6_N_TUPLE)
		{
		  flow.pattern.ip6_ip6.in_protocol.prot = in_proto.prot;
		  flow.pattern.ip6_ip6_n_tuple.in_src_port = in_sport;
		  flow.pattern.ip6_ip6_n_tuple.in_dst_port = in_dport;
		}
	      break;
	    default:
	      break;
	    }
	}

      flow.type = type;

      if (is_template)
	{
	  rv = vnet_flow_template_add (vnm, &flow, &template_index);
	  if (!rv)
	    vlib_cli_output (vm, "flow template %u added", template_index);
	}
      else
	{
	  rv = vnet_flow_add (vnm, &flow, &flow_index);
	  if (!rv)
	    vlib_cli_output (vm, "flow %u added", flow_index);
	}

  if (rv < 0)
    error = clib_error_return (0, "flow error: %U", format_flow_error, rv);

  return error;
}

static clib_error_t *
flow_add_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_add (vm, ctx, 0);
}

static clib_error_t *
flow_template_add_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_add (vm, ctx, 1);
}

/* The rss settings can be given several times. The interface is accepted, but not used. */
static const cli_arg_t flow_add_args[] = {
  CLI_OPT_KEYWORD ("src-ip", cli_type_flow_ip4),
  CLI_OPT_KEYWORD ("dst-ip", cli_type_flow_ip4),
  CLI_OPT_KEYWORD ("ip6-src-ip", cli_type_flow_ip6),
  CLI_OPT_KEYWORD ("ip6-dst-ip", cli_type_flow_ip6),
  CLI_OPT_KEYWORD ("src-port", cli_type_flow_port),
  CLI_OPT_KEYWORD ("dst-port", cli_type_flow_port),
  CLI_OPT_KEYWORD ("proto", cli_type_flow_protocol),
  CLI_OPT_KEYWORD ("eth-type", cli_type_flow_ethernet_type),
  CLI_OPT_KEYWORD ("in-src-ip", cli_type_flow_ip4, .help = "inner source address"),
  CLI_OPT_KEYWORD ("in-dst-ip", cli_type_flow_ip4, .help = "inner destination address"),
  CLI_OPT_KEYWORD ("in-ip6-src-ip", cli_type_flow_ip6, .help = "inner source address"),
  CLI_OPT_KEYWORD ("in-ip6-dst-ip", cli_type_flow_ip6, .help = "inner destination address"),
  CLI_OPT_KEYWORD ("in-src-port", cli_type_flow_port, .help = "inner source port"),
  CLI_OPT_KEYWORD ("in-dst-port", cli_type_flow_port, .help = "inner destination port"),
  CLI_OPT_KEYWORD ("in-proto", cli_type_flow_protocol, .help = "inner protocol"),
  CLI_GROUP_REQUIRES ("gtpc", "match a GTP-C tunnel", "teid",
		      CLI_OPT_KEYWORD ("teid", cli_type_u32)),
  CLI_GROUP_REQUIRES ("gtpu", "match a GTP-U tunnel", "teid",
		      CLI_OPT_KEYWORD ("teid", cli_type_u32)),
  CLI_GROUP_REQUIRES ("vxlan", "match a VXLAN tunnel", "vni",
		      CLI_OPT_KEYWORD ("vni", cli_type_u32)),
  CLI_GROUP_REQUIRES ("session", "match an L2TPv3 session, with proto l2tp", "id",
		      CLI_OPT_KEYWORD ("id", cli_type_u32)),
  CLI_OPT_KEYWORD ("spi", cli_type_u32, .help = "IPsec SPI, with proto esp or ah"),
  CLI_OPT_KEYWORD ("spec", cli_type_string, .help = "spec of a generic pattern"),
  CLI_OPT_KEYWORD ("mask", cli_type_string, .help = "mask of a generic pattern"),
  CLI_OPT_KEYWORD ("next-node", cli_type_node, .help = "send the packets to the node"),
  CLI_OPT_KEYWORD ("mark", cli_type_u32, .help = "mark the packets with the id"),
  CLI_OPT_KEYWORD ("buffer-advance", cli_type_flow_int),
  CLI_OPT_KEYWORD ("redirect-to-queue", cli_type_u32),
  CLI_FLAG ("drop"),
  CLI_ONEOF (
    "rss-or-interface", CLI_F_OPTIONAL | CLI_F_REPEAT,
    CLI_SEQ (
      CLI_ENUM ("rss", 0, { "rss", "receive side scaling", 1 }),
      CLI_ONEOF (
	"rss-setting", 0,
	CLI_KEYWORD ("function", cli_type_enum, .choices = flow_rss_function_choices),
	CLI_SEQ_LEAD (CLI_KEYWORD ("types", cli_type_enum, .choices = flow_rss_type_choices),
		      CLI_OPT_KEYWORD ("use", cli_type_enum, .choices = flow_rss_type_choices),
		      CLI_OPT_KEYWORD ("and", cli_type_enum, .choices = flow_rss_type_choices)),
	CLI_SEQ_LEAD (CLI_KEYWORD ("queues", cli_type_u32, .help = "first queue"),
		      CLI_KEYWORD ("to", cli_type_u32, .help = "last queue")))),
    CLI_VALUE ("interface", cli_type_hw_interface, .flags = CLI_F_HIDDEN)),
  {},
};

VLIB_CLI_COMMAND (flow_add_command, static) = {
  .path = "flow add",
  .short_help = "Add a flow",
  .args = flow_add_args,
  .handler = flow_add_command_fn,
};

VLIB_CLI_COMMAND (flow_template_add_command, static) = {
  .path = "flow template-add",
  .short_help = "Add a flow template",
  .args = flow_add_args,
  .handler = flow_template_add_command_fn,
};

static clib_error_t *
flow_cli_result (int rv)
{
  if (rv < 0)
    return clib_error_return (0, "flow error: %U", format_flow_error, rv);

  return 0;
}

static clib_error_t *
flow_del_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_result (vnet_flow_del (vnet_get_main (), cli_u64 (ctx, "index", ~0)));
}

static clib_error_t *
flow_enable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_result (
    vnet_flow_enable (vnet_get_main (), cli_u64 (ctx, "index", ~0), cli_index (ctx, "interface")));
}

static clib_error_t *
flow_disable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_result (vnet_flow_disable (vnet_get_main (), cli_u64 (ctx, "index", ~0)));
}

static clib_error_t *
flow_template_del_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_result (
    vnet_flow_template_del (vnet_get_main (), cli_u64 (ctx, "template-index", ~0)));
}

static clib_error_t *
flow_template_enable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_result (
    vnet_flow_template_enable (vnet_get_main (), cli_u64 (ctx, "template-index", ~0),
			       cli_index (ctx, "interface"), cli_u64 (ctx, "n-flows", 0)));
}

static clib_error_t *
flow_template_disable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_result (
    vnet_flow_template_disable (vnet_get_main (), cli_u64 (ctx, "template-index", ~0)));
}

static clib_error_t *
flow_cli_async_range (cli_ctx_t *ctx, int is_enable)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index = ~0, *flow_indices = 0, n_flows;
  clib_error_t *error = 0;
  cli_value_t *v;
  int rv;

  cli_foreach (v, ctx, "interface") hw_if_index = v->index;

  cli_foreach (v, ctx, "flow-index") vec_add1 (flow_indices, v->u64);

  if (hw_if_index == ~0)
    return clib_error_return (0, "Please specify interface name");

  n_flows = vec_len (flow_indices);
  if (n_flows == 0)
    return clib_error_return (0, "Please specify flow-indices");

  if (is_enable)
    rv = vnet_flow_async_range_enable (vnm, cli_u64 (ctx, "template-index", ~0), flow_indices,
				       hw_if_index);
  else
    rv = vnet_flow_async_range_disable (vnm, flow_indices, hw_if_index);

  if (rv < 0)
    error = flow_cli_result (rv);
  else if (rv < n_flows)
    error = clib_error_return (0, "only %d / %d success", rv, n_flows);

  vec_free (flow_indices);

  return error;
}

static clib_error_t *
flow_async_range_enable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_async_range (ctx, 1);
}

static clib_error_t *
flow_async_range_disable_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return flow_cli_async_range (ctx, 0);
}

/* the interface was accepted by the commands which do not need it */
static const cli_arg_t flow_index_args[] = {
  CLI_KEYWORD ("index", cli_type_u32, .help = "flow index"),
  CLI_VALUE ("interface", cli_type_hw_interface, .flags = CLI_F_OPTIONAL | CLI_F_HIDDEN),
  {},
};

static const cli_arg_t flow_template_index_args[] = {
  CLI_KEYWORD ("template-index", cli_type_u32),
  CLI_VALUE ("interface", cli_type_hw_interface, .flags = CLI_F_OPTIONAL | CLI_F_HIDDEN),
  {},
};

/* the indices follow the word flow-indices, the interface can be anywhere */
static const cli_arg_t flow_async_range_enable_args[] = {
  CLI_KEYWORD ("template-index", cli_type_u32),
  CLI_FLAG ("flow-indices", .help = "followed by the flow indices"),
  CLI_ONEOF ("flow-index-or-interface", CLI_F_OPTIONAL | CLI_F_REPEAT,
	     CLI_VALUE ("flow-index", cli_type_u32, .requires = "flow-indices"),
	     CLI_VALUE ("interface", cli_type_hw_interface)),
  {},
};

static const cli_arg_t flow_async_range_disable_args[] = {
  CLI_KEYWORD ("template-index", cli_type_u32, .flags = CLI_F_OPTIONAL | CLI_F_HIDDEN),
  CLI_FLAG ("flow-indices", .help = "followed by the flow indices"),
  CLI_ONEOF ("flow-index-or-interface", CLI_F_OPTIONAL | CLI_F_REPEAT,
	     CLI_VALUE ("flow-index", cli_type_u32, .requires = "flow-indices"),
	     CLI_VALUE ("interface", cli_type_hw_interface)),
  {},
};

VLIB_CLI_COMMAND (flow_del_command, static) = {
  .path = "flow del",
  .short_help = "Delete a flow",
  .args = flow_index_args,
  .handler = flow_del_command_fn,
};

VLIB_CLI_COMMAND (flow_enable_command, static) = {
  .path = "flow enable",
  .short_help = "Enable a flow on an interface",
  .args = CLI_ARGS (CLI_KEYWORD ("index", cli_type_u32, .help = "flow index"),
		    CLI_VALUE ("interface", cli_type_hw_interface)),
  .handler = flow_enable_command_fn,
};

VLIB_CLI_COMMAND (flow_disable_command, static) = {
  .path = "flow disable",
  .short_help = "Disable a flow",
  .args = flow_index_args,
  .handler = flow_disable_command_fn,
};

VLIB_CLI_COMMAND (flow_template_del_command, static) = {
  .path = "flow template-del",
  .short_help = "Delete a flow template",
  .args = flow_template_index_args,
  .handler = flow_template_del_command_fn,
};

VLIB_CLI_COMMAND (flow_template_enable_command, static) = {
  .path = "flow template-enable",
  .short_help = "Enable a flow template on an interface",
  .args = CLI_ARGS (CLI_KEYWORD ("template-index", cli_type_u32),
		    CLI_VALUE ("interface", cli_type_hw_interface),
		    CLI_OPT_KEYWORD ("n-flows", cli_type_u32, .help = "number of flows")),
  .handler = flow_template_enable_command_fn,
};

VLIB_CLI_COMMAND (flow_template_disable_command, static) = {
  .path = "flow template-disable",
  .short_help = "Disable a flow template",
  .args = flow_template_index_args,
  .handler = flow_template_disable_command_fn,
};

VLIB_CLI_COMMAND (flow_async_range_enable_command, static) = {
  .path = "flow async-range-enable",
  .short_help = "Enable a range of flows of a template",
  .args = flow_async_range_enable_args,
  .handler = flow_async_range_enable_command_fn,
};

VLIB_CLI_COMMAND (flow_async_range_disable_command, static) = {
  .path = "flow async-range-disable",
  .short_help = "Disable a range of flows",
  .args = flow_async_range_disable_args,
  .handler = flow_async_range_disable_command_fn,
};

static u8 *
format_flow_match_element (u8 * s, va_list * args)
{
  char *type = va_arg (*args, char *);
  void *ptr = va_arg (*args, void *);

  if (strncmp (type, "u8", 2) == 0)
    return format (s, "%d", *(u8 *) ptr);

  if (strncmp (type, "u16", 3) == 0)
    return format (s, "%d", *(u16 *) ptr);

  if (strncmp (type, "u32", 3) == 0)
    return format (s, "%d", *(u32 *) ptr);

  if (strncmp (type, "ethernet_header_t", 13) == 0)
    {
      ethernet_max_header_t m;
      memset (&m, 0, sizeof (m));
      m.ethernet = *(ethernet_header_t *) ptr;
      /* convert the ethernet type to net order */
      m.ethernet.type = clib_host_to_net_u16 (m.ethernet.type);
      return format (s, "%U", format_ethernet_header, &m);
    }

  if (strncmp (type, "ip4_address_t", 13) == 0)
    return format (s, "%U", format_ip4_address, ptr);

  if (strncmp (type, "ip4_address_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip4_address_and_mask, ptr);

  if (strncmp (type, "ip6_address_t", 13) == 0)
    return format (s, "%U", format_ip6_address, ptr);

  if (strncmp (type, "ip6_address_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip6_address_and_mask, ptr);

  if (strncmp (type, "ip_prot_and_mask_t", 13) == 0)
    return format (s, "%U", format_ip_protocol_and_mask, ptr);

  if (strncmp (type, "ip_port_and_mask_t", 18) == 0)
    return format (s, "%U", format_ip_port_and_mask, ptr);

  if (strncmp (type, "generic_pattern_t", 17) == 0)
    return format (s, "generic");

  s = format (s, "unknown type '%s'", type);
  return s;
}

#define _fe(a,b) s2 = format (s2, "%s%s %U", s2 ? ", ":"", #b, \
			      format_flow_match_element, #a, &f->b);
#define _(a,b,c) \
u8 * format_flow_match_##b (u8 * s, va_list * args)			\
{									\
  vnet_flow_##b##_t *f = __builtin_va_arg (*args, vnet_flow_##b##_t *); \
  u8 *s2 = 0; \
foreach_flow_entry_##b \
  s = format (s, "%v", s2);; \
  vec_free (s2); \
return s; \
}
foreach_flow_type
#undef _
#undef _fe
static u8 *
format_flow_match (u8 * s, va_list * args)
{
  vnet_flow_t *f = va_arg (*args, vnet_flow_t *);

#define _(a, b, c)                                                                                 \
  if (f->type == VNET_FLOW_TYPE_##a)                                                               \
    return format (s, "%U", format_flow_match_##b, &f->pattern.b);
  foreach_flow_type_inline;
#undef _

  if (f->type == VNET_FLOW_TYPE_GENERIC && f->generic_pattern)
    return format (s, "%U", format_flow_match_generic, f->generic_pattern);

  return s;
}

u8 *
format_flow_actions_detail (u8 *s, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_flow_t *f = va_arg (*args, vnet_flow_t *);
  u8 *t = 0;

  if (f->actions & VNET_FLOW_ACTION_DROP)
    t = format (t, "%sdrop", t ? ", " : "");

  if (f->actions & VNET_FLOW_ACTION_COUNT)
    t = format (t, "%scount", t ? ", " : "");

  if (f->actions & VNET_FLOW_ACTION_MARK)
    t = format (t, "%smark %u", t ? ", " : "", f->mark_flow_id);

  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    t =
      format (t, "%sredirect-to-queue %u", t ? ", " : "", f->redirect_queue);

  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    t = format (t, "%snext-node %U", t ? ", " : "",
		format_vlib_node_name, vm, f->redirect_node_index);

  if (f->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
    t = format (t, "%sbuffer-advance %d", t ? ", " : "", f->buffer_advance);

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {
      t = format (t, "%srss function %U", t ? ", " : "",
		  format_rss_function, f->rss_fun);
      t = format (t, "%srss types %U", t ? ", " : "",
		  format_rss_types, f->rss_types);
    }

  /* Shouldn't happened, but just in case. */
  if (!t)
    t = format (t, "no action");

  s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_flow (u8 *s, va_list *args)
{
  vnet_flow_t *f = va_arg (*args, vnet_flow_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "flow-index %u type %s %s", f->index, flow_type_strings[f->type],
	      IS_FLOW_ENABLED (f) ? "active" : "inactive"),
  s = format (s, "\n%Umatch: %U", format_white_space, indent + 2, format_flow_match, f);
  s = format (s, "\n%Uaction:", format_white_space, indent + 2);
  s = format (s, "\n%U%U", format_white_space, indent + 4, format_flow_actions_detail, f);
  return s;
}
