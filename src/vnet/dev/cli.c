/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#define _GNU_SOURCE
#include <dlfcn.h>

#include <vnet/vnet.h>
#include <vnet/interface/cli_types.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/api.h>
#include <vppinfra/format_table.h>

static u8 *
parse_device (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u8 *id = format (0, "%v%c", tok, 0);
  vnet_dev_t *dev = vnet_dev_by_id ((char *) id);

  vec_free (id);
  if (!dev)
    return format (0, "unknown device '%v'", tok);

  v->index = dev->index;
  return 0;
}

static void
complete_device (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  pool_foreach_pointer (dev, dm->devices)
    {
      if (cli_prefix_match (dev->device_id, prefix))
	cli_candidate_add (out, dev->device_id,
			   pool_elt_at_index (dm->drivers, dev->driver_index)->registration->name);
    }
}

CLIB_CLI_TYPE (cli_type_dev, static) = {
  .name = "device-id",
  .help = "id of an attached device",
  .parse = parse_device,
  .complete = complete_device,
};

static const char *
next_driver_name (const cli_arg_t *a, u32 *iter, u32 *value, const char **help)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  while (*iter < vec_len (dm->drivers))
    {
      u32 i = (*iter)++;
      vnet_dev_driver_t *driver;

      if (pool_is_free_index (dm->drivers, i))
	continue;

      driver = pool_elt_at_index (dm->drivers, i);
      *value = i;
      if (help)
	*help = driver->description;
      return driver->registration->name;
    }
  return 0;
}

CLIB_CLI_TYPE (cli_type_dev_driver, static) = {
  .name = "driver",
  .help = "name of a device driver",
  .next_name = next_driver_name,
  .parse = cli_names_parse,
  .complete = cli_names_complete,
};

static const cli_choice_t dev_flag_choices[] = {
#define _(b, n, d) { #n, d, 1u << (b) },
  foreach_vnet_dev_flag
#undef _
  {},
};

static const cli_choice_t dev_port_flag_choices[] = {
#define _(b, n, d) { #n, d, 1u << (b) },
  foreach_vnet_dev_port_flag
#undef _
  {},
};

static const cli_choice_t dev_rx_queue_assignment_choices[] = {
  { "round-robin", "queues are assigned round robin", VNET_DEV_RX_QUEUE_ASSIGNMENT_ROUND_ROBIN },
  { "queue-per-thread", "one queue per thread", VNET_DEV_RX_QUEUE_ASSIGNMENT_QUEUE_PER_THREAD },
  { "main-thread-only", "all queues are polled by the main thread",
    VNET_DEV_RX_QUEUE_ASSIGNMENT_MAIN_THREAD_ONLY },
  {},
};

/* "crypto-queue <i> [size <n>] [threads <list>] ...": the size and the
 * threads belong to the last crypto-queue given */
#define DEV_CRYPTO_ARGS                                                                            \
  CLI_OPT_KEYWORD ("num-crypto-queues", cli_type_u32, .min = 1, .max = CLIB_U16_MAX,               \
		   .help = "number of crypto queues"),                                             \
    CLI_OPT_KEYWORD ("crypto-queue-size", cli_type_u32, .min = 1, .max = CLIB_U16_MAX,             \
		     .help = "default size of the crypto queues"),                                 \
    CLI_OPT_KEYWORD_F ("crypto-queue", cli_type_u32, CLI_F_REPEAT, .max = CLIB_U16_MAX - 1,        \
		       .help = "start of the configuration of a queue"),                           \
    CLI_OPT_KEYWORD_F ("size", cli_type_u32, CLI_F_REPEAT, .min = 1, .max = CLIB_U16_MAX,          \
		       .help = "size of the last crypto-queue"),                                   \
    CLI_OPT_KEYWORD_F ("threads", cli_type_bitmap, CLI_F_REPEAT,                                   \
		       .help = "threads of the last crypto-queue")

static clib_error_t *
dev_crypto_config_from_ctx (cli_ctx_t *ctx, vnet_dev_crypto_config_t *cc)
{
  cli_value_t *v;
  vnet_dev_crypto_queue_config_t *qc = 0;

  if ((v = cli_get (ctx, "num-crypto-queues")))
    cc->num_queues = v->u64;
  if ((v = cli_get (ctx, "crypto-queue-size")))
    cc->queue_size = v->u64;

  /* the values of a queue follow its crypto-queue in the order they were typed */
  vec_foreach (v, ctx->values)
    {
      const char *name = v->arg->name;

      if (strcmp (name, "crypto-queue") == 0)
	{
	  vec_validate (cc->queues, v->u64);
	  qc = cc->queues + v->u64;
	}
      else if (strcmp (name, "size") == 0 || strcmp (name, "threads") == 0)
	{
	  if (!qc)
	    return clib_error_return (0, "'%s' must follow a 'crypto-queue'", name);
	  if (name[0] == 's')
	    qc->size = v->u64;
	  else
	    qc->threads = clib_bitmap_dup ((clib_bitmap_t *) v->str);
	}
    }
  return 0;
}

static clib_error_t *
dev_copy_str (char *dst, u32 max_len, const char *what, cli_value_t *v)
{
  if (vec_len (v->str) > max_len)
    return clib_error_return (0, "%s is too long, up to %u characters", what, max_len);

  clib_memcpy (dst, v->str, vec_len (v->str));
  dst[vec_len (v->str)] = 0;
  return 0;
}

static clib_error_t *
device_attach_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_attach_args_t a = {};
  cli_value_t *v;
  clib_error_t *err;
  vnet_dev_rv_t rv;

  err =
    dev_copy_str (a.device_id, sizeof (a.device_id) - 1, "device id", cli_get (ctx, "device-id"));
  if (err)
    return err;

  if ((v = cli_get (ctx, "driver")))
    {
      vnet_dev_main_t *dm = &vnet_dev_main;
      const char *name = pool_elt_at_index (dm->drivers, v->index)->registration->name;

      if (strlen (name) >= sizeof (a.driver_name))
	return clib_error_return (0, "driver name is too long");
      strcpy (a.driver_name, name);
    }

  if ((v = cli_get (ctx, "flags")))
    a.flags.n = v->u64;

  if ((v = cli_get (ctx, "args")))
    a.args = vec_dup (v->str);

  err = dev_crypto_config_from_ctx (ctx, &a.crypto);
  if (err)
    {
      vec_free (a.args);
      vnet_dev_crypto_config_free (&a.crypto);
      return err;
    }

  rv = vnet_dev_api_attach (vm, &a);

  vec_free (a.args);
  vnet_dev_crypto_config_free (&a.crypto);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to attach '%s': %U", a.device_id, format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_attach_cmd, static) = {
  .path = "device attach",
  .short_help = "Attach a device and create its ports",
  .args = CLI_ARGS (
    CLI_VALUE ("device-id", cli_type_string, .help = "id of the device, e.g. pci/0000:01:00.0"),
    CLI_OPT_KEYWORD ("driver", cli_type_dev_driver,
		     .help = "driver to use, default is the first one which matches the device"),
    CLI_OPT_KEYWORD ("flags", cli_type_flags, .choices = dev_flag_choices),
    CLI_OPT_KEYWORD ("args", cli_type_string,
		     .help = "device arguments, quote if there are spaces"),
    DEV_CRYPTO_ARGS),
  .handler = device_attach_cmd_fn,
};

static clib_error_t *
device_detach_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_detach_args_t a = { .dev_index = cli_index (ctx, "device-id") };
  vnet_dev_t *dev = vnet_dev_by_index (a.dev_index);
  vnet_dev_rv_t rv;

  rv = vnet_dev_api_detach (vm, &a);
  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to detach '%s': %U", dev->device_id, format_vnet_dev_rv,
			      rv);

  return 0;
}

VLIB_CLI_COMMAND (device_detach_cmd, static) = {
  .path = "device detach",
  .short_help = "Detach a device",
  .args = CLI_ARGS (CLI_VALUE ("device-id", cli_type_dev)),
  .handler = device_detach_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_reset_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_t *dev = vnet_dev_by_index (cli_index (ctx, "device-id"));
  vnet_dev_api_reset_args_t a = {};
  vnet_dev_rv_t rv;

  clib_memcpy (a.device_id, dev->device_id, sizeof (a.device_id));

  rv = vnet_dev_api_reset (vm, &a);
  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to reset '%s': %U", a.device_id, format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_reset_cmd, static) = {
  .path = "device reset",
  .short_help = "Reset a device",
  .args = CLI_ARGS (CLI_VALUE ("device-id", cli_type_dev)),
  .handler = device_reset_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_create_if_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_create_port_if_args_t a = {};
  vnet_dev_t *dev = vnet_dev_by_index (cli_index (ctx, "device-id"));
  cli_value_t *v;
  clib_error_t *err;
  vnet_dev_rv_t rv;

  a.dev_index = dev->index;

  if ((v = cli_get (ctx, "if-name")))
    {
      err = dev_copy_str (a.intf_name, sizeof (a.intf_name) - 1, "interface name", v);
      if (err)
	return err;
    }

  a.port_id = cli_u64 (ctx, "port", 0);
  if ((v = cli_get (ctx, "flags")))
    a.flags.n = v->u64;
  a.num_rx_queues = cli_u64 (ctx, "num-rx-queues", 0);
  a.num_tx_queues = cli_u64 (ctx, "num-tx-queues", 0);
  if ((v = cli_get (ctx, "rx-queue-assignment")))
    a.rx_queue_assignment = v->index;
  a.rx_queue_size = cli_u64 (ctx, "rx-queues-size", 0);
  a.tx_queue_size = cli_u64 (ctx, "tx-queues-size", 0);
  if ((v = cli_get (ctx, "args")))
    a.args = vec_dup (v->str);

  rv = vnet_dev_api_create_port_if (vm, &a);

  vec_free (a.args);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to create_if '%s': %U", dev->device_id, format_vnet_dev_rv,
			      rv);

  return 0;
}

VLIB_CLI_COMMAND (device_create_if_cmd, static) = {
  .path = "device create-interface",
  .short_help = "Create the interface of a device port",
  .args = CLI_ARGS (CLI_VALUE ("device-id", cli_type_dev),
		    CLI_OPT_KEYWORD ("if-name", cli_type_string, .alias = "name",
				     .help = "name of the interface"),
		    CLI_OPT_KEYWORD ("port", cli_type_u32, .help = "port id, default 0"),
		    CLI_OPT_KEYWORD ("flags", cli_type_flags, .choices = dev_port_flag_choices),
		    CLI_OPT_KEYWORD ("num-rx-queues", cli_type_u32),
		    CLI_OPT_KEYWORD ("num-tx-queues", cli_type_u32),
		    CLI_OPT_KEYWORD ("rx-queue-assignment", cli_type_enum,
				     .choices = dev_rx_queue_assignment_choices),
		    CLI_OPT_KEYWORD ("rx-queues-size", cli_type_u32),
		    CLI_OPT_KEYWORD ("tx-queues-size", cli_type_u32),
		    CLI_OPT_KEYWORD ("args", cli_type_string,
				     .help = "interface arguments, quote if there are spaces")),
  .handler = device_create_if_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_remove_if_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_remove_port_if_args_t a = { .sw_if_index = cli_index (ctx, "interface") };
  vnet_dev_rv_t rv;

  rv = vnet_dev_api_remove_port_if (vm, &a);
  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to remove interface: %U", format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_remove_if_cmd, static) = {
  .path = "device remove-interface",
  .short_help = "Remove the interface of a device port",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw-if-index")),
  .handler = device_remove_if_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_create_sec_if_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_port_add_sec_if_args_t a = {};
  cli_value_t *v;
  clib_error_t *err;
  vnet_dev_rv_t rv;

  if ((v = cli_get (ctx, "primary-sw-if-index")))
    a.primary_sw_if_index = v->u64;
  else if (cli_get (ctx, "primary-if-name"))
    a.primary_sw_if_index = cli_index (ctx, "primary-if-name");
  else
    return clib_error_return (0, "the interface of the port is missing");

  if ((v = cli_get (ctx, "if-name")))
    {
      err = dev_copy_str (a.intf_name, sizeof (a.intf_name) - 1, "interface name", v);
      if (err)
	return err;
    }

  if ((v = cli_get (ctx, "args")))
    a.args = vec_dup (v->str);

  rv = vnet_dev_api_port_add_sec_if (vm, &a);

  vec_free (a.args);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to create secondary interface: %U", format_vnet_dev_rv,
			      rv);

  return 0;
}

VLIB_CLI_COMMAND (device_create_sec_if_cmd, static) = {
  .path = "device create-secondary-interface",
  .short_help = "Create a secondary interface of a device port",
  .args = CLI_ARGS (
    CLI_OPT_KEYWORD ("primary-if-name", cli_type_sw_interface, .excludes = "primary-sw-if-index",
		     .help = "interface of the port to add the secondary interface to"),
    CLI_OPT_KEYWORD_F ("primary-sw-if-index", cli_type_u32, CLI_F_HIDDEN,
		       .excludes = "primary-if-name"),
    CLI_OPT_KEYWORD ("if-name", cli_type_string, .help = "name of the secondary interface"),
    CLI_OPT_KEYWORD ("args", cli_type_string,
		     .help = "interface arguments, quote if there are spaces")),
  .handler = device_create_sec_if_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_remove_sec_if_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_port_del_sec_if_args_t a = { .sw_if_index = cli_index (ctx, "interface") };
  vnet_dev_rv_t rv;

  rv = vnet_dev_api_port_del_sec_if (vm, &a);
  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to remove secondary interface: %U", format_vnet_dev_rv,
			      rv);

  return 0;
}

VLIB_CLI_COMMAND (device_remove_sec_if_cmd, static) = {
  .path = "device remove-secondary-interface",
  .short_help = "Remove a secondary interface of a device port",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw-if-index")),
  .handler = device_remove_sec_if_cmd_fn,
  .is_mp_safe = 1,
};

static vnet_dev_t **
dev_vector_from_ctx (cli_ctx_t *ctx)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_t **devs = 0;
  cli_value_t *v;

  cli_foreach (v, ctx, "device-id") vec_add1 (devs, vnet_dev_by_index (v->index));

  if (vec_len (devs) == 0)
    pool_foreach_pointer (dev, dm->devices)
      vec_add1 (devs, dev);

  return devs;
}

/* prints the output of a formatter at indent, if there is any */
static void
show_device_output (vlib_main_t *vm, u32 indent, format_function_t *fn, ...)
{
  u8 *s = format (0, "%U", format_white_space, indent);
  va_list va;

  va_start (va, fn);
  s = fn (s, &va);
  va_end (va);

  if (vec_len (s) > indent)
    vlib_cli_output (vm, "%v", s);
  vec_free (s);
}

static clib_error_t *
show_devices_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_format_args_t fa = {}, *a = &fa;
  vnet_dev_t **devs = dev_vector_from_ctx (ctx);
  cli_value_t *v;

  fa.plain_text = ctx->plain_text_only;
  fa.width = ctx->terminal_width;

  if ((v = cli_get (ctx, "debug-level")))
    fa.debug = v->u64;
  else if (cli_flag (ctx, "debug"))
    fa.debug = 1;

  if (cli_flag (ctx, "all"))
    fa.info = fa.status = fa.rss = fa.capabilities = fa.queues = fa.arguments = fa.module =
      fa.counters = 1;
  else
    {
      fa.info = cli_flag (ctx, "info");
      fa.status = cli_flag (ctx, "status");
      fa.rss = cli_flag (ctx, "rss");
      fa.capabilities = cli_flag (ctx, "capabilities");
      fa.queues = cli_flag (ctx, "queues");
      fa.arguments = cli_flag (ctx, "arguments");
      fa.module = cli_flag (ctx, "module");
      fa.counters = cli_flag (ctx, "counters");
    }

  fa.show_zero_counters = cli_flag (ctx, "zero-counters");
  fa.clear = cli_flag (ctx, "clear");
  if (fa.show_zero_counters || fa.clear)
    fa.counters = 1;

  if ((fa.info | fa.status | fa.rss | fa.capabilities | fa.queues | fa.arguments | fa.module |
       fa.counters) == 0)
    fa.info = 1;

  vec_foreach_pointer (dev, devs)
    {
      vlib_cli_output (vm, "device '%U':", format_vnet_dev_value, a, "%s", dev->device_id);
      show_device_output (vm, 2, format_vnet_dev_info, a, dev);

      foreach_vnet_dev_port (p, dev)
	{
	  vlib_cli_output (vm, "  Port %U:", format_vnet_dev_value, a, "%u", p->port_id);
	  show_device_output (vm, 4, format_vnet_dev_port_info, a, p);

	  if (fa.counters)
	    show_device_output (vm, 4, format_vnet_dev_counters, a, p->counter_main);

	  if (fa.queues || fa.counters)
	    {
	      foreach_vnet_dev_port_rx_queue (q, p)
		{
		  /* queues without counters only show up with their info */
		  if (fa.queues == 0 && q->counter_main == 0)
		    continue;

		  vlib_cli_output (vm, "    RX queue %U:", format_vnet_dev_value, a, "%u",
				   q->queue_id);
		  if (fa.queues)
		    show_device_output (vm, 6, format_vnet_dev_rx_queue_info, a, q);
		  if (fa.counters && q->counter_main)
		    show_device_output (vm, 6, format_vnet_dev_counters, a, q->counter_main);
		}

	      foreach_vnet_dev_port_tx_queue (q, p)
		{
		  /* queues without counters only show up with their info */
		  if (fa.queues == 0 && q->counter_main == 0)
		    continue;

		  vlib_cli_output (vm, "    TX queue %U:", format_vnet_dev_value, a, "%u",
				   q->queue_id);
		  if (fa.queues)
		    show_device_output (vm, 6, format_vnet_dev_tx_queue_info, a, q);
		  if (fa.counters && q->counter_main)
		    show_device_output (vm, 6, format_vnet_dev_counters, a, q->counter_main);
		}
	    }

	  if (fa.clear)
	    vnet_dev_process_call_port_op_no_rv (vm, p, vnet_dev_port_clear_counters);
	}

      if (fa.queues || fa.counters)
	vec_foreach_pointer (cq, dev->crypto_queues)
	  {
	    vlib_cli_output (vm, "  Crypto queue %U:", format_vnet_dev_value, a, "%u", cq->index);
	    if (fa.queues)
	      show_device_output (vm, 4, format_vnet_dev_crypto_queue_info, a, cq);
	    if (fa.counters)
	      show_device_output (vm, 4, format_vnet_dev_crypto_queue_counters, a, cq);
	    if (fa.clear)
	      vnet_dev_crypto_queue_clear_counters (cq);
	  }
    }
  vec_free (devs);
  return 0;
}

VLIB_CLI_COMMAND (show_devices_cmd, static) = {
  .path = "show device",
  .short_help = "Show devices, ports and queues",
  .args = CLI_ARGS (
    CLI_FLAG ("info", .help = "show the device and port information, the default"),
    CLI_FLAG ("status", .help = "show the driver specific port status"),
    CLI_FLAG ("rss", .help = "show the RSS configuration"),
    CLI_FLAG ("capabilities", .help = "show the capabilities and offloads"),
    CLI_FLAG ("queues", .help = "show the queues"),
    CLI_FLAG ("arguments", .alias = "args", .help = "show the device and port arguments"),
    CLI_FLAG ("module", .help = "show the transceiver module information"),
    CLI_FLAG ("counters", .help = "show the non-zero counters"),
    CLI_FLAG ("zero-counters", .help = "show the counters including the ones which are zero"),
    CLI_FLAG ("clear", .help = "clear the counters after showing them"),
    CLI_FLAG ("all", .help = "show everything except the debug information"),
    CLI_FLAG ("debug", .help = "show debug information"),
    CLI_OPT_KEYWORD ("debug-level", cli_type_u32, .help = "level of the debug information"),
    CLI_VALUE ("device-id", cli_type_dev, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT,
	       .help = "only these devices")),
  .handler = show_devices_cmd_fn,
  .is_mp_safe = 1,
};

static const cli_column_t show_device_drivers_columns[] = {
  { "name", "name" },
  { "bus", "bus" },
  { "priority", "priority" },
  { "shared_object", "shared object" },
  { "description", "description" },
  {},
};

static clib_error_t *
show_device_drivers_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_driver_t *driver = 0;
  table_t table = {}, *t = &table;
  clib_json_text_t j;
  int structured = cli_is_structured (ctx);
  int c = 0;

  if (pool_elts (dm->drivers) == 0 && !structured)
    {
      vlib_cli_output (vm, "no device drivers loaded");
      return 0;
    }

  if (structured)
    {
      clib_json_init (&j);
      clib_json_add_array (&j, 0);
    }
  else
    {
      table_add_hdr_row (t, 5, "name", "bus", "priority", "shared object", "description");
      table_set_cell_align (t, -1, 0, TTAA_LEFT);
      table_set_cell_align (t, -1, 3, TTAA_LEFT);
      table_set_cell_align (t, -1, 4, TTAA_LEFT);
    }

  pool_foreach (driver, dm->drivers)
    {
      vnet_dev_driver_registration_t *r = driver->registration;
      Dl_info info = {};
      const char *desc = driver->description ? driver->description : "";
      const char *file = "";

      if (dladdr (r, &info) && info.dli_fname)
	{
	  file = strrchr (info.dli_fname, '/');
	  if (file)
	    file++;
	  else
	    file = info.dli_fname;
	}

      if (structured)
	{
	  clib_json_add_object (&j, 0);
	  clib_json_add_string (&j, "name", "%s", r->name);
	  clib_json_add_string (&j, "bus", "%s", r->bus);
	  clib_json_add_number (&j, "priority", r->priority);
	  clib_json_add_string (&j, "shared_object", "%s", file);
	  clib_json_add_string (&j, "description", "%s", desc);
	  clib_json_parent (&j);
	  continue;
	}

      table_format_cell (t, c, 0, "%s", r->name);
      table_format_cell (t, c, 1, "%s", r->bus);
      table_format_cell (t, c, 2, "%d", r->priority);
      table_format_cell (t, c, 3, "%s", file);
      table_format_cell (t, c, 4, "%s", desc);
      table_set_cell_align (t, c, 0, TTAA_LEFT);
      table_set_cell_align (t, c, 2, TTAA_CENTER);
      table_set_cell_align (t, c, 3, TTAA_LEFT);
      table_set_cell_align (t, c, 4, TTAA_LEFT);
      c++;
    }

  if (structured)
    {
      clib_json_parent (&j);
      return cli_emit_table (ctx, &j, show_device_drivers_columns);
    }

  styled_text_t st = { .output = ctx->plain_text_only ? ST_O_PLAIN : ST_O_UNKNOWN };

  styled_text_add (&st, "%T", format_styled_table, t);
  vlib_cli_output (vm, "%U", format_styled_text, &st);

  styled_text_free (&st);
  table_free (t);
  return 0;
}

VLIB_CLI_COMMAND (show_device_drivers_cmd, static) = {
  .path = "show device drivers",
  .short_help = "Show the loaded device drivers",
  .handler = show_device_drivers_cmd_fn,
  .is_mp_safe = 1,
  .is_structured = 1,
};

static clib_error_t *
show_device_dma_slabs_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vlib_cli_output (vm, "%U", format_vnet_dev_dma_slabs);
  return 0;
}

VLIB_CLI_COMMAND (show_device_dma_slabs_cmd, static) = {
  .path = "show device dma-slabs",
  .short_help = "Show the DMA slabs",
  .handler = show_device_dma_slabs_cmd_fn,
  .is_mp_safe = 1,
};

static const cli_choice_t rss_fields_choices[] = {
#define _(n, v, h) { .name = n, .help = h, .value = (v) },
  foreach_vnet_dev_rss_fields_alias
#undef _
#define _(v, n, s, h) { .name = s, .help = h, .value = (v) },
    foreach_vnet_dev_rss_field
#undef _
  { .name = "inherit", .help = "fields of the parent class", .value = VNET_DEV_RSS_FIELDS_INHERIT },
  {},
};

static const cli_choice_t rss_function_choices[] = {
#define _(n, s) { .name = s, .value = VNET_DEV_RSS_FUNCTION_##n },
  foreach_vnet_dev_rss_function
#undef _
  {},
};

static const char *rss_class_names[] = {
#define _(n, s, p) [VNET_DEV_RSS_CLASS_##n] = s,
  foreach_vnet_dev_rss_class
#undef _
};

/* arguments of the rss commands, the class keywords start with ',' so they go last */
#define RSS_CLASS_ARG(n, s, p)                                                                     \
  , CLI_OPT_KEYWORD (s, cli_type_flags, .choices = rss_fields_choices,                             \
		     .help = "hash fields of the " s " class")
#define RSS_ARGS                                                                                   \
  CLI_OPT_KEYWORD ("function", cli_type_enum, .choices = rss_function_choices,                     \
		   .help = "hash function"),                                                       \
    CLI_OPT_KEYWORD ("key", cli_type_hex, .max = VNET_DEV_RSS_KEY_MAX_SIZE,                        \
		     .help = "RSS key, hex string"),                                               \
    CLI_OPT_KEYWORD ("lut", cli_type_u32_list, .max = VNET_DEV_RSS_LUT_MAX_SIZE,                   \
		     .help = "queue ids, e.g. 0,1,2,3") foreach_vnet_dev_rss_class

static clib_error_t *
rss_config_set (vlib_main_t *vm, cli_ctx_t *ctx, vnet_dev_port_t *port)
{
  vnet_dev_api_port_set_rss_config_args_t a = {
    .port_id = port->port_id,
    .dev_index = port->dev->index,
  };
  vnet_dev_rss_config_t *cfg = &a.rss_config;
  cli_value_t *v;
  vnet_dev_rv_t rv;
  u8 *err = 0;

  if ((v = cli_get (ctx, "key")))
    {
      clib_memcpy (cfg->key, v->str, vec_len (v->str));
      cfg->key_len = vec_len (v->str);
      cfg->set_key = 1;
    }

  if ((v = cli_get (ctx, "lut")))
    {
      u32 *lut = (u32 *) v->str;

      for (u32 i = 0; i < vec_len (lut); i++)
	{
	  if (lut[i] > CLIB_U16_MAX)
	    return clib_error_return (0, "queue id %u is too big", lut[i]);
	  cfg->lut[i] = lut[i];
	}
      cfg->lut_len = vec_len (lut);
      cfg->set_lut = 1;
    }

  if ((v = cli_get (ctx, "function")))
    {
      cfg->function = v->index;
      cfg->set_function = 1;
    }

  for (u32 i = 0; i < VNET_DEV_RSS_N_CLASSES; i++)
    if ((v = cli_get (ctx, rss_class_names[i])))
      {
	if ((v->u64 & VNET_DEV_RSS_FIELDS_INHERIT) && v->u64 != VNET_DEV_RSS_FIELDS_INHERIT)
	  return clib_error_return (0, "'inherit' can't be combined with fields");
	vnet_dev_rss_config_set_class (cfg, i, v->u64);
      }

  if (port->attr.caps.rss == 0)
    return clib_error_return (0, "port doesn't support RSS");

  if (vnet_dev_rss_config_validate (port, cfg, &err) != VNET_DEV_OK)
    return clib_error_return (0, "%v", err);

  rv = vnet_dev_api_port_set_rss_config (vm, &a);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to set RSS configuration: %U", format_vnet_dev_rv, rv);

  return 0;
}

static clib_error_t *
device_set_rss_config_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 sw_if_index = cli_index (ctx, "interface");
  vnet_dev_port_t *port;

  if (sw_if_index != ~0)
    port = vnet_dev_get_port_from_sw_if_index (sw_if_index);
  else
    {
      vnet_dev_t *dev = vnet_dev_by_index (cli_index (ctx, "dev"));

      port = dev ? vnet_dev_get_port_by_id (dev, cli_u64 (ctx, "port", 0)) : 0;
    }

  if (port == 0)
    return clib_error_return (0, "unknown port");

  return rss_config_set (vm, ctx, port);
}

#define _ RSS_CLASS_ARG
VLIB_CLI_COMMAND (device_set_rss_config_cmd, static) = {
  .path = "device set-rss-config",
  .short_help = "Set the RSS hash fields, hash function, key and lookup table of a port",
  .args = CLI_ARGS (
    CLI_ONEOF ("target", 0,
	       CLI_VALUE ("interface", cli_type_sw_interface, .help = "interface of the port"),
	       CLI_SEQ (CLI_KEYWORD ("dev", cli_type_dev, .help = "device of the port"),
			CLI_OPT_KEYWORD ("port", cli_type_u32, .help = "port id, default 0"))),
    RSS_ARGS),
  .handler = device_set_rss_config_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
set_interface_rss_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_port_t *port = vnet_dev_get_port_from_sw_if_index (cli_index (ctx, "interface"));

  if (port == 0)
    return clib_error_return (0, "not a device interface");

  return rss_config_set (vm, ctx, port);
}

VLIB_CLI_COMMAND (set_interface_rss_cmd, static) = {
  .path = "set interface rss",
  .short_help = "Set the RSS hash fields, hash function, key and lookup table of an interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface), RSS_ARGS),
  .handler = set_interface_rss_cmd_fn,
  .is_mp_safe = 1,
};
#undef _
