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
#include <vlib/unix/unix.h>
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

static void
complete_driver (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_driver_t *driver;

  pool_foreach (driver, dm->drivers)
    {
      if (cli_prefix_match (driver->registration->name, prefix))
	cli_candidate_add (out, driver->registration->name, driver->description);
    }
}

static u8 *
parse_driver (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  v->str = vec_dup (tok);
  return 0;
}

CLIB_CLI_TYPE (cli_type_dev_driver, static) = {
  .name = "driver",
  .help = "name of a device driver",
  .owns_str = 1,
  .parse = parse_driver,
  .complete = complete_driver,
};

/* Comma separated list of flag names, e.g. NO_STATS,INTERRUPT-MODE, case
 * is ignored and '-' is the same as '_'. The value is the mask. */
typedef struct
{
  const char *name;
  const char *help;
  u64 value;
} dev_flag_name_t;

static u8 *
parse_flag_list (const dev_flag_name_t *flags, u8 *tok, cli_value_t *v)
{
  u32 start = 0;

  v->u64 = 0;
  for (u32 i = 0; i <= vec_len (tok); i++)
    {
      u8 *name = 0, *raw;
      const dev_flag_name_t *f;

      if (i < vec_len (tok) && tok[i] != ',')
	continue;

      vec_add (name, tok + start, i - start);
      raw = vec_dup (name);
      for (u32 j = 0; j < vec_len (name); j++)
	{
	  if (name[j] == '-')
	    name[j] = '_';
	  else if (name[j] >= 'a' && name[j] <= 'z')
	    name[j] -= 'a' - 'A';
	}

      for (f = flags; f->name; f++)
	if (vec_len (name) == strlen (f->name) && memcmp (name, f->name, vec_len (name)) == 0)
	  break;

      if (!f->name)
	{
	  u8 *err = format (0, "unknown flag '%v'", raw);

	  vec_free (name);
	  vec_free (raw);
	  return err;
	}
      v->u64 |= f->value;
      vec_free (name);
      vec_free (raw);
      start = i + 1;
    }
  return 0;
}

static void
complete_flag_list (const dev_flag_name_t *flags, u8 *prefix, cli_candidate_t **out)
{
  u32 base = 0;

  for (u32 i = 0; i < vec_len (prefix); i++)
    if (prefix[i] == ',')
      base = i + 1;

  for (const dev_flag_name_t *f = flags; f->name; f++)
    {
      u32 len = vec_len (prefix) - base;
      u8 *text = 0;

      if (len > strlen (f->name))
	continue;
      for (u32 i = 0; i < len; i++)
	{
	  u8 c = prefix[base + i] == '-' ? '_' : prefix[base + i];

	  if (c >= 'a' && c <= 'z')
	    c -= 'a' - 'A';
	  if (c != f->name[i])
	    goto next;
	}
      vec_add (text, prefix, base);
      text = format (text, "%s%c", f->name, 0);
      cli_candidate_add (out, (char *) text, f->help);
      vec_free (text);
    next:;
    }
}

static const dev_flag_name_t dev_flags[] = {
#define _(b, n, d) { #n, d, 1ull << (b) },
  foreach_vnet_dev_flag
#undef _
  {},
};

static u8 *
parse_dev_flags (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_flag_list (dev_flags, tok, v);
}

static void
complete_dev_flags (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  complete_flag_list (dev_flags, prefix, out);
}

CLIB_CLI_TYPE (cli_type_dev_flags, static) = {
  .name = "flags",
  .help = "comma separated list of device flags",
  .parse = parse_dev_flags,
  .complete = complete_dev_flags,
};

static const dev_flag_name_t dev_port_flags[] = {
#define _(b, n, d) { #n, d, 1ull << (b) },
  foreach_vnet_dev_port_flag
#undef _
  {},
};

static u8 *
parse_dev_port_flags (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  return parse_flag_list (dev_port_flags, tok, v);
}

static void
complete_dev_port_flags (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  complete_flag_list (dev_port_flags, prefix, out);
}

CLIB_CLI_TYPE (cli_type_dev_port_flags, static) = {
  .name = "flags",
  .help = "comma separated list of port flags",
  .parse = parse_dev_port_flags,
  .complete = complete_dev_port_flags,
};

static const cli_choice_t dev_rx_queue_assignment_choices[] = {
  { "round-robin", "queues are assigned round robin", VNET_DEV_RX_QUEUE_ASSIGNMENT_ROUND_ROBIN },
  { "queue-per-thread", "one queue per thread", VNET_DEV_RX_QUEUE_ASSIGNMENT_QUEUE_PER_THREAD },
  { "main-thread-only", "all queues are polled by the main thread",
    VNET_DEV_RX_QUEUE_ASSIGNMENT_MAIN_THREAD_ONLY },
  {},
};

/* hex string, the value is a vector of bytes */
static u8 *
parse_rss_key (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  u8 *key = 0;
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat_user (&in, unformat_hex_string, &key) &&
       unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);

  if (!ok || vec_len (key) > VNET_DEV_RSS_KEY_MAX_SIZE)
    {
      vec_free (key);
      return format (0, "'%v' is not a hex string of up to %u bytes", tok,
		     VNET_DEV_RSS_KEY_MAX_SIZE);
    }

  v->str = key;
  return 0;
}

CLIB_CLI_TYPE (cli_type_dev_rss_key, static) = {
  .name = "rss-key",
  .help = "RSS key, hex string",
  .owns_str = 1,
  .parse = parse_rss_key,
};

/* comma separated queue ids, the value is a vector of u16 */
static u8 *
parse_rss_lut (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u16 *lut = 0;
  u32 start = 0;

  for (u32 i = 0; i <= vec_len (tok); i++)
    {
      u32 n = 0;

      if (i < vec_len (tok) && tok[i] != ',')
	continue;

      if (i == start || i - start > 5)
	goto bad;
      for (u32 j = start; j < i; j++)
	{
	  if (!cli_is_digit (tok[j]))
	    goto bad;
	  n = n * 10 + tok[j] - '0';
	}
      if (n > CLIB_U16_MAX || vec_len (lut) == VNET_DEV_RSS_LUT_MAX_SIZE)
	goto bad;
      vec_add1 (lut, n);
      start = i + 1;
    }

  v->str = (u8 *) lut;
  return 0;

bad:
  vec_free (lut);
  return format (0, "'%v' is not a list of up to %u queue ids, e.g. 0,1,2,3", tok,
		 VNET_DEV_RSS_LUT_MAX_SIZE);
}

CLIB_CLI_TYPE (cli_type_dev_rss_lut, static) = {
  .name = "rss-lut",
  .help = "comma separated queue ids",
  .owns_str = 1,
  .parse = parse_rss_lut,
};

/* "crypto-queue <i> [size <n>] [threads <list>] ...": the size and the
 * threads belong to the last crypto-queue given */
#define DEV_CRYPTO_ARGS                                                                            \
  CLI_KEYWORD ("num-crypto-queues", cli_type_u32, .flags = CLI_F_OPTIONAL, .min = 1,               \
	       .max = CLIB_U16_MAX, .help = "number of crypto queues"),                            \
    CLI_KEYWORD ("crypto-queue-size", cli_type_u32, .flags = CLI_F_OPTIONAL, .min = 1,             \
		 .max = CLIB_U16_MAX, .help = "default size of the crypto queues"),                \
    CLI_KEYWORD ("crypto-queue", cli_type_u32, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT,             \
		 .max = CLIB_U16_MAX - 1, .help = "start of the configuration of a queue"),        \
    CLI_KEYWORD ("size", cli_type_u32, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT, .min = 1,           \
		 .max = CLIB_U16_MAX, .help = "size of the last crypto-queue"),                    \
    CLI_KEYWORD ("threads", cli_type_bitmap, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT,               \
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
dev_copy_str (char *dst, u32 size, const char *what, cli_value_t *v)
{
  if (vec_len (v->str) >= size)
    return clib_error_return (0, "%s is too long, up to %u characters", what, size - 1);

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

  err = dev_copy_str (a.device_id, sizeof (a.device_id), "device id", cli_get (ctx, "device-id"));
  if (err)
    return err;

  if ((v = cli_get (ctx, "driver")))
    {
      err = dev_copy_str (a.driver_name, sizeof (a.driver_name), "driver name", v);
      if (err)
	return err;
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
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("device-id", cli_type_string, .help = "id of the device, e.g. pci/0000:01:00.0"),
      CLI_KEYWORD ("driver", cli_type_dev_driver, .flags = CLI_F_OPTIONAL,
		   .help = "driver to use, default is the first one which matches the device"),
      CLI_KEYWORD ("flags", cli_type_dev_flags, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("args", cli_type_string, .flags = CLI_F_OPTIONAL,
		   .help = "device arguments, quote if there are spaces"),
      DEV_CRYPTO_ARGS,
      {},
    },
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
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("device-id", cli_type_dev),
      {},
    },
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
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("device-id", cli_type_dev),
      {},
    },
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
      err = dev_copy_str (a.intf_name, sizeof (a.intf_name), "interface name", v);
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
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("device-id", cli_type_dev),
      CLI_KEYWORD ("if-name", cli_type_string, .alias = "name", .flags = CLI_F_OPTIONAL,
		   .help = "name of the interface"),
      CLI_KEYWORD ("port", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "port id, default 0"),
      CLI_KEYWORD ("flags", cli_type_dev_port_flags, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("num-rx-queues", cli_type_u32, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("num-tx-queues", cli_type_u32, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("rx-queue-assignment", cli_type_enum, .flags = CLI_F_OPTIONAL,
		   .choices = dev_rx_queue_assignment_choices),
      CLI_KEYWORD ("rx-queues-size", cli_type_u32, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("tx-queues-size", cli_type_u32, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("args", cli_type_string, .flags = CLI_F_OPTIONAL,
		   .help = "interface arguments, quote if there are spaces"),
      {},
    },
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
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      {},
    },
  .handler = device_remove_if_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
device_create_sec_if_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_port_add_sec_if_args_t a = { .primary_sw_if_index =
					      cli_index (ctx, "primary-if-name") };
  cli_value_t *v;
  clib_error_t *err;
  vnet_dev_rv_t rv;

  if ((v = cli_get (ctx, "if-name")))
    {
      err = dev_copy_str (a.intf_name, sizeof (a.intf_name), "interface name", v);
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
  .args =
    (cli_arg_t[]) {
      CLI_KEYWORD ("primary-if-name", cli_type_sw_interface,
		   .help = "interface of the port to add the secondary interface to"),
      CLI_KEYWORD ("if-name", cli_type_string, .flags = CLI_F_OPTIONAL,
		   .help = "name of the secondary interface"),
      CLI_KEYWORD ("args", cli_type_string, .flags = CLI_F_OPTIONAL,
		   .help = "interface arguments, quote if there are spaces"),
      {},
    },
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
  .args =
    (cli_arg_t[]) {
      CLI_VALUE ("interface", cli_type_sw_interface),
      {},
    },
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

static clib_error_t *
show_devices_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_format_args_t fa = {}, *a = &fa;
  vnet_dev_t **devs = dev_vector_from_ctx (ctx);
  cli_value_t *v;

  if ((unix_main.flags & UNIX_FLAG_NOCOLOR) || !vlib_unix_cli_ansi_capable ())
    fa.plain_text = 1;

  if ((v = cli_get (ctx, "debug-level")))
    fa.debug = v->u64;
  else if (cli_flag (ctx, "debug"))
    fa.debug = 1;

  vec_foreach_pointer (dev, devs)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      vlib_cli_output (vm, "  %U", format_vnet_dev_info, a, dev);
      foreach_vnet_dev_port (p, dev)
	{
	  vlib_cli_output (vm, "  Port %u:", p->port_id);
	  vlib_cli_output (vm, "    %U", format_vnet_dev_port_info, a, p);

	  foreach_vnet_dev_port_rx_queue (q, p)
	    {
	      vlib_cli_output (vm, "    RX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_rx_queue_info, a, q);
	    }

	  foreach_vnet_dev_port_tx_queue (q, p)
	    {
	      vlib_cli_output (vm, "    TX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_tx_queue_info, a, q);
	    }
	}

      vec_foreach_pointer (cq, dev->crypto_queues)
	{
	  vlib_cli_output (vm, "  Crypto queue %u:", cq->index);
	  vlib_cli_output (vm, "    %U", format_vnet_dev_crypto_queue_info, a, cq);
	}
    }
  vec_free (devs);
  return 0;
}

VLIB_CLI_COMMAND (show_devices_cmd, static) = {
  .path = "show device",
  .short_help = "Show devices, ports and queues",
  .args =
    (cli_arg_t[]) {
      CLI_FLAG ("debug", .help = "show debug information"),
      CLI_KEYWORD ("debug-level", cli_type_u32, .flags = CLI_F_OPTIONAL,
		   .help = "level of the debug information"),
      CLI_VALUE ("device-id", cli_type_dev, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT,
		 .help = "only these devices"),
      {},
    },
  .handler = show_devices_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_device_counters_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_format_args_t fa = { .show_zero_counters = cli_flag (ctx, "all"),
				.clear = cli_flag (ctx, "clear") };
  vnet_dev_t **devs = dev_vector_from_ctx (ctx);

  vec_foreach_pointer (dev, devs)
    {
      vlib_cli_output (vm, "device '%s':", dev->device_id);
      foreach_vnet_dev_port (p, dev)
	{
	  vlib_cli_output (vm, "  Port %u:", p->port_id);
	  vlib_cli_output (vm, "    %U", format_vnet_dev_counters, &fa, p->counter_main);

	  foreach_vnet_dev_port_rx_queue (q, p)
	    {
	      vlib_cli_output (vm, "    RX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_counters, &fa, q->counter_main);
	    }

	  foreach_vnet_dev_port_tx_queue (q, p)
	    {
	      vlib_cli_output (vm, "    TX queue %u:", q->queue_id);
	      vlib_cli_output (vm, "      %U", format_vnet_dev_counters, &fa, q->counter_main);
	    }
	  if (fa.clear)
	    vnet_dev_process_call_port_op_no_rv (vm, p, vnet_dev_port_clear_counters);
	}

      vec_foreach_pointer (cq, dev->crypto_queues)
	{
	  vlib_cli_output (vm, "  Crypto queue %u:", cq->index);
	  vlib_cli_output (vm, "    %U", format_vnet_dev_crypto_queue_counters, &fa, cq);
	  if (fa.clear)
	    vnet_dev_crypto_queue_clear_counters (cq);
	}
    }

  vec_free (devs);
  return 0;
}

VLIB_CLI_COMMAND (show_device_counters_cmd, static) = {
  .path = "show device counters",
  .short_help = "Show the counters of devices, ports and queues",
  .args =
    (cli_arg_t[]) {
      CLI_FLAG ("all", .help = "show the counters which are zero"),
      CLI_FLAG ("clear", .help = "clear the counters after showing them"),
      CLI_VALUE ("device-id", cli_type_dev, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT,
		 .help = "only these devices"),
      {},
    },
  .handler = show_device_counters_cmd_fn,
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

  vlib_cli_output (vm, "%U", format_table, t);

  table_free (t);
  return 0;
}

VLIB_CLI_COMMAND (show_device_drivers_cmd, static) = {
  .path = "show device drivers",
  .short_help = "Show the loaded device drivers",
  .handler = show_device_drivers_cmd_fn,
  .is_mp_safe = 1,
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

static clib_error_t *
device_set_rss_config_cmd_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_api_port_set_rss_config_args_t a = {};
  cli_value_t *v;
  vnet_dev_rv_t rv;
  u32 sw_if_index = cli_index (ctx, "interface");

  if (sw_if_index != ~0)
    {
      vnet_dev_port_t *port = vnet_dev_get_port_from_sw_if_index (sw_if_index);

      if (port == 0)
	return clib_error_return (0, "unsupported interface");
      a.port_id = port->port_id;
      a.dev_index = port->dev->index;
    }
  else
    {
      a.port_id = cli_u64 (ctx, "port", 0);
      a.dev_index = cli_index (ctx, "dev");
    }

  if ((v = cli_get (ctx, "key")))
    {
      clib_memcpy (a.rss_config.key, v->str, vec_len (v->str));
      a.rss_config.key_len = vec_len (v->str);
      a.rss_config.set_key = 1;
    }

  if ((v = cli_get (ctx, "lut")))
    {
      clib_memcpy (a.rss_config.lut, v->str, vec_len (v->str) * sizeof (u16));
      a.rss_config.lut_len = vec_len (v->str);
      a.rss_config.set_lut = 1;
    }

  rv = vnet_dev_api_port_set_rss_config (vm, &a);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "unable to set RSS configuration: %U", format_vnet_dev_rv, rv);

  return 0;
}

VLIB_CLI_COMMAND (device_set_rss_config_cmd, static) = {
  .path = "device set-rss-config",
  .short_help = "Set the RSS key and the lookup table of a port",
  .args =
    (cli_arg_t[]) {
      CLI_ONEOF ("target", 0,
		 CLI_VALUE ("interface", cli_type_sw_interface, .help = "interface of the port"),
		 CLI_SEQ (CLI_KEYWORD ("dev", cli_type_dev, .help = "device of the port"),
			  CLI_KEYWORD ("port", cli_type_u32, .flags = CLI_F_OPTIONAL,
				       .help = "port id, default 0"))),
      CLI_KEYWORD ("key", cli_type_dev_rss_key, .flags = CLI_F_OPTIONAL),
      CLI_KEYWORD ("lut", cli_type_dev_rss_lut, .flags = CLI_F_OPTIONAL),
      {},
    },
  .handler = device_set_rss_config_cmd_fn,
  .is_mp_safe = 1,
};
