/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/dev_funcs.h>
#include <qat.h>

static clib_error_t *
qat_show_ring_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_dev_t *dev;
  u8 *dev_id = vec_dup (cli_get (ctx, "device-id")->str);
  u32 queue = cli_u64 (ctx, "queue", 0), count = cli_u64 (ctx, "count", 4);
  clib_error_t *err = 0;

  vec_add1 (dev_id, 0);
  dev = vnet_dev_by_id ((char *) dev_id);
  vec_free (dev_id);

  if (dev == 0 || strcmp (vnet_dev_main.drivers[dev->driver_index].registration->name, "qat"))
    return clib_error_return (0, "please specify a qat device id");

  if (queue >= vec_len (dev->crypto_queues))
    return clib_error_return (0, "device has %u crypto queues", vec_len (dev->crypto_queues));

  u8 *s = vnet_dev_format_in_process (0, dev, "%U", format_qat_ring_dump, dev->crypto_queues[queue],
				      count);
  vlib_cli_output (vm, "%v", s);
  vec_free (s);

  return err;
}

VLIB_CLI_COMMAND (qat_show_ring_cmd, static) = {
  .path = "show device driver qat ring",
  .short_help = "Dump the descriptor ring of a qat crypto queue",
  .args = CLI_ARGS (
    CLI_VALUE ("device-id", cli_type_string, .help = "id of the device, e.g. pci/0000:3d:01.0"),
    CLI_OPT_KEYWORD ("queue", cli_type_u32, .help = "crypto queue, default 0"),
    CLI_OPT_KEYWORD ("count", cli_type_u32, .help = "number of descriptors, default 4")),
  .handler = qat_show_ring_fn,
};

static clib_error_t *
qat_show_session_fn (vlib_main_t *vm, cli_ctx_t *cli)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 index = cli_u64 (cli, "crypto-context-index", ~0);

  if (pool_is_free_index (cm->ctxs, index))
    return clib_error_return (0, "please specify a valid crypto context index");

  vnet_crypto_ctx_t *ctx = cm->ctxs[index];
  vnet_dev_crypto_engine_t *e =
    vnet_dev_crypto_get_engine (vnet_crypto_ctx_get_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_ASYNC));
  if (e == 0 || strcmp (vnet_dev_main.drivers[e->driver_index].registration->name, "qat"))
    return clib_error_return (0, "context %u does not use the qat async engine", index);

  qat_key_t *k = (qat_key_t *) vnet_crypto_get_async_key_data (ctx);

  if (k->cd == 0)
    return clib_error_return (0, "context %u has no qat session", index);

  vlib_cli_output (vm, "%U", format_qat_session, k, ctx->alg);
  return 0;
}

VLIB_CLI_COMMAND (qat_show_session_cmd, static) = {
  .path = "show device driver qat session",
  .short_help = "Show the qat session of a crypto context",
  .args = CLI_ARGS (CLI_VALUE ("crypto-context-index", cli_type_u32)),
  .handler = qat_show_session_fn,
};
