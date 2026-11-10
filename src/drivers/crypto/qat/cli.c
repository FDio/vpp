/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/dev_funcs.h>
#include <qat.h>

static clib_error_t *
qat_show_ring_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_dev_t *dev = 0;
  u8 *dev_id = 0;
  u32 queue = 0, count = 4;
  clib_error_t *err = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue %u", &queue))
	;
      else if (unformat (input, "count %u", &count))
	;
      else if (unformat (input, "%s", &dev_id))
	;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (dev_id)
    {
      vec_add1 (dev_id, 0);
      dev = vnet_dev_by_id ((char *) dev_id);
      vec_free (dev_id);
    }

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
  .short_help = "show device driver qat ring <device-id> [queue <n>] [count <n>]",
  .function = qat_show_ring_fn,
};

static clib_error_t *
qat_show_session_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 index = ~0;

  if (!unformat (input, "%u", &index) || pool_is_free_index (cm->ctxs, index))
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
  .short_help = "show device driver qat session <crypto-context-index>",
  .function = qat_show_session_fn,
};
