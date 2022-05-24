/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/dma/dma.h>

static clib_error_t *
show_dma_backends_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  vlib_dma_main_t *dm = &vlib_dma_main;

  if (vec_len (dm->backends))
    {
      vlib_dma_backend_t *b;
      vec_foreach (b, dm->backends)
	vlib_cli_output (vm, "%s", b->name);
    }
  else
    vlib_cli_output (vm, "No active DMA backends");

  return 0;
}

VLIB_CLI_COMMAND (avf_create_command, static) = {
  .path = "show dma backends",
  .short_help = "show dma backends",
  .function = show_dma_backends_command_fn,
};

static clib_error_t *
test_dma_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  vlib_dma_config_t cfg = { .max_transfers = 16, .max_transfer_size = 768 };
  vlib_dma_batch_t *b;
  int config_index = -1;
  u32 rsz, n_alloc, v;
  u8 *from = 0, *to = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "transfers %u", &v))
	cfg.max_transfers = v;
      else if (unformat (input, "size %u", &v))
	cfg.max_transfer_size = v;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if ((config_index = vlib_dma_config_add (vm, &cfg)) < 0)
    {
      err = clib_error_return (0, "Unable to allocate dma config");
      goto done;
    }

  rsz = round_pow2 (cfg.max_transfer_size, CLIB_CACHE_LINE_BYTES);
  n_alloc = rsz * cfg.max_transfers * 2;

  if ((from = vlib_physmem_alloc (vm, n_alloc)) == 0)
    {
      err = clib_error_return (0, "Unable to allocate %u bytes of physmem",
			       n_alloc);
      goto done;
    }
  to = from + n_alloc / 2;

  b = vlib_dma_batch_new (vm, config_index);
  vlib_dma_batch_set_cookie (vm, b, 0x12345678);

  for (int i = 0; i < cfg.max_transfers; i++)
    vlib_dma_batch_add (vm, b, to + i * rsz, from + i * rsz,
			cfg.max_transfer_size);

  vlib_dma_batch_submit (vm, b);

done:
  if (config_index != CLIB_U32_MAX)
    vlib_dma_config_del (vm, config_index);
  if (from)
    vlib_physmem_free (vm, from);
  return err;
}

VLIB_CLI_COMMAND (test_dma_command, static) = {
  .path = "test dma",
  .short_help = "test dma [transfers <x>]",
  .function = test_dma_command_fn,
};
