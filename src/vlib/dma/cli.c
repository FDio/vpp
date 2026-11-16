/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/physmem_funcs.h>
#include <vlib/dma/dma.h>

static clib_error_t *
show_dma_backends_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
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
  .handler = show_dma_backends_command_fn,
};

static void
test_dma_cb_fn (vlib_main_t *vm, vlib_dma_batch_t *b)
{
  fformat (stderr, "%s: cb %p cookie %lx\n", __func__, b,
	   vlib_dma_batch_get_cookie (vm, b));
}

static clib_error_t *
fill_random_data (void *buffer, uword size)
{
  uword seed = random_default_seed ();

  uword remain = size;
  const uword p = clib_mem_get_page_size ();
  uword offset = 0;

  clib_random_buffer_t rb;
  clib_random_buffer_init (&rb, seed);

  while (remain > 0)
    {
      uword fill_size = clib_min (p, remain);

      clib_random_buffer_fill (&rb, fill_size);
      void *rbuf = clib_random_buffer_get_data (&rb, fill_size);
      clib_memcpy_fast (buffer + offset, rbuf, fill_size);
      clib_random_buffer_free (&rb);

      offset += fill_size;
      remain -= fill_size;
    }

  return 0;
}

static clib_error_t *
test_dma_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  clib_error_t *err = 0;
  vlib_dma_batch_t *b;
  int config_index = -1;
  u32 rsz, n_alloc;
  u8 *from = 0, *to = 0;
  vlib_dma_config_t cfg = { .max_transfers = cli_u64 (ctx, "transfers", 256),
			    .max_transfer_size = cli_u64 (ctx, "size", 4096),
			    .callback_fn = test_dma_cb_fn };

  if ((config_index = vlib_dma_config_add (vm, &cfg)) < 0)
    {
      err = clib_error_return (0, "Unable to allocate dma config");
      return err;
    }

  rsz = round_pow2 (cfg.max_transfer_size, CLIB_CACHE_LINE_BYTES);
  n_alloc = rsz * cfg.max_transfers * 2;

  if ((from = vlib_physmem_alloc_aligned_on_numa (
	 vm, n_alloc, CLIB_CACHE_LINE_BYTES, vm->numa_node)) == 0)
    {
      err = clib_error_return (0, "Unable to allocate %u bytes of physmem",
			       n_alloc);
      return err;
    }
  to = from + n_alloc / 2;

  u32 port_allocator_seed;

  fill_random_data (from, (uword) cfg.max_transfers * rsz);

  b = vlib_dma_batch_new (vm, config_index);
  vlib_dma_batch_set_cookie (vm, b, 0x12345678);

  port_allocator_seed = clib_cpu_time_now ();
  int transfers = random_u32 (&port_allocator_seed) % cfg.max_transfers;
  if (!transfers)
    transfers = 1;
  for (int i = 0; i < transfers; i++)
    vlib_dma_batch_add (vm, b, to + i * rsz, from + i * rsz,
			cfg.max_transfer_size);

  vlib_dma_batch_submit (vm, b);
  return err;
}

static clib_error_t *
test_show_dma_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  clib_error_t *err = 0;
  int config_index = cli_u64 (ctx, "config", 0);

  for (u32 i = 0; i < vlib_get_n_threads (); i++)
    vlib_cli_output (vm, "Config %d %U", config_index, vlib_dma_config_info,
		     config_index, vlib_get_main_by_index (i));
  return err;
}

VLIB_CLI_COMMAND (test_dma_command, static) = {
  .path = "test dma",
  .short_help = "Test the DMA",
  .args =
    (cli_arg_t[]) {
      CLI_KEYWORD ("transfers", cli_type_u32, .flags = CLI_F_OPTIONAL,
		   .help = "number of transfers, default 256"),
      CLI_KEYWORD ("size", cli_type_u32, .flags = CLI_F_OPTIONAL,
		   .help = "size of a transfer, default 4096"),
      {},
    },
  .handler = test_dma_command_fn,
};

VLIB_CLI_COMMAND (show_dma_command, static) = {
  .path = "show dma",
  .short_help = "Show a DMA config",
  .args =
    (cli_arg_t[]) {
      CLI_KEYWORD ("config", cli_type_u32, .flags = CLI_F_OPTIONAL, .help = "config index"),
      {},
    },
  .handler = test_show_dma_fn,
};
