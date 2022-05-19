/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 * Copyright (c) 2022 Intel and/or its affiliates.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vlib/dma/dma.h>

/**
 * Format DMA backend as per the following format
 *
 * verbose:
 *   "NAME", "Sock", "Transfers", "Transfer Size", "Instance"
 *   "Assigned thread", "Service configs",
 *   "Capability"
 * non-verbose:
 *   "NAME", "Sock", "Transfers", "Transfer Size", "Instance"
 */
u8 *
format_dma_cap (u8 *s, va_list *args)
{
  vlib_dma_cap_t *cap = va_arg (*args, vlib_dma_cap_t *);
  s =
    format (s, "Capabilites: %s %s ", cap->dma_cap & DMA_CAPA_SVA ? "SVA" : "",
	    cap->dma_cap & DMA_CAPA_SCATTER_GATHER ? "| SCATTER_GATHER" : "");
  s = format (s, "transfer: %d size: %d ordered: %s\n", cap->max_transfers,
	      cap->max_transfer_size, cap->ordered ? "true" : "false");
  return s;
}

u8 *
format_backend (u8 *s, va_list *args)
{
  vlib_dma_backend_t *backend = va_arg (*args, vlib_dma_backend_t *);
  int verbose = va_arg (*args, int);

  s = format (s, "\n%-12s%-12s%-12s%-12s%-16s%-16s", "NAME", "ID", "Sock",
	      "Transfers", "Transfer Size", "Instance");
  s = format (s, "\n%-12s%-12d%-12d%-12d%-16d%-16p\n", backend->name,
	      backend - dma_main.backends, backend->cap.numa_node,
	      backend->cap.max_transfers, backend->cap.max_transfer_size,
	      backend->instance);

  if (verbose)
    s = format (s, "\n\t    %U", format_dma_cap, &backend->cap);

  return s;
}

/**
 * Format DMA config info as per the following format
 *
 * verbose:
 *   "Configs"
 *        "ID", "Backend ID", "Data Addr", "Results Addr"
 *        "Template", "stride", "src_offset", "dst_offset", "size_offset"
 *        "Transfers", "Bytes"
 * non-verbose:
 *   "Thread", "Configs"
 */
u8 *
format_config (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_dma_config_t *config = va_arg (*args, vlib_dma_config_t *);
  int verbose = va_arg (*args, int);
  u32 config_index = config - dma_main.configs;
  vlib_dma_stats_t stats;

  s = format (s, "%-12s%-12s\n", "ID", "Backend ID");
  s = format (s, "%-12d%-12d\n", config - dma_main.configs,
	      config->backend_index);

  s = format (s, "%-12s%-12s%-12s%-12s%-12s\n", "Template:", "stride",
	      "src_offset", "dst_offset", "size_offset");
  s = format (s, "%-12s%-12d%-12d%-12d%-12d\n", "", config->template->stride,
	      config->template->src_ptr_offset,
	      config->template->dst_ptr_offset, config->template->size_offset);
  if (!vlib_dma_get_stats (vm, config_index, &stats))
    s = format (s, "Submitted: %ld Completed: %ld CPU fallback: %ld\n",
		stats.submitted, stats.completed, stats.fallback);
  if (verbose)
    s = vlib_dma_dump_info (vm, config_index, s);

  return s;
}

static void
dma_cli_show_all_backends (vlib_main_t *vm, int verbose)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_backend_t *backend;
  if (!vec_len (dm->backends))
    {
      vlib_cli_output (vm, "No DMA engine registered");
      return;
    }

  vec_foreach (backend, dm->backends)
    {
      vlib_cli_output (vm, "%U", format_backend, backend, verbose);
    }
  return;
}

static void
dma_cli_show_all_configs (vlib_main_t *vm, int verbose)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_config_t *config;
  if (!vec_len (dm->configs))
    {
      vlib_cli_output (vm, "No config registered");
      return;
    }

  vec_foreach (config, dm->configs)
    {
      vlib_cli_output (vm, "%U", format_config, vm, config, verbose);
    }

  return;
}

static clib_error_t *
show_dma_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  int verbose = 0, backends = 0, configs = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      dma_cli_show_all_backends (vm, 0);
      dma_cli_show_all_configs (vm, 0);
      return 0;
    }
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "verbose %d", &verbose))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else if (unformat (line_input, "backends"))
	backends = 1;
      else if (unformat (line_input, "configs"))
	configs = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (backends)
    dma_cli_show_all_backends (vm, verbose);
  if (configs)
    dma_cli_show_all_configs (vm, verbose);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (vlib_cli_show_dma_command) = {
  .path = "show dma",
  .short_help = "show dma [backends] [configs] [verbose [n]] [thread] ",
  .function = show_dma_command_fn,
};

void
fill_random_data (void *buffer, uword size, uword transfers)
{
  uword loop = transfers;
  uword seed = random_default_seed ();
  uword offset = 0;

  clib_random_buffer_t rb;
  clib_random_buffer_init (&rb, seed);

  while (loop > 0)
    {
      clib_random_buffer_fill (&rb, size);
      void *rbuf = clib_random_buffer_get_data (&rb, size);
      clib_memcpy_fast (buffer + offset, rbuf, size);
      clib_random_buffer_free (&rb);

      offset += size;
      loop--;
    }

  return;
}

static void
dma_benchmark_result (vlib_main_t *vm, u32 size, u32 transfers, uword elapsed)
{
  vlib_cli_output (vm, "%-24s%-24s%-24s%-24s", "Copy length(B)",
		   "Throughput(Mb/s)", "IOPS", "Latency(ns)");
  uword total_size = size * transfers;
  double throughput = total_size * (1e6) / (1 << 20) * (1e3) / elapsed * 8;
  double iops = 1e9 * transfers / elapsed;
  double latency = 1.0 * elapsed / transfers;
  vlib_cli_output (vm, "\n%-24d%-24.2f%-24.2f%-24.2f", size, throughput, iops,
		   latency);
}

#define TRANSFER_BATCH_SIZE 256
static clib_error_t *
test_dma (vlib_main_t *vm, unformat_input_t *input,
	  vlib_cli_command_t *cmd_arg)
{
  u32 transfers = 256, size = 4096, cnt, remains;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  vlib_dma_config_args_t args;
  vlib_dma_completion_cb_fn_t cb = NULL;
  vlib_dma_transfer_template_t template;
  int i, config_index = -1;
  uword offset = 0, cookie = 0;
  void *src = NULL, *dst = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "num-transfers %d", &transfers))
	;
      else if (unformat (line_input, "transfer-size %d", &size))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  remains = transfers;
  args.max_transfers = 2;
  args.max_transfer_size = TRANSFER_BATCH_SIZE;
  args.cpu_fallback = 0;
  args.barrier_before_last = 0;
  args.cb = cb;
  args.template = &template;
  config_index = vlib_dma_config (vm, &args);
  if (config_index < 0)
    {
      error = clib_error_return (0, "No config suitable for test");
      goto done;
    }

  /* prepare two hugepages */
  uword log2_page_size = clib_mem_get_log2_default_hugepage_size ();
  uword page_size = 1 << log2_page_size;
  ASSERT (page_size >= (uword) size * transfers);

  src = clib_mem_vm_map (0, page_size, log2_page_size, "Source");
  if (src == CLIB_MEM_VM_MAP_FAILED)
    {
      error = clib_error_return (0, "Error: Hugepage map failed!");
      goto done;
    }
  dst = clib_mem_vm_map (0, page_size, log2_page_size, "Destination");
  if (dst == CLIB_MEM_VM_MAP_FAILED)
    {
      error = clib_error_return (0, "Error: Hugepage map failed!");
      goto done;
    }

  fill_random_data (src, size, transfers);
  fill_random_data (dst, size, transfers);

  u64 start_time, end_time;
  start_time = unix_time_now_nsec ();

  do
    {
      cnt = clib_min (remains, TRANSFER_BATCH_SIZE);
      for (i = 0; i < cnt; i++)
	{
	  offset += i * size;
	  vlib_dma_add_transfer (&template, dst + offset, src + offset, size);
	}
      remains -= cnt;
      while (vlib_dma_transfer (vm, config_index, cnt, 0))
	;

      while (!vlib_dma_get_completed (vm, config_index, &cb, &cookie))
	;
    }
  while (remains);

  end_time = unix_time_now_nsec ();
  dma_benchmark_result (vm, size, transfers, end_time - start_time);

  if (clib_memcmp (dst, src, size * transfers))
    {
      clib_error_return (0, "DMA transfer check failed");
      goto done;
    }

  vlib_cli_output (vm, "\nCPU reference");
  start_time = unix_time_now_nsec ();
  for (int i = 0; i != transfers; ++i)
    {
      uword offset = (uword) size * i;
      clib_memcpy_fast (dst + offset, src + offset, size);
    }

  end_time = unix_time_now_nsec ();
  dma_benchmark_result (vm, size, transfers, end_time - start_time);

done:
  if (src)
    clib_mem_vm_unmap (src);
  if (dst)
    clib_mem_vm_unmap (dst);
  if (config_index >= 0)
    vlib_dma_release (vm, config_index);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (test_dma_command, static) = {
  .path = "test dma",
  .short_help = "test dma [num-transfers <n>] [transfer-size <n>]",
  .function = test_dma,
};
