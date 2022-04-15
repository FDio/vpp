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
format_dma (u8 *s, va_list *args)
{
  vlib_dma_backend_t *backend = va_arg (*args, vlib_dma_backend_t *);
  int verbose = va_arg (*args, int);

  s = format (s, "%-12s%-5s%-10s%-15s%-12s", "NAME", "Sock", "Transfers",
	      "Transfer Size", "Instance");
  s = format (s, "\n%-12s%-5d%-10d%-15d%-12p", backend->name,
	      backend->status.cap.numa_node, backend->status.cap.max_transfers,
	      backend->status.cap.max_transfer_size, backend->ctx);

  if (verbose)
    {
      if (backend->status.state == DMA_BACKEND_ASSIGNED)
	{
	  s = format (s, "\n\t    Assigned to thread %d",
		      backend->status.thread_index);
	}
      else
	s = format (s, "\n\t    Unassigned");
      s = format (s, "\n\t    %U", format_dma_cap, &backend->status.cap);
    }

  return s;
}

u8 *
format_config_stats (u8 *s, va_list *args)
{
  vlib_dma_config_t *config = va_arg (*args, vlib_dma_config_t *);
  s = format (s, "%-10d%-10d\n", config->n_transfers, config->n_bytes);
  return s;
}

/**
 * Format DMA thread info as per the following format
 *
 * verbose:
 *   "Thread", "Configs"
 *       "Transfers", "Bytes"
 * non-verbose:
 *   "Thread", "Configs"
 */
u8 *
format_thread (u8 *s, va_list *args)
{
  vlib_dma_thread_t *thread = va_arg (*args, vlib_dma_thread_t *);
  int verbose = va_arg (*args, int);
  vlib_dma_config_t **config;
  if (vec_len (thread->reg_configs))
    {
      s = format (s, "%-12s%-10s\n", "Thread ID", "Configs");
      s = format (s, "%-12d%-10d\n", thread->thread_index,
		  vec_len (thread->reg_configs));

      if (verbose)
	{
	  s = format (s, "\t    %-10s%-10s\n", "Transfers", "Bytes");
	  vec_foreach (config, thread->reg_configs)
	    {
	      s = format (s, "\t    %U\n", format_config_stats, *config);
	    }
	}
    }

  return s;
}

static void
dma_cli_show_all_dmas (vlib_main_t *vm, int verbose)
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
      vlib_cli_output (vm, "%U", format_dma, backend, verbose);
    }
  return;
}

static void
dma_cli_show_all_configs (vlib_main_t *vm, int verbose)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_thread_t *thread;
  u32 thread_index;

  for (thread_index = 0; thread_index < vec_len (dm->threads); thread_index++)
    {
      thread = dm->threads + thread_index;
      vlib_cli_output (vm, "%U", format_thread, thread, verbose);
    }
  return;
}

static clib_error_t *
show_dma_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  int verbose = 0, thread = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      dma_cli_show_all_dmas (vm, 0);
      dma_cli_show_all_configs (vm, 0);
      return 0;
    }
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "verbose %d", &verbose))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else if (unformat (line_input, "thread"))
	thread = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
  dma_cli_show_all_dmas (vm, verbose);
  if (thread)
    dma_cli_show_all_configs (vm, verbose);

  vlib_dma_release (vm, 0);
done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (vlib_cli_show_dma_command) = {
  .path = "show dma",
  .short_help = "show dma [verbose [n]] [thread] ",
  .function = show_dma_command_fn,
};
