/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/perfmon/perfmon.h>
#include <vppinfra/format_table.h>

clib_perfmon_main_t clib_perfmon_main;

__clib_export clib_error_t *
clib_perfmon_init_by_bundle_name (clib_perfmon_ctx_t *ctx, char *fmt, ...)
{
  clib_perfmon_main_t *pm = &clib_perfmon_main;
  clib_perfmon_bundle_t *b = 0;
  int group_fd = -1;
  clib_error_t *err = 0;
  va_list va;
  char *bundle_name;

  struct perf_event_attr pe = {
    .size = sizeof (struct perf_event_attr),
    .disabled = 1,
    .exclude_kernel = 1,
    .exclude_hv = 1,
    .pinned = 1,
    .exclusive = 1,
    .read_format = (PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
		    PERF_FORMAT_TOTAL_TIME_RUNNING),
  };

  va_start (va, fmt);
  bundle_name = (char *) va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (bundle_name, 0);

  for (clib_perfmon_bundle_reg_t *r = pm->bundle_regs; r; r = r->next)
    {
      if (strncmp (r->bundle->name, bundle_name, vec_len (bundle_name) - 1))
	continue;
      b = r->bundle;
      break;
    }

  if (b == 0)
    {
      err = clib_error_return (0, "Unknown bundle '%s'", bundle_name);
      goto done;
    }

  clib_memset_u8 (ctx, 0, sizeof (clib_perfmon_ctx_t));
  vec_validate_init_empty (ctx->fds, b->n_events - 1, -1);
  ctx->bundle = b;

  for (int i = 0; i < b->n_events; i++)
    {
      pe.config = b->config[i];
      pe.type = b->type;
      int fd = syscall (__NR_perf_event_open, &pe, /* pid */ 0, /* cpu */ -1,
			/* group_fd */ group_fd, /* flags */ 0);
      if (fd < 0)
	{
	  err = clib_error_return_unix (0, "perf_event_open[%u]", i);
	  goto done;
	}

      if (ctx->debug)
	fformat (stderr, "perf event %u open, fd %d\n", i, fd);

      if (group_fd == -1)
	{
	  group_fd = fd;
	  pe.pinned = 0;
	  pe.exclusive = 0;
	}

      ctx->fds[i] = fd;
    }

  ctx->group_fd = group_fd;
  ctx->data = vec_new (u64, 3 + b->n_events);
  ctx->ref_clock = os_cpu_clock_frequency ();
  vec_validate (ctx->capture_groups, 0);

done:
  if (err)
    clib_perfmon_free (ctx);

  vec_free (bundle_name);
  return err;
}

__clib_export void
clib_perfmon_free (clib_perfmon_ctx_t *ctx)
{
  clib_perfmon_clear (ctx);
  vec_free (ctx->captures);
  vec_free (ctx->capture_groups);

  for (int i = 0; i < vec_len (ctx->fds); i++)
    if (ctx->fds[i] > -1)
      close (ctx->fds[i]);
  vec_free (ctx->fds);
  vec_free (ctx->data);
}

__clib_export void
clib_perfmon_clear (clib_perfmon_ctx_t *ctx)
{
  for (int i = 0; i < vec_len (ctx->captures); i++)
    vec_free (ctx->captures[i].desc);
  vec_reset_length (ctx->captures);
  for (int i = 0; i < vec_len (ctx->capture_groups); i++)
    vec_free (ctx->capture_groups[i].name);
  vec_reset_length (ctx->capture_groups);
}

__clib_export u64 *
clib_perfmon_capture (clib_perfmon_ctx_t *ctx, u32 n_ops, char *fmt, ...)
{
  u32 read_size = (ctx->bundle->n_events + 3) * sizeof (u64);
  clib_perfmon_capture_t *c;
  u64 d[CLIB_PERFMON_MAX_EVENTS + 3];
  va_list va;

  if ((read (ctx->group_fd, d, read_size) != read_size))
    {
      if (ctx->debug)
	fformat (stderr, "reading of %u bytes failed, %s (%d)\n", read_size,
		 strerror (errno), errno);
      return 0;
    }

  if (ctx->debug)
    {
      fformat (stderr, "read events: %lu enabled: %lu running: %lu ", d[0],
	       d[1], d[2]);
      fformat (stderr, "data: [%lu", d[3]);
      for (int i = 1; i < ctx->bundle->n_events; i++)
	fformat (stderr, ", %lu", d[i + 3]);
      fformat (stderr, "]\n");
    }

  vec_add2 (ctx->captures, c, 1);

  va_start (va, fmt);
  c->desc = va_format (0, fmt, &va);
  va_end (va);

  c->n_ops = n_ops;
  c->group = vec_len (ctx->capture_groups) - 1;
  c->time_enabled = d[1];
  c->time_running = d[2];
  for (int i = 0; i < CLIB_PERFMON_MAX_EVENTS; i++)
    c->data[i] = d[i + 3];

  return ctx->data + vec_len (ctx->data) - ctx->bundle->n_events;
}

__clib_export void
clib_perfmon_capture_group (clib_perfmon_ctx_t *ctx, char *fmt, ...)
{
  clib_perfmon_capture_group_t *cg;
  va_list va;

  cg = vec_end (ctx->capture_groups) - 1;

  if (cg->name != 0)
    vec_add2 (ctx->capture_groups, cg, 1);

  va_start (va, fmt);
  cg->name = va_format (0, fmt, &va);
  va_end (va);
  ASSERT (cg->name);
}

__clib_export void
clib_perfmon_warmup (clib_perfmon_ctx_t *ctx)
{
  for (u64 i = 0; i < (u64) ctx->ref_clock; i++)
    asm volatile("" : : "r"(i * i) : "memory");
}

__clib_export u8 *
format_perfmon_bundle (u8 *s, va_list *args)
{
  clib_perfmon_ctx_t *ctx = va_arg (*args, clib_perfmon_ctx_t *);
  clib_perfmon_capture_t *c;
  clib_perfmon_capture_group_t *cg = 0;
  char **hdr = ctx->bundle->column_headers;
  table_t _t = {}, *t = &_t;
  u32 n_row = 0, col = 0;

  table_add_header_row (t, 0);

  for (char **h = ctx->bundle->column_headers; h[0]; h++)
    n_row++;

  vec_foreach (c, ctx->captures)
    {
      if (cg != ctx->capture_groups + c->group)
	{
	  cg = ctx->capture_groups + c->group;
	  table_format_cell (t, col, -1, "%v", cg->name);
	  table_set_cell_align (t, col, -1, TTAA_LEFT);
	  table_set_cell_fg_color (t, col, -1, TTAC_BRIGHT_RED);

	  table_format_cell (t, col, 0, "Ops");
	  table_set_cell_fg_color (t, col, 0, TTAC_BRIGHT_YELLOW);

	  for (int i = 0; i < n_row; i++)
	    {
	      table_format_cell (t, col, i + 1, "%s", hdr[i]);
	      table_set_cell_fg_color (t, col, i + 1, TTAC_BRIGHT_YELLOW);
	    }
	  col++;
	}
      table_format_cell (t, col, -1, "%v", c->desc);
      table_format_cell (t, col, 0, "%7u", c->n_ops);
      for (int i = 0; i < n_row; i++)
	table_format_cell (t, col, i + 1, "%U", ctx->bundle->format_fn, ctx, c,
			   i);
      col++;
    }

  s = format (s, "%U", format_table, t);
  table_free (t);
  return s;
}
