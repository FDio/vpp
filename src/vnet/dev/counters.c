/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/log.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vppinfra/format_table.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "counters",
};

vnet_dev_counter_main_t *
vnet_dev_counters_alloc (vlib_main_t *vm, vnet_dev_counter_t *counters,
			 u16 n_counters, char *fmt, ...)
{
  vnet_dev_counter_t *c;
  vnet_dev_counter_main_t *cm;
  u32 alloc_sz;

  alloc_sz = sizeof (*cm) + n_counters * sizeof (*c);
  cm = clib_mem_alloc_aligned (alloc_sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (cm, 0, sizeof (*cm));
  cm->n_counters = n_counters;

  if (fmt && strlen (fmt))
    {
      va_list va;
      va_start (va, fmt);
      cm->desc = va_format (0, fmt, &va);
      va_end (va);
    }

  for (u32 i = 0; i < n_counters; i++)
    {
      cm->counters[i] = counters[i];
      cm->counters[i].index = i;
    }

  vec_validate_aligned (cm->counter_data, n_counters - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (cm->counter_start, n_counters - 1,
			CLIB_CACHE_LINE_BYTES);

  return cm;
}

void
vnet_dev_counters_clear (vlib_main_t *vm, vnet_dev_counter_main_t *cm)
{
  for (int i = 0; i < cm->n_counters; i++)
    {
      cm->counter_start[i] += cm->counter_data[i];
      cm->counter_data[i] = 0;
    }
}

void
vnet_dev_counters_free (vlib_main_t *vm, vnet_dev_counter_main_t *cm)
{
  vec_free (cm->desc);
  vec_free (cm->counter_data);
  vec_free (cm->counter_start);
  clib_mem_free (cm);
}

u8 *
format_vnet_dev_counter_name (u8 *s, va_list *va)
{
  vnet_dev_counter_t *c = va_arg (*va, vnet_dev_counter_t *);

  if (c->type == VNET_DEV_CTR_TYPE_VENDOR)
    s = format (s, "%s", c->name);
  else if (c->type == VNET_DEV_CTR_TYPE_RX_DROPS || c->type == VNET_DEV_CTR_TYPE_TX_DROPS)
    s = format (s, "drops");
  else
    s = format (s, "total");

  return s;
}

u8 *
format_vnet_dev_counters (u8 *s, va_list *va)
{
  vnet_dev_format_args_t *a = va_arg (*va, vnet_dev_format_args_t *);
  vnet_dev_counter_main_t *cm = va_arg (*va, vnet_dev_counter_main_t *);
  table_t table = {}, *t = &table;
  u32 row = 0;
  char *units[] = {
    [VNET_DEV_CTR_UNIT_BYTES] = "bytes",
    [VNET_DEV_CTR_UNIT_PACKETS] = "packets",
    [VNET_DEV_CTR_UNIT_DESCRIPTORS] = "descriptors",
    [VNET_DEV_CTR_UNIT_BUFFERS] = "buffers",
    [VNET_DEV_CTR_UNIT_COMMANDS] = "commands",
  };
  char *directions[] = {
    [VNET_DEV_CTR_DIR_RX] = "rx",
    [VNET_DEV_CTR_DIR_TX] = "tx",
  };

  t->no_ansi = a->no_color;
  t->default_header_col.align = TTAA_LEFT;
  t->default_body.align = TTAA_LEFT;
  if (a->no_color == 0)
    {
      t->default_header_col.flags |= TTAF_FG_COLOR_SET;
      t->default_header_col.fg_color = TTAC_YELLOW;
    }
  table_add_header_col (t, 4, "dir", "counter", "value", "unit");
  table_set_cell_align (t, -1, 2, TTAA_RIGHT);

  foreach_vnet_dev_counter (c, cm)
    {
      if (a->show_zero_counters == 0 && cm->counter_data[c->index] == 0)
	continue;

      if (c->dir < ARRAY_LEN (directions) && directions[c->dir])
	table_format_cell (t, row, 0, "%s", directions[c->dir]);
      else
	table_format_cell (t, row, 0, "");
      table_format_cell (t, row, 1, "%U", format_vnet_dev_counter_name, c);
      table_format_cell (t, row, 2, "%llu", (unsigned long long) cm->counter_data[c->index]);
      if (c->unit < ARRAY_LEN (units) && units[c->unit])
	table_format_cell (t, row, 3, "%s", units[c->unit]);
      else
	table_format_cell (t, row, 3, "");
      row++;
    }

  if (row)
    s = format (s, "%U", format_table, t);
  table_free (t);

  return s;
}
