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

  char *std_counters[] = {
    [VNET_DEV_CTR_TYPE_RX_BYTES] = "total bytes received",
    [VNET_DEV_CTR_TYPE_TX_BYTES] = "total bytes transmitted",
    [VNET_DEV_CTR_TYPE_RX_PACKETS] = "total packets received",
    [VNET_DEV_CTR_TYPE_TX_PACKETS] = "total packets transmitted",
    [VNET_DEV_CTR_TYPE_RX_DROPS] = "total drops received",
    [VNET_DEV_CTR_TYPE_TX_DROPS] = "total drops transmitted",
  };

  if (c->type == VNET_DEV_CTR_TYPE_VENDOR)
    s = format (s, "%s", c->name);
  else if (c->type < ARRAY_LEN (std_counters) && std_counters[c->type])
    s = format (s, "%s", std_counters[c->type]);
  else
    ASSERT (0);

  return s;
}

u8 *
format_vnet_dev_counters (u8 *s, va_list *va)
{
  vnet_dev_format_args_t *a = va_arg (*va, vnet_dev_format_args_t *);
  vnet_dev_counter_main_t *cm = va_arg (*va, vnet_dev_counter_main_t *);
  table_t table = {};
  u32 row = 0, line = 0, indent = format_get_indent (s);
  u64 standard[VNET_DEV_CTR_TYPE_VENDOR] = {};
  u8 present[VNET_DEV_CTR_TYPE_VENDOR] = {};
  struct
  {
    vnet_dev_counter_type_t bytes, packets, drops;
    char *direction;
  } groups[] = {
    {
      VNET_DEV_CTR_TYPE_RX_BYTES,
      VNET_DEV_CTR_TYPE_RX_PACKETS,
      VNET_DEV_CTR_TYPE_RX_DROPS,
      "received",
    },
    {
      VNET_DEV_CTR_TYPE_TX_BYTES,
      VNET_DEV_CTR_TYPE_TX_PACKETS,
      VNET_DEV_CTR_TYPE_TX_DROPS,
      "transmitted",
    },
  };
  char *directions[] = {
    [VNET_DEV_CTR_DIR_RX] = "rx",
    [VNET_DEV_CTR_DIR_TX] = "tx",
  };
  char *units[] = {
    [VNET_DEV_CTR_UNIT_BYTES] = "bytes",
    [VNET_DEV_CTR_UNIT_PACKETS] = "packets",
    [VNET_DEV_CTR_UNIT_DESCRIPTORS] = "descriptors",
    [VNET_DEV_CTR_UNIT_BUFFERS] = "buffers",
  };

  table_add_hdr_row (&table, 4, "Name", "Dir", "Unit", "Count");
  table_add_hdr_col (&table, 0);
  table_set_cell_align (&table, -1, -1, TTAA_LEFT);
  table_set_cell_align (&table, -1, 2, TTAA_RIGHT);

  foreach_vnet_dev_counter (c, cm)
    {
      if (c->type != VNET_DEV_CTR_TYPE_VENDOR)
	{
	  ASSERT (c->type < ARRAY_LEN (standard));
	  standard[c->type] = cm->counter_data[c->index];
	  present[c->type] = 1;
	  continue;
	}

      if (a->show_zero_counters == 0 && cm->counter_data[c->index] == 0)
	continue;

      table_format_cell (&table, row, -1, "%U", format_vnet_dev_counter_name, c);
      table_set_cell_align (&table, row, -1, TTAA_LEFT);
      table_format_cell (
	&table, row, 0, "%s",
	c->dir < ARRAY_LEN (directions) && directions[c->dir] ? directions[c->dir] : "");
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      table_format_cell (&table, row, 1, "%s",
			 c->unit < ARRAY_LEN (units) && units[c->unit] ? units[c->unit] : "");
      table_set_cell_align (&table, row, 1, TTAA_LEFT);
      table_format_cell (&table, row, 2, "%lu", cm->counter_data[c->index]);
      row++;
    }

  for (u32 i = 0; i < ARRAY_LEN (groups); i++)
    {
      u64 packets = standard[groups[i].packets];
      u64 bytes = standard[groups[i].bytes];
      u64 drops = standard[groups[i].drops];
      u8 show_traffic =
	packets || bytes ||
	(a->show_zero_counters && (present[groups[i].packets] || present[groups[i].bytes]));
      u8 show_drops = drops || (a->show_zero_counters && present[groups[i].drops]);

      if (!show_traffic && !show_drops)
	continue;
      if (line++)
	s = format (s, "\n%U", format_white_space, indent);
      if (show_traffic)
	s = format (s, "%lu packets %s, %lu bytes", packets, groups[i].direction, bytes);
      if (show_drops)
	{
	  if (show_traffic)
	    s = format (s, ", %lu drops", drops);
	  else
	    s = format (s, "%lu drops %s", drops, groups[i].direction);
	}
    }

  if (row)
    {
      if (line)
	s = format (s, "\n%U", format_white_space, indent);
      s = format (s, "Hardware Counters:\n%U%U", format_white_space, indent + 2, format_table,
		  &table);
    }
  else if (line == 0)
    s = format (s, "none");

  table_free (&table);

  return s;
}
