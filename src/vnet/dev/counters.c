/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/devices/devices.h>
#include <vnet/interface/rx_queue_funcs.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "counters",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U%s" f,                      \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

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

  return cm;
}

void
vnet_dev_counters_free (vlib_main_t *vm, vnet_dev_counter_main_t *cm)
{
  vec_free (cm->desc);
  vec_free (cm->counter_data);
  clib_mem_free (cm);
}

u8 *
format_vnet_dev_counter_name (u8 *s, va_list *va)
{
  vnet_dev_counter_t *c = va_arg (*va, vnet_dev_counter_t *);

  char *std_counters[] = {
    [VNET_DEV_COUNTER_TYPE_RX_BYTES] = "total bytes received",
    [VNET_DEV_COUNTER_TYPE_TX_BYTES] = "total bytes transmitted",
    [VNET_DEV_COUNTER_TYPE_RX_PACKETS] = "total packets received",
    [VNET_DEV_COUNTER_TYPE_TX_PACKETS] = "total packets transmitted",
    [VNET_DEV_COUNTER_TYPE_RX_DROPS] = "total drops received",
    [VNET_DEV_COUNTER_TYPE_TX_DROPS] = "total drops transmitted",
  };

  char *directions[] = {
    [VNET_DEV_COUNTER_DIR_RX] = "received",
    [VNET_DEV_COUNTER_DIR_TX] = "sent",
  };
  char *units[] = {
    [VNET_DEV_COUNTER_UNIT_BYTES] = "bytes",
    [VNET_DEV_COUNTER_UNIT_PACKETS] = "packets",
  };

  if (c->type == VNET_DEV_COUNTER_TYPE_VENDOR)
    {
      s = format (s, "%s", c->name);

      if (c->unit < ARRAY_LEN (units) && units[c->unit])
	s = format (s, " %s", units[c->unit]);

      if (c->dir < ARRAY_LEN (directions) && directions[c->dir])
	s = format (s, " %s", directions[c->dir]);
    }
  else if (c->type < ARRAY_LEN (std_counters) && std_counters[c->type])
    s = format (s, "%s", std_counters[c->type]);
  else
    ASSERT (0);

  return s;
}

static u8 *
_fmt_vnet_dev_cntrs (u8 *s, vnet_dev_counter_main_t *cm, int all)
{
  u32 line = 0, indent = format_get_indent (s);

  foreach_vnet_dev_counter (c, cm)
    {
      if (all == 0 && cm->counter_data[c->index] == 0)
	continue;

      if (line++)
	s = format (s, "\n%U", format_white_space, indent);

      s = format (s, "%-45U%lu", format_vnet_dev_counter_name, c,
		  cm->counter_data[c->index]);
    }

  return s;
}

u8 *
format_vnet_dev_counters (u8 *s, va_list *va)
{
  return _fmt_vnet_dev_cntrs (s, va_arg (*va, vnet_dev_counter_main_t *), 0);
}

u8 *
format_vnet_dev_counters_all (u8 *s, va_list *va)
{
  return _fmt_vnet_dev_cntrs (s, va_arg (*va, vnet_dev_counter_main_t *), 1);
}
