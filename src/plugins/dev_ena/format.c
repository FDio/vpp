/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vlib/pci/pci.h"
#include "vnet/error.h"
#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_ena/ena.h>

u8 *
format_ena_dev_info (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  ena_device_t *ed = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);
  format (s, "Elastic Network Adapter:");
  format (s, "\n%UDevice version is %u, implementation id is %u",
	  format_white_space, indent + 2, ed->dev_attr.device_version,
	  ed->dev_attr.impl_id);
  format (s, "\n%Urx drops %lu, tx drops %lu", format_white_space, indent + 2,
	  ed->aenq.rx_drops, ed->aenq.tx_drops);
  format (s, "\n%ULast keepalive was ", format_white_space, indent + 2);
  if (ed->aenq.last_keepalive != 0.0)
    format (s, "%.1f seconds ago",
	    vlib_time_now (vlib_get_main ()) - ed->aenq.last_keepalive);
  else
    format (s, "never");
  return s;
}

u8 *
format_ena_mem_addr (u8 *s, va_list *args)
{
  ena_mem_addr_t *ema = va_arg (*args, ena_mem_addr_t *);
  return format (s, "0x%lx", (u64) ema->addr_hi << 32 | ema->addr_lo);
}
