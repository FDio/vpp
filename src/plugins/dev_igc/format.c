/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vlib/pci/pci.h"
#include "vnet/error.h"
#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_igc/igc.h>
#include <dev_igc/igc_regs.h>

static u8 *
_format_igc_reg (u8 *s, u32 offset, u32 val, int no_zero, u32 mask)
{
  u32 indent = format_get_indent (s);
  u32 rv = 0, f, v;
  u8 *s2 = 0;
  int line = 0;

#define _(o, rn, m)                                                           \
  if (offset == o)                                                            \
    {                                                                         \
      if (line++)                                                             \
	s = format (s, "\n%U", format_white_space, indent);                   \
      vec_reset_length (s2);                                                  \
      s2 = format (s2, "[0x%05x] %s:", o, #rn);                               \
      rv = val;                                                               \
      s = format (s, "%-32v = 0x%08x", s2, rv);                               \
      f = 0;                                                                  \
      m                                                                       \
    }

#define __(l, fn)                                                             \
  v = (rv >> f) & pow2_mask (l);                                              \
  if ((pow2_mask (l) << f) & mask)                                            \
    if (v || (!no_zero && #fn[0] != '_'))                                     \
      {                                                                       \
	vec_reset_length (s2);                                                \
	s = format (s, "\n%U", format_white_space, indent + 2);               \
	s2 = format (s2, "[%2u:%2u] %s", f + l - 1, f, #fn);                  \
	s = format (s, "%-30v = ", s2);                                       \
	if (l < 3)                                                            \
	  s = format (s, "%u", v);                                            \
	else if (l <= 8)                                                      \
	  s = format (s, "0x%02x (%u)", v, v);                                \
	else if (l <= 16)                                                     \
	  s = format (s, "0x%04x", v);                                        \
	else                                                                  \
	  s = format (s, "0x%08x", v);                                        \
      }                                                                       \
  f += l;

  foreach_igc_reg;
#undef _

  vec_free (s2);

  return s;
}

u8 *
format_igc_reg_read (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_igc_reg (s, offset, val, 0, 0xffffffff);
}

u8 *
format_igc_reg_write (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_igc_reg (s, offset, val, 1, 0xffffffff);
}

u8 *
format_igc_reg_diff (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 old = va_arg (*args, u32);
  u32 new = va_arg (*args, u32);
  return _format_igc_reg (s, offset, new, 0, old ^ new);
}

u8 *
format_igc_port_status (u8 *s, va_list *args)
{
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  igc_port_t *ip = vnet_dev_get_port_data (port);
  u32 speed = 0;
  if (ip->last_status.speed_2p5)
    speed = 2500;
  else if (ip->last_status.speed < 3)
    speed = (u32[]){ 10, 100, 1000 }[ip->last_status.speed];

  s = format (s, "Link %s, speed %u Mbps, duplex %s",
	      ip->last_status.link_up ? "up" : "down", speed,
	      ip->last_status.full_duplex ? "full" : "half");
  return s;
}
