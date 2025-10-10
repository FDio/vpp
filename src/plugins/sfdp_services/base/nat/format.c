/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/nat/nat.h>

static u8 *
format_sfdp_nat_rewrite_SADDR (u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg (*args, nat_rewrite_data_t *);
  s = format (s, "%U", format_ip4_address, &rewrite->rewrite.saddr);
  return s;
}

static u8 *
format_sfdp_nat_rewrite_SPORT (u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg (*args, nat_rewrite_data_t *);
  s = format (s, "%u", clib_net_to_host_u16 (rewrite->rewrite.sport));
  return s;
}

static u8 *
format_sfdp_nat_rewrite_DADDR (u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg (*args, nat_rewrite_data_t *);
  s = format (s, "%U", format_ip4_address, &rewrite->rewrite.daddr);
  return s;
}
static u8 *
format_sfdp_nat_rewrite_DPORT (u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg (*args, nat_rewrite_data_t *);
  s = format (s, "%u", clib_net_to_host_u16 (rewrite->rewrite.dport));
  return s;
}
static u8 *
format_sfdp_nat_rewrite_ICMP_ID (u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg (*args, nat_rewrite_data_t *);
  s = format (s, "%u", rewrite->rewrite.icmp_id);
  return s;
}
static u8 *
format_sfdp_nat_rewrite_TXFIB (u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg (*args, nat_rewrite_data_t *);
  s = format (s, "fib-index %u", rewrite->rewrite.fib_index);
  return s;
}

u8 *
format_sfdp_nat_rewrite (u8 *s, va_list *args)
{
  nat_rewrite_data_t *rewrite = va_arg (*args, nat_rewrite_data_t *);
#define _(sym, x, str)                                                        \
  if (rewrite->ops & NAT_REWRITE_OP_##sym)                                    \
    s = format (s, "rewrite %s (to %U),", str, format_sfdp_nat_rewrite_##sym, \
		rewrite);
  foreach_nat_rewrite_op
#undef _
    // if (s && s[vec_len (s) - 1] == ',') vec_resize (s, vec_len (s) - 1);
    return s;
}