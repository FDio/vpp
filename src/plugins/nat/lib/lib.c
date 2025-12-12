/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <nat/lib/lib.h>
#include <nat/lib/nat_proto.h>

uword
unformat_nat_protocol (unformat_input_t *input, va_list *args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0)
    ;
#define _(N, i, n, s) else if (unformat (input, s)) *r = NAT_PROTOCOL_##N;
  foreach_nat_protocol
#undef _
    else return 0;
  return 1;
}

u8 *
format_nat_protocol (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(N, j, n, str)                                                       \
  case NAT_PROTOCOL_##N:                                                      \
    t = (u8 *) str;                                                           \
    break;
      foreach_nat_protocol
#undef _
	default : s = format (s, "unknown");
      return s;
    }
  s = format (s, "%s", t);
  return s;
}
