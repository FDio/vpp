/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/error.h>
#include <vnet/api_errno.h>

static char *error_strings[] = {
#define _(a, b, c) [-(b)] = c,
  foreach_vnet_error
#undef _
};

clib_error_t *
vnet_error (vnet_error_t rv, char *fmt, ...)
{
  clib_error_t *e, *err = 0;
  va_list va;
  vec_add2 (err, e, 1);
  e->what = format (e->what, "%s", error_strings[-rv]);

  if (fmt)
    {
      vec_add1 (e->what, ' ');
      vec_add1 (e->what, '(');
      va_start (va, fmt);
      e->what = va_format (e->what, fmt, &va);
      vec_add1 (e->what, ')');
      va_end (va);
    }

  e->code = rv;
  return err;
}

u8 *
format_vnet_api_errno (u8 *s, va_list *args)
{
  vnet_api_error_t api_error = va_arg (*args, vnet_api_error_t);
#ifdef _
#undef _
#endif
#define _(a, b, c)                                                            \
  case b:                                                                     \
    s = format (s, "%s", c);                                                  \
    break;
  switch (api_error)
    {
      foreach_vnet_error default : s = format (s, "UNKNOWN");
      break;
    }
  return s;
#undef _
}
