/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Intel and/or its affiliates.
 */

#include <idpf/idpf.h>

u8 *
format_idpf_device_name (u8 *s, va_list *args)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 i = va_arg (*args, u32);
  idpf_device_t *id = idpf_get_device (i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, id->pci_dev_handle);

  if (id->name)
    return format (s, "%s", id->name);

  s = format (s, "idpf-%x/%x/%x/%x", addr->domain, addr->bus, addr->slot,
	      addr->function);
  return s;
}

u8 *
format_idpf_device_flags (u8 *s, va_list *args)
{
  idpf_device_t *id = va_arg (*args, idpf_device_t *);
  u8 *t = 0;

#define _(a, b, c)                                                            \
  if (id->flags & (1 << a))                                                   \
    t = format (t, "%s%s", t ? " " : "", c);
  foreach_idpf_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_idpf_checksum_cap_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  int not_first = 0;

  char *strs[32] = {
#define _(a, b, c) [a] = c,
    foreach_idpf_checksum_cap_flag
#undef _
  };

  for (int i = 0; i < 32; i++)
    {
      if ((flags & (1 << i)) == 0)
	continue;
      if (not_first)
	s = format (s, " ");
      if (strs[i])
	s = format (s, "%s", strs[i]);
      else
	s = format (s, "unknown(%u)", i);
      not_first = 1;
    }
  return s;
}
