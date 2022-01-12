/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface.h>

VLIB_REGISTER_LOG_CLASS (if_caps_log, static) = {
  .class_name = "interface",
  .subclass_name = "caps",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (if_caps_log.class, fmt, __VA_ARGS__)

format_function_t format_vnet_hw_if_caps;

void
vnet_hw_if_change_caps (vnet_main_t *vnm, u32 hw_if_index,
			vnet_hw_if_caps_change_t *caps)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_hw_if_caps_t old = hi->caps;

  hi->caps = (hi->caps & ~caps->mask) | caps->val;

  log_debug ("change: interface %U, set: %U, cleared: %U",
	     format_vnet_hw_if_index_name, vnm, hw_if_index,
	     format_vnet_hw_if_caps, (old ^ hi->caps) & caps->val,
	     format_vnet_hw_if_caps, (old ^ hi->caps) & ~caps->val);
}

u8 *
format_vnet_hw_if_caps (u8 *s, va_list *va)
{
  vnet_hw_if_caps_t caps = va_arg (*va, vnet_hw_if_caps_t);

  const char *strings[sizeof (vnet_hw_if_caps_t) * 8] = {
#define _(bit, sfx, str) [bit] = (str),
    foreach_vnet_hw_if_caps
#undef _
  };

  if (caps == 0)
    return format (s, "none");

  while (caps)
    {
      int bit = get_lowest_set_bit_index (caps);

      if (strings[bit])
	s = format (s, "%s", strings[bit]);
      else
	s = format (s, "unknown-%u", bit);

      caps = clear_lowest_set_bit (caps);
      if (caps)
	vec_add1 (s, ' ');
    }

  return s;
}
