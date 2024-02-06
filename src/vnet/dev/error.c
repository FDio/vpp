/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/flow/flow.h>

clib_error_t *
vnet_dev_port_err (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_rv_t rv,
		   char *fmt, ...)
{
  clib_error_t *err;
  va_list va;
  u8 *s;

  if (rv == VNET_DEV_OK)
    return 0;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  err = clib_error_return (0, "%s port %u: %U (%v)", port->dev->device_id,
			   port->port_id, format_vnet_dev_rv, rv, s);
  vec_free (s);
  return err;
}

int
vnet_dev_flow_err (vlib_main_t *vm, vnet_dev_rv_t rv)
{
  if (rv == VNET_DEV_OK)
    return 0;

  switch (rv)
    {
      /* clang-format off */
#define _(n, e, s)                                            \
    case VNET_DEV_ERR_##e:                                    \
      return VNET_FLOW_ERROR_##e;
    foreach_flow_error;
#undef _
      /* clang-format on */
    default:
      ASSERT (0);
    }

  ASSERT (0);

  return 0;
}
