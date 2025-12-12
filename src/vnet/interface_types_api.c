/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/interface_types_api.h>

STATIC_ASSERT_SIZEOF (vl_api_direction_t, 1);

int
direction_decode (vl_api_direction_t _dir, vlib_dir_t * out)
{
  switch (_dir)
    {
    case RX:
      *out = VLIB_RX;
      return (0);
    case TX:
      *out = VLIB_TX;
      return (0);
    }
  return (VNET_API_ERROR_INVALID_VALUE);
}

vl_api_direction_t
direction_encode (vlib_dir_t dir)
{
  return (vl_api_direction_t) dir;
}
