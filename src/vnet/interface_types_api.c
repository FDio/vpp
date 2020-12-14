/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
