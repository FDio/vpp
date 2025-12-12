/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef __INTERFACE_TYPES_API_H__
#define __INTERFACE_TYPES_API_H__

#include <vnet/vnet.h>
#include <vlibapi/api_types.h>

#include <vnet/interface.api_types.h>

extern int direction_decode (vl_api_direction_t _dir, vlib_dir_t * out);
extern vl_api_direction_t direction_encode (vlib_dir_t dir);

#endif
