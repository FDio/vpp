/* SPDX-License-Identifier: Apache-2.0 */
/*
 * pppox_msg_enum.h - vpp engine plug-in message enumeration
 *
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 */
#ifndef included_pppox_msg_enum_h
#define included_pppox_msg_enum_h

#include <vppinfra/byte_order.h>

#define vl_msg_id(n, h) n,
typedef enum
{
#include <pppox/pppox_all_api_h.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

#endif /* included_pppox_msg_enum_h */
