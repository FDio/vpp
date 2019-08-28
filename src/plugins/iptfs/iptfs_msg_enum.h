/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * January 10 2020, Christian E. Hopps <chopps@labn.net>
 */

#ifndef included_iptfs_msg_enum_h
#define included_iptfs_msg_enum_h

#include <vppinfra/byte_order.h>

#define vl_msg_id(n, h) n,
typedef enum
{
#include <iptfs/iptfs_all_api_h.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

#endif /* included_iptfs_msg_enum_h */
