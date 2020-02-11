
/*
 * vrrp_msg_enum.h - vrrp plug-in message enumeration
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef included_vrrp_msg_enum_h
#define included_vrrp_msg_enum_h

#include <vppinfra/byte_order.h>

#define vl_msg_id(n,h) n,
typedef enum {
#include <vrrp/vrrp_all_api_h.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

#endif /* included_vrrp_msg_enum_h */
