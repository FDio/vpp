/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Cisco and/or its affiliates.
 */

/*
 * vl_memory_msg_enum.h - Our view of how to number API messages
 * Clients have their own view, which has to agree with ours.
 */

#ifndef __VL_MSG_ENUM_H__
#define __VL_MSG_ENUM_H__

#include <vppinfra/byte_order.h>

#define vl_msg_id(n,h) n,
typedef enum
{
  VL_ILLEGAL_MESSAGE_ID = 0,
#include <vlibmemory/vl_memory_api_h.h>
} vl_msg_id_t;
#undef vl_msg_id

#endif /* __VL_MSG_ENUM_H__ */
