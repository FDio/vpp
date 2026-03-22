/*
 * pppoeclient_msg_enum.h - vpp engine plug-in message enumeration
 *
 * Copyright (c) 2017 RaydoNetworks.
 */
#ifndef included_pppoeclient_msg_enum_h
#define included_pppoeclient_msg_enum_h

#include <vppinfra/byte_order.h>

#define vl_msg_id(n, h) n,
typedef enum
{
#include <pppoeclient/pppoeclient_all_api_h.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

#endif /* included_pppoeclient_msg_enum_h */
