/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018, Microsoft Corporation.
 */

/*
 * vmbus.h: VMBus definitions.
 */

#ifndef included_vlib_vmbus_h
#define included_vlib_vmbus_h

#include <vlib/vlib.h>

typedef union
{
  u8 guid[16];
  u32 as_u32[4];
} vlib_vmbus_addr_t;

typedef u32 vlib_vmbus_dev_handle_t;

vlib_vmbus_addr_t *vlib_vmbus_get_all_dev_addrs ();
vlib_vmbus_addr_t *vlib_vmbus_get_addr (vlib_vmbus_dev_handle_t h);
uword vlib_vmbus_get_private_data (vlib_vmbus_dev_handle_t h);
void vlib_vmbus_set_private_data (vlib_vmbus_dev_handle_t h,
				  uword private_data);

format_function_t format_vlib_vmbus_addr;
unformat_function_t unformat_vlib_vmbus_addr;
clib_error_t *vlib_vmbus_bind_to_uio (vlib_vmbus_addr_t * addr);
#endif /* included_vlib_vmbus_h */
