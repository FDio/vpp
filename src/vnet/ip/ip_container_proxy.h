/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef included_ip_container_proxy_h
#define included_ip_container_proxy_h

#include <vnet/fib/fib_types.h>

typedef struct _vnet_ip_container_proxy_args
{
  fib_prefix_t prefix;
  u32 sw_if_index;
  u8 is_add;
} vnet_ip_container_proxy_args_t;

clib_error_t *vnet_ip_container_proxy_add_del (vnet_ip_container_proxy_args_t
					       * args);

typedef int (*ip_container_proxy_cb_t) (const fib_prefix_t * pfx,
					u32 sw_if_index, void *ctx);
void ip_container_proxy_walk (ip_container_proxy_cb_t cb, void *ctx);

#endif
