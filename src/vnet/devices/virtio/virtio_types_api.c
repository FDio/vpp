/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2025 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>

#include <vlibapi/api_types.h>
#include <vnet/devices/virtio/virtio_types_api.h>


u64
virtio_features_decode (u32 first, u32 last)
{
  return clib_net_to_host_u32 (first) | ((u64)clib_net_to_host_u32 (last) << 32);
}

void
virtio_features_encode (u64 features, u32 *first, u32 *last)
{
  *first = clib_net_to_host_u32 (features);
  *last = clib_net_to_host_u32 (features >> 32);
}
