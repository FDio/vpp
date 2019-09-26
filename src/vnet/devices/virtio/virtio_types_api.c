/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
