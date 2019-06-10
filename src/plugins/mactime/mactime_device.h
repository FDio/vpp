/*
 * mactime_device.h - device table entry
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_mactime_device_h
#define included_mactime_device_h
#include <vppinfra/time_range.h>

#define MACTIME_RANGE_TYPE_DROP 0
#define MACTIME_RANGE_TYPE_ALLOW 1

typedef struct
{
  u8 *device_name;
  u8 mac_address[6];
  u64 data_quota;
  u64 data_used_in_range;
  u32 flags;
  u32 pool_index;
  f64 last_seen;
  clib_timebase_range_t *ranges;
} mactime_device_t;

/** Always drop packets from this device */
#define MACTIME_DEVICE_FLAG_STATIC_DROP		(1<<0)
#define MACTIME_DEVICE_FLAG_STATIC_ALLOW	(1<<1)
#define MACTIME_DEVICE_FLAG_DYNAMIC_DROP	(1<<2)
#define MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW	(1<<3)
#define MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA	(1<<4)
#define MACTIME_DEVICE_FLAG_DROP_UDP_10001      (1<<5)

#endif /* included_mactime_device_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
