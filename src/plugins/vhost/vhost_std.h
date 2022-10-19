/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __VHOST_STD_H__
#define __VHOST_STD_H__

typedef struct
{
  u64 guest_phys_addr;
  u64 memory_size;
  u64 userspace_addr;
  u64 mmap_offset;
} vhost_memory_region_t;

typedef struct
{
  u32 nregions;
  u32 padding;
  vhost_memory_region_t regions[0];
} vhost_memory_t;

typedef struct
{
  u32 index;
  u32 num;
} vhost_vring_state_t;

typedef struct
{
  u32 index;
  int fd;
} vhost_vring_file_t;

typedef struct
{
  u32 index;
  u32 flags;
  u64 desc_user_addr;
  u64 used_user_addr;
  u64 avail_user_addr;
  u64 log_guest_addr;
} vhost_vring_addr_t;

typedef struct
{
  u64 size;
  u64 offset;
} vhost_user_log_t;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
