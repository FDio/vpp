/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
