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
#ifndef __VIRTIO_VHOST_STD_H__
#define __VIRTIO_VHOST_STD_H__

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

/* vhost kernel ioctls */
#define VHOST_VIRTIO 0xAF
#define VHOST_GET_FEATURES _IOR(VHOST_VIRTIO, 0x00, u64)
#define VHOST_SET_FEATURES _IOW(VHOST_VIRTIO, 0x00, u64)
#define VHOST_SET_OWNER _IO(VHOST_VIRTIO, 0x01)
#define VHOST_RESET_OWNER _IO(VHOST_VIRTIO, 0x02)
#define VHOST_SET_MEM_TABLE _IOW(VHOST_VIRTIO, 0x03, vhost_memory_t)
#define VHOST_SET_LOG_BASE _IOW(VHOST_VIRTIO, 0x04, u64)
#define VHOST_SET_LOG_FD _IOW(VHOST_VIRTIO, 0x07, int)
#define VHOST_SET_VRING_NUM _IOW(VHOST_VIRTIO, 0x10, vhost_vring_state_t)
#define VHOST_SET_VRING_ADDR _IOW(VHOST_VIRTIO, 0x11, vhost_vring_addr_t)
#define VHOST_SET_VRING_BASE _IOW(VHOST_VIRTIO, 0x12, vhost_vring_state_t)
#define VHOST_GET_VRING_BASE _IOWR(VHOST_VIRTIO, 0x12, vhost_vring_state_t)
#define VHOST_SET_VRING_KICK _IOW(VHOST_VIRTIO, 0x20, vhost_vring_file_t)
#define VHOST_SET_VRING_CALL _IOW(VHOST_VIRTIO, 0x21, vhost_vring_file_t)
#define VHOST_SET_VRING_ERR _IOW(VHOST_VIRTIO, 0x22, vhost_vring_file_t)
#define VHOST_NET_SET_BACKEND _IOW(VHOST_VIRTIO, 0x30, vhost_vring_file_t)

/* vhost worker fork mode control (kernel >= 6.12 with
 * CONFIG_VHOST_ENABLE_FORK_OWNER_CONTROL=y) */
#define VHOST_FORK_OWNER_KTHREAD  0
#define VHOST_FORK_OWNER_TASK	  1
#define VHOST_SET_FORK_FROM_OWNER _IOW (VHOST_VIRTIO, 0x84, u8)
#define VHOST_GET_FORK_FROM_OWNER _IOR (VHOST_VIRTIO, 0x85, u8)
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
