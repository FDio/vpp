/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Minimal userspace vhost interface, subset of include/uapi/linux/vhost.h.
 * The syscall exception permits use of these definitions without imposing
 * GPL terms on userspace code including this header.
 */
#pragma once

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
#define VHOST_VIRTIO	      0xAF
#define VHOST_GET_FEATURES    _IOR (VHOST_VIRTIO, 0x00, u64)
#define VHOST_SET_FEATURES    _IOW (VHOST_VIRTIO, 0x00, u64)
#define VHOST_SET_OWNER	      _IO (VHOST_VIRTIO, 0x01)
#define VHOST_RESET_OWNER     _IO (VHOST_VIRTIO, 0x02)
#define VHOST_SET_MEM_TABLE   _IOW (VHOST_VIRTIO, 0x03, vhost_memory_t)
#define VHOST_SET_LOG_BASE    _IOW (VHOST_VIRTIO, 0x04, u64)
#define VHOST_SET_LOG_FD      _IOW (VHOST_VIRTIO, 0x07, int)
#define VHOST_SET_VRING_NUM   _IOW (VHOST_VIRTIO, 0x10, vhost_vring_state_t)
#define VHOST_SET_VRING_ADDR  _IOW (VHOST_VIRTIO, 0x11, vhost_vring_addr_t)
#define VHOST_SET_VRING_BASE  _IOW (VHOST_VIRTIO, 0x12, vhost_vring_state_t)
#define VHOST_GET_VRING_BASE  _IOWR (VHOST_VIRTIO, 0x12, vhost_vring_state_t)
#define VHOST_SET_VRING_KICK  _IOW (VHOST_VIRTIO, 0x20, vhost_vring_file_t)
#define VHOST_SET_VRING_CALL  _IOW (VHOST_VIRTIO, 0x21, vhost_vring_file_t)
#define VHOST_SET_VRING_ERR   _IOW (VHOST_VIRTIO, 0x22, vhost_vring_file_t)
#define VHOST_NET_SET_BACKEND _IOW (VHOST_VIRTIO, 0x30, vhost_vring_file_t)
#define VHOST_SET_BACKEND_FEATURES _IOW (VHOST_VIRTIO, 0x25, u64)
#define VHOST_GET_BACKEND_FEATURES _IOR (VHOST_VIRTIO, 0x26, u64)

/* vhost worker fork mode control (kernel >= 6.12 with
 * CONFIG_VHOST_ENABLE_FORK_OWNER_CONTROL=y) */
#define VHOST_FORK_OWNER_KTHREAD  0
#define VHOST_FORK_OWNER_TASK	  1
#define VHOST_SET_FORK_FROM_OWNER _IOW (VHOST_VIRTIO, 0x84, u8)
#define VHOST_GET_FORK_FROM_OWNER _IOR (VHOST_VIRTIO, 0x85, u8)

/* vhost-vdpa */
typedef struct
{
  u64 iova;
  u64 size;
  u64 uaddr;
  u8 perm;
  u8 type;
} vhost_iotlb_msg_t;

typedef struct
{
  u32 type;
  u32 asid;
  union
  {
    vhost_iotlb_msg_t iotlb;
    u8 padding[64];
  };
} vhost_msg_v2_t;

typedef struct
{
  u32 off;
  u32 len;
  u8 buf[];
} vhost_vdpa_config_t;

typedef struct
{
  u64 first;
  u64 last;
} vhost_vdpa_iova_range_t;

#define VHOST_IOTLB_UPDATE	     2
#define VHOST_IOTLB_BATCH_BEGIN	     5
#define VHOST_IOTLB_BATCH_END	     6
#define VHOST_IOTLB_MSG_V2	     2
#define VHOST_ACCESS_RW		     3
#define VHOST_BACKEND_F_IOTLB_MSG_V2 1
#define VHOST_BACKEND_F_IOTLB_BATCH  2

#define VHOST_VDPA_GET_DEVICE_ID    _IOR (VHOST_VIRTIO, 0x70, u32)
#define VHOST_VDPA_GET_STATUS	    _IOR (VHOST_VIRTIO, 0x71, u8)
#define VHOST_VDPA_SET_STATUS	    _IOW (VHOST_VIRTIO, 0x72, u8)
#define VHOST_VDPA_GET_CONFIG	    _IOR (VHOST_VIRTIO, 0x73, vhost_vdpa_config_t)
#define VHOST_VDPA_SET_VRING_ENABLE _IOW (VHOST_VIRTIO, 0x75, vhost_vring_state_t)
#define VHOST_VDPA_GET_VRING_NUM    _IOR (VHOST_VIRTIO, 0x76, u16)
#define VHOST_VDPA_SET_CONFIG_CALL  _IOW (VHOST_VIRTIO, 0x77, int)
#define VHOST_VDPA_GET_IOVA_RANGE   _IOR (VHOST_VIRTIO, 0x78, vhost_vdpa_iova_range_t)
#define VHOST_VDPA_GET_VQS_COUNT    _IOR (VHOST_VIRTIO, 0x80, u32)
