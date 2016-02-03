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
#ifndef __VIRTIO_VHOST_USER_H__
#define __VIRTIO_VHOST_USER_H__
/* vhost-user data structures */

#define VHOST_MEMORY_MAX_NREGIONS       8
#define VHOST_USER_MSG_HDR_SZ           12
#define VHOST_VRING_MAX_SIZE            32768
#define VHOST_NET_VRING_IDX_RX          0
#define VHOST_NET_VRING_IDX_TX          1
#define VHOST_NET_VRING_NUM             2

#define VIRTQ_DESC_F_NEXT               1
#define VHOST_USER_REPLY_MASK       (0x1 << 2)

#if RTE_VERSION >= RTE_VERSION_NUM(2, 2, 0, 0)
#define VHOST_USER_PROTOCOL_F_MQ   0
#define VHOST_USER_PROTOCOL_FEATURES   (1ULL << VHOST_USER_PROTOCOL_F_MQ)

/* If multiqueue is provided by host, then we suppport it. */
#define VIRTIO_NET_CTRL_MQ   4
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET        0
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN        1
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX        0x8000
#endif

#define foreach_virtio_net_feature      \
 _ (VIRTIO_NET_F_MRG_RXBUF, 15)         \
 _ (VIRTIO_F_ANY_LAYOUT, 27)

typedef enum {
#define _(f,n) FEAT_##f = (n),
  foreach_virtio_net_feature
#undef _
} virtio_net_feature_t;

int vhost_user_create_if(vnet_main_t * vnm, vlib_main_t * vm, 
    const char * sock_filename, u8 is_server,
    u32 * sw_if_index, u64 feature_mask,
    u8 renumber, u32 custom_dev_instance);
int vhost_user_modify_if(vnet_main_t * vnm, vlib_main_t * vm,
    const char * sock_filename, u8 is_server,
    u32 sw_if_index, u64 feature_mask,
    u8 renumber, u32 custom_dev_instance);
int vhost_user_delete_if(vnet_main_t * vnm, vlib_main_t * vm, u32 sw_if_index);

typedef struct vhost_user_memory_region {
  u64 guest_phys_addr;
  u64 memory_size;
  u64 userspace_addr;
  u64 mmap_offset;
} vhost_user_memory_region_t;

typedef struct vhost_user_memory {
  u32 nregions;
  u32 padding;
  vhost_user_memory_region_t regions[VHOST_MEMORY_MAX_NREGIONS];
} vhost_user_memory_t;

typedef struct vhost_vring_state { 
  unsigned int index, num;
} vhost_vring_state_t;

typedef struct vhost_vring_addr {
  unsigned int index, flags;
  u64 desc_user_addr, used_user_addr, avail_user_addr, log_guest_addr;
} vhost_vring_addr_t;

typedef enum vhost_user_req {
  VHOST_USER_NONE = 0,
  VHOST_USER_GET_FEATURES = 1,
  VHOST_USER_SET_FEATURES = 2,
  VHOST_USER_SET_OWNER = 3,
  VHOST_USER_RESET_OWNER = 4,
  VHOST_USER_SET_MEM_TABLE = 5,
  VHOST_USER_SET_LOG_BASE = 6,
  VHOST_USER_SET_LOG_FD = 7,
  VHOST_USER_SET_VRING_NUM = 8,
  VHOST_USER_SET_VRING_ADDR = 9,
  VHOST_USER_SET_VRING_BASE = 10,
  VHOST_USER_GET_VRING_BASE = 11,
  VHOST_USER_SET_VRING_KICK = 12,
  VHOST_USER_SET_VRING_CALL = 13,
  VHOST_USER_SET_VRING_ERR = 14,
#if RTE_VERSION >= RTE_VERSION_NUM(2, 2, 0, 0)
  VHOST_USER_GET_PROTOCOL_FEATURES = 15,
  VHOST_USER_SET_PROTOCOL_FEATURES = 16,
  VHOST_USER_GET_QUEUE_NUM = 17,
  VHOST_USER_SET_VRING_ENABLE = 18,
#endif
  VHOST_USER_MAX
} vhost_user_req_t;

// vring_desc I/O buffer descriptor
typedef struct {
  uint64_t addr;  // packet data buffer address
  uint32_t len;   // packet data buffer size
  uint16_t flags; // (see below)
  uint16_t next;  // optional index next descriptor in chain
} __attribute ((packed)) vring_desc_t;

typedef struct {
  uint16_t flags;
  uint16_t idx;
  uint16_t ring[VHOST_VRING_MAX_SIZE];
} __attribute ((packed)) vring_avail_t;

typedef struct {
  uint16_t flags;
  uint16_t idx;
  struct /* vring_used_elem */ {
    uint32_t id; 
    uint32_t len; 
  } ring[VHOST_VRING_MAX_SIZE];
} __attribute ((packed)) vring_used_t;

typedef struct {
  u8 flags;
  u8 gso_type;
  u16 hdr_len;
  u16 gso_size;
  u16 csum_start;
  u16 csum_offset;
} __attribute ((packed)) virtio_net_hdr_t;

typedef struct  {
  virtio_net_hdr_t hdr;
  u16 num_buffers;
} __attribute ((packed)) virtio_net_hdr_mrg_rxbuf_t;

typedef struct vhost_user_msg {
    vhost_user_req_t request;
    u32 flags;
    u32 size;
    union {
        u64 u64;
        vhost_vring_state_t state;
        vhost_vring_addr_t addr;
        vhost_user_memory_t memory;
    };
} __attribute ((packed)) vhost_user_msg_t;

typedef struct {
  u32 qsz;
  u16 last_avail_idx;
  u16 last_used_idx;
  vring_desc_t *desc;
  vring_avail_t *avail;
  vring_used_t *used;
  int callfd;
  int kickfd;
  int errfd;
  u32 callfd_idx;
  u32 n_since_last_int;
  f64 int_deadline;
} vhost_user_vring_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  volatile u32 * lockp;
  u32 is_up;
  u32 admin_up;
  u32 unix_fd;
  u32 unix_file_index;
  u32 client_fd;
  char sock_filename[256];
  int sock_errno;
  u8 sock_is_server;
  u32 hw_if_index, sw_if_index;
  u8 active;
  
  u32 nregions;
  u64 features;
  u64 feature_mask;
  u32 num_vrings;
  vhost_user_memory_region_t regions[VHOST_MEMORY_MAX_NREGIONS];
  void * region_mmap_addr[VHOST_MEMORY_MAX_NREGIONS];
  u32 region_mmap_fd[VHOST_MEMORY_MAX_NREGIONS];
  vhost_user_vring_t vrings[2];
  int virtio_net_hdr_sz;
  int is_any_layout;
  u32 * d_trace_buffers;
} vhost_user_intf_t;

typedef struct {
  u32 ** rx_buffers;
  u32 mtu_bytes;
  vhost_user_intf_t * vhost_user_interfaces;
  u32 * vhost_user_inactive_interfaces_index;
  uword * vhost_user_interface_index_by_listener_fd;
  uword * vhost_user_interface_index_by_sock_fd;
  uword * vhost_user_interface_index_by_sw_if_index;
  u32 * show_dev_instance_by_real_dev_instance;
  u32 coalesce_frames;
  f64 coalesce_time;
  int dont_dump_vhost_user_memory;
} vhost_user_main_t;

typedef struct {
    u8 if_name[64];
    u32 sw_if_index;
    u32 virtio_net_hdr_sz;
    u64 features;
    u8 is_server;
    u8 sock_filename[256];
    u32 num_regions;
    int sock_errno;
} vhost_user_intf_details_t;

int vhost_user_dump_ifs(vnet_main_t * vnm, vlib_main_t * vm,
        vhost_user_intf_details_t **out_vuids);

// CLI commands to be used from dpdk
clib_error_t *
vhost_user_connect_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd);
clib_error_t *
vhost_user_delete_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd);
clib_error_t *
show_vhost_user_command_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd);

#endif
