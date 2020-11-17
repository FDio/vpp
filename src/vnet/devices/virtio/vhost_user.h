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

#include <vnet/devices/virtio/virtio_std.h>
#include <vnet/devices/virtio/vhost_std.h>

/* vhost-user data structures */

#define VHOST_MEMORY_MAX_NREGIONS       8
#define VHOST_USER_MSG_HDR_SZ           12
#define VHOST_VRING_MAX_N               16	//8TX + 8RX
#define VHOST_VRING_IDX_RX(qid)         (2*qid)
#define VHOST_VRING_IDX_TX(qid)         (2*qid + 1)

#define VHOST_USER_VRING_NOFD_MASK      0x100

#define VHOST_USER_PROTOCOL_F_MQ   0
#define VHOST_USER_PROTOCOL_F_LOG_SHMFD	1
#define VHOST_VRING_F_LOG 0

#define VHOST_USER_PROTOCOL_FEATURES   ((1ULL << VHOST_USER_PROTOCOL_F_MQ) |	\
					(1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD))

#define vu_log_debug(dev, f, ...) \
{                                                                             \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, vhost_user_main.log_default, "%U: " f,       \
	   format_vnet_hw_if_index_name, vnet_get_main(),                     \
	   dev->hw_if_index, ##__VA_ARGS__);                                  \
};

#define vu_log_warn(dev, f, ...) \
{                                                                             \
  vlib_log(VLIB_LOG_LEVEL_WARNING, vhost_user_main.log_default, "%U: " f,     \
	   format_vnet_hw_if_index_name, vnet_get_main(),                     \
	   dev->hw_if_index, ##__VA_ARGS__);                                  \
};
#define vu_log_err(dev, f, ...) \
{                                                                             \
  vlib_log(VLIB_LOG_LEVEL_ERR, vhost_user_main.log_default, "%U: " f,         \
	   format_vnet_hw_if_index_name, vnet_get_main(),                     \
	   dev->hw_if_index, ##__VA_ARGS__);                                  \
};

#define UNIX_GET_FD(unixfd_idx) ({ \
    typeof(unixfd_idx) __unixfd_idx = (unixfd_idx); \
    (__unixfd_idx != ~0) ? \
        pool_elt_at_index (file_main.file_pool, \
                           __unixfd_idx)->file_descriptor : -1; })

#define foreach_virtio_trace_flags \
  _ (SIMPLE_CHAINED, 0, "Simple descriptor chaining") \
  _ (SINGLE_DESC,  1, "Single descriptor packet") \
  _ (INDIRECT, 2, "Indirect descriptor") \
  _ (MAP_ERROR, 4, "Memory mapping error")

typedef enum
{
#define _(n,i,s) VIRTIO_TRACE_F_##n,
  foreach_virtio_trace_flags
#undef _
} virtio_trace_flag_t;

#define FEATURE_VIRTIO_NET_F_HOST_TSO_FEATURE_BITS \
  (VIRTIO_FEATURE (VIRTIO_NET_F_CSUM) |		   \
   VIRTIO_FEATURE (VIRTIO_NET_F_HOST_UFO) |	   \
   VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO4) |	   \
   VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO6))

#define FEATURE_VIRTIO_NET_F_GUEST_TSO_FEATURE_BITS \
  (VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM) |	    \
   VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_UFO) |	    \
   VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4) |	    \
   VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6))

#define FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS \
  (FEATURE_VIRTIO_NET_F_HOST_TSO_FEATURE_BITS |		 \
   FEATURE_VIRTIO_NET_F_GUEST_TSO_FEATURE_BITS)


typedef struct
{
  char *sock_filename;
  u64 feature_mask;
  u32 custom_dev_instance;
  u8 hwaddr[6];
  u8 renumber;
  u8 is_server;
  u8 enable_gso;
  u8 enable_packed;
  u8 enable_event_idx;

  /* return */
  u32 sw_if_index;
} vhost_user_create_if_args_t;

int vhost_user_create_if (vnet_main_t * vnm, vlib_main_t * vm,
			  vhost_user_create_if_args_t * args);
int vhost_user_modify_if (vnet_main_t * vnm, vlib_main_t * vm,
			  vhost_user_create_if_args_t * args);
int vhost_user_delete_if (vnet_main_t * vnm, vlib_main_t * vm,
			  u32 sw_if_index);

/* *INDENT-OFF* */
typedef struct vhost_user_memory_region
{
  u64 guest_phys_addr;
  u64 memory_size;
  u64 userspace_addr;
  u64 mmap_offset;
} __attribute ((packed)) vhost_user_memory_region_t;

typedef struct vhost_user_memory
{
  u32 nregions;
  u32 padding;
  vhost_user_memory_region_t regions[VHOST_MEMORY_MAX_NREGIONS];
} __attribute ((packed)) vhost_user_memory_t;

typedef enum vhost_user_req
{
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
  VHOST_USER_GET_PROTOCOL_FEATURES = 15,
  VHOST_USER_SET_PROTOCOL_FEATURES = 16,
  VHOST_USER_GET_QUEUE_NUM = 17,
  VHOST_USER_SET_VRING_ENABLE = 18,
  VHOST_USER_MAX
} vhost_user_req_t;

typedef struct vhost_user_msg {
  vhost_user_req_t request;
  u32 flags;
  u32 size;
  union
    {
      u64 u64;
      vhost_vring_state_t state;
      vhost_vring_addr_t addr;
      vhost_user_memory_t memory;
      vhost_user_log_t log;
    };
} __attribute ((packed)) vhost_user_msg_t;
/* *INDENT-ON* */

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 qsz_mask;
  u16 last_avail_idx;
  u16 last_used_idx;
  u16 n_since_last_int;
  union
  {
    vring_desc_t *desc;
    vring_packed_desc_t *packed_desc;
  };
  union
  {
    vring_avail_t *avail;
    vring_desc_event_t *avail_event;
  };
  union
  {
    vring_used_t *used;
    vring_desc_event_t *used_event;
  };
  uword desc_user_addr;
  uword used_user_addr;
  uword avail_user_addr;
  f64 int_deadline;
  u8 started;
  u8 enabled;
  u8 log_used;
  //Put non-runtime in a different cache line
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  int errfd;
  u32 callfd_idx;
  u32 kickfd_idx;
  u64 log_guest_addr;

  /* The rx queue policy (interrupt/adaptive/polling) for this queue */
  u32 mode;

  /*
   * It contains the device queue number. -1 if it does not. The idea is
   * to not invoke vnet_hw_interface_assign_rx_thread and
   * vnet_hw_interface_unassign_rx_thread more than once for the duration of
   * the interface even if it is disconnected and reconnected.
   */
  i16 qid;

  u16 used_wrap_counter;
  u16 avail_wrap_counter;

  u16 last_kick;
  u8 first_kick;
} vhost_user_vring_t;

#define VHOST_USER_EVENT_START_TIMER 1
#define VHOST_USER_EVENT_STOP_TIMER  2

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 is_ready;
  u32 admin_up;
  u32 unix_server_index;
  u32 clib_file_index;
  char sock_filename[256];
  int sock_errno;
  uword if_index;
  u32 hw_if_index, sw_if_index;

  //Feature negotiation
  u64 features;
  u64 feature_mask;
  u64 protocol_features;

  //Memory region information
  u32 nregions;
  vhost_user_memory_region_t regions[VHOST_MEMORY_MAX_NREGIONS];
  void *region_mmap_addr[VHOST_MEMORY_MAX_NREGIONS];
  u64 region_guest_addr_lo[VHOST_MEMORY_MAX_NREGIONS];
  u64 region_guest_addr_hi[VHOST_MEMORY_MAX_NREGIONS];
  u32 region_mmap_fd[VHOST_MEMORY_MAX_NREGIONS];

  //Virtual rings
  vhost_user_vring_t vrings[VHOST_VRING_MAX_N];
  volatile u32 *vring_locks[VHOST_VRING_MAX_N];

  int virtio_net_hdr_sz;
  int is_any_layout;

  void *log_base_addr;
  u64 log_size;

  /* Whether to use spinlock or per_cpu_tx_qid assignment */
  u8 use_tx_spinlock;
  u16 *per_cpu_tx_qid;

  u8 enable_gso;

  /* Packed ring configured */
  u8 enable_packed;

  u8 enable_event_idx;
} vhost_user_intf_t;

typedef struct
{
  uword dst;
  uword src;
  u32 len;
} vhost_copy_t;

typedef struct
{
  u16 qid; /** The interface queue index (Not the virtio vring idx) */
  u16 device_index; /** The device index */
  u32 virtio_ring_flags; /** Runtime queue flags  **/
  u16 first_desc_len; /** Length of the first data descriptor **/
  virtio_net_hdr_mrg_rxbuf_t hdr; /** Virtio header **/
} vhost_trace_t;

#define VHOST_USER_RX_BUFFERS_N (2 * VLIB_FRAME_SIZE + 2)
#define VHOST_USER_COPY_ARRAY_N (4 * VLIB_FRAME_SIZE)

typedef struct
{
  u32 rx_buffers_len;
  u32 rx_buffers[VHOST_USER_RX_BUFFERS_N];

  virtio_net_hdr_mrg_rxbuf_t tx_headers[VLIB_FRAME_SIZE];
  vhost_copy_t copy[VHOST_USER_COPY_ARRAY_N];

  /* This is here so it doesn't end-up
   * using stack or registers. */
  vhost_trace_t *current_trace;

  u32 *to_next_list;
  vlib_buffer_t **rx_buffers_pdesc;
} vhost_cpu_t;

typedef struct
{
  mhash_t if_index_by_sock_name;
  u32 mtu_bytes;
  vhost_user_intf_t *vhost_user_interfaces;
  u32 *show_dev_instance_by_real_dev_instance;
  u32 coalesce_frames;
  f64 coalesce_time;
  int dont_dump_vhost_user_memory;

  /** Per-CPU data for vhost-user */
  vhost_cpu_t *cpus;

  /** Pseudo random iterator */
  u32 random;

  /* The number of rx interface/queue pairs in interrupt mode */
  u32 ifq_count;

  /* logging */
  vlib_log_class_t log_default;

  /* gso interface count */
  u32 gso_count;
} vhost_user_main_t;

typedef struct
{
  u8 if_name[64];
  u32 sw_if_index;
  u32 virtio_net_hdr_sz;
  u64 features;
  u8 is_server;
  u8 sock_filename[256];
  u32 num_regions;
  int sock_errno;
} vhost_user_intf_details_t;

int vhost_user_dump_ifs (vnet_main_t * vnm, vlib_main_t * vm,
			 vhost_user_intf_details_t ** out_vuids);

extern vlib_node_registration_t vhost_user_send_interrupt_node;
extern vnet_device_class_t vhost_user_device_class;
extern vlib_node_registration_t vhost_user_input_node;
extern vhost_user_main_t vhost_user_main;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
