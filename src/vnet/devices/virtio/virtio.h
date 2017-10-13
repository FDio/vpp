/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _VNET_DEVICES_VIRTIO_VIRTIO_H_
#define _VNET_DEVICES_VIRTIO_VIRTIO_H_

#define foreach_virtio_if_flag \
  _(0, ADMIN_UP, "admin-up")		\
  _(1, DELETING, "deleting")

typedef enum
{
#define _(a, b, c) VIRTIO_IF_FLAG_##b = (1 << a),
  foreach_virtio_if_flag
#undef _
} virtio_if_flag_t;

typedef enum
{
  VIRTIO_IF_TYPE_TAP,
  VIRTIO_IF_N_TYPES,
} virtio_if_type_t;


typedef struct
{
  struct vring_desc *desc;
  struct vring_used *used;
  struct vring_avail *avail;
  u16 desc_in_use;
  u16 desc_next;
  int kick_fd;
  int call_fd;
  u16 size;
  u32 flags;
  u32 call_file_index;
  u32 *buffers;
  u16 last_used_idx;
} virtio_vring_t;

typedef struct
{
  u32 flags;
  u32 dev_instance;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 per_interface_next_index;
  int fd;
  int tap_fd;
  virtio_vring_t *vrings;

  u64 features, remote_features;

  virtio_if_type_t type;
  u8 *name;
  u8 *net_ns;
  int ifindex;
} virtio_if_t;

typedef struct
{
  virtio_if_t *interfaces;
} virtio_main_t;

extern virtio_main_t virtio_main;
extern vnet_device_class_t virtio_device_class;
extern vlib_node_registration_t virtio_input_node;

clib_error_t *virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx,
				 u16 sz);
clib_error_t *virtio_vring_free (virtio_if_t * vif, u32 idx);

#endif /* _VNET_DEVICES_VIRTIO_VIRTIO_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
