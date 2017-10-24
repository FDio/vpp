/*
 *------------------------------------------------------------------
 * af_packet.h - linux kernel packet interface header file
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vppinfra/lock.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  u8 *host_if_name;
  int host_if_index;
  int fd;
  struct tpacket_req *rx_req;
  struct tpacket_req *tx_req;
  u8 *rx_ring;
  u8 *tx_ring;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 clib_file_index;

  u32 next_rx_frame;
  u32 next_tx_frame;

  u32 per_interface_next_index;
  u8 is_admin_up;
} af_packet_if_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  af_packet_if_t *interfaces;

  /* bitmap of pending rx interfaces */
  uword *pending_input_bitmap;

  /* rx buffer cache */
  u32 **rx_buffers;

  /* hash of host interface names */
  mhash_t if_index_by_host_if_name;
} af_packet_main_t;

extern af_packet_main_t af_packet_main;
extern vnet_device_class_t af_packet_device_class;
extern vlib_node_registration_t af_packet_input_node;

int af_packet_create_if (vlib_main_t * vm, u8 * host_if_name,
			 u8 * hw_addr_set, u32 * sw_if_index);
int af_packet_delete_if (vlib_main_t * vm, u8 * host_if_name);
int af_packet_set_l4_cksum_offload (vlib_main_t * vm, u32 sw_if_index,
				    u8 set);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
