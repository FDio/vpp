/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_TCP_TCP_LOCAL_H_
#define SRC_VNET_TCP_TCP_LOCAL_H_

#include <vnet/vnet.h>

#define TCP_NO_NODE_SET ((u16) ~0)

typedef enum
{
  TCP_LOCAL_NEXT_DROP,
  TCP_LOCAL_NEXT_PUNT,
  TCP_LOCAL_NEXT_RESET,
  TCP_LOCAL_NEXT_INPUT,
  TCP_LOCAL_N_NEXT
} tcp_local_next_t;

void tcp_register_dst_port (vlib_main_t *vm, u16 dst_port, u32 node_index,
			    u8 is_ip4);
void tcp_unregister_dst_port (vlib_main_t *vm, u16 dst_port, u8 is_ip4);
u8 tcp_is_valid_dst_port (u16 dst_port, u8 is_ip4);

#endif /* SRC_VNET_TCP_TCP_LOCAL_H_ */
