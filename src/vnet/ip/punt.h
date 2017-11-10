/*
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
 */

/**
 * @file
 * @brief Definitions for punt infrastructure.
 */
#ifndef included_punt_h
#define included_punt_h

#include <sys/un.h>
#include <stdbool.h>

typedef enum
{
#define punt_error(n,s) PUNT_ERROR_##n,
#include <vnet/ip/punt_error.def>
#undef punt_error
  PUNT_N_ERROR,
} punt_error_t;


clib_error_t *vnet_punt_add_del (vlib_main_t * vm, u8 ipv,
				 u8 protocol, u16 port, bool is_add);
clib_error_t *vnet_punt_socket_add (vlib_main_t * vm, u32 header_version,
				    bool is_ip4, u8 protocol, u16 port,
				    char *client_pathname);
clib_error_t *vnet_punt_socket_del (vlib_main_t * vm, bool is_ip4,
				    u8 l4_protocol, u16 port);
char *vnet_punt_get_server_pathname (void);

enum punt_action_e
{
  PUNT_L2 = 0,
  PUNT_IP4_ROUTED,
  PUNT_IP6_ROUTED,
};

/*
 * Packet descriptor header. Version 1
 * If this header changes, the version must also change to notify clients.
 */
#define PUNT_PACKETDESC_VERSION 1
typedef struct __attribute__ ((packed))
{
  u32 sw_if_index;		/* RX or TX interface */
  enum punt_action_e action;
} punt_packetdesc_t;

/*
 * Client registration
 */
typedef struct
{
  u16 port;
  struct sockaddr_un caddr;
} punt_client_t;

typedef struct
{
  int socket_fd;
  char sun_path[sizeof (struct sockaddr_un)];
  punt_client_t *clients_by_dst_port4;
  punt_client_t *clients_by_dst_port6;
  u32 clib_file_index;
  bool is_configured;
  vlib_node_t *interface_output_node;
  u32 *ready_fds;
  u32 *rx_buffers;
} punt_main_t;
extern punt_main_t punt_main;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
