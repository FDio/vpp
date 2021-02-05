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

#include <linux/un.h>
#include <stdbool.h>
#include <vnet/ip/ip.h>

/* Punting reason flags bitfield
 * (position, length, value, name, string)
 */
#define foreach_vnet_punt_reason_flag                                         \
  _ (0, 1, 0, IP4_PACKET, "ip4-packet")                                       \
  _ (0, 1, 1, IP6_PACKET, "ip6-packet")

typedef enum vnet_punt_reason_flag_t_
{
#define _(pos, len, value, name, str)                                         \
  VNET_PUNT_REASON_F_##name = ((value) << (pos)),
  foreach_vnet_punt_reason_flag
#undef _
} __clib_packed vnet_punt_reason_flag_t;

enum vnet_punt_reason_flag_mask_t_
{
#define _(pos, len, value, name, str)                                         \
  VNET_PUNT_REASON_F_MASK_##name = (((1 << (len)) - 1) << (pos)),
  foreach_vnet_punt_reason_flag
#undef _
};

/* predicates associated with vlib_punt_reason_flag_t*/
#define _(pos, len, value, name, str)                                         \
  static_always_inline int vnet_punt_reason_flag_is_##name (                  \
    vnet_punt_reason_flag_t f)                                                \
  {                                                                           \
    return (f & VNET_PUNT_REASON_F_MASK_##name) == VNET_PUNT_REASON_F_##name; \
  }
foreach_vnet_punt_reason_flag
#undef _

#define foreach_punt_type                       \
  _(L4, "l4")                                   \
  _(EXCEPTION, "exception")                     \
  _(IP_PROTO, "ip-proto")

  typedef enum punt_type_t_ {
#define _(v, s) PUNT_TYPE_##v,
    foreach_punt_type
#undef _
  } punt_type_t;

typedef struct punt_l4_t_
{
  ip_address_family_t af;
  ip_protocol_t protocol;
  u16 port;
} punt_l4_t;

typedef struct punt_ip_proto_t_
{
  ip_address_family_t af;
  ip_protocol_t protocol;
} punt_ip_proto_t;

typedef struct punt_exception_t_
{
  vlib_punt_reason_t reason;
} punt_exception_t;

typedef struct punt_union_t_
{
  punt_exception_t exception;
  punt_l4_t l4;
  punt_ip_proto_t ip_proto;
} punt_union_t;

typedef struct punt_reg_t_
{
  punt_type_t type;
  punt_union_t punt;
} punt_reg_t;


clib_error_t *vnet_punt_add_del (vlib_main_t * vm,
				 const punt_reg_t * pr, bool is_add);
clib_error_t *vnet_punt_socket_add (vlib_main_t * vm,
				    u32 header_version,
				    const punt_reg_t * pr,
				    char *client_pathname);
clib_error_t *vnet_punt_socket_del (vlib_main_t * vm, const punt_reg_t * pr);
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
  punt_reg_t reg;
  struct sockaddr_un caddr;
} punt_client_t;

typedef struct punt_client_db_t_
{
  void *clients_by_l4_port;
  u32 *clients_by_exception;
  void *clients_by_ip_proto;
} punt_client_db_t;

typedef struct punt_thread_data_t_
{
  struct iovec *iovecs;
} punt_thread_data_t;

typedef struct
{
  int socket_fd;
  char sun_path[sizeof (struct sockaddr_un)];
  punt_client_db_t db;
  punt_client_t *punt_client_pool;
  u32 clib_file_index;
  bool is_configured;
  vlib_node_t *interface_output_node;
  u32 *ready_fds;
  u32 *rx_buffers;
  punt_thread_data_t *thread_data;
  vlib_punt_hdl_t hdl;
} punt_main_t;

extern punt_main_t punt_main;

typedef walk_rc_t (*punt_client_walk_cb_t) (const punt_client_t * pc,
					    void *ctx);
extern void punt_client_walk (punt_type_t pt,
			      punt_client_walk_cb_t cb, void *ctx);

extern u8 *format_vnet_punt_reason_flags (u8 *s, va_list *args);

/*
 * inlines for the data-plane
 */
static_always_inline u32
punt_client_l4_mk_key (ip_address_family_t af, u16 port)
{
  return (af << BITS (port) | port);
}

static_always_inline punt_client_t *
punt_client_l4_get (ip_address_family_t af, u16 port)
{
  punt_main_t *pm = &punt_main;
  uword *p;

  p = hash_get (pm->db.clients_by_l4_port, punt_client_l4_mk_key (af, port));

  if (p)
    return (pool_elt_at_index (pm->punt_client_pool, p[0]));

  return (NULL);
}

static_always_inline u32
punt_client_ip_proto_mk_key (ip_address_family_t af, ip_protocol_t proto)
{
  return (af << 16 | proto);
}

static_always_inline punt_client_t *
punt_client_ip_proto_get (ip_address_family_t af, ip_protocol_t proto)
{
  punt_main_t *pm = &punt_main;
  uword *p;

  p =
    hash_get (pm->db.clients_by_ip_proto,
	      punt_client_ip_proto_mk_key (af, proto));

  if (p)
    return (pool_elt_at_index (pm->punt_client_pool, p[0]));

  return (NULL);
}

static_always_inline punt_client_t *
punt_client_exception_get (vlib_punt_reason_t reason)
{
  punt_main_t *pm = &punt_main;
  u32 pci;

  if (reason >= vec_len (pm->db.clients_by_exception))
    return (NULL);

  pci = pm->db.clients_by_exception[reason];

  if (~0 != pci)
    return (pool_elt_at_index (pm->punt_client_pool, pci));

  return (NULL);
}

extern vlib_node_registration_t udp4_punt_node;
extern vlib_node_registration_t udp6_punt_node;
extern vlib_node_registration_t udp4_punt_socket_node;
extern vlib_node_registration_t udp6_punt_socket_node;
extern vlib_node_registration_t ip4_proto_punt_socket_node;
extern vlib_node_registration_t ip6_proto_punt_socket_node;
extern vlib_node_registration_t punt_socket_rx_node;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
