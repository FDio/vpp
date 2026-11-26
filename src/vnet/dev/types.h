/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_TYPES_H_
#define _VNET_DEV_TYPES_H_

#include <vppinfra/types.h>
#include <vnet/dev/errors.h>

typedef char vnet_dev_device_id_t[48];
typedef char vnet_dev_if_name_t[32];
typedef char vnet_dev_driver_name_t[16];
typedef char vnet_dev_bus_name_t[16];
typedef u16 vnet_dev_port_id_t;
typedef struct vnet_dev vnet_dev_t;
typedef struct vnet_dev_port vnet_dev_port_t;
typedef struct vnet_dev_rx_queue vnet_dev_rx_queue_t;
typedef struct vnet_dev_tx_queue vnet_dev_tx_queue_t;

/* Frame sizes (max_rx_frame_size, max_supported_rx_frame_size) follow IEEE 802.3
 * and include the Ethernet FCS, so they are what the hardware counts. */
#define VNET_DEV_ETH_FCS_LEN 4

#define VNET_DEV_RSS_KEY_MAX_SIZE 64
#define VNET_DEV_RSS_LUT_MAX_SIZE 256

/* traffic classes for rss hash fields, a class which is not set uses the
 * fields of its parent */
#define foreach_vnet_dev_rss_class                                                                 \
  _ (DEFAULT, "default", DEFAULT)                                                                  \
  _ (IP4, "ipv4", DEFAULT)                                                                         \
  _ (IP4_TCP, "ipv4-tcp", IP4)                                                                     \
  _ (IP4_UDP, "ipv4-udp", IP4)                                                                     \
  _ (IP4_SCTP, "ipv4-sctp", IP4)                                                                   \
  _ (IP4_ESP, "ipv4-esp", IP4)                                                                     \
  _ (IP4_AH, "ipv4-ah", IP4)                                                                       \
  _ (IP4_IPIP_GRE, "ipv4-ipip-gre", IP4)                                                           \
  _ (IP4_IPIP, "ipv4-ipip", IP4_IPIP_GRE)                                                          \
  _ (IP4_GRE, "ipv4-gre", IP4_IPIP_GRE)                                                            \
  _ (IP4_VXLAN, "ipv4-vxlan", IP4_UDP)                                                             \
  _ (IP4_GENEVE, "ipv4-geneve", IP4_UDP)                                                           \
  _ (IP4_GTPU, "ipv4-gtpu", IP4_UDP)                                                               \
  _ (IP6, "ipv6", DEFAULT)                                                                         \
  _ (IP6_TCP, "ipv6-tcp", IP6)                                                                     \
  _ (IP6_UDP, "ipv6-udp", IP6)                                                                     \
  _ (IP6_SCTP, "ipv6-sctp", IP6)                                                                   \
  _ (IP6_ESP, "ipv6-esp", IP6)                                                                     \
  _ (IP6_AH, "ipv6-ah", IP6)                                                                       \
  _ (IP6_IPIP_GRE, "ipv6-ipip-gre", IP6)                                                           \
  _ (IP6_IPIP, "ipv6-ipip", IP6_IPIP_GRE)                                                          \
  _ (IP6_GRE, "ipv6-gre", IP6_IPIP_GRE)                                                            \
  _ (IP6_VXLAN, "ipv6-vxlan", IP6_UDP)                                                             \
  _ (IP6_GENEVE, "ipv6-geneve", IP6_UDP)                                                           \
  _ (IP6_GTPU, "ipv6-gtpu", IP6_UDP)

typedef enum
{
#define _(n, s, p) VNET_DEV_RSS_CLASS_##n,
  foreach_vnet_dev_rss_class
#undef _
    VNET_DEV_RSS_N_CLASSES,
} __clib_packed vnet_dev_rss_class_t;

#define foreach_vnet_dev_rss_field                                                                 \
  _ (0x01, src_ip, "src-ip", "source IP address")                                                  \
  _ (0x02, dst_ip, "dst-ip", "destination IP address")                                             \
  _ (0x04, src_port, "src-port", "source TCP, UDP or SCTP port")                                   \
  _ (0x08, dst_port, "dst-port", "destination TCP, UDP or SCTP port")                              \
  _ (0x10, spi, "spi", "ESP or AH security parameter index")                                       \
  _ (0x20, inner, "inner", "the other fields from the innermost headers of a tunnel")

typedef union
{
  struct
  {
    u32 src_ip : 1;
    u32 dst_ip : 1;
    u32 src_port : 1;
    u32 dst_port : 1;
    u32 spi : 1;
    u32 inner : 1;
    u32 _reserved : 25;
    u32 is_set : 1;
  };
  u32 as_u32;
} vnet_dev_rss_fields_t;

#define VNET_DEV_RSS_FIELDS_MASK    0x3f
#define VNET_DEV_RSS_FIELDS_INNER   0x20
#define VNET_DEV_RSS_FIELDS_2_TUPLE 0x03
#define VNET_DEV_RSS_FIELDS_4_TUPLE 0x0f

/* names for field masks, 5-tuple is accepted as input only */
#define foreach_vnet_dev_rss_fields_alias                                                          \
  _ ("no-hash", 0, "not hashed, to the queue of the first LUT entry")                              \
  _ ("2-tuple", VNET_DEV_RSS_FIELDS_2_TUPLE, "src-ip,dst-ip")                                      \
  _ ("4-tuple", VNET_DEV_RSS_FIELDS_4_TUPLE, "src-ip,dst-ip,src-port,dst-port")                    \
  _ ("5-tuple", VNET_DEV_RSS_FIELDS_4_TUPLE, "same as 4-tuple")

/* unknown: a fixed function the device doesn't document */
#define foreach_vnet_dev_rss_function                                                              \
  _ (UNKNOWN, "unknown")                                                                           \
  _ (TOEPLITZ, "toeplitz")                                                                         \
  _ (SYMMETRIC_TOEPLITZ, "symmetric-toeplitz")                                                     \
  _ (XOR, "xor")

typedef enum
{
#define _(n, s) VNET_DEV_RSS_FUNCTION_##n,
  foreach_vnet_dev_rss_function
#undef _
    VNET_DEV_RSS_N_FUNCTIONS,
} __clib_packed vnet_dev_rss_function_t;

/* hashing of devices which take ipv4, ipv6 and their tcp and udp either on
 * addresses or on addresses and ports: ip4 and ip6 hash the addresses, the
 * others also the ports */
typedef union
{
  struct
  {
    u8 ip4 : 1;
    u8 ip4_tcp : 1;
    u8 ip4_udp : 1;
    u8 ip6 : 1;
    u8 ip6_tcp : 1;
    u8 ip6_udp : 1;
  };
  u8 as_u8;
} vnet_dev_rss_tuple_types_t;

typedef struct
{
  u8 key[VNET_DEV_RSS_KEY_MAX_SIZE];
  u16 lut[VNET_DEV_RSS_LUT_MAX_SIZE];
  u16 lut_len;
  u8 key_len;
  vnet_dev_rss_fields_t fields[VNET_DEV_RSS_N_CLASSES];
  vnet_dev_rss_function_t function;
  /* change request only, classes which go back to the fields of the parent */
  u32 reset_classes;
  u8 set_key : 1;
  u8 set_lut : 1;
  u8 set_function : 1;
} vnet_dev_rss_config_t;

typedef enum
{
  VNET_DEV_MINUS_OK = 0,
#define _(n, d) VNET_DEV_ERR_MINUS_##n,
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_minus_rv_t;

typedef enum
{
  VNET_DEV_OK = 0,
#define _(n, d) VNET_DEV_ERR_##n = -(VNET_DEV_ERR_MINUS_##n),
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_rv_t;

/* do not change bit assignments - API dependency */
#define foreach_vnet_dev_flag _ (0, NO_STATS, "don't poll device stats")

typedef union
{
  enum
  {
#define _(b, n, d) VNET_DEV_F_##n = 1ull << (b),
    foreach_vnet_dev_flag
#undef _
  } e;
  u32 n;
} vnet_dev_flags_t;

/* do not change bit assignments - API dependency */
#define foreach_vnet_dev_port_flag                                            \
  _ (0, INTERRUPT_MODE, "enable interrupt mode")                              \
  _ (1, CONSISTENT_QP, "consistent queue pairs")                              \
  _ (2, QUEUE_PER_THREAD, "one rx and one tx queue per thread (inc main)")

typedef union
{
  enum
  {
#define _(b, n, d) VNET_DEV_PORT_F_##n = 1ull << (b),
    foreach_vnet_dev_port_flag
#undef _
  } e;
  u32 n;
} vnet_dev_port_flags_t;

typedef enum
{
  VNET_DEV_RX_QUEUE_ASSIGNMENT_ROUND_ROBIN = 0,
  VNET_DEV_RX_QUEUE_ASSIGNMENT_QUEUE_PER_THREAD,
  VNET_DEV_RX_QUEUE_ASSIGNMENT_MAIN_THREAD_ONLY,
} vnet_dev_rx_queue_assignment_t;

#endif /* _VNET_DEV_TYPES_H_ */
