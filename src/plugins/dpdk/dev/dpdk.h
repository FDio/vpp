/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#pragma once

#include <vnet/dev/dev.h>
#define __clib_always_inline always_inline
#undef always_inline
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_bus.h>
#include <rte_bus_pci.h>
#include <rte_pci.h>

typedef struct
{
  u32 flow_id;
  u16 next_index;
  i16 buffer_advance;
} dev_dpdk_flow_lookup_entry_t;

typedef struct
{
  u16 port_id;
  u16 tcp_tso : 1;
  u16 udp_tso : 1;
  u16 lro : 1;
  u16 rx_scatter : 1;
  u16 rx_ip4_csum : 1;
  u16 tx_tcp_csum : 1;
  u16 tx_udp_csum : 1;
  u16 tx_ip4_csum : 1;
  u16 tx_outer_ip4_csum : 1;
  u16 tx_outer_udp_csum : 1;
  u64 rx_offload_capa;
  u64 tx_offload_capa;
  u64 rx_offload_config;
  u64 tx_offload_config;
  dev_dpdk_flow_lookup_entry_t *flow_lookup_entries;
} dev_dpdk_port_t;

#define foreach_dev_dpdk_port_arg                                                                  \
  _ (BOOL, TCP_TSO, "tcp_tso", "Enable TCP TSO", .default_val.boolean = 0)                         \
  _ (BOOL, UDP_TSO, "udp_tso", "Enable UDP TSO", .default_val.boolean = 0)                         \
  _ (BOOL, LRO, "lro", "Enable LRO", .default_val.boolean = 0)                                     \
  _ (BOOL, RX_SCATTER, "rx_scatter", "Enable RX scatter", .default_val.boolean = 1)                \
  _ (BOOL, TX_TCP_CSUM, "tx_tcp_csum", "Enable TX TCP checksum", .default_val.boolean = 1)         \
  _ (BOOL, TX_UDP_CSUM, "tx_udp_csum", "Enable TX UDP checksum", .default_val.boolean = 1)         \
  _ (BOOL, TX_IP4_CSUM, "tx_ip4_csum", "Enable TX IPv4 checksum", .default_val.boolean = 1)        \
  _ (BOOL, TX_OUTER_IP4_CSUM, "tx_outer_ip4_csum", "Enable TX outer IPv4 checksum",                \
     .default_val.boolean = 0)                                                                     \
  _ (BOOL, TX_OUTER_UDP_CSUM, "tx_outer_udp_csum", "Enable TX outer UDP checksum",                 \
     .default_val.boolean = 0)

enum
{
#define _(type, id, name, desc, ...) DEV_DPDK_PORT_ARG_##id,
  foreach_dev_dpdk_port_arg
#undef _
};

extern vnet_dev_node_t dev_dpdk_rx_node;
extern vnet_dev_node_t dev_dpdk_tx_node;

static const u64 dev_dpdk_tx_checksum_offload_flags =
  RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM |
  RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
static const u64 dev_dpdk_rx_lro_flags = RTE_ETH_RX_OFFLOAD_TCP_LRO;
static const u64 dev_dpdk_tx_tcp_tso_flags =
  RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_TSO;
static const u64 dev_dpdk_tx_udp_tso_flags =
  RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_TSO;
static const u64 dev_dpdk_rx_scatter_flags = RTE_ETH_RX_OFFLOAD_SCATTER;
static const u64 dev_dpdk_rx_ip4_csum_flags = RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
static const u64 dev_dpdk_tx_tcp_csum_flags = RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
static const u64 dev_dpdk_tx_udp_csum_flags = RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
static const u64 dev_dpdk_tx_ip4_csum_flags = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
static const u64 dev_dpdk_tx_outer_ip4_csum_flags = RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM;
static const u64 dev_dpdk_tx_outer_udp_csum_flags = RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;

vnet_dev_rv_t dev_dpdk_port_alloc (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t dev_dpdk_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void dev_dpdk_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);

format_function_t format_dpdk_rx_offload_caps;
format_function_t format_dpdk_tx_offload_caps;

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dpdk_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "dev_dpdk_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, dpdk_log.class, "%U: " f, format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, dpdk_log.class, "%U: " f, format_vnet_dev_addr, dev,            \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, dpdk_log.class, "%U: " f, format_vnet_dev_addr, dev,           \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, dpdk_log.class, "%U: " f, format_vnet_dev_addr, dev, ##__VA_ARGS__)
