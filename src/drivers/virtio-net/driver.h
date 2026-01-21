/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc. */

#pragma once

#include <vppinfra/clib.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <virtio_net.h>

/* Virtio PCI Capabilities */
#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_ISR_CFG	  3
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
#define VIRTIO_PCI_CAP_PCI_CFG	  5

#define foreach_virtio_config_status_flags                                                         \
  _ (ACK, 0x01)                                                                                    \
  _ (DRIVER, 0x02)                                                                                 \
  _ (DRIVER_OK, 0x04)                                                                              \
  _ (FEATURES_OK, 0x08)                                                                            \
  _ (NEEDS_RESET, 0x40)                                                                            \
  _ (FAILED, 0x80)

typedef enum
{
#define _(a, b) VIRTIO_CONFIG_STATUS_##a = b,
  foreach_virtio_config_status_flags
#undef _
} virtio_config_status_flags_t;

#define foreach_virtio_net_config_status_flags                                                     \
  _ (LINK_UP, 0x01)                                                                                \
  _ (ANNOUNCE, 0x02)

typedef enum
{
#define _(a, b) VIRTIO_NET_S_##a = b,
  foreach_virtio_net_config_status_flags
#undef _
} virtio_net_config_status_flags_t;

typedef struct
{
  u8 cap_vndr;	 /* Generic PCI field: PCI_CAP_ID_VNDR */
  u8 cap_next;	 /* Generic PCI field: next ptr. */
  u8 cap_len;	 /* Generic PCI field: capability length */
  u8 cfg_type;	 /* Identifies the structure. */
  u8 bar;	 /* Where to find it. */
  u8 padding[3]; /* Pad to full dword. */
  u32 offset;	 /* Offset within bar. */
  u32 length;	 /* Length of the structure, in bytes. */
} virtio_pci_cap_t;

typedef struct
{
  virtio_pci_cap_t cap;
  u32 notify_off_multiplier; /* Multiplier for queue_notify_off. */
} virtio_pci_notify_cap_t;

typedef struct
{
  /* About the whole device. */
  u32 device_feature_select; /* read-write */
  u32 device_feature;	     /* read-only */
  u32 driver_feature_select; /* read-write */
  u32 driver_feature;	     /* read-write */
  u16 msix_config;	     /* read-write */
  u16 num_queues;	     /* read-only */
  u8 device_status;	     /* read-write */
  u8 config_generation;	     /* read-only */
  /* About a specific virtqueue. */
  u16 queue_select;	 /* read-write */
  u16 queue_size;	 /* read-write, power of 2. */
  u16 queue_msix_vector; /* read-write */
  u16 queue_enable;	 /* read-write */
  u16 queue_notify_off;	 /* read-only */
  u64 queue_desc;	 /* read-write */
  u64 queue_driver;	 /* read-write */
  u64 queue_device;	 /* read-write */
} virtio_pci_common_cfg_t;

typedef struct
{
  u8 mac[6];
  u16 status;
  u16 max_virtqueue_pairs;
  u16 mtu;
  u32 speed;
  u8 duplex;
  u8 rss_max_key_size;
  u16 rss_max_indirection_table_length;
  u32 supported_hash_types;
} virtio_net_config_t;

typedef struct
{
  u32 dummy;
} vn_port_t;

typedef struct
{
  u32 dummy;
} vn_rxq_t;

typedef struct
{
  u32 dummy;
} vn_txq_t;

typedef struct
{
  virtio_pci_common_cfg_t *common_cfg;
  void *notify_base;
  u8 *isr;
  virtio_net_config_t *device_cfg;
  u32 notify_off_multiplier;
  void *bar[6];
} vn_dev_t;

format_function_t format_virtio_pci_cap_common_cfg;
format_function_t format_virtio_net_config;
format_function_t format_virtio_config_status;
format_function_t format_virtio_net_config_status;
format_function_t format_virtio_pci_isr;
format_function_t format_virtio_pci_notify_cfg;
format_function_t format_virtio_features;
format_function_t format_virtio_net_device_info;
format_function_t format_virtio_net_port_status;

vnet_dev_port_op_t vn_port_init;
vnet_dev_port_op_t vn_port_start;
vnet_dev_port_op_no_rv_t vn_port_stop;

vnet_dev_rx_queue_op_t vn_rx_queue_alloc;
vnet_dev_rx_queue_op_no_rv_t vn_rx_queue_free;

vnet_dev_tx_queue_op_t vn_tx_queue_alloc;
vnet_dev_tx_queue_op_no_rv_t vn_tx_queue_free;

extern vnet_dev_node_t vn_rx_node;
extern vnet_dev_node_t vn_tx_node;

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, vn_log.class, "%U" f, format_vnet_dev_log, (dev),                \
	    clib_string_skip_prefix (__func__, "vn_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, vn_log.class, "%U: " f, format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, vn_log.class, "%U: " f, format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, vn_log.class, "%U: " f, format_vnet_dev_addr, dev,             \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, vn_log.class, "%U: " f, format_vnet_dev_addr, dev, ##__VA_ARGS__)
