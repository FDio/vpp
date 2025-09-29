/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>

typedef struct
{
  vlib_log_class_t log_class;
} dev_virtio_main_t;

extern dev_virtio_main_t dev_virtio_main;

typedef struct
{
  /* mapped register regions */
  void *common_cfg;
  void *notify_base;
  void *isr;
  void *device_cfg;
  u32 notify_off_multiplier;
  u16 notify_cap_offset;
  u16 max_queue_pairs;
  u16 num_queues;
  u16 mtu;
  u8 mac[6];
  u64 features;
  u8 link_up;
  u8 modern;
} dev_virtio_device_t;

typedef struct
{
  u16 primary_queue_pairs;
} dev_virtio_port_t;

typedef struct
{
  u16 queue_id;
} dev_virtio_rxq_t;

typedef struct
{
  u16 queue_id;
} dev_virtio_txq_t;

/* format.c */
format_function_t format_virtio_port_status;

/* pci.c */
vnet_dev_rv_t virtio_pci_map_caps (vlib_main_t *vm, vnet_dev_t *dev,
			      dev_virtio_device_t *vd);

/* port.c */
vnet_dev_rv_t virtio_port_init (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t virtio_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void virtio_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t virtio_port_cfg_change (vlib_main_t *vm,
			       vnet_dev_port_t *port,
			       vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t
virtio_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req);

/* queue.c */
vnet_dev_rv_t virtio_rx_queue_alloc (vlib_main_t *vm,
			       vnet_dev_rx_queue_t *rxq);
void virtio_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t virtio_tx_queue_alloc (vlib_main_t *vm,
			       vnet_dev_tx_queue_t *txq);
void virtio_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
