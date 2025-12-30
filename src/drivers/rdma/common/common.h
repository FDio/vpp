/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/types.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <infiniband/verbs.h>

struct ibv_qp;
struct ibv_flow;

typedef struct
{
  u32 pool_index;
  struct ibv_flow *handle;
  struct ibv_flow_attr attr;
  struct ibv_flow_spec spec;
} rdma_rx_flow_t;

typedef struct
{
  u64 bit;
  const char *name;
} rdma_cap_list_entry_t;

typedef struct
{
  u8 mac[6];
  u32 flow_index;
} rdma_rx_mac_flow_t;

typedef enum
{
  RDMA_QP_STAGE_NONE,
  RDMA_QP_STAGE_RESET,
  RDMA_QP_STAGE_INIT,
  RDMA_QP_STAGE_RTR,
  RDMA_QP_STAGE_RTS,
} rdma_qp_stage_t;

typedef vnet_dev_rv_t (rdma_rxq_irq_enable_fn_t) (vlib_main_t *, vnet_dev_rx_queue_t *);
typedef void (rdma_rxq_irq_disable_fn_t) (vlib_main_t *, vnet_dev_rx_queue_t *);

typedef struct
{
  vnet_dev_rx_queue_t *rxq;
  struct ibv_cq *ibv_cq;
  struct ibv_comp_channel *ibv_comp_ch;
  u32 cq_clib_file_index;
  u8 cq_file_added;
  u8 *driver_name;
} rdma_rxq_irq_t;

u32 rdma_port_speed (u8 speed);
u32 rdma_port_width_lanes (u8 width);
u16 rdma_port_mtu (u8 mtu);
int rdma_gid_to_mac (const union ibv_gid *gid, u8 *mac);
int rdma_qp_start (struct ibv_qp *qp, u8 ibv_port, rdma_qp_stage_t *failed_stage);
int rdma_qp_stop (struct ibv_qp *qp);
void rdma_port_collect_addrs (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req,
			      vnet_dev_hw_addr_t **addrs);
vnet_dev_rv_t rdma_port_cfg_rxq_intr_mode_change (vlib_main_t *vm, vnet_dev_port_t *port, u16 qid,
						  u8 enable, u8 all,
						  rdma_rxq_irq_enable_fn_t *rxq_irq_enable,
						  rdma_rxq_irq_disable_fn_t *rxq_irq_disable);

vnet_dev_rv_t rdma_rxq_irq_enable (vlib_main_t *vm, rdma_rxq_irq_t *ri);
void rdma_rxq_irq_disable (vlib_main_t *vm, rdma_rxq_irq_t *ri);
vnet_dev_rv_t rdma_rxq_add_eth_flow (struct ibv_qp *qp, rdma_rx_flow_t ***flows, u8 ibv_port,
				     const u8 *mac, const u8 *mask, u16 ether_type, u32 flags,
				     u32 *flow_index);
u8 rdma_mac_in_addrs (vnet_dev_hw_addr_t *addrs, const u8 *mac);
i32 rdma_find_ucast_flow (rdma_rx_mac_flow_t *ucast_flows, const u8 *mac);
vnet_dev_rv_t rdma_program_flow_state (struct ibv_qp *qp, rdma_rx_flow_t ***flows,
				       rdma_rx_mac_flow_t **ucast_flows, u32 *promisc_flow_index,
				       u32 *mcast_flow_index, vnet_dev_hw_addr_t *addrs, u8 promisc,
				       u8 ibv_port);
void rdma_rxq_remove_flow_index (rdma_rx_flow_t ***flows, u32 idx);
void rdma_rxq_destroy_flows (rdma_rx_flow_t ***flows);
uword rdma_sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t *addr);

u8 *format_rdma_cap_list (u8 *s, vnet_dev_format_args_t *a, const rdma_cap_list_entry_t *caps_list,
			  u32 n_caps, u64 caps);
format_function_t format_rdma_ibv_flow_spec;
format_function_t format_rdma_ibv_flow_flags;
format_function_t format_rdma_dev_attr_ex;
format_function_t format_rdma_port_attr;
format_function_t format_rdma_dev_info;
format_function_t format_rdma_port_status;
format_function_t format_rdma_rxq_flows;
enum
{
  RDMA_RX_FLOW_INDEX_INVALID = ~0,
};
