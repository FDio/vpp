/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/types.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <infiniband/verbs.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/packet.h>

struct ibv_qp;
struct ibv_flow;

#define foreach_rdma_ibv_device_cap_flags                                                          \
  _ (RESIZE_MAX_WR, "resize-max-wr")                                                               \
  _ (BAD_PKEY_CNTR, "bad-pkey-cntr")                                                               \
  _ (BAD_QKEY_CNTR, "bad-qkey-cntr")                                                               \
  _ (RAW_MULTI, "raw-multi")                                                                       \
  _ (AUTO_PATH_MIG, "auto-path-mig")                                                               \
  _ (CHANGE_PHY_PORT, "change-phy-port")                                                           \
  _ (UD_AV_PORT_ENFORCE, "ud-av-port-enforce")                                                     \
  _ (CURR_QP_STATE_MOD, "curr-qp-state-mod")                                                       \
  _ (SHUTDOWN_PORT, "shutdown-port")                                                               \
  _ (INIT_TYPE, "init-type")                                                                       \
  _ (PORT_ACTIVE_EVENT, "port-active-event")                                                       \
  _ (SYS_IMAGE_GUID, "sys-image-guid")                                                             \
  _ (RC_RNR_NAK_GEN, "rc-rnr-nak-gen")                                                             \
  _ (SRQ_RESIZE, "srq-resize")                                                                     \
  _ (N_NOTIFY_CQ, "n-notify-cq")                                                                   \
  _ (MEM_WINDOW, "mem-window")                                                                     \
  _ (UD_IP_CSUM, "ud-ip-csum")                                                                     \
  _ (XRC, "xrc")                                                                                   \
  _ (MEM_MGT_EXTENSIONS, "mem-mgt-extensions")                                                     \
  _ (MEM_WINDOW_TYPE_2A, "mem-window-type-2a")                                                     \
  _ (MEM_WINDOW_TYPE_2B, "mem-window-type-2b")                                                     \
  _ (RC_IP_CSUM, "rc-ip-csum")                                                                     \
  _ (RAW_IP_CSUM, "raw-ip-csum")                                                                   \
  _ (MANAGED_FLOW_STEERING, "managed-flow-steering")                                               \
  _ (RAW_SCATTER_FCS, "raw-scatter-fcs")                                                           \
  _ (PCI_WRITE_END_PADDING, "pci-write-end-padding")

typedef struct
{
  u64 bit;
  const char *name;
} rdma_cap_name_t;

typedef struct
{
  u32 pool_index;
  struct ibv_flow *handle;
  struct ibv_flow_attr attr;
  struct ibv_flow_spec spec;
} rdma_rx_flow_t;

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

typedef struct
{
  struct ibv_qp *qp;
  rdma_rx_flow_t **flows;
  rdma_rx_mac_flow_t *ucast_flows;
  u32 promisc_flow_index;
  u32 mcast_flow_index;
} rdma_rss_qp_t;

enum
{
  RDMA_RSS_DEFAULT,
  RDMA_RSS_IP6,
};

typedef struct
{
  struct ibv_rwq_ind_table *rwq_ind_tbl;
  rdma_rss_qp_t qp[2];
} rdma_rss_t;

typedef struct
{
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  u32 max_ind_tbl_size;
  u32 hash_function;
  u64 hash_fields_mask;
} rdma_rss_caps_t;

#define RDMA_RSS_KEY_SIZE 40

#define RDMA_NETDEV_MTU_OVERHEAD (sizeof (ethernet_header_t) + VNET_DEV_ETH_FCS_LEN)

void rdma_rss_init (rdma_rss_t *rss);
void rdma_rss_disable (rdma_rss_t *rss);
vnet_dev_rv_t rdma_rss_enable (rdma_rss_t *rss, const rdma_rss_caps_t *caps, struct ibv_wq **wqs,
			       const vnet_dev_rss_config_t *cfg);
vnet_dev_rv_t rdma_rss_program_flows (rdma_rss_t *rss, vnet_dev_port_t *port,
				      vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t rdma_rss_cfg_validate (const rdma_rss_caps_t *caps, const vnet_dev_rss_config_t *req);
void rdma_rss_cfg_merge (vnet_dev_rss_config_t *cfg, const vnet_dev_rss_config_t *req);
format_function_t format_rdma_rss_flows;
vnet_dev_rv_t rdma_netdev_set_mtu (u32 ifindex, u32 max_rx_frame_size, clib_error_t **errp);

u32 rdma_port_speed (struct ibv_port_attr *attr);
u32 rdma_port_netdev_ifindex (vlib_pci_addr_t *addr, u8 ibv_port);
vnet_dev_rv_t rdma_netdev_module_eeprom_read (u32 ifindex, vnet_dev_port_module_eeprom_req_t *r);
int rdma_port_mac (struct ibv_context *ctx, u8 ibv_port, int gid_tbl_len,
		   vnet_dev_hw_addr_t *hw_addr);
uword rdma_sysfs_path_to_pci_addr (char *path, vlib_pci_addr_t *addr);
int rdma_pci_addr_has_device (vlib_pci_addr_t *addr);
vnet_dev_rv_t rdma_open_device (vlib_pci_addr_t *addr, struct ibv_context **ctxp);
int rdma_dev_close (struct ibv_context *ctx, struct ibv_pd *pd, struct ibv_mr *mr);
void rdma_port_poll_state (vlib_main_t *vm, vnet_dev_port_t *port, struct ibv_context *ctx);
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
				     const u8 *mac, const u8 *mask, u16 ether_type, u16 priority,
				     u32 flags, u32 *flow_index);
u8 rdma_mac_in_addrs (vnet_dev_hw_addr_t *addrs, const u8 *mac);
i32 rdma_find_ucast_flow (rdma_rx_mac_flow_t *ucast_flows, const u8 *mac);
vnet_dev_rv_t rdma_program_flow_state (struct ibv_qp *qp, rdma_rx_flow_t ***flows,
				       rdma_rx_mac_flow_t **ucast_flows, u32 *promisc_flow_index,
				       u32 *mcast_flow_index, vnet_dev_hw_addr_t *addrs, u8 promisc,
				       u8 ibv_port, u16 ether_type, u16 priority, u8 with_mcast);
void rdma_rxq_remove_flow_index (rdma_rx_flow_t ***flows, u32 idx);
void rdma_rxq_destroy_flows (rdma_rx_flow_t ***flows);

format_function_t format_rdma_ibv_wc;
format_function_t format_rdma_ibv_dev_info;
format_function_t format_rdma_cap_list;
format_function_t format_rdma_port_status;
enum
{
  RDMA_RX_FLOW_INDEX_INVALID = ~0,
};
