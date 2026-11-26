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
#include <vnet/ip/ip_packet.h>

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

typedef enum
{
  RDMA_TUNNEL_NONE,
  RDMA_TUNNEL_GRE,
  RDMA_TUNNEL_VXLAN,
} __clib_packed rdma_tunnel_t;

/* what a flow matches after the destination mac: ether_type 0 matches anything, l4_spec_type
 * IBV_FLOW_SPEC_TCP or IBV_FLOW_SPEC_UDP, ip_proto an outer ip protocol, a tunnel and the inner
 * ip version and transport */
typedef struct
{
  u16 ether_type;
  u8 l4_spec_type;
  u8 ip_proto;
  rdma_tunnel_t tunnel;
  u16 inner_ether_type;
  u8 inner_l4_spec_type;
} rdma_flow_match_t;

typedef struct
{
  u32 pool_index;
  struct ibv_flow *handle;
  struct ibv_flow_attr attr;
  struct ibv_flow_spec spec;
  rdma_flow_match_t match;
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

/* rss qps: name, string, class, ether type, transport, ip protocol, tunnel, inner ether type and
 * transport, priority. ip4 also takes all traffic which no other qp matches, a qp only exists
 * when it hashes differently than the qp which would take its traffic otherwise */
#define RDMA_E4	 ETHERNET_TYPE_IP4
#define RDMA_E6	 ETHERNET_TYPE_IP6
#define RDMA_TCP IBV_FLOW_SPEC_TCP
#define RDMA_UDP IBV_FLOW_SPEC_UDP
#define foreach_rdma_rss_tunnel_qp(o)                                                              \
  _ (IP##o##_GRE, "ip" #o "-gre", IP##o##_GRE, RDMA_E##o, 0, 0, GRE, 0, 0, 2)                      \
  _ (IP##o##_GRE_IP4, "ip" #o "-gre-ip4", IP##o##_GRE, RDMA_E##o, 0, 0, GRE, RDMA_E4, 0, 1)        \
  _ (IP##o##_GRE_IP4_TCP, "ip" #o "-gre-ip4-tcp", IP##o##_GRE, RDMA_E##o, 0, 0, GRE, RDMA_E4,      \
     RDMA_TCP, 0)                                                                                  \
  _ (IP##o##_GRE_IP4_UDP, "ip" #o "-gre-ip4-udp", IP##o##_GRE, RDMA_E##o, 0, 0, GRE, RDMA_E4,      \
     RDMA_UDP, 0)                                                                                  \
  _ (IP##o##_GRE_IP6, "ip" #o "-gre-ip6", IP##o##_GRE, RDMA_E##o, 0, 0, GRE, RDMA_E6, 0, 1)        \
  _ (IP##o##_GRE_IP6_TCP, "ip" #o "-gre-ip6-tcp", IP##o##_GRE, RDMA_E##o, 0, 0, GRE, RDMA_E6,      \
     RDMA_TCP, 0)                                                                                  \
  _ (IP##o##_GRE_IP6_UDP, "ip" #o "-gre-ip6-udp", IP##o##_GRE, RDMA_E##o, 0, 0, GRE, RDMA_E6,      \
     RDMA_UDP, 0)                                                                                  \
  _ (IP##o##_IPIP_IP4, "ip" #o "-ipip-ip4", IP##o##_IPIP, RDMA_E##o, 0, IP_PROTOCOL_IP_IN_IP,      \
     NONE, RDMA_E4, 0, 1)                                                                          \
  _ (IP##o##_IPIP_IP4_TCP, "ip" #o "-ipip-ip4-tcp", IP##o##_IPIP, RDMA_E##o, 0,                    \
     IP_PROTOCOL_IP_IN_IP, NONE, RDMA_E4, RDMA_TCP, 0)                                             \
  _ (IP##o##_IPIP_IP4_UDP, "ip" #o "-ipip-ip4-udp", IP##o##_IPIP, RDMA_E##o, 0,                    \
     IP_PROTOCOL_IP_IN_IP, NONE, RDMA_E4, RDMA_UDP, 0)                                             \
  _ (IP##o##_IPIP_IP6, "ip" #o "-ipip-ip6", IP##o##_IPIP, RDMA_E##o, 0, IP_PROTOCOL_IPV6, NONE,    \
     RDMA_E6, 0, 1)                                                                                \
  _ (IP##o##_IPIP_IP6_TCP, "ip" #o "-ipip-ip6-tcp", IP##o##_IPIP, RDMA_E##o, 0, IP_PROTOCOL_IPV6,  \
     NONE, RDMA_E6, RDMA_TCP, 0)                                                                   \
  _ (IP##o##_IPIP_IP6_UDP, "ip" #o "-ipip-ip6-udp", IP##o##_IPIP, RDMA_E##o, 0, IP_PROTOCOL_IPV6,  \
     NONE, RDMA_E6, RDMA_UDP, 0)                                                                   \
  _ (IP##o##_VXLAN, "ip" #o "-vxlan", IP##o##_VXLAN, RDMA_E##o, RDMA_UDP, 0, VXLAN, 0, 0, 2)       \
  _ (IP##o##_VXLAN_IP4, "ip" #o "-vxlan-ip4", IP##o##_VXLAN, RDMA_E##o, RDMA_UDP, 0, VXLAN,        \
     RDMA_E4, 0, 1)                                                                                \
  _ (IP##o##_VXLAN_IP4_TCP, "ip" #o "-vxlan-ip4-tcp", IP##o##_VXLAN, RDMA_E##o, RDMA_UDP, 0,       \
     VXLAN, RDMA_E4, RDMA_TCP, 0)                                                                  \
  _ (IP##o##_VXLAN_IP4_UDP, "ip" #o "-vxlan-ip4-udp", IP##o##_VXLAN, RDMA_E##o, RDMA_UDP, 0,       \
     VXLAN, RDMA_E4, RDMA_UDP, 0)                                                                  \
  _ (IP##o##_VXLAN_IP6, "ip" #o "-vxlan-ip6", IP##o##_VXLAN, RDMA_E##o, RDMA_UDP, 0, VXLAN,        \
     RDMA_E6, 0, 1)                                                                                \
  _ (IP##o##_VXLAN_IP6_TCP, "ip" #o "-vxlan-ip6-tcp", IP##o##_VXLAN, RDMA_E##o, RDMA_UDP, 0,       \
     VXLAN, RDMA_E6, RDMA_TCP, 0)                                                                  \
  _ (IP##o##_VXLAN_IP6_UDP, "ip" #o "-vxlan-ip6-udp", IP##o##_VXLAN, RDMA_E##o, RDMA_UDP, 0,       \
     VXLAN, RDMA_E6, RDMA_UDP, 0)

#define foreach_rdma_rss_qp                                                                        \
  _ (IP4, "ip4", IP4, 0, 0, 0, NONE, 0, 0, 5)                                                      \
  _ (IP6, "ip6", IP6, RDMA_E6, 0, 0, NONE, 0, 0, 4)                                                \
  _ (IP4_TCP, "ip4-tcp", IP4_TCP, RDMA_E4, RDMA_TCP, 0, NONE, 0, 0, 3)                             \
  _ (IP4_UDP, "ip4-udp", IP4_UDP, RDMA_E4, RDMA_UDP, 0, NONE, 0, 0, 3)                             \
  _ (IP6_TCP, "ip6-tcp", IP6_TCP, RDMA_E6, RDMA_TCP, 0, NONE, 0, 0, 3)                             \
  _ (IP6_UDP, "ip6-udp", IP6_UDP, RDMA_E6, RDMA_UDP, 0, NONE, 0, 0, 3)                             \
  foreach_rdma_rss_tunnel_qp (4) foreach_rdma_rss_tunnel_qp (6)

enum
{
#define _(n, s, c, e, l4, pr, t, ie, il4, p) RDMA_RSS_##n,
  foreach_rdma_rss_qp
#undef _
    RDMA_RSS_N_QP,
};

typedef struct
{
  struct ibv_rwq_ind_table *rwq_ind_tbl;
  /* first lut entry only, for qps which hash nothing */
  struct ibv_rwq_ind_table *rwq_ind_tbl_first;
  rdma_rss_qp_t qp[RDMA_RSS_N_QP];
} rdma_rss_t;

typedef struct ibv_qp *(rdma_rss_create_qp_fn_t) (struct ibv_context *,
						  struct ibv_qp_init_attr_ex *);

/* create_qp, if set, creates the rss qps, e.g. with device specific flags */
typedef struct
{
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  u32 max_ind_tbl_size;
  u32 hash_function;
  u64 hash_fields_mask;
  rdma_rss_create_qp_fn_t *create_qp;
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
vnet_dev_rss_caps_t rdma_rss_dev_caps (u64 hash_fields_mask, u32 hash_function);
styled_format_fn_t styled_format_rdma_rss_flows;
vnet_dev_rv_t rdma_netdev_set_mtu (u32 ifindex, u32 max_rx_frame_size, clib_error_t **errp);

u32 rdma_port_speed (struct ibv_port_attr *attr);
u32 rdma_port_netdev_ifindex (struct ibv_context *ctx, u8 ibv_port);
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
				     const u8 *mac, const u8 *mask, const rdma_flow_match_t *match,
				     u16 priority, u32 flags, u32 *flow_index);
u8 rdma_mac_in_addrs (vnet_dev_hw_addr_t *addrs, const u8 *mac);
i32 rdma_find_ucast_flow (rdma_rx_mac_flow_t *ucast_flows, const u8 *mac);
vnet_dev_rv_t rdma_program_flow_state (struct ibv_qp *qp, rdma_rx_flow_t ***flows,
				       rdma_rx_mac_flow_t **ucast_flows, u32 *promisc_flow_index,
				       u32 *mcast_flow_index, vnet_dev_hw_addr_t *addrs, u8 promisc,
				       u8 ibv_port, const rdma_flow_match_t *match, u16 priority,
				       u8 with_mcast);
void rdma_rxq_remove_flow_index (rdma_rx_flow_t ***flows, u32 idx);
void rdma_rxq_destroy_flows (rdma_rx_flow_t ***flows);

format_function_t format_rdma_ibv_wc;
styled_format_fn_t styled_format_rdma_ibv_dev_info;
styled_format_fn_t styled_format_rdma_ibv_dev_caps;
format_function_t format_rdma_cap_list;
styled_format_fn_t styled_format_rdma_port_status;
enum
{
  RDMA_RX_FLOW_INDEX_INVALID = ~0,
};
