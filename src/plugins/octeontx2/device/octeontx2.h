/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

/* Copyright (c) 2019 Marvell International Ltd. */

#ifndef __included_octeontx2_h__
#define __included_octeontx2_h__

/* $$$$ We should rename always_inline -> clib_always_inline */
#undef always_inline

#define ALLOW_EXPERIMENTAL_API

#include <rte_config.h>

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>
#include <rte_sched.h>
#include <rte_net.h>
#include <rte_bus_pci.h>
#include <rte_flow.h>

#include <vnet/devices/devices.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#include <vlib/pci/pci.h>
#include <vnet/flow/flow.h>

extern vnet_device_class_t otx2_device_class;
extern vlib_node_registration_t otx2_input_node;
extern vlib_node_registration_t admin_up_down_process_node;

#define foreach_otx2_pmd          \
  _ ("net_octeontx2", OCTEONTX2)

typedef enum
{
  VNET_OTX2_PMD_NONE,
#define _(s,f) VNET_OTX2_PMD_##f,
  foreach_otx2_pmd
#undef _
    VNET_OTX2_PMD_UNKNOWN,	/* must be last */
} octeontx2_pmd_t;

typedef enum
{
  VNET_OTX2_PORT_TYPE_ETH_1G,
  VNET_OTX2_PORT_TYPE_ETH_2_5G,
  VNET_OTX2_PORT_TYPE_ETH_5G,
  VNET_OTX2_PORT_TYPE_ETH_10G,
  VNET_OTX2_PORT_TYPE_ETH_20G,
  VNET_OTX2_PORT_TYPE_ETH_25G,
  VNET_OTX2_PORT_TYPE_ETH_40G,
  VNET_OTX2_PORT_TYPE_ETH_50G,
  VNET_OTX2_PORT_TYPE_ETH_56G,
  VNET_OTX2_PORT_TYPE_ETH_100G,
  VNET_OTX2_PORT_TYPE_ETH_VF,
  VNET_OTX2_PORT_TYPE_UNKNOWN,
} otx2_port_type_t;

typedef uint16_t otx2_portid_t;

#define foreach_otx2_device_flags \
  _( 0, ADMIN_UP, "admin-up") \
  _( 1, PROMISC, "promisc") \
  _( 2, PMD, "pmd") \
  _( 3, PMD_INIT_FAIL, "pmd-init-fail") \
  _( 4, MAYBE_MULTISEG, "maybe-multiseg") \
  _( 5, HAVE_SUBIF, "subif") \
  _( 9, TX_OFFLOAD, "tx-offload") \
  _(11, RX_FLOW_OFFLOAD, "rx-flow-offload") \
  _(12, RX_IP4_CKSUM, "rx-ip4-cksum")

enum
{
#define _(a, b, c) OTX2_DEVICE_FLAG_##b = (1 << a),
  foreach_otx2_device_flags
#undef _
};

typedef struct
{
  u32 flow_index;
  u32 mark;
  struct rte_flow *handle;
} otx2_flow_entry_t;

typedef struct
{
  u32 flow_id;
  u16 next_index;
  i16 buffer_advance;
} otx2_flow_lookup_entry_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 **lockp;

  /* Instance ID to access internal device array. */
  otx2_portid_t device_index;

  otx2_portid_t port_id;

  u32 hw_if_index;
  u32 sw_if_index;

  /* next node index if we decide to steal the rx graph arc */
  u32 per_interface_next_index;

  octeontx2_pmd_t pmd:8;
  i8 cpu_socket;

  u16 flags;

  u16 nb_tx_desc;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  u8 *name;
  u8 *interface_name_suffix;

  /* number of sub-interfaces */
  u16 num_subifs;

  /* PMD related */
  u16 tx_q_used;
  u16 rx_q_used;
  u16 nb_rx_desc;
  u16 *cpu_socket_id_by_queue;
  u8 *buffer_pool_for_queue;
  struct rte_eth_conf port_conf;
  struct rte_eth_txconf tx_conf;

  /* flow related */
  u32 supported_flow_actions;
  otx2_flow_entry_t *flow_entries;	/* pool */
  otx2_flow_lookup_entry_t *flow_lookup_entries;	/* pool */
  u32 *parked_lookup_indexes;	/* vector */
  u32 parked_loop_count;
  struct rte_flow_error last_flow_error;

  struct rte_eth_link link;
  f64 time_last_link_update;

  struct rte_eth_stats stats;
  struct rte_eth_stats last_stats;
  struct rte_eth_stats last_cleared_stats;
  struct rte_eth_xstat *xstats;
  f64 time_last_stats_update;
  otx2_port_type_t port_type;

  /* mac address */
  u8 *default_mac_address;

  /* error string */
  clib_error_t *errors;
} otx2_device_t;

#define OTX2_STATS_POLL_INTERVAL      (10.0)
#define OTX2_MIN_STATS_POLL_INTERVAL  (0.001)	/* 1msec */

#define OTX2_LINK_POLL_INTERVAL       (3.0)
#define OTX2_MIN_LINK_POLL_INTERVAL   (0.001)	/* 1msec */

typedef struct
{
  u32 device;
  u16 queue_id;
} otx2_device_and_queue_t;

#define foreach_otx2_device_config_item \
  _ (num_rx_queues) \
  _ (num_tx_queues) \
  _ (num_rx_desc) \
  _ (num_tx_desc) \
  _ (rss_fn)

typedef struct
{
  vlib_pci_addr_t pci_addr;
  u8 *name;
  u8 vlan_strip_offload;
#define OTX2_DEVICE_VLAN_STRIP_DEFAULT 0
#define OTX2_DEVICE_VLAN_STRIP_OFF 1
#define OTX2_DEVICE_VLAN_STRIP_ON  2

#define _(x) uword x;
    foreach_otx2_device_config_item
#undef _
    clib_bitmap_t * workers;
} otx2_device_config_t;

typedef struct
{
  /* Config stuff */
  u8 **eal_init_args;
  u8 *eal_init_args_str;
  u8 *uio_driver_name;
  u8 no_multi_seg;
  u8 enable_tcp_udp_checksum;
  u8 no_tx_checksum_offload;

  /* Required config parameters */
  u8 coremask_set_manually;
  u8 nchannels_set_manually;
  u32 coremask;
  u32 nchannels;
  u32 num_mbufs;
  u32 num_crypto_mbufs;

  /* per-device config */
  otx2_device_config_t default_devconf;
  otx2_device_config_t *dev_confs;
  uword *device_config_index_by_pci_addr;

} otx2_config_main_t;

extern otx2_config_main_t otx2_config_main;

#define OTX2_RX_BURST_SZ VLIB_FRAME_SIZE
#define OTX2_MAX_NUM_MEMPOOLS  8

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *vbufs[OTX2_RX_BURST_SZ];
  u32 buffers[OTX2_RX_BURST_SZ];
  u16 next[OTX2_RX_BURST_SZ];
  vlib_buffer_t buffer_template;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  /*count to refill or deplete pool */
  i64 n_buffers_to_free;
  /*Device flags */
  u64 xd_flags;
  /*Number of packet bytes */
  u32 rx_n_bytes;
  /*packet offload flags */
  u16 rx_or_flags;
  /*n_packets not freed by device due to b->refcount >1 */
  u16 tx_not_freed;
  u32 buffer_pool_index;
  struct rte_mempool *otx2_mempool_by_index[OTX2_MAX_NUM_MEMPOOLS];
} otx2_per_thread_data_t __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)));

typedef struct
{
  /* Devices */
  otx2_device_t *devices;
  otx2_per_thread_data_t *per_thread_data;

  /* buffer flags template, configurable to enable/disable tcp / udp cksum */
  u32 buffer_flags_template;

  /*
   * flag indicating that a posted admin up/down
   * (via post_sw_interface_set_flags) is in progress
   */
  u8 admin_up_down_in_progress;

  /* control interval of octeontx2 link state and stat polling */
  f64 link_state_poll_interval;
  f64 stat_poll_interval;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  otx2_config_main_t *conf;

  /* logging */
  vlib_log_class_t log_default;
} otx2_main_t;

extern otx2_main_t otx2_main;

typedef struct
{
  u32 buffer_index;
  u16 device_index;
  u8 queue_index;
  vlib_buffer_t buffer;
  u8 data[256];			/* First 256 data bytes, used for hexdump */
} otx2_tx_trace_t;

typedef struct
{
  u32 buffer_index;
  u16 device_index;
  u16 queue_index;
  vlib_buffer_t buffer;
  u8 data[256];			/* First 256 data bytes, used for hexdump */
} otx2_rx_trace_t;

void otx2_device_setup (otx2_device_t * xd);
void otx2_device_start (otx2_device_t * xd);
void otx2_device_stop (otx2_device_t * xd);

int otx2_port_state_callback (otx2_portid_t port_id,
			      enum rte_eth_event_type type,
			      void *param, void *ret_param);

#define foreach_otx2_error						\
  _(NONE, "no error")							\
  _(RX_PACKET_ERROR, "Rx packet errors")				\
  _(RX_BAD_FCS, "Rx bad fcs")						\
  _(IP_CHECKSUM_ERROR, "Rx ip checksum errors")				\
  _(RX_ALLOC_FAIL, "rx buf alloc from free list failed")		\
  _(RX_ALLOC_NO_PHYSMEM, "rx buf alloc failed no physmem")		\
  _(RX_ALLOC_DROP_PKTS, "rx packets dropped due to alloc error")

typedef enum
{
#define _(f,s) OTX2_ERROR_##f,
  foreach_otx2_error
#undef _
    OTX2_N_ERROR,
} otx2_error_t;

#define otx2_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, otx2_main.log_default, __VA_ARGS__)
#define otx2_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, otx2_main.log_default, __VA_ARGS__)
#define otx2_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, otx2_main.log_default, __VA_ARGS__)
#define otx2_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, otx2_main.log_default, __VA_ARGS__)

void otx2_update_link_state (otx2_device_t * xd, f64 now);

format_function_t format_otx2_device_name;
format_function_t format_otx2_device;
format_function_t format_otx2_device_errors;
format_function_t format_otx2_tx_trace;
format_function_t format_otx2_rx_trace;
format_function_t format_otx2_flow;
format_function_t format_otx2_rss_hf_name;
format_function_t format_otx2_rx_offload_caps;
format_function_t format_otx2_tx_offload_caps;
vnet_flow_dev_ops_function_t otx2_flow_ops_fn;

clib_error_t *unformat_rss_fn (unformat_input_t * input, uword * rss_fn);

struct rte_pci_device *otx2_get_pci_device (const struct rte_eth_dev_info
					    *info);
#if CLI_DEBUG
int otx2_buffer_validate_trajectory_all (u32 * uninitialized);
void otx2_buffer_poison_trajectory_all (void);
#endif

#endif /* __included_octeontx2_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
