/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_dpdk_h__
#define __included_dpdk_h__

/* $$$$ We should rename always_inline -> clib_always_inline */
#undef always_inline

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
#include <rte_eth_bond.h>
#include <rte_sched.h>
#include <rte_net.h>

#include <vnet/unix/pcap.h>
#include <vnet/devices/devices.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#include <vlib/pci/pci.h>

#define NB_MBUF   (16<<10)

extern vnet_device_class_t dpdk_device_class;
extern vlib_node_registration_t dpdk_input_node;

#define foreach_dpdk_pmd          \
  _ ("net_thunderx", THUNDERX)    \
  _ ("net_e1000_em", E1000EM)     \
  _ ("net_e1000_igb", IGB)        \
  _ ("net_e1000_igb_vf", IGBVF)   \
  _ ("net_ixgbe", IXGBE)          \
  _ ("net_ixgbe_vf", IXGBEVF)     \
  _ ("net_i40e", I40E)            \
  _ ("net_i40e_vf", I40EVF)       \
  _ ("net_virtio", VIRTIO)        \
  _ ("net_enic", ENIC)            \
  _ ("net_vmxnet3", VMXNET3)      \
  _ ("AF_PACKET PMD", AF_PACKET)  \
  _ ("net_bonding", BOND)         \
  _ ("net_fm10k", FM10K)          \
  _ ("net_cxgbe", CXGBE)          \
  _ ("net_mlx4", MLX4)            \
  _ ("net_mlx5", MLX5)            \
  _ ("net_dpaa2", DPAA2)          \
  _ ("net_virtio_user", VIRTIO_USER) \
  _ ("net_vhost", VHOST_ETHER)

typedef enum
{
  VNET_DPDK_PMD_NONE,
#define _(s,f) VNET_DPDK_PMD_##f,
  foreach_dpdk_pmd
#undef _
    VNET_DPDK_PMD_UNKNOWN,	/* must be last */
} dpdk_pmd_t;

typedef enum
{
  VNET_DPDK_PORT_TYPE_ETH_1G,
  VNET_DPDK_PORT_TYPE_ETH_10G,
  VNET_DPDK_PORT_TYPE_ETH_25G,
  VNET_DPDK_PORT_TYPE_ETH_40G,
  VNET_DPDK_PORT_TYPE_ETH_50G,
  VNET_DPDK_PORT_TYPE_ETH_100G,
  VNET_DPDK_PORT_TYPE_ETH_BOND,
  VNET_DPDK_PORT_TYPE_ETH_SWITCH,
  VNET_DPDK_PORT_TYPE_AF_PACKET,
  VNET_DPDK_PORT_TYPE_ETH_VF,
  VNET_DPDK_PORT_TYPE_VIRTIO_USER,
  VNET_DPDK_PORT_TYPE_VHOST_ETHER,
  VNET_DPDK_PORT_TYPE_UNKNOWN,
} dpdk_port_type_t;

/*
 * The header for the tx_vector in dpdk_device_t.
 * Head and tail are indexes into the tx_vector and are of type
 * u64 so they never overflow.
 */
typedef struct
{
  u64 tx_head;
  u64 tx_tail;
} tx_ring_hdr_t;

typedef struct
{
  struct rte_ring *swq;

  u64 hqos_field0_slabmask;
  u32 hqos_field0_slabpos;
  u32 hqos_field0_slabshr;
  u64 hqos_field1_slabmask;
  u32 hqos_field1_slabpos;
  u32 hqos_field1_slabshr;
  u64 hqos_field2_slabmask;
  u32 hqos_field2_slabpos;
  u32 hqos_field2_slabshr;
  u32 hqos_tc_table[64];
} dpdk_device_hqos_per_worker_thread_t;

typedef struct
{
  struct rte_ring **swq;
  struct rte_mbuf **pkts_enq;
  struct rte_mbuf **pkts_deq;
  struct rte_sched_port *hqos;
  u32 hqos_burst_enq;
  u32 hqos_burst_deq;
  u32 pkts_enq_len;
  u32 swq_pos;
  u32 flush_count;
} dpdk_device_hqos_per_hqos_thread_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 **lockp;

  /* Instance ID */
  u32 device_index;

  u32 hw_if_index;
  u32 vlib_sw_if_index;

  /* next node index if we decide to steal the rx graph arc */
  u32 per_interface_next_index;

  /* dpdk rte_mbuf rx and tx vectors, VLIB_FRAME_SIZE */
  struct rte_mbuf ***tx_vectors;	/* one per worker thread */
  struct rte_mbuf ***rx_vectors;

  /* vector of traced contexts, per device */
  u32 **d_trace_buffers;

  dpdk_pmd_t pmd:8;
  i8 cpu_socket;

  u16 flags;
#define DPDK_DEVICE_FLAG_ADMIN_UP           (1 << 0)
#define DPDK_DEVICE_FLAG_PROMISC            (1 << 1)
#define DPDK_DEVICE_FLAG_PMD                (1 << 2)
#define DPDK_DEVICE_FLAG_PMD_INIT_FAIL      (1 << 3)
#define DPDK_DEVICE_FLAG_MAYBE_MULTISEG     (1 << 4)
#define DPDK_DEVICE_FLAG_HAVE_SUBIF         (1 << 5)
#define DPDK_DEVICE_FLAG_HQOS               (1 << 6)
#define DPDK_DEVICE_FLAG_BOND_SLAVE         (1 << 7)
#define DPDK_DEVICE_FLAG_BOND_SLAVE_UP      (1 << 8)
#define DPDK_DEVICE_FLAG_TX_OFFLOAD         (1 << 9)
#define DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM   (1 << 10)

  u16 nb_tx_desc;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  u8 *interface_name_suffix;

  /* number of sub-interfaces */
  u16 num_subifs;

  /* PMD related */
  u16 tx_q_used;
  u16 rx_q_used;
  u16 nb_rx_desc;
  u16 *cpu_socket_id_by_queue;
  struct rte_eth_conf port_conf;
  struct rte_eth_txconf tx_conf;

  /* HQoS related */
  dpdk_device_hqos_per_worker_thread_t *hqos_wt;
  dpdk_device_hqos_per_hqos_thread_t *hqos_ht;

  /* af_packet or BondEthernet instance number */
  u8 port_id;

  /* Bonded interface port# of a slave -
     only valid if DPDK_DEVICE_FLAG_BOND_SLAVE bit is set */
  u8 bond_port;

  struct rte_eth_link link;
  f64 time_last_link_update;

  struct rte_eth_stats stats;
  struct rte_eth_stats last_stats;
  struct rte_eth_stats last_cleared_stats;
  struct rte_eth_xstat *xstats;
  struct rte_eth_xstat *last_cleared_xstats;
  f64 time_last_stats_update;
  dpdk_port_type_t port_type;

  /* mac address */
  u8 *default_mac_address;

  /* error string */
  clib_error_t *errors;
} dpdk_device_t;

#define DPDK_STATS_POLL_INTERVAL      (10.0)
#define DPDK_MIN_STATS_POLL_INTERVAL  (0.001)	/* 1msec */

#define DPDK_LINK_POLL_INTERVAL       (3.0)
#define DPDK_MIN_LINK_POLL_INTERVAL   (0.001)	/* 1msec */

typedef struct
{
  u32 device;
  u16 queue_id;
} dpdk_device_and_queue_t;

#ifndef DPDK_HQOS_DBG_BYPASS
#define DPDK_HQOS_DBG_BYPASS 0
#endif

#ifndef HQOS_FLUSH_COUNT_THRESHOLD
#define HQOS_FLUSH_COUNT_THRESHOLD              100000
#endif

typedef struct dpdk_device_config_hqos_t
{
  u32 hqos_thread;
  u32 hqos_thread_valid;

  u32 swq_size;
  u32 burst_enq;
  u32 burst_deq;

  u32 pktfield0_slabpos;
  u32 pktfield1_slabpos;
  u32 pktfield2_slabpos;
  u64 pktfield0_slabmask;
  u64 pktfield1_slabmask;
  u64 pktfield2_slabmask;
  u32 tc_table[64];

  struct rte_sched_port_params port;
  struct rte_sched_subport_params *subport;
  struct rte_sched_pipe_params *pipe;
  uint32_t *pipe_map;
} dpdk_device_config_hqos_t;

int dpdk_hqos_validate_mask (u64 mask, u32 n);
void dpdk_device_config_hqos_pipe_profile_default (dpdk_device_config_hqos_t *
						   hqos, u32 pipe_profile_id);
void dpdk_device_config_hqos_default (dpdk_device_config_hqos_t * hqos);
clib_error_t *dpdk_port_setup_hqos (dpdk_device_t * xd,
				    dpdk_device_config_hqos_t * hqos);
void dpdk_hqos_metadata_set (dpdk_device_hqos_per_worker_thread_t * hqos,
			     struct rte_mbuf **pkts, u32 n_pkts);

#define foreach_dpdk_device_config_item \
  _ (num_rx_queues) \
  _ (num_tx_queues) \
  _ (num_rx_desc) \
  _ (num_tx_desc) \
  _ (rss_fn)

typedef struct
{
  vlib_pci_addr_t pci_addr;
  u8 is_blacklisted;
  u8 vlan_strip_offload;
#define DPDK_DEVICE_VLAN_STRIP_DEFAULT 0
#define DPDK_DEVICE_VLAN_STRIP_OFF 1
#define DPDK_DEVICE_VLAN_STRIP_ON  2

#define _(x) uword x;
    foreach_dpdk_device_config_item
#undef _
    clib_bitmap_t * workers;
  u32 hqos_enabled;
  dpdk_device_config_hqos_t hqos;
} dpdk_device_config_t;

typedef struct
{

  /* Config stuff */
  u8 **eal_init_args;
  u8 *eal_init_args_str;
  u8 *uio_driver_name;
  u8 no_multi_seg;
  u8 enable_tcp_udp_checksum;

  /* Required config parameters */
  u8 coremask_set_manually;
  u8 nchannels_set_manually;
  u32 coremask;
  u32 nchannels;
  u32 num_mbufs;

  /*
   * format interface names ala xxxEthernet%d/%d/%d instead of
   * xxxEthernet%x/%x/%x.
   */
  u8 interface_name_format_decimal;

  /* per-device config */
  dpdk_device_config_t default_devconf;
  dpdk_device_config_t *dev_confs;
  uword *device_config_index_by_pci_addr;

} dpdk_config_main_t;

dpdk_config_main_t dpdk_config_main;

typedef struct
{

  /* Devices */
  dpdk_device_t *devices;
  dpdk_device_and_queue_t **devices_by_hqos_cpu;

  /* per-thread recycle lists */
  u32 **recycle;

  /* per-thread buffer templates */
  vlib_buffer_t *buffer_templates;

  /* buffer flags template, configurable to enable/disable tcp / udp cksum */
  u32 buffer_flags_template;

  /* vlib buffer free list, must be same size as an rte_mbuf */
  u32 vlib_buffer_free_list_index;

  /* Ethernet input node index */
  u32 ethernet_input_node_index;

  /* pcap tracing [only works if (CLIB_DEBUG > 0)] */
  int tx_pcap_enable;
  pcap_main_t pcap_main;
  u8 *pcap_filename;
  u32 pcap_sw_if_index;
  u32 pcap_pkts_to_capture;

  /*
   * flag indicating that a posted admin up/down
   * (via post_sw_interface_set_flags) is in progress
   */
  u8 admin_up_down_in_progress;

  u8 use_rss;

  /* which cpus are running I/O TX */
  int hqos_cpu_first_index;
  int hqos_cpu_count;

  /* control interval of dpdk link state and stat polling */
  f64 link_state_poll_interval;
  f64 stat_poll_interval;

  /* Sleep for this many usec after each device poll */
  u32 poll_sleep_usec;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  dpdk_config_main_t *conf;

  /* mempool */
  struct rte_mempool **pktmbuf_pools;

  /* API message ID base */
  u16 msg_id_base;
} dpdk_main_t;

extern dpdk_main_t dpdk_main;

typedef struct
{
  u32 buffer_index;
  u16 device_index;
  u8 queue_index;
  struct rte_mbuf mb;
  /* Copy of VLIB buffer; packet data stored in pre_data. */
  vlib_buffer_t buffer;
} dpdk_tx_dma_trace_t;

typedef struct
{
  u32 buffer_index;
  u16 device_index;
  u16 queue_index;
  struct rte_mbuf mb;
  vlib_buffer_t buffer;		/* Copy of VLIB buffer; pkt data stored in pre_data. */
  u8 data[256];			/* First 256 data bytes, used for hexdump */
} dpdk_rx_dma_trace_t;

void dpdk_device_setup (dpdk_device_t * xd);
void dpdk_device_start (dpdk_device_t * xd);
void dpdk_device_stop (dpdk_device_t * xd);

#if DPDK_VOID_CALLBACK
void dpdk_port_state_callback (uint8_t port_id,
			       enum rte_eth_event_type type, void *param);
#else
int dpdk_port_state_callback (uint8_t port_id,
			      enum rte_eth_event_type type,
			      void *param, void *ret_param);
#endif

#define foreach_dpdk_error						\
  _(NONE, "no error")							\
  _(RX_PACKET_ERROR, "Rx packet errors")				\
  _(RX_BAD_FCS, "Rx bad fcs")						\
  _(IP_CHECKSUM_ERROR, "Rx ip checksum errors")				\
  _(RX_ALLOC_FAIL, "rx buf alloc from free list failed")		\
  _(RX_ALLOC_NO_PHYSMEM, "rx buf alloc failed no physmem")		\
  _(RX_ALLOC_DROP_PKTS, "rx packets dropped due to alloc error")

typedef enum
{
#define _(f,s) DPDK_ERROR_##f,
  foreach_dpdk_error
#undef _
    DPDK_N_ERROR,
} dpdk_error_t;

void dpdk_update_link_state (dpdk_device_t * xd, f64 now);

format_function_t format_dpdk_device_name;
format_function_t format_dpdk_device;
format_function_t format_dpdk_device_errors;
format_function_t format_dpdk_tx_dma_trace;
format_function_t format_dpdk_rx_dma_trace;
format_function_t format_dpdk_rte_mbuf;
format_function_t format_dpdk_rx_rte_mbuf;
unformat_function_t unformat_dpdk_log_level;
clib_error_t *unformat_rss_fn (unformat_input_t * input, uword * rss_fn);
clib_error_t *unformat_hqos (unformat_input_t * input,
			     dpdk_device_config_hqos_t * hqos);

uword
admin_up_down_process (vlib_main_t * vm,
		       vlib_node_runtime_t * rt, vlib_frame_t * f);

clib_error_t *dpdk_buffer_pool_create (vlib_main_t * vm, unsigned num_mbufs,
				       unsigned socket_id);

#endif /* __included_dpdk_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
