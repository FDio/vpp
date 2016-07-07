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
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#ifdef RTE_LIBRTE_KNI
#include <rte_kni.h>
#endif
#include <rte_virtio_net.h>
#include <rte_pci_dev_ids.h>
#include <rte_version.h>
#include <rte_eth_bond.h>

#include <vnet/unix/pcap.h>
#include <vnet/devices/virtio/vhost-user.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#include <vlib/pci/pci.h>

#define NB_MBUF   (16<<10)

extern vnet_device_class_t dpdk_device_class;
extern vlib_node_registration_t dpdk_input_node;
extern vlib_node_registration_t handoff_dispatch_node;

typedef enum {
  VNET_DPDK_DEV_ETH = 1,      /* Standard DPDK PMD driver */
  VNET_DPDK_DEV_KNI,          /* Kernel NIC Interface */
  VNET_DPDK_DEV_VHOST_USER,
  VNET_DPDK_DEV_UNKNOWN,      /* must be last */
} dpdk_device_type_t;

#define foreach_dpdk_pmd          \
  _ ("rte_nicvf_pmd", THUNDERX)	  \
  _ ("rte_em_pmd", E1000EM)       \
  _ ("rte_igb_pmd", IGB)          \
  _ ("rte_igbvf_pmd", IGBVF)      \
  _ ("rte_ixgbe_pmd", IXGBE)      \
  _ ("rte_ixgbevf_pmd", IXGBEVF)  \
  _ ("rte_i40e_pmd", I40E)        \
  _ ("rte_i40evf_pmd", I40EVF)    \
  _ ("rte_virtio_pmd", VIRTIO)    \
  _ ("rte_enic_pmd", ENIC)        \
  _ ("rte_vmxnet3_pmd", VMXNET3)  \
  _ ("AF_PACKET PMD", AF_PACKET)  \
  _ ("rte_bond_pmd", BOND)        \
  _ ("rte_pmd_fm10k", FM10K)      \
  _ ("rte_cxgbe_pmd", CXGBE)      \
  _ ("rte_dpaa2_dpni", DPAA2)

typedef enum {
  VNET_DPDK_PMD_NONE,
#define _(s,f) VNET_DPDK_PMD_##f,
  foreach_dpdk_pmd
#undef _
  VNET_DPDK_PMD_UNKNOWN, /* must be last */
} dpdk_pmd_t;

typedef enum {
  VNET_DPDK_PORT_TYPE_ETH_1G,
  VNET_DPDK_PORT_TYPE_ETH_10G,
  VNET_DPDK_PORT_TYPE_ETH_40G,
  VNET_DPDK_PORT_TYPE_ETH_BOND,
  VNET_DPDK_PORT_TYPE_ETH_SWITCH,
  VNET_DPDK_PORT_TYPE_AF_PACKET,
  VNET_DPDK_PORT_TYPE_UNKNOWN,
} dpdk_port_type_t;

typedef struct {
  f64 deadline;
  vlib_frame_t * frame;
} dpdk_frame_t;

#define DPDK_EFD_MAX_DISCARD_RATE 10

typedef struct {
  u16 last_burst_sz;
  u16 max_burst_sz;
  u32 full_frames_cnt;
  u32 consec_full_frames_cnt;
  u32 congestion_cnt;
  u64 last_poll_time;
  u64 max_poll_delay;
  u32 discard_cnt;
  u32 total_packet_cnt;
} dpdk_efd_agent_t;

typedef struct {
  int callfd;
  int kickfd;
  int errfd;
  int enabled;
  u32 callfd_idx;
  u32 n_since_last_int;
  f64 int_deadline;
  u64 packets;
  u64 bytes;
} dpdk_vu_vring;

typedef struct {
  u32 is_up;
  u32 unix_fd;
  u32 unix_file_index;
  u32 client_fd;
  char sock_filename[256];
  int sock_errno;
  u8 sock_is_server;
  u8 active;

  u64 feature_mask;
  u32 num_vrings;
  dpdk_vu_vring vrings[VHOST_MAX_QUEUE_PAIRS * 2];
  u64 region_addr[VHOST_MEMORY_MAX_NREGIONS];
  u32 region_fd[VHOST_MEMORY_MAX_NREGIONS];
  u64 region_offset[VHOST_MEMORY_MAX_NREGIONS];
} dpdk_vu_intf_t;

typedef void (*dpdk_flowcontrol_callback_t) (vlib_main_t *vm,
                                             u32 hw_if_index,
                                             u32 n_packets);

/*
 * The header for the tx_vector in dpdk_device_t.
 * Head and tail are indexes into the tx_vector and are of type
 * u64 so they never overflow.
 */
typedef struct {
  u64 tx_head;
  u64 tx_tail;
} tx_ring_hdr_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  volatile u32 **lockp;

  /* Instance ID */
  u32 device_index;

  u32 vlib_hw_if_index;
  u32 vlib_sw_if_index;

  /* next node index if we decide to steal the rx graph arc */
  u32 per_interface_next_index;

  /* dpdk rte_mbuf rx and tx vectors, VLIB_FRAME_SIZE */
  struct rte_mbuf *** tx_vectors; /* one per worker thread */
  struct rte_mbuf *** rx_vectors;

  /* vector of traced contexts, per device */
  u32 * d_trace_buffers;

  /* per-worker destination frame queue */
  dpdk_frame_t * frames;

  /* number of sub-interfaces */
  u16 vlan_subifs;

  dpdk_device_type_t dev_type:8;
  dpdk_pmd_t pmd:8;
  i8 cpu_socket;

  u8 admin_up;
  u8 promisc;

  CLIB_CACHE_LINE_ALIGN_MARK(cacheline1);

  /* PMD related */
  u16 tx_q_used;
  u16 rx_q_used;
  u16 nb_rx_desc;
  u16 nb_tx_desc;
  u16 * cpu_socket_id_by_queue;
  struct rte_eth_conf port_conf;
  struct rte_eth_txconf tx_conf;

  /* KNI related */
  struct rte_kni *kni;
  u8 kni_port_id;

  /* vhost-user related */
  u32 vu_if_id;
  struct virtio_net  vu_vhost_dev;
  u32 vu_is_running;
  dpdk_vu_intf_t *vu_intf;

  /* af_packet */
  u8 af_packet_port_id;

  struct rte_eth_link link;
  f64 time_last_link_update;

  struct rte_eth_stats stats;
  struct rte_eth_stats last_stats;
  struct rte_eth_stats last_cleared_stats;
  struct rte_eth_xstats * xstats;
  struct rte_eth_xstats * last_cleared_xstats;
  f64 time_last_stats_update;
  dpdk_port_type_t port_type;

  dpdk_efd_agent_t efd_agent;
  u8 need_txlock; /* Used by VNET_DPDK_DEV_VHOST_USER */
} dpdk_device_t;


#define DPDK_TX_RING_SIZE (4 * 1024)

#define DPDK_STATS_POLL_INTERVAL      (10.0)
#define DPDK_MIN_STATS_POLL_INTERVAL  (0.001) /* 1msec */

#define DPDK_LINK_POLL_INTERVAL       (3.0)
#define DPDK_MIN_LINK_POLL_INTERVAL   (0.001) /* 1msec */

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

  /* total input packet counter */
  u64 aggregate_rx_packets;
} dpdk_worker_t;

typedef struct {
  u32 device;
  u16 queue_id;
} dpdk_device_and_queue_t;

/* Early-Fast-Discard (EFD) */
#define DPDK_EFD_DISABLED                       0
#define DPDK_EFD_DISCARD_ENABLED                (1 << 0)
#define DPDK_EFD_MONITOR_ENABLED                (1 << 1)
#define DPDK_EFD_DROPALL_ENABLED                (1 << 2)

#define DPDK_EFD_DEFAULT_DEVICE_QUEUE_HI_THRESH_PCT    90
#define DPDK_EFD_DEFAULT_CONSEC_FULL_FRAMES_HI_THRESH  6

typedef struct dpdk_efd_t {
  u16 enabled;
  u16 queue_hi_thresh;
  u16 consec_full_frames_hi_thresh;
  u16 pad;
} dpdk_efd_t;

#define foreach_dpdk_device_config_item \
  _ (num_rx_queues) \
  _ (num_tx_queues) \
  _ (num_rx_desc) \
  _ (num_tx_desc) \
  _ (rss_fn)

typedef struct {
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
} dpdk_device_config_t;

typedef struct {

  /* Config stuff */
  u8 ** eal_init_args;
  u8 * eal_init_args_str;
  u8 * uio_driver_name;
  u8 no_multi_seg;
  u8 enable_tcp_udp_checksum;

  /* Required config parameters */
  u8 coremask_set_manually;
  u8 nchannels_set_manually;
  u32 coremask;
  u32 nchannels;
  u32 num_mbufs;
  u8 num_kni;/* while kni_init allows u32, port_id in callback fn is only u8 */

  /*
   * format interface names ala xxxEthernet%d/%d/%d instead of
   * xxxEthernet%x/%x/%x.
   */
  u8 interface_name_format_decimal;

  /* virtio vhost-user switch */
  u8 use_virtio_vhost;

  /* vhost-user coalescence frames config */
  u32 vhost_coalesce_frames;
  f64 vhost_coalesce_time;

  /* per-device config */
  dpdk_device_config_t default_devconf;
  dpdk_device_config_t * dev_confs;
  uword * device_config_index_by_pci_addr;

} dpdk_config_main_t;

dpdk_config_main_t dpdk_config_main;

typedef struct {

  /* Devices */
  dpdk_device_t * devices;
  dpdk_device_and_queue_t ** devices_by_cpu;

  /* per-thread recycle lists */
  u32 ** recycle;

  /* buffer flags template, configurable to enable/disable tcp / udp cksum */
  u32 buffer_flags_template;

  /* flow control callback. If 0 then flow control is disabled */
  dpdk_flowcontrol_callback_t flowcontrol_callback;

  /* vlib buffer free list, must be same size as an rte_mbuf */
  u32 vlib_buffer_free_list_index;

  /* dpdk worker "threads" */
  dpdk_worker_t * workers;


  /* Ethernet input node index */
  u32 ethernet_input_node_index;

  /* pcap tracing [only works if (CLIB_DEBUG > 0)] */
  int tx_pcap_enable;
  pcap_main_t pcap_main;
  u8 * pcap_filename;
  u32 pcap_sw_if_index;
  u32 pcap_pkts_to_capture;

  /* hashes */
  uword * dpdk_device_by_kni_port_id;
  uword * vu_sw_if_index_by_listener_fd;
  uword * vu_sw_if_index_by_sock_fd;
  u32 * vu_inactive_interfaces_device_index;

  u32 next_vu_if_id;

  /* efd (early-fast-discard) settings */
  dpdk_efd_t efd;

  /*
   * flag indicating that a posted admin up/down
   * (via post_sw_interface_set_flags) is in progress
   */
  u8 admin_up_down_in_progress;

  u8 use_rss;

  /* which cpus are running dpdk-input */
  int input_cpu_first_index;
  int input_cpu_count;

  /* control interval of dpdk link state and stat polling */
  f64 link_state_poll_interval;
  f64 stat_poll_interval;

  /* Sleep for this many MS after each device poll */
  u32 poll_sleep;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  dpdk_config_main_t * conf;
} dpdk_main_t;

dpdk_main_t dpdk_main;

typedef enum {
  DPDK_RX_NEXT_IP4_INPUT,
  DPDK_RX_NEXT_IP6_INPUT,
  DPDK_RX_NEXT_MPLS_INPUT,
  DPDK_RX_NEXT_ETHERNET_INPUT,
  DPDK_RX_NEXT_DROP,
  DPDK_RX_N_NEXT,
} dpdk_rx_next_t;

typedef struct {
  u32 buffer_index;
  u16 device_index;
  u8 queue_index;
  struct rte_mbuf mb;
  /* Copy of VLIB buffer; packet data stored in pre_data. */
  vlib_buffer_t buffer;
} dpdk_tx_dma_trace_t;

typedef struct {
  u32 buffer_index;
  u16 device_index;
  u16 queue_index;
  struct rte_mbuf mb;
  vlib_buffer_t buffer; /* Copy of VLIB buffer; pkt data stored in pre_data. */
  u8 data[256];         /* First 256 data bytes, used for hexdump */
} dpdk_rx_dma_trace_t;

void vnet_buffer_needs_dpdk_mb (vlib_buffer_t * b);

void dpdk_set_next_node (dpdk_rx_next_t, char *);

clib_error_t * dpdk_set_mac_address (vnet_hw_interface_t * hi, char * address);

clib_error_t * dpdk_set_mc_filter (vnet_hw_interface_t * hi,
                                   struct ether_addr mc_addr_vec[], int naddr);

void dpdk_thread_input (dpdk_main_t * dm, dpdk_device_t * xd);

clib_error_t * dpdk_port_setup (dpdk_main_t * dm, dpdk_device_t * xd);

void dpdk_set_flowcontrol_callback (vlib_main_t *vm, 
                                    dpdk_flowcontrol_callback_t callback);

u32 dpdk_interface_tx_vector (vlib_main_t * vm, u32 dev_instance);

void set_efd_bitmap (u8 *bitmap, u32 value, u32 op);

struct rte_mbuf * dpdk_replicate_packet_mb (vlib_buffer_t * b);
struct rte_mbuf * dpdk_zerocopy_replicate_packet_mb (vlib_buffer_t * b);

#define foreach_dpdk_error						\
  _(NONE, "no error")							\
  _(RX_PACKET_ERROR, "Rx packet errors")				\
  _(RX_BAD_FCS, "Rx bad fcs")						\
  _(L4_CHECKSUM_ERROR, "Rx L4 checksum errors")				\
  _(IP_CHECKSUM_ERROR, "Rx ip checksum errors")				\
  _(RX_ALLOC_FAIL, "rx buf alloc from free list failed")		\
  _(RX_ALLOC_NO_PHYSMEM, "rx buf alloc failed no physmem")		\
  _(RX_ALLOC_DROP_PKTS, "rx packets dropped due to alloc error")        \
  _(IPV4_EFD_DROP_PKTS, "IPV4 Early Fast Discard rx drops")             \
  _(IPV6_EFD_DROP_PKTS, "IPV6 Early Fast Discard rx drops")             \
  _(MPLS_EFD_DROP_PKTS, "MPLS Early Fast Discard rx drops")             \
  _(VLAN_EFD_DROP_PKTS, "VLAN Early Fast Discard rx drops")

typedef enum {
#define _(f,s) DPDK_ERROR_##f,
  foreach_dpdk_error
#undef _
  DPDK_N_ERROR,
} dpdk_error_t;

/*
 * Increment EFD drop counter
 */
static_always_inline
void increment_efd_drop_counter (vlib_main_t * vm, u32 counter_index, u32 count)
{
   vlib_node_t *my_n;

   my_n = vlib_get_node (vm, dpdk_input_node.index);
   vm->error_main.counters[my_n->error_heap_index+counter_index] += count;
}

int dpdk_set_stat_poll_interval (f64 interval);
int dpdk_set_link_state_poll_interval (f64 interval);
void dpdk_update_link_state (dpdk_device_t * xd, f64 now);
void dpdk_device_lock_init(dpdk_device_t * xd);
void dpdk_device_lock_free(dpdk_device_t * xd);
void dpdk_efd_update_counters(dpdk_device_t *xd, u32 n_buffers, u16 enabled);
u32 is_efd_discardable(vlib_thread_main_t *tm,
                       vlib_buffer_t * b0,
                       struct rte_mbuf *mb);

/* dpdk vhost-user interrupt management */
u8 dpdk_vhost_user_want_interrupt (dpdk_device_t *xd, int idx);
void dpdk_vhost_user_send_interrupt (vlib_main_t * vm, dpdk_device_t * xd,
                                    int idx);


static inline u64 vnet_get_aggregate_rx_packets (void)
{
    dpdk_main_t * dm = &dpdk_main;
    u64 sum = 0;
    dpdk_worker_t * dw;

    vec_foreach(dw, dm->workers)
        sum += dw->aggregate_rx_packets;

    return sum;
}

void dpdk_rx_trace (dpdk_main_t * dm,
                    vlib_node_runtime_t * node,
                    dpdk_device_t * xd,
                    u16 queue_id,
                    u32 * buffers,
                    uword n_buffers);

#define EFD_OPERATION_LESS_THAN          0
#define EFD_OPERATION_GREATER_OR_EQUAL   1

void efd_config(u32 enabled,
                u32 ip_prec,  u32 ip_op,
                u32 mpls_exp, u32 mpls_op,
                u32 vlan_cos, u32 vlan_op);

void post_sw_interface_set_flags (vlib_main_t *vm, u32 sw_if_index, u32 flags);

typedef struct vhost_user_memory vhost_user_memory_t;

void dpdk_vhost_user_process_init (void **ctx);
void dpdk_vhost_user_process_cleanup (void *ctx);
uword dpdk_vhost_user_process_if (vlib_main_t *vm, dpdk_device_t *xd, void *ctx);

// vhost-user calls
int dpdk_vhost_user_create_if (vnet_main_t * vnm, vlib_main_t * vm,
                              const char * sock_filename,
                              u8 is_server,
                              u32 * sw_if_index,
                              u64 feature_mask,
                              u8 renumber, u32 custom_dev_instance,
                              u8 *hwaddr);
int dpdk_vhost_user_modify_if (vnet_main_t * vnm, vlib_main_t * vm,
                              const char * sock_filename,
                              u8 is_server,
                              u32 sw_if_index,
                              u64 feature_mask,
                              u8 renumber, u32 custom_dev_instance);
int dpdk_vhost_user_delete_if (vnet_main_t * vnm, vlib_main_t * vm,
                              u32 sw_if_index);
int dpdk_vhost_user_dump_ifs (vnet_main_t * vnm, vlib_main_t * vm,
                             vhost_user_intf_details_t **out_vuids);

u32 dpdk_get_admin_up_down_in_progress (void);

u32 dpdk_num_mbufs (void);

dpdk_pmd_t dpdk_get_pmd_type (vnet_hw_interface_t *hi);

i8 dpdk_get_cpu_socket (vnet_hw_interface_t *hi);

void * dpdk_input_multiarch_select();
void * dpdk_input_rss_multiarch_select();
void * dpdk_input_efd_multiarch_select();

clib_error_t*
dpdk_get_hw_interface_stats (u32 hw_if_index, struct rte_eth_stats* dest);

format_function_t format_dpdk_device_name;
format_function_t format_dpdk_device;
format_function_t format_dpdk_tx_dma_trace;
format_function_t format_dpdk_rx_dma_trace;
format_function_t format_dpdk_rte_mbuf;
format_function_t format_dpdk_rx_rte_mbuf;
unformat_function_t unformat_socket_mem;
clib_error_t * unformat_rss_fn(unformat_input_t * input, uword * rss_fn);


static inline void
dpdk_pmd_constructor_init()
{
  /* Add references to DPDK Driver Constructor functions to get the dynamic
   * loader to pull in the driver library & run the constructors.
   */
#define _(d)                                            \
  do {                                                  \
    void devinitfn_ ##d(void);                          \
    __attribute__((unused)) void (* volatile pf)(void); \
    pf = devinitfn_ ##d;                                \
  } while(0);

#ifdef RTE_LIBRTE_EM_PMD
  _(em_pmd_drv)
#endif

#ifdef RTE_LIBRTE_IGB_PMD
  _(pmd_igb_drv)
#endif

#ifdef RTE_LIBRTE_IXGBE_PMD
  _(rte_ixgbe_driver)
#endif

#ifdef RTE_LIBRTE_I40E_PMD
  _(rte_i40e_driver)
  _(rte_i40evf_driver)
#endif

#ifdef RTE_LIBRTE_FM10K_PMD
  _(rte_fm10k_driver)
#endif

#ifdef RTE_LIBRTE_VIRTIO_PMD
  _(rte_virtio_driver)
#endif

#ifdef RTE_LIBRTE_VMXNET3_PMD
  _(rte_vmxnet3_driver)
#endif

#ifdef RTE_LIBRTE_VICE_PMD
  _(rte_vice_driver)
#endif

#ifdef RTE_LIBRTE_ENIC_PMD
  _(rte_enic_driver)
#endif

#ifdef RTE_LIBRTE_PMD_AF_PACKET
  _(pmd_af_packet_drv)
#endif

#ifdef RTE_LIBRTE_CXGBE_PMD
  _(rte_cxgbe_driver)
#endif

#ifdef RTE_LIBRTE_PMD_BOND
  _(bond_drv)
#endif

#ifdef RTE_LIBRTE_DPAA2_PMD
  _(pmd_dpaa2_drv)
#endif

#undef _

/*
 * At the moment, the ThunderX NIC driver doesn't have
 * an entry point named "devinitfn_rte_xxx_driver"
 */
#define _(d)                                          \
  do {                                                  \
    void d(void);			                      \
    __attribute__((unused)) void (* volatile pf)(void); \
    pf = d;		                              \
  } while(0);

#ifdef RTE_LIBRTE_THUNDERVNIC_PMD
  _(rte_nicvf_pmd_init)
#endif
#undef _

}

uword
admin_up_down_process (vlib_main_t * vm,
                       vlib_node_runtime_t * rt,
                       vlib_frame_t * f);

#endif /* __included_dpdk_h__ */
