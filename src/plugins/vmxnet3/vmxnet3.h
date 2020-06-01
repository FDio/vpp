/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __included_vmnet_vmnet_h__
#define __included_vmnet_vmnet_h__

#define foreach_vmxnet3_tx_func_error	       \
  _(ERROR_PACKETS, "error packets") \
  _(LINK_DOWN, "link down") \
  _(NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f,s) VMXNET3_TX_ERROR_##f,
  foreach_vmxnet3_tx_func_error
#undef _
    VMXNET3_TX_N_ERROR,
} vmxnet3_tx_func_error_t;

#define foreach_vmxnet3_rxmode_flags \
  _(0, UCAST, "unicast") \
  _(1, MCAST, "multicast")		   \
  _(2, BCAST, "broadcast") \
  _(3, ALL_MULTI, "all multicast") \
  _(4, PROMISC, "promiscuous")

enum
{
#define _(a, b, c) VMXNET3_RXMODE_##b = (1 << a),
  foreach_vmxnet3_rxmode_flags
#undef _
};

#define foreach_vmxnet3_show_entry \
  _(RX_COMP, "rx comp") \
  _(RX_DESC0, "rx desc 0") \
  _(RX_DESC1, "rx desc 1") \
  _(TX_COMP, "tx comp") \
  _(TX_DESC, "tx desc")

enum
{
#define _(a, b) VMXNET3_SHOW_##a,
  foreach_vmxnet3_show_entry
#undef _
};

#define foreach_vmxnet3_feature_flags \
  _(0, RXCSUM, "rx checksum") \
  _(1, RSS, "RSS")	   \
  _(2, RXVLAN, "rx VLAN") \
  _(3, LRO, "LRO")

enum
{
#define _(a, b, c) VMXNET3_F_##b = (1 << a),
  foreach_vmxnet3_feature_flags
#undef _
};

#define foreach_vmxnet3_rss_hash_type \
  _(0, IPV4, "ipv4")	   \
  _(1, TCP_IPV4, "tcp ipv4") \
  _(2, IPV6, "ipv6") \
  _(3, TCP_IPV6, "tcp ipv6")

enum
{
#define _(a, b, c) VMXNET3_RSS_HASH_TYPE_##b = (1 << a),
  foreach_vmxnet3_rss_hash_type
#undef _
};

#define VMXNET3_RSS_HASH_FUNC_TOEPLITZ	1
#define VMXNET3_RSS_MAX_KEY_SZ		40
#define VMXNET3_RSS_MAX_IND_TABLE_SZ	128

#define VMXNET3_TXQ_MAX 8
#define VMXNET3_RXQ_MAX 16
#define VMXNET3_TX_START(vd) ((vd)->queues)
#define VMXNET3_RX_START(vd) \
  ((vd)->queues + (vd)->num_tx_queues * sizeof (vmxnet3_tx_queue))

/* BAR 0 */
#define VMXNET3_REG_IMR     0x0000	/* Interrupt Mask Register */
#define VMXNET3_REG_TXPROD  0x0600	/* Tx Producer Index */
#define VMXNET3_REG_RXPROD  0x0800	/* Rx Producer Index for ring 1 */
#define VMXNET3_REG_RXPROD2 0x0A00	/* Rx Producer Index for ring 2 */


/* BAR 1 */
#define VMXNET3_REG_VRRS 0x0000	/* VMXNET3 Revision Report Selection */
#define VMXNET3_REG_UVRS 0x0008	/* UPT Version Report Selection */
#define VMXNET3_REG_DSAL 0x0010	/* Driver Shared Address Low */
#define VMXNET3_REG_DSAH 0x0018	/* Driver Shared Address High */
#define VMXNET3_REG_CMD  0x0020	/* Command */
#define VMXNET3_REG_MACL 0x0028	/* MAC Address Low */
#define VMXNET3_REG_MACH 0x0030	/* MAC Address High */
#define VMXNET3_REG_ICR  0x0038	/* Interrupt Cause Register */
#define VMXNET3_REG_ECR  0x0040	/* Event Cause Register */

#define VMXNET3_VLAN_LEN 4
#define VMXNET3_FCS_LEN  4
#define VMXNET3_MTU (1514 + VMXNET3_VLAN_LEN + VMXNET3_FCS_LEN)

#define VMXNET3_RXF_BTYPE (1 << 14)	/* rx body buffer type */
#define VMXNET3_RXF_GEN   (1 << 31)	/* rx generation */

#define VMXNET3_RXCF_CKSUM_MASK (0xFFFF)	/* rx checksum mask */
#define VMXNET3_RXCF_TUC  (1 << 16)	/* rx udp/tcp checksum correct */
#define VMXNET3_RXCF_UDP  (1 << 17)	/* rx udp packet */
#define VMXNET3_RXCF_TCP  (1 << 18)	/* rx tcp packet */
#define VMXNET3_RXCF_IPC  (1 << 19)	/* rx ip checksum correct */
#define VMXNET3_RXCF_IP6  (1 << 20)	/* rx ip6 packet */
#define VMXNET3_RXCF_IP4  (1 << 21)	/* rx ip4 packet */
#define VMXNET3_RXCF_CT   (0x7F << 24)	/* rx completion type 24-30, 7 bits */
#define VMXNET3_RXCF_GEN  (1 << 31)	/* rx completion generation */

#define VMXNET3_RXC_INDEX (0xFFF)	/* rx completion index mask */

#define foreach_vmxnet3_offload \
  _(0, NONE, "none") \
  _(2, CSUM, "checksum") \
  _(3, TSO, "tso")

enum
{
#define _(a, b, c) VMXNET3_OM_##b = (a),
  foreach_vmxnet3_offload
#undef _
};

/* tx desc flag 0 */
#define VMXNET3_TXF_GEN  (1 << 14)	/* tx generation */

/* tx desc flag 1 */
#define VMXNET3_TXF_OM(x) ((x) << 10)	/* tx offload mode */
#define VMXNET3_TXF_MSSCOF(x) ((x) << 18)	/* tx MSS checksum offset, flags */
#define VMXNET3_TXF_EOP  (1 << 12)	/* tx end of packet */
#define VMXNET3_TXF_CQ   (1 << 13)	/* tx completion request */

/* tx completion flag */
#define VMXNET3_TXCF_GEN (1 << 31)	/* tx completion generation */
#define VMXNET3_TXC_INDEX (0xFFF)	/* tx completion index mask */

#define VMXNET3_RX_RING_SIZE 2
#define VMXNET3_INPUT_REFILL_THRESHOLD 32
#define VMXNET3_NUM_TX_DESC 1024
#define VMXNET3_NUM_TX_COMP VMXNET3_NUM_TX_DESC
#define VMXNET3_NUM_RX_DESC 1024
#define VMXNET3_NUM_RX_COMP VMXNET3_NUM_RX_DESC

#define VMXNET3_VERSION_MAGIC 0x69505845
#define VMXNET3_SHARED_MAGIC  0xbabefee1
#define VMXNET3_VERSION_SELECT     1
#define VMXNET3_UPT_VERSION_SELECT 1
#define VMXNET3_MAX_INTRS          25
#define VMXNET3_IC_DISABLE_ALL     0x1

#define VMXNET3_GOS_BITS_32     (1 << 0)
#define VMXNET3_GOS_BITS_64     (2 << 0)
#define VMXNET3_GOS_TYPE_LINUX  (1 << 2)
#define VMXNET3_RXCL_LEN_MASK   (0x3FFF)	// 14 bits
#define VMXNET3_RXCL_ERROR      (1 << 14)

#define VMXNET3_RXCI_EOP        (1 << 14)	/* end of packet */
#define VMXNET3_RXCI_SOP        (1 << 15)	/* start of packet */
#define VMXNET3_RXCI_CNC        (1 << 30)	/* Checksum not calculated */

#define VMXNET3_RXCOMP_TYPE     (3 << 24)	/* RX completion descriptor */
#define VMXNET3_RXCOMP_TYPE_LRO (4 << 24)	/* RX completion descriptor for LRO */

#define VMXNET3_RXECF_MSS_MASK  (0xFFFF)	// 16 bits

#define foreach_vmxnet3_device_flags		\
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error")		   \
  _(2, ADMIN_UP, "admin-up") \
  _(3, IOVA, "iova") \
  _(4, LINK_UP, "link-up") \
  _(5, SHARED_TXQ_LOCK, "shared-txq-lock") \
  _(6, ELOG, "elog")

enum
{
#define _(a, b, c) VMXNET3_DEVICE_F_##b = (1 << a),
  foreach_vmxnet3_device_flags
#undef _
};

#define foreach_vmxnet3_set_cmds \
  _(0, ACTIVATE_DEV, "activate device") \
  _(1, QUIESCE_DEV, "quiesce device") \
  _(2, RESET_DEV, "reset device") \
  _(3, UPDATE_RX_MODE, "update rx mode") \
  _(4, UPDATE_MAC_FILTERS, "update mac filters") \
  _(5, UPDATE_VLAN_FILTERS, "update vlan filters") \
  _(6, UPDATE_RSSIDT, "update rss idt") \
  _(7, UPDATE_IML, "update iml") \
  _(8, UPDATE_PMCFG, "update pm cfg") \
  _(9, UPDATE_FEATURE, "update feature") \
  _(10, STOP_EMULATION, "stop emulation") \
  _(11, LOAD_PLUGIN, "load plugin") \
  _(12, ACTIVATE_VF, "activate vf") \
  _(13, RESERVED3, "reserved 3") \
  _(14, RESERVED4, "reservced 4") \
  _(15, REGISTER_MEMREGS, "register mem regs")

enum
{
#define _(a, b, c) VMXNET3_CMD_##b = (a + 0xCAFE0000),
  foreach_vmxnet3_set_cmds
#undef _
};

#define foreach_vmxnet3_get_cmds \
  _(0, GET_QUEUE_STATUS, "get queue status") \
  _(1, GET_STATS, "get stats") \
  _(2, GET_LINK, "get link") \
  _(3, GET_PERM_MAC_LO, "get perm mac lo") \
  _(4, GET_PERM_MAC_HI, "get perm mac hi") \
  _(5, GET_DID_LO, "get did lo") \
  _(6, GET_DID_HI, "get did hi") \
  _(7, GET_DEV_EXTRA_INFO, "get dev extra info") \
  _(8, GET_CONF_INTR, "get conf intr") \
  _(9, GET_ADAPTIVE_RING_INFO, "get adaptive ring info") \
  _(10, GET_TXDATA_DESC_SIZE, "get txdata desc size") \
  _(11, RESERVED5, "reserved5")

enum
{
#define _(a, b, c) VMXNET3_CMD_##b = (a + 0xF00D0000),
  foreach_vmxnet3_get_cmds
#undef _
};

typedef CLIB_PACKED (struct
		     {
		     u32 version; u32 guest_info; u32 version_support;
		     u32 upt_version_support; u64 upt_features;
		     u64 driver_data_address; u64 queue_desc_address;
		     u32 driver_data_len; u32 queue_desc_len;
		     u32 mtu;
		     u16 max_num_rx_sg; u8 num_tx_queues; u8 num_rx_queues;
		     u32 pad[4];
		     }) vmxnet3_misc_config;

typedef CLIB_PACKED (struct
		     {
		     u8 mask_mode;
		     u8 num_intrs;
		     u8 event_intr_index;
		     u8 moderation_level[VMXNET3_MAX_INTRS]; u32 control;
		     u32 pad[2];
		     }) vmxnet3_interrupt_config;

typedef CLIB_PACKED (struct
		     {
		     u32 mode; u16 multicast_len; u16 pad;
		     u64 multicast_address; u8 vlan_filter[512];
		     }) vmxnet3_rx_filter_config;

typedef CLIB_PACKED (struct
		     {
		     u32 version; u32 length;
		     u64 address;
		     }) vmxnet3_variable_config;

typedef CLIB_PACKED (struct
		     {
		     u32 magic;
		     u32 pad;
		     vmxnet3_misc_config misc;
		     vmxnet3_interrupt_config interrupt;
		     vmxnet3_rx_filter_config rx_filter;
		     vmxnet3_variable_config rss;
		     vmxnet3_variable_config pattern;
		     vmxnet3_variable_config plugin; u32 ecr;
		     u32 pad1[5];
		     }) vmxnet3_shared;

typedef CLIB_PACKED (struct
		     {
		     u8 stopped;
		     u8 pad[3];
		     u32 error;
		     }) vmxnet3_queue_status;

typedef CLIB_PACKED (struct
		     {
		     u32 num_deferred; u32 threshold;
		     u64 pad;
		     }) vmxnet3_tx_queue_control;

typedef CLIB_PACKED (struct
		     {
		     u64 desc_address;
		     u64 data_address;
		     u64 comp_address; u64 driver_data_address; u64 pad;
		     u32 num_desc;
		     u32 num_data; u32 num_comp; u32 driver_data_len;
		     u8 intr_index;
		     u8 pad1; u16 data_address_size; u8 pad2[4];
		     }) vmxnet3_tx_queue_config;

typedef CLIB_PACKED (struct
		     {
		     u64 tso_pkts;
		     u64 tso_bytes;
		     u64 ucast_pkts; u64 ucast_bytes; u64 mcast_pkts;
		     u64 mcast_bytes;
		     u64 bcast_pkts; u64 bcast_bytes; u64 error_pkts;
		     u64 discard_pkts;
		     }) vmxnet3_tx_stats;

typedef CLIB_PACKED (struct
		     {
		     vmxnet3_tx_queue_control ctrl;
		     vmxnet3_tx_queue_config cfg;
		     vmxnet3_queue_status status; vmxnet3_tx_stats stats;
		     u8 pad[88];
		     }) vmxnet3_tx_queue;

typedef CLIB_PACKED (struct
		     {
		     u8 update_prod; u8 pad[7];
		     u64 pad1;
		     }) vmxnet3_rx_queue_control;

typedef CLIB_PACKED (struct
		     {
		     u64 desc_address[2];
		     u64 comp_address; u64 driver_data_address;
		     u64 data_address; u32 num_desc[2];
		     u32 num_comp;
		     u32 driver_data_len; u8 intr_index; u8 pad1;
		     u16 data_address_size; u8 pad2[4];
		     }) vmxnet3_rx_queue_config;

typedef CLIB_PACKED (struct
		     {
		     u64 lro_pkts;
		     u64 lro_bytes;
		     u64 ucast_pkts; u64 ucast_bytes; u64 mcast_pkts;
		     u64 mcast_bytes;
		     u64 bcast_pkts; u64 bcast_bytes; u64 nobuf_pkts;
		     u64 error_pkts;
		     }) vmxnet3_rx_stats;

typedef CLIB_PACKED (struct
		     {
		     vmxnet3_rx_queue_control ctrl;
		     vmxnet3_rx_queue_config cfg;
		     vmxnet3_queue_status status; vmxnet3_rx_stats stats;
		     u8 pad[88];
		     }) vmxnet3_rx_queue;

/*
 * flags:
 *   buffer length   -- bits 0-13
 *   buffer type     -- bit  14
 *   descriptor type -- bit  15
 *   reserved        -- bits 16-30
 *   generation      -- bit  31
 */
typedef CLIB_PACKED (struct
		     {
		     u64 address;
		     u32 flags;
		     u32 pad;
		     }) vmxnet3_rx_desc;

/*
 * index:
 *   RX desc index           -- bits 0-11
 *   ext1                    -- bits 12-13
 *   end of packet           -- bit  14
 *   start of packet         -- bit  15
 *   ring ID                 -- bits 16-25
 *   RSS hash type           -- bits 26-29
 *   checksum not calculated -- bit  30
 *   ext2                    -- bit  31
 *
 * rss: RSS hash value
 *
 * len:
 *   data length             -- bits 0-13
 *   error                   -- bit  14
 *   tag is stripped         -- bit  15
 *   tag stripped            -- bits 16-31
 *
 * flags:
 *   checksum                -- bits 0 - 15
 *   tcp/udp checksum correct-- bit  16
 *   udp packet              -- bit  17
 *   tcp packet              -- bit  18
 *   ip checksum correct     -- bit  19
 *   ipv6                    -- bit  20
 *   ipv4                    -- bit  21
 *   ip fragment             -- bit  22
 *   frame crc correct       -- bit  23
 *   completion type         -- bits 24-30
 *   generation              -- bit  31
 */
typedef CLIB_PACKED (struct
		     {
		     u32 index; u32 rss;
		     u32 len;
		     u32 flags;
		     }) vmxnet3_rx_comp;

/*
 * flags:
 *   mss                     -- bits 0 - 15
 *   tcp/udp checksum correct-- bit  16
 *   udp packet              -- bit  17
 *   tcp packet              -- bit  18
 *   ip checksum correct     -- bit  19
 *   ipv6                    -- bit  20
 *   ipv4                    -- bit  21
 *   ip fragment             -- bit  22
 *   frame crc correct       -- bit  23
 *   completion type         -- bits 24-30
 *   generation              -- bit  31
 */
typedef CLIB_PACKED (struct
		     {
		     u32 dword1;
		     u8 seg_cnt; u8 dup_ack_cnt; u16 ts_delta; u32 dword2;
		     u32 flags;
		     }) vmxnet3_rx_comp_ext;

/*
 * index:
 *   TX desc index           -- bits 0-11
 *   ext1                    -- bits 12-31
 *
 * flags:
 *   reserved                -- bits 0-23
 *   completion type         -- bits 24-30
 *   generation              -- bit  31
 */
typedef CLIB_PACKED (struct
		     {
		     u32 index;
		     u32 pad[2];
		     u32 flags;
		     }) vmxnet3_tx_comp;

/*
 * flags[0]:
 *   length                  -- bits 0-13
 *   generation              -- bit  14
 *   reserved                -- bit  15
 *   descriptor type         -- bit  16
 *   ext1                    -- bit  17
 *   MSS, checksum offset    -- bits 18-31
 * flags[1]:
 *   header length           -- bits 0-9
 *   offload mode            -- bits 10-11
 *   end of packet           -- bit  12
 *   completion request      -- bit  13
 *   ext2                    -- bit  14
 *   vlan tag insertion      -- bit  15
 *   tag to insert           -- bits 16-31
 */
typedef CLIB_PACKED (struct
		     {
		     u64 address;
		     u32 flags[2];
		     }) vmxnet3_tx_desc;

typedef CLIB_PACKED (struct
		     {
		     u16 hash_type;
		     u16 hash_func;
		     u16 hash_key_sz;
		     u16 ind_table_sz;
		     u8 hash_key[VMXNET3_RSS_MAX_KEY_SZ];
		     u8 ind_table[VMXNET3_RSS_MAX_IND_TABLE_SZ];
		     }) vmxnet3_rss_shared;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *bufs;
  u32 gen;
  u16 fill;
  u16 rid;
  u16 produce;
  u16 consume;
} vmxnet3_rx_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 gen;
  u16 next;
} vmxnet3_rx_comp_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 size;
  u8 int_mode;
  u8 buffer_pool_index;
  u32 queue_index;
  vmxnet3_rx_ring rx_ring[VMXNET3_RX_RING_SIZE];
  vmxnet3_rx_desc *rx_desc[VMXNET3_RX_RING_SIZE];
  vmxnet3_rx_comp *rx_comp;
  vmxnet3_rx_comp_ring rx_comp_ring;
} vmxnet3_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *bufs;
  u32 gen;
  u16 produce;
  u16 consume;
} vmxnet3_tx_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 gen;
  u16 next;
} vmxnet3_tx_comp_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 size;
  u32 reg_txprod;
  clib_spinlock_t lock;

  vmxnet3_tx_desc *tx_desc;
  vmxnet3_tx_comp *tx_comp;
  vmxnet3_tx_ring tx_ring;
  vmxnet3_tx_comp_ring tx_comp_ring;
} vmxnet3_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  u32 numa_node;
  vlib_pci_dev_handle_t pci_dev_handle;
  vlib_pci_addr_t pci_addr;
  void *bar[2];

  /* queues */
  vmxnet3_rxq_t *rxqs;
  vmxnet3_txq_t *txqs;

  u16 num_tx_queues;
  u16 num_rx_queues;
  u16 num_intrs;

  u8 version;
  u8 mac_addr[6];

  clib_error_t *error;

  vmxnet3_shared *driver_shared;
  void *queues;
  vmxnet3_rss_shared *rss;
  u32 link_speed;
  u8 gso_enable;
  vmxnet3_tx_stats *tx_stats;
  vmxnet3_rx_stats *rx_stats;
} vmxnet3_device_t;

typedef struct
{
  vmxnet3_device_t *devices;
  u16 msg_id_base;
  vlib_log_class_t log_default;
} vmxnet3_main_t;

extern vmxnet3_main_t vmxnet3_main;

typedef struct
{
  vlib_pci_addr_t addr;
  u32 enable_elog;
  u16 rxq_size;
  u16 rxq_num;
  u16 txq_size;
  u16 txq_num;
  u8 bind;
  u8 enable_gso;
  /* return */
  i32 rv;
  u32 sw_if_index;
  clib_error_t *error;
} vmxnet3_create_if_args_t;

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  vlib_buffer_t buffer;
} vmxnet3_input_trace_t;

void vmxnet3_create_if (vlib_main_t * vm, vmxnet3_create_if_args_t * args);
void vmxnet3_delete_if (vlib_main_t * vm, vmxnet3_device_t * ad);

extern clib_error_t *vmxnet3_plugin_api_hookup (vlib_main_t * vm);
extern vlib_node_registration_t vmxnet3_input_node;
extern vnet_device_class_t vmxnet3_device_class;

/* format.c */
format_function_t format_vmxnet3_device;
format_function_t format_vmxnet3_device_name;
format_function_t format_vmxnet3_input_trace;

#define vmxnet3_log_debug(dev, f, ...)			      \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, vmxnet3_main.log_default, "%U: " f, \
	    format_vlib_pci_addr, &dev->pci_addr, \
	    ## __VA_ARGS__)

#define vmxnet3_log_error(dev, f, ...)			    \
  vlib_log (VLIB_LOG_LEVEL_ERR, vmxnet3_main.log_default, "%U: " f, \
	    format_vlib_pci_addr, &dev->pci_addr, \
	    ## __VA_ARGS__)

/* no log version, called by data plane */
static_always_inline void
vmxnet3_reg_write_inline (vmxnet3_device_t * vd, u8 bar, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) vd->bar[bar] + addr) = val;
}

static_always_inline void
vmxnet3_reg_write (vmxnet3_device_t * vd, u8 bar, u32 addr, u32 val)
{
  vmxnet3_log_debug (vd, "reg wr bar %u addr 0x%x val 0x%x", bar, addr, val);
  vmxnet3_reg_write_inline (vd, bar, addr, val);
}

static_always_inline u32
vmxnet3_reg_read (vmxnet3_device_t * vd, u8 bar, u32 addr)
{
  u32 val;

  val = *(volatile u32 *) (vd->bar[bar] + addr);
  vmxnet3_log_debug (vd, "reg rd bar %u addr 0x%x val 0x%x", bar, addr, val);

  return val;
}

static_always_inline uword
vmxnet3_dma_addr (vlib_main_t * vm, vmxnet3_device_t * vd, void *p)
{
  return (vd->flags & VMXNET3_DEVICE_F_IOVA) ? pointer_to_uword (p) :
    vlib_physmem_get_pa (vm, p);
}

static_always_inline void
vmxnet3_rx_ring_advance_produce (vmxnet3_rxq_t * rxq, vmxnet3_rx_ring * ring)
{
  ring->produce++;
  if (PREDICT_FALSE (ring->produce == rxq->size))
    {
      ring->produce = 0;
      ring->gen ^= VMXNET3_RXF_GEN;
    }
}

static_always_inline clib_error_t *
vmxnet3_rxq_refill_ring0 (vlib_main_t * vm, vmxnet3_device_t * vd,
			  vmxnet3_rxq_t * rxq)
{
  vmxnet3_rx_desc *rxd;
  u16 n_refill, n_alloc;
  vmxnet3_rx_ring *ring;
  vmxnet3_rx_queue *rx;

  ring = &rxq->rx_ring[0];
  n_refill = rxq->size - ring->fill;

  if (PREDICT_TRUE (n_refill <= VMXNET3_INPUT_REFILL_THRESHOLD))
    return 0;

  n_alloc =
    vlib_buffer_alloc_to_ring_from_pool (vm, ring->bufs, ring->produce,
					 rxq->size, n_refill,
					 rxq->buffer_pool_index);
  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, ring->bufs, ring->produce, rxq->size,
				    n_alloc);
      return clib_error_return (0, "buffer alloc failed");
    }

  while (n_alloc)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, ring->bufs[ring->produce]);
      rxd = &rxq->rx_desc[0][ring->produce];
      rxd->address = vlib_buffer_get_pa (vm, b);
      rxd->flags = ring->gen | vlib_buffer_get_default_data_size (vm);

      vmxnet3_rx_ring_advance_produce (rxq, ring);
      ring->fill++;
      n_alloc--;
    }

  rx = VMXNET3_RX_START (vd);
  if (PREDICT_FALSE (rx->ctrl.update_prod))
    vmxnet3_reg_write_inline (vd, 0, VMXNET3_REG_RXPROD, ring->produce);

  return 0;
}

static_always_inline clib_error_t *
vmxnet3_rxq_refill_ring1 (vlib_main_t * vm, vmxnet3_device_t * vd,
			  vmxnet3_rxq_t * rxq)
{
  vmxnet3_rx_desc *rxd;
  u16 n_refill, n_alloc;
  vmxnet3_rx_ring *ring;
  vmxnet3_rx_queue *rx;

  ring = &rxq->rx_ring[1];
  n_refill = rxq->size - ring->fill;

  if (PREDICT_TRUE (n_refill <= VMXNET3_INPUT_REFILL_THRESHOLD))
    return 0;

  n_alloc =
    vlib_buffer_alloc_to_ring_from_pool (vm, ring->bufs, ring->produce,
					 rxq->size, n_refill,
					 rxq->buffer_pool_index);
  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, ring->bufs, ring->produce, rxq->size,
				    n_alloc);
      return clib_error_return (0, "buffer alloc failed");
    }

  while (n_alloc)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, ring->bufs[ring->produce]);
      rxd = &rxq->rx_desc[1][ring->produce];
      rxd->address = vlib_buffer_get_pa (vm, b);
      rxd->flags = ring->gen | vlib_buffer_get_default_data_size (vm) |
	VMXNET3_RXF_BTYPE;

      vmxnet3_rx_ring_advance_produce (rxq, ring);
      ring->fill++;
      n_alloc--;
    }

  rx = VMXNET3_RX_START (vd);
  if (PREDICT_FALSE (rx->ctrl.update_prod))
    vmxnet3_reg_write_inline (vd, 0, VMXNET3_REG_RXPROD2, ring->produce);

  return 0;
}

#endif /* __included_vmnet_vmnet_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
