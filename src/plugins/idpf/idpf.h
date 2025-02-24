/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _IDPF_H_
#define _IDPF_H_

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <vppinfra/types.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/lock.h>

#include <vlib/log.h>
#include <vlib/pci/pci.h>

#include <vnet/interface.h>

#include <vnet/devices/devices.h>
#include <vnet/flow/flow.h>

#include <idpf/virtchnl2.h>
#include <sys/queue.h>

#define BIT(a) (1UL << (a))

/*
 * LAN PF register
 */
#define MAKEMASK(m, s) ((m) << (s))

/* Receive queues */
#define PF_QRX_BASE		0x00000000
#define PF_QRX_TAIL(_QRX)	(PF_QRX_BASE + (((_QRX) *0x1000)))
#define PF_QRX_BUFFQ_BASE	0x03000000
#define PF_QRX_BUFFQ_TAIL(_QRX) (PF_QRX_BUFFQ_BASE + (((_QRX) *0x1000)))

/* Transmit queues */
#define PF_QTX_BASE		 0x05000000
#define PF_QTX_COMM_DBELL(_DBQM) (PF_QTX_BASE + ((_DBQM) *0x1000))

/* Control(PF Mailbox) Queue */
#define PF_FW_BASE 0x08400000

#define PF_FW_ARQBAL		 (PF_FW_BASE)
#define PF_FW_ARQBAH		 (PF_FW_BASE + 0x4)
#define PF_FW_ARQLEN		 (PF_FW_BASE + 0x8)
#define PF_FW_ARQLEN_ARQLEN_S	 0
#define PF_FW_ARQLEN_ARQLEN_M	 MAKEMASK (0x1FFF, PF_FW_ARQLEN_ARQLEN_S)
#define PF_FW_ARQLEN_ARQVFE_S	 28
#define PF_FW_ARQLEN_ARQVFE_M	 BIT (PF_FW_ARQLEN_ARQVFE_S)
#define PF_FW_ARQLEN_ARQOVFL_S	 29
#define PF_FW_ARQLEN_ARQOVFL_M	 BIT (PF_FW_ARQLEN_ARQOVFL_S)
#define PF_FW_ARQLEN_ARQCRIT_S	 30
#define PF_FW_ARQLEN_ARQCRIT_M	 BIT (PF_FW_ARQLEN_ARQCRIT_S)
#define PF_FW_ARQLEN_ARQENABLE_S 31
#define PF_FW_ARQLEN_ARQENABLE_M BIT (PF_FW_ARQLEN_ARQENABLE_S)
#define PF_FW_ARQH		 (PF_FW_BASE + 0xC)
#define PF_FW_ARQH_ARQH_S	 0
#define PF_FW_ARQH_ARQH_M	 MAKEMASK (0x1FFF, PF_FW_ARQH_ARQH_S)
#define PF_FW_ARQT		 (PF_FW_BASE + 0x10)

#define PF_FW_ATQBAL		 (PF_FW_BASE + 0x14)
#define PF_FW_ATQBAH		 (PF_FW_BASE + 0x18)
#define PF_FW_ATQLEN		 (PF_FW_BASE + 0x1C)
#define PF_FW_ATQLEN_ATQLEN_S	 0
#define PF_FW_ATQLEN_ATQLEN_M	 MAKEMASK (0x3FF, PF_FW_ATQLEN_ATQLEN_S)
#define PF_FW_ATQLEN_ATQVFE_S	 28
#define PF_FW_ATQLEN_ATQVFE_M	 BIT (PF_FW_ATQLEN_ATQVFE_S)
#define PF_FW_ATQLEN_ATQOVFL_S	 29
#define PF_FW_ATQLEN_ATQOVFL_M	 BIT (PF_FW_ATQLEN_ATQOVFL_S)
#define PF_FW_ATQLEN_ATQCRIT_S	 30
#define PF_FW_ATQLEN_ATQCRIT_M	 BIT (PF_FW_ATQLEN_ATQCRIT_S)
#define PF_FW_ATQLEN_ATQENABLE_S 31
#define PF_FW_ATQLEN_ATQENABLE_M BIT (PF_FW_ATQLEN_ATQENABLE_S)
#define PF_FW_ATQH		 (PF_FW_BASE + 0x20)
#define PF_FW_ATQH_ATQH_S	 0
#define PF_FW_ATQH_ATQH_M	 MAKEMASK (0x3FF, PF_FW_ATQH_ATQH_S)
#define PF_FW_ATQT		 (PF_FW_BASE + 0x24)

/* Interrupts */
#define PF_GLINT_BASE		     0x08900000
#define PF_GLINT_DYN_CTL_ITR_INDX_S  3
#define PF_GLINT_DYN_CTL_ITR_INDX_M  MAKEMASK (0x3, PF_GLINT_DYN_CTL_ITR_INDX_S)
#define PF_GLINT_DYN_CTL_INTERVAL_S  5
#define PF_GLINT_DYN_CTL_INTERVAL_M  BIT (PF_GLINT_DYN_CTL_INTERVAL_S)
#define PF_GLINT_DYN_CTL_WB_ON_ITR_S 30
#define PF_GLINT_DYN_CTL_WB_ON_ITR_M BIT (PF_GLINT_DYN_CTL_WB_ON_ITR_S)

/* Generic registers */
#define PFGEN_RSTAT		0x08407008 /* PFR Status */
#define PFGEN_RSTAT_PFR_STATE_S 0
#define PFGEN_RSTAT_PFR_STATE_M MAKEMASK (0x3, PFGEN_RSTAT_PFR_STATE_S)
#define PFGEN_CTRL		0x0840700C
#define PFGEN_CTRL_PFSWR	BIT (0)

#define IDPF_CTLQ_ID	       -1
#define IDPF_CTLQ_LEN	       64
#define IDPF_DFLT_MBX_BUF_SIZE 4096

#define IDPF_MAX_NUM_QUEUES 256
#define IDPF_MIN_BUF_SIZE   1024
#define IDPF_MAX_FRAME_SIZE 9728
#define IDPF_MAX_PKT_TYPE   1024
#define IDPF_QUEUE_SZ_MAX   4096
#define IDPF_QUEUE_SZ_MIN   64

#define IDPF_RESET_SUSPEND_TIME	 20e-3
#define IDPF_RESET_MAX_WAIT_TIME 1

#define IDPF_SEND_TO_PF_SUSPEND_TIME  10e-3
#define IDPF_SEND_TO_PF_MAX_WAIT_TIME 1
#define IDPF_SEND_TO_PF_MAX_TRY_TIMES 200

#define IDPF_RX_MAX_DESC_IN_CHAIN 5

#define IDPF_MAX_VPORT_NUM  8
#define IDPF_DFLT_Q_VEC_NUM 1
#define IDPF_DFLT_INTERVAL  16

#define IDPF_DEFAULT_RXQ_NUM 16
#define IDPF_DEFAULT_TXQ_NUM 16

#define IDPF_ETH_ALEN 6

#define IDPF_INVALID_VPORT_IDX 0xffff
#define IDPF_TXQ_PER_GRP       1
#define IDPF_TX_COMPLQ_PER_GRP 1
#define IDPF_RXQ_PER_GRP       1
#define IDPF_RX_BUFQ_PER_GRP   2
#define IDPF_RX_BUF_STRIDE     64

/* Maximum buffer lengths for all control queue types */
#define IDPF_CTLQ_MAX_RING_SIZE 1024
#define IDPF_CTLQ_MAX_BUF_LEN	4096

#define IDPF_HI_DWORD(x) ((u32) ((((x) >> 16) >> 16) & 0xFFFFFFFF))
#define IDPF_LO_DWORD(x) ((u32) ((x) &0xFFFFFFFF))
#define IDPF_HI_WORD(x)	 ((u16) (((x) >> 16) & 0xFFFF))
#define IDPF_LO_WORD(x)	 ((u16) ((x) &0xFFFF))

#define IDPF_CTLQ_DESC(R, i) (&(((idpf_ctlq_desc_t *) ((R)->desc_ring.va))[i]))

#define IDPF_CTLQ_DESC_UNUSED(R)                                              \
  (u16) ((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->ring_size) +     \
	 (R)->next_to_clean - (R)->next_to_use - 1)

#define IDPF_GET_PTYPE_SIZE(p)                                                \
  (sizeof (virtchnl2_ptype_t) +                                               \
   (((p)->proto_id_count ? ((p)->proto_id_count - 1) : 0) *                   \
    sizeof ((p)->proto_id[0])))

/* log configuration */
extern vlib_log_class_registration_t idpf_log;
extern vlib_log_class_registration_t idpf_stats_log;

#define idpf_log_err(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_ERR, idpf_log._class, "%U: " f,                    \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define idpf_log_warn(dev, f, ...)                                            \
  vlib_log (VLIB_LOG_LEVEL_WARNING, idpf_log._class, "%U: " f,                \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define idpf_log_debug(dev, f, ...)                                           \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, idpf_log._class, "%U: " f,                  \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define idpf_stats_log_debug(dev, f, ...)                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, idpf_stats_log._class, "%U: " f,            \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

/* List handler */
#ifndef LIST_HEAD_TYPE
#define LIST_HEAD_TYPE(list_name, type) LIST_HEAD (list_name, type)
#endif

#ifndef LIST_ENTRY_TYPE
#define LIST_ENTRY_TYPE(type) LIST_ENTRY (type)
#endif

#ifndef LIST_FOR_EACH_ENTRY_SAFE
#define LIST_FOR_EACH_ENTRY_SAFE(pos, temp, head, entry_type, list)           \
  LIST_FOREACH (pos, head, list)
#endif

#ifndef LIST_FOR_EACH_ENTRY
#define LIST_FOR_EACH_ENTRY(pos, head, entry_type, list)                      \
  LIST_FOREACH (pos, head, list)
#endif

#define foreach_idpf_device_flags                                             \
  _ (0, INITIALIZED, "initialized")                                           \
  _ (1, ERROR, "error")                                                       \
  _ (2, ADMIN_UP, "admin-up")                                                 \
  _ (3, VA_DMA, "vaddr-dma")                                                  \
  _ (4, LINK_UP, "link-up")                                                   \
  _ (6, ELOG, "elog")                                                         \
  _ (7, PROMISC, "promisc")                                                   \
  _ (8, RX_INT, "rx-interrupts")                                              \
  _ (9, RX_FLOW_OFFLOAD, "rx-flow-offload")

enum
{
#define _(a, b, c) IDPF_DEVICE_F_##b = (1 << a),
  foreach_idpf_device_flags
#undef _
};

#define IDPF_PTYPE_UNKNOWN		     0x00000000
#define IDPF_PTYPE_L2_ETHER		     0x00000001
#define IDPF_PTYPE_L2_ETHER_TIMESYNC	     0x00000002
#define IDPF_PTYPE_L2_ETHER_ARP		     0x00000003
#define IDPF_PTYPE_L2_ETHER_LLDP	     0x00000004
#define IDPF_PTYPE_L2_ETHER_NSH		     0x00000005
#define IDPF_PTYPE_L2_ETHER_VLAN	     0x00000006
#define IDPF_PTYPE_L2_ETHER_QINQ	     0x00000007
#define IDPF_PTYPE_L2_ETHER_PPPOE	     0x00000008
#define IDPF_PTYPE_L2_ETHER_FCOE	     0x00000009
#define IDPF_PTYPE_L2_ETHER_MPLS	     0x0000000a
#define IDPF_PTYPE_L2_MASK		     0x0000000f
#define IDPF_PTYPE_L3_IPV4		     0x00000010
#define IDPF_PTYPE_L3_IPV4_EXT		     0x00000030
#define IDPF_PTYPE_L3_IPV6		     0x00000040
#define IDPF_PTYPE_L3_IPV4_EXT_UNKNOWN	     0x00000090
#define IDPF_PTYPE_L3_IPV6_EXT		     0x000000c0
#define IDPF_PTYPE_L3_IPV6_EXT_UNKNOWN	     0x000000e0
#define IDPF_PTYPE_L3_MASK		     0x000000f0
#define IDPF_PTYPE_L4_TCP		     0x00000100
#define IDPF_PTYPE_L4_UDP		     0x00000200
#define IDPF_PTYPE_L4_FRAG		     0x00000300
#define IDPF_PTYPE_L4_SCTP		     0x00000400
#define IDPF_PTYPE_L4_ICMP		     0x00000500
#define IDPF_PTYPE_L4_NONFRAG		     0x00000600
#define IDPF_PTYPE_L4_IGMP		     0x00000700
#define IDPF_PTYPE_L4_MASK		     0x00000f00
#define IDPF_PTYPE_TUNNEL_IP		     0x00001000
#define IDPF_PTYPE_TUNNEL_GRE		     0x00002000
#define IDPF_PTYPE_TUNNEL_VXLAN		     0x00003000
#define IDPF_PTYPE_TUNNEL_NVGRE		     0x00004000
#define IDPF_PTYPE_TUNNEL_GENEVE	     0x00005000
#define IDPF_PTYPE_TUNNEL_GRENAT	     0x00006000
#define IDPF_PTYPE_TUNNEL_GTPC		     0x00007000
#define IDPF_PTYPE_TUNNEL_GTPU		     0x00008000
#define IDPF_PTYPE_TUNNEL_ESP		     0x00009000
#define IDPF_PTYPE_TUNNEL_L2TP		     0x0000a000
#define IDPF_PTYPE_TUNNEL_VXLAN_GPE	     0x0000b000
#define IDPF_PTYPE_TUNNEL_MPLS_IN_GRE	     0x0000c000
#define IDPF_PTYPE_TUNNEL_MPLS_IN_UDP	     0x0000d000
#define IDPF_PTYPE_TUNNEL_MASK		     0x0000f000
#define IDPF_PTYPE_INNER_L2_ETHER	     0x00010000
#define IDPF_PTYPE_INNER_L2_ETHER_VLAN	     0x00020000
#define IDPF_PTYPE_INNER_L2_ETHER_QINQ	     0x00030000
#define IDPF_PTYPE_INNER_L2_MASK	     0x000f0000
#define IDPF_PTYPE_INNER_L3_IPV4	     0x00100000
#define IDPF_PTYPE_INNER_L3_IPV4_EXT	     0x00200000
#define IDPF_PTYPE_INNER_L3_IPV6	     0x00300000
#define IDPF_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN 0x00400000
#define IDPF_PTYPE_INNER_L3_IPV6_EXT	     0x00500000
#define IDPF_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN 0x00600000
#define IDPF_PTYPE_INNER_L3_MASK	     0x00f00000
#define IDPF_PTYPE_INNER_L4_TCP		     0x01000000
#define IDPF_PTYPE_INNER_L4_UDP		     0x02000000
#define IDPF_PTYPE_INNER_L4_FRAG	     0x03000000
#define IDPF_PTYPE_INNER_L4_SCTP	     0x04000000
#define IDPF_PTYPE_INNER_L4_ICMP	     0x05000000
#define IDPF_PTYPE_INNER_L4_NONFRAG	     0x06000000
#define IDPF_PTYPE_INNER_L4_MASK	     0x0f000000
#define IDPF_PTYPE_ALL_MASK		     0x0fffffff

/* Flags sub-structure
 * |0  |1  |2  |3  |4  |5  |6  |7  |8  |9  |10 |11 |12 |13 |14 |15 |
 * |DD |CMP|ERR|  * RSV *  |FTYPE  | *RSV* |RD |VFC|BUF|  HOST_ID  |
 */
/* command flags and offsets */
#define IDPF_CTLQ_FLAG_DD_S	 0
#define IDPF_CTLQ_FLAG_CMP_S	 1
#define IDPF_CTLQ_FLAG_ERR_S	 2
#define IDPF_CTLQ_FLAG_FTYPE_S	 6
#define IDPF_CTLQ_FLAG_RD_S	 10
#define IDPF_CTLQ_FLAG_VFC_S	 11
#define IDPF_CTLQ_FLAG_BUF_S	 12
#define IDPF_CTLQ_FLAG_HOST_ID_S 13

#define IDPF_CTLQ_FLAG_DD  BIT (IDPF_CTLQ_FLAG_DD_S)  /* 0x1	  */
#define IDPF_CTLQ_FLAG_CMP BIT (IDPF_CTLQ_FLAG_CMP_S) /* 0x2	  */
#define IDPF_CTLQ_FLAG_ERR BIT (IDPF_CTLQ_FLAG_ERR_S) /* 0x4	  */
#define IDPF_CTLQ_FLAG_FTYPE_VM                                               \
  BIT (IDPF_CTLQ_FLAG_FTYPE_S)					 /* 0x40	  */
#define IDPF_CTLQ_FLAG_FTYPE_PF BIT (IDPF_CTLQ_FLAG_FTYPE_S + 1) /* 0x80   */
#define IDPF_CTLQ_FLAG_RD	BIT (IDPF_CTLQ_FLAG_RD_S)	 /* 0x400  */
#define IDPF_CTLQ_FLAG_VFC	BIT (IDPF_CTLQ_FLAG_VFC_S)	 /* 0x800  */
#define IDPF_CTLQ_FLAG_BUF	BIT (IDPF_CTLQ_FLAG_BUF_S)	 /* 0x1000 */

/* Host ID is a special field that has 3b and not a 1b flag */
#define IDPF_CTLQ_FLAG_HOST_ID_M MAKE_MASK (0x7000UL, IDPF_CTLQ_FLAG_HOST_ID_S)

#define IDPF_FLEX_TXD_QW1_DTYPE_S 0
#define IDPF_FLEX_TXD_QW1_DTYPE_M MAKEMASK (0x1FUL, IDPF_FLEX_TXD_QW1_DTYPE_S)
#define IDPF_FLEX_TXD_QW1_CMD_S	  5
#define IDPF_FLEX_TXD_QW1_CMD_M	  MAKEMASK (0x7FFUL, IDPF_FLEX_TXD_QW1_CMD_S)

typedef struct idpf_vport idpf_vport_t;

typedef volatile struct
{
  u64 buf_addr; /* Packet buffer address */
  struct
  {
    u64 cmd_dtype;
    union
    {
      /* DTYPE = IDPF_TX_DESC_DTYPE_FLEX_DATA_(0x03) */
      u8 raw[4];

      /* DTYPE = IDPF_TX_DESC_DTYPE_FLEX_TSYN_L2TAG1 (0x06) */
      struct
      {
	u16 l2tag1;
	u8 flex;
	u8 tsync;
      } tsync;

      /* DTYPE=IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2 (0x07) */
      struct
      {
	u16 l2tag1;
	u16 l2tag2;
      } l2tags;
    } flex;
    u16 buf_size;
  } qw1;
} idpf_flex_tx_desc_t;

typedef struct
{
  union
  {
    u64 qword[2];
  };
} idpf_tx_desc_t;

STATIC_ASSERT_SIZEOF (idpf_tx_desc_t, 16);

typedef struct idpf_rxq
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qrx_tail;
  u16 next;
  u16 size;
  virtchnl2_rx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u8 int_mode;
  u8 buffer_pool_index;
  u32 queue_index;

  struct idpf_rxq *bufq1;
  struct idpf_rxq *bufq2;
} idpf_rxq_t;

typedef struct idpf_txq
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qtx_tail;
  u16 next;
  u16 size;
  u32 *ph_bufs;
  clib_spinlock_t lock;
  idpf_tx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u16 *rs_slots;

  idpf_tx_desc_t *tmp_descs;
  u32 *tmp_bufs;
  u32 queue_index;

  struct idpf_txq *complq;
} idpf_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;
  u32 cmd_retval;
  u8 *mbx_resp;
  virtchnl2_op_t pend_cmd;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  u32 numa_node;
  void *bar0;
  u8 *name;

  /* queues */
  u16 n_tx_queues;
  u16 n_rx_queues;
  u32 txq_model;
  u32 rxq_model;

  u16 vsi_id;
  u8 hwaddr[6];
  u16 max_mtu;
  vlib_pci_addr_t pci_addr;

  /* error */
  clib_error_t *error;

  /* hw info */
  u8 *hw_addr;
  u64 hw_addr_len;

  /* control queue - send and receive */
  struct idpf_ctlq_info *asq;
  struct idpf_ctlq_info *arq;

  /* pci info */
  u16 device_id;
  u16 vendor_id;
  u16 subsystem_device_id;
  u16 subsystem_vendor_id;

  /* max config queue number per vc message */
  u32 max_rxq_per_msg;
  u32 max_txq_per_msg;

  /* vport info */
  idpf_vport_t **vports;
  u16 max_vport_nb;
  u16 req_vports[IDPF_MAX_VPORT_NUM];
  u16 req_vport_nb;
  u16 cur_vports;
  u16 cur_vport_nb;
  u16 cur_vport_idx;

  u32 ptype_tbl[IDPF_MAX_PKT_TYPE];

  /* device capability */
  u32 csum_caps;
  u32 seg_caps;
  u32 hsplit_caps;
  u32 rsc_caps;
  u64 rss_caps;
  u64 other_caps;

  u16 max_rx_q;
  u16 max_tx_q;
  u16 max_rx_bufq;
  u16 max_tx_complq;
  u16 max_sriov_vfs;
  u16 max_vports;
  u16 default_num_vports;

  u32 device_type;

  LIST_HEAD_TYPE (list_head, idpf_ctlq_info) cq_list_head;
} idpf_device_t;

/* memory allocation tracking */
typedef struct
{
  void *va;
  u64 pa;
  u32 size;
} idpf_dma_mem_t;

/* Message type read in virtual channel from PF */
typedef enum
{
  IDPF_MSG_ERR = -1, /* Meet error when accessing admin queue */
  IDPF_MSG_NON,	     /* Read nothing from admin queue */
  IDPF_MSG_SYS,	     /* Read system msg from admin queue */
  IDPF_MSG_CMD,	     /* Read async command result */
} idpf_vc_result_t;

typedef struct
{
  u32 tx_start_qid;
  u32 rx_start_qid;
  u32 tx_compl_start_qid;
  u32 rx_buf_start_qid;

  u64 tx_qtail_start;
  u32 tx_qtail_spacing;
  u64 rx_qtail_start;
  u32 rx_qtail_spacing;
  u64 tx_compl_qtail_start;
  u32 tx_compl_qtail_spacing;
  u64 rx_buf_qtail_start;
  u32 rx_buf_qtail_spacing;
} idpf_chunks_info_t;

typedef struct
{
  u32 ops;
  u8 *in_args;	    /* buffer for sending */
  u32 in_args_size; /* buffer size for sending */
  u8 *out_buffer;   /* buffer for response */
  u32 out_size;	    /* buffer size for response */
} idpf_cmd_info_t;

typedef struct
{
  idpf_device_t *id;
  u16 idx;
} idpf_vport_param_t;

struct idpf_vport
{
  idpf_device_t *id;
  virtchnl2_create_vport_t *vport_info;
  u16 idx;
  u16 vport_id;
  u32 txq_model;
  u32 rxq_model;
  u32 num_tx_q;
  idpf_txq_t *txqs;
  u16 num_tx_complq;
  u16 num_rx_q;
  idpf_rxq_t *rxqs;
  u16 num_rx_bufq;

  u16 max_mtu;
  u8 default_mac_addr[VIRTCHNL2_ETH_LENGTH_OF_ADDRESS];

  u16 max_pkt_len; /* Maximum packet length */

  /* MSIX info*/
  virtchnl2_queue_vector_t *qv_map; /* queue vector mapping */
  u16 max_vectors;
  virtchnl2_alloc_vectors_t *recv_vectors;

  /* Chunk info */
  idpf_chunks_info_t chunks_info;

  virtchnl2_vport_stats_t eth_stats_offset;
};

#define IDPF_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef enum
{
  IDPF_PROCESS_REQ_ADD_DEL_ETH_ADDR = 1,
  IDPF_PROCESS_REQ_CONFIG_PROMISC_MDDE = 2,
  IDPF_PROCESS_REQ_PROGRAM_FLOW = 3,
} idpf_process_req_type_t;

typedef struct
{
  idpf_process_req_type_t type;
  u32 dev_instance;
  u32 calling_process_index;
  u8 eth_addr[6];
  int is_add, is_enable;

  /* below parameters are used for 'program flow' event */
  u8 *rule;
  u32 rule_len;
  u8 *program_status;
  u32 status_len;

  clib_error_t *error;
} idpf_process_req_t;

typedef struct
{
  u64 qw1s[IDPF_RX_MAX_DESC_IN_CHAIN - 1];
  u32 buffers[IDPF_RX_MAX_DESC_IN_CHAIN - 1];
} idpf_rx_tail_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t *bufs[IDPF_RX_VECTOR_SZ];
  u16 next[IDPF_RX_VECTOR_SZ];
  u64 qw1s[IDPF_RX_VECTOR_SZ];
  u32 flow_ids[IDPF_RX_VECTOR_SZ];
  idpf_rx_tail_t tails[IDPF_RX_VECTOR_SZ];
  vlib_buffer_t buffer_template;
} idpf_per_thread_data_t;

typedef struct
{
  u16 msg_id_base;

  idpf_device_t **devices;
  idpf_per_thread_data_t *per_thread_data;
} idpf_main_t;

extern idpf_main_t idpf_main;

typedef struct
{
  vlib_pci_addr_t addr;
  u8 *name;
  u16 rxq_single;
  u16 txq_single;
  u16 rxq_num;
  u16 txq_num;
  u16 req_vport_nb;
  u16 rxq_size;
  u16 txq_size;
  int rv;
  u32 sw_if_index;
  clib_error_t *error;
} idpf_create_if_args_t;

void idpf_create_if (vlib_main_t *vm, idpf_create_if_args_t *args);

extern vlib_node_registration_t idpf_process_node;
extern vnet_device_class_t idpf_device_class;

/* format.c */
format_function_t format_idpf_device_name;
format_function_t format_idpf_device_flags;

static inline void
clear_cmd (idpf_device_t *id)
{
  /* Return value may be checked in anither thread, need to ensure the
   * coherence. */
  CLIB_MEMORY_BARRIER ();
  id->pend_cmd = VIRTCHNL2_OP_UNKNOWN;
  id->cmd_retval = VIRTCHNL2_STATUS_SUCCESS;
}

static_always_inline idpf_device_t *
idpf_get_device (u32 dev_instance)
{
  return pool_elt_at_index (idpf_main.devices, dev_instance)[0];
}

static inline void
idpf_reg_write (idpf_device_t *id, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) id->bar0 + addr) = val;
}

static inline u32
idpf_reg_read (idpf_device_t *id, u32 addr)
{
  u32 val = *(volatile u32 *) (id->bar0 + addr);
  return val;
}

static inline void
idpf_reg_flush (idpf_device_t *id)
{
  idpf_reg_read (id, PFGEN_RSTAT);
  asm volatile("" ::: "memory");
}

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u32 flow_id;
  u64 qw1s[IDPF_RX_MAX_DESC_IN_CHAIN];
} idpf_input_trace_t;

/* Error Codes */
/* Linux kernel driver can't directly use these. Instead, they are mapped to
 * linux compatible error codes which get translated in the build script.
 */
#define IDPF_SUCCESS		      0
#define IDPF_ERR_PARAM		      -53  /* -EBADR */
#define IDPF_ERR_NOT_IMPL	      -95  /* -EOPNOTSUPP */
#define IDPF_ERR_NOT_READY	      -16  /* -EBUSY */
#define IDPF_ERR_BAD_PTR	      -14  /* -EFAULT */
#define IDPF_ERR_INVAL_SIZE	      -90  /* -EMSGSIZE */
#define IDPF_ERR_DEVICE_NOT_SUPPORTED -19  /* -ENODEV */
#define IDPF_ERR_FW_API_VER	      -13  /* -EACCESS */
#define IDPF_ERR_NO_MEMORY	      -12  /* -ENOMEM */
#define IDPF_ERR_CFG		      -22  /* -EINVAL */
#define IDPF_ERR_OUT_OF_RANGE	      -34  /* -ERANGE */
#define IDPF_ERR_ALREADY_EXISTS	      -17  /* -EEXIST */
#define IDPF_ERR_DOES_NOT_EXIST	      -6   /* -ENXIO */
#define IDPF_ERR_IN_USE		      -114 /* -EALREADY */
#define IDPF_ERR_MAX_LIMIT	      -109 /* -ETOOMANYREFS */
#define IDPF_ERR_RESET_ONGOING	      -104 /* -ECONNRESET */

/* CRQ/CSQ specific error codes */
#define IDPF_ERR_CTLQ_ERROR   -74  /* -EBADMSG */
#define IDPF_ERR_CTLQ_TIMEOUT -110 /* -ETIMEDOUT */
#define IDPF_ERR_CTLQ_FULL    -28  /* -ENOSPC */
#define IDPF_ERR_CTLQ_NO_WORK -42  /* -ENOMSG */
#define IDPF_ERR_CTLQ_EMPTY   -105 /* -ENOBUFS */

/* Used for queue init, response and events */
typedef enum
{
  IDPF_CTLQ_TYPE_MAILBOX_TX = 0,
  IDPF_CTLQ_TYPE_MAILBOX_RX = 1,
  IDPF_CTLQ_TYPE_CONFIG_TX = 2,
  IDPF_CTLQ_TYPE_CONFIG_RX = 3,
  IDPF_CTLQ_TYPE_EVENT_RX = 4,
  IDPF_CTLQ_TYPE_RDMA_TX = 5,
  IDPF_CTLQ_TYPE_RDMA_RX = 6,
  IDPF_CTLQ_TYPE_RDMA_COMPL = 7
} idpf_ctlq_type_t;

typedef enum
{
  IDPF_PROCESS_EVENT_START = 1,
  IDPF_PROCESS_EVENT_DELETE_IF = 2,
  IDPF_PROCESS_EVENT_AQ_INT = 3,
  IDPF_PROCESS_EVENT_REQ = 4,
} idpf_process_event_t;

/*
 * Generic Control Queue Structures
 */
typedef struct
{
  /* used for queue tracking */
  u32 head;
  u32 tail;
  /* Below applies only to default mb (if present) */
  u32 len;
  u32 bah;
  u32 bal;
  u32 len_mask;
  u32 len_ena_mask;
  u32 head_mask;
} idpf_ctlq_reg_t;

/* Generic queue msg structure */
typedef struct
{
  u8 vmvf_type; /* represents the source of the message on recv */
#define IDPF_VMVF_TYPE_VF 0
#define IDPF_VMVF_TYPE_VM 1
#define IDPF_VMVF_TYPE_PF 2
  u8 host_id;
  /* 3b field used only when sending a message to peer - to be used in
   * combination with target func_id to route the message
   */
#define IDPF_HOST_ID_MASK 0x7

  u16 opcode;
  u16 data_len; /* data_len = 0 when no payload is attached */
  union
  {
    u16 func_id; /* when sending a message */
    u16 status;	 /* when receiving a message */
  };
  union
  {
    struct
    {
      u32 chnl_retval;
      u32 chnl_opcode;
    } mbx;
    u64 cookie;
  } cookie;
  union
  {
#define IDPF_DIRECT_CTX_SIZE   16
#define IDPF_INDIRECT_CTX_SIZE 8
    /* 16 bytes of context can be provided or 8 bytes of context
     * plus the address of a DMA buffer
     */
    u8 direct[IDPF_DIRECT_CTX_SIZE];
    struct
    {
      u8 context[IDPF_INDIRECT_CTX_SIZE];
      idpf_dma_mem_t *payload;
    } indirect;
  } ctx;
} idpf_ctlq_msg_t;

/* Generic queue info structures */
/* MB, CONFIG and EVENT q do not have extended info */
typedef struct
{
  idpf_ctlq_type_t type;
  int id;	       /* absolute queue offset passed as input
			* -1 for default mailbox if present
			*/
  u16 len;	       /* Queue length passed as input */
  u16 buf_size;	       /* buffer size passed as input */
  u64 base_address;    /* output, HPA of the Queue start  */
  idpf_ctlq_reg_t reg; /* registers accessed by ctlqs */

  int ext_info_size;
  void *ext_info; /* Specific to q type */
} idpf_ctlq_create_info_t;

/* Control Queue information */
typedef struct idpf_ctlq_info
{
  LIST_ENTRY_TYPE (idpf_ctlq_info) cq_list;

  idpf_ctlq_type_t cq_type;
  int q_id;
  clib_spinlock_t cq_lock; /* queue lock */

  /* used for interrupt processing */
  u16 next_to_use;
  u16 next_to_clean;
  u16 next_to_post;

  idpf_dma_mem_t desc_ring; /* descriptor ring memory */

  union
  {
    idpf_dma_mem_t **rx_buff;
    idpf_ctlq_msg_t **tx_msg;
  } bi;

  u16 buf_size;	       /* queue buffer size */
  u16 ring_size;       /* Number of descriptors */
  idpf_ctlq_reg_t reg; /* registers accessed by ctlqs */
} idpf_ctlq_info_t;

/* PF/VF mailbox commands */
enum idpf_mbx_opc
{
  /* idpf_mbq_opc_send_msg_to_pf:
   *	usage: used by PF or VF to send a message to its CPF
   *	target: RX queue and function ID of parent PF taken from HW
   */
  idpf_mbq_opc_send_msg_to_pf = 0x0801,

  /* idpf_mbq_opc_send_msg_to_vf:
   *	usage: used by PF to send message to a VF
   *	target: VF control queue ID must be specified in descriptor
   */
  idpf_mbq_opc_send_msg_to_vf = 0x0802,

  /* idpf_mbq_opc_send_msg_to_peer_pf:
   *	usage: used by any function to send message to any peer PF
   *	target: RX queue and host of parent PF taken from HW
   */
  idpf_mbq_opc_send_msg_to_peer_pf = 0x0803,

  /* idpf_mbq_opc_send_msg_to_peer_drv:
   *	usage: used by any function to send message to any peer driver
   *	target: RX queue and target host must be specific in descriptor
   */
  idpf_mbq_opc_send_msg_to_peer_drv = 0x0804,
};

typedef struct
{
  u16 flags;
  u16 opcode;
  u16 datalen; /* 0 for direct commands */
  union
  {
    u16 ret_val;
    u16 pfid_vfid;
  };
  u32 cookie_high;
  u32 cookie_low;
  union
  {
    struct
    {
      u32 param0;
      u32 param1;
      u32 param2;
      u32 param3;
    } direct;
    struct
    {
      u32 param0;
      u32 param1;
      u32 addr_high;
      u32 addr_low;
    } indirect;
    u8 raw[16];
  } params;
} idpf_ctlq_desc_t;

int idpf_ctlq_init (vlib_main_t *vm, idpf_device_t *id, u8 num_q,
		    idpf_ctlq_create_info_t *q_info);
int idpf_ctlq_add (vlib_main_t *vm, idpf_device_t *id,
		   idpf_ctlq_create_info_t *qinfo, struct idpf_ctlq_info **cq);
void idpf_ctlq_remove (idpf_device_t *id, struct idpf_ctlq_info *cq);
int idpf_ctlq_send (idpf_device_t *id, struct idpf_ctlq_info *cq,
		    u16 num_q_msg, idpf_ctlq_msg_t q_msg[]);
int idpf_ctlq_recv (struct idpf_ctlq_info *cq, u16 *num_q_msg,
		    idpf_ctlq_msg_t *q_msg);
int idpf_ctlq_clean_sq (struct idpf_ctlq_info *cq, u16 *clean_count,
			idpf_ctlq_msg_t *msg_status[]);
int idpf_ctlq_post_rx_buffs (idpf_device_t *id, struct idpf_ctlq_info *cq,
			     u16 *buff_count, idpf_dma_mem_t **buffs);
void idpf_ctlq_deinit (idpf_device_t *id);
int idpf_ctlq_alloc_ring_res (vlib_main_t *vm, idpf_device_t *id,
			      struct idpf_ctlq_info *cq);
void idpf_ctlq_dealloc_ring_res (idpf_device_t *id, struct idpf_ctlq_info *cq);
void *idpf_alloc_dma_mem (vlib_main_t *vm, idpf_device_t *id,
			  idpf_dma_mem_t *mem, u64 size);
void idpf_free_dma_mem (idpf_device_t *id, idpf_dma_mem_t *mem);

#endif /* IDPF_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
