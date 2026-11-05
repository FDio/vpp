/* SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
 * Copyright (c) 2026 Damjan Marion
 * Copyright(c) 2001-2023 Intel Corporation
 */

#pragma once

#include <vppinfra/clib.h>

enum
{
  ICE_DEVICE_STATE_ACTIVE = 0,
};

#define ICE_AQ_CLEAR_PXE_RX_COUNT     2
#define ICE_AQ_SFF_READ_MAX	      16
#define ICE_AQ_LARGE_BUFFER_THRESHOLD 512
#define ICE_PKG_MIN_DMA_SIZE	      28
#define ICE_PKG_ALIGNMENT	      4
#define ICE_QUEUE_BASE_SHIFT	      7
#define ICE_RX_BUFFER_SIZE_SHIFT      7
#define ICE_RX_BUFFER_SIZE_UNIT	      (1U << ICE_RX_BUFFER_SIZE_SHIFT)
#define ICE_RX_BUFFER_SIZE_MAX	      127
#define ICE_ITR_INTERVAL_UNIT_US      2
#define ICE_RESET_DELAY_BIAS	      10
#define ICE_RESET_DELAY_UNIT_SECONDS  0.1
#define ICE_COUNTER_BITS	      40
#define ICE_COUNTER_HIGH_MASK	      0xff
#define ICE_COUNTER_MASK	      ((1ULL << ICE_COUNTER_BITS) - 1)

/* Reset and PF identification registers */
#define ICE_GLGEN_RSTAT	 0x000b8188
#define ICE_GLGEN_RSTCTL 0x000b8180
#define ICE_GLNVM_ULD	 0x000b6008
#define ICE_PFGEN_CTRL	 0x00091000
#define ICE_PF_FUNC_RID	 0x0009e880
/* LAN queue allocation registers */
#define ICE_PFLAN_RX_QALLOC 0x001d2500
#define ICE_PFLAN_TX_QALLOC 0x001d2580

/* AdminQ registers */
#define ICE_PF_FW_ATQBAL 0x00080000
#define ICE_PF_FW_ATQBAH 0x00080100
#define ICE_PF_FW_ATQLEN 0x00080200
#define ICE_PF_FW_ATQH	 0x00080300
#define ICE_PF_FW_ATQT	 0x00080400
#define ICE_PF_FW_ARQBAL 0x00080080
#define ICE_PF_FW_ARQBAH 0x00080180
#define ICE_PF_FW_ARQLEN 0x00080280
#define ICE_PF_FW_ARQH	 0x00080380
#define ICE_PF_FW_ARQT	 0x00080480

/* LAN queue registers */
#define ICE_QRX_CTRL(q)		    (0x00120000 + (q) * 4)
#define ICE_QRX_CONTEXT(i, q)	    (0x00280000 + (i) * 8192 + (q) * 4)
#define ICE_QRXFLXP_CNTXT(q)	    (0x00480000 + (q) * 4)
#define ICE_QRX_TAIL(q)		    (0x00290000 + (q) * 4)
#define ICE_QRX_ITR(q)		    (0x00292000 + (q) * 4)
#define ICE_QTX_COMM_HEAD(q)	    (0x000e0000 + (q) * 4)
#define ICE_QTX_COMM_DBELL(q)	    (0x002c0000 + (q) * 4)
#define ICE_GLCOMM_QTX_CNTX_DATA(i) (0x002d2d40 + (i) * 4)
#define ICE_GLCOMM_QTX_CNTX_CTL	    0x002d2dc8
#define ICE_GLCOMM_QTX_CNTX_STAT    0x002d2dcc

/* Interrupt registers */
#define ICE_QINT_TQCTL(q)    (0x00140000 + (q) * 4)
#define ICE_QINT_RQCTL(q)    (0x00150000 + (q) * 4)
#define ICE_GLINT_DYN_CTL(v) (0x00160000 + (v) * 4)
#define ICE_GLINT_ITR0(v)    (0x00154000 + (v) * 4)
#define ICE_PFINT_FW_CTL     0x0016c800

/* link flow control TX pause quanta and refresh timer */
#define ICE_E810_PRTMAC_TX_PS_QNT_LFC  0x001e37e0
#define ICE_E810_PRTMAC_TX_PS_RFSH_LFC 0x001e3900
#define ICE_E830_PRTMAC_CL01_PS_QNT    0x001e32a0
#define ICE_E830_PRTMAC_CL01_QNT_THR   0x001e3320

#define ICE_AQC_MAC_MAX_FRAME_SIZE 9728

/* Malicious driver detection registers */
#define ICE_GL_MDET_TX_PQM	       0x002d2e00
#define ICE_GL_MDET_TX_TCLAN	       0x000fc068
#define ICE_GL_MDET_TX_TDPU	       0x00049350
#define ICE_E830_GL_MDET_TX_TCLAN_FIFO 0x000fcfd0
#define ICE_E830_GL_MDET_TX_TDPU_FIFO  0x00049d80
#define ICE_PRTDCB_TDPUC	       0x00040940

/* VSI statistics registers */
#define ICE_GLSWID_RUPP(vsi) (0x00345000 + (vsi) * 4)
#define ICE_GLV_BPRCL(vsi)   (0x003b6000 + (vsi) * 8)
#define ICE_GLV_BPRCH(vsi)   (0x003b6004 + (vsi) * 8)
#define ICE_GLV_BPTCL(vsi)   (0x0030e000 + (vsi) * 8)
#define ICE_GLV_BPTCH(vsi)   (0x0030e004 + (vsi) * 8)
#define ICE_GLV_GORCL(vsi)   (0x003b0000 + (vsi) * 8)
#define ICE_GLV_GORCH(vsi)   (0x003b0004 + (vsi) * 8)
#define ICE_GLV_GOTCL(vsi)   (0x00300000 + (vsi) * 8)
#define ICE_GLV_GOTCH(vsi)   (0x00300004 + (vsi) * 8)
#define ICE_GLV_MPRCL(vsi)   (0x003b4000 + (vsi) * 8)
#define ICE_GLV_MPRCH(vsi)   (0x003b4004 + (vsi) * 8)
#define ICE_GLV_MPTCL(vsi)   (0x0030c000 + (vsi) * 8)
#define ICE_GLV_MPTCH(vsi)   (0x0030c004 + (vsi) * 8)
#define ICE_GLV_RDPC(vsi)    (0x00294c04 + (vsi) * 4)
#define ICE_GLV_REPC(vsi)    (0x00295804 + (vsi) * 4)
#define ICE_GLV_TEPC(vsi)    (0x00312000 + (vsi) * 4)
#define ICE_GLV_UPRCL(vsi)   (0x003b2000 + (vsi) * 8)
#define ICE_GLV_UPRCH(vsi)   (0x003b2004 + (vsi) * 8)
#define ICE_GLV_UPTCL(vsi)   (0x0030a000 + (vsi) * 8)
#define ICE_GLV_UPTCH(vsi)   (0x0030a004 + (vsi) * 8)

/* Physical port statistics registers */
#define ICE_PRTRPB_RDPC		       0x000ac260
#define ICE_PRTRPB_LDPC		       0x000ac280
#define ICE_GLPRT_STDC(i)	       (0x00340000 + (i) * 4)
#define ICE_GLPRT_BPRCL(port)	       (0x00381380 + (port) * 8)
#define ICE_GLPRT_BPRCH(port)	       (0x00381384 + (port) * 8)
#define ICE_GLPRT_BPTCL(port)	       (0x00381240 + (port) * 8)
#define ICE_GLPRT_BPTCH(port)	       (0x00381244 + (port) * 8)
#define ICE_GLPRT_CRCERRS(port)	       (0x00380100 + (port) * 8)
#define ICE_GLPRT_GORCL(port)	       (0x00380000 + (port) * 8)
#define ICE_GLPRT_GORCH(port)	       (0x00380004 + (port) * 8)
#define ICE_GLPRT_GOTCL(port)	       (0x00380b40 + (port) * 8)
#define ICE_GLPRT_GOTCH(port)	       (0x00380b44 + (port) * 8)
#define ICE_GLPRT_ILLERRC(port)	       (0x003801c0 + (port) * 8)
#define ICE_GLPRT_LXOFFRXC(port)       (0x003802c0 + (port) * 8)
#define ICE_GLPRT_LXOFFTXC(port)       (0x00381180 + (port) * 8)
#define ICE_GLPRT_LXONRXC(port)	       (0x00380280 + (port) * 8)
#define ICE_GLPRT_LXONTXC(port)	       (0x00381140 + (port) * 8)
#define ICE_GLPRT_MLFC(port)	       (0x00380040 + (port) * 8)
#define ICE_GLPRT_MPRCL(port)	       (0x00381340 + (port) * 8)
#define ICE_GLPRT_MPRCH(port)	       (0x00381344 + (port) * 8)
#define ICE_GLPRT_MPTCL(port)	       (0x00381200 + (port) * 8)
#define ICE_GLPRT_MPTCH(port)	       (0x00381204 + (port) * 8)
#define ICE_GLPRT_MRFC(port)	       (0x00380080 + (port) * 8)
#define ICE_GLPRT_PRC64L(port)	       (0x00380900 + (port) * 8)
#define ICE_GLPRT_PRC64H(port)	       (0x00380904 + (port) * 8)
#define ICE_GLPRT_PRC127L(port)	       (0x00380940 + (port) * 8)
#define ICE_GLPRT_PRC127H(port)	       (0x00380944 + (port) * 8)
#define ICE_GLPRT_PRC255L(port)	       (0x00380980 + (port) * 8)
#define ICE_GLPRT_PRC255H(port)	       (0x00380984 + (port) * 8)
#define ICE_GLPRT_PRC511L(port)	       (0x003809c0 + (port) * 8)
#define ICE_GLPRT_PRC511H(port)	       (0x003809c4 + (port) * 8)
#define ICE_GLPRT_PRC1023L(port)       (0x00380a00 + (port) * 8)
#define ICE_GLPRT_PRC1023H(port)       (0x00380a04 + (port) * 8)
#define ICE_GLPRT_PRC1522L(port)       (0x00380a40 + (port) * 8)
#define ICE_GLPRT_PRC1522H(port)       (0x00380a44 + (port) * 8)
#define ICE_GLPRT_PRC9522L(port)       (0x00380a80 + (port) * 8)
#define ICE_GLPRT_PRC9522H(port)       (0x00380a84 + (port) * 8)
#define ICE_GLPRT_PTC64L(port)	       (0x00380b80 + (port) * 8)
#define ICE_GLPRT_PTC64H(port)	       (0x00380b84 + (port) * 8)
#define ICE_GLPRT_PTC127L(port)	       (0x00380bc0 + (port) * 8)
#define ICE_GLPRT_PTC127H(port)	       (0x00380bc4 + (port) * 8)
#define ICE_GLPRT_PTC255L(port)	       (0x00380c00 + (port) * 8)
#define ICE_GLPRT_PTC255H(port)	       (0x00380c04 + (port) * 8)
#define ICE_GLPRT_PTC511L(port)	       (0x00380c40 + (port) * 8)
#define ICE_GLPRT_PTC511H(port)	       (0x00380c44 + (port) * 8)
#define ICE_GLPRT_PTC1023L(port)       (0x00380c80 + (port) * 8)
#define ICE_GLPRT_PTC1023H(port)       (0x00380c84 + (port) * 8)
#define ICE_GLPRT_PTC1522L(port)       (0x00380cc0 + (port) * 8)
#define ICE_GLPRT_PTC1522H(port)       (0x00380cc4 + (port) * 8)
#define ICE_GLPRT_PTC9522L(port)       (0x00380d00 + (port) * 8)
#define ICE_GLPRT_PTC9522H(port)       (0x00380d04 + (port) * 8)
#define ICE_GLPRT_PXOFFRXC(p, tc)      (0x00380500 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_PXOFFRXC_H(p, tc)    (0x00380504 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_PXOFFTXC(p, tc)      (0x00380f40 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_PXOFFTXC_H(p, tc)    (0x00380f44 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_PXONRXC(p, tc)       (0x00380300 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_PXONRXC_H(p, tc)     (0x00380304 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_PXONTXC(p, tc)       (0x00380d40 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_PXONTXC_H(p, tc)     (0x00380d44 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_RFC(port)	       (0x00380ac0 + (port) * 8)
#define ICE_GLPRT_RJC(port)	       (0x00380b00 + (port) * 8)
#define ICE_GLPRT_RLEC(port)	       (0x00380140 + (port) * 8)
#define ICE_GLPRT_ROC(port)	       (0x00380240 + (port) * 8)
#define ICE_GLPRT_RUC(port)	       (0x00380200 + (port) * 8)
#define ICE_GLPRT_RXON2OFFCNT(p, tc)   (0x00380700 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_RXON2OFFCNT_H(p, tc) (0x00380704 + (p) * 8 + (tc) * 64)
#define ICE_GLPRT_TDOLD(port)	       (0x00381280 + (port) * 8)
#define ICE_GLPRT_UPRCL(port)	       (0x00381300 + (port) * 8)
#define ICE_GLPRT_UPRCH(port)	       (0x00381304 + (port) * 8)
#define ICE_GLPRT_UPTCL(port)	       (0x003811c0 + (port) * 8)
#define ICE_GLPRT_UPTCH(port)	       (0x003811c4 + (port) * 8)

/* Reset and PF identification register layouts */
typedef union
{
  struct
  {
    u32 devstate : 2;
    u32 reset_type : 2;
    u32 _reserved : 28;
  };
  u32 as_u32;
} ice_reg_glgen_rstat_t;

typedef union
{
  struct
  {
    u32 global_reset_delay : 6;
    u32 _reserved_6_7 : 2;
    u32 ecc_reset_enable : 1;
    u32 _reserved_9_29 : 21;
    u32 ecc_reset_timeout_enable : 1;
    u32 flr_timeout_enable : 1;
  };
  u32 as_u32;
} ice_reg_glgen_rstctl_t;

typedef union
{
  struct
  {
    u32 pcier_done : 1;
    u32 pcier_done_1 : 1;
    u32 _reserved_2 : 1;
    u32 corer_done : 1;
    u32 globr_done : 1;
    u32 por_done : 1;
    u32 _reserved_6_7 : 2;
    u32 por_done_1 : 1;
    u32 pcier_done_2 : 1;
    u32 pe_done : 1;
    u32 hlp_core_done : 1;
    u32 hlp_full_done : 1;
    u32 _reserved_13_31 : 19;
  };
  u32 as_u32;
} ice_reg_glnvm_uld_t;

typedef union
{
  struct
  {
    u32 pf_sw_reset : 1;
    u32 _reserved : 31;
  };
  u32 as_u32;
} ice_reg_pfgen_ctrl_t;

typedef union
{
  struct
  {
    u32 function_number : 3;
    u32 _reserved : 29;
  };
  u32 as_u32;
} ice_reg_pf_func_rid_t;

/* LAN queue allocation register layouts */
typedef union
{
  struct
  {
    u32 first_queue : 11;
    u32 _reserved_11_15 : 5;
    u32 last_queue : 11;
    u32 _reserved_27_30 : 4;
    u32 valid : 1;
  };
  u32 as_u32;
} ice_reg_rxq_alloc_t;

typedef union
{
  struct
  {
    u32 first_queue : 14;
    u32 _reserved_14_15 : 2;
    u32 last_queue : 14;
    u32 _reserved_30 : 1;
    u32 valid : 1;
  };
  u32 as_u32;
} ice_reg_txq_alloc_t;

/* AdminQ register layouts */
typedef union
{
  struct
  {
    u32 length : 10;
    u32 _reserved : 18;
    u32 vf_error : 1;
    u32 overflow : 1;
    u32 critical_error : 1;
    u32 enable : 1;
  };
  u32 as_u32;
} ice_reg_aq_len_t;

/* LAN queue control register layouts */
typedef union
{
  struct
  {
    u32 enable_request : 1;
    u32 _reserved_1 : 1;
    u32 enable_status : 1;
    u32 _reserved_3_31 : 29;
  };
  u32 as_u32;
} ice_reg_qrx_ctrl_t;

typedef union
{
  struct
  {
    u32 rxdid : 6;
    u32 _reserved_6_7 : 2;
    u32 priority : 3;
    u32 timestamp : 1;
    u32 _reserved_12_31 : 20;
  };
  u32 as_u32;
} ice_reg_qrxflxp_cntxt_t;

typedef union
{
  struct
  {
    u32 head : 13;
    u32 _reserved_13_15 : 3;
    u32 report_status_pending : 1;
    u32 _reserved_17_31 : 15;
  };
  u32 as_u32;
} ice_reg_qtx_comm_head_t;

typedef union
{
  struct
  {
    u32 queue_id : 14;
    u32 _reserved_14_15 : 2;
    u32 cmd : 3;
    u32 cmd_exec : 1;
    u32 _reserved_20_31 : 12;
  };
  u32 as_u32;
} ice_reg_glcomm_qtx_cntx_ctl_t;

typedef union
{
  struct
  {
    u32 cmd_in_prog : 1;
    u32 _reserved : 31;
  };
  u32 as_u32;
} ice_reg_glcomm_qtx_cntx_stat_t;

/* Interrupt register layouts (QINT_RQCTL and QINT_TQCTL share this layout) */
enum
{
  ICE_ITR_INDEX_NONE = 3,
};

typedef union
{
  struct
  {
    u32 msix_indx : 11;
    u32 itr_indx : 2;
    u32 _reserved_13_29 : 17;
    u32 cause_ena : 1;
    u32 _reserved_31 : 1;
  };
  u32 as_u32;
} ice_reg_qint_ctl_t;

typedef union
{
  struct
  {
    u32 no_expire : 1;
    u32 _reserved_1_31 : 31;
  };
  u32 as_u32;
} ice_reg_qrx_itr_t;

typedef union
{
  struct
  {
    u32 msix_indx : 11;
    u32 _reserved_11_29 : 19;
    u32 cause_ena : 1;
    u32 _reserved_31 : 1;
  };
  u32 as_u32;
} ice_reg_pfint_ctl_t;

typedef union
{
  struct
  {
    u32 intena : 1;
    u32 clearpba : 1;
    u32 swint_trig : 1;
    u32 itr_indx : 2;
    u32 interval : 12;
    u32 _reserved_17_23 : 7;
    u32 sw_itr_indx_ena : 1;
    u32 sw_itr_indx : 2;
    u32 _reserved_27_29 : 3;
    u32 wb_on_itr : 1;
    u32 intena_msk : 1;
  };
  u32 as_u32;
} ice_reg_glint_dyn_ctl_t;

/* Malicious driver detection register layouts */
typedef union
{
  struct
  {
    u32 pf_num : 3;
    u32 _reserved_3 : 1;
    u32 vf_num : 8;
    u32 queue_num : 14;
    u32 event_type : 5;
    u32 valid : 1;
  };
  u32 as_u32;
} ice_reg_mdet_tx_pqm_t;

typedef union
{
  struct
  {
    u32 queue_num : 15;
    u32 vf_num : 8;
    u32 pf_num : 3;
    u32 event_type : 5;
    u32 valid : 1;
  };
  u32 as_u32;
} ice_reg_mdet_tx_tclan_t;

typedef ice_reg_mdet_tx_tclan_t ice_reg_mdet_tx_tdpu_t;

typedef union
{
  struct
  {
    u32 function_num : 10;
    u32 pf_num : 3;
    u32 function_type : 2;
    u32 event_type : 5;
    u32 fifo_full : 1;
    u32 valid : 1;
    u32 _reserved_22_23 : 2;
    u32 event_count : 8;
  };
  u32 as_u32;
} ice_reg_e830_mdet_tx_tclan_fifo_t;

typedef ice_reg_e830_mdet_tx_tclan_fifo_t ice_reg_e830_mdet_tx_tdpu_fifo_t;

typedef union
{
  struct
  {
    u32 max_tx_frame : 16;
    u32 malformed_length : 1;
    u32 malformed_command : 1;
    u32 ttl_drop : 1;
    u32 unsupported_request_drop : 1;
    u32 dummy : 1;
    u32 big_packet_size : 1;
    u32 l2_accept_fail : 1;
    u32 dscp_check_fail : 1;
    u32 rcu_antispoof : 1;
    u32 nic_dsi : 1;
    u32 nic_ipsec : 1;
    u32 _reserved_27_30 : 4;
    u32 clear_drop : 1;
  };
  u32 as_u32;
} ice_reg_prtdcb_tdpuc_t;

/* AdminQ descriptor and command layouts */
typedef union
{
  struct
  {
    u16 done : 1;
    u16 complete : 1;
    u16 error : 1;
    u16 vf_event : 1;
    u16 _reserved_4_8 : 5;
    u16 large_buffer : 1;
    u16 read : 1;
    u16 vf_context : 1;
    u16 buffer : 1;
    u16 suppress_interrupt : 1;
    u16 interrupt_on_error : 1;
    u16 flush_on_error : 1;
  };
  u16 as_u16;
} ice_aq_desc_flags_t;

/* RSS command layouts */
typedef union
{
  struct
  {
    u16 vsi_id : 10;
    u16 _reserved : 5;
    u16 valid : 1;
  };
  u16 as_u16;
} ice_aq_rss_vsi_id_t;

typedef union
{
  struct
  {
    u16 table_type : 2;
    u16 table_size : 2;
    u16 global_index : 4;
    u16 _reserved : 8;
  };
  u16 as_u16;
} ice_aq_rss_lut_flags_t;

/* Request/Release Resource Ownership command layout */
enum
{
  ICE_AQ_RES_ID_NVM = 0x0001,
  ICE_AQ_RES_ID_SDP = 0x0002,
  ICE_AQ_RES_ID_CHANGE_LOCK = 0x0003,
  ICE_AQ_RES_ID_GLOBAL_CFG_LOCK = 0x0004,
};

enum
{
  ICE_AQ_RES_ACCESS_READ = 1,
  ICE_AQ_RES_ACCESS_WRITE = 2,
};

enum
{
  ICE_AQ_RES_GLOBAL_SUCCESS = 0,
  ICE_AQ_RES_GLOBAL_IN_PROGRESS = 1,
  ICE_AQ_RES_GLOBAL_DONE = 2,
};

typedef struct
{
  u16 resource_id;
  u16 access_type;
  u32 timeout;
  u32 resource_number;
  u16 status;
  u16 _reserved;
} ice_aq_resource_params_t;

STATIC_ASSERT_SIZEOF (ice_aq_resource_params_t, 16);

/* Update Package command layout */
typedef union
{
  struct
  {
    u8 last_buffer : 1;
  };
  u8 as_u8;
} ice_aq_update_pkg_flags_t;

/* Tx queue disable command layout */
typedef union
{
  struct
  {
    u8 rst_src : 2;
    u8 subseq_call : 1;
    u8 flush_pipe : 1;
    u8 _reserved : 4;
  };
  u8 as_u8;
} ice_aq_q_dis_cmd_t;

typedef union
{
  struct
  {
    u16 vmvf_num : 10;
    u16 timeout : 6;
  };
  u16 as_u16;
} ice_aq_q_dis_vmvf_timeout_t;

typedef struct
{
  i8 temp;
  u8 temp_warning_threshold;
  u8 temp_critical_threshold;
  u8 temp_fatal_threshold;
  u8 reserved[4];
} ice_aqc_sensor_reading_t;

STATIC_ASSERT_SIZEOF (ice_aqc_sensor_reading_t, 8);

typedef struct
{
  u8 lport_num;
  u8 lport_num_valid : 1;
  u8 _reserved_9 : 7;
  struct
  {
    u16 i2c_addr : 10;
    u16 i2c_addr_10bit : 1;
    u16 set_page : 2;
    u16 _reserved_13_14 : 2;
    u16 is_write : 1;
  } i2c_bus_addr;
  u16 i2c_mem_addr;
  u8 eeprom_bank;
  u8 eeprom_page;
  u32 addr_high;
  u32 addr_low;
} ice_aqc_sff_eeprom_t;

STATIC_ASSERT_SIZEOF (ice_aqc_sff_eeprom_t, 16);

typedef struct
{
  union
  {
    struct
    {
      u8 mib_type : 2;
      u8 bridge_type : 2;
      u8 tx_state : 2;
      u8 dcbx_mode : 2;
    };
    u8 type;
  };
  u8 state;
  u16 local_len, remote_len;
  u8 reserved[2];
  u32 addr_high, addr_low;
} ice_aqc_lldp_mib_event_t;

typedef struct
{
  u16 caller_opcode, command_tag;
  u8 reserved[12];
} ice_aqc_txq_cleanup_event_t;

typedef struct
{
  union
  {
    struct
    {
      u8 synce_lock_loss : 1;
      u8 holdover_change : 1;
      u8 timesync_lock_loss : 1;
      u8 reserved3_7 : 5;
    };
    u8 error_type;
  };
  u8 reserved[15];
} ice_aqc_cgu_error_event_t;

typedef struct
{
  u32 prtdcb_ruptq, qtx_ctl;
  u8 reserved[8];
} ice_aqc_lan_overflow_event_t;

typedef struct
{
  u16 status_code, event_source;
  u32 internal_data1, internal_data2;
} ice_aqc_health_status_elem_t;

#define foreach_ice_aq_health_source                                                               \
  _ (1, PF, "PF")                                                                                  \
  _ (2, PORT, "port")                                                                              \
  _ (3, GLOBAL, "global")

enum
{
#define _(v, n, d) ICE_AQ_HEALTH_SOURCE_##n = v,
  foreach_ice_aq_health_source
#undef _
};

#define foreach_ice_aq_health_status                                                               \
  _ (0x101, ERR_UNKNOWN_MOD_STRICT, "unsupported module (strict mode)", ERR)                       \
  _ (0x102, ERR_MOD_TYPE, "unsupported module type", ERR)                                          \
  _ (0x103, ERR_MOD_QUAL, "module qualification failed", ERR)                                      \
  _ (0x104, ERR_MOD_COMM, "module communication failed", ERR)                                      \
  _ (0x105, ERR_MOD_CONFLICT, "module conflict", ERR)                                              \
  _ (0x106, ERR_MOD_NOT_PRESENT, "module not present", ERR)                                        \
  _ (0x107, INFO_MOD_UNDERUTILIZED, "module underutilized", INFO)                                  \
  _ (0x108, ERR_UNKNOWN_MOD_LENIENT, "unsupported module (lenient mode)", ERR)                     \
  _ (0x109, ERR_MOD_DIAGNOSTIC_FEATURE, "module diagnostics not implemented", ERR)                 \
  _ (0x10B, ERR_INVALID_LINK_CFG, "invalid link configuration", ERR)                               \
  _ (0x10C, ERR_PORT_ACCESS, "port hardware access failed", ERR)                                   \
  _ (0x10D, ERR_PORT_UNREACHABLE, "port unreachable", ERR)                                         \
  _ (0x10F, INFO_PORT_SPEED_MOD_LIMITED, "port speed limited by module", INFO)                     \
  _ (0x110, ERR_PARALLEL_FAULT, "parallel detection fault", ERR)                                   \
  _ (0x111, INFO_PORT_SPEED_PHY_LIMITED, "port speed limited by PHY", INFO)                        \
  _ (0x112, ERR_NETLIST_TOPO, "topology netlist corrupted", ERR)                                   \
  _ (0x113, ERR_NETLIST, "unrecoverable netlist error", ERR)                                       \
  _ (0x114, ERR_TOPO_CONFLICT, "topology conflict", ERR)                                           \
  _ (0x115, ERR_LINK_HW_ACCESS, "link hardware access failed", ERR)                                \
  _ (0x116, ERR_LINK_RUNTIME, "link runtime failure", ERR)                                         \
  _ (0x117, ERR_DNL_INIT, "link management initialization failed", ERR)                            \
  _ (0x120, ERR_PHY_NVM_PROG, "PHY NVM programming failed", ERR)                                   \
  _ (0x121, ERR_PHY_FW_LOAD, "PHY firmware load failed", ERR)                                      \
  _ (0x500, INFO_RECOVERY, "firmware recovery mode", INFO)                                         \
  _ (0x501, ERR_FLASH_ACCESS, "flash access failed", ERR)                                          \
  _ (0x502, ERR_NVM_AUTH, "NVM authentication failed", ERR)                                        \
  _ (0x503, ERR_OROM_AUTH, "option ROM authentication failed", ERR)                                \
  _ (0x504, ERR_DDP_AUTH, "DDP authentication failed", ERR)                                        \
  _ (0x505, ERR_NVM_COMPAT, "incompatible NVM image", ERR)                                         \
  _ (0x506, ERR_OROM_COMPAT, "incompatible option ROM image", ERR)                                 \
  _ (0x507, ERR_NVM_SEC_VIOLATION, "NVM security version violation", ERR)                          \
  _ (0x508, ERR_OROM_SEC_VIOLATION, "option ROM security version violation", ERR)                  \
  _ (0x509, ERR_DCB_MIB, "invalid DCB MIB", ERR)                                                   \
  _ (0x50A, ERR_MNG_TIMEOUT, "management timeout", ERR)                                            \
  _ (0x50B, ERR_BMC_RESET, "reset requested by BMC", ERR)                                          \
  _ (0x50C, ERR_LAST_MNG_FAIL, "management command failed", ERR)                                   \
  _ (0x50D, ERR_RESOURCE_ALLOC_FAIL, "resource allocation failed", ERR)                            \
  _ (0x601, INFO_LOSS_OF_LOCK, "clock lock lost", INFO)                                            \
  _ (0x1000, ERR_FW_LOOP, "firmware reset loop", ERR)                                              \
  _ (0x1001, ERR_FW_PFR_FAIL, "PF reset failed", ERR)                                              \
  _ (0x1002, ERR_LAST_FAIL_AQ, "last failed AdminQ command", ERR)

enum
{
#define _(v, n, d, l) ICE_AQ_HEALTH_##n = v,
  foreach_ice_aq_health_status
#undef _
};

#define ICE_AQ_HEALTH_DATA_UNDEFINED 0xdeadbeef

#define ICE_AQ_HEALTH_API_MAJOR 1
#define ICE_AQ_HEALTH_API_MINOR 7
#define ICE_AQ_HEALTH_API_PATCH 6

typedef struct
{
  union
  {
    struct
    {
      u8 pf_specific : 1;
      u8 all_pfs : 1;
      u8 global : 1;
      u8 reserved : 5;
    };
    u8 as_u8;
  } sources;
  u8 reserved[15];
} ice_aqc_health_status_config_t;

STATIC_ASSERT_SIZEOF (ice_aqc_health_status_config_t, 16);

typedef struct
{
  u16 count;
  u8 reserved[6];
  u32 addr_high, addr_low;
} ice_aqc_health_status_event_t;

typedef struct
{
  u8 command_flags;
  union
  {
    struct
    {
      u8 reserved0 : 1;
      u8 more_data : 1;
      u8 reserved2_7 : 6;
    };
    u8 response_flags;
  };
  u16 timestamp_high;
  u32 timestamp_low;
  u32 addr_high, addr_low;
} ice_aqc_fw_log_event_t;

typedef struct
{
  u16 offset_low;
  u8 offset_high, command_flags;
  u16 module, length;
  u32 addr_high, addr_low;
} ice_aqc_nvm_event_t;

typedef struct
{
  u32 id;
  u32 reserved;
  u32 addr_high, addr_low;
} ice_aqc_pf_vf_msg_t;

STATIC_ASSERT_SIZEOF (ice_aqc_lldp_mib_event_t, 16);
STATIC_ASSERT_SIZEOF (ice_aqc_txq_cleanup_event_t, 16);
STATIC_ASSERT_SIZEOF (ice_aqc_cgu_error_event_t, 16);
STATIC_ASSERT_SIZEOF (ice_aqc_lan_overflow_event_t, 16);
STATIC_ASSERT_SIZEOF (ice_aqc_health_status_elem_t, 12);
STATIC_ASSERT_SIZEOF (ice_aqc_health_status_event_t, 16);
STATIC_ASSERT_SIZEOF (ice_aqc_fw_log_event_t, 16);
STATIC_ASSERT_SIZEOF (ice_aqc_nvm_event_t, 16);
STATIC_ASSERT_SIZEOF (ice_aqc_pf_vf_msg_t, 16);

typedef union
{
  u8 raw[16];
  ice_aqc_lldp_mib_event_t lldp_mib_event;
  ice_aqc_txq_cleanup_event_t txq_cleanup_event;
  ice_aqc_cgu_error_event_t cgu_error_event;
  ice_aqc_lan_overflow_event_t lan_overflow_event;
  ice_aqc_health_status_config_t health_status_config;
  ice_aqc_health_status_event_t health_status_event;
  ice_aqc_fw_log_event_t fw_log_event;
  ice_aqc_nvm_event_t nvm_event;
  ice_aqc_pf_vf_msg_t pf_vf_msg;
  struct
  {
    u16 num_entries;
    u8 reserved[6];
    u32 addr_high;
    u32 addr_low;
  } alloc_free_resources;
  struct
  {
    u8 reserved[8];
    u32 addr_high;
    u32 addr_low;
  } indirect;
  struct
  {
    u8 driver_unloading;
    u8 reserved[15];
  } q_shutdown;
  struct
  {
    u32 rom_ver;
    u32 fw_build;
    u8 fw_branch, fw_major, fw_minor, fw_patch;
    u8 api_branch, api_major, api_minor, api_patch;
  } get_version;
  struct
  {
    u8 major;
    u8 minor;
    u8 build;
    u8 subbuild;
    u8 _reserved[12];
  } driver_version;
  struct
  {
    u8 cmd_flags;
    u8 pf_index;
    u8 reserved[2];
    u32 count;
    u32 addr_high;
    u32 addr_low;
  } list_caps;
  struct
  {
    u16 flags;
    u8 reserved[2];
    u8 num_addr;
    u8 reserved1[3];
    u32 addr_high;
    u32 addr_low;
  } mac_read;
  struct
  {
    u8 rx_count;
    u8 reserved[15];
  } clear_pxe;
  struct
  {
    u16 flags;
    u16 element;
    u16 num_elems;
    u16 reserved;
    u32 addr_high;
    u32 addr_low;
  } sw_cfg;
  struct
  {
    union
    {
      struct
      {
	u16 number : 10;
	u16 _reserved_10_14 : 5;
	u16 valid : 1;
      };
      u16 as_u16;
    } vsi_num;
    u16 cmd_flags;
    u8 vf_id;
    u8 reserved;
    union
    {
      struct
      {
	u16 type : 2;
	u16 _reserved : 14;
      };
      u16 as_u16;
    } vsi_flags;
    u32 addr_high;
    u32 addr_low;
  } vsi;
  struct
  {
    u16 num_rules;
    u8 reserved[6];
    u32 addr_high;
    u32 addr_low;
  } sw_rules;
  struct
  {
    u8 port_num;
    u8 num_branches;
    u16 reserved;
    u32 reserved1;
    u32 addr_high;
    u32 addr_low;
  } topology;
  struct
  {
    u8 lport_num;
    u8 reserved;
    u16 cmd_flags;
    u32 reserved1;
    u32 addr_high;
    u32 addr_low;
  } link_status;
  struct
  {
    u8 lport_num;
    u8 reserved[7];
    u16 event_mask;
    u8 reserved1[6];
  } event_mask;
  struct
  {
    u8 lport_num;
    u8 reserved;
    u16 report_mode;
    u32 reserved1;
    u32 addr_high;
    u32 addr_low;
  } phy_caps;
  struct
  {
    u16 max_frame_size;
    u8 params;
    u8 tx_tmr_priority;
    u16 tx_tmr_value;
    u16 fc_refresh_threshold;
    u8 drop_opts;
    u8 reserved[7];
  } set_mac_cfg;
  struct
  {
    u8 lport_num;
    u8 lport_num_valid;
    u8 count : 4;
    u8 _reserved_count : 4;
    u8 innermost_phy_index;
    struct
    {
      u8 index : 4;
      u8 _reserved : 2;
      u8 forced : 1;
      u8 valid : 1;
    } active;
    struct
    {
      u8 index : 4;
      u8 _reserved : 3;
      u8 valid : 1;
    } pending;
    u8 reserved[2];
    u32 addr_high;
    u32 addr_low;
  } port_options;
  struct
  {
    u8 sensor;
    u8 format;
    u8 reserved[6];
    u32 addr_high;
    u32 addr_low;
  } get_sensor_reading;
  ice_aqc_sensor_reading_t sensor_reading;
  ice_aqc_sff_eeprom_t sff_eeprom;
  struct
  {
    u8 num_qgrps;
    u8 reserved[3];
    u32 reserved1;
    u32 addr_high;
    u32 addr_low;
  } add_txqs;
  struct
  {
    ice_aq_q_dis_cmd_t command_type;
    u8 num_entries;
    ice_aq_q_dis_vmvf_timeout_t vmvf_and_timeout;
    u32 blocked_cgds;
    u32 addr_high;
    u32 addr_low;
  } disable_txqs;
  struct
  {
    ice_aq_rss_vsi_id_t vsi_id;
    u8 reserved[6];
    u32 addr_high;
    u32 addr_low;
  } rss_key;
  struct
  {
    ice_aq_rss_vsi_id_t vsi_id;
    ice_aq_rss_lut_flags_t flags;
    u32 reserved;
    u32 addr_high;
    u32 addr_low;
  } rss_lut;
  ice_aq_resource_params_t resource;
  struct
  {
    ice_aq_update_pkg_flags_t flags;
    u8 reserved[7];
    u32 addr_high;
    u32 addr_low;
  } update_pkg;
} ice_aq_params_t;

STATIC_ASSERT_SIZEOF (ice_aq_params_t, 16);

typedef struct
{
  ice_aq_desc_flags_t flags;
  u16 opcode;
  u16 datalen;
  u16 retval;
  u32 cookie_high;
  u32 cookie_low;
  ice_aq_params_t params;
} ice_aq_desc_t;

STATIC_ASSERT_SIZEOF (ice_aq_desc_t, 32);

#define foreach_ice_adminq_opcode                                                                  \
  _ (0x0001, GET_VER)                                                                              \
  _ (0x0002, DRIVER_VER)                                                                           \
  _ (0x0003, Q_SHUTDOWN)                                                                           \
  _ (0x0008, REQUEST_RESOURCE)                                                                     \
  _ (0x0009, RELEASE_RESOURCE)                                                                     \
  _ (0x000a, LIST_FUNC_CAPS)                                                                       \
  _ (0x000b, LIST_DEV_CAPS)                                                                        \
  _ (0x0107, MANAGE_MAC_READ)                                                                      \
  _ (0x0110, CLEAR_PXE)                                                                            \
  _ (0x0200, GET_SW_CFG)                                                                           \
  _ (0x0208, ALLOC_RESOURCES)                                                                      \
  _ (0x0209, FREE_RESOURCES)                                                                       \
  _ (0x0210, ADD_VSI)                                                                              \
  _ (0x0211, UPDATE_VSI)                                                                           \
  _ (0x0212, GET_VSI)                                                                              \
  _ (0x0213, FREE_VSI)                                                                             \
  _ (0x02a0, ADD_SW_RULES)                                                                         \
  _ (0x02a2, REMOVE_SW_RULES)                                                                      \
  _ (0x02a4, CLEAR_PF_CFG)                                                                         \
  _ (0x0400, GET_DFLT_TOPO)                                                                        \
  _ (0x0600, GET_PHY_CAPS)                                                                         \
  _ (0x0601, SET_PHY_CFG)                                                                          \
  _ (0x0603, SET_MAC_CFG)                                                                          \
  _ (0x0607, GET_LINK_STATUS)                                                                      \
  _ (0x0613, SET_EVENT_MASK)                                                                       \
  _ (0x0632, GET_SENSOR_READING)                                                                   \
  _ (0x06ea, GET_PORT_OPTIONS)                                                                     \
  _ (0x06ee, SFF_EEPROM)                                                                           \
  _ (0x0702, NVM_ERASE)                                                                            \
  _ (0x0703, NVM_WRITE)                                                                            \
  _ (0x0707, NVM_WRITE_ACTIVATE)                                                                   \
  _ (0x0801, SEND_MSG_TO_PF)                                                                       \
  _ (0x0802, SEND_MSG_TO_VF)                                                                       \
  _ (0x0a01, LLDP_MIB_CHANGE)                                                                      \
  _ (0x0b02, SET_RSS_KEY)                                                                          \
  _ (0x0b03, SET_RSS_LUT)                                                                          \
  _ (0x0b04, GET_RSS_KEY)                                                                          \
  _ (0x0b05, GET_RSS_LUT)                                                                          \
  _ (0x0c30, ADD_TXQS)                                                                             \
  _ (0x0c31, DIS_TXQS)                                                                             \
  _ (0x0c41, UPLOAD_SECTION)                                                                       \
  _ (0x0c42, UPDATE_PACKAGE)                                                                       \
  _ (0x0c43, GET_PKG_INFO_LIST)                                                                    \
  _ (0x0c60, EVENT_CGU_ERROR)                                                                      \
  _ (0x1001, EVENT_LAN_OVERFLOW)                                                                   \
  _ (0xff20, SET_HEALTH_STATUS_CONFIG)                                                             \
  _ (0xff22, HEALTH_STATUS_EVENT)                                                                  \
  _ (0xff33, FW_LOG_EVENT)

typedef enum
{
#define _(v, n) ICE_AQC_OP_##n = (v),
  foreach_ice_adminq_opcode
#undef _
} ice_aq_opcode_t;

#define foreach_ice_aq_rc                                                                          \
  _ (0, OK)                                                                                        \
  _ (1, EPERM)                                                                                     \
  _ (2, ENOENT)                                                                                    \
  _ (3, ESRCH)                                                                                     \
  _ (4, EINTR)                                                                                     \
  _ (5, EIO)                                                                                       \
  _ (6, ENXIO)                                                                                     \
  _ (7, E2BIG)                                                                                     \
  _ (8, EAGAIN)                                                                                    \
  _ (9, ENOMEM)                                                                                    \
  _ (10, EACCES)                                                                                   \
  _ (11, EFAULT)                                                                                   \
  _ (12, EBUSY)                                                                                    \
  _ (13, EEXIST)                                                                                   \
  _ (14, EINVAL)                                                                                   \
  _ (15, ENOTTY)                                                                                   \
  _ (16, ENOSPC)                                                                                   \
  _ (17, ENOSYS)                                                                                   \
  _ (18, ERANGE)                                                                                   \
  _ (19, EFLUSHED)                                                                                 \
  _ (20, BAD_ADDR)                                                                                 \
  _ (21, EMODE)                                                                                    \
  _ (22, EFBIG)                                                                                    \
  _ (23, ESBCOMP)                                                                                  \
  _ (24, ENOSEC)                                                                                   \
  _ (25, EBADSIG)                                                                                  \
  _ (26, ESVN)                                                                                     \
  _ (27, EBADMAN)                                                                                  \
  _ (28, EBADBUF)                                                                                  \
  _ (29, EACCES_BMCU)

typedef enum
{
#define _(v, n) ICE_AQ_RC_##n = v,
  foreach_ice_aq_rc
#undef _
} ice_aq_rc_t;

enum
{
  ICE_RSS_KEY_SIZE = 40,
  ICE_RSS_EXT_KEY_SIZE = 12,
  ICE_RSS_LUT_SIZE = 64,
  ICE_RSS_MAX_QUEUES = ICE_RSS_LUT_SIZE,
};

typedef struct
{
  u8 standard_key[ICE_RSS_KEY_SIZE];
  u8 extended_key[ICE_RSS_EXT_KEY_SIZE];
} ice_aq_rss_key_t;

STATIC_ASSERT_SIZEOF (ice_aq_rss_key_t, 52);

typedef struct
{
  u8 entries[ICE_RSS_LUT_SIZE];
} ice_aq_rss_lut_t;

STATIC_ASSERT_SIZEOF (ice_aq_rss_lut_t, 64);

/* Package buffer section directory. */
typedef struct
{
  u16 index_table_size;
  u16 data_end;
  u32 section_type;
  u16 section_offset;
  u16 section_size;
} ice_pkg_buf_hdr_t;

STATIC_ASSERT_SIZEOF (ice_pkg_buf_hdr_t, 12);

#define ICE_VSIG_GROUP_BITS 13
#define ICE_VSIG_PF_BITS    3

typedef union
{
  struct
  {
    u16 group : ICE_VSIG_GROUP_BITS;
    u16 pf : ICE_VSIG_PF_BITS;
  };
  u16 as_u16;
} ice_vsig_t;

typedef struct
{
  u16 count;
  u16 offset;
  u16 value;
} ice_pkg_xlt2_entry_t;

STATIC_ASSERT_SIZEOF (ice_pkg_xlt2_entry_t, 6);

/* Profile package sections. */
#define ICE_PROFILE_PTG_COUNT		256
#define ICE_PROFILE_FV_OFFSET_UNUSED	511
#define ICE_PROFILE_FV_INDEX_DEFAULT	31
#define ICE_PROFILE_MASK_COUNT		32
#define ICE_PROFILE_TC_OVERRIDE_COUNT	32
#define ICE_PROFILE_FLAG_SELECTOR_START 38
#define ICE_PROFILE_FLAG_SELECTOR_BITS	9
#define ICE_PROFILE_FLAG_MASK_INDEX	15
#define ICE_PROFILE_METADATA_WORD_BITS	16
#define ICE_PROFILE_PACKET_FLAG_COUNT	64

enum
{
  ICE_METADATA_PACKET_DROP = 128,
  ICE_METADATA_MANAGEMENT_VSI = 172,
  ICE_METADATA_PACKET_FLAGS = 320,
};

#define ICE_PROFILE_FV_WORDS	24
#define ICE_PROFILE_PTYPE_COUNT 1024
#define ICE_PROFILE_VSI_COUNT	768
#define ICE_PROFILE_TCAM_COUNT	512
#define ICE_PROFILE_COUNT	128

enum
{
  ICE_RES_RSS_PROFILE = 0x60,
  ICE_RES_RSS_TCAM = 0x61,
};

enum
{
  ICE_PTYPE_IPV4_FRAG = 22,
  ICE_PTYPE_IPV4_PAYLOAD = 23,
  ICE_PTYPE_IPV4_UDP = 24,
  ICE_PTYPE_IPV4_TCP = 26,
  ICE_PTYPE_IPV4_SCTP = 27,
  ICE_PTYPE_IPV4_ICMP = 28,
  ICE_PTYPE_IPV6_FRAG = 88,
  ICE_PTYPE_IPV6_PAYLOAD = 89,
  ICE_PTYPE_IPV6_UDP = 90,
  ICE_PTYPE_IPV6_TCP = 92,
  ICE_PTYPE_IPV6_SCTP = 93,
  ICE_PTYPE_IPV6_ICMP = 94,
};

/* Protocol IDs identify parser header instances, not IP protocol numbers. */
enum
{
  ICE_PROT_IPV4_OUTER = 32,
  ICE_PROT_IPV6_OUTER = 40,
  ICE_PROT_TCP_INNER = 49,
  ICE_PROT_UDP_INNER = 53,
  ICE_PROT_SCTP_INNER = 96,
  ICE_PROT_UNUSED = 255,
};

#define foreach_ice_protocol_id                                                                    \
  _ (0, "invalid")                                                                                 \
  _ (1, "MAC (outer/first or single)")                                                             \
  _ (2, "MAC (second outer)")                                                                      \
  _ (4, "MAC (inner/last)")                                                                        \
  _ (7, "MAC-in-MAC")                                                                              \
  _ (9, "EtherType (outer/last)")                                                                  \
  _ (10, "EtherType (inner/last)")                                                                 \
  _ (15, "payload")                                                                                \
  _ (16, "VLAN (outer/first)")                                                                     \
  _ (17, "VLAN (outer/last)")                                                                      \
  _ (18, "VLAN (inner/first)")                                                                     \
  _ (27, "MPLS (before outer/last)")                                                               \
  _ (28, "MPLS (outer/last or single)")                                                            \
  _ (29, "MPLS (inner/last)")                                                                      \
  _ (32, "IPv4 (outer/first or single)")                                                           \
  _ (33, "IPv4 (inner/last)")                                                                      \
  _ (34, "IPv4 (second inner/last)")                                                               \
  _ (40, "IPv6 (outer/first or single)")                                                           \
  _ (41, "IPv6 (inner/last)")                                                                      \
  _ (42, "IPv6 (second inner/last)")                                                               \
  _ (43, "IPv6 next protocol")                                                                     \
  _ (47, "IPv6 fragment")                                                                          \
  _ (49, "TCP (inner/last)")                                                                       \
  _ (52, "UDP (outer/first)")                                                                      \
  _ (53, "UDP (inner/last or single)")                                                             \
  _ (64, "GRE (outer/first)")                                                                      \
  _ (84, "NSH (first)")                                                                            \
  _ (88, "ESP (first)")                                                                            \
  _ (89, "AH / second ESP")                                                                        \
  _ (96, "SCTP (inner/last)")                                                                      \
  _ (98, "ICMP (inner/last)")                                                                      \
  _ (100, "ICMPv6 (inner/last)")                                                                   \
  _ (101, "VRRP (first)")                                                                          \
  _ (102, "OSPF")                                                                                  \
  _ (103, "PPPoE")                                                                                 \
  _ (104, "L2TPv3")                                                                                \
  _ (105, "eCPRI")                                                                                 \
  _ (106, "PPP")                                                                                   \
  _ (114, "ATA over Ethernet (outer/first)")                                                       \
  _ (116, "control (outer/first)")                                                                 \
  _ (117, "LLDP (outer/first)")                                                                    \
  _ (118, "ARP (outer/first)")                                                                     \
  _ (120, "EAPOL (outer/first)")                                                                   \
  _ (255, "metadata / unused")

typedef struct
{
  u8 protocol;
  u16 offset;
  u8 reserved;
} __clib_packed ice_profile_fv_t;

#define ICE_PROFILE_KEY_FLAGS_START    0
#define ICE_PROFILE_KEY_FLAGS_BITS     16
#define ICE_PROFILE_KEY_PTG_START      16
#define ICE_PROFILE_KEY_PTG_BITS       8
#define ICE_PROFILE_KEY_VSIG_START     24
#define ICE_PROFILE_KEY_PF_START       37
#define ICE_PROFILE_KEY_BYTES	       5
#define ICE_PROFILE_KEY_DISABLED_FLAGS 0xfffe

typedef union
{
  struct
  {
    u16 flags;
    u8 ptg;
    ice_vsig_t vsig;
  } __clib_packed;
  u8 as_u8[ICE_PROFILE_KEY_BYTES];
} __clib_packed ice_profile_key_t;

typedef struct
{
  u16 address;
  union
  {
    struct
    {
      ice_profile_key_t zero, one;
    };
    u8 key[2 * ICE_PROFILE_KEY_BYTES];
  };
  u8 profile;
} __clib_packed ice_profile_tcam_t;

STATIC_ASSERT_SIZEOF (ice_vsig_t, 2);
STATIC_ASSERT_SIZEOF (ice_profile_key_t, ICE_PROFILE_KEY_BYTES);

typedef struct
{
  u8 xlt1_partition_mode;
  u8 xlt2_partition_mode;
  u8 profile_partition_mode;
  u8 reserved;
  u32 flag15_mask[2];
  u8 entries[8][24];
} __clib_packed ice_profile_key_builder_t;

STATIC_ASSERT_SIZEOF (ice_profile_key_builder_t, 204);

typedef struct
{
  u16 count, offset;
  ice_profile_fv_t words[ICE_PROFILE_FV_WORDS];
} __clib_packed ice_profile_fv_section_t;

typedef struct
{
  union
  {
    struct
    {
      u16 type_id : 7;
      u16 shared : 1;
      u16 _reserved_8_11 : 4;
      u16 scan_bottom : 1;
      u16 ignore_index : 1;
      u16 _reserved_14_15 : 2;
    };
    u16 type;
  };
  u16 count, index;
} ice_aqc_resource_t;

STATIC_ASSERT_SIZEOF (ice_aqc_resource_t, 6);

typedef struct
{
  u16 count, offset;
  u8 values[ICE_PROFILE_PTYPE_COUNT];
} ice_profile_xlt1_section_t;

typedef struct
{
  u16 count, offset, values[ICE_PROFILE_VSI_COUNT];
} ice_profile_xlt2_section_t;

typedef struct
{
  u16 count;
  ice_profile_tcam_t entries[128];
} __clib_packed ice_profile_tcam_block_t;

typedef struct
{
  u16 count;
  ice_profile_tcam_t entry;
} __clib_packed ice_profile_tcam_entry_section_t;

STATIC_ASSERT_SIZEOF (ice_profile_fv_t, 4);
STATIC_ASSERT_SIZEOF (ice_profile_tcam_t, 13);
STATIC_ASSERT_SIZEOF (ice_profile_fv_section_t, 100);
STATIC_ASSERT_SIZEOF (ice_profile_xlt1_section_t, 1028);
STATIC_ASSERT_SIZEOF (ice_profile_xlt2_section_t, 1540);
STATIC_ASSERT_SIZEOF (ice_profile_tcam_block_t, 1666);
STATIC_ASSERT_SIZEOF (ice_profile_tcam_entry_section_t, 15);

/* Device capability and DDP package response data */
typedef struct
{
  u16 cap;
  u8 major_ver;
  u8 minor_ver;
  u32 number;
  u32 logical_id;
  u32 phys_id;
  u64 reserved[2];
} ice_aqc_list_caps_elem_t;

STATIC_ASSERT_SIZEOF (ice_aqc_list_caps_elem_t, 32);

#define foreach_ice_aqc_capability                                                                 \
  _ (0x0001, SWITCHING_MODE)                                                                       \
  _ (0x0002, MANAGEABILITY_MODE)                                                                   \
  _ (0x0004, OS2BMC)                                                                               \
  _ (0x0005, VALID_FUNCTIONS)                                                                      \
  _ (0x0006, ALTERNATE_RAM)                                                                        \
  _ (0x0008, WOL_PROXY)                                                                            \
  _ (0x0012, SRIOV)                                                                                \
  _ (0x0013, VF)                                                                                   \
  _ (0x0014, VMDQ)                                                                                 \
  _ (0x0015, IEEE_802_1QBG)                                                                        \
  _ (0x0016, IEEE_802_1BR)                                                                         \
  _ (0x0017, VSI)                                                                                  \
  _ (0x0018, DCB)                                                                                  \
  _ (0x0021, RESERVED)                                                                             \
  _ (0x0022, ISCSI)                                                                                \
  _ (0x0040, RSS)                                                                                  \
  _ (0x0041, RXQS)                                                                                 \
  _ (0x0042, TXQS)                                                                                 \
  _ (0x0043, MSIX)                                                                                 \
  _ (0x0045, FD)                                                                                   \
  _ (0x0046, IEEE_1588)                                                                            \
  _ (0x0047, MAX_MTU)                                                                              \
  _ (0x0048, NVM_VER)                                                                              \
  _ (0x0049, PENDING_NVM_VER)                                                                      \
  _ (0x004a, OROM_VER)                                                                             \
  _ (0x004b, PENDING_OROM_VER)                                                                     \
  _ (0x004c, NET_VER)                                                                              \
  _ (0x004d, PENDING_NET_VER)                                                                      \
  _ (0x0051, IWARP)                                                                                \
  _ (0x0061, LED)                                                                                  \
  _ (0x0062, SDP)                                                                                  \
  _ (0x0064, WR_CSR_PROT)                                                                          \
  _ (0x0067, SENSOR_READING)                                                                       \
  _ (0x0073, LOGICAL_TO_PHYSICAL_PORT_MAP)                                                         \
  _ (0x0074, SKU)                                                                                  \
  _ (0x0075, PORT_MAP)                                                                             \
  _ (0x0076, PCIE_RESET_AVOIDANCE)                                                                 \
  _ (0x0077, POST_UPDATE_RESET_RESTRICT)                                                           \
  _ (0x0080, NVM_MGMT)                                                                             \
  _ (0x0081, EXT_TOPO_DEV_IMG0)                                                                    \
  _ (0x0082, EXT_TOPO_DEV_IMG1)                                                                    \
  _ (0x0083, EXT_TOPO_DEV_IMG2)                                                                    \
  _ (0x0084, EXT_TOPO_DEV_IMG3)                                                                    \
  _ (0x0085, TX_SCHED_TOPO_COMP_MODE)                                                              \
  _ (0x0087, NAC_TOPOLOGY)                                                                         \
  _ (0x008a, DYNAMIC_FLATTENING)                                                                   \
  _ (0x0090, OROM_RECOVERY_UPDATE)                                                                 \
  _ (0x0092, FW_LAG_SUPPORT)                                                                       \
  _ (0x0096, NEXT_CLUSTER_ID)                                                                      \
  _ (0x00f2, CEM)

typedef enum
{
#define _(v, n) ICE_AQC_CAPS_##n = (v),
  foreach_ice_aqc_capability
#undef _
} ice_aqc_capability_t;

#define ICE_SR_NVM_DEV_STARTER_VER 0x0018

typedef union
{
  struct
  {
    u32 word_address : 16;
    u32 value : 16;
  };
  u32 as_u32;
} ice_aqc_nvm_cap_word_t;

typedef union
{
  struct
  {
    u16 minor : 8;
    u16 _reserved_8_11 : 4;
    u16 major : 4;
  };
  u16 as_u16;
} ice_nvm_ver_t;

typedef struct
{
  u8 major;
  u8 minor;
  u8 update;
  u8 draft;
} ice_pkg_ver_t;

typedef struct
{
  ice_pkg_ver_t ver;
  u8 name[28];
  u32 track_id;
  u8 is_in_nvm;
  u8 is_active;
  u8 is_active_at_boot;
  u8 is_modified;
} ice_aqc_pkg_info_t;

STATIC_ASSERT_SIZEOF (ice_aqc_pkg_info_t, 40);

#define ICE_DDP_PKG_COUNT 4

typedef struct
{
  u32 count;
  ice_aqc_pkg_info_t pkg_info[ICE_DDP_PKG_COUNT];
} ice_aqc_pkg_info_resp_t;

STATIC_ASSERT_SIZEOF (ice_aqc_pkg_info_resp_t, 164);

/* Switch, MAC and VSI command data */
typedef struct
{
  union
  {
    struct
    {
      u16 number : 10;
      u16 _reserved : 4;
      u16 type : 2;
    };
    u16 as_u16;
  } vsi_port;
  u16 swid;
  u16 pf_vf_num;
} __clib_packed ice_aqc_sw_cfg_elem_t;

STATIC_ASSERT_SIZEOF (ice_aqc_sw_cfg_elem_t, 6);

#define ICE_AQC_SW_CFG_PHYS_PORT 0

typedef struct
{
  u8 lport_num;
  u8 addr_type;
  u8 mac_addr[6];
} ice_aqc_mac_read_resp_t;

STATIC_ASSERT_SIZEOF (ice_aqc_mac_read_resp_t, 8);

#define ICE_AQC_MAC_ADDR_TYPE_LAN 0

typedef union
{
  struct
  {
    u16 noncontiguous : 1;
    u16 _reserved : 15;
  };
  u16 as_u16;
} ice_aq_vsi_q_mapping_flags_t;

typedef union
{
  struct
  {
    u16 queue_offset : 11;
    u16 queue_count_log2 : 4;
    u16 _reserved : 1;
  };
  u16 as_u16;
} ice_aq_vsi_tc_mapping_t;

typedef union
{
  struct
  {
    u8 lut_type : 2;
    u8 global_lut_index : 4;
    u8 hash_type : 2;
  };
  u8 as_u8;
} ice_aq_vsi_q_opt_rss_t;

typedef union
{
  struct
  {
    u8 _reserved_0_4 : 5;
    u8 allow_loopback : 1;
    u8 local_loopback : 1;
    u8 source_prune : 1;
  };
  u8 as_u8;
} ice_aq_vsi_sw_flags_t;

typedef union
{
  struct
  {
    u8 allow_dest_override : 1;
    u8 _reserved_1 : 1;
    u8 mac_anti_spoof : 1;
    u8 _reserved_3 : 1;
    u8 tx_vlan_prune : 4;
  };
  u8 as_u8;
} ice_aq_vsi_sec_flags_t;

enum
{
  ICE_VSI_VLAN_TX_ACCEPT_UNTAGGED = 1,
  ICE_VSI_VLAN_TX_ACCEPT_TAGGED = 2,
  ICE_VSI_VLAN_TX_ACCEPT_ALL = 3,
};

enum
{
  ICE_VSI_VLAN_EGRESS_STRIP_BOTH = 0,
  ICE_VSI_VLAN_EGRESS_STRIP_PRIORITY = 1,
  ICE_VSI_VLAN_EGRESS_STRIP = 2,
  ICE_VSI_VLAN_EGRESS_KEEP = 3,
};

typedef union
{
  struct
  {
    u8 tx_mode : 2;
    u8 insert_pvid : 1;
    u8 egress_mode : 2;
    u8 block_tx_descriptor : 1;
    u8 _reserved_6_7 : 2;
  };
  u8 as_u8;
} ice_aq_vsi_inner_vlan_flags_t;

typedef struct
{
  union
  {
    struct
    {
      u16 switch_section : 1;
      u16 security_section : 1;
      u16 vlan_section : 1;
      u16 outer_tag_section : 1;
      u16 ingress_up_section : 1;
      u16 egress_up_section : 1;
      u16 rxq_map_section : 1;
      u16 queue_option_section : 1;
      u16 outer_up_section : 1;
      u16 _reserved_9 : 1;
      u16 acl_section : 1;
      u16 flow_director_section : 1;
      u16 pasid_section : 1;
      u16 _reserved_13_15 : 3;
    };
    u16 as_u16;
  } valid_sections;
  u8 sw_id;
  ice_aq_vsi_sw_flags_t sw_flags;
  union
  {
    struct
    {
      u8 rx_vlan_prune : 1;
      u8 _reserved_1_2 : 2;
      u8 rx_pass_prune : 1;
      u8 lan_enable : 1;
      u8 _reserved_5_7 : 3;
    };
    u8 as_u8;
  } sw_flags2;
  u8 veb_stat_id;
  ice_aq_vsi_sec_flags_t sec_flags;
  u8 sec_reserved;
  u16 port_based_inner_vlan;
  u8 inner_vlan_reserved[2];
  ice_aq_vsi_inner_vlan_flags_t inner_vlan_flags;
  u8 inner_vlan_reserved2[3];
  u32 ingress_table;
  u32 egress_table;
  u16 port_based_outer_vlan;
  u8 outer_vlan_flags;
  u8 outer_vlan_reserved;
  ice_aq_vsi_q_mapping_flags_t mapping_flags;
  u16 q_mapping[16];
  ice_aq_vsi_tc_mapping_t tc_mapping[8];
  ice_aq_vsi_q_opt_rss_t q_opt_rss;
  u8 q_opt_tc;
  u8 q_opt_flags;
  u8 q_opt_reserved[3];
  u32 outer_up_table;
  u16 acl_def_act;
  u16 fd_options;
  u16 max_fd_fltr_dedicated;
  u16 max_fd_fltr_shared;
  u16 fd_def_q;
  u16 fd_report_opt;
  u32 pasid_id;
  u8 reserved[24];
} ice_aqc_vsi_props_t;

STATIC_ASSERT_SIZEOF (ice_aqc_vsi_props_t, 128);

typedef enum
{
  ICE_AQ_VSI_TYPE_VF = 0,
  ICE_AQ_VSI_TYPE_VMDQ2 = 1,
  ICE_AQ_VSI_TYPE_PF = 2,
  ICE_AQ_VSI_TYPE_EMP = 3,
} ice_aq_vsi_type_t;

typedef struct
{
  u16 type;
  u16 status;
  u16 recipe_id;
  u16 src;
  u32 act;
  u16 index;
  u16 hdr_len;
  u8 hdr_data[16];
} ice_sw_rule_t;

STATIC_ASSERT_SIZEOF (ice_sw_rule_t, 32);

typedef struct
{
  u16 type;
  u16 status;
  u16 recipe_id;
  u16 src;
  u32 act;
  u16 index;
  u16 hdr_len;
} ice_sw_rule_remove_t;

STATIC_ASSERT_SIZEOF (ice_sw_rule_remove_t, 16);

#define foreach_ice_aqc_sw_rule_type                                                               \
  _ (0, LKUP_RX)                                                                                   \
  _ (1, LKUP_TX)                                                                                   \
  _ (2, LARGE_ACTION)                                                                              \
  _ (3, VSI_LIST_SET)                                                                              \
  _ (4, VSI_LIST_CLEAR)                                                                            \
  _ (5, PRUNE_LIST_SET)                                                                            \
  _ (6, PRUNE_LIST_CLEAR)

typedef enum
{
#define _(v, n) ICE_AQC_SW_RULE_##n = (v),
  foreach_ice_aqc_sw_rule_type
#undef _
} ice_aqc_sw_rule_type_t;

#define foreach_ice_sw_lkup_type                                                                   \
  _ (0, ETHERTYPE)                                                                                 \
  _ (1, MAC)                                                                                       \
  _ (2, MAC_VLAN)                                                                                  \
  _ (3, PROMISC)                                                                                   \
  _ (4, VLAN)                                                                                      \
  _ (5, DEFAULT)                                                                                   \
  _ (8, ETHERTYPE_MAC)                                                                             \
  _ (9, PROMISC_VLAN)

typedef enum
{
#define _(v, n) ICE_SW_LKUP_##n = (v),
  foreach_ice_sw_lkup_type
#undef _
} ice_sw_lkup_type_t;

typedef union
{
  struct
  {
    u32 action_type : 2;
    u32 loopback_enable : 1;
    u32 lan_enable : 1;
    u32 vsi_id : 10;
    u32 vsi_list : 1;
    u32 _reserved_15_16 : 2;
    u32 valid : 1;
    u32 drop : 1;
    u32 _reserved_19_31 : 13;
  };
  u32 as_u32;
} ice_sw_rule_action_t;

/* Scheduler and TX queue command data */
typedef struct
{
  u16 bw_profile_idx;
  u16 bw_alloc;
} ice_aqc_elem_bw_t;

typedef struct
{
  u8 elem_type;
  union
  {
    struct
    {
      u8 generic : 1;
      u8 cir : 1;
      u8 eir : 1;
      u8 _reserved : 5;
    };
    u8 as_u8;
  } valid_sections;
  u8 generic;
  u8 flags;
  ice_aqc_elem_bw_t cir_bw;
  ice_aqc_elem_bw_t eir_bw;
  u16 srl_id;
  u16 reserved;
} ice_aqc_sched_elem_t;

STATIC_ASSERT_SIZEOF (ice_aqc_sched_elem_t, 16);

typedef enum
{
  ICE_AQC_SCHED_ELEM_UNDEFINED = 0,
  ICE_AQC_SCHED_ELEM_ROOT_PORT = 1,
  ICE_AQC_SCHED_ELEM_TC = 2,
  ICE_AQC_SCHED_ELEM_GENERIC = 3,
  ICE_AQC_SCHED_ELEM_ENTRY_POINT = 4,
  ICE_AQC_SCHED_ELEM_LEAF = 5,
  ICE_AQC_SCHED_ELEM_PADDED = 6,
} ice_aqc_sched_elem_type_t;

typedef struct
{
  u32 parent_teid;
  u32 node_teid;
  ice_aqc_sched_elem_t data;
} ice_aqc_sched_elem_data_t;

typedef struct
{
  u32 parent_teid;
  u16 num_elems;
  u16 reserved;
  ice_aqc_sched_elem_data_t elem[9];
} ice_aqc_topo_branch_t;

STATIC_ASSERT_SIZEOF (ice_aqc_topo_branch_t, 224);

typedef struct
{
  u16 txq_id;
  u8 reserved[2];
  u32 q_teid;
  u8 txq_ctx[22];
  u8 reserved1[2];
  ice_aqc_sched_elem_t info;
} ice_aqc_add_txq_t;

STATIC_ASSERT_SIZEOF (ice_aqc_add_txq_t, 48);

typedef struct
{
  u32 parent_teid;
  u8 num_txqs;
  u8 reserved[3];
  ice_aqc_add_txq_t txq;
} ice_aqc_add_txq_group_t;

STATIC_ASSERT_SIZEOF (ice_aqc_add_txq_group_t, 56);

typedef struct
{
  u32 parent_teid;
  u8 num_queues;
  u8 reserved;
  u16 queue_id;
} __clib_packed ice_aqc_dis_txq_item_t;

STATIC_ASSERT_SIZEOF (ice_aqc_dis_txq_item_t, 8);

/* LAN queue context data */
typedef union
{
  struct
  {
    u64 head : 13;
    u64 cpuid : 8;
    u64 _reserved_21_31 : 11;
    u64 base : 57;
    u64 qlen : 13;
    u64 dbuf : 7;
    u64 hbuf : 5;
    u64 dtype : 2;
    u64 dsize : 1;
    u64 crcstrip : 1;
    u64 _reserved_118 : 1;
    u64 l2tsel : 1;
    u64 hsplit_0 : 4;
    u64 hsplit_1 : 2;
    u64 _reserved_126 : 1;
    u64 showiv : 1;
    u64 _reserved_128_173 : 46;
    u64 rxmax : 14;
    u64 _reserved_188_192 : 5;
    u64 tphrdesc_ena : 1;
    u64 tphwdesc_ena : 1;
    u64 tphdata_ena : 1;
    u64 tphhead_ena : 1;
    u64 _reserved_197 : 1;
    u64 lrxqthresh : 3;
    u64 prefena : 1;
    u64 _reserved_202_255 : 54;
  } __clib_packed;
  u32 as_u32[8];
} ice_rxq_ctx_t;

STATIC_ASSERT_SIZEOF (ice_rxq_ctx_t, 32);

enum
{
  ICE_TXQ_VMVF_TYPE_VF = 0,
  ICE_TXQ_VMVF_TYPE_VMQ = 1,
  ICE_TXQ_VMVF_TYPE_PF = 2,
};

typedef union
{
  struct
  {
    u64 base : 57;
    u64 port_num : 3;
    u64 cgd_num : 5;
    u64 pf_num : 3;
    u64 vmvf_num : 10;
    u64 vmvf_type : 2;
    u64 src_vsi : 10;
    u64 tsyn_ena : 1;
    u64 internal_usage_flag : 1;
    u64 alt_vlan : 1;
    u64 cpuid : 8;
    u64 wb_mode : 1;
    u64 tphrd_desc : 1;
    u64 tphrd : 1;
    u64 tphwr_desc : 1;
    u64 cmpq_id : 9;
    u64 qnum_in_func : 14;
    u64 itr_notification_mode : 1;
    u64 adjust_prof_id : 6;
    u64 qlen : 13;
    u64 quanta_prof_idx : 4;
    u64 tso_ena : 1;
    u64 tso_qnum : 11;
    u64 legacy_int : 1;
    u64 drop_ena : 1;
    u64 cache_prof_idx : 2;
    u64 pkt_shaper_prof_idx : 3;
    u64 _reserved_171 : 1;
    u64 gsc_ena : 1;
    u64 _reserved_173_175 : 3;
  } __clib_packed;
  u8 as_u8[22];
} ice_txq_ctx_t;

STATIC_ASSERT_SIZEOF (ice_txq_ctx_t, 22);

/* LAN descriptor layouts */
#define ICE_RX_PACKET_LENGTH_MASK 0x3fff
#define ICE_RX_STATUS_EOP_SHIFT	  1

typedef enum
{
  ICE_RX_DESC_ID_LEGACY_16B = 0,
  ICE_RX_DESC_ID_LEGACY_32B = 1,
  ICE_RX_DESC_ID_FLEX_NIC = 2,
} ice_rx_desc_id_t;

typedef union
{
  struct
  {
    u8 mirror_status : 6;
    u8 unicast_multicast_broadcast : 2;
  };
  u8 as_u8;
} ice_rx_flex_mirror_t;

STATIC_ASSERT_SIZEOF (ice_rx_flex_mirror_t, 1);

typedef union
{
  struct
  {
    u16 packet_type : 10;
    u16 flex_flags : 6;
  };
  u16 as_u16;
} ice_rx_flex_packet_type_t;

STATIC_ASSERT_SIZEOF (ice_rx_flex_packet_type_t, 2);

typedef union
{
  struct
  {
    u16 length : 14;
    u16 _reserved : 2;
  };
  u16 as_u16;
} ice_rx_flex_packet_length_t;

STATIC_ASSERT_SIZEOF (ice_rx_flex_packet_length_t, 2);

typedef union
{
  struct
  {
    u16 length : 11;
    u16 sph : 1;
    u16 flex_flags : 4;
  };
  u16 as_u16;
} ice_rx_flex_header_length_t;

STATIC_ASSERT_SIZEOF (ice_rx_flex_header_length_t, 2);

typedef union
{
  struct
  {
    u16 done : 1;
    u16 end_of_packet : 1;
    u16 header_buffer_overflow : 1;
    u16 l3_l4_parsed : 1;
    u16 ip_error : 1;
    u16 l4_error : 1;
    u16 extended_ip_error : 1;
    u16 external_udp_error : 1;
    u16 loopback : 1;
    u16 ipv6_ext : 1;
    u16 receive_error : 1;
    u16 crc_present : 1;
    u16 rss_valid : 1;
    u16 l2_tag1_present : 1;
    u16 flex_meta0_valid : 1;
    u16 flex_meta1_valid : 1;
  };
  u16 as_u16;
} ice_rx_flex_status_t;

STATIC_ASSERT_SIZEOF (ice_rx_flex_status_t, 2);

typedef union
{
  struct
  {
    u64 pkt_addr, hdr_addr;
  } read;
  struct
  {
    u8 rxdid;
    ice_rx_flex_mirror_t mirror;
    ice_rx_flex_packet_type_t packet_type;
    ice_rx_flex_packet_length_t packet_length;
    ice_rx_flex_header_length_t header_length;
    ice_rx_flex_status_t status;
    u16 l2_tag1;
    u32 rss_hash;
  } wb;
  u64 qword[2];
  u64x2 as_u64x2;
} ice_rx_desc_t;

typedef enum
{
  ICE_TX_DESC_TYPE_DATA = 0,
  ICE_TX_DESC_TYPE_CTX = 1,
  ICE_TX_DESC_TYPE_DONE = 0xf,
} ice_tx_desc_type_t;

#define ICE_TX_BUFFER_SIZE_SHIFT 34
#define ICE_TX_MAC_LENGTH_UNIT	 2
#define ICE_TX_IP_LENGTH_UNIT	 4
#define ICE_TX_L4_LENGTH_UNIT	 4
#define ICE_TX_MAC_LENGTH_MAX	 254

typedef enum
{
  ICE_TX_IP_TYPE_NON_IP = 0,
  ICE_TX_IP_TYPE_IPV6 = 1,
  ICE_TX_IP_TYPE_IPV4 = 2,
  ICE_TX_IP_TYPE_IPV4_CKSUM = 3,
} ice_tx_ip_type_t;

typedef enum
{
  ICE_TX_L4_TYPE_RESERVED = 0,
  ICE_TX_L4_TYPE_TCP = 1,
  ICE_TX_L4_TYPE_SCTP = 2,
  ICE_TX_L4_TYPE_UDP = 3,
} ice_tx_l4_type_t;

#define ICE_TX_DESC_MAX_BUFFER_SIZE (1 << 14)

typedef union
{
  struct
  {
    u64 descriptor_type : 4;
    u64 end_of_packet : 1;
    u64 report_status : 1;
    u64 reserved_command : 1;
    u64 insert_l2_tag : 1;
    u64 dummy : 1;
    u64 ip_type : 2;
    u64 _reserved_11 : 1;
    u64 l4_type : 2;
    u64 request_event : 1;
    u64 _reserved_15 : 1;
    u64 mac_length : 7;
    u64 ip_length : 7;
    u64 l4_length : 4;
    u64 buffer_size : 14;
    u64 l2_tag : 16;
  };
  u64 as_u64;
} ice_tx_cmd_t;

typedef union
{
  vec128_t as_vec128;
  struct
  {
    u64 buf_addr;
    ice_tx_cmd_t cmd;
  };
} ice_tx_desc_t;

typedef union
{
  struct
  {
    u64 descriptor_type : 4;
    u64 tso : 1;
    u64 _reserved_5 : 11;
    u64 _reserved_16 : 14;
    u64 tso_len : 18;
    u64 _reserved_48 : 2;
    u64 mss : 14;
  };
  u64 as_u64;
} ice_tx_ctx_cmd_t;

typedef union
{
  vec128_t as_vec128;
  struct
  {
    u64 tunnel_params;
    ice_tx_ctx_cmd_t cmd;
  };
} ice_tx_ctx_desc_t;

typedef union
{
  vec512_t as_vec512;
  ice_tx_desc_t desc[4];
} ice_tx_desc4_t;

STATIC_ASSERT_SIZEOF (ice_rx_desc_t, 16);
STATIC_ASSERT_SIZEOF (ice_tx_desc_t, 16);
STATIC_ASSERT_SIZEOF (ice_tx_ctx_desc_t, 16);
STATIC_ASSERT_SIZEOF (ice_tx_desc4_t, 64);

/* Link and PHY command data */
typedef struct
{
  union
  {
    struct
    {
      u8 topology_conflict : 1;
      u8 media_conflict : 1;
      u8 topology_corrupt : 1;
      u8 _reserved_3 : 1;
      u8 topology_unreachable : 1;
      u8 topology_underutilized : 1;
      u8 media_underutilized : 1;
      u8 unsupported_media : 1;
    };
    u8 as_u8;
  } topo_media_conflict;
  union
  {
    struct
    {
      u8 config_error : 1;
      u8 _reserved_1 : 1;
      u8 invalid_port_option : 1;
      u8 invalid_feature_or_config : 1;
      u8 critical_sdp_error : 1;
      u8 unsupported_module_power : 1;
      u8 external_phy_load_failure : 1;
      u8 invalid_max_power_limit : 1;
    };
    u8 as_u8;
  } link_cfg_err;
  union
  {
    struct
    {
      u8 link_up : 1;
      u8 link_fault : 1;
      u8 tx_fault : 1;
      u8 rx_fault : 1;
      u8 remote_fault : 1;
      u8 port_link_up : 1;
      u8 media_available : 1;
      u8 signal_detect : 1;
    };
    u8 as_u8;
  } link_info;
  union
  {
    struct
    {
      u8 completed : 1;
      u8 link_partner_ability : 1;
      u8 parallel_detection_fault : 1;
      u8 fec_enabled : 1;
      u8 phy_low_power : 1;
      u8 pause_tx : 1;
      u8 pause_rx : 1;
      u8 qualified_module : 1;
    };
    u8 as_u8;
  } an_info;
  union
  {
    struct
    {
      u8 phy_temperature_alarm : 1;
      u8 excessive_errors : 1;
      u8 tx_state : 2;
      u8 _reserved_4_7 : 4;
    };
    u8 as_u8;
  } ext_info;
  union
  {
    struct
    {
      u8 local_phy : 1;
      u8 remote_phy : 1;
      u8 local_mac : 1;
      u8 phy_index : 3;
      u8 _reserved_6_7 : 2;
    };
    u8 as_u8;
  } lb_status;
  u16 max_frame_size;
  union
  {
    struct
    {
      u8 kr_25g_fec : 1;
      u8 rs_528_fec : 1;
      u8 rs_544_fec : 1;
      u8 pacing : 4;
      u8 fixed_pacing : 1;
    };
    u8 as_u8;
  } cfg;
  union
  {
    struct
    {
      u8 power_class : 6;
      u8 _reserved_6_7 : 2;
    };
    u8 as_u8;
  } power_desc;
  union
  {
    struct
    {
      u16 speed_10m : 1;
      u16 speed_100m : 1;
      u16 speed_1g : 1;
      u16 speed_2_5g : 1;
      u16 speed_5g : 1;
      u16 speed_10g : 1;
      u16 speed_20g : 1;
      u16 speed_25g : 1;
      u16 speed_40g : 1;
      u16 speed_50g : 1;
      u16 speed_100g : 1;
      u16 speed_200g : 1;
      u16 _reserved_12_14 : 3;
      u16 unknown : 1;
    };
    u16 as_u16;
  } link_speed;
  u16 reserved3;
  union
  {
    struct
    {
      u8 rs_272_fec : 1;
      u8 _reserved_1_7 : 7;
    };
    u8 as_u8;
  } ext_fec_status;
  u8 reserved4;
  u64 phy_type_low;
  u64 phy_type_high;
  u64 lp_phy_type_low;
  u64 lp_phy_type_high;
  union
  {
    struct
    {
      u8 kr_10g : 1;
      u8 kr_25g : 1;
      u8 rs_528 : 1;
      u8 kr_272_50g : 1;
      u8 kr_272_100g : 1;
      u8 kr_272_200g : 1;
      u8 _reserved_6_7 : 2;
    };
    u8 as_u8;
  } lp_fec_adv;
  union
  {
    struct
    {
      u8 kr_10g : 1;
      u8 kr_25g : 1;
      u8 rs_528 : 1;
      u8 kr_272 : 1;
      u8 _reserved_4_7 : 4;
    };
    u8 as_u8;
  } lp_fec_req;
  union
  {
    struct
    {
      u8 pause : 1;
      u8 asymmetric_pause : 1;
      u8 _reserved_2_7 : 6;
    };
    u8 as_u8;
  } lp_flowcontrol;
  u8 reserved5[5];
} ice_aqc_link_status_t;

STATIC_ASSERT_SIZEOF (ice_aqc_link_status_t, 56);

typedef enum
{
  ICE_AQC_LINK_STATUS_V1_SIZE = 32,
  ICE_AQC_LINK_STATUS_V2_SIZE = 56,
} ice_aqc_link_status_size_t;

enum
{
  ICE_AQC_LINK_EVENT_ENABLE = 3,
};

typedef union
{
  struct
  {
    u16 reserved0 : 1;
    u16 link_up_down : 1;
    u16 media_unavailable : 1;
    u16 link_fault : 1;
    u16 phy_temperature_alarm : 1;
    u16 excessive_errors : 1;
    u16 signal_detect : 1;
    u16 autoneg_completed : 1;
    u16 module_qualification_failure : 1;
    u16 port_tx_suspended : 1;
    u16 topology_conflict : 1;
    u16 media_conflict : 1;
    u16 phy_fw_load_failure : 1;
    u16 reserved13_15 : 3;
  };
  u16 as_u16;
} ice_aq_link_event_mask_t;

#define foreach_ice_aq_link_tx_state                                                               \
  _ (0, ACTIVE, "active")                                                                          \
  _ (1, DRAINED, "drained")                                                                        \
  _ (2, RESERVED, "reserved")                                                                      \
  _ (3, FLUSHED, "flushed")

enum
{
#define _(v, n, d) ICE_AQ_LINK_TX_##n = v,
  foreach_ice_aq_link_tx_state
#undef _
};

typedef enum
{
  ICE_AQC_REPORT_TOPO_CAP_NO_MEDIA = 0,
  ICE_AQC_REPORT_TOPO_CAP_MEDIA = 2,
  ICE_AQC_REPORT_ACTIVE_CFG = 4,
  ICE_AQC_REPORT_DFLT_CFG = 8,
} ice_aqc_phy_rpt_mode_t;

typedef union
{
  struct
  {
    u64 base_100_tx : 1;
    u64 sgmii_100m : 1;
    u64 base_1000_t : 1;
    u64 base_1000_sx : 1;
    u64 base_1000_lx : 1;
    u64 base_1000_kx : 1;
    u64 sgmii_1g : 1;
    u64 base_2500_t : 1;
    u64 base_2500_x : 1;
    u64 base_2500_kx : 1;
    u64 base_5g_t : 1;
    u64 base_5g_kr : 1;
    u64 base_10g_t : 1;
    u64 sfi_10g_da : 1;
    u64 base_10g_sr : 1;
    u64 base_10g_lr : 1;
    u64 base_10g_kr_cr1 : 1;
    u64 sfi_10g_aoc_acc : 1;
    u64 sfi_10g_c2c : 1;
    u64 base_25g_t : 1;
    u64 base_25g_cr : 1;
    u64 base_25g_cr_s : 1;
    u64 base_25g_cr1 : 1;
    u64 base_25g_sr : 1;
    u64 base_25g_lr : 1;
    u64 base_25g_kr : 1;
    u64 base_25g_kr_s : 1;
    u64 base_25g_kr1 : 1;
    u64 aui_25g_aoc_acc : 1;
    u64 aui_25g_c2c : 1;
    u64 base_40g_cr4 : 1;
    u64 base_40g_sr4 : 1;
    u64 base_40g_lr4 : 1;
    u64 base_40g_kr4 : 1;
    u64 xlaui_40g_aoc_acc : 1;
    u64 xlaui_40g : 1;
    u64 base_50g_cr2 : 1;
    u64 base_50g_sr2 : 1;
    u64 base_50g_lr2 : 1;
    u64 base_50g_kr2 : 1;
    u64 laui2_50g_aoc_acc : 1;
    u64 laui2_50g : 1;
    u64 aui2_50g_aoc_acc : 1;
    u64 aui2_50g : 1;
    u64 base_50g_cp : 1;
    u64 base_50g_sr : 1;
    u64 base_50g_fr : 1;
    u64 base_50g_lr : 1;
    u64 base_50g_kr_pam4 : 1;
    u64 aui1_50g_aoc_acc : 1;
    u64 aui1_50g : 1;
    u64 base_100g_cr4 : 1;
    u64 base_100g_sr4 : 1;
    u64 base_100g_lr4 : 1;
    u64 base_100g_kr4 : 1;
    u64 caui4_100g_aoc_acc : 1;
    u64 caui4_100g : 1;
    u64 aui4_100g_aoc_acc : 1;
    u64 aui4_100g : 1;
    u64 base_100g_cr_pam4 : 1;
    u64 base_100g_kr_pam4 : 1;
    u64 base_100g_cp2 : 1;
    u64 base_100g_sr2 : 1;
    u64 base_100g_dr : 1;
  };
  u64 as_u64;
} ice_phy_type_low_t;

typedef union
{
  struct
  {
    u64 base_100g_kr2_pam4 : 1;
    u64 caui2_100g_aoc_acc : 1;
    u64 caui2_100g : 1;
    u64 aui2_100g_aoc_acc : 1;
    u64 aui2_100g : 1;
    u64 base_200g_cr4_pam4 : 1;
    u64 base_200g_sr4 : 1;
    u64 base_200g_fr4 : 1;
    u64 base_200g_lr4 : 1;
    u64 base_200g_dr4 : 1;
    u64 base_200g_kr4_pam4 : 1;
    u64 aui4_200g_aoc_acc : 1;
    u64 aui4_200g : 1;
    u64 aui8_200g_aoc_acc : 1;
    u64 aui8_200g : 1;
    u64 _reserved_15_63 : 49;
  };
  u64 as_u64;
} ice_phy_type_high_t;

typedef struct
{
  u64 phy_type_low;
  u64 phy_type_high;
  union
  {
    struct
    {
      u8 pause_tx : 1;
      u8 pause_rx : 1;
      u8 low_power : 1;
      u8 link_enabled : 1;
      u8 autoneg : 1;
      u8 module_qualification : 1;
      u8 lesm : 1;
      u8 auto_fec : 1;
    } caps_flags;
    u8 caps;
  };
  union
  {
    struct
    {
      u8 d3cold_low_power_autoneg : 1;
      u8 clause28 : 1;
      u8 clause73 : 1;
      u8 clause37 : 1;
      u8 _reserved : 4;
    } an_flags;
    u8 low_power_ctrl_an;
  };
  u16 eee_cap;
  u16 eeer_value;
  u8 phy_id_oui[4];
  u8 phy_fw_ver[8];
  u8 link_fec_options;
  u8 module_compliance_enforcement;
  u8 extended_compliance_code;
  u8 module_type[3];
  u8 qualified_module_count;
  u8 reserved[7];
  struct
  {
    u8 vendor_oui[3];
    u8 reserved;
    u8 part_number[16];
    u32 revision;
    u64 reserved1;
  } qualified_modules[16];
} ice_aqc_get_phy_caps_data_t;

STATIC_ASSERT_SIZEOF (ice_aqc_get_phy_caps_data_t, 560);

typedef struct
{
  u8 pmd_count : 4;
  u8 pmd_width : 4;
  u8 max_lane_speed : 4;
  u8 _reserved : 4;
  u8 global_scid[2];
  u8 phy_scid[2];
  u8 pf2port_cid[2];
} ice_aqc_port_option_t;

STATIC_ASSERT_SIZEOF (ice_aqc_port_option_t, 8);

typedef struct
{
  u64 phy_type_low;
  u64 phy_type_high;
  union
  {
    struct
    {
      u8 tx_pause : 1;
      u8 rx_pause : 1;
      u8 low_power : 1;
      u8 link_enabled : 1;
      u8 _reserved : 1;
      u8 auto_link_update : 1;
      u8 lesm : 1;
      u8 auto_fec : 1;
    } caps_flags;
    u8 caps;
  };
  u8 low_power_ctrl_an;
  u16 eee_cap;
  u16 eeer_value;
  u8 link_fec_opt;
  u8 module_compliance_enforcement;
} ice_aqc_set_phy_cfg_data_t;

STATIC_ASSERT_SIZEOF (ice_aqc_set_phy_cfg_data_t, 24);

/* RSS profile registers and package section identifiers. */
#define ICE_GLQF_HINSET(p, i)	  (0x0040e000 + (p) * 4 + (i) * 512)
#define ICE_GLQF_HMASK_SEL(p)	  (0x00410000 + (p) * 4)
#define ICE_GLQF_HMASK(i)	  (0x0040fc00 + (i) * 4)
#define ICE_GLQF_HSYMM(p, i)	  (0x0040f000 + (p) * 4 + (i) * 512)
#define ICE_VSIQF_HASH_CTL(v)	  (0x0040d000 + (v) * 4)
#define ICE_VSIQF_TC_REGION(v, i) (0x00448000 + (v) * 4 + (i) * 4096)
#define ICE_VSIQF_HLUT(v, i)	  (0x00420000 + (v) * 4 + (i) * 4096)
#define ICE_PFQF_HLUT(i)	  (0x00430000 + (i) * 64)
#define ICE_GLQF_HLUT(g, i)	  (0x00438000 + (g) * 512 + (i) * 4)
#define ICE_PFQF_HLUT_SIZE	  0x00455480
#define ICE_GLQF_HLUT_SIZE(g)	  (0x00455400 + (g) * 4)
#define ICE_GLQF_PROF2TC(p, i)	  (0x0044d000 + (p) * 4 + (i) * 512)

enum
{
  ICE_RSS_LUT_VSI = 0,
  ICE_RSS_LUT_RESERVED = 1,
  ICE_RSS_LUT_PF = 2,
  ICE_RSS_LUT_GLOBAL = 3,
};

enum
{
  ICE_RSS_PF_LUT_128 = 0,
  ICE_RSS_PF_LUT_512 = 1,
  ICE_RSS_PF_LUT_2048 = 2,
  ICE_RSS_PF_LUT_RESERVED = 3,
};

enum
{
  ICE_RSS_GLOBAL_LUT_128 = 0,
  ICE_RSS_GLOBAL_LUT_512 = 1,
};

#define ICE_RSS_LUT_SIZE_128	      128
#define ICE_RSS_LUT_SIZE_512	      512
#define ICE_RSS_LUT_SIZE_2048	      2048
#define ICE_RSS_VSI_LUT_ENTRY_MASK    0xf
#define ICE_RSS_PF_LUT_ENTRY_MASK     0xff
#define ICE_RSS_GLOBAL_LUT_ENTRY_MASK 0x3f
#define ICE_RSS_REGION_MAX_SIZE_LOG2  8

typedef union
{
  struct
  {
    u32 size : 2;
    u32 reserved : 30;
  };
  u32 as_u32;
} ice_reg_pfqf_hlut_size_t;

typedef union
{
  struct
  {
    u32 size : 1;
    u32 reserved : 31;
  };
  u32 as_u32;
} ice_reg_glqf_hlut_size_t;

typedef union
{
  struct
  {
    u32 lut_select : 2;
    u32 global_lut : 4;
    u32 hash_scheme : 2;
    u32 tc_override_select : 5;
    u32 reserved0 : 2;
    u32 tc_override_enable : 1;
    u32 reserved1 : 16;
  };
  u32 as_u32;
} ice_reg_vsiqf_hash_ctl_t;

typedef union
{
  struct
  {
    u16 base : 11;
    u16 size_log2 : 4;
    u16 reserved : 1;
  };
  u16 as_u16;
} ice_reg_tc_region_t;

typedef union
{
  ice_reg_tc_region_t regions[2];
  u32 as_u32;
} ice_reg_vsiqf_tc_region_t;

typedef union
{
  struct
  {
    u8 enable : 1;
    u8 region : 3;
  };
  u8 as_u8;
} ice_reg_profile_tc_override_t;

STATIC_ASSERT_SIZEOF (ice_reg_vsiqf_hash_ctl_t, 4);
STATIC_ASSERT_SIZEOF (ice_reg_vsiqf_tc_region_t, 4);

typedef union
{
  struct
  {
    u32 rx_no_desc : 16;
    u32 rx_errors : 16;
  };
  u32 as_u32;
} ice_reg_glv_repc_t;

typedef union
{
  struct
  {
    u8 first_enable : 1;
    u8 first_region : 3;
    u8 second_enable : 1;
    u8 second_region : 3;
  };
  u8 as_u8;
} ice_reg_profile_tc_pair_t;

typedef union
{
  ice_reg_profile_tc_pair_t pairs[4];
  u32 as_u32;
} ice_reg_glqf_prof2tc_t;

typedef union
{
  struct
  {
    u8 fv_word_index : 5;
    u8 reserved : 2;
    u8 valid : 1;
  };
  u8 as_u8;
} ice_reg_input_set_word_t;

typedef union
{
  ice_reg_input_set_word_t words[4];
  u32 as_u32;
} ice_reg_glqf_hinset_t;

typedef union
{
  struct
  {
    u32 word_index : 5;
    u32 reserved : 11;
    u32 mask : 16;
  };
  u32 as_u32;
} ice_reg_glqf_hmask_t;

STATIC_ASSERT_SIZEOF (ice_reg_input_set_word_t, 1);
STATIC_ASSERT_SIZEOF (ice_reg_glqf_hinset_t, 4);
STATIC_ASSERT_SIZEOF (ice_reg_glqf_hmask_t, 4);
STATIC_ASSERT_SIZEOF (ice_reg_pfqf_hlut_size_t, 4);
STATIC_ASSERT_SIZEOF (ice_reg_glqf_hlut_size_t, 4);
STATIC_ASSERT_SIZEOF (ice_reg_glv_repc_t, 4);
STATIC_ASSERT_SIZEOF (ice_reg_profile_tc_pair_t, 1);
STATIC_ASSERT_SIZEOF (ice_reg_glqf_prof2tc_t, 4);

enum
{
  ICE_RSS_SECTION_KEY_BUILDER = 41,
  ICE_RSS_SECTION_XLT1 = 42,
  ICE_RSS_SECTION_XLT2 = 43,
  ICE_RSS_SECTION_TCAM = 44,
  ICE_RSS_SECTION_FV = 46,
};
