/*
 * srv6_end.h
 *
 * Copyright (c) 2019 Arrcus Inc and/or its affiliates.
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

#ifndef __included_srv6_end_h__
#define __included_srv6_end_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#define SRV6_GTP_UDP_DST_PORT 2152

#define SRV6_NHTYPE_NONE 	0
#define SRV6_NHTYPE_IPV4 	1
#define SRV6_NHTYPE_IPV6 	2
#define SRV6_NHTYPE_NON_IP	3

#ifndef IP_PROTOCOL_IP6_ETHERNET
#define IP_PROTOCOL_IP6_ETHERNET	143
#endif

#define SRV6_GTP6_UNKNOW	0
#define SRV6_GTP6_DT4		1
#define SRV6_GTP6_DT6		2
#define SRV6_GTP6_DT46		3

#define SRV6_GTP4_UNKNOW	0
#define SRV6_GTP4_DT4		1
#define SRV6_GTP4_DT6		2
#define SRV6_GTP4_DT46		3

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BITALIGN2(A,B)          A; B
#define BITALIGN3(A,B,C)        A; B; C
#else
#define BITALIGN2(A,B)          B; A
#define BITALIGN3(A,B,C)        C; B; A
#endif

#define GTPU_EXTHDR_FLAG                0x04
#define GTPU_SEQ_FLAG			0x02
#define GTPU_EXTHDR_PDU_SESSION         0x85

#define SRH_TAG_ECHO_REPLY              0x0008
#define SRH_TAG_ECHO_REQUEST            0x0004
#define SRH_TAG_ERROR_INDICATION        0x0002
#define SRH_TAG_END_MARKER              0x0001

#define GTPU_RECOVERY_IE_TYPE		0x0e

#define GTPU_IE_MAX_SIZ			256
#define SRH_TLV_USER_PLANE_CONTAINER	0x0a	/* tentative */

typedef enum mobile_policy_function_list
{
  SRV6_MOBILE_POLICY_UNKNOWN_FUNCTION = 0,
  SRV6_MOBILE_POLICY_T_M_GTP4_D,
  SRV6_MOBILE_POLICY_T_M_GTP4_DT4,
  SRV6_MOBILE_POLICY_T_M_GTP4_DT6,
  SRV6_MOBILE_POLICY_T_M_GTP4_DT46,
  SRV6_MOBILE_POLICY_END_M_GTP6_D,
} mobile_policy_function_list_t;

typedef enum mobile_localsid_function_list
{
  SRV6_MOBILE_LOCALSID_UNKNOWN_FUNCTION = 0,
  SRV6_MOBILE_LOCALSID_END_M_GTP4_E,
  SRV6_MOBILE_LOCALSID_END_M_GTP6_E,
  SRV6_MOBILE_LOCALSID_END_M_GTP6_D,
  SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DI,
  SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT4,
  SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT6,
  SRV6_MOBILE_LOCALSID_END_M_GTP6_D_DT46,
} mobile_localsid_function_list_t;

/* *INDENT-OFF* */
typedef struct
{
  u8 type;
  u8 restart_counter;
} __attribute__ ((packed)) gtpu_recovery_ie;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef struct
{
  u16 seq;
  u8 npdu_num;
  u8 nextexthdr;
} __attribute__ ((packed)) gtpu_exthdr_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef struct
{
  u8 ver_flags;
  u8 type;
  u16 length;     /* length in octets of the payload */
  u32 teid;
  gtpu_exthdr_t ext[0];
} __attribute__ ((packed)) gtpu_header_t;
/* *INDENT-ON* */

#define GTPU_TYPE_ECHO_REQUEST          1
#define GTPU_TYPE_ECHO_REPLY            2
#define GTPU_TYPE_ERROR_INDICATION      26
#define GTPU_TYPE_END_MARKER            254
#define GTPU_TYPE_GTPU                  255

/* *INDENT-OFF* */
typedef struct
{
  BITALIGN2 (u8 ppi:3,
             u8 spare:5);

  u8 padding[3];
} __attribute__ ((packed)) gtpu_paging_policy_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef struct
{
  u8 exthdrlen;
  BITALIGN2(u8 type:4,
            u8 spare:4);
  union {
    struct gtpu_qfi_bits {BITALIGN3(u8 p:1,
		                    u8 r:1,
				    u8 qfi:6);
    } bits;

    u8 val;
  } u;

  gtpu_paging_policy_t  paging[0];
  u8 nextexthdr;
} __attribute__ ((packed)) gtpu_pdu_session_t;
/* *INDENT-ON* */

#define GTPU_PDU_SESSION_P_BIT_MASK     0x80
#define GTPU_PDU_SESSION_R_BIT_MASK     0x40
#define GTPU_PDU_SESSION_QFI_MASK       0x3f

#define SRV6_PDU_SESSION_U_BIT_MASK     0x01
#define SRV6_PDU_SESSION_R_BIT_MASK     0x02
#define SRV6_PDU_SESSION_QFI_MASK       0xfC

/* *INDENT-OFF* */
typedef struct
{
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;        /* 8 bytes */
} __attribute__ ((packed)) ip4_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef struct
{
  ip6_header_t ip6;          /* 40 bytes */
  udp_header_t udp;          /* 8 bytes */
  gtpu_header_t gtpu;        /* 8 bytes */
} __attribute__ ((packed)) ip6_gtpu_header_t;
/* *INDENT-ON* */

#define GTPU_V1_VER   (1<<5)

#define GTPU_PT_GTP   (1<<4)

/* *INDENT-OFF* */
typedef struct
{
  u8 type;
  u8 length;
  u8 value[0];
} __attribute__ ((packed)) user_plane_sub_tlv_t;
/* *INDENT-ON* */

#define USER_PLANE_SUB_TLV_IE	0x01

/* SRv6 mobile Plugin Params */

/* GTP6.D, GTP6.Di */
typedef struct srv6_end_gtp6_d_param_s
{
  u8 nhtype;

  ip6_address_t sr_prefix;
  u32 sr_prefixlen;

  bool drop_in;

  u32 fib_table;
  u32 fib4_index;
  u32 fib6_index;
} srv6_end_gtp6_d_param_t;

/* GTP6.DT */
typedef struct srv6_end_gtp6_dt_param_s
{
  u8 type;

  u32 fib4_index;
  u32 fib6_index;
  u32 local_fib_index;
} srv6_end_gtp6_dt_param_t;

/* GTP6.E */
typedef struct srv6_end_gtp6_e_param_s
{
  u32 fib_table;
  u32 fib4_index;
  u32 fib6_index;
} srv6_end_gtp6_e_param_t;

/* GTP4.DT */
typedef struct srv6_t_gtp4_dt_param_s
{
  u8 type;

  u32 fib4_index;
  u32 fib6_index;
  u32 local_fib_index;
} srv6_t_gtp4_dt_param_t;

/* GTP4.E */
typedef struct srv6_end_gtp4_e_param_s
{
  u32 v4src_position;
  ip4_address_t v4src_addr;

  u32 fib_table;
  u32 fib4_index;
  u32 fib6_index;
} srv6_end_gtp4_e_param_t;

/* GTP4.D */
typedef struct srv6_end_gtp4_d_param_s
{
  u8 nhtype;

  ip6_address_t sr_prefix;
  u32 sr_prefixlen;

  ip6_address_t v6src_prefix;
  u32 v6src_prefixlen;

  bool drop_in;

  u32 fib_table;
  u32 fib4_index;
  u32 fib6_index;
} srv6_end_gtp4_d_param_t;

typedef struct srv6_end_main_v4_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp4_e_node_index;
  u32 error_node_index;

  u32 dst_p_len;		// dst prefix len
  u32 src_p_len;		// src prefix len

  ip4_gtpu_header_t cache_hdr;

} srv6_end_main_v4_t;

typedef struct srv6_t_main_v4_decap_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 t_m_gtp4_d_node_index;
  u32 error_node_index;

  ip6_header_t cache_hdr;
} srv6_t_main_v4_decap_t;

extern srv6_end_main_v4_t srv6_end_main_v4;
extern srv6_t_main_v4_decap_t srv6_t_main_v4_decap;
extern vlib_node_registration_t srv6_end_m_gtp4_e;

typedef struct srv6_end_main_v6_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp6_e_node_index;
  u32 error_node_index;

  ip6_gtpu_header_t cache_hdr;
} srv6_end_main_v6_t;

extern srv6_end_main_v6_t srv6_end_main_v6;
extern vlib_node_registration_t srv6_end_m_gtp6_e;

typedef struct srv6_end_main_v6_decap_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp6_d_node_index;
  u32 error_node_index;

  ip6_header_t cache_hdr;
} srv6_end_main_v6_decap_t;

extern srv6_end_main_v6_decap_t srv6_end_main_v6_decap;
extern vlib_node_registration_t srv6_end_m_gtp6_d;

typedef struct srv6_end_main_v6_decap_di_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp6_d_di_node_index;
  u32 error_node_index;

  ip6srv_combo_header_t cache_hdr;
} srv6_end_main_v6_decap_di_t;

extern srv6_end_main_v6_decap_di_t srv6_end_main_v6_decap_di;
extern vlib_node_registration_t srv6_end_m_gtp6_d_di;

typedef struct srv6_end_main_v6_dt_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 end_m_gtp6_dt_node_index;
  u32 error_node_index;
} srv6_end_main_v6_dt_t;

extern srv6_end_main_v6_dt_t srv6_end_main_v6_dt;
extern vlib_node_registration_t srv6_end_m_gtp6_dt;

typedef struct srv6_t_main_v4_dt_s
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 t_m_gtp4_dt_node_index;
  u32 error_node_index;
} srv6_t_main_v4_dt_t;

extern srv6_t_main_v4_dt_t srv6_t_main_v4_dt;
extern vlib_node_registration_t srv6_t_m_gtp4_dt;

#endif /* __included_srv6_end_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
