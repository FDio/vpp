/*
 * Copyright (c) 2024 InMon Corp.
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

#ifndef __included_sflow_usersock_h__
#define __included_sflow_usersock_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <signal.h>
#include <ctype.h>

#include <sflow/sflow_netlink.h>

// ==================== shared with hsflowd mod_vpp =========================
// See https://github.com/sflow/host-sflow

#define SFLOW_VPP_NETLINK_USERSOCK_MULTICAST 29

typedef enum
{
  SFLOW_VPP_MSG_STATUS = 1,
  SFLOW_VPP_MSG_IF_COUNTERS
} EnumSFlowVppMsgType;

typedef enum
{
  SFLOW_VPP_ATTR_PORTNAME,    /* string */
  SFLOW_VPP_ATTR_IFINDEX,     /* u32 */
  SFLOW_VPP_ATTR_IFTYPE,      /* u32 */
  SFLOW_VPP_ATTR_IFSPEED,     /* u64 */
  SFLOW_VPP_ATTR_IFDIRECTION, /* u32 */
  SFLOW_VPP_ATTR_OPER_UP,     /* u32 */
  SFLOW_VPP_ATTR_ADMIN_UP,    /* u32 */
  SFLOW_VPP_ATTR_RX_OCTETS,   /* u64 */
  SFLOW_VPP_ATTR_TX_OCTETS,   /* u64 */
  SFLOW_VPP_ATTR_RX_PKTS,     /* u64 */
  SFLOW_VPP_ATTR_TX_PKTS,     /* u64 */
  SFLOW_VPP_ATTR_RX_BCASTS,   /* u64 */
  SFLOW_VPP_ATTR_TX_BCASTS,   /* u64 */
  SFLOW_VPP_ATTR_RX_MCASTS,   /* u64 */
  SFLOW_VPP_ATTR_TX_MCASTS,   /* u64 */
  SFLOW_VPP_ATTR_RX_DISCARDS, /* u64 */
  SFLOW_VPP_ATTR_TX_DISCARDS, /* u64 */
  SFLOW_VPP_ATTR_RX_ERRORS,   /* u64 */
  SFLOW_VPP_ATTR_TX_ERRORS,   /* u64 */
  SFLOW_VPP_ATTR_HW_ADDRESS,  /* binary */
  SFLOW_VPP_ATTR_UPTIME_S,    /* u32 */
  SFLOW_VPP_ATTR_OSINDEX,     /* u32 Linux ifIndex number, where applicable */
  SFLOW_VPP_ATTR_DROPS,	      /* u32 all FIFO and netlink sendmsg drops */
  SFLOW_VPP_ATTR_SEQ,	      /* u32 send seq no */
  /* enum shared with hsflowd, so only add here */
  __SFLOW_VPP_ATTRS
} EnumSFlowVppAttributes;

#define SFLOW_VPP_PSAMPLE_GROUP_INGRESS 3
#define SFLOW_VPP_PSAMPLE_GROUP_EGRESS	4

// =========================================================================
typedef struct
{
  u64 byts;
  u64 pkts;
  u64 m_pkts;
  u64 b_pkts;
  u64 errs;
  u64 drps;
} sflow_ctrs_t;

typedef struct
{
  sflow_ctrs_t tx;
  sflow_ctrs_t rx;
} sflow_counters_t;

typedef struct _SFLOWUS_field_t
{
  EnumSFlowVppAttributes field;
  int len;
} SFLOWUS_field_t;

#define SFLOWUS_ATTRS __SFLOW_VPP_ATTRS
#define SFLOWUS_IOV_FRAGS                                                     \
  ((2 * SFLOWUS_ATTRS) + 2) // TODO: may only be +1 -- no ge header?

typedef struct _SFLOWUS
{
  SFLOWNL nl;
  SFLOWNLAttr attr[__SFLOW_VPP_ATTRS];
  struct iovec iov[SFLOWUS_IOV_FRAGS];
} SFLOWUS;

EnumSFLOWNLState SFLOWUS_init (SFLOWUS *ust);
bool SFLOWUS_open (SFLOWUS *ust);
bool SFLOWUS_close (SFLOWUS *ust);

bool SFLOWUS_set_msg_type (SFLOWUS *ust, EnumSFlowVppMsgType type);
bool SFLOWUS_set_attr (SFLOWUS *ust, EnumSFlowVppAttributes field, void *buf,
		       int len);
#define SFLOWUS_set_attr_int(ust, field, val)                                 \
  SFLOWUS_set_attr ((ust), (field), &(val), sizeof (val))

int SFLOWUS_send (SFLOWUS *ust);

#endif /* __included_sflow_usersock_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
