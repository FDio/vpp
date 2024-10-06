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
  /* enum shared with hsflowd, so only add here */
  __SFLOW_VPP_ATTR_MAX
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

typedef struct _SFLOWUS
{
  u32 id;
  int nl_sock;
  u32 nl_seq;
  u32 group_id;
} SFLOWUS;

typedef struct _SFLOWUSAttr
{
  bool included : 1;
  struct nlattr attr;
  struct iovec val;
} SFLOWUSAttr;

typedef struct _SFLOWUSSpec
{
  struct nlmsghdr nlh;
  SFLOWUSAttr attr[__SFLOW_VPP_ATTR_MAX];
  int n_attrs;
  int attrs_len;
} SFLOWUSSpec;

bool SFLOWUS_open (SFLOWUS *ust);
bool SFLOWUS_close (SFLOWUS *ust);

bool SFLOWUSSpec_setMsgType (SFLOWUSSpec *spec, EnumSFlowVppMsgType type);
bool SFLOWUSSpec_setAttr (SFLOWUSSpec *spec, EnumSFlowVppAttributes field,
			  void *buf, int len);
#define SFLOWUSSpec_setAttrInt(spec, field, val)                              \
  SFLOWUSSpec_setAttr ((spec), (field), &(val), sizeof (val))

void SFLOWUSSpec_send (SFLOWUS *ust, SFLOWUSSpec *spec);

#endif /* __included_sflow_usersock_h__ */
