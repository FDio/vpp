/*
 * Copyright (c) 2025 InMon Corp.
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

#ifndef __included_sflow_dropmon_h__
#define __included_sflow_dropmon_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/net_dropmon.h>
#include <net/if.h>
#include <signal.h>
#include <ctype.h>

#define SFLOWDM_DROPMON_READNL_RCV_BUF 8192
#define SFLOWDM_DROPMON_READNL_SND_BUF 1000000

#ifndef NET_DM_GENL_NAME
  #define NET_DM_GENL_NAME "NET_DM"
#endif

typedef enum
{
  SFLOWDM_STATE_INIT,
  SFLOWDM_STATE_OPEN,
  SFLOWDM_STATE_WAIT_FAMILY,
  SFLOWDM_STATE_READY
} EnumSFLOWDMState;

typedef struct _SFLOWDM
{
  EnumSFLOWDMState state;
  u32 id;
  int nl_sock;
  u32 nl_seq;
  u32 genetlink_version;
  u16 family_id;
  u32 group_id;
} SFLOWDM;

typedef struct _SFLOWDMAttr
{
  bool included : 1;
  struct nlattr attr;
  struct iovec val;
} SFLOWDMAttr;

typedef struct _SFLOWDMSpec
{
  struct nlmsghdr nlh;
  struct genlmsghdr ge;
  SFLOWDMAttr attr[NET_DM_ATTR_MAX];
  int n_attrs;
  int attrs_len;
} SFLOWDMSpec;

bool SFLOWDM_open (SFLOWDM *dmt);
bool SFLOWDM_close (SFLOWDM *dmt);
EnumSFLOWDMState SFLOWDM_state (SFLOWDM *dmt);
EnumSFLOWDMState SFLOWDM_open_step (SFLOWDM *dmt);

bool SFLOWDMSpec_setAttr (SFLOWDMSpec *spec, int field, void *buf, int len);
#define SFLOWDMSpec_setAttrInt(spec, field, val)		\
  SFLOWDMSpec_setAttr ((spec), (field), &(val), sizeof (val))

int SFLOWDMSpec_send (SFLOWDM *dmt, SFLOWDMSpec *spec);

#endif /* __included_sflow_dropmon_h__ */
