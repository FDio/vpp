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

#include <sflow/sflow_netlink.h>

#define SFLOWDM_DROPMON_READNL_RCV_BUF 8192
#define SFLOWDM_DROPMON_READNL_SND_BUF 1000000

#ifndef NET_DM_GENL_NAME
#define NET_DM_GENL_NAME "NET_DM"
#endif

#define SFLOWDM_FAM	      NET_DM_GENL_NAME
#define SFLOWDM_FAM_LEN	      sizeof (SFLOWDM_FAM)
#define SFLOWDM_FAM_FOOTPRINT NLMSG_ALIGN (SFLOWDM_FAM_LEN)
#define SFLOWDM_ATTRS	      NET_DM_ATTR_MAX + 1
#define SFLOWDM_IOV_FRAGS     ((2 * SFLOWDM_ATTRS) + 2)

typedef struct _SFLOWDM
{
  SFLOWNL nl;
  char fam_name[SFLOWDM_FAM_FOOTPRINT];
  SFLOWNLAttr attr[SFLOWDM_ATTRS];
  struct iovec iov[SFLOWDM_IOV_FRAGS];
} SFLOWDM;

EnumSFLOWNLState SFLOWDM_init (SFLOWDM *dmt);
bool SFLOWDM_open (SFLOWDM *dmt);
bool SFLOWDM_close (SFLOWDM *dmt);
EnumSFLOWNLState SFLOWDM_state (SFLOWDM *dmt);
EnumSFLOWNLState SFLOWDM_open_step (SFLOWDM *dmt);

bool SFLOWDM_set_attr (SFLOWDM *dmt, int field, void *buf, int len);
#define SFLOWDM_set_attr_int(dmt, field, val)                                 \
  SFLOWDM_set_attr ((dmt), (field), &(val), sizeof (val))

int SFLOWDM_send (SFLOWDM *dmt);

#endif /* __included_sflow_dropmon_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
