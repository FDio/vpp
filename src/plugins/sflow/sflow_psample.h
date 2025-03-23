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

#ifndef __included_sflow_psample_h__
#define __included_sflow_psample_h__

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
#include <linux/psample.h>
#include <signal.h>
#include <ctype.h>

#include <sflow/sflow_netlink.h>

// #define SFLOWPS_DEBUG

#define SFLOWPS_PSAMPLE_READNL_RCV_BUF 8192
#define SFLOWPS_PSAMPLE_READNL_SND_BUF 1000000

/* Shadow the attributes in linux/psample.h so
 * we can easily compile/test fields that are not
 * defined on the kernel we are compiling on.
 */
typedef enum
{
#define SFLOWPS_FIELDDATA(field, len, descr) field,
#include "sflow/sflow_psample_fields.h"
#undef SFLOWPS_FIELDDATA
  __SFLOWPS_PSAMPLE_ATTRS
} EnumSFLOWPSAttributes;

typedef struct _SFLOWPS_field_t
{
  EnumSFLOWPSAttributes field;
  int len;
  char *descr;
} SFLOWPS_field_t;

static const SFLOWPS_field_t SFLOWPS_Fields[] = {
#define SFLOWPS_FIELDDATA(field, len, descr) { field, len, descr },
#include "sflow/sflow_psample_fields.h"
#undef SFLOWPS_FIELDDATA
};

#define SFLOWPS_FAM	      PSAMPLE_GENL_NAME
#define SFLOWPS_FAM_LEN	      sizeof (SFLOWPS_FAM)
#define SFLOWPS_FAM_FOOTPRINT NLMSG_ALIGN (SFLOWPS_FAM_LEN)
#define SFLOWPS_IOV_FRAGS     ((2 * __SFLOWPS_PSAMPLE_ATTRS) + 2)

typedef struct _SFLOWPS
{
  SFLOWNL nl;
  char fam_name[SFLOWPS_FAM_FOOTPRINT];
  SFLOWNLAttr attr[__SFLOWPS_PSAMPLE_ATTRS];
  struct iovec iov[SFLOWPS_IOV_FRAGS];
} SFLOWPS;

EnumSFLOWNLState SFLOWPS_init (SFLOWPS *pst);
bool SFLOWPS_open (SFLOWPS *pst);
bool SFLOWPS_close (SFLOWPS *pst);
EnumSFLOWNLState SFLOWPS_state (SFLOWPS *pst);
EnumSFLOWNLState SFLOWPS_open_step (SFLOWPS *pst);

bool SFLOWPS_set_attr (SFLOWPS *pst, EnumSFLOWPSAttributes field, void *buf,
		       int len);
#define SFLOWPS_set_attr_int(pst, field, val)                                 \
  SFLOWPS_set_attr ((pst), (field), &(val), sizeof (val))

int SFLOWPS_send (SFLOWPS *pst);

#endif /* __included_sflow_psample_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
