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
  __SFLOWPS_PSAMPLE_ATTR_MAX
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

typedef enum
{
  SFLOWPS_STATE_INIT,
  SFLOWPS_STATE_OPEN,
  SFLOWPS_STATE_WAIT_FAMILY,
  SFLOWPS_STATE_READY
} EnumSFLOWPSState;

typedef struct _SFLOWPS
{
  EnumSFLOWPSState state;
  u32 id;
  int nl_sock;
  u32 nl_seq;
  u32 genetlink_version;
  u16 family_id;
  u32 group_id;
} SFLOWPS;

typedef struct _SFLOWPSAttr
{
  bool included : 1;
  struct nlattr attr;
  struct iovec val;
} SFLOWPSAttr;

typedef struct _SFLOWPSSpec
{
  struct nlmsghdr nlh;
  struct genlmsghdr ge;
  SFLOWPSAttr attr[__SFLOWPS_PSAMPLE_ATTR_MAX];
  int n_attrs;
  int attrs_len;
} SFLOWPSSpec;

bool SFLOWPS_open (SFLOWPS *pst);
bool SFLOWPS_close (SFLOWPS *pst);
EnumSFLOWPSState SFLOWPS_state (SFLOWPS *pst);
EnumSFLOWPSState SFLOWPS_open_step (SFLOWPS *pst);

bool SFLOWPSSpec_setAttr (SFLOWPSSpec *spec, EnumSFLOWPSAttributes field,
			  void *buf, int len);
#define SFLOWPSSpec_setAttrInt(spec, field, val)                              \
  SFLOWPSSpec_setAttr ((spec), (field), &(val), sizeof (val))

int SFLOWPSSpec_send (SFLOWPS *pst, SFLOWPSSpec *spec);

#endif /* __included_sflow_psample_h__ */
