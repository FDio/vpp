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

#ifndef __included_sflow_netlink_h__
#define __included_sflow_netlink_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

#include <fcntl.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <signal.h>
#include <ctype.h>

#define SFLOWNL_RCV_BUF 8192
#define SFLOWNL_SND_BUF 1000000

typedef enum
{
  SFLOWNL_USERSOCK = 1,
  SFLOWNL_PSAMPLE,
  SFLOWNL_DROPMON,
} EnumSFLOWNLMod;

typedef enum
{
  SFLOWNL_STATE_UNDEFINED = 0,
  SFLOWNL_STATE_INIT,
  SFLOWNL_STATE_OPEN,
  SFLOWNL_STATE_WAIT_FAMILY,
  SFLOWNL_STATE_READY
} EnumSFLOWNLState;

typedef struct _SFLOWNLAttr
{
  bool included : 1;
  struct nlattr attr;
  struct iovec val;
} SFLOWNLAttr;

typedef struct _SFLOWNL
{
  // connect
  EnumSFLOWNLState state;
  EnumSFLOWNLMod id;
  int nl_sock;
  u32 nl_seq;
  u32 genetlink_version;
  u16 family_id;
  u32 group_id;
  // setup
  char *family_name;
  u32 family_len;
  u32 join_group_id;
  char *join_group_name;
  // msg
  struct nlmsghdr nlh;
  struct genlmsghdr ge;
  SFLOWNLAttr *attr;
  u32 attr_max;
  u32 n_attrs;
  u32 attrs_len;
  u32 iov_max;
  struct iovec *iov;
} SFLOWNL;

void sflow_netlink_set_nonblocking (int fd);
void sflow_netlink_set_close_on_exec (int fd);
int sflow_netlink_set_send_buffer (int fd, int requested);
u32 sflow_netlink_generic_pid (u32 mod_id);
int sflow_netlink_generic_open (SFLOWNL *nl);
int sflow_netlink_usersock_open (SFLOWNL *nl);
int sflow_netlink_close (SFLOWNL *nl);
bool sflow_netlink_set_attr (SFLOWNL *nl, int field, void *val, int len);

#define sflow_netlink_set_attr_int(nl, field, val)                            \
  sflow_netlink_set_attr ((nl), (field), &(val), sizeof (val))

int sflow_netlink_generic_send_cmd (int sockfd, u32 mod_id, int type, int cmd,
				    int req_type, void *req, int req_len,
				    int req_footprint, u32 seqNo);
int sflow_netlink_send_attrs (SFLOWNL *nl, bool ge);
void sflow_netlink_reset_attrs (SFLOWNL *nl);
void sflow_netlink_generic_get_family (SFLOWNL *nl);
void sflow_netlink_generic_read (SFLOWNL *nl, struct nlmsghdr *nlh);
void sflow_netlink_read (SFLOWNL *nl);

#endif /* __included_sflow_netlink_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
