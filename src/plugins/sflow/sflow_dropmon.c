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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

#include <fcntl.h>
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
#include <sflow/sflow_dropmon.h>

/*_________________---------------------------__________________
  _________________       SFLOWDM_init        __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWDM_init (SFLOWDM *dmt)
{
  dmt->nl.id = SFLOWNL_DROPMON;
  memset (dmt->fam_name, 0, SFLOWDM_FAM_FOOTPRINT);
  memcpy (dmt->fam_name, SFLOWDM_FAM, SFLOWDM_FAM_LEN);
  dmt->nl.family_name = dmt->fam_name;
  dmt->nl.family_len = SFLOWDM_FAM_LEN;
  dmt->nl.join_group_id = NET_DM_GRP_ALERT;
  dmt->nl.attr = dmt->attr;
  dmt->nl.attr_max = SFLOWDM_ATTRS - 1;
  dmt->nl.iov = dmt->iov;
  dmt->nl.iov_max = SFLOWDM_IOV_FRAGS - 1;
  dmt->nl.state = SFLOWNL_STATE_INIT;
  return dmt->nl.state;
}

/*_________________---------------------------__________________
  _________________       SFLOWDM_open        __________________
  -----------------___________________________------------------
*/

bool
SFLOWDM_open (SFLOWDM *dmt)
{
  if (dmt->nl.state == SFLOWNL_STATE_UNDEFINED)
    SFLOWDM_init (dmt);
  if (dmt->nl.nl_sock == 0)
    {
      dmt->nl.nl_sock = sflow_netlink_generic_open (&dmt->nl);
      if (dmt->nl.nl_sock > 0)
	sflow_netlink_generic_get_family (&dmt->nl);
    }
  return (dmt->nl.nl_sock > 0);
}

/*_________________---------------------------__________________
  _________________       SFLOWDM_close       __________________
  -----------------___________________________------------------
*/

bool
SFLOWDM_close (SFLOWDM *dmt)
{
  return (sflow_netlink_close (&dmt->nl) == 0);
}

/*_________________---------------------------__________________
  _________________       SFLOWDM_state       __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWDM_state (SFLOWDM *dmt)
{
  return dmt->nl.state;
}

/*_________________---------------------------__________________
  _________________    SFLOWDM_open_step      __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWDM_open_step (SFLOWDM *dmt)
{
  switch (dmt->nl.state)
    {
    case SFLOWNL_STATE_UNDEFINED:
      SFLOWDM_init (dmt);
      break;
    case SFLOWNL_STATE_INIT:
      SFLOWDM_open (dmt);
      break;
    case SFLOWNL_STATE_OPEN:
      sflow_netlink_generic_get_family (&dmt->nl);
      break;
    case SFLOWNL_STATE_WAIT_FAMILY:
      sflow_netlink_read (&dmt->nl);
      break;
    case SFLOWNL_STATE_READY:
      break;
    }
  return dmt->nl.state;
}

/*_________________---------------------------__________________
  _________________    SFLOWDMSpec_setAttr    __________________
  -----------------___________________________------------------
*/

bool
SFLOWDM_set_attr (SFLOWDM *dmt, int field, void *val, int len)
{
  return sflow_netlink_set_attr (&dmt->nl, field, val, len);
}

/*_________________---------------------------__________________
  _________________    SFLOWDMSpec_send       __________________
  -----------------___________________________------------------
*/

int
SFLOWDM_send (SFLOWDM *dmt)
{
  dmt->nl.ge.cmd = NET_DM_CMD_PACKET_ALERT;
  dmt->nl.ge.version = 0; // NET_DM_CFG_VERSION==0 but no NET_DM_CMD_VERSION
  int status = sflow_netlink_send_attrs (&dmt->nl, true);
  sflow_netlink_reset_attrs (&dmt->nl);
  if (status <= 0)
    {
      SFLOW_ERR ("DROPMON strerror(errno) = %s; errno = %d\n",
		 strerror (errno), errno);
    }
  return status;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
