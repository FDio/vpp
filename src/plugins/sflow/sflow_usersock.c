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
#include <signal.h>
#include <ctype.h>

#include <sflow/sflow_netlink.h>
#include <sflow/sflow_usersock.h>

/*_________________---------------------------__________________
  _________________       SFLOWUS_init        __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWUS_init (SFLOWUS *ust)
{
  ust->nl.id = SFLOWNL_USERSOCK;
  ust->nl.group_id = SFLOW_NETLINK_USERSOCK_MULTICAST;
  ust->nl.attr = ust->attr;
  ust->nl.attr_max = SFLOWUS_ATTRS - 1;
  ust->nl.iov = ust->iov;
  ust->nl.iov_max = SFLOWUS_IOV_FRAGS - 1;
  ust->nl.state = SFLOWNL_STATE_INIT;
  return ust->nl.state;
}

/*_________________---------------------------__________________
  _________________       SFLOWUS_open        __________________
  -----------------___________________________------------------
*/

bool
SFLOWUS_open (SFLOWUS *ust)
{
  if (ust->nl.state == SFLOWNL_STATE_UNDEFINED)
    SFLOWUS_init (ust);
  if (ust->nl.nl_sock == 0)
    sflow_netlink_usersock_open (&ust->nl);
  if (ust->nl.nl_sock > 0)
    {
      ust->nl.state = SFLOWNL_STATE_READY;
      return true;
    }
  return false;
}

/*_________________---------------------------__________________
  _________________       SFLOWUS_close       __________________
  -----------------___________________________------------------
*/

bool
SFLOWUS_close (SFLOWUS *ust)
{
  return (sflow_netlink_close (&ust->nl) == 0);
}

/*_________________---------------------------__________________
  _________________  SFLOWUS_set_msg_type     __________________
  -----------------___________________________------------------
*/

bool
SFLOWUS_set_msg_type (SFLOWUS *ust, EnumSFlowVppMsgType msgType)
{
  ust->nl.nlh.nlmsg_type = msgType;
  return true;
}

/*_________________---------------------------__________________
  _________________    SFLOWUS_open_step      __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWUS_open_step (SFLOWUS *ust)
{
  switch (ust->nl.state)
    {
    case SFLOWNL_STATE_UNDEFINED:
      SFLOWUS_init (ust);
      break;
    case SFLOWNL_STATE_INIT:
      SFLOWUS_open (ust);
      break;
    case SFLOWNL_STATE_OPEN:
    case SFLOWNL_STATE_WAIT_FAMILY:
    case SFLOWNL_STATE_READY:
      break;
    }
  return ust->nl.state;
}

/*_________________---------------------------__________________
  _________________    SFLOWUS_set_attr       __________________
  -----------------___________________________------------------
*/

bool
SFLOWUS_set_attr (SFLOWUS *ust, EnumSFlowVppAttributes field, void *val,
		  int len)
{
  return sflow_netlink_set_attr (&ust->nl, field, val, len);
}

/*_________________---------------------------__________________
  _________________        SFLOWUS_send       __________________
  -----------------___________________________------------------
*/

int
SFLOWUS_send (SFLOWUS *ust)
{
  int status = sflow_netlink_send_attrs (&ust->nl, false);
  sflow_netlink_reset_attrs (&ust->nl);
  if (status <= 0)
    {
      // Linux replies with ECONNREFUSED when
      // a multicast is sent via NETLINK_USERSOCK, but
      // it's not an error so we can just ignore it here.
      if (errno != ECONNREFUSED)
	{
	  SFLOW_DBG ("USERSOCK strerror(errno) = %s\n", strerror (errno));
	  return -1;
	}
    }
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
