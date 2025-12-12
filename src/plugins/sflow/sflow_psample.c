/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 InMon Corp.
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
#include <linux/psample.h>
#include <signal.h>
#include <ctype.h>

#include <sflow/sflow_netlink.h>
#include <sflow/sflow_psample.h>

/*_________________---------------------------__________________
  _________________       SFLOWPS_init        __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWPS_init (SFLOWPS *pst)
{
  pst->nl.id = SFLOWNL_PSAMPLE;
  memset (pst->fam_name, 0, SFLOWPS_FAM_FOOTPRINT);
  memcpy (pst->fam_name, SFLOWPS_FAM, SFLOWPS_FAM_LEN);
  pst->nl.family_name = pst->fam_name;
  pst->nl.family_len = SFLOWPS_FAM_LEN;
  pst->nl.join_group_name = PSAMPLE_NL_MCGRP_SAMPLE_NAME;
  pst->nl.attr = pst->attr;
  pst->nl.attr_max = __SFLOWPS_PSAMPLE_ATTRS - 1;
  pst->nl.iov = pst->iov;
  pst->nl.iov_max = SFLOWPS_IOV_FRAGS - 1;
  pst->nl.state = SFLOWNL_STATE_INIT;
  return pst->nl.state;
}

/*_________________---------------------------__________________
  _________________       SFLOWPS_open        __________________
  -----------------___________________________------------------
*/

bool
SFLOWPS_open (SFLOWPS *pst)
{
  if (pst->nl.state == SFLOWNL_STATE_UNDEFINED)
    SFLOWPS_init (pst);
  if (pst->nl.nl_sock == 0)
    {
      pst->nl.nl_sock = sflow_netlink_generic_open (&pst->nl);
      if (pst->nl.nl_sock > 0)
	sflow_netlink_generic_get_family (&pst->nl);
    }
  return (pst->nl.nl_sock > 0);
}

/*_________________---------------------------__________________
  _________________       SFLOWPS_close       __________________
  -----------------___________________________------------------
*/

bool
SFLOWPS_close (SFLOWPS *pst)
{
  return (sflow_netlink_close (&pst->nl) == 0);
}

/*_________________---------------------------__________________
  _________________       SFLOWPS_state       __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWPS_state (SFLOWPS *pst)
{
  return pst->nl.state;
}

/*_________________---------------------------__________________
  _________________    SFLOWPS_open_step      __________________
  -----------------___________________________------------------
*/

EnumSFLOWNLState
SFLOWPS_open_step (SFLOWPS *pst)
{
  switch (pst->nl.state)
    {
    case SFLOWNL_STATE_UNDEFINED:
      SFLOWPS_init (pst);
      break;
    case SFLOWNL_STATE_INIT:
      SFLOWPS_open (pst);
      break;
    case SFLOWNL_STATE_OPEN:
      sflow_netlink_generic_get_family (&pst->nl);
      break;
    case SFLOWNL_STATE_WAIT_FAMILY:
      sflow_netlink_read (&pst->nl);
      break;
    case SFLOWNL_STATE_READY:
      break;
    }
  return pst->nl.state;
}

/*_________________---------------------------__________________
  _________________    SFLOWPS_set_attr       __________________
  -----------------___________________________------------------
*/

bool
SFLOWPS_set_attr (SFLOWPS *pst, EnumSFLOWPSAttributes field, void *val,
		  int len)
{
  int expected_len = SFLOWPS_Fields[field].len;
  if (expected_len && expected_len != len)
    {
      SFLOW_ERR ("SFLOWPS_set_attr(%s) length=%u != expected: %u\n",
		 SFLOWPS_Fields[field].descr, len, expected_len);
      return false;
    }
  return sflow_netlink_set_attr (&pst->nl, field, val, len);
}

/*_________________---------------------------__________________
  _________________        SFLOWPS_send       __________________
  -----------------___________________________------------------
*/

int
SFLOWPS_send (SFLOWPS *pst)
{
  pst->nl.ge.cmd = PSAMPLE_CMD_SAMPLE;
  pst->nl.ge.version = PSAMPLE_GENL_VERSION;
  int status = sflow_netlink_send_attrs (&pst->nl, true);
  sflow_netlink_reset_attrs (&pst->nl);
  if (status <= 0)
    {
      SFLOW_ERR ("PSAMPLE strerror(errno) = %s; errno = %d\n",
		 strerror (errno), errno);
    }
  return status;
}
