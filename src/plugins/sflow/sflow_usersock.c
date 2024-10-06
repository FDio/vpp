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

#if defined(__cplusplus)
extern "C"
{
#endif

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

#include <sflow/sflow_usersock.h>

  /*_________________---------------------------__________________
    _________________       fcntl utils         __________________
    -----------------___________________________------------------
  */

  static void
  setNonBlocking (int fd)
  {
    // set the socket to non-blocking
    int fdFlags = fcntl (fd, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if (fcntl (fd, F_SETFL, fdFlags) < 0)
      {
	SFLOW_ERR ("fcntl(O_NONBLOCK) failed: %s\n", strerror (errno));
      }
  }

  static void
  setCloseOnExec (int fd)
  {
    // make sure it doesn't get inherited, e.g. when we fork a script
    int fdFlags = fcntl (fd, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if (fcntl (fd, F_SETFD, fdFlags) < 0)
      {
	SFLOW_ERR ("fcntl(F_SETFD=FD_CLOEXEC) failed: %s\n", strerror (errno));
      }
  }

  /*_________________---------------------------__________________
    _________________       usersock_open       __________________
    -----------------___________________________------------------
  */

  static int
  usersock_open (void)
  {
    int nl_sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (nl_sock < 0)
      {
	SFLOW_ERR ("nl_sock open failed: %s\n", strerror (errno));
	return -1;
      }
    // bind does not seem necessary (for sender)
    // bind to a suitable id
    // struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_pid = getpid() };
    // if(bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    //  clib_warning("usersock_open: bind failed: %s\n", strerror(errno));
    setNonBlocking (nl_sock);
    setCloseOnExec (nl_sock);
    return nl_sock;
  }

  /*_________________---------------------------__________________
    _________________       SFLOWUS_open        __________________
    -----------------___________________________------------------
  */

  bool
  SFLOWUS_open (SFLOWUS *ust)
  {
    if (ust->nl_sock == 0)
      {
	ust->nl_sock = usersock_open ();
      }
    return true;
  }

  /*_________________---------------------------__________________
    _________________       SFLOWUS_close       __________________
    -----------------___________________________------------------
  */

  bool
  SFLOWUS_close (SFLOWUS *ust)
  {
    if (ust->nl_sock != 0)
      {
	int err = close (ust->nl_sock);
	if (err == 0)
	  {
	    ust->nl_sock = 0;
	    return true;
	  }
	else
	  {
	    SFLOW_WARN ("SFLOWUS_close: returned %d : %s\n", err,
			strerror (errno));
	  }
      }
    return false;
  }

  /*_________________---------------------------__________________
    _________________  SFLOWUSSpec_setMsgType   __________________
    -----------------___________________________------------------
  */

  bool
  SFLOWUSSpec_setMsgType (SFLOWUSSpec *spec, EnumSFlowVppMsgType msgType)
  {
    spec->nlh.nlmsg_type = msgType;
    return true;
  }

  /*_________________---------------------------__________________
    _________________    SFLOWUSSpec_setAttr    __________________
    -----------------___________________________------------------
  */

  bool
  SFLOWUSSpec_setAttr (SFLOWUSSpec *spec, EnumSFlowVppAttributes field,
		       void *val, int len)
  {
    SFLOWUSAttr *usa = &spec->attr[field];
    if (usa->included)
      return false;
    usa->included = true;
    usa->attr.nla_type = field;
    usa->attr.nla_len = sizeof (usa->attr) + len;
    int len_w_pad = NLMSG_ALIGN (len);
    usa->val.iov_len = len_w_pad;
    usa->val.iov_base = val;
    spec->n_attrs++;
    spec->attrs_len += sizeof (usa->attr);
    spec->attrs_len += len_w_pad;
    return true;
  }

  /*_________________---------------------------__________________
    _________________    SFLOWUSSpec_send       __________________
    -----------------___________________________------------------
  */

  int
  SFLOWUSSpec_send (SFLOWUS *ust, SFLOWUSSpec *spec)
  {
    spec->nlh.nlmsg_len = NLMSG_LENGTH (spec->attrs_len);
    spec->nlh.nlmsg_flags = 0;
    spec->nlh.nlmsg_seq = ++ust->nl_seq;
    spec->nlh.nlmsg_pid = getpid ();

#define MAX_IOV_FRAGMENTS (2 * __SFLOW_VPP_ATTR_MAX) + 2

    struct iovec iov[MAX_IOV_FRAGMENTS];
    u32 frag = 0;
    iov[frag].iov_base = &spec->nlh;
    iov[frag].iov_len = sizeof (spec->nlh);
    frag++;
    int nn = 0;
    for (u32 ii = 0; ii < __SFLOW_VPP_ATTR_MAX; ii++)
      {
	SFLOWUSAttr *usa = &spec->attr[ii];
	if (usa->included)
	  {
	    nn++;
	    iov[frag].iov_base = &usa->attr;
	    iov[frag].iov_len = sizeof (usa->attr);
	    frag++;
	    iov[frag] = usa->val; // struct copy
	    frag++;
	  }
      }
    ASSERT (nn == spec->n_attrs);

    struct sockaddr_nl da = {
      .nl_family = AF_NETLINK,
      .nl_groups = (1 << (ust->group_id - 1)) // for multicast to the group
      // .nl_pid = 1e9+6343 // for unicast to receiver bound to netlink socket
      // with that "pid"
    };

    struct msghdr msg = { .msg_name = &da,
			  .msg_namelen = sizeof (da),
			  .msg_iov = iov,
			  .msg_iovlen = frag };

    int status = sendmsg (ust->nl_sock, &msg, 0);
    // clib_warning("sendmsg returned %d\n", status);
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
