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

#include <sflow/sflow_netlink.h>

/*_________________---------------------------__________________
  _________________       fcntl utils         __________________
  -----------------___________________________------------------
*/

void
sflow_netlink_set_nonblocking (int fd)
{
  // set the socket to non-blocking
  int fdFlags = fcntl (fd, F_GETFL);
  fdFlags |= O_NONBLOCK;
  if (fcntl (fd, F_SETFL, fdFlags) < 0)
    {
      SFLOW_ERR ("fcntl(O_NONBLOCK) failed: %s\n", strerror (errno));
    }
}

void
sflow_netlink_set_close_on_exec (int fd)
{
  // make sure it doesn't get inherited, e.g. when we fork a script
  int fdFlags = fcntl (fd, F_GETFD);
  fdFlags |= FD_CLOEXEC;
  if (fcntl (fd, F_SETFD, fdFlags) < 0)
    {
      SFLOW_ERR ("fcntl(F_SETFD=FD_CLOEXEC) failed: %s\n", strerror (errno));
    }
}

int
sflow_netlink_set_send_buffer (int fd, int requested)
{
  int txbuf = 0;
  socklen_t txbufsiz = sizeof (txbuf);
  if (getsockopt (fd, SOL_SOCKET, SO_SNDBUF, &txbuf, &txbufsiz) < 0)
    {
      SFLOW_ERR ("getsockopt(SO_SNDBUF) failed: %s", strerror (errno));
    }
  if (txbuf < requested)
    {
      txbuf = requested;
      if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &txbuf, sizeof (txbuf)) < 0)
	{
	  SFLOW_WARN ("setsockopt(SO_TXBUF=%d) failed: %s", requested,
		      strerror (errno));
	}
      // see what we actually got
      txbufsiz = sizeof (txbuf);
      if (getsockopt (fd, SOL_SOCKET, SO_SNDBUF, &txbuf, &txbufsiz) < 0)
	{
	  SFLOW_ERR ("getsockopt(SO_SNDBUF) failed: %s", strerror (errno));
	}
    }
  return txbuf;
}

/*_________________---------------------------__________________
  _________________       generic_pid         __________________
  -----------------___________________________------------------
  choose a 32-bit id that is likely to be unique even if more
  than one module in this process wants to bind a netlink socket
*/

u32
sflow_netlink_generic_pid (u32 mod_id)
{
  return ((mod_id << 16) + getpid ());
}

/*_________________---------------------------__________________
  _________________       generic_open        __________________
  -----------------___________________________------------------
*/

int
sflow_netlink_generic_open (SFLOWNL *nl)
{
  nl->nl_sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (nl->nl_sock < 0)
    {
      SFLOW_ERR ("nl_sock open failed: %s\n", strerror (errno));
      return -1;
    }
  // bind to a suitable id
  struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
			    .nl_pid = sflow_netlink_generic_pid (nl->id) };
  if (bind (nl->nl_sock, (struct sockaddr *) &sa, sizeof (sa)) < 0)
    {
      SFLOW_ERR ("sflow_netlink_generic_open: bind failed: sa.nl_pid=%u "
		 "sock=%d id=%d: %s\n",
		 sa.nl_pid, nl->nl_sock, nl->id, strerror (errno));
    }
  sflow_netlink_set_nonblocking (nl->nl_sock);
  sflow_netlink_set_close_on_exec (nl->nl_sock);
  sflow_netlink_set_send_buffer (nl->nl_sock, SFLOWNL_SND_BUF);
  nl->state = SFLOWNL_STATE_OPEN;
  return nl->nl_sock;
}

/*_________________---------------------------__________________
  _________________      usersock_open        __________________
  -----------------___________________________------------------
*/

int
sflow_netlink_usersock_open (SFLOWNL *nl)
{
  nl->nl_sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
  if (nl->nl_sock < 0)
    {
      SFLOW_ERR ("nl_sock open failed: %s\n", strerror (errno));
      return -1;
    }
  sflow_netlink_set_nonblocking (nl->nl_sock);
  sflow_netlink_set_close_on_exec (nl->nl_sock);
  nl->state = SFLOWNL_STATE_OPEN;
  return nl->nl_sock;
}

/*_________________---------------------------__________________
  _________________        close              __________________
  -----------------___________________________------------------
*/

int
sflow_netlink_close (SFLOWNL *nl)
{
  int err = 0;
  if (nl->nl_sock > 0)
    {
      err = close (nl->nl_sock);
      if (err == 0)
	{
	  nl->nl_sock = 0;
	}
      else
	{
	  SFLOW_ERR ("sflow_netlink_close: returned %d : %s\n", err,
		     strerror (errno));
	}
    }
  nl->state = SFLOWNL_STATE_INIT;
  return err;
}

/*_________________---------------------------__________________
  _________________        set_attr           __________________
  -----------------___________________________------------------
*/

bool
sflow_netlink_set_attr (SFLOWNL *nl, int field, void *val, int len)
{
  SFLOWNLAttr *psa = &nl->attr[field];
  if (psa->included)
    return false;
  psa->included = true;
  psa->attr.nla_type = field;
  psa->attr.nla_len = sizeof (psa->attr) + len;
  int len_w_pad = NLMSG_ALIGN (len);
  psa->val.iov_len = len_w_pad;
  psa->val.iov_base = val;
  nl->n_attrs++;
  nl->attrs_len += sizeof (psa->attr);
  nl->attrs_len += len_w_pad;
  return true;
}

/*_________________---------------------------__________________
  _________________     generic_send_cmd      __________________
  -----------------___________________________------------------
*/

int
sflow_netlink_generic_send_cmd (int sockfd, u32 mod_id, int type, int cmd,
				int req_type, void *req, int req_len,
				int req_footprint, u32 seqNo)
{
  struct nlmsghdr nlh = {};
  struct genlmsghdr ge = {};
  struct nlattr attr = {};

  attr.nla_len = sizeof (attr) + req_len;
  attr.nla_type = req_type;

  ge.cmd = cmd;
  ge.version = 1;

  nlh.nlmsg_len = NLMSG_LENGTH (req_footprint + sizeof (attr) + sizeof (ge));
  nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh.nlmsg_type = type;
  nlh.nlmsg_seq = seqNo;
  nlh.nlmsg_pid = sflow_netlink_generic_pid (mod_id);

  struct iovec iov[4] = { { .iov_base = &nlh, .iov_len = sizeof (nlh) },
			  { .iov_base = &ge, .iov_len = sizeof (ge) },
			  { .iov_base = &attr, .iov_len = sizeof (attr) },
			  { .iov_base = req, .iov_len = req_footprint } };

  struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
  struct msghdr msg = { .msg_name = &sa,
			.msg_namelen = sizeof (sa),
			.msg_iov = iov,
			.msg_iovlen = 4 };
  return sendmsg (sockfd, &msg, 0);
}

/*_________________---------------------------__________________
  _________________       send_attrs          __________________
  -----------------___________________________------------------
*/

int
sflow_netlink_send_attrs (SFLOWNL *nl, bool ge)
{
  if (ge)
    {
      nl->nlh.nlmsg_len = NLMSG_LENGTH (sizeof (nl->ge) + nl->attrs_len);
      nl->nlh.nlmsg_type = nl->family_id;
      nl->nlh.nlmsg_pid = sflow_netlink_generic_pid (nl->id);
    }
  else
    {
      nl->nlh.nlmsg_len = NLMSG_LENGTH (nl->attrs_len);
      nl->nlh.nlmsg_pid = getpid ();
    }

  nl->nlh.nlmsg_flags = 0;
  nl->nlh.nlmsg_seq = ++nl->nl_seq;

  struct iovec *iov = nl->iov;
  u32 frag = 0;
  iov[frag].iov_base = &nl->nlh;
  iov[frag].iov_len = sizeof (nl->nlh);
  frag++;
  if (ge)
    {
      iov[frag].iov_base = &nl->ge;
      iov[frag].iov_len = sizeof (nl->ge);
      frag++;
    }
  int nn = 0;
  for (u32 ii = 0; ii <= nl->attr_max; ii++)
    {
      SFLOWNLAttr *psa = &nl->attr[ii];
      if (psa->included)
	{
	  nn++;
	  iov[frag].iov_base = &psa->attr;
	  iov[frag].iov_len = sizeof (psa->attr);
	  frag++;
	  iov[frag] = psa->val; // struct copy
	  frag++;
	}
    }
  ASSERT (nn == nl->n_attrs);

  struct sockaddr_nl da = { .nl_family = AF_NETLINK,
			    .nl_groups = (1 << (nl->group_id - 1)) };

  struct msghdr msg = { .msg_name = &da,
			.msg_namelen = sizeof (da),
			.msg_iov = iov,
			.msg_iovlen = frag };

  return sendmsg (nl->nl_sock, &msg, 0);
}

/*_________________---------------------------__________________
  _________________       reset_attrs         __________________
  -----------------___________________________------------------
*/

void
sflow_netlink_reset_attrs (SFLOWNL *nl)
{
  for (u32 ii = 0; ii <= nl->attr_max; ii++)
    nl->attr[ii].included = false;
  nl->n_attrs = 0;
  nl->attrs_len = 0;
}

/*_________________---------------------------__________________
  _________________   generic_get_family      __________________
  -----------------___________________________------------------
*/

void
sflow_netlink_generic_get_family (SFLOWNL *nl)
{
  int status = sflow_netlink_generic_send_cmd (
    nl->nl_sock, nl->id, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
    CTRL_ATTR_FAMILY_NAME, nl->family_name, nl->family_len,
    NLMSG_ALIGN (nl->family_len), ++nl->nl_seq);
  if (status >= 0)
    nl->state = SFLOWNL_STATE_WAIT_FAMILY;
}

/*_________________---------------------------__________________
  _________________       generic_read        __________________
  -----------------___________________________------------------
*/

void
sflow_netlink_generic_read (SFLOWNL *nl, struct nlmsghdr *nlh)
{
  char *msg = (char *) NLMSG_DATA (nlh);
  int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
  struct genlmsghdr *genl = (struct genlmsghdr *) msg;
  SFLOW_DBG ("generic netlink CMD = %u\n", genl->cmd);

  for (int offset = GENL_HDRLEN; offset < msglen;)
    {
      struct nlattr *attr = (struct nlattr *) (msg + offset);
      if (attr->nla_len == 0 || (attr->nla_len + offset) > msglen)
	{
	  SFLOW_ERR ("processNetlink_GENERIC attr parse error\n");
	  break; // attr parse error
	}
      char *attr_datap = (char *) attr + NLA_HDRLEN;
      switch (attr->nla_type)
	{
	case CTRL_ATTR_VERSION:
	  nl->genetlink_version = *(u32 *) attr_datap;
	  break;
	case CTRL_ATTR_FAMILY_ID:
	  nl->family_id = *(u16 *) attr_datap;
	  SFLOW_DBG ("generic family id: %u\n", nl->family_id);
	  break;
	case CTRL_ATTR_FAMILY_NAME:
	  SFLOW_DBG ("generic family name: %s\n", attr_datap);
	  break;
	case CTRL_ATTR_MCAST_GROUPS:
	  for (int grp_offset = NLA_HDRLEN; grp_offset < attr->nla_len;)
	    {
	      struct nlattr *grp_attr =
		(struct nlattr *) (msg + offset + grp_offset);
	      if (grp_attr->nla_len == 0 ||
		  (grp_attr->nla_len + grp_offset) > attr->nla_len)
		{
		  SFLOW_ERR ("processNetlink_GENERIC grp_attr parse error\n");
		  break;
		}
	      char *grp_name = NULL;
	      u32 grp_id = 0;
	      for (int gf_offset = NLA_HDRLEN; gf_offset < grp_attr->nla_len;)
		{
		  struct nlattr *gf_attr =
		    (struct nlattr *) (msg + offset + grp_offset + gf_offset);
		  if (gf_attr->nla_len == 0 ||
		      (gf_attr->nla_len + gf_offset) > grp_attr->nla_len)
		    {
		      SFLOW_ERR (
			"processNetlink_GENERIC gf_attr parse error\n");
		      break;
		    }
		  char *grp_attr_datap = (char *) gf_attr + NLA_HDRLEN;
		  switch (gf_attr->nla_type)
		    {
		    case CTRL_ATTR_MCAST_GRP_NAME:
		      grp_name = grp_attr_datap;
		      SFLOW_DBG ("netlink multicast group: %s\n", grp_name);
		      break;
		    case CTRL_ATTR_MCAST_GRP_ID:
		      grp_id = *(u32 *) grp_attr_datap;
		      SFLOW_DBG ("netlink multicast group id: %u\n", grp_id);
		      break;
		    }
		  gf_offset += NLMSG_ALIGN (gf_attr->nla_len);
		}
	      if (nl->group_id == 0 && grp_name &&
		  (((nl->join_group_id != 0) && grp_id == nl->join_group_id) ||
		   ((nl->join_group_name != NULL) &&
		    !strcmp (grp_name, nl->join_group_name))))
		{
		  SFLOW_DBG ("netlink found group %s=%u\n", grp_name, grp_id);
		  nl->group_id = grp_id;
		  // We don't need to actually join the group if we
		  // are only sending to it.
		}

	      grp_offset += NLMSG_ALIGN (grp_attr->nla_len);
	    }
	  break;
	default:
	  SFLOW_DBG ("netlink attr type: %u (nested=%u) len: %u\n",
		     attr->nla_type, attr->nla_type & NLA_F_NESTED,
		     attr->nla_len);
	  break;
	}
      offset += NLMSG_ALIGN (attr->nla_len);
    }
  if (nl->family_id && nl->group_id)
    {
      SFLOW_DBG ("netlink state->READY\n");
      nl->state = SFLOWNL_STATE_READY;
    }
}

/*_________________---------------------------__________________
  _________________   sflow_netlink_read      __________________
  -----------------___________________________------------------
*/

void
sflow_netlink_read (SFLOWNL *nl)
{
  uint8_t recv_buf[SFLOWNL_RCV_BUF];
  memset (recv_buf, 0, SFLOWNL_RCV_BUF); // for coverity
  int numbytes = recv (nl->nl_sock, recv_buf, sizeof (recv_buf), 0);
  if (numbytes <= 0)
    {
      SFLOW_ERR ("sflow_netlink_read returned %d : %s\n", numbytes,
		 strerror (errno));
      return;
    }
  struct nlmsghdr *nlh = (struct nlmsghdr *) recv_buf;
  while (NLMSG_OK (nlh, numbytes))
    {
      if (nlh->nlmsg_type == NLMSG_DONE)
	break;
      if (nlh->nlmsg_type == NLMSG_ERROR)
	{
	  struct nlmsgerr *err_msg = (struct nlmsgerr *) NLMSG_DATA (nlh);
	  if (err_msg->error == 0)
	    {
	      SFLOW_DBG ("received Netlink ACK\n");
	    }
	  else
	    {
	      SFLOW_ERR ("error in netlink message: %d : %s\n", err_msg->error,
			 strerror (-err_msg->error));
	    }
	  return;
	}
      if (nlh->nlmsg_type == NETLINK_GENERIC)
	{
	  sflow_netlink_generic_read (nl, nlh);
	}
      else if (nlh->nlmsg_type == nl->family_id)
	{
	  // We are write-only, don't need to read these.
	}
      nlh = NLMSG_NEXT (nlh, numbytes);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
