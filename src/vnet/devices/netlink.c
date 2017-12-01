/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/virtio_net.h>
#include <linux/vhost.h>
#include <sys/eventfd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

clib_error_t *
vnet_netlink_set_if_attr (int ifindex, unsigned short rta_type, void *data,
			  int data_len)
{
  clib_error_t *err = 0;
  int sock;
  struct sockaddr_nl ra = { 0 };
  struct
  {
    struct nlmsghdr nh;
    struct ifinfomsg ifmsg;
    char attrbuf[512];
  } req;
  struct rtattr *rta;

  memset (&req, 0, sizeof (req));
  if ((sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    return clib_error_return_unix (0, "socket(AF_NETLINK)");

  ra.nl_family = AF_NETLINK;
  ra.nl_pid = getpid ();

  if ((bind (sock, (struct sockaddr *) &ra, sizeof (ra))) == -1)
    {
      err = clib_error_return_unix (0, "bind");
      goto error;
    }

  req.nh.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifinfomsg));
  req.nh.nlmsg_flags = NLM_F_REQUEST;
  req.nh.nlmsg_type = RTM_SETLINK;
  req.ifmsg.ifi_family = AF_UNSPEC;
  req.ifmsg.ifi_index = ifindex;
  req.ifmsg.ifi_change = 0xffffffff;
  rta = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN (req.nh.nlmsg_len));
  rta->rta_type = rta_type;
  rta->rta_len = RTA_LENGTH (data_len);
  req.nh.nlmsg_len = NLMSG_ALIGN (req.nh.nlmsg_len) + RTA_LENGTH (data_len);
  memcpy (RTA_DATA (rta), data, data_len);

  if ((send (sock, &req, req.nh.nlmsg_len, 0)) == -1)
    err = clib_error_return_unix (0, "send");

error:
  close (sock);
  return err;
}

clib_error_t *
vnet_netlink_set_if_mtu (int ifindex, int mtu)
{
  clib_error_t *err;

  err = vnet_netlink_set_if_attr (ifindex, IFLA_MTU, &mtu, sizeof (int));
  return err;
}

clib_error_t *
vnet_netlink_set_if_namespace (int ifindex, char *net_ns)
{
  clib_error_t *err;
  int ns_fd;
  u8 *s;
  s = format (0, "/var/run/netns/%s%c", net_ns, 0);
  ns_fd = open ((char *) s, O_RDONLY);
  vec_free (s);
  if (ns_fd == -1)
    return clib_error_return (0, "namespace '%s' doesn't exist", net_ns);

  err =
    vnet_netlink_set_if_attr (ifindex, IFLA_NET_NS_FD, &ns_fd, sizeof (int));
  close (ns_fd);
  return err;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
