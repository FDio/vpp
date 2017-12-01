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

typedef struct
{
  u8 *data;
} vnet_netlink_msg_t;

void
vnet_netlink_msg_init (vnet_netlink_msg_t * m, u16 type, u16 flags,
		       void *msg_data, int msg_len)
{
  struct nlmsghdr *nh;
  u8 *p;
  int len = NLMSG_LENGTH (msg_len);
  memset (m, 0, sizeof (vnet_netlink_msg_t));
  vec_add2 (m->data, p, len);
  ASSERT (m->data == p);

  nh = (struct nlmsghdr *) p;
  nh->nlmsg_flags = flags;
  nh->nlmsg_type = type;
  clib_memcpy (m->data + sizeof (struct nlmsghdr), msg_data, msg_len);
}

static void
vnet_netlink_msg_add_rtattr (vnet_netlink_msg_t * m, u16 rta_type,
			     void *rta_data, int rta_data_len)
{
  struct rtattr *rta;
  u8 *p;

  vec_add2 (m->data, p, RTA_LENGTH (rta_data_len));
  rta = (struct rtattr *) p;
  rta->rta_type = rta_type;
  rta->rta_len = RTA_LENGTH (rta_data_len);
  clib_memcpy (RTA_DATA (rta), rta_data, rta_data_len);
}

static clib_error_t *
vnet_netlink_msg_send (vnet_netlink_msg_t * m)
{
  clib_error_t *err = 0;
  struct sockaddr_nl ra = { 0 };
  int sock;
  struct nlmsghdr *nh = (struct nlmsghdr *) m->data;
  nh->nlmsg_len = vec_len (m->data);

  if ((sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    return clib_error_return_unix (0, "socket(AF_NETLINK)");

  ra.nl_family = AF_NETLINK;
  ra.nl_pid = getpid ();

  if ((bind (sock, (struct sockaddr *) &ra, sizeof (ra))) == -1)
    {
      err = clib_error_return_unix (0, "bind");
      goto error;
    }

  if ((send (sock, m->data, vec_len (m->data), 0)) == -1)
    err = clib_error_return_unix (0, "send");

error:
  close (sock);
  vec_free (m->data);
  return err;
}

clib_error_t *
vnet_netlink_set_if_namespace (int ifindex, char *net_ns)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  clib_error_t *err;
  int data;
  u16 type;
  u8 *s;

  if (strncmp (net_ns, "pid:", 4) == 0)
    {
      data = atoi (net_ns + 4);
      type = IFLA_NET_NS_PID;
    }
  else
    {
      if (net_ns[0] == '/')
	s = format (0, "%s%c", net_ns, 0);
      else
	s = format (0, "/var/run/netns/%s%c", net_ns, 0);

      data = open ((char *) s, O_RDONLY);
      type = IFLA_NET_NS_FD;
      vec_free (s);
      if (data == -1)
	return clib_error_return (0, "namespace '%s' doesn't exist", net_ns);
    }

  ifmsg.ifi_family = AF_UNSPEC;
  ifmsg.ifi_index = ifindex;
  ifmsg.ifi_change = 0xffffffff;
  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));

  vnet_netlink_msg_add_rtattr (&m, type, &data, sizeof (int));
  err = vnet_netlink_msg_send (&m);

  if (type == IFLA_NET_NS_FD)
    close (data);
  return err;
}

clib_error_t *
vnet_netlink_set_if_master (int ifindex, int master_ifindex)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  ifmsg.ifi_family = AF_UNSPEC;
  ifmsg.ifi_index = ifindex;
  ifmsg.ifi_change = 0xffffffff;
  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));
  vnet_netlink_msg_add_rtattr (&m, IFLA_MASTER, &master_ifindex,
			       sizeof (int));
  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_set_if_mtu (int ifindex, int mtu)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  ifmsg.ifi_family = AF_UNSPEC;
  ifmsg.ifi_index = ifindex;
  ifmsg.ifi_change = 0xffffffff;
  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));
  vnet_netlink_msg_add_rtattr (&m, IFLA_MTU, &mtu, sizeof (int));
  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_add_ip4_addr (int ifindex, void *addr, int pfx_len)
{
  vnet_netlink_msg_t m;
  struct ifaddrmsg ifa = { 0 };

  ifa.ifa_family = AF_INET;
  ifa.ifa_prefixlen = pfx_len;
  ifa.ifa_index = ifindex;

  vnet_netlink_msg_init (&m, RTM_NEWADDR,
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
			 &ifa, sizeof (struct ifaddrmsg));

  vnet_netlink_msg_add_rtattr (&m, IFA_LOCAL, addr, 4);
  vnet_netlink_msg_add_rtattr (&m, IFA_ADDRESS, addr, 4);
  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_add_ip6_addr (int ifindex, void *addr, int pfx_len)
{
  vnet_netlink_msg_t m;
  struct ifaddrmsg ifa = { 0 };

  ifa.ifa_family = AF_INET6;
  ifa.ifa_prefixlen = pfx_len;
  ifa.ifa_index = ifindex;

  vnet_netlink_msg_init (&m, RTM_NEWADDR,
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
			 &ifa, sizeof (struct ifaddrmsg));

  vnet_netlink_msg_add_rtattr (&m, IFA_LOCAL, addr, 16);
  vnet_netlink_msg_add_rtattr (&m, IFA_ADDRESS, addr, 16);
  return vnet_netlink_msg_send (&m);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
