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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/devices/netlink.h>

typedef struct
{
  u8 *data;
} vnet_netlink_msg_t;

static void
vnet_netlink_msg_init (vnet_netlink_msg_t * m, u16 type, u16 flags,
		       void *msg_data, int msg_len)
{
  struct nlmsghdr *nh;
  u8 *p;
  clib_memset (m, 0, sizeof (vnet_netlink_msg_t));
  vec_add2 (m->data, p, NLMSG_SPACE (msg_len));
  ASSERT (m->data == p);

  nh = (struct nlmsghdr *) p;
  nh->nlmsg_flags = flags | NLM_F_ACK;
  nh->nlmsg_type = type;
  clib_memcpy (m->data + sizeof (struct nlmsghdr), msg_data, msg_len);
}

static void
vnet_netlink_msg_add_rtattr (vnet_netlink_msg_t * m, u16 rta_type,
			     void *rta_data, int rta_data_len)
{
  struct rtattr *rta;
  u8 *p;

  vec_add2 (m->data, p, RTA_SPACE (rta_data_len));
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
  int len, sock;
  struct nlmsghdr *nh = (struct nlmsghdr *) m->data;
  nh->nlmsg_len = vec_len (m->data);
  char buf[4096];

  if ((sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    return clib_error_return_unix (0, "socket(AF_NETLINK)");

  ra.nl_family = AF_NETLINK;
  ra.nl_pid = 0;

  if ((bind (sock, (struct sockaddr *) &ra, sizeof (ra))) == -1)
    {
      err = clib_error_return_unix (0, "bind");
      goto done;
    }

  if ((send (sock, m->data, vec_len (m->data), 0)) == -1)
    err = clib_error_return_unix (0, "send");

  if ((len = recv (sock, buf, sizeof (buf), 0)) == -1)
    err = clib_error_return_unix (0, "recv");

  for (nh = (struct nlmsghdr *) buf; NLMSG_OK (nh, len);
       nh = NLMSG_NEXT (nh, len))
    {
      if (nh->nlmsg_type == NLMSG_DONE)
	goto done;

      if (nh->nlmsg_type == NLMSG_ERROR)
	{
	  struct nlmsgerr *e = (struct nlmsgerr *) NLMSG_DATA (nh);
	  if (e->error)
	    err = clib_error_return (0, "netlink error %d", e->error);
	  goto done;
	}
    }

done:
  close (sock);
  vec_free (m->data);
  return err;
}

clib_error_t *
vnet_netlink_set_link_name (int ifindex, char *new_ifname)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  ifmsg.ifi_index = ifindex;
  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));

  vnet_netlink_msg_add_rtattr (&m, IFLA_IFNAME, new_ifname,
			       strlen (new_ifname) + 1);

  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_set_link_netns (int ifindex, int netns_fd, char *new_ifname)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  ifmsg.ifi_index = ifindex;
  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));

  vnet_netlink_msg_add_rtattr (&m, IFLA_NET_NS_FD, &netns_fd, sizeof (int));
  if (new_ifname)
    vnet_netlink_msg_add_rtattr (&m, IFLA_IFNAME, new_ifname,
				 strlen (new_ifname) + 1);

  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_set_link_master (int ifindex, char *master_ifname)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };
  int i;

  ifmsg.ifi_index = ifindex;

  if ((i = if_nametoindex (master_ifname)) == 0)
    clib_error_return_unix (0, "unknown master interface '%s'",
			    master_ifname);

  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));
  vnet_netlink_msg_add_rtattr (&m, IFLA_MASTER, &i, sizeof (int));
  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_set_link_addr (int ifindex, u8 * mac)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  ifmsg.ifi_index = ifindex;

  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));
  vnet_netlink_msg_add_rtattr (&m, IFLA_ADDRESS, mac, 6);
  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_set_link_state (int ifindex, int up)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  ifmsg.ifi_flags = IFF_UP;
  ifmsg.ifi_change = IFF_UP;
  ifmsg.ifi_index = ifindex;

  vnet_netlink_msg_init (&m, RTM_SETLINK, NLM_F_REQUEST,
			 &ifmsg, sizeof (struct ifinfomsg));
  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_set_link_mtu (int ifindex, int mtu)
{
  vnet_netlink_msg_t m;
  struct ifinfomsg ifmsg = { 0 };

  ifmsg.ifi_index = ifindex;

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

clib_error_t *
vnet_netlink_add_ip4_route (void *dst, u8 dst_len, void *gw)
{
  vnet_netlink_msg_t m;
  struct rtmsg rtm = { 0 };
  u8 dflt[4] = { 0 };

  rtm.rtm_family = AF_INET;
  rtm.rtm_table = RT_TABLE_MAIN;
  rtm.rtm_type = RTN_UNICAST;
  rtm.rtm_dst_len = dst_len;

  vnet_netlink_msg_init (&m, RTM_NEWROUTE,
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
			 &rtm, sizeof (struct rtmsg));

  vnet_netlink_msg_add_rtattr (&m, RTA_GATEWAY, gw, 4);
  vnet_netlink_msg_add_rtattr (&m, RTA_DST, dst ? dst : dflt, 4);
  return vnet_netlink_msg_send (&m);
}

clib_error_t *
vnet_netlink_add_ip6_route (void *dst, u8 dst_len, void *gw)
{
  vnet_netlink_msg_t m;
  struct rtmsg rtm = { 0 };
  u8 dflt[16] = { 0 };

  rtm.rtm_family = AF_INET6;
  rtm.rtm_table = RT_TABLE_MAIN;
  rtm.rtm_type = RTN_UNICAST;
  rtm.rtm_dst_len = dst_len;

  vnet_netlink_msg_init (&m, RTM_NEWROUTE,
			 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
			 &rtm, sizeof (struct rtmsg));

  vnet_netlink_msg_add_rtattr (&m, RTA_GATEWAY, gw, 16);
  vnet_netlink_msg_add_rtattr (&m, RTA_DST, dst ? dst : dflt, 16);
  return vnet_netlink_msg_send (&m);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
