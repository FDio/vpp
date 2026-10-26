/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Intel Corporation
 */

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <string.h>
#include <unistd.h>

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_src.h>

#include "fcp_route.h"

extern u32 fcp_phy_for_host (u32 host_if_index);

static vlib_log_class_t fcp_route_logger;

#define FCP_ROUTE_DBG(...)  vlib_log_debug (fcp_route_logger, __VA_ARGS__)
#define FCP_ROUTE_INFO(...) vlib_log_info (fcp_route_logger, __VA_ARGS__)
#define FCP_ROUTE_WARN(...) vlib_log_warn (fcp_route_logger, __VA_ARGS__)

static fib_source_t fcp_route_source;
static int fcp_processing;

int
fcp_route_processing (void)
{
  return fcp_processing;
}

static int
fcp_parse_addrs (u8 *data, u8 *end, u32 bits, struct sockaddr **addrs)
{
  for (u32 index = 0; index < RTAX_MAX; index++)
    {
      addrs[index] = NULL;
      if (!(bits & (1 << index)))
	continue;
      if (end - data < 2)
	return -1;
      struct sockaddr *addr = (struct sockaddr *) data;
      uword size = SA_SIZE (addr);
      if (size > end - data || addr->sa_len > size || (addr->sa_len && addr->sa_len < 2))
	return -1;
      addrs[index] = addr;
      data += size;
    }
  return 0;
}

static int
fcp_sockaddr_ip (const struct sockaddr *addr, ip_address_t *ip)
{
  if (!addr)
    return -1;
  if (addr->sa_family == AF_INET && addr->sa_len >= sizeof (struct sockaddr_in))
    {
      ip_address_set (ip, &((const struct sockaddr_in *) addr)->sin_addr, AF_IP4);
      return 0;
    }
  if (addr->sa_family == AF_INET6 && addr->sa_len >= sizeof (struct sockaddr_in6))
    {
      ip_address_set (ip, &((const struct sockaddr_in6 *) addr)->sin6_addr, AF_IP6);
      return 0;
    }
  return -1;
}

static u32
fcp_mask_length (const struct sockaddr *mask, int family)
{
  u32 size = family == AF_INET ? 4 : 16;
  u8 bytes[16] = {};
  uword offset = family == AF_INET ? offsetof (struct sockaddr_in, sin_addr) :
				     offsetof (struct sockaddr_in6, sin6_addr);

  if (!mask)
    return size * 8;
  if (mask->sa_len > offset)
    clib_memcpy_fast (bytes, (const u8 *) mask + offset, clib_min (size, mask->sa_len - offset));
  u32 length = 0;
  for (u32 index = 0; index < size; index++)
    for (int bit = 7; bit >= 0; bit--)
      if (bytes[index] & (1 << bit))
	length++;
      else
	return length;
  return length;
}

static void
fcp_route_message (u8 *data, uword size, u32 only_host, int removing)
{
  struct rt_msghdr *header = (struct rt_msghdr *) data;
  struct sockaddr *addrs[RTAX_MAX];
  u32 host_index, phy_index, bits;
  u8 *payload;
  ip_address_t destination = {};
  int is_addr;

  if (size < 4 || header->rtm_version != RTM_VERSION || header->rtm_msglen != size)
    return;
  if (header->rtm_type == RTM_IFINFO)
    {
      struct if_msghdr *info = (struct if_msghdr *) data;
      if (!removing && !only_host && size >= sizeof (*info))
	{
	  u32 phy = fcp_phy_for_host (info->ifm_index);
	  if (phy != ~0)
	    {
	      u32 flags = (info->ifm_flags & IFF_UP) ? VNET_SW_INTERFACE_FLAG_ADMIN_UP : 0;
	      FCP_ROUTE_INFO ("admin_state_change: %U flags %u", format_vnet_sw_if_index_name,
			      vnet_get_main (), phy, flags);
	      vnet_sw_interface_set_flags (vnet_get_main (), phy, flags);
	    }
	}
      return;
    }
  is_addr = header->rtm_type == RTM_NEWADDR || header->rtm_type == RTM_DELADDR;
  if (is_addr)
    {
      struct ifa_msghdr *ifa = (struct ifa_msghdr *) data;
      if (size < sizeof (*ifa))
	return;
      host_index = ifa->ifam_index;
      bits = ifa->ifam_addrs;
      payload = data + sizeof (*ifa);
    }
  else if (header->rtm_type == RTM_ADD || header->rtm_type == RTM_DELETE ||
	   header->rtm_type == RTM_CHANGE || header->rtm_type == RTM_GET)
    {
      if (size < sizeof (*header) || header->rtm_errno)
	return;
      host_index = header->rtm_index;
      bits = header->rtm_addrs;
      payload = data + sizeof (*header);
    }
  else
    return;

  if (only_host && host_index != only_host)
    return;
  phy_index = fcp_phy_for_host (host_index);
  if (phy_index == ~0 || fcp_parse_addrs (payload, data + size, bits, addrs) ||
      fcp_sockaddr_ip (addrs[is_addr ? RTAX_IFA : RTAX_DST], &destination))
    return;

  ip_address_family_t family = ip_addr_version (&destination);
  int af = family == AF_IP4 ? AF_INET : AF_INET6;
  int is_del = removing || header->rtm_type == RTM_DELETE || header->rtm_type == RTM_DELADDR;

  if (is_addr)
    {
      u32 prefix = fcp_mask_length (addrs[RTAX_NETMASK], af);
      FCP_ROUTE_DBG ("ip%c_addr_%s: %U %U/%u", family == AF_IP4 ? '4' : '6', is_del ? "del" : "add",
		     format_vnet_sw_if_index_name, vnet_get_main (), phy_index, format_ip_address,
		     &destination, prefix);
      fcp_processing++;
      if (family == AF_IP4)
	ip4_add_del_interface_address (vlib_get_main (), phy_index, &ip_addr_v4 (&destination),
				       prefix, is_del);
      else if (ip6_address_is_link_local_unicast (&ip_addr_v6 (&destination)))
	{
	  if (is_del)
	    ip6_link_disable (phy_index);
	  else
	    {
	      ip6_link_enable (phy_index, NULL);
	      ip6_link_set_local_address (phy_index, &ip_addr_v6 (&destination));
	    }
	}
      else
	ip6_add_del_interface_address (vlib_get_main (), phy_index, &ip_addr_v6 (&destination),
				       prefix, is_del);
      fcp_processing--;
      return;
    }

  if (header->rtm_flags & RTF_LLDATA)
    {
      struct sockaddr_dl *link = (struct sockaddr_dl *) addrs[RTAX_GATEWAY];
      if (!link || link->sdl_family != AF_LINK || link->sdl_alen != sizeof (mac_address_t) ||
	  link->sdl_len < offsetof (struct sockaddr_dl, sdl_data) + link->sdl_nlen + link->sdl_alen)
	return;
      if (is_del)
	{
	  FCP_ROUTE_DBG ("neighbor del: %U on %U", format_ip_address, &destination,
			 format_vnet_sw_if_index_name, vnet_get_main (), phy_index);
	  ip_neighbor_del (&destination, phy_index);
	}
      else
	{
	  mac_address_t mac;
	  clib_memcpy_fast (&mac, LLADDR (link), sizeof (mac));
	  FCP_ROUTE_DBG ("neighbor add: %U %U on %U", format_ip_address, &destination,
			 format_mac_address, &mac, format_vnet_sw_if_index_name, vnet_get_main (),
			 phy_index);
	  ip_neighbor_add (&destination, &mac, phy_index,
			   (header->rtm_flags & RTF_STATIC) ? IP_NEIGHBOR_FLAG_STATIC :
							      IP_NEIGHBOR_FLAG_DYNAMIC,
			   NULL);
	}
      return;
    }

  if (header->rtm_flags & (RTF_LOCAL | RTF_BROADCAST | RTF_MULTICAST))
    return;
  if (!(header->rtm_flags & RTF_GATEWAY))
    return;

  fib_prefix_t prefix = {
    .fp_proto = family == AF_IP4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6,
    .fp_len = (header->rtm_flags & RTF_HOST) ? (family == AF_IP4 ? 32 : 128) :
					       fcp_mask_length (addrs[RTAX_NETMASK], af),
    .fp_addr = ip_addr_46 (&destination),
  };
  u32 fib_index = fib_table_get_index_for_sw_if_index (prefix.fp_proto, phy_index);
  if (fib_index == ~0)
    return;
  if (is_del)
    {
      FCP_ROUTE_DBG ("route del: %U on %U", format_fib_prefix, &prefix,
		     format_vnet_sw_if_index_name, vnet_get_main (), phy_index);
      fib_table_entry_delete (fib_index, &prefix, fcp_route_source);
      return;
    }
  ip_address_t gateway = {};
  if (fcp_sockaddr_ip (addrs[RTAX_GATEWAY], &gateway) || ip_addr_version (&gateway) != family)
    return;
  FCP_ROUTE_DBG ("route add: %U via %U on %U", format_fib_prefix, &prefix, format_ip_address,
		 &gateway, format_vnet_sw_if_index_name, vnet_get_main (), phy_index);
  fib_route_path_t *paths = NULL;
  fib_route_path_t path_entry = {
    .frp_proto = fib_proto_to_dpo (prefix.fp_proto),
    .frp_addr = ip_addr_46 (&gateway),
    .frp_sw_if_index = phy_index,
    .frp_fib_index = ~0,
    .frp_weight = 1,
  };
  vec_add1 (paths, path_entry);
  fib_table_entry_update (fib_index, &prefix, fcp_route_source, FIB_ENTRY_FLAG_NONE, paths);
  vec_free (paths);
}

static void
fcp_route_messages (u8 *data, uword size, u32 only_host, int removing)
{
  while (size >= 4)
    {
      struct rt_msghdr *header = (struct rt_msghdr *) data;
      if (header->rtm_msglen < 4 || header->rtm_msglen > size)
	break;
      fcp_route_message (data, header->rtm_msglen, only_host, removing);
      size -= header->rtm_msglen;
      data += header->rtm_msglen;
    }
}

static void
fcp_route_snapshot (u32 host_index, int removing)
{
  for (u32 index = 0; index < 4; index++)
    {
      int mib[] = { CTL_NET,
		    PF_ROUTE,
		    0,
		    index >= 2 ? (index == 2 ? AF_INET : AF_INET6) : AF_UNSPEC,
		    index == 0 ? NET_RT_IFLIST :
		    index == 1 ? NET_RT_DUMP :
				 NET_RT_FLAGS,
		    index >= 2 ? RTF_LLINFO : 0 };
      size_t size = 0;
      if (sysctl (mib, ARRAY_LEN (mib), NULL, &size, NULL, 0) || !size)
	continue;
      u8 *data = clib_mem_alloc (size);
      if (!sysctl (mib, ARRAY_LEN (mib), data, &size, NULL, 0))
	fcp_route_messages (data, size, host_index, removing);
      clib_mem_free (data);
    }
}

void
fcp_route_dump (u32 host_index)
{
  fcp_route_snapshot (host_index, 0);
}

void
fcp_route_cleanup (u32 host_index)
{
  fcp_route_snapshot (host_index, 1);
}

static clib_error_t *
fcp_route_read_ready (clib_file_t *file)
{
  u8 data[65536];
  ssize_t length;
  while ((length = read (file->file_descriptor, data, sizeof (data))) > 0)
    fcp_route_messages (data, length, 0, 0);
  return NULL;
}

static clib_error_t *
fcp_route_init (vlib_main_t *vm)
{
  fcp_route_logger = vlib_log_register_class ("freebsd-cp", "route");
  int fd = socket (PF_ROUTE, SOCK_RAW | SOCK_NONBLOCK, 0);
  if (fd < 0)
    {
      FCP_ROUTE_WARN ("routing socket: %s", strerror (errno));
      return clib_error_return_unix (0, "freebsd-cp routing socket");
    }
  fcp_route_source = fib_source_allocate ("freebsd-cp", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);
  clib_file_t file = {
    .file_descriptor = fd,
    .read_function = fcp_route_read_ready,
    .description = format (0, "freebsd-cp routing socket"),
  };
  clib_file_add (&file_main, &file);
  return NULL;
}
VLIB_INIT_FUNCTION (fcp_route_init);
