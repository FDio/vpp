/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <plugins/linux-cp/lcp_interface.h>
#include <plugins/linux-cp/lcp_nl.h>
#include <netlink/route/nexthop.h>

static clib_error_t *
lcp_test_route_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  enum
  {
    VALID,
    DESTINATION,
    GATEWAY_FIRST,
    GATEWAY_LAST,
    SOURCE
  } fault = VALID;
  const nl_vft_t *vft;
  struct rtnl_route *route = NULL;
  struct rtnl_nexthop *nh = NULL;
  struct nl_addr *addr = NULL;
  clib_error_t *error = NULL;
  u32 phy = ~0, table = ~0;
  int family = 0, operation = -1, width, rv;
  u8 bytes[17] = {};
  index_t pair;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "phy %u", &phy))
	;
      else if (unformat (input, "table %u", &table))
	;
      else if (unformat (input, "ip4"))
	family = AF_INET;
      else if (unformat (input, "ip6"))
	family = AF_INET6;
      else if (unformat (input, "add"))
	operation = 0;
      else if (unformat (input, "replace"))
	operation = 1;
      else if (unformat (input, "del"))
	operation = 2;
      else if (unformat (input, "valid"))
	fault = VALID;
      else if (unformat (input, "destination"))
	fault = DESTINATION;
      else if (unformat (input, "gateway-first"))
	fault = GATEWAY_FIRST;
      else if (unformat (input, "gateway-last"))
	fault = GATEWAY_LAST;
      else if (unformat (input, "source"))
	fault = SOURCE;
      else
	return clib_error_return (0, "unknown input: %U", format_unformat_error, input);
    }

  if (phy == ~0 || table == ~0 || !family || operation < 0)
    return clib_error_return (0, "phy, table, address family and operation are required");
  if (fault == SOURCE && (family != AF_INET6 || operation == 2))
    return clib_error_return (0, "source fixture requires IPv6 add or replace");
  pair = lcp_itf_pair_find_by_phy (phy);
  if (pair == INDEX_INVALID)
    return clib_error_return (0, "interface has no LCP pair");
  if (lcp_itf_pair_find_by_vif (lcp_itf_pair_get (pair)->lip_vif_index) != pair)
    return clib_error_return (0, "LCP pair is outside the default namespace");
  vft = vlib_get_plugin_symbol ("linux_nl_plugin.so", "lcp_router_vft");
  if (!vft || !vft->nvl_rt_route_add.cb || !vft->nvl_rt_route_del.cb)
    return clib_error_return (0, "linux-nl route callbacks unavailable");

  width = family == AF_INET ? 4 : 16;
  route = rtnl_route_alloc ();
  if (!route)
    goto allocation_failed;
  if ((rv = rtnl_route_set_family (route, family)) < 0 ||
      (rv = rtnl_route_set_type (route, fault == SOURCE ? RTN_MULTICAST : RTN_UNICAST)) < 0)
    goto fixture_failed;
  rtnl_route_set_table (route, table);
  rtnl_route_set_protocol (route, RTPROT_STATIC);
  addr = nl_addr_build (family, bytes, width + (fault == DESTINATION));
  if (!addr)
    goto allocation_failed;
  nl_addr_set_prefixlen (addr, 0);
  if ((rv = rtnl_route_set_dst (route, addr)) < 0)
    goto fixture_failed;
  nl_addr_put (addr);
  addr = NULL;

  if (fault == SOURCE)
    {
      addr = nl_addr_build (family, bytes, width + 1);
      if (!addr)
	goto allocation_failed;
      nl_addr_set_prefixlen (addr, width * 8);
      if ((rv = rtnl_route_set_src (route, addr)) < 0)
	goto fixture_failed;
      nl_addr_put (addr);
      addr = NULL;
    }

  for (int i = 0; i < 2; i++)
    {
      bool oversized = (fault == GATEWAY_FIRST && i == 0) || (fault == GATEWAY_LAST && i == 1);
      clib_memset (bytes, 0, sizeof (bytes));
      if (family == AF_INET)
	{
	  bytes[0] = 192;
	  bytes[2] = 2;
	}
      else
	{
	  bytes[0] = 0x20;
	  bytes[1] = 1;
	  bytes[2] = 0x0d;
	  bytes[3] = 0xb8;
	}
      bytes[width - 1] = i + 1;
      addr = nl_addr_build (family, bytes, width + oversized);
      nh = rtnl_route_nh_alloc ();
      if (!addr || !nh)
	goto allocation_failed;
      rtnl_route_nh_set_ifindex (nh, lcp_itf_pair_get (pair)->lip_vif_index);
      rtnl_route_nh_set_gateway (nh, addr);
      rtnl_route_add_nexthop (route, nh);
      nh = NULL;
      nl_addr_put (addr);
      addr = NULL;
    }

  if (operation == 2)
    vft->nvl_rt_route_del.cb (route);
  else
    vft->nvl_rt_route_add.cb (route, operation == 1);
  goto done;

allocation_failed:
  error = clib_error_return (0, "libnl fixture allocation failed");
  goto done;
fixture_failed:
  error = clib_error_return (0, "libnl fixture rejected: %d", rv);
done:
  if (addr)
    nl_addr_put (addr);
  if (nh)
    rtnl_route_nh_free (nh);
  if (route)
    rtnl_route_put (route);
  return error;
}

VLIB_CLI_COMMAND (lcp_test_route, static) = {
  .path = "test lcp route",
  .short_help = "test lcp route phy <index> table <id> ip4|ip6 add|replace|del "
		"valid|destination|gateway-first|gateway-last|source",
  .function = lcp_test_route_command,
};
