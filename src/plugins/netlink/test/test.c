/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <librtnl/netns.h>

#include <vnet/plugin/plugin.h>
#include <librtnl/mapper.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>

u32 handles[10];

static void
test_notify(void *obj, netns_type_t type, u32 flags, uword opaque) {
  u32 index = (u32) opaque;
  const char *action = (flags & NETNS_F_ADD)?"add":(flags & NETNS_F_DEL)?"del":"mod";

  switch (type) {
    case NETNS_TYPE_ADDR:
      clib_warning("%d: addr %s %U", index, action, format_ns_addr, (ns_addr_t *)obj);
      break;
    case NETNS_TYPE_ROUTE:
      clib_warning("%d: route %s %U", index, action, format_ns_route, (ns_route_t *)obj);
      break;
    case NETNS_TYPE_LINK:
      clib_warning("%d:link %s %U", index, action, format_ns_link, (ns_link_t *)obj);
      break;
    case NETNS_TYPE_NEIGH:
      clib_warning("%d: neigh %s %U", index, action, format_ns_neigh, (ns_neigh_t *)obj);
      break;
  }
}

static clib_error_t *
test_enable_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
  char *nsname = 0;
  u32 index;
  if (!unformat(input, "%s", &nsname)) {
    return clib_error_return(0, "unknown input `%U'",
                             format_unformat_error, input);
  }
  if (!unformat(input, "%d", &index)) {
    return clib_error_return(0, "unknown input `%U'",
                             format_unformat_error, input);
  }

  if (!strcmp(nsname, "default"))
    nsname[0] = 0;

  netns_sub_t sub;
  sub.notify = test_notify;
  sub.opaque = index;
  handles[index] = netns_open(nsname, &sub);
  if (handles[index] == ~0) {
    return clib_error_create("Could not open netns with name %s", nsname);
  }
  return 0;
}

static clib_error_t *
test_disable_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  u32 index;
  if (!unformat(input, "%d", &index)) {
    return clib_error_return(0, "unknown input `%U'",
                             format_unformat_error, input);
  }

  netns_close(handles[index]);
  return 0;
}

VLIB_CLI_COMMAND (rtnl_enable_command, static) = {
    .path = "test netns enable",
    .short_help = "test netns enable [<ns-name>|default] <index>",
    .function = test_enable_command_fn,
};

VLIB_CLI_COMMAND (rtnl_disable_command, static) = {
    .path = "test netns disable",
    .short_help = "test rtnl disable <index>",
    .function = test_disable_command_fn,
};

u32 mapper_indexes[10];

static clib_error_t *
mapper_ns_add_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  u32 index;
  char *nsname;
  u32 table_id;
  if (!unformat(input, "%d", &index))
    return clib_error_return(0, "invalid index `%U'",
                             format_unformat_error, input);
  if (!unformat(input, "%s", &nsname))
    return clib_error_return(0, "invalid nsname `%U'",
                             format_unformat_error, input);
  if (!unformat(input, "%d", &table_id))
      return clib_error_return(0, "invalid fib index `%U'",
                               format_unformat_error, input);

  if (!strcmp(nsname, "default"))
    nsname[0] = 0;

  u32 fib4 = ip4_fib_index_from_table_id(table_id);
  u32 fib6 = ip6_fib_index_from_table_id(table_id);

  if (mapper_add_ns(nsname, fib4, fib6, &mapper_indexes[index]))
    return clib_error_return(0, "Could not add ns %s", nsname);
  return 0;
}

VLIB_CLI_COMMAND (mapper_ns_add_command, static) = {
    .path = "test mapper ns add",
    .short_help = "test mapper ns add <index> <nsname> <table-id>",
    .function = mapper_ns_add_command_fn,
};

static clib_error_t *
mapper_ns_del_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  u32 index;
  if (!unformat(input, "%d", &index))
    return clib_error_return(0, "invalid index `%U'",
                             format_unformat_error, input);

  if (mapper_del_ns(mapper_indexes[index]))
    return clib_error_return(0, "Could not del ns %d", index);
  return 0;
}

VLIB_CLI_COMMAND (mapper_ns_del_command, static) = {
    .path = "test mapper ns delete",
    .short_help = "test mapper ns delete <index>",
    .function = mapper_ns_del_command_fn,
};

static clib_error_t *
mapper_iface_command_fn (vlib_main_t * vm,
                         unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  u32 nsindex;
  u32 ifindex;
  u32 sw_if_index;
  int del = 0;
  if (!unformat(input, "%d", &nsindex))
    return clib_error_return(0, "invalid nsindex `%U'",
                             format_unformat_error, input);
  if (!unformat(input, "%d", &ifindex))
    return clib_error_return(0, "invalid ifindex `%U'",
                             format_unformat_error, input);
  if (!unformat(input, "%d", &sw_if_index))
    return clib_error_return(0, "invalid sw_if_index `%U'",
                             format_unformat_error, input);
  if (unformat(input, "del"))
    del = 1;

  clib_warning("mapper_add_del %d %d %d %d", mapper_indexes[nsindex], ifindex, sw_if_index, del);

  if (mapper_add_del(mapper_indexes[nsindex], ifindex, sw_if_index, del))
    return clib_error_return(0, "Could not add iface");
  return 0;
}


VLIB_CLI_COMMAND (mapper_iface_command, static) = {
    .path = "test mapper iface",
    .short_help = "test mapper iface <nsindex> <linux-ifindex> <sw_if_index> [del]",
    .function = mapper_iface_command_fn,
};

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  //.version = VPP_BUILD_VER, FIXME
  .description = "netlink",
};
/* *INDENT-ON* */

