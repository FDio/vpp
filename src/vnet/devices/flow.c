/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

static format_function_t format_device_flow;

void
vnet_device_flow_register_cb (vnet_device_flow_type_t type,
			      vnet_device_flow_cb_t * fn)
{
  vnet_device_main_t *dm = &device_main;
  vec_validate (dm->flow_callbacks, type);
  vec_add1 (dm->flow_callbacks[type], fn);
}

void
vnet_device_flow_add (vnet_device_flow_t * flow)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f;
  u32 i;

  if (pool_elts (dm->flows) == 0)
    {
      pool_get (dm->flows, f);
      f->type = VNET_DEVICE_FLOW_TYPE_UNKNOWN;
    }

  pool_get (dm->flows, f);
  flow->id = f - dm->flows;
  clib_memcpy (f, flow, sizeof (vnet_device_flow_t));

  vec_foreach_index (i, dm->flow_callbacks[flow->type])
    (*dm->flow_callbacks[flow->type][i]) (VNET_DEVICE_FLOW_ADD, f);
}

void
vnet_device_flow_del (u32 flow_id)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f = pool_elt_at_index (dm->flows, flow_id);;
  u32 i;

  vec_foreach_index (i, dm->flow_callbacks[f->type])
    (*dm->flow_callbacks[f->type][i]) (VNET_DEVICE_FLOW_DEL, f);

  memset (f, 0, sizeof (*f));
  pool_put (dm->flows, f);
}


static clib_error_t *
show_device_flow (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f;

  const char * flow_type_strings[] = { 0,
#define _(a,b,c) c,
      foreach_device_flow_type
#undef _
  };

  vlib_cli_output (vm, "%5s  %-15s  %s", "ID", "Type", "Description");
  pool_foreach (f, dm->flows,
    {
      if (f->type == VNET_DEVICE_FLOW_TYPE_UNKNOWN)
        continue;
      vlib_cli_output (vm, "%5u  %-15s  %U", f->id, flow_type_strings[f->type],
		       format_device_flow, f);
    });

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_device_flow_command, static) = {
    .path = "show device flow",
    .short_help = "show device flow",
    .function = show_device_flow,
};

/*
 *  TO BE REMOVED
 */
/* *INDENT-ON* */

static clib_error_t *
test_device_flow (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  vnet_device_flow_t flow = { 0 };

  flow.type = VNET_DEVICE_FLOW_TYPE_IP4_VXLAN;
  flow.ip4_vxlan.src_addr.as_u32 = 0x0a000001;
  flow.ip4_vxlan.dst_addr.as_u32 = 0x0a000101;
  flow.ip4_vxlan.src_port = 1111;
  flow.ip4_vxlan.dst_port = 2222;
  flow.ip4_vxlan.vni = 1234;
  vnet_device_flow_add (&flow);

  flow.type = VNET_DEVICE_FLOW_TYPE_IP6_VXLAN;
  flow.ip6_vxlan.src_addr.as_u64[0] = clib_host_to_net_u64 (0x20010001UL <<32);
  flow.ip6_vxlan.src_addr.as_u64[1] = clib_host_to_net_u64 (1);
  flow.ip6_vxlan.dst_addr.as_u64[0] = clib_host_to_net_u64 (0x20010002UL <<32);
  flow.ip6_vxlan.dst_addr.as_u64[1] = clib_host_to_net_u64 (1);
  flow.ip6_vxlan.src_port = 3333;
  flow.ip6_vxlan.dst_port = 4444;
  flow.ip6_vxlan.vni = 2345;
  vnet_device_flow_add (&flow);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_device_flow_command, static) = {
    .path = "test device flow",
    .short_help = "test device flow",
    .function = test_device_flow,
};
/* *INDENT-ON* */


static u8 *
format_device_flow_entry (u8 * s, va_list * args)
{
  char * type = va_arg (*args, char *);
  void * ptr = va_arg (*args, void *);

  if (strncmp (type, "u8", 2) == 0)
    return format (s, "%d", * (u8 *) ptr);

  if (strncmp (type, "u16", 3) == 0)
    return format (s, "%d", * (u16 *) ptr);

  if (strncmp (type, "u32", 3) == 0)
    return format (s, "%d", * (u32 *) ptr);

  if (strncmp (type, "ip4_address_t", 13) == 0)
    return format (s, "%U", format_ip4_address, ptr);

  if (strncmp (type, "ip6_address_t", 13) == 0)
    return format (s, "%U", format_ip6_address, ptr);

  s = format (s, "unknown type '%s'", type);
  return s;
}

#define _fe(a,b) s2 = format (s2, "%s%s %U", s2 ? ", ":"", #b, \
			      format_device_flow_entry, #a, &f->b);
#define _(a,b,c) \
u8 * format_device_flow_##b (u8 * s, va_list * args)			\
{									\
  vnet_device_flow_##b##_t *f = __builtin_va_arg (*args, vnet_device_flow_##b##_t *); \
  u8 *s2 = 0; \
foreach_device_flow_entry_##b \
  s = format (s, "%v", s2);; \
  vec_free (s2); \
return s; \
}
foreach_device_flow_type
#undef _
#undef _fe

static u8 *
format_device_flow (u8 *s, va_list * args)
{
  vnet_device_flow_t *f = va_arg (*args, vnet_device_flow_t *);

#define _(a,b,c) \
  if (f->type == VNET_DEVICE_FLOW_TYPE_##a) \
    return format (s, "%U", format_device_flow_##b, &f->b);
  foreach_device_flow_type;
#undef _

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
