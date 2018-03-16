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
vnet_device_flow_register_cb (u32 hw_if_index, vnet_device_flow_cb_t * fn)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_hw_if_t *hwif;

  vec_validate (dm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (dm->interfaces, hw_if_index);

  ASSERT (hwif->callback == 0);
  hwif->callback = fn;
}

u32
vnet_device_flow_request_range (u32 n_entries)
{
  vnet_device_main_t *dm = &device_main;
  u32 rv = dm->flows_used;
  dm->flows_used += n_entries;
  return rv;
}

void
vnet_device_flow_add (vnet_device_flow_t * flow)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f;
  uword *p;
  u32 flow_index;

  ASSERT (flow->id < dm->flows_used);

  p = hash_get (dm->global_flow_pool_index_by_flow_id, flow->id);
  ASSERT (p == 0);

  pool_get (dm->global_flow_pool, f);
  flow_index = f - dm->global_flow_pool;
  clib_memcpy (f, flow, sizeof (vnet_device_flow_t));
  hash_set (dm->global_flow_pool_index_by_flow_id, flow->id, flow_index);
}

static vnet_device_flow_t *
vnet_device_get_flow (u32 flow_id)
{
  vnet_device_main_t *dm = &device_main;
  uword *p;

  p = hash_get (dm->global_flow_pool_index_by_flow_id, flow_id);
  ASSERT (p != 0);
  return pool_elt_at_index (dm->global_flow_pool, p[0]);
}

void
vnet_device_flow_del (u32 flow_id)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f = vnet_device_get_flow (flow_id);
  uword hw_if_index;

  clib_bitmap_foreach(hw_if_index, f->hw_if_bmp,
    ({
     vnet_device_flow_disable (flow_id, hw_if_index);
    }));

  clib_bitmap_free (f->hw_if_bmp);
  memset (f, 0, sizeof (*f));
  pool_put (dm->global_flow_pool, f);
}

void
vnet_device_flow_enable (u32 flow_id, u32 hw_if_index)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f = vnet_device_get_flow (flow_id);
  vnet_device_flow_hw_if_t *hwif;
  u32 flow_index, *fidp;

  vec_validate (dm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (dm->interfaces, hw_if_index);

  /* avoid using flow 0 */
  if (pool_elts (hwif->flows) == 0)
    pool_get (hwif->flows, fidp);

  pool_get (hwif->flows, fidp);
  flow_index = hwif->flows - fidp;
  *fidp = flow_id;

  hash_set (hwif->flow_index_by_flow_id, flow_id, flow_index);

  /* don't enable flow twice */
  ASSERT (clib_bitmap_get (f->hw_if_bmp, hw_if_index) == 0);

  f->hw_if_bmp = clib_bitmap_set (f->hw_if_bmp, hw_if_index, 1);

  if (hwif->callback)
    hwif->callback (VNET_DEVICE_FLOW_ADD, f, hw_if_index, flow_index);
}

void
vnet_device_flow_disable (u32 flow_id, u32 hw_if_index)
{
  vnet_device_main_t *dm = &device_main;
  vnet_device_flow_t *f = vnet_device_get_flow (flow_id);
  vnet_device_flow_hw_if_t *hwif;
  uword *p;

  vec_validate (dm->interfaces, hw_if_index);
  hwif = vec_elt_at_index (dm->interfaces, hw_if_index);

  /* don't disable if not enabled */
  ASSERT (clib_bitmap_get (f->hw_if_bmp, hw_if_index) == 0);

  f->hw_if_bmp = clib_bitmap_set (f->hw_if_bmp, hw_if_index, 0);

  p = hash_get (hwif->flow_index_by_flow_id, flow_id);
  ASSERT (p != 0);

  if (hwif->callback)
    hwif->callback (VNET_DEVICE_FLOW_DEL, f, hw_if_index, p[0]);

  pool_put_index (hwif->flows, p[0]);
  hash_unset (hwif->flow_index_by_flow_id, flow_id);
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
  pool_foreach (f, dm->global_flow_pool,
    {
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
  vnet_device_flow_request_range (1000);
  u32 start = vnet_device_flow_request_range (1024);

  flow.type = VNET_DEVICE_FLOW_TYPE_IP4_VXLAN;
  flow.ip4_vxlan.src_addr.as_u32 = 0x0a000001;
  flow.ip4_vxlan.dst_addr.as_u32 = 0x0a000101;
  flow.ip4_vxlan.src_port = 1111;
  flow.ip4_vxlan.dst_port = 2222;
  flow.ip4_vxlan.vni = 1234;
  flow.id = start++;
  vnet_device_flow_add (&flow);
  vnet_device_flow_enable (flow.id, 0);

  flow.type = VNET_DEVICE_FLOW_TYPE_IP6_VXLAN;
  flow.ip6_vxlan.src_addr.as_u64[0] =
    clib_host_to_net_u64 (0x20010001UL << 32);
  flow.ip6_vxlan.src_addr.as_u64[1] = clib_host_to_net_u64 (1);
  flow.ip6_vxlan.dst_addr.as_u64[0] =
    clib_host_to_net_u64 (0x20010002UL << 32);
  flow.ip6_vxlan.dst_addr.as_u64[1] = clib_host_to_net_u64 (1);
  flow.ip6_vxlan.src_port = 3333;
  flow.ip6_vxlan.dst_port = 4444;
  flow.ip6_vxlan.vni = 2345;
  flow.id = start++;
  vnet_device_flow_add (&flow);
  vnet_device_flow_enable (flow.id, 0);

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
  char *type = va_arg (*args, char *);
  void *ptr = va_arg (*args, void *);

  if (strncmp (type, "u8", 2) == 0)
    return format (s, "%d", *(u8 *) ptr);

  if (strncmp (type, "u16", 3) == 0)
    return format (s, "%d", *(u16 *) ptr);

  if (strncmp (type, "u32", 3) == 0)
    return format (s, "%d", *(u32 *) ptr);

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
format_device_flow (u8 * s, va_list * args)
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
