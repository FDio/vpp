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
/**
 * @file
 * @brief NAT66 implementation
 */

#include <nat/nat66/nat66.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/reass/ip6_sv_reass.h>

nat66_main_t nat66_main;

/* Hook up input features */
VNET_FEATURE_INIT (nat66_in2out, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat66-in2out",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = VNET_FEATURES ("ip6-sv-reassembly-feature"),
};
VNET_FEATURE_INIT (nat66_out2in, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat66-out2in",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = VNET_FEATURES ("ip6-sv-reassembly-feature"),
};

clib_error_t *nat66_plugin_api_hookup (vlib_main_t * vm);

#define fail_if_enabled()                                                     \
  do                                                                          \
    {                                                                         \
      nat66_main_t *nm = &nat66_main;                                         \
      if (PREDICT_FALSE (nm->enabled))                                        \
	{                                                                     \
	  nat66_elog_warn ("plugin enabled");                                 \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

#define fail_if_disabled()                                                    \
  do                                                                          \
    {                                                                         \
      nat66_main_t *nm = &nat66_main;                                         \
      if (PREDICT_FALSE (!nm->enabled))                                       \
	{                                                                     \
	  nat66_elog_warn ("plugin disabled");                                \
	  return 1;                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

static clib_error_t *
nat66_init (vlib_main_t * vm)
{
  nat66_main_t *nm = &nat66_main;

  clib_memset (nm, 0, sizeof (*nm));

  nm->session_counters.name = "session counters";
  nm->in2out_packets.name = "in2out";
  nm->in2out_packets.stat_segment_name = "/nat64/in2out";
  nm->out2in_packets.name = "out2in";
  nm->out2in_packets.stat_segment_name = "/nat64/out2in";

  nm->nat_fib_src_hi = fib_source_allocate ("nat66-hi", FIB_SOURCE_PRIORITY_HI,
					    FIB_SOURCE_BH_SIMPLE);
  return nat66_plugin_api_hookup (vm);
}

int
nat66_plugin_enable (u32 outside_vrf)
{
  nat66_main_t *nm = &nat66_main;

  u32 static_mapping_buckets = 1024;
  uword static_mapping_memory_size = 64 << 20;

  fail_if_enabled ();

  clib_bihash_init_24_8 (&nm->sm_l, "nat66-static-map-by-local",
			 static_mapping_buckets, static_mapping_memory_size);
  clib_bihash_init_24_8 (&nm->sm_e, "nat66-static-map-by-external",
			 static_mapping_buckets, static_mapping_memory_size);

  nm->outside_vrf_id = outside_vrf;
  nm->outside_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP6, outside_vrf, nm->nat_fib_src_hi);
  nm->enabled = 1;
  return 0;
}

int
nat66_plugin_disable ()
{
  nat66_main_t *nm = &nat66_main;
  nat66_interface_t *i, *temp;
  int error = 0;

  temp = pool_dup (nm->interfaces);
  pool_foreach (i, temp)
    {
      if (nat66_interface_is_inside (i))
	error = nat66_interface_add_del (i->sw_if_index, 1, 0);

      if (nat66_interface_is_outside (i))
	error = nat66_interface_add_del (i->sw_if_index, 0, 0);

      if (error)
	{
	  nat66_elog_warn ("error occurred while removing interface");
	}
    }
  pool_free (temp);
  pool_free (nm->interfaces);

  pool_free (nm->sm);
  clib_bihash_free_24_8 (&nm->sm_l);
  clib_bihash_free_24_8 (&nm->sm_e);

  nm->interfaces = 0;
  nm->sm = 0;

  vlib_clear_combined_counters (&nm->session_counters);
  vlib_clear_simple_counters (&nm->in2out_packets);
  vlib_clear_simple_counters (&nm->out2in_packets);

  nm->enabled = 0;
  return error;
}

static void
nat66_validate_counters (nat66_main_t * nm, u32 sw_if_index)
{
  vlib_validate_simple_counter (&nm->in2out_packets, sw_if_index);
  vlib_zero_simple_counter (&nm->in2out_packets, sw_if_index);
  vlib_validate_simple_counter (&nm->out2in_packets, sw_if_index);
  vlib_zero_simple_counter (&nm->out2in_packets, sw_if_index);
}

int
nat66_interface_add_del (u32 sw_if_index, u8 is_inside, u8 is_add)
{
  nat66_main_t *nm = &nat66_main;
  nat66_interface_t *interface = 0, *i;
  const char *feature_name;

  fail_if_disabled ();

  pool_foreach (i, nm->interfaces)
   {
    if (i->sw_if_index == sw_if_index)
      {
        interface = i;
        break;
      }
  }

  if (is_add)
    {
      if (interface)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (nm->interfaces, interface);
      interface->sw_if_index = sw_if_index;
      interface->flags =
	is_inside ? NAT66_INTERFACE_FLAG_IS_INSIDE :
	NAT66_INTERFACE_FLAG_IS_OUTSIDE;
      nat66_validate_counters (nm, sw_if_index);
    }
  else
    {
      if (!interface)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      pool_put (nm->interfaces, interface);
    }

  feature_name = is_inside ? "nat66-in2out" : "nat66-out2in";
  int rv = ip6_sv_reass_enable_disable_with_refcnt (sw_if_index, is_add);
  if (rv)
    return rv;
  return vnet_feature_enable_disable ("ip6-unicast", feature_name,
				      sw_if_index, is_add, 0, 0);
}

void
nat66_interfaces_walk (nat66_interface_walk_fn_t fn, void *ctx)
{
  nat66_main_t *nm = &nat66_main;
  nat66_interface_t *i = 0;

  pool_foreach (i, nm->interfaces)
   {
    if (fn (i, ctx))
      break;
  }
}

nat66_static_mapping_t *
nat66_static_mapping_get (ip6_address_t * addr, u32 fib_index, u8 is_local)
{
  nat66_main_t *nm = &nat66_main;
  nat66_static_mapping_t *sm = 0;
  nat66_sm_key_t sm_key;
  clib_bihash_kv_24_8_t kv, value;

  sm_key.addr.as_u64[0] = addr->as_u64[0];
  sm_key.addr.as_u64[1] = addr->as_u64[1];
  sm_key.fib_index = fib_index;
  sm_key.rsvd = 0;

  kv.key[0] = sm_key.as_u64[0];
  kv.key[1] = sm_key.as_u64[1];
  kv.key[2] = sm_key.as_u64[2];

  if (!clib_bihash_search_24_8
      (is_local ? &nm->sm_l : &nm->sm_e, &kv, &value))
    sm = pool_elt_at_index (nm->sm, value.value);

  return sm;
}

int
nat66_static_mapping_add_del (ip6_address_t * l_addr, ip6_address_t * e_addr,
			      u32 vrf_id, u8 is_add)
{
  nat66_main_t *nm = &nat66_main;
  int rv = 0;
  nat66_static_mapping_t *sm = 0;
  nat66_sm_key_t sm_key;
  clib_bihash_kv_24_8_t kv, value;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP6, vrf_id);

  fail_if_disabled ();

  sm_key.addr.as_u64[0] = l_addr->as_u64[0];
  sm_key.addr.as_u64[1] = l_addr->as_u64[1];
  sm_key.fib_index = fib_index;
  sm_key.rsvd = 0;
  kv.key[0] = sm_key.as_u64[0];
  kv.key[1] = sm_key.as_u64[1];
  kv.key[2] = sm_key.as_u64[2];

  if (!clib_bihash_search_24_8 (&nm->sm_l, &kv, &value))
    sm = pool_elt_at_index (nm->sm, value.value);

  if (is_add)
    {
      if (sm)
	return VNET_API_ERROR_VALUE_EXIST;

      fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, vrf_id,
						     nm->nat_fib_src_hi);
      pool_get (nm->sm, sm);
      clib_memset (sm, 0, sizeof (*sm));
      sm->l_addr.as_u64[0] = l_addr->as_u64[0];
      sm->l_addr.as_u64[1] = l_addr->as_u64[1];
      sm->e_addr.as_u64[0] = e_addr->as_u64[0];
      sm->e_addr.as_u64[1] = e_addr->as_u64[1];
      sm->fib_index = fib_index;

      sm_key.fib_index = fib_index;
      kv.key[0] = sm_key.as_u64[0];
      kv.key[1] = sm_key.as_u64[1];
      kv.key[2] = sm_key.as_u64[2];
      kv.value = sm - nm->sm;
      if (clib_bihash_add_del_24_8 (&nm->sm_l, &kv, 1))
	nat66_elog_warn ("nat66-static-map-by-local add key failed");
      sm_key.addr.as_u64[0] = e_addr->as_u64[0];
      sm_key.addr.as_u64[1] = e_addr->as_u64[1];
      sm_key.fib_index = 0;
      kv.key[0] = sm_key.as_u64[0];
      kv.key[1] = sm_key.as_u64[1];
      kv.key[2] = sm_key.as_u64[2];
      if (clib_bihash_add_del_24_8 (&nm->sm_e, &kv, 1))
	nat66_elog_warn ("nat66-static-map-by-external add key failed");

      vlib_validate_combined_counter (&nm->session_counters, kv.value);
      vlib_zero_combined_counter (&nm->session_counters, kv.value);
    }
  else
    {
      if (!sm)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      kv.value = sm - nm->sm;
      if (clib_bihash_add_del_24_8 (&nm->sm_l, &kv, 0))
	nat66_elog_warn ("nat66-static-map-by-local delete key failed");
      sm_key.addr.as_u64[0] = e_addr->as_u64[0];
      sm_key.addr.as_u64[1] = e_addr->as_u64[1];
      sm_key.fib_index = 0;
      kv.key[0] = sm_key.as_u64[0];
      kv.key[1] = sm_key.as_u64[1];
      kv.key[2] = sm_key.as_u64[2];
      if (clib_bihash_add_del_24_8 (&nm->sm_e, &kv, 0))
	nat66_elog_warn ("nat66-static-map-by-external delete key failed");
      fib_table_unlock (sm->fib_index, FIB_PROTOCOL_IP6, nm->nat_fib_src_hi);
      pool_put (nm->sm, sm);
    }

  return rv;
}

void
nat66_static_mappings_walk (nat66_static_mapping_walk_fn_t fn, void *ctx)
{
  nat66_main_t *nm = &nat66_main;
  nat66_static_mapping_t *sm = 0;

  pool_foreach (sm, nm->sm)
   {
    if (fn (sm, ctx))
      break;
  }
}

VLIB_PLUGIN_REGISTER () =
{
 .version = VPP_BUILD_VER,
 .description = "NAT66",
};

VLIB_INIT_FUNCTION (nat66_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
