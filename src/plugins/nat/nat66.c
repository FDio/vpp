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

#include <nat/nat66.h>
#include <vnet/fib/fib_table.h>

nat66_main_t nat66_main;

/* *INDENT-OFF* */

/* Hook up input features */
VNET_FEATURE_INIT (nat66_in2out, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat66-in2out",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
VNET_FEATURE_INIT (nat66_out2in, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat66-out2in",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

/* *INDENT-ON* */


void
nat66_init (void)
{
  nat66_main_t *nm = &nat66_main;
  u32 static_mapping_buckets = 1024;
  uword static_mapping_memory_size = 64 << 20;

  clib_bihash_init_24_8 (&nm->sm_l, "nat66-static-map-by-local",
			 static_mapping_buckets, static_mapping_memory_size);
  clib_bihash_init_24_8 (&nm->sm_e, "nat66-static-map-by-external",
			 static_mapping_buckets, static_mapping_memory_size);

  nm->session_counters.name = "session counters";
}

int
nat66_interface_add_del (u32 sw_if_index, u8 is_inside, u8 is_add)
{
  nat66_main_t *nm = &nat66_main;
  snat_interface_t *interface = 0, *i;
  const char *feature_name;

  /* *INDENT-OFF* */
  pool_foreach (i, nm->interfaces,
  ({
    if (i->sw_if_index == sw_if_index)
      {
        interface = i;
        break;
      }
  }));
  /* *INDENT-ON* */

  if (is_add)
    {
      if (interface)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (nm->interfaces, interface);
      interface->sw_if_index = sw_if_index;
      interface->flags =
	is_inside ? NAT_INTERFACE_FLAG_IS_INSIDE :
	NAT_INTERFACE_FLAG_IS_OUTSIDE;
    }
  else
    {
      if (!interface)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      pool_put (nm->interfaces, interface);
    }

  feature_name = is_inside ? "nat66-in2out" : "nat66-out2in";
  return vnet_feature_enable_disable ("ip6-unicast", feature_name,
				      sw_if_index, is_add, 0, 0);
}

void
nat66_interfaces_walk (nat66_interface_walk_fn_t fn, void *ctx)
{
  nat66_main_t *nm = &nat66_main;
  snat_interface_t *i = 0;

  /* *INDENT-OFF* */
  pool_foreach (i, nm->interfaces,
  ({
    if (fn (i, ctx))
      break;
  }));
  /* *INDENT-ON* */
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
						     FIB_SOURCE_PLUGIN_HI);
      pool_get (nm->sm, sm);
      memset (sm, 0, sizeof (*sm));
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
	nat_log_warn ("nat66-static-map-by-local add key failed");
      sm_key.addr.as_u64[0] = e_addr->as_u64[0];
      sm_key.addr.as_u64[1] = e_addr->as_u64[1];
      sm_key.fib_index = 0;
      kv.key[0] = sm_key.as_u64[0];
      kv.key[1] = sm_key.as_u64[1];
      kv.key[2] = sm_key.as_u64[2];
      if (clib_bihash_add_del_24_8 (&nm->sm_e, &kv, 1))
	nat_log_warn ("nat66-static-map-by-external add key failed");

      vlib_validate_combined_counter (&nm->session_counters, kv.value);
      vlib_zero_combined_counter (&nm->session_counters, kv.value);
    }
  else
    {
      if (!sm)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      kv.value = sm - nm->sm;
      if (clib_bihash_add_del_24_8 (&nm->sm_l, &kv, 0))
	nat_log_warn ("nat66-static-map-by-local delete key failed");
      sm_key.addr.as_u64[0] = e_addr->as_u64[0];
      sm_key.addr.as_u64[1] = e_addr->as_u64[1];
      sm_key.fib_index = 0;
      kv.key[0] = sm_key.as_u64[0];
      kv.key[1] = sm_key.as_u64[1];
      kv.key[2] = sm_key.as_u64[2];
      if (clib_bihash_add_del_24_8 (&nm->sm_e, &kv, 0))
	nat_log_warn ("nat66-static-map-by-external delete key failed");
      fib_table_unlock (sm->fib_index, FIB_PROTOCOL_IP6,
			FIB_SOURCE_PLUGIN_HI);
      pool_put (nm->sm, sm);
    }

  return rv;
}

void
nat66_static_mappings_walk (nat66_static_mapping_walk_fn_t fn, void *ctx)
{
  nat66_main_t *nm = &nat66_main;
  nat66_static_mapping_t *sm = 0;

  /* *INDENT-OFF* */
  pool_foreach (sm, nm->sm,
  ({
    if (fn (sm, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
