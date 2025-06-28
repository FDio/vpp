// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <stdbool.h>
// #include <gateway/gateway.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
// #include <schain/service.h>
// #include <schain/timer_lru.h>
#include "schain.h"


static clib_error_t *
schain_show_interface_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  schain_main_t *schain = &schain_main;
  gw_main_t *gm = &gateway_main;
  u32 sw_if_index;
  u32 inside_tenant_id, outside_tenant_id;
  vec_foreach_index (sw_if_index, gm->tenant_idx_by_sw_if_idx[VLIB_RX]) {
    // schain_tenant_t *tenant = schain_tenant_at_index(schain, tenant_idx);
    if (sw_if_index == ~0)
      continue;
    u16 *config = vec_elt_at_index(gm->tenant_idx_by_sw_if_idx[VLIB_RX], sw_if_index);
    if (config[0] == 0xFFFF)
      continue;
    inside_tenant_id = schain_tenant_at_index(schain, config[0])->tenant_id;
    outside_tenant_id = ~0;
    if (sw_if_index < vec_len(gm->tenant_idx_by_sw_if_idx[VLIB_TX])) {
      config = vec_elt_at_index(gm->tenant_idx_by_sw_if_idx[VLIB_TX], sw_if_index);
      if (config[0] != 0xFFFF)
        outside_tenant_id = schain_tenant_at_index(schain, config[0])->tenant_id;
    }

    vlib_cli_output(vm, "%U: tenant: rx %d tx: %d", format_vnet_sw_if_index_name, vnet_get_main(), sw_if_index,
                    inside_tenant_id, outside_tenant_id);
  }
  return 0;
}


static clib_error_t *
schain_tenant_show_stats_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  schain_main_t *schain = &schain_main;
  u32 tenant_idx;
  pool_foreach_index (tenant_idx, schain->tenants) {
    vlib_cli_output(vm, "%d: %U", schain->tenants[tenant_idx].tenant_id, format_schain_tenant_stats, schain, tenant_idx);
  }
  return err;
}

VLIB_CLI_COMMAND(show_schain_tenant_stats_command, static) = {
  .path = "show schain tenant statistics",
  .short_help = "show schain tenant statistics",
  .function = schain_tenant_show_stats_command_fn,
};





VLIB_CLI_COMMAND(show_schain_interface, static) = {
  .path = "show schain interface",
  .short_help = "show schain interface",
  .function = schain_show_interface_command_fn,
};


static clib_error_t *
schain_show_service_chain_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  schain_main_t *schain = &schain_main;
  u32 index;
  vec_foreach_index (index, schain->service_chains) {
    vlib_cli_output(vm, "Service chain: %d %U", index, format_schain_service_chain, index);
  }
  return 0;
}

VLIB_CLI_COMMAND(schain_show_service_chain_command, static) = {
  .path = "show schain service-chain",
  .short_help = "show schain service-chain",
  .function = schain_show_service_chain_command_fn,
};

static clib_error_t *
set_schain_session_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 dport, sport;
  ip46_address_t src, dst;
  u8 proto;
  u32 tenant_id = ~0;
  u32 context_id = 0; // TODO: support context_id

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "tenant %d %U:%d %U %U:%d", &tenant_id, unformat_ip46_address, &src, IP46_TYPE_ANY, &sport,
                 unformat_ip_protocol, &proto, unformat_ip46_address, &dst, IP46_TYPE_ANY, &dport)) {
      if (sport == 0 || sport > 65535) {
        error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
        goto done;
      }
      if (dport == 0 || dport > 65535) {
        error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
        goto done;
      }
    } else {
      error = clib_error_return(0, "unknown input `%U'", format_unformat_error, line_input);
      goto done;
    }
  }

  if (tenant_id == ~0) {
    error = clib_error_return(0, "Specify tenant");
    goto done;
  }

  schain_session_key_t k;
  k.context_id = context_id;
  k.src = src;
  k.dst = dst;
  k.sport = clib_host_to_net_u16(sport);
  k.dport = clib_host_to_net_u16(dport);
  k.proto = proto;

  u16 tenant_idx = schain_tenant_idx_by_id(tenant_id);
  if (tenant_idx == schain_TENANT_INVALID_IDX) {
    error = clib_error_return(0, "Tenant not found");
    goto done;
  }
  u32 flow_index;
  schain_session_t *session = schain_create_session(tenant_idx, &k, 0, true, &flow_index);
  if (!session)
    error = clib_error_return(0, "Creating static session failed");

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(set_schain_session_command, static) = {
  .path = "set schain session",
  .short_help = "set schain session tenant <tenant> <ipaddr:port> <protocol> <ipaddr:port>",
  .function = set_schain_session_command_fn,
};

u8 *
format_schain_lru_entry(u8 *s, va_list *args)
{
  dlist_elt_t *lru_entry = va_arg(*args, dlist_elt_t *);
  schain_main_t *schain = va_arg(*args, schain_main_t *);

  u32 session_index = lru_entry->value;
  schain_session_t *session = schain_session_at_index_check(schain, session_index);
  if (session) {
    s = format(s, "%d %.2f", session_index, session->last_heard);
  } else {
    s = format(s, "No sessions");
  }
  return s;
}

static clib_error_t *
schain_show_lru_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  schain_main_t *schain = &schain_main;
  schain_per_thread_data_t *ptd;
  u32 thread_index;

  vec_foreach_index (thread_index, schain->per_thread_data) {
    ptd = vec_elt_at_index(schain->per_thread_data, thread_index);
    vlib_cli_output(vm, "Elements in LRU list %d", pool_elts(ptd->lru_pool));
    for (int i = 0; i < schain_N_TIMEOUT; i++) {
      vlib_cli_output(vm, "Head index: %d", ptd->lru_head_index[i]);
      dlist_elt_t *lru_entry = pool_elt_at_index(ptd->lru_pool, ptd->lru_head_index[i]);
      while (lru_entry) {
        vlib_cli_output(vm, "LRU: %U %d %d %d", format_schain_lru_entry, lru_entry, schain, lru_entry->next,
                        lru_entry->prev, lru_entry->value);
        if (lru_entry->next == ~0 || lru_entry->next == ptd->lru_head_index[i])
          break;
        lru_entry = pool_elt_at_index(ptd->lru_pool, lru_entry->next);
      }
    }
  }
  return 0;
}

VLIB_CLI_COMMAND(show_schain_lru, static) = {
  .path = "show schain lru",
  .short_help = "show schain lru",
  .function = schain_show_lru_command_fn,
};

#include <vnet/classify/vnet_classify.h>

static void
schain_filter_set_trace_chain(vnet_classify_main_t *cm, u32 table_index)
{
  clib_warning("Setting trace chain to %d", table_index);
  // if (table_index == ~0) {
  //   u32 old_table_index;

  //   old_table_index = vlib_global_main.trace_filter.classify_table_index;
  //   vnet_classify_delete_table_index(cm, old_table_index, 1);
  // }
  // vlib_global_main.trace_filter.classify_table_index = table_index;
}

static clib_error_t *
schain_set_trace_filter_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  schain_main_t *schain = &schain_main;
  u32 nbuckets = 8;
  uword memory_size = (uword) (128 << 10);
  u32 skip = ~0;
  u32 match = ~0;
  u8 *match_vector;
  int is_add = 1;
  u32 table_index = ~0;
  u32 next_table_index = ~0;
  u32 miss_next_index = ~0;
  u32 current_data_flag = 0;
  int current_data_offset = 0;
  u8 *mask = 0;
  vnet_classify_main_t *cm = &vnet_classify_main;
  int rv = 0;
  clib_error_t *err = 0;

  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "del"))
      is_add = 0;
    else if (unformat(line_input, "buckets %d", &nbuckets))
      ;
    else if (unformat(line_input, "mask %U", unformat_classify_mask, &mask, &skip, &match))
      ;
    else if (unformat(line_input, "memory-size %U", unformat_memory_size, &memory_size))
      ;
    else
      break;
  }

  if (is_add && mask == 0)
    err = clib_error_return(0, "Mask required");

  else if (is_add && skip == ~0)
    err = clib_error_return(0, "skip count required");

  else if (is_add && match == ~0)
    err = clib_error_return(0, "match count required");

  if (err) {
    unformat_free(line_input);
    return err;
  }

  if (!is_add) {
    /*
     * Delete an existing trace classify table.
     */
    schain_filter_set_trace_chain(cm, ~0);

    vec_free(mask);
    unformat_free(line_input);

    return 0;
  }

  /*
   * Find an existing compatible table or else make a new one.
   */
  table_index = schain->trace_filter_table_index;
  if (table_index != ~0) {
    /*
     * look for a compatible table in the existing chain
     *  - if a compatible table is found, table_index is updated with it
     *  - if not, table_index is updated to ~0 (aka nil) and because of that
     *    we are going to create one (see below). We save the original head
     *    in next_table_index so we can chain it with the newly created
     *    table
     */
    next_table_index = table_index;
    table_index = classify_lookup_chain(table_index, mask, skip, match);
  }

  /*
   * When no table is found, make one.
   */
  if (table_index == ~0) {
    u32 new_head_index;

    /*
     * Matching table wasn't found, so create a new one at the
     * head of the next_table_index chain.
     */
    rv = vnet_classify_add_del_table(cm, mask, nbuckets, memory_size, skip, match, next_table_index, miss_next_index,
                                     &table_index, current_data_flag, current_data_offset, 1, 0);

    if (rv != 0) {
      vec_free(mask);
      unformat_free(line_input);
      return clib_error_return(0, "vnet_classify_add_del_table returned %d", rv);
    }

    /*
     * Reorder tables such that masks are most-specify to least-specific.
     */
    new_head_index = classify_sort_table_chain(cm, table_index);

    /*
     * Put first classifier table in chain in a place where
     * other data structures expect to find and use it.
     */
    schain_filter_set_trace_chain(cm, new_head_index);
  }

  vec_free(mask);

  /*
   * Now try to parse a and add a filter-match session.
   */
  if (unformat(line_input, "match %U", unformat_classify_match, cm, &match_vector, table_index) == 0)
    return 0;

  /*
   * We use hit or miss to determine whether to trace or pcap pkts
   * so the session setup is very limited
   */
  rv = vnet_classify_add_del_session(cm, table_index, match_vector, 0 /* hit_next_index */, 0 /* opaque_index */,
                                     0 /* advance */, 0 /* action */, 0 /* metadata */, 1 /* is_add */);

  vec_free(match_vector);

  return 0;
}

VLIB_CLI_COMMAND(set_schain_trace_filter, static) = {
  .path = "set schain trace filter",
  .short_help = "set schain trace filter",
  .function = schain_set_trace_filter_command_fn,
};

#if 0
static int
schain_session_table_walk_ip6_cb (clib_bihash_kv_40_8_t *kvp, void *arg)
{
  clib_warning("schain_session_table_walk_ip6_cb %llx", kvp->value);

  schain_session_ip6_key_t *k = (schain_session_ip6_key_t *)&kvp->key;
  clib_warning("KEY %U", format_schain_session_ip6_key, k);
  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
test_schain_session_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 dport, sport;
  ip_address_t src, dst;
  u8 proto;
  u32 tenant_id = ~0;
  u32 context_id = 0; // TODO: support context_id

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "tenant %d %U:%d %U %U:%d", &tenant_id, unformat_ip_address, &src, &sport,
                 unformat_ip_protocol, &proto, unformat_ip_address, &dst, &dport)) {
    } else if (unformat(line_input, "tenant %d [%U]:%d %U [%U]:%d", &tenant_id, unformat_ip_address, &src, &sport,
                        unformat_ip_protocol, &proto, unformat_ip_address, &dst, &dport)) {
    } else {
      error = clib_error_return(0, "unknown input `%U'", format_unformat_error, line_input);
      goto done;
    }
  }

  if (sport == 0 || sport > 65535) {
    error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
    goto done;
  }
  if (dport == 0 || dport > 65535) {
    error = clib_error_return(0, "invalid port `%U'", format_unformat_error, line_input);
    goto done;
  }

  if (tenant_id == ~0) {
    error = clib_error_return(0, "Specify tenant");
    goto done;
  }

  bool is_ip6 = src.version == AF_IP6;
  schain_session_key_t k;
  if (is_ip6) {
    k.ip6.context_id = context_id;
    k.ip6.src = src.ip.ip6;
    k.ip6.dst = dst.ip.ip6;
    k.ip6.sport = clib_host_to_net_u16(sport);
    k.ip6.dport = clib_host_to_net_u16(dport);
    k.ip6.proto = proto;
    k.is_ip6 = true;
  } else {
    k.ip4.context_id = context_id;
    k.ip4.src = src.ip.ip4.as_u32;
    k.ip4.dst = dst.ip.ip4.as_u32;
    k.ip4.sport = clib_host_to_net_u16(sport);
    k.ip4.dport = clib_host_to_net_u16(dport);
    k.ip4.proto = proto;
    k.is_ip6 = false;
  }

  clib_warning("Adding a session");
  u16 tenant_idx = schain_tenant_idx_by_id(tenant_id);
  u32 flow_index;
  schain_session_t *session = schain_create_session(tenant_idx, &k, 0, true, &flow_index);
  if (!session)
    error = clib_error_return(0, "Creating static session failed");
  session->type = is_ip6 ? schain_SESSION_TYPE_IP6 : schain_SESSION_TYPE_IP4;

  u64 v;
  int rv = schain_lookup(&k, is_ip6, &v);
  clib_warning("Looking up the same session %d %llx", rv, v);

  clib_bihash_kv_40_8_t kv;
  kv.key[0] = k.ip6.as_u64[0];
  kv.key[1] = k.ip6.as_u64[1];
  kv.key[2] = k.ip6.as_u64[2];
  kv.key[3] = k.ip6.as_u64[3];
  kv.key[4] = k.ip6.as_u64[4];
  kv.value = 123;

  schain_main_t *schain = &schain_main;


  kv.value = 0x12345678;
  rv = clib_bihash_add_del_40_8(&schain->table6, &kv, 2);
  clib_warning("adding key to table %d", rv);

  clib_bihash_kv_40_8_t kv2 = {0};
  rv = clib_bihash_search_40_8(&schain_main.table6, &kv, &kv2);
  clib_warning("Looking up the same session %d %llx", rv, kv2.value);


  clib_bihash_foreach_key_value_pair_40_8 (&schain->table6, schain_session_table_walk_ip6_cb, 0);

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(test_schain_session_command, static) = {
  .path = "test schain session",
  .short_help = "test schain session",
  .function = test_schain_session_command_fn,
};
#endif