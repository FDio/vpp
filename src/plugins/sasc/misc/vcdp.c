// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

// #define _GNU_SOURCE
// #include <sys/mman.h>

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#undef BIHASH_TYPE
#undef __included_bihash_template_h__
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#include <vcdp/lookup/lookup_inlines.h>
#include <vcdp/service.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>

#include <vcdp/vcdp.h>

#include <cbor.h>

#define VCDP_DEFAULT_BITMAP VCDP_SERVICE_MASK(drop)

VCDP_SERVICE_DECLARE(drop)

vcdp_main_t vcdp_main;
vcdp_cfg_main_t vcdp_cfg_main;

clib_error_t *
vcdp_init(vlib_main_t *vm)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp->log_class = vlib_log_register_class("vcdp", 0);

  vlib_call_init_function(vm, vcdp_service_init);
  vcdp_service_next_indices_init(vm, vcdp_lookup_ip4_node.index);
  vcdp_service_next_indices_init(vm, vcdp_lookup_ip6_node.index);
  vcdp_service_next_indices_init(vm, vcdp_handoff_node.index);

  time_t epoch = time(NULL);

  uword log_n_thread = max_log2(vlib_num_workers());
  uword template_shift = VCDP_SESSION_ID_TOTAL_BITS - VCDP_SESSION_ID_EPOCH_N_BITS - log_n_thread;
  vcdp->session_id_ctr_mask = (((u64) 1 << template_shift) - 1);

  /* initialize per-thread data */
  pool_init_fixed(vcdp->sessions, vcdp_cfg_main.no_sessions);

  vec_validate(vcdp->per_thread_data, vlib_num_workers());
  for (int i = 0; i <= vlib_num_workers(); i++) {
    dlist_elt_t *head;
    vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, i);
    ptd->session_id_template = (u64) epoch << (template_shift + log_n_thread);
    ptd->session_id_template |= (u64) i << template_shift;

    /* Initialise LRU lists per timer type */
    for (int i = 0; i < VCDP_N_TIMEOUT; i++) {
      pool_get(ptd->lru_pool, head);
      ptd->lru_head_index[i] = head - ptd->lru_pool;
      clib_dlist_init(ptd->lru_pool, ptd->lru_head_index[i]);
    }
  }

#define _(x, y, z) vcdp->timeouts[VCDP_TIMEOUT_##x] = y;
  foreach_vcdp_timeout
#undef _

    pool_init_fixed(vcdp->tenants, vcdp_cfg_main.no_tenants);
  vcdp_tenant_init_counters_simple(vcdp->tenant_simple_ctr);
  vcdp_tenant_init_counters_combined(vcdp->tenant_combined_ctr);

  u32 session_buckets = vcdp_calc_bihash_buckets(vcdp_cfg_main.no_sessions);
  u32 tenant_buckets = vcdp_calc_bihash_buckets(vcdp_cfg_main.no_tenants);

  clib_bihash_init_40_8(&vcdp->session_hash, "vcdp session hash table", session_buckets, 0);
  clib_bihash_init_8_8(&vcdp->tenant_idx_by_id, "vcdp tenant table", tenant_buckets, 0);
  clib_bihash_init_8_8(&vcdp->session_index_by_id, "session idx by id", session_buckets, 0);

  /* Handover back to the lookup node, which takes care of setting up ICMP error service chains etc. */
  vcdp->frame_queue_index = vlib_frame_queue_main_init(vcdp_lookup_ip4_node.index, 0);
  vcdp->frame_queue_icmp_index = vlib_frame_queue_main_init(vcdp_icmp_fwd_ip4_node.index, 0);

  cbor_set_allocs(clib_mem_alloc, clib_mem_realloc, clib_mem_free);

  return 0;
}

static u32 **simple_dir_entry_indices = 0;
static u32 **combined_dir_entry_indices = 0;
static void
vcdp_tenant_init_counters_per_instance(vcdp_main_t *vcdp, u16 tenant_idx, u32 tenant_id)
{
  /* Allocate counters for this interface. */
  vec_validate(simple_dir_entry_indices, tenant_idx);
  vec_validate(combined_dir_entry_indices, tenant_idx);
  u8 *tenant_name = format(0, "%d%c", tenant_id, 0);
  // clib_spinlock_lock (&nat->counter_lock);
  vcdp_tenant_init_counters_simple_per_instance(vcdp->tenant_simple_ctr, tenant_idx, (char *) tenant_name,
                                                &simple_dir_entry_indices[tenant_idx]);
  vcdp_tenant_init_counters_combined_per_instance(vcdp->tenant_combined_ctr, tenant_idx, (char *) tenant_name,
                                                  &combined_dir_entry_indices[tenant_idx]);
  vec_free(tenant_name);
  // clib_spinlock_unlock (&nat->counter_lock);
}

static void
vcdp_tenant_remove_counters_per_instance(vcdp_main_t *vcdp, u16 tenant_idx)
{
  // Remove symlink

  // clib_spinlock_lock (&nat->counter_lock);
  vcdp_tenant_remove_counters_simple_per_instance(simple_dir_entry_indices[tenant_idx]);
  vcdp_tenant_remove_counters_combined_per_instance(combined_dir_entry_indices[tenant_idx]);
  vec_free(simple_dir_entry_indices[tenant_idx]);
  vec_free(combined_dir_entry_indices[tenant_idx]);
  // clib_spinlock_unlock (&nat->counter_lock);
}


int
vcdp_set_services(vcdp_main_t *vcdp, u32 chain_id, u32 *services)
{
  vcdp_service_main_t *sm = &vcdp_service_main;

  // Check if the service chain terminates (last element of services is terminal)
  if (sm->services[services[vec_len(services) - 1]]->is_terminal != 1) {
    return -1;
  }
  // Check if the service chain id exists
  if (vec_elt_at_index(vcdp->service_chains, chain_id) != 65535) {
    return -1;
  }
  vec_validate_init_empty(vcdp->service_chains, chain_id, 65535);

  // Add next-nodes and build graph
  for (int i = 0; i < vec_len(services); i++) {
    
  vcdp->service_chains[chain_id] = services;
  return 0;
}

#if 0
VCDP_SERVICE_DECLARE(l4_lifecycle)
clib_error_t *
vcdp_set_services(vcdp_main_t *vcdp, u32 tenant_id, u32 bitmap, vl_api_vcdp_service_chain_t service_chain)
{
  u32 gen_bitmap = 0, tcp_bitmap = 0;
  u16 tenant_idx;
  vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
  if (!tenant)
    return clib_error_return(0, "Can't assign service map: tenant id %d not found", tenant_id);

  /*
   * Ensure the service chain terminates
   * Split TCP specific services from generic ones
   */
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  bool terminates = false;
  vec_foreach_index (i, sm->services) {
    if (bitmap & sm->services[i]->service_mask[0]) {
      if (sm->services[i]->is_terminal)
        terminates = true;
      if (!sm->services[i]->is_tcp_specific)
        gen_bitmap |= sm->services[i]->service_mask[0];
      tcp_bitmap |= sm->services[i]->service_mask[0];
    }
  }
  if (!terminates) {
    return clib_error_return(0, "Service chain does not terminate. %U", format_vcdp_bitmap, bitmap);
  }
  tenant->bitmaps[service_chain] = gen_bitmap;
  tenant->tcp_bitmaps[service_chain] = tcp_bitmap;

  // Special case l4_lifecycle for now for TCP services which should use tcp-check(-lite)
  tenant->tcp_bitmaps[service_chain] &= ~VCDP_SERVICE_MASK(l4_lifecycle);

  vcdp_log_debug("Set services for tenant %d, dir: %d: %U", tenant_id, service_chain, format_vcdp_bitmap, gen_bitmap);
  vcdp_log_debug("Set services for tenant %d, dir: %d: %U", tenant_id, service_chain, format_vcdp_bitmap, tcp_bitmap);

  return 0;
}
#endif
clib_error_t *
vcdp_set_timeout(vcdp_main_t *vcdp, u32 timeouts[])
{
#define _(name, val, str)                                                                                              \
  if (timeouts[VCDP_TIMEOUT_##name] > 0) {                                                                             \
    vcdp->timeouts[VCDP_TIMEOUT_##name] = timeouts[VCDP_TIMEOUT_##name];                                               \
  }
  foreach_vcdp_timeout
#undef _

    return 0;
}

// TODO: Change to sparse vector or something more lightweight than bihash
u16
vcdp_tenant_idx_by_id(u32 tenant_id)
{
  vcdp_main_t *vcdp = &vcdp_main;
  clib_bihash_kv_8_8_t kv = {.key = tenant_id};

  if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
    /* Not found */
    return ~0;
  }
  return kv.value;
}

vcdp_tenant_t *
vcdp_tenant_get_by_id(u32 tenant_id, u16 *tenant_idx)
{
  vcdp_main_t *vcdp = &vcdp_main;

  *tenant_idx = vcdp_tenant_idx_by_id(tenant_id);

  clib_bihash_kv_8_8_t kv = {.key = tenant_id};

  if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
    /* Not found */
    return 0;
  }
  *tenant_idx = kv.value;
  return vcdp_tenant_at_index(&vcdp_main, *tenant_idx);
}

u32
vcdp_calc_bihash_buckets(u32 n_elts)
{
  n_elts = n_elts / 2.5;
  u64 lower_pow2 = 1;
  while (lower_pow2 * 2 < n_elts) {
    lower_pow2 = 2 * lower_pow2;
  }
  u64 upper_pow2 = 2 * lower_pow2;
  if ((upper_pow2 - n_elts) < (n_elts - lower_pow2)) {
    if (upper_pow2 <= UINT32_MAX) {
      return upper_pow2;
    }
  }
  return lower_pow2;
}

VLIB_INIT_FUNCTION(vcdp_init) = {
  .runs_after = VLIB_INITS("threads_init"),
};

static clib_error_t *
vcdp_config(vlib_main_t *vm, unformat_input_t *input)
{
  u32 tenants = 0;
  u32 tunnels = 0;
  u32 nat_instances = 0;
  u32 sessions = 0;

  /* Set defaults */
  vcdp_cfg_main.no_nat_instances = 16; // 1 << 10; // 1024
  vcdp_cfg_main.no_sessions = 128000;  // 1 << 20;                            // 1M
  vcdp_cfg_main.no_tenants = 1 << 10;  // 1024
  vcdp_cfg_main.no_tunnels = 0;        // 1 << 20; // 1M;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "tenants %d", &tenants))
      vcdp_cfg_main.no_tenants = tenants;
    else if (unformat(input, "tunnels %d", &tunnels))
      vcdp_cfg_main.no_tunnels = tunnels;
    else if (unformat(input, "nat-instances %d", &nat_instances))
      vcdp_cfg_main.no_nat_instances = nat_instances;
    else if (unformat(input, "sessions %d", &sessions))
      vcdp_cfg_main.no_sessions = sessions;
    else
      return clib_error_return(0, "unknown input '%U'", format_unformat_error, input);
  }
  return 0;
}
VLIB_EARLY_CONFIG_FUNCTION(vcdp_config, "vcdp");
