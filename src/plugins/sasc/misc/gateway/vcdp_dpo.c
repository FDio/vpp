// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

// Get packets from a FIB DPO into VCDP.

#include <vnet/ip/ip.h>
// #include "vcdp_dpo.h"
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/lookup/lookup_inlines.h>
#include <vnet/fib/fib_source.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/dpo/drop_dpo.h>
#include "vcdp_dpo.h"

dpo_type_t vcdp_dpo_type;
dpo_type_t vcdp_if_dpo_type;
fib_source_t fib_src;


void
vcdp_dpo_create (dpo_proto_t dproto, u32 index, dpo_id_t *dpo)
{
    dpo_set (dpo, vcdp_dpo_type, dproto, index);
}

u8 *
format_vcdp_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  vcdp_dpo_t *dpo = vcdp_dpo_get(index);

  return (format (s, "dpo-vcdp index: %d tenant_idx: %d parent dpo_index: %d, parent dpo_next_node: %d",
                  index, dpo->tenant_idx, dpo->dpo_parent.dpoi_index, dpo->dpo_parent.dpoi_next_node));
}

static void
vcdp_dpo_lock (dpo_id_t *dpo)
{
}

static void
vcdp_dpo_unlock (dpo_id_t *dpo)
{
}

vcdp_dpo_t *vcdp_dpo_pool;
vcdp_fib_t *vcdp_fib_pool;

static vcdp_dpo_t *
vcdp_dpo_alloc (void)
{
  vlib_main_t *vm = vlib_get_main ();
  u8 need_barrier_sync = pool_get_will_expand (vcdp_dpo_pool);
  vcdp_dpo_t *dpo;


  if (need_barrier_sync)
    vlib_worker_thread_barrier_sync (vm);

  pool_get_aligned_zero (vcdp_dpo_pool, dpo, sizeof (vcdp_dpo_t));

  if (need_barrier_sync)
    vlib_worker_thread_barrier_release (vm);

  return (dpo);
}

vcdp_dpo_t *
vcdp_dpo_get (index_t index)
{
  return (pool_elt_at_index (vcdp_dpo_pool, index));
}

static index_t
vcdp_dpo_get_index (vcdp_dpo_t *dpo)
{
  return (dpo - vcdp_dpo_pool);
}

static void
vcdp_dpo_interpose(const dpo_id_t *original, const dpo_id_t *parent, dpo_id_t *clone)
{
  vcdp_dpo_t *dpo, *dpo_clone;
  dpo_clone = vcdp_dpo_alloc();
  dpo = vcdp_dpo_get (original->dpoi_index);
  dpo_clone->tenant_idx = dpo->tenant_idx;
  dpo_stack(vcdp_dpo_type, dpo_clone->proto, &dpo_clone->dpo_parent, parent);
  dpo_set(clone, vcdp_dpo_type, original->dpoi_proto, vcdp_dpo_get_index(dpo_clone));
}

const static dpo_vft_t vcdp_dpo_vft = {
  .dv_lock = vcdp_dpo_lock,
  .dv_unlock = vcdp_dpo_unlock,
  .dv_format = format_vcdp_dpo,
  .dv_mk_interpose = vcdp_dpo_interpose,
};

const static char *const vcdp_ip6_nodes[] = {
  "vcdp-lookup-ip6",
  NULL,
};

const static char *const vcdp_ip4_nodes[] = {
  "vcdp-input-dpo",
  NULL,
};

const static char *const *const vcdp_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = vcdp_ip4_nodes,
  [DPO_PROTO_IP6] = vcdp_ip6_nodes,
  [DPO_PROTO_MPLS] = 0,
};

static fib_node_t *
vcdp_fib_get_node (fib_node_index_t index)
{
  vcdp_fib_t *vcdp_fib;

  vcdp_fib = pool_elt_at_index (vcdp_fib_pool, index);

  return (&(vcdp_fib->node));
}
static void
vcdp_fib_last_lock_gone (fib_node_t *node)
{
  /*
   * the lifetime of the entry is managed by the API.
   */
  ASSERT (0);
}

static void
vcdp_fib_stack (vcdp_fib_t *ipt)
{
  // const dpo_id_t *dpo;
  /*dpo = */fib_entry_contribute_ip_forwarding(ipt->fib_entry);
  // dpo_copy (&pr->dpo, dpo);
}

static vcdp_fib_t *
vcdp_fib_get_from_node (fib_node_t *node)
{
  return ((vcdp_fib_t *) (((char *) node) - STRUCT_OFFSET_OF (vcdp_fib_t, node)));
}

/*
 * A back walk has reached this VCDP entry
 */
static fib_node_back_walk_rc_t
vcdp_fib_back_walk_notify (fib_node_t *node, fib_node_back_walk_ctx_t *ctx)
{
  vcdp_fib_t *vcdp_fib = vcdp_fib_get_from_node(node);

  vcdp_fib_stack (vcdp_fib);

  /*
   * no need to propagate further up the graph, since there's nothing there
   */
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

fib_node_type_t vcdp_fib_node_type;
static const fib_node_vft_t vcdp_fib_node_vft = {
  .fnv_get = vcdp_fib_get_node,
  .fnv_last_lock = vcdp_fib_last_lock_gone,
  .fnv_back_walk = vcdp_fib_back_walk_notify,
};

clib_error_t *
vcdp_dpo_module_init (vlib_main_t *vm)
{
  return 0;
  // ip_pmtu_adj_delegate_type =
  //   adj_delegate_register_new_type (&ip_path_adj_delegate_vft);

  fib_src = fib_source_allocate("dpo-vcdp-source", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_SIMPLE);
  vcdp_fib_node_type = fib_node_register_new_type ("vcdp", &vcdp_fib_node_vft);
  vcdp_dpo_type = dpo_register_new_type (&vcdp_dpo_vft, vcdp_nodes);

  return 0;
}

/*
 * Add a VCDP DPO entry to the FIB.
 * This is used to intercept packets and send them to the VCDP.
 * 1. Hijack traffic. Entry not used for forwarding. E.g. NAT64 or DNAT
 * 2. Normal forwarding entry combined with VCDP. Interpose required.
 * 3. Hijack entry without normal forwarding entry. Forward via covering prefix.
 *
 * Track prefix and detect if anything changes.
 */
void
vcdp_dpo_entry(u32 fib_index, ip_prefix_t *prefix, u16 index, bool is_interpose)
{
  fib_prefix_t pfx;
  ip_prefix_to_fib_prefix(prefix, &pfx);

  dpo_proto_t dproto = fib_proto_to_dpo(pfx.fp_proto);

  // Index is the tenant index.
  dpo_id_t tmp = DPO_INVALID;
  if (is_interpose) {
    // Inject VCDP interception into the forwarding path.
    // Terminal VCDP node forwards using the forwarding DPO.
    vcdp_fib_t *vcdp_fib;
    pool_get(vcdp_fib_pool, vcdp_fib);
    fib_node_init (&(vcdp_fib->node), vcdp_fib_node_type);
    vcdp_fib->fib_entry = fib_entry_track(fib_index, &pfx, vcdp_fib_node_type, vcdp_fib - vcdp_fib_pool, &vcdp_fib->sibling);

    vcdp_dpo_t *dpo = vcdp_dpo_alloc();
    dpo->proto = dproto;
    dpo->tenant_idx = index;
    dpo_set(&tmp, vcdp_dpo_type, dproto, vcdp_dpo_get_index(dpo));
    dpo_stack(vcdp_dpo_type, dproto, &dpo->dpo_parent, drop_dpo_get(dproto));
    u32 fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT | FIB_ENTRY_FLAG_EXCLUSIVE | FIB_ENTRY_FLAG_INTERPOSE;

    /* TODO: Only add if there is a covering route. Bug in FIB? */
    fib_table_entry_special_dpo_add(fib_index, &pfx, fib_src, fib_flags, &tmp);
    dpo_reset(&tmp);
  } else {
    // Hijack traffic. E.g NAT64 or DNAT
    vcdp_dpo_create(dproto, index, &tmp);
    u32 fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT | FIB_ENTRY_FLAG_EXCLUSIVE;

    fib_table_entry_special_dpo_add(fib_index, &pfx, fib_src, fib_flags, &tmp);
    dpo_reset(&tmp);


  }
}

VLIB_INIT_FUNCTION(vcdp_dpo_module_init);