/*
 *------------------------------------------------------------------
 * ip_path_mtu.c
 *
 * Copyright (c) 2021 Graphiant.
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
 *------------------------------------------------------------------
 */

#include <vnet/ip/ip_path_mtu.h>
#include <vnet/ip/ip_frag.h>
#include <vnet/adj/adj_delegate.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>

#include <vnet/dpo/drop_dpo.h>

/**
 * Path MTU
 *
 * A path is a peer. A peer is known by an IP address (in a table).
 * Insert a DPO in the forwarding chain for the peer to perform the
 * fragmentation.
 * For attached peers, all traffic will use the peer's adjacency, there
 * is already an MTU chekc in the adjacency (for the link's MTU) so as an
 * optimisation, instead of using a DPO, we add a delegate to the adjacency
 * to set the adjacency's MTU to the path MTU.
 */

/**
 * the logger
 */
static vlib_log_class_t ip_pmtu_logger;

static adj_delegate_type_t ip_pmtu_adj_delegate_type;
static fib_source_t ip_pmtu_source;

/**
 * DPO pool
 */
ip_pmtu_dpo_t *ip_pmtu_dpo_pool;

/**
 * DPO type registered for these GBP FWD
 */
static dpo_type_t ip_pmtu_dpo_type;

/**
 * Fib node type for the tracker
 */
static fib_node_type_t ip_pmtu_fib_type;

/**
 * Path MTU tracker pool
 */
ip_pmtu_t *ip_pmtu_pool;

/**
 * Delegate added to adjacencies to track path MTU
 */
typedef struct ip_path_mtu_adj_delegate_t_
{
  u16 pmtu;
} ip_path_mtu_adj_delegate_t;

static ip_path_mtu_adj_delegate_t *ip_path_mtu_adj_delegate_pool;

/* DB of all FIB PMTU settings */
typedef struct ip_pmtu_key_t_
{
  ip46_address_t nh;
  u32 table_id;
  fib_protocol_t fproto;
} __clib_packed ip_pmtu_key_t;

static uword *ip_pmtu_db;

#define IP_PMTU_TRKR_DBG(_ipt, _fmt, _args...)                                \
  {                                                                           \
    vlib_log_debug (ip_pmtu_logger, "[%U]: " _fmt ": ", format_ip_pmtu,       \
		    _ipt - ip_pmtu_pool, ##_args);                            \
  }
#define IP_PMTU_DBG(_fmt, _args...)                                           \
  {                                                                           \
    vlib_log_debug (ip_pmtu_logger, _fmt ": ", ##_args);                      \
  }

static u8 *
format_ip_pmtu_flags (u8 *s, va_list *ap)
{
  ip_pmtu_flags_t f = va_arg (*ap, ip_pmtu_flags_t);

  if (0)
    ;
#define _(a, b, c) else if (f & IP_PMTU_FLAG_##a) s = format (s, "%s ", c);
  foreach_ip_pmtu_flag
#undef _

    return (s);
}

u32
ip_pmtu_get_table_id (const ip_pmtu_t *ipt)
{
  const fib_prefix_t *pfx;
  u32 fib_index;

  pfx = fib_entry_get_prefix (ipt->ipt_fib_entry);
  fib_index = fib_entry_get_fib_index (ipt->ipt_fib_entry);

  return (fib_table_get_table_id (fib_index, pfx->fp_proto));
}

void
ip_pmtu_get_ip (const ip_pmtu_t *ipt, ip_address_t *ip)
{
  const fib_prefix_t *pfx;

  pfx = fib_entry_get_prefix (ipt->ipt_fib_entry);
  ip_address_from_46 (&pfx->fp_addr, pfx->fp_proto, ip);
}

static u8 *
format_ip_pmtu (u8 *s, va_list *ap)
{
  ip_pmtu_t *ipt;
  index_t ipti = va_arg (*ap, index_t);
  const fib_prefix_t *pfx;
  u32 fib_index;

  ipt = pool_elt_at_index (ip_pmtu_pool, ipti);
  pfx = fib_entry_get_prefix (ipt->ipt_fib_entry);
  fib_index = fib_entry_get_fib_index (ipt->ipt_fib_entry);

  s =
    format (s, "[%d] [tbl:[%d:%d]] %U pmtu:[cfg:%d, oper:%d, parent:%d] [%U]",
	    ipti, ip_pmtu_get_table_id (ipt), fib_index, format_fib_prefix,
	    pfx, ipt->ipt_cfg_pmtu, ipt->ipt_oper_pmtu, ipt->ipt_parent_pmtu,
	    format_ip_pmtu_flags, ipt->ipt_flags);

  return (s);
}

static u8 *
format_ip_path_mtu_adj_delegate (const adj_delegate_t *aed, u8 *s)
{
  ip_path_mtu_adj_delegate_t *ip_adj;

  ip_adj = pool_elt_at_index (ip_path_mtu_adj_delegate_pool, aed->ad_index);

  s = format (s, "IP path-MTU: %d", ip_adj->pmtu);

  return (s);
}

static void
ip_pmtu_adj_delegate_adj_created (adj_index_t ai)
{
  ip_path_mtu_adj_delegate_t *ipp_ad;
  const ip_pmtu_t *ipt;
  ip_adjacency_t *adj;
  u32 table_id;
  uword *p;

  adj = adj_get (ai);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_MCAST:
    case IP_LOOKUP_NEXT_BCAST:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      return;

    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MIDCHAIN:
      break;
    }

  table_id = fib_table_get_table_id_for_sw_if_index (
    adj->ia_nh_proto, adj->rewrite_header.sw_if_index);

  ip_pmtu_key_t key = {
    .nh = adj->sub_type.nbr.next_hop,
    .table_id = table_id,
    .fproto = adj->ia_nh_proto,
  };

  p = hash_get_mem (ip_pmtu_db, &key);

  if (NULL == p)
    return;

  ipt = pool_elt_at_index (ip_pmtu_pool, p[0]);

  pool_get (ip_path_mtu_adj_delegate_pool, ipp_ad);
  ipp_ad->pmtu = ipt->ipt_cfg_pmtu;

  adj_delegate_add (adj, ip_pmtu_adj_delegate_type,
		    ipp_ad - ip_path_mtu_adj_delegate_pool);

  adj_nbr_set_mtu (ai, ipp_ad->pmtu);

  IP_PMTU_TRKR_DBG (ipt, "adj-added:", ai);
}

static void
ip_pmtu_adj_delegate_adj_deleted (adj_delegate_t *ad)
{
  pool_put_index (ip_path_mtu_adj_delegate_pool, ad->ad_index);
}

static void
ip_pmtu_adj_delegate_adj_modified (adj_delegate_t *ad)
{
  ip_path_mtu_adj_delegate_t *ipp_ad;

  ipp_ad = pool_elt_at_index (ip_path_mtu_adj_delegate_pool, ad->ad_index);

  adj_nbr_set_mtu (ad->ad_adj_index, ipp_ad->pmtu);
}

const adj_delegate_vft_t ip_path_adj_delegate_vft = {
  .adv_format = format_ip_path_mtu_adj_delegate,
  .adv_adj_deleted = ip_pmtu_adj_delegate_adj_deleted,
  .adv_adj_modified = ip_pmtu_adj_delegate_adj_modified,
  .adv_adj_created = ip_pmtu_adj_delegate_adj_created,
};

static bool
ip_path_mtu_value_invalid (u16 pmtu)
{
  return (pmtu == 0 || pmtu == 0xffff);
}

static adj_walk_rc_t
ip_ptmu_adj_walk_remove (adj_index_t ai, void *ctx)
{
  adj_delegate_t *ad;

  ad = adj_delegate_get (adj_get (ai), ip_pmtu_adj_delegate_type);

  if (ad)
    {
      adj_nbr_set_mtu (ai, 0);

      pool_put_index (ip_path_mtu_adj_delegate_pool, ad->ad_index);
      adj_delegate_remove (ai, ip_pmtu_adj_delegate_type);
    }
  return (ADJ_WALK_RC_CONTINUE);
}

static adj_walk_rc_t
ip_ptmu_adj_walk_update (adj_index_t ai, void *ctx)
{
  ip_path_mtu_adj_delegate_t *ipp_ad;
  adj_delegate_t *ad;
  u16 *pmtup;

  pmtup = ctx;
  ad = adj_delegate_get (adj_get (ai), ip_pmtu_adj_delegate_type);

  if (ad)
    ipp_ad = pool_elt_at_index (ip_path_mtu_adj_delegate_pool, ad->ad_index);
  else
    {
      pool_get (ip_path_mtu_adj_delegate_pool, ipp_ad);

      adj_delegate_add (adj_get (ai), ip_pmtu_adj_delegate_type,
			ipp_ad - ip_path_mtu_adj_delegate_pool);
    }

  ipp_ad->pmtu = *pmtup;

  adj_nbr_set_mtu (ai, ipp_ad->pmtu);

  return (ADJ_WALK_RC_CONTINUE);
}

static ip_pmtu_dpo_t *
ip_pmtu_dpo_alloc (void)
{
  vlib_main_t *vm = vlib_get_main ();
  u8 need_barrier_sync = pool_get_will_expand (ip_pmtu_dpo_pool);
  ip_pmtu_dpo_t *ipm;


  if (need_barrier_sync)
    vlib_worker_thread_barrier_sync (vm);

  pool_get_aligned_zero (ip_pmtu_dpo_pool, ipm, sizeof (ip_pmtu_dpo_t));

  if (need_barrier_sync)
    vlib_worker_thread_barrier_release (vm);

  return (ipm);
}

static ip_pmtu_dpo_t *
ip_pmtu_dpo_get_from_dpo (const dpo_id_t *dpo)
{
  ASSERT (ip_pmtu_dpo_type == dpo->dpoi_type);

  return (ip_pmtu_dpo_get (dpo->dpoi_index));
}

static index_t
ip_pmtu_dpo_get_index (ip_pmtu_dpo_t *ipm)
{
  return (ipm - ip_pmtu_dpo_pool);
}

static void
ip_pmtu_dpo_lock (dpo_id_t *dpo)
{
  ip_pmtu_dpo_t *ipm;

  ipm = ip_pmtu_dpo_get_from_dpo (dpo);
  ipm->ipm_locks++;
}

static void
ip_pmtu_dpo_unlock (dpo_id_t *dpo)
{
  ip_pmtu_dpo_t *ipm;

  ipm = ip_pmtu_dpo_get_from_dpo (dpo);
  ipm->ipm_locks--;

  if (0 == ipm->ipm_locks)
    {
      dpo_reset (&ipm->ipm_dpo);
      pool_put (ip_pmtu_dpo_pool, ipm);
    }
}

static u32
ip_pmtu_dpo_get_urpf (const dpo_id_t *dpo)
{
  ip_pmtu_dpo_t *ipm;

  ipm = ip_pmtu_dpo_get_from_dpo (dpo);

  return (dpo_get_urpf (&ipm->ipm_dpo));
}

void
ip_pmtu_dpo_add_or_lock (u16 pmtu, const dpo_id_t *parent, dpo_id_t *dpo)
{
  ip_pmtu_dpo_t *ipm;

  ipm = ip_pmtu_dpo_alloc ();

  ipm->ipm_proto = parent->dpoi_proto;
  ipm->ipm_pmtu = pmtu;

  dpo_stack (ip_pmtu_dpo_type, ipm->ipm_proto, &ipm->ipm_dpo, parent);
  dpo_set (dpo, ip_pmtu_dpo_type, ipm->ipm_proto, ip_pmtu_dpo_get_index (ipm));
}

u8 *
format_ip_pmtu_dpo (u8 *s, va_list *ap)
{
  index_t index = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);
  ip_pmtu_dpo_t *ipm = ip_pmtu_dpo_get (index);

  s = format (s, "ip-pmtu-dpo: %U, mtu:%d", format_dpo_proto, ipm->ipm_proto,
	      ipm->ipm_pmtu);
  s = format (s, "\n%U", format_white_space, indent + 2);
  s = format (s, "%U", format_dpo_id, &ipm->ipm_dpo, indent + 4);

  return (s);
}

/**
 * Interpose a path MTU DPO
 */
static void
ip_pmtu_dpo_interpose (const dpo_id_t *original, const dpo_id_t *parent,
		       dpo_id_t *clone)
{
  ip_pmtu_dpo_t *ipm, *ipm_clone;

  ipm_clone = ip_pmtu_dpo_alloc ();
  ipm = ip_pmtu_dpo_get (original->dpoi_index);

  ipm_clone->ipm_proto = ipm->ipm_proto;
  ipm_clone->ipm_pmtu = ipm->ipm_pmtu;

  dpo_stack (ip_pmtu_dpo_type, ipm_clone->ipm_proto, &ipm_clone->ipm_dpo,
	     parent);
  dpo_set (clone, ip_pmtu_dpo_type, ipm_clone->ipm_proto,
	   ip_pmtu_dpo_get_index (ipm_clone));
}

static u16
ip_pmtu_dpo_get_mtu (const dpo_id_t *dpo)
{
  ip_pmtu_dpo_t *ipd;

  ipd = pool_elt_at_index (ip_pmtu_dpo_pool, dpo->dpoi_index);

  return (ipd->ipm_pmtu);
}

const static dpo_vft_t ip_pmtu_dpo_vft = {
  .dv_lock = ip_pmtu_dpo_lock,
  .dv_unlock = ip_pmtu_dpo_unlock,
  .dv_format = format_ip_pmtu_dpo,
  .dv_get_urpf = ip_pmtu_dpo_get_urpf,
  .dv_mk_interpose = ip_pmtu_dpo_interpose,
  .dv_get_mtu = ip_pmtu_dpo_get_mtu,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char *const ip_pmtu_dpo_ip4_nodes[] = {
  "ip4-pmtu-dpo",
  NULL,
};

const static char *const ip_pmtu_dpo_ip6_nodes[] = {
  "ip6-pmtu-dpo",
  NULL,
};

const static char *const *const ip_pmtu_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = ip_pmtu_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = ip_pmtu_dpo_ip6_nodes,
};

static bool
ip_mtu_fib_entry_is_attached (fib_node_index_t fib_entry)
{
  const fib_prefix_t *pfx;
  u32 cover, fib_index;

  fib_index = fib_entry_get_fib_index (fib_entry);
  pfx = fib_entry_get_prefix (fib_entry);

  /*
   * If the tracked prefix's cover is attached, then all packets that
   * are forwarded to this neighbour will use the adjacency, this is a
   * more efficient place to perform the MTU check and fragging
   */
  cover = fib_table_get_less_specific (fib_index, pfx);

  return (FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags (cover) ||
	  FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags (fib_entry));
}

static index_t
ip_pmtu_alloc (u32 fib_index, const fib_prefix_t *pfx,
	       const ip_pmtu_key_t *key, u16 pmtu)
{
  dpo_id_t ip_dpo = DPO_INVALID;
  ip_pmtu_t *ipt;
  fib_node_index_t cover;
  const dpo_id_t *lb_dpo;
  index_t ipti;

  pool_get (ip_pmtu_pool, ipt);
  fib_node_init (&(ipt->ipt_node), ip_pmtu_fib_type);

  ipti = ipt - ip_pmtu_pool;
  hash_set_mem_alloc (&ip_pmtu_db, key, ipti);

  ipt->ipt_cfg_pmtu = pmtu;
  ipt->ipt_fib_entry = fib_entry_track (fib_index, pfx, ip_pmtu_fib_type, ipti,
					&ipt->ipt_sibling);

  /*
   * If the tracked prefix's cover is attached, then all packets that
   * are forwarded to this neighbour will use the adjacency, this is a
   * more efficient place to perform the MTU check and fragging
   */
  cover = fib_table_get_less_specific (fib_index, pfx);

  if (ip_mtu_fib_entry_is_attached (ipt->ipt_fib_entry))
    {
      u32 sw_if_index;

      ipt->ipt_flags |= IP_PMTU_FLAG_ATTACHED;
      ipt->ipt_oper_pmtu = ipt->ipt_cfg_pmtu;

      sw_if_index = fib_entry_get_resolving_interface (cover);

      /* walk all adjs to add/update delegate */
      adj_nbr_walk_nh (sw_if_index, pfx->fp_proto, &pfx->fp_addr,
		       ip_ptmu_adj_walk_update, &ipt->ipt_oper_pmtu);
    }
  else
    {
      ipt->ipt_flags |= IP_PMTU_FLAG_REMOTE;

      lb_dpo = fib_entry_contribute_ip_forwarding (ipt->ipt_fib_entry);

      ipt->ipt_oper_pmtu = clib_min (dpo_get_mtu (lb_dpo), ipt->ipt_cfg_pmtu);

      /*
       * interpose a policy DPO from the nh so that MTU is applied
       */
      ip_pmtu_dpo_add_or_lock (ipt->ipt_oper_pmtu,
			       drop_dpo_get (fib_proto_to_dpo (pfx->fp_proto)),
			       &ip_dpo);

      fib_table_entry_special_dpo_add (fib_index, pfx, ip_pmtu_source,
				       FIB_ENTRY_FLAG_INTERPOSE, &ip_dpo);
      dpo_reset (&ip_dpo);
    }

  IP_PMTU_TRKR_DBG (ipt, "create");

  return (ipti);
}

static void
ip_pmtu_stack (ip_pmtu_t *ipt)
{
  bool was_attached, is_attached;
  const fib_prefix_t *pfx;
  u32 fib_index;

  pfx = fib_entry_get_prefix (ipt->ipt_fib_entry);
  fib_index = fib_entry_get_fib_index (ipt->ipt_fib_entry);

  was_attached = !!(ipt->ipt_flags & IP_PMTU_FLAG_ATTACHED);
  is_attached = ip_mtu_fib_entry_is_attached (ipt->ipt_fib_entry);

  if (was_attached && !is_attached)
    {
      /* transition from attached to remote - walk all adjs to remove delegate
       */
      adj_nbr_walk_nh (fib_entry_get_resolving_interface (ipt->ipt_fib_entry),
		       pfx->fp_proto, &pfx->fp_addr, ip_ptmu_adj_walk_remove,
		       &ipt->ipt_oper_pmtu);
      ipt->ipt_flags &= ~IP_PMTU_FLAG_ATTACHED;
    }
  if (!was_attached && is_attached)
    {
      /* transition from remote to attached - remove the DPO */
      fib_table_entry_special_remove (fib_index, pfx, ip_pmtu_source);
      ipt->ipt_flags &= ~IP_PMTU_FLAG_REMOTE;
    }

  if (is_attached)
    {
      /* walk all adjs to add/update delegate */
      ipt->ipt_oper_pmtu = ipt->ipt_cfg_pmtu;
      adj_nbr_walk_nh (fib_entry_get_resolving_interface (ipt->ipt_fib_entry),
		       pfx->fp_proto, &pfx->fp_addr, ip_ptmu_adj_walk_update,
		       &ipt->ipt_oper_pmtu);
      ipt->ipt_flags |= IP_PMTU_FLAG_ATTACHED;
    }
  else
    {
      const dpo_id_t *lb_dpo;
      u16 dpo_mtu;

      fib_table_entry_special_remove (fib_index, pfx, ip_pmtu_source);

      ipt->ipt_flags |= IP_PMTU_FLAG_REMOTE;
      lb_dpo = fib_entry_contribute_ip_forwarding (ipt->ipt_fib_entry);
      dpo_mtu = dpo_get_mtu (lb_dpo);

      ipt->ipt_oper_pmtu = clib_min (dpo_mtu, ipt->ipt_cfg_pmtu);

      /*
       * if the configured path-MTU is less that the egress/interface then
       * interpose a policy DPO from the nh so that MTU is applied
       */
      if (ipt->ipt_oper_pmtu < dpo_mtu)
	{
	  dpo_id_t ip_dpo = DPO_INVALID;

	  ip_pmtu_dpo_add_or_lock (
	    ipt->ipt_oper_pmtu,
	    drop_dpo_get (fib_proto_to_dpo (pfx->fp_proto)), &ip_dpo);

	  fib_table_entry_special_dpo_update (
	    fib_index, pfx, ip_pmtu_source, FIB_ENTRY_FLAG_INTERPOSE, &ip_dpo);
	  dpo_reset (&ip_dpo);
	}
    }
  IP_PMTU_TRKR_DBG (ipt, "stack");
}

static void
ip_pmtu_update (index_t ipti, u16 pmtu)
{
  ip_pmtu_t *ipt;

  ipt = pool_elt_at_index (ip_pmtu_pool, ipti);
  ipt->ipt_flags &= ~IP_PMTU_FLAG_STALE;
  ipt->ipt_cfg_pmtu = pmtu;

  ip_pmtu_stack (ipt);
}

static index_t
ip_pmtu_destroy (index_t ipti, const ip_pmtu_key_t *key)
{
  ip_pmtu_t *ipt;
  const fib_prefix_t *pfx;

  ipt = pool_elt_at_index (ip_pmtu_pool, ipti);
  pfx = fib_entry_get_prefix (ipt->ipt_fib_entry);

  IP_PMTU_TRKR_DBG (ipt, "destroy");

  if (ipt->ipt_flags & IP_PMTU_FLAG_REMOTE)
    fib_table_entry_special_remove (
      fib_entry_get_fib_index (ipt->ipt_fib_entry), pfx, ip_pmtu_source);
  else
    /* remove the delegate from all the adjacencies */
    adj_nbr_walk_nh (fib_entry_get_resolving_interface (ipt->ipt_fib_entry),
		     pfx->fp_proto, &pfx->fp_addr, ip_ptmu_adj_walk_remove,
		     NULL);

  /*
   * Drop the fib entry we're tracking
   */
  fib_entry_untrack (ipt->ipt_fib_entry, ipt->ipt_sibling);

  /*
   * remove from DB and return to pool
   */
  hash_unset_mem_free (&ip_pmtu_db, key);
  pool_put (ip_pmtu_pool, ipt);

  return (ipti);
}

int
ip_path_mtu_update (const ip_address_t *nh, u32 table_id, u16 pmtu)
{
  fib_prefix_t pfx;
  u32 fib_index;
  uword *p;

  ip_address_to_fib_prefix (nh, &pfx);
  fib_index = fib_table_find (pfx.fp_proto, table_id);

  if (~0 == fib_index)
    return (VNET_API_ERROR_NO_SUCH_TABLE);

  ip_pmtu_key_t key = {
    .fproto = pfx.fp_proto,
    .table_id = table_id,
    .nh = pfx.fp_addr,
  };

  p = hash_get_mem (ip_pmtu_db, &key);

  if (!ip_path_mtu_value_invalid (pmtu))
    {
      /* Add or update of path MTU */
      if (NULL == p)
	ip_pmtu_alloc (fib_index, &pfx, &key, pmtu);
      else
	ip_pmtu_update (p[0], pmtu);
    }
  else
    {
      if (NULL != p)
	ip_pmtu_destroy (p[0], &key);
    }

  return (0);
}

static walk_rc_t
ip_path_mtu_walk_mark (index_t ipti, void *ctx)
{
  ip_pmtu_t *ipt;

  ipt = ip_path_mtu_get (ipti);

  ipt->ipt_flags |= IP_PMTU_FLAG_STALE;

  return (WALK_CONTINUE);
}

typedef struct ip_path_mtu_walk_sweep_ctx_t_
{
  index_t *indicies;
} ip_path_mtu_walk_sweep_ctx_t;

static walk_rc_t
ip_path_mtu_walk_sweep (index_t ipti, void *arg)
{
  ip_path_mtu_walk_sweep_ctx_t *ctx = arg;
  ip_pmtu_t *ipt;

  ipt = ip_path_mtu_get (ipti);

  if (ipt->ipt_flags & IP_PMTU_FLAG_STALE)
    {
      vec_add1 (ctx->indicies, ipti);
    }

  return (WALK_CONTINUE);
}

int
ip_path_mtu_replace_begin (void)
{
  IP_PMTU_DBG ("replace-begin");

  ip_path_mtu_walk (ip_path_mtu_walk_mark, NULL);

  return (0);
}

int
ip_path_mtu_replace_end (void)
{
  index_t *ipti;

  IP_PMTU_DBG ("replace-end");

  /*
   * not safe to walk the pool whilst deleting, so create
   * temporary storage of stale entries
   */
  ip_path_mtu_walk_sweep_ctx_t ctx = {
    .indicies = NULL,
  };

  ip_path_mtu_walk (ip_path_mtu_walk_sweep, &ctx);

  vec_foreach (ipti, ctx.indicies)
    {
      ip_pmtu_t *ipt;
      ip_address_t ip;

      ipt = ip_path_mtu_get (*ipti);
      ip_pmtu_get_ip (ipt, &ip);
      ip_path_mtu_update (&ip, ip_pmtu_get_table_id (ipt), 0);
    }

  vec_free (ctx.indicies);

  return (0);
}

void
ip_path_mtu_walk (ip_path_mtu_walk_t fn, void *ctx)
{
  index_t ipmi;

  pool_foreach_index (ipmi, ip_pmtu_pool)
    {
      if (WALK_STOP == fn (ipmi, ctx))
	break;
    }
}

static fib_node_t *
ip_pmtu_get_node (fib_node_index_t index)
{
  ip_pmtu_t *ipt;

  ipt = pool_elt_at_index (ip_pmtu_pool, index);

  return (&(ipt->ipt_node));
}

static ip_pmtu_t *
ip_pmtu_get_from_node (fib_node_t *node)
{
  return (
    (ip_pmtu_t *) (((char *) node) - STRUCT_OFFSET_OF (ip_pmtu_t, ipt_node)));
}

static void
ip_pmtu_last_lock_gone (fib_node_t *node)
{
  /*
   * the lifetime of the entry is managed by the API.
   */
  ASSERT (0);
}

/*
 * A back walk has reached this BIER entry
 */
static fib_node_back_walk_rc_t
ip_pmtu_back_walk_notify (fib_node_t *node, fib_node_back_walk_ctx_t *ctx)
{
  /*
   * re-populate the ECMP tables with new choices
   */
  ip_pmtu_t *ipr = ip_pmtu_get_from_node (node);

  ip_pmtu_stack (ipr);

  /*
   * no need to propagate further up the graph, since there's nothing there
   */
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

static const fib_node_vft_t ip_ptmu_fib_node_vft = {
  .fnv_get = ip_pmtu_get_node,
  .fnv_last_lock = ip_pmtu_last_lock_gone,
  .fnv_back_walk = ip_pmtu_back_walk_notify,
};

static clib_error_t *
ip_path_module_init (vlib_main_t *vm)
{
  ip_pmtu_adj_delegate_type =
    adj_delegate_register_new_type (&ip_path_adj_delegate_vft);
  ip_pmtu_source = fib_source_allocate ("path-mtu", FIB_SOURCE_PRIORITY_HI,
					FIB_SOURCE_BH_SIMPLE);
  ip_pmtu_fib_type =
    fib_node_register_new_type ("ip-pmtu", &ip_ptmu_fib_node_vft);

  ip_pmtu_db = hash_create_mem (0, sizeof (ip_pmtu_key_t), sizeof (index_t));
  ip_pmtu_logger = vlib_log_register_class ("ip", "pmtu");
  ip_pmtu_dpo_type =
    dpo_register_new_type (&ip_pmtu_dpo_vft, ip_pmtu_dpo_nodes);

  return (NULL);
}

VLIB_INIT_FUNCTION (ip_path_module_init);

static clib_error_t *
show_ip_pmtu_command (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  index_t ipti;

  if (unformat (input, "%d", &ipti))
    {
      /*
       * show one in detail
       */
      if (!pool_is_free_index (ip_pmtu_pool, ipti))
	vlib_cli_output (vm, "%U", format_ip_pmtu, ipti);
      else
	vlib_cli_output (vm, "entry %d invalid", ipti);
    }
  else
    {
      /*
       * show all
       */
      pool_foreach_index (ipti, ip_pmtu_pool)
	{
	  vlib_cli_output (vm, "%U", format_ip_pmtu, ipti);
	}
    }

  return (NULL);
}

VLIB_CLI_COMMAND (show_fib_entry, static) = {
  .path = "show ip pmtu",
  .function = show_ip_pmtu_command,
  .short_help = "show ip path MTU",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
