/*
 * Copyright (c) 2017-2019 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <math.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <inttypes.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/pool.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <search.h>
#include <netinet/ip.h>

#include "pfcp.h"
#include "upf.h"
#include "upf_app_db.h"
#include "upf_pfcp.h"
#include "upf_pfcp_api.h"
#include "upf_pfcp_server.h"

#if CLIB_DEBUG > 2
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

upf_main_t upf_main;

#define SESS_CREATE 0
#define SESS_MODIFY 1
#define SESS_DEL 2

static void pfcp_add_del_ue_ip (const void *ue_ip, void *si, int is_add);
static void pfcp_add_del_v4_teid (const void *teid, void *si, int is_add);
static void pfcp_add_del_v6_teid (const void *teid, void *si, int is_add);
static void pfcp_add_del_v4_tdf (const void *tdf, void *si, int is_add);
static void pfcp_add_del_v6_tdf (const void *tdf, void *si, int is_add);
u8 *format_upf_acl (u8 * s, va_list * args);

#define vec_bsearch(k, v, compar)				\
	bsearch((k), (v), vec_len((v)), sizeof((v)[0]), compar)

static u8 *
format_upf_device_name (u8 * s, va_list * args)
{
  upf_main_t *gtm = &upf_main;
  u32 i = va_arg (*args, u32);
  upf_nwi_t *nwi;

  nwi = pool_elt_at_index (gtm->nwis, i);

  s = format (s, "upf-nwi-%U", format_network_instance, nwi->name);
  return s;
}

static clib_error_t *
upf_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (gtpu_device_class,static) = {
  .name = "GTPU",
  .format_device_name = format_upf_device_name,
  .format_tx_trace = format_upf_encap_trace,
  .admin_up_down_function = upf_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_gtpu_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (gtpu_hw_class) =
{
  .name = "GTPU",
  .format_header = format_gtpu_header_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static int
vnet_upf_create_nwi_if (u8 * name, u32 ip4_table_id, u32 ip6_table_id,
			u32 * sw_if_idx)
{
  vnet_main_t *vnm = upf_main.vnet_main;
  l2input_main_t *l2im = &l2input_main;
  upf_main_t *gtm = &upf_main;
  vnet_hw_interface_t *hi;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  upf_nwi_t *nwi;
  uword if_index;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (p)
    {
      nwi = vec_elt_at_index (gtm->nwis, p[0]);
      if (sw_if_index)
	*sw_if_idx = nwi->sw_if_index;
      return VNET_API_ERROR_IF_ALREADY_EXISTS;
    }

  pool_get (gtm->nwis, nwi);
  memset (nwi, 0, sizeof (*nwi));
  memset (&nwi->fib_index, ~0, sizeof (nwi->fib_index));

  nwi->name = vec_dup (name);

  if_index = nwi - gtm->nwis;

  if (vec_len (gtm->free_nwi_hw_if_indices) > 0)
    {
      vnet_interface_main_t *im = &vnm->interface_main;
      hw_if_index = gtm->free_nwi_hw_if_indices
	[vec_len (gtm->free_nwi_hw_if_indices) - 1];
      _vec_len (gtm->free_nwi_hw_if_indices) -= 1;

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = if_index;
      hi->hw_instance = hi->dev_instance;

      /* clear old stats of freed nwi before reuse */
      sw_if_index = hi->sw_if_index;
      vnet_interface_counter_lock (im);
      vlib_zero_combined_counter
	(&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
	 sw_if_index);
      vlib_zero_combined_counter (&im->combined_sw_if_counters
				  [VNET_INTERFACE_COUNTER_RX], sw_if_index);
      vlib_zero_simple_counter (&im->sw_if_counters
				[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
      vnet_interface_counter_unlock (im);
    }
  else
    {
      hw_if_index = vnet_register_interface
	(vnm, gtpu_device_class.index, if_index, gtpu_hw_class.index,
	 if_index);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
    }

  nwi->hw_if_index = hw_if_index;
  nwi->sw_if_index = sw_if_index = hi->sw_if_index;

  vec_validate_init_empty (gtm->nwi_index_by_sw_if_index, sw_if_index, ~0);
  gtm->nwi_index_by_sw_if_index[sw_if_index] = if_index;

  /* setup l2 input config with l2 feature and bd 0 to drop packet */
  vec_validate (l2im->configs, sw_if_index);
  l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
  l2im->configs[sw_if_index].bd_index = 0;

  /* move into fib table */
  ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, ip4_table_id, 0);
  ip_table_bind (FIB_PROTOCOL_IP6, sw_if_index, ip6_table_id, 0);

  nwi->fib_index[FIB_PROTOCOL_IP4] =
    ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
  nwi->fib_index[FIB_PROTOCOL_IP6] =
    ip6_fib_table_get_index_for_sw_if_index (sw_if_index);

  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /*
   * L3 enable the interface
   */
  ip4_sw_interface_enable_disable (sw_if_index, 1);
  ip6_sw_interface_enable_disable (sw_if_index, 1);

  vnet_get_sw_interface (vnet_get_main (), sw_if_index)->flood_class =
    VNET_FLOOD_CLASS_TUNNEL_NORMAL;

  hash_set_mem (gtm->nwi_index_by_name, nwi->name, if_index);

  if (sw_if_idx)
    *sw_if_idx = nwi->sw_if_index;

  return 0;
}

static int
vnet_upf_delete_nwi_if (u8 * name, u32 * sw_if_idx)
{
  vnet_main_t *vnm = upf_main.vnet_main;
  upf_main_t *gtm = &upf_main;
  upf_nwi_t *nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  nwi = pool_elt_at_index (gtm->nwis, p[0]);

  /* disable nwi if */
  vnet_sw_interface_set_flags (vnm, nwi->sw_if_index, 0 /* down */ );
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, nwi->sw_if_index);
  si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

  /* make sure session is removed from l2 bd or xconnect */
  set_int_l2_mode (gtm->vlib_main, vnm, MODE_L3, nwi->sw_if_index, 0, 0, 0,
		   0);
  gtm->nwi_index_by_sw_if_index[nwi->sw_if_index] = ~0;

  vec_add1 (gtm->free_nwi_hw_if_indices, nwi->hw_if_index);

  hash_unset_mem (gtm->nwi_index_by_name, nwi->name);
  vec_free (nwi->name);
  pool_put (gtm->nwis, nwi);

  return 0;
}

int
vnet_upf_nwi_add_del (u8 * name, u32 ip4_table_id, u32 ip6_table_id, u8 add)
{
  return (add) ?
    vnet_upf_create_nwi_if (name, ip4_table_id, ip6_table_id, NULL) :
    vnet_upf_delete_nwi_if (name, NULL);
}

static int
pfcp_pdr_id_compare (const void *p1, const void *p2)
{
  const upf_pdr_t *a = (upf_pdr_t *) p1;
  const upf_pdr_t *b = (upf_pdr_t *) p2;

  /* compare rule_ids */
  return intcmp (a->id, b->id);
}

#define vec_diff(new, old, compar, add_del, user)			\
  do {									\
    size_t _i = 0, _j = 0;						\
									\
    if (new)								\
      vec_sort_with_function(new,compar);				\
    if (old)								\
      vec_sort_with_function(old,compar);				\
    if (new && old)							\
      while (_i < vec_len(new) && _j < vec_len(old)) {			\
	int r = compar(&vec_elt(new, _i), &vec_elt(old, _j));		\
	if (r == 0) {							\
	  _i++;;							\
	  _j++;								\
	} else if (r < 0) {						\
	  /* insert new entry */					\
	  add_del(&vec_elt(new, _i), user, 1);				\
	  _i++;								\
	} else {							\
	  /* remove old entry */					\
	  add_del(&vec_elt(old, _j), user, 0);				\
	  _j++;								\
	}								\
      }									\
									\
    if (new)								\
      for (;_i < vec_len(new); _i++)					\
	/* insert new entry */						\
	add_del(&vec_elt(new, _i), user, 1);				\
    if (old)								\
      for (;_j < vec_len(old); _j++)					\
	/* remove old entry */						\
	add_del(&vec_elt(old, _j), user, 0);				\
  } while (0)

static int
pfcp_far_id_compare (const void *p1, const void *p2)
{
  const upf_far_t *a = (upf_far_t *) p1;
  const upf_far_t *b = (upf_far_t *) p2;

  /* compare rule_ids */
  return intcmp (a->id, b->id);
}

static int
pfcp_urr_id_compare (const void *p1, const void *p2)
{
  const upf_urr_t *a = (upf_urr_t *) p1;
  const upf_urr_t *b = (upf_urr_t *) p2;

  /* compare rule_ids */
  return intcmp (a->id, b->id);
}

static int
pfcp_qer_id_compare (const void *p1, const void *p2)
{
  const upf_qer_t *a = (upf_qer_t *) p1;
  const upf_qer_t *b = (upf_qer_t *) p2;

  /* compare rule_ids */
  return intcmp (a->id, b->id);
}

upf_node_assoc_t *
pfcp_get_association (pfcp_node_id_t * node_id)
{
  upf_main_t *gtm = &upf_main;
  uword *p = NULL;

  switch (node_id->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      p = mhash_get (&gtm->node_index_by_ip, &node_id->ip);
      break;

    case NID_FQDN:
      p = hash_get_mem (gtm->node_index_by_fqdn, node_id->fqdn);
      break;
    }

  if (!p)
    return 0;

  return pool_elt_at_index (gtm->nodes, p[0]);
}

upf_node_assoc_t *
pfcp_new_association (session_handle_t session_handle,
		      ip46_address_t * lcl_addr, ip46_address_t * rmt_addr,
		      pfcp_node_id_t * node_id)
{
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;

  pool_get_aligned (gtm->nodes, n, CLIB_CACHE_LINE_BYTES);
  memset (n, 0, sizeof (*n));
  n->sessions = ~0;
  n->node_id = *node_id;
  n->session_handle = session_handle;
  n->lcl_addr = *lcl_addr;
  n->rmt_addr = *rmt_addr;

  switch (node_id->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      mhash_set (&gtm->node_index_by_ip, &node_id->ip, n - gtm->nodes, NULL);
      break;

    case NID_FQDN:
      n->node_id.fqdn = vec_dup (node_id->fqdn);
      hash_set_mem (gtm->node_index_by_fqdn, n->node_id.fqdn, n - gtm->nodes);
      break;
    }

  return n;
}

void
pfcp_release_association (upf_node_assoc_t * n)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_main_t *gtm = &upf_main;
  u32 node_id = n - gtm->nodes;
  u32 idx = n->sessions;
  pfcp_msg_t *msg;

  switch (n->node_id.type)
    {
    case NID_IPv4:
    case NID_IPv6:
      mhash_unset (&gtm->node_index_by_ip, &n->node_id.ip, NULL);
      break;

    case NID_FQDN:
      hash_unset_mem (gtm->node_index_by_fqdn, n->node_id.fqdn);
      vec_free (n->node_id.fqdn);
      break;
    }

  upf_debug ("pfcp_release_association idx: %u");

  while (idx != ~0)
    {
      upf_session_t *sx = pool_elt_at_index (gtm->sessions, idx);

      ASSERT (sx->assoc.node == node_id);

      idx = sx->assoc.next;

      if (pfcp_disable_session (sx, false) != 0)
	clib_error ("failed to remove UPF session 0x%016" PRIx64,
		    sx->cp_seid);
      pfcp_free_session (sx);
    }

  ASSERT (n->sessions == ~0);

  /* *INDENT-OFF* */
  pool_foreach (msg, psm->msg_pool,
  ({
    if (!msg->is_valid_pool_item || msg->node != node_id)
      continue;
    hash_unset (psm->request_q, msg->seq_no);
    mhash_unset (&psm->response_q, msg->request_key, NULL);
    upf_pfcp_server_stop_timer (msg->timer);
    pfcp_msg_pool_put (psm, msg);
  }));
  /* *INDENT-ON* */
}

static void
node_assoc_attach_session (upf_node_assoc_t * n, upf_session_t * sx)
{
  upf_main_t *gtm = &upf_main;
  u32 pfcp_idx = sx - gtm->sessions;

  sx->assoc.node = n - gtm->nodes;
  sx->assoc.prev = ~0;

  if (n->sessions != ~0)
    {
      upf_session_t *prev = pool_elt_at_index (gtm->sessions, n->sessions);

      ASSERT (prev->assoc.prev == ~0);
      ASSERT (prev->assoc.node == sx->assoc.node);
      ASSERT (!pool_is_free_index (gtm->sessions, n->sessions));

      prev->assoc.prev = pfcp_idx;
    }

  sx->assoc.next = n->sessions;
  n->sessions = pfcp_idx;
}

static void
node_assoc_detach_session (upf_session_t * sx)
{
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;

  ASSERT (sx->assoc.node != ~0);
  ASSERT (!pool_is_free_index (gtm->nodes, sx->assoc.node));

  if (sx->assoc.prev != ~0)
    {
      upf_session_t *prev = pool_elt_at_index (gtm->sessions, sx->assoc.prev);

      ASSERT (prev->assoc.node == sx->assoc.node);

      prev->assoc.next = sx->assoc.next;
    }
  else
    {
      n = pool_elt_at_index (gtm->nodes, sx->assoc.node);
      ASSERT (n->sessions != ~0);

      n->sessions = sx->assoc.next;
    }

  if (sx->assoc.next != ~0)
    {
      upf_session_t *next = pool_elt_at_index (gtm->sessions, sx->assoc.next);

      ASSERT (next->assoc.node == sx->assoc.node);

      next->assoc.prev = sx->assoc.prev;
    }

  sx->assoc.node = sx->assoc.prev = sx->assoc.next = ~0;
}

upf_session_t *
pfcp_create_session (upf_node_assoc_t * assoc,
		     const ip46_address_t * up_address, uint64_t cp_seid,
		     const ip46_address_t * cp_address)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  vlib_main_t *vm = vlib_get_main ();
  upf_main_t *gtm = &upf_main;
  upf_session_t *sx;

  upf_debug ("CP F-SEID: 0x%016" PRIx64 " @ %U\n"
	     "UP F-SEID: 0x%016" PRIx64 " @ %U\n",
	     cp_seid, format_ip46_address, cp_address, IP46_TYPE_ANY,
	     cp_seid, format_ip46_address, up_address, IP46_TYPE_ANY);

  vlib_worker_thread_barrier_sync (vm);

  pool_get_aligned (gtm->sessions, sx, CLIB_CACHE_LINE_BYTES);
  memset (sx, 0, sizeof (*sx));

  sx->up_address = *up_address;
  sx->cp_seid = cp_seid;
  sx->cp_address = *cp_address;

  sx->last_ul_traffic = vlib_time_now (psm->vlib_main);
  for (size_t i = 0; i < ARRAY_LEN (sx->rules); i++)
    sx->rules[i].inactivity_timer.handle = ~0;

  sx->unix_time_start = psm->now;

  clib_spinlock_init (&sx->lock);

  //TODO sx->up_f_seid = sx - gtm->sessions;
  node_assoc_attach_session (assoc, sx);
  hash_set (gtm->session_by_id, cp_seid, sx - gtm->sessions);

  vlib_worker_thread_barrier_release (vm);

  return sx;
}

void
pfcp_update_session (upf_session_t * sx)
{
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);

  // TODO: do we need some kind of update lock ?

  if (active->inactivity_timer.period != 0)
    pending->inactivity_timer = active->inactivity_timer;
}

static void
upf_peer_restack_dpo (upf_peer_t * p)
{
  dpo_id_t dpo = DPO_INVALID;

  fib_entry_contribute_forwarding (p->fib_entry_index, p->forw_type, &dpo);
  dpo_stack_from_node (p->encap_index, &p->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static upf_peer_t *
upf_peer_from_fib_node (fib_node_t * node)
{
  return ((upf_peer_t *) (((char *) node) -
			  STRUCT_OFFSET_OF (upf_peer_t, node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of GTPU DIP to encap node.
 */
static fib_node_back_walk_rc_t
upf_peer_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  upf_peer_restack_dpo (upf_peer_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
upf_peer_fib_node_get (fib_node_index_t index)
{
  upf_main_t *gtm = &upf_main;
  upf_peer_t *p;

  p = pool_elt_at_index (gtm->peers, index);

  return (&p->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
upf_peer_last_lock_gone (fib_node_t * node)
{
  /*
   * The GTP peer is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by GTPU tunnels
 * for participation in the FIB object graph.
 */
const fib_node_vft_t upf_vft = {
  .fnv_get = upf_peer_fib_node_get,
  .fnv_last_lock = upf_peer_last_lock_gone,
  .fnv_back_walk = upf_peer_back_walk,
};

static uword
peer_addr_ref (const upf_far_forward_t * fwd)
{
  u8 is_ip4 =
    !!(fwd->
       outer_header_creation.description & OUTER_HEADER_CREATION_ANY_IP4);
  upf_main_t *gtm = &upf_main;
  clib_bihash_kv_24_8_t kv, value;
  u32 fib_index;
  upf_peer_t *p;

  fib_index = (is_ip4) ?
    ip4_fib_table_get_index_for_sw_if_index (fwd->dst_sw_if_index) :
    ip6_fib_table_get_index_for_sw_if_index (fwd->dst_sw_if_index);

  kv.key[0] = fwd->outer_header_creation.ip.as_u64[0];
  kv.key[1] = fwd->outer_header_creation.ip.as_u64[1];
  kv.key[2] = fib_index;

  if (!clib_bihash_search_24_8 (&gtm->peer_index_by_ip, &kv, &value))
    {
      p = pool_elt_at_index (gtm->peers, value.value);
      p->ref_cnt++;
      return value.value;
    }

  pool_get_aligned (gtm->peers, p, CLIB_CACHE_LINE_BYTES);
  memset (p, 0, sizeof (*p));
  p->ref_cnt = 1;
  p->encap_fib_index = fib_index;

  if (is_ip4)
    {
      p->encap_index = upf4_encap_node.index;
      p->forw_type = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;
    }
  else
    {
      p->encap_index = upf6_encap_node.index;
      p->forw_type = FIB_FORW_CHAIN_TYPE_UNICAST_IP6;
    }

  kv.value = p - gtm->peers;
  clib_bihash_add_del_24_8 (&gtm->peer_index_by_ip, &kv, 1 /* is_add */ );

  fib_node_init (&p->node, gtm->fib_node_type);
  fib_prefix_t tun_dst_pfx;
  fib_prefix_from_ip46_addr (&fwd->outer_header_creation.ip, &tun_dst_pfx);

  p->fib_entry_index = fib_entry_track (p->encap_fib_index,
					&tun_dst_pfx,
					gtm->fib_node_type,
					p - gtm->peers, &p->sibling_index);
  upf_peer_restack_dpo (p);

  return p - gtm->peers;
}

static uword
peer_addr_unref (const upf_far_forward_t * fwd)
{
  u8 is_ip4 =
    !!(fwd->
       outer_header_creation.description & OUTER_HEADER_CREATION_ANY_IP4);
  upf_main_t *gtm = &upf_main;
  clib_bihash_kv_24_8_t kv, value;
  upf_peer_t *p = NULL;

  kv.key[0] = fwd->outer_header_creation.ip.as_u64[0];
  kv.key[1] = fwd->outer_header_creation.ip.as_u64[1];
  kv.key[2] = (is_ip4) ?
    ip4_fib_table_get_index_for_sw_if_index (fwd->dst_sw_if_index) :
    ip6_fib_table_get_index_for_sw_if_index (fwd->dst_sw_if_index);

  if (!clib_bihash_search_24_8 (&gtm->peer_index_by_ip, &kv, &value))
    p = pool_elt_at_index (gtm->peers, value.value);
  ASSERT (p);

  if (--(p->ref_cnt) != 0)
    return p->ref_cnt;

  clib_bihash_add_del_24_8 (&gtm->peer_index_by_ip, &kv, 0 /* is_add */ );

  fib_entry_untrack (p->fib_entry_index, p->sibling_index);
  fib_node_deinit (&p->node);
  pool_put (gtm->peers, p);

  return 0;
}

static inline void
pfcp_free_pdr (upf_pdr_t * pdr)
{
  upf_adf_put_adr_db (pdr->pdi.adr.db_id);
  vec_free (pdr->pdi.acl);
  vec_free (pdr->urr_ids);
  vec_free (pdr->qer_ids);
}

int
pfcp_make_pending_pdr (upf_session_t * sx)
{
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);

  if (pending->pdr)
    return 0;

  if (active->pdr)
    {
      size_t i;

      pending->pdr = vec_dup (active->pdr);
      vec_foreach_index (i, active->pdr)
      {
	upf_pdr_t *pdr = vec_elt_at_index (pending->pdr, i);

	pdr->pdi.adr.db_id = upf_adf_get_adr_db (pdr->pdi.adr.application_id);
	pdr->pdi.acl = vec_dup (vec_elt (active->pdr, i).pdi.acl);
	pdr->urr_ids = vec_dup (vec_elt (active->pdr, i).urr_ids);
	pdr->qer_ids = vec_dup (vec_elt (active->pdr, i).qer_ids);
      }
    }

  return 0;
}

static inline void
pfcp_free_far (upf_far_t * far)
{
  vec_free (far->forward.rewrite);
}

int
pfcp_make_pending_far (upf_session_t * sx)
{
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);

  if (pending->far)
    return 0;

  if (active->far)
    {
      size_t i;

      pending->far = vec_dup (active->far);
      vec_foreach_index (i, active->far)
      {
	upf_far_t *old = vec_elt_at_index (active->far, i);
	upf_far_t *new = vec_elt_at_index (pending->far, i);

	new->forward.rewrite = NULL;
	if (!(old->apply_action & FAR_FORWARD)
	    || old->forward.rewrite == NULL)
	  {
	    continue;
	  }

	new->forward.rewrite = vec_dup (old->forward.rewrite);
      }
    }

  return 0;
}

static inline void
pfcp_free_urr (upf_urr_t * urr)
{
  upf_urr_traffic_t *tt;

  /* *INDENT-OFF* */
  pool_foreach (tt, urr->traffic,
  ({
    hash_unset_mem_free (&urr->traffic_by_ue, &tt->ip);
  }));
  /* *INDENT-ON* */

  pool_free (urr->traffic);
  hash_free (urr->traffic_by_ue);
  vec_free (urr->linked_urr_ids);
  clib_bitmap_free (urr->liusa_bitmap);
}

int
pfcp_make_pending_urr (upf_session_t * sx)
{
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);
  upf_urr_t *urr;

  if (pending->urr)
    return 0;

  if (active->urr)
    {
      clib_spinlock_lock (&sx->lock);

      pending->urr = vec_dup (active->urr);
      vec_foreach (urr, pending->urr)
      {
	urr->update_flags = 0;
	urr->traffic = NULL;
	urr->traffic_by_ue = NULL;
	urr->linked_urr_ids = vec_dup (urr->linked_urr_ids);
	urr->liusa_bitmap = NULL;
	memset (&urr->volume.measure, 0, sizeof (urr->volume.measure));
      }

      clib_spinlock_unlock (&sx->lock);
    }

  return 0;
}

static upf_qer_policer_t *
init_qer_policer (upf_qer_t * qer)
{
  sse2_qos_pol_cfg_params_st cfg = {
    .rate_type = SSE2_QOS_RATE_KBPS,
    .rnd_type = SSE2_QOS_ROUND_TO_CLOSEST,
    .rfc = SSE2_QOS_POLICER_TYPE_1R2C,
    .color_aware = 0,
    .conform_action = {.action_type = SSE2_QOS_ACTION_TRANSMIT,},
    .exceed_action = {.action_type = SSE2_QOS_ACTION_DROP,},
    .violate_action = {.action_type = SSE2_QOS_ACTION_DROP,},
  };
  upf_main_t *gtm = &upf_main;
  upf_qer_policer_t *pol;

  pool_get_aligned_zero (gtm->qer_policers, pol, CLIB_CACHE_LINE_BYTES);
  qer->policer.value = pol - gtm->qer_policers;

  cfg.rb.kbps.cir_kbps = qer->mbr.ul;
  sse2_pol_logical_2_physical (&cfg, &pol->policer[UPF_UL]);

  cfg.rb.kbps.cir_kbps = qer->mbr.dl;
  sse2_pol_logical_2_physical (&cfg, &pol->policer[UPF_DL]);

  clib_bihash_add_del_8_8 (&gtm->qer_by_id, &qer->policer, 1 /* is_add */ );

  return pol;
}

static void
attach_qer_policer (upf_qer_t * qer)
{
  upf_main_t *gtm = &upf_main;
  upf_qer_policer_t *pol;

  if (qer->policer.key == ~0 || !(qer->flags & PFCP_QER_MBR))
    return;

  if (clib_bihash_search_inline_8_8 (&gtm->qer_by_id, &qer->policer))
    pol = init_qer_policer (qer);
  else
    pol = pool_elt_at_index (gtm->qer_policers, qer->policer.value);

  clib_atomic_fetch_add (&pol->ref_cnt, 1);

  //sse2_pol_logical_2_physical(&qer->cfg, pol);
}

static void
detach_qer_policer (upf_qer_t * qer)
{
  upf_main_t *gtm = &upf_main;
  upf_qer_policer_t *pol;

  if (qer->policer.value == ~0)
    return;

  pol = pool_elt_at_index (gtm->qer_policers, qer->policer.value);
  if (!clib_atomic_sub_fetch (&pol->ref_cnt, 1))
    {
      clib_bihash_add_del_8_8 (&gtm->qer_by_id, &qer->policer,
			       0 /* is_add */ );
      pool_put (gtm->qer_policers, pol);
    }
}

static inline void
pfcp_free_qer (upf_qer_t * qer)
{
  detach_qer_policer (qer);
}

int
pfcp_make_pending_qer (upf_session_t * sx)
{
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);
  upf_qer_t *qer;

  if (pending->qer)
    return 0;

  if (active->qer)
    {
      pending->qer = vec_dup (active->qer);
      vec_foreach (qer, pending->qer)
      {
	qer->policer.value = ~0;
      }
    }

  return 0;
}

static void
pfcp_free_rules (upf_session_t * sx, int rule)
{
  struct rules *rules = pfcp_get_rules (sx, rule);
  upf_pdr_t *pdr;
  upf_far_t *far;
  upf_urr_t *urr;
  upf_qer_t *qer;

  vec_foreach (pdr, rules->pdr)
  {
    pfcp_free_pdr (pdr);
  }

  vec_free (rules->pdr);
  vec_foreach (far, rules->far)
  {
    pfcp_free_far (far);
  }
  vec_free (rules->far);
  vec_foreach (urr, rules->urr)
  {
    pfcp_free_urr (urr);
  }
  vec_free (rules->urr);
  vec_foreach (qer, rules->qer)
  {
    pfcp_free_qer (qer);
  }
  vec_free (rules->qer);
  vec_free (rules->ue_src_ip);
  vec_free (rules->ue_dst_ip);
  vec_free (rules->v4_teid);
  vec_free (rules->v6_teid);
  vec_free (rules->v4_acls);
  vec_free (rules->v6_acls);

  memset (rules, 0, sizeof (*rules));
}

int
pfcp_disable_session (upf_session_t * sx, int drop_msgs)
{
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);
  pfcp_server_main_t *psm = &pfcp_server_main;
  const f64 now = psm->timer.last_run_time;
  upf_main_t *gtm = &upf_main;
  ue_ip_t *ue_ip;
  gtpu4_endp_rule_t *v4_teid;
  gtpu6_endp_rule_t *v6_teid;
  upf_urr_t *urr;
  upf_acl_t *acl;

  hash_unset (gtm->session_by_id, sx->cp_seid);
  vec_foreach (v4_teid, active->v4_teid) pfcp_add_del_v4_teid (v4_teid, sx,
							       0);
  vec_foreach (v6_teid, active->v6_teid) pfcp_add_del_v6_teid (v6_teid, sx,
							       0);
  vec_foreach (ue_ip, active->ue_dst_ip) pfcp_add_del_ue_ip (ue_ip, sx, 0);
  vec_foreach (ue_ip, active->ue_src_ip) pfcp_add_del_ue_ip (ue_ip, sx, 0);
  vec_foreach (acl, active->v4_acls) pfcp_add_del_v4_tdf (acl, sx, 0);
  vec_foreach (acl, active->v6_acls) pfcp_add_del_v6_tdf (acl, sx, 0);

  node_assoc_detach_session (sx);

  //TODO: free DL fifo...

  //gtm->session_index_by_sw_if_index[sx->sw_if_index] = ~0;

  /* stop all timers */
  vec_foreach (urr, active->urr)
  {
    upf_pfcp_session_stop_urr_time (&urr->measurement_period, now);
    upf_pfcp_session_stop_urr_time (&urr->time_threshold, now);
    upf_pfcp_session_stop_urr_time (&urr->time_quota, now);
    upf_pfcp_session_stop_urr_time (&urr->traffic_timer, now);
  }
  upf_pfcp_session_stop_up_inactivity_timer (&active->inactivity_timer);

  if (drop_msgs)
    {
      u32 si = sx - gtm->sessions;
      pfcp_msg_t *msg;

      /* *INDENT-OFF* */
      pool_foreach (msg, psm->msg_pool,
      ({
	if (!msg->is_valid_pool_item || msg->session_index != si)
	  continue;

	hash_unset (psm->request_q, msg->seq_no);
	mhash_unset (&psm->response_q, msg->request_key, NULL);
	upf_pfcp_server_stop_timer (msg->timer);
	pfcp_msg_pool_put (psm, msg);
      }));
      /* *INDENT-ON* */

    }

  return 0;
}

void
pfcp_free_session (upf_session_t * sx)
{
  vlib_main_t *vm = vlib_get_main ();
  upf_main_t *gtm = &upf_main;

  vlib_worker_thread_barrier_sync (vm);

  for (size_t i = 0; i < ARRAY_LEN (sx->rules); i++)
    pfcp_free_rules (sx, i);

  clib_spinlock_free (&sx->lock);
  pool_put (gtm->sessions, sx);

  vlib_worker_thread_barrier_release (vm);

}

#define pfcp_rule_vector_fns(t, REMOVE)					\
upf_##t##_t * pfcp_get_##t##_by_id(struct rules *rules,			\
				   typeof (((upf_##t##_t *)0)->id) t##_id) \
{									\
  upf_##t##_t r = { .id = t##_id };					\
									\
  return vec_bsearch(&r, rules->t, pfcp_##t##_id_compare);		\
}									\
									\
upf_##t##_t *pfcp_get_##t(upf_session_t *sx, int rule,		\
			  typeof (((upf_##t##_t *)0)->id) t##_id)	\
{									\
  struct rules *rules = pfcp_get_rules(sx, rule);				\
  upf_##t##_t r = { .id = t##_id };					\
									\
  if (rule == PFCP_PENDING)						\
    if (pfcp_make_pending_##t(sx) != 0)					\
      return NULL;							\
									\
  printf("LOOKUP t##: %u\n", t##_id);					\
  return vec_bsearch(&r, rules->t, pfcp_##t##_id_compare);		\
}									\
									\
int pfcp_sort_##t##s(struct rules *rules)					\
{									\
  vec_sort_with_function(rules->t, pfcp_##t##_id_compare);		\
  return 0;								\
}									\
									\
int pfcp_delete_##t(upf_session_t *sx, u32 t##_id)			\
{									\
  struct rules *rules = pfcp_get_rules(sx, PFCP_PENDING);			\
  upf_##t##_t r = { .id = t##_id };					\
  upf_##t##_t *p;							\
									\
  if (pfcp_make_pending_##t(sx) != 0)					\
    return -1;								\
									\
  if (!(p = vec_bsearch(&r, rules->t, pfcp_##t##_id_compare)))		\
    return -1;								\
									\
  do { REMOVE; } while (0);						\
  pfcp_free_##t (p);							\
									\
  vec_delete(rules->t, 1, p - rules->t);				\
  return 0;								\
}

/* *INDENT-OFF* */
pfcp_rule_vector_fns(pdr, ({}))
pfcp_rule_vector_fns(far, ({}))
pfcp_rule_vector_fns(urr, ({}))
pfcp_rule_vector_fns(qer, ({}))
/* *INDENT-ON* */

void
pfcp_send_end_marker (upf_session_t * sx, u16 far_id)
{
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  upf_far_t r = {.id = far_id };
  upf_main_t *gtm = &upf_main;
  send_end_marker_t *send_em;
  upf_peer_t *peer;
  upf_far_t *far;

  if (!(far = vec_bsearch (&r, active->far, pfcp_far_id_compare)))
    return;

  peer = pool_elt_at_index (gtm->peers, far->forward.peer_idx);

  vec_add2 (pending->send_end_marker, send_em, 1);
  send_em->far_id = far_id;
  send_em->fib_index = peer->encap_fib_index;
  send_em->dpoi_index = peer->next_dpo.dpoi_index;
}

static int
ip46_address_fib_cmp (const void *a0, const void *b0)
{
  const ip46_address_fib_t *a = a0;
  const ip46_address_fib_t *b = b0;
  int r;

  if ((r = intcmp (a->fib_index, b->fib_index)) != 0)
    return r;

  return ip46_address_cmp (&a->addr, &b->addr);
}

static int
v4_teid_cmp (const void *a0, const void *b0)
{
  const gtpu4_endp_rule_t *a = a0;
  const gtpu4_endp_rule_t *b = b0;
  return memcmp (&a->key, &b->key, sizeof (a->key));
}

static int
v6_teid_cmp (const void *a0, const void *b0)
{
  const gtpu6_endp_rule_t *a = a0;
  const gtpu6_endp_rule_t *b = b0;
  return memcmp (&a->key, &b->key, sizeof (a->key));
}

static int
upf_acl_cmp (const void *a, const void *b)
{
  return memcmp (a, b, offsetof (upf_acl_t, pdr_idx));
}

//TODO: instead of using the UE IP, we should use the DL SDF dst fields
static void
pfcp_add_del_ue_ip (const void *ip, void *si, int is_add)
{
  const ue_ip_t *ue_ip = ip;
  upf_session_t *sx = si;
  fib_prefix_t pfx;

  memset (&pfx, 0, sizeof (pfx));

  if (ip46_address_is_ip4 (&ue_ip->addr))
    {
      pfx.fp_addr.ip4.as_u32 = ue_ip->addr.ip4.as_u32;
      pfx.fp_len = 32;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      pfx.fp_addr.ip6.as_u64[0] = ue_ip->addr.ip6.as_u64[0];
      pfx.fp_addr.ip6.as_u64[1] = ue_ip->addr.ip6.as_u64[1];
      pfx.fp_len = 64;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
    }

  if (is_add)
    {
      dpo_id_t sxd = DPO_INVALID;

      upf_session_dpo_add_or_lock (fib_proto_to_dpo (pfx.fp_proto), sx, &sxd);

      /* add reverse route for client ip through special DPO */
      fib_table_entry_special_dpo_add (ue_ip->fib_index, &pfx,
				       FIB_SOURCE_SPECIAL,
				       FIB_ENTRY_FLAG_EXCLUSIVE |
				       FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
				       &sxd);
    }
  else
    {
      /* delete reverse route for client ip */
      fib_table_entry_special_remove (ue_ip->fib_index, &pfx,
				      FIB_SOURCE_SPECIAL);
    }
}

static void
pfcp_add_del_v4_teid (const void *teid, void *si, int is_add)
{
  upf_main_t *gtm = &upf_main;
  upf_session_t *sess = si;
  const gtpu4_endp_rule_t *v4_teid = teid;
  clib_bihash_kv_8_8_t kv;

  kv.key = v4_teid->key.as_u64;
  kv.value = ((u64) v4_teid->rule_index << 32) | (sess - gtm->sessions);

  upf_debug
    ("upf_pfcp: is_add: %d, TEID: 0x%08x, IP:%U, Session:%p, idx: %p.",
     is_add, v4_teid->key.teid, format_ip4_address, &v4_teid->key.dst, sess,
     sess - gtm->sessions);

  clib_bihash_add_del_8_8 (&gtm->v4_tunnel_by_key, &kv, is_add);
}

static void
pfcp_add_del_v6_teid (const void *teid, void *si, int is_add)
{
  upf_main_t *gtm = &upf_main;
  upf_session_t *sess = si;
  const gtpu6_endp_rule_t *v6_teid = teid;
  clib_bihash_kv_24_8_t kv;

  kv.key[0] = v6_teid->key.dst.as_u64[0];
  kv.key[1] = v6_teid->key.dst.as_u64[1];
  kv.key[2] = v6_teid->key.teid;
  kv.value = ((u64) v6_teid->rule_index << 32) | (sess - gtm->sessions);

  upf_debug
    ("upf_pfcp: is_add: %d, TEID: 0x%08x, IP:%U, Session:%p, idx: %p.",
     is_add, v6_teid->key.teid, format_ip6_address, &v6_teid->key.dst, sess,
     sess - gtm->sessions);

  clib_bihash_add_del_24_8 (&gtm->v6_tunnel_by_key, &kv, is_add);
}

static void
pfcp_add_del_tdf (const void *tdf, void *si, int is_ip4, int is_add)
{
  upf_main_t *gtm = &upf_main;
  upf_acl_t *acl = (upf_acl_t *) tdf;
  upf_session_t *sx = si;
  fib_prefix_t pfx = {
    .fp_addr = acl->match.address[UPF_ACL_FIELD_SRC],
  };
  u32 fib_index;

  if (acl->fib_index >= vec_len (gtm->tdf_ul_table[pfx.fp_proto]))
    return;

  upf_debug ("acl fib idx: 0x%08x, tdf fib idx: 0x%08x, ACL: %U\n",
	     acl->fib_index,
	     vec_elt (gtm->tdf_ul_table[pfx.fp_proto], acl->fib_index),
	     format_upf_acl, acl);

  fib_index = vec_elt (gtm->tdf_ul_table[pfx.fp_proto], acl->fib_index);
  if (~0 == fib_index)
    return;

  if (is_ip4)
    {
      pfx.fp_proto = FIB_PROTOCOL_IP4;
      pfx.fp_len =
	ip4_mask_to_preflen (&acl->mask.address[UPF_ACL_FIELD_SRC].ip4);
    }
  else
    {
      pfx.fp_proto = FIB_PROTOCOL_IP6;
      pfx.fp_len =
	ip6_mask_to_preflen (&acl->mask.address[UPF_ACL_FIELD_SRC].ip6);
    }

  if (is_add)
    {
      dpo_id_t sxd = DPO_INVALID;

      upf_session_dpo_add_or_lock (fib_proto_to_dpo (pfx.fp_proto), sx, &sxd);

      /* add reverse route for client ip through special DPO */
      fib_table_entry_special_dpo_add (fib_index, &pfx,
				       FIB_SOURCE_SPECIAL,
				       FIB_ENTRY_FLAG_ATTACHED,
				       // FIB_ENTRY_FLAG_EXCLUSIVE | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT,
				       &sxd);
    }
  else
    {
      /* delete reverse route for client ip */
      fib_table_entry_special_remove (fib_index, &pfx, FIB_SOURCE_SPECIAL);
    }
}

static void
pfcp_add_del_v4_tdf (const void *tdf, void *si, int is_add)
{
  pfcp_add_del_tdf (tdf, si, 1 /* is_ip4 */ , is_add);
}

static void
pfcp_add_del_v6_tdf (const void *tdf, void *si, int is_add)
{
  pfcp_add_del_tdf (tdf, si, 0 /* is_ip4 */ , is_add);
}

u8 *
format_upf_acl (u8 * s, va_list * args)
{
  upf_acl_t *acl = va_arg (*args, upf_acl_t *);
  ip46_type_t itype = (acl->is_ip4) ? IP46_TYPE_IP4 : IP46_TYPE_IP6;

  return format (s,
		 "%u: %u, (%u/%u/%u/%u) TEID 0x%08x, UE-IP %U, %u/%u, %U/%U:%u-%u <-> %U/%U:%u-%u",
		 acl->pdr_idx, acl->precedence, !!acl->is_ip4,
		 !!acl->match_teid, !!acl->match_ue_ip, !!acl->match_sdf,
		 acl->teid, format_ip46_address, &acl->ue_ip, itype,
		 acl->match.protocol, acl->mask.protocol, format_ip46_address,
		 &acl->match.address[IPFILTER_RULE_FIELD_SRC], itype,
		 format_ip46_address,
		 &acl->mask.address[IPFILTER_RULE_FIELD_SRC], itype,
		 acl->mask.port[IPFILTER_RULE_FIELD_SRC],
		 acl->match.port[IPFILTER_RULE_FIELD_SRC],
		 format_ip46_address,
		 &acl->match.address[IPFILTER_RULE_FIELD_DST], itype,
		 format_ip46_address,
		 &acl->mask.address[IPFILTER_RULE_FIELD_DST], itype,
		 acl->mask.port[IPFILTER_RULE_FIELD_DST],
		 acl->match.port[IPFILTER_RULE_FIELD_DST]);
}

always_inline u32
upf_fib_index_by_sw_if_index (u32 sw_if_index, int is_ip4)
{
  u32 *fib_index_by_sw_if_index = is_ip4 ?
    ip4_main.fib_index_by_sw_if_index : ip6_main.fib_index_by_sw_if_index;

  return vec_elt (fib_index_by_sw_if_index, sw_if_index);
}

/* Maybe should be moved into the core somewhere */
always_inline void
ip4_address_mask_from_width (ip4_address_t * a, u32 width)
{
  int i, byte, bit, bitnum;
  ASSERT (width <= 32);
  clib_memset (a, 0, sizeof (a[0]));
  for (i = 0; i < width; i++)
    {
      bitnum = (7 - (i & 7));
      byte = i / 8;
      bit = 1 << bitnum;
      a->as_u8[byte] |= bit;
    }
}

always_inline void
compile_teid (const upf_pdr_t * pdr, upf_acl_t * acl)
{
  if (!(pdr->pdi.fields & F_PDI_LOCAL_F_TEID))
    return;

  acl->match_teid = 1;
  acl->teid = pdr->pdi.teid.teid;
}

static void
compile_ue_ip (int is_ip4, const upf_pdr_t * pdr, upf_acl_t * acl)
{
  if (!(pdr->pdi.fields & F_PDI_UE_IP_ADDR))
    return;

  if (is_ip4 && pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
    {
      acl->match_ue_ip =
	(pdr->pdi.src_intf == SRC_INTF_ACCESS) ? UPF_ACL_UL : UPF_ACL_DL;
      ip46_address_set_ip4 (&acl->ue_ip, &pdr->pdi.ue_addr.ip4);
    }
  else if (!is_ip4 && pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
    {
      acl->match_ue_ip =
	(pdr->pdi.src_intf == SRC_INTF_ACCESS) ? UPF_ACL_UL : UPF_ACL_DL;
      ip46_address_set_ip6 (&acl->ue_ip, &pdr->pdi.ue_addr.ip6);
    }
}

static void
acl_set_ue_ip (ip46_address_t * ip, ip46_address_t * mask, int is_ip4,
	       const upf_pdr_t * pdr)
{
  if (!(pdr->pdi.fields & F_PDI_UE_IP_ADDR))
    return;

  if (is_ip4 && pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
    {
      ip46_address_set_ip4 (ip, &pdr->pdi.ue_addr.ip4);
      ip46_address_mask_ip4 (mask);
      ip4_address_mask_from_width (&mask->ip4, 32);
    }
  else if (!is_ip4 && pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
    {
      ip46_address_set_ip6 (ip, &pdr->pdi.ue_addr.ip6);
      ip6_address_mask_from_width (&mask->ip6, 64);
    }
}

static void
ip_assign_address (int dst, int src, int is_ip4, const upf_pdr_t * pdr,
		   const acl_rule_t * rule, upf_acl_t * acl)
{
  ip46_address_t *mask = &acl->mask.address[dst];
  ip46_address_t *ip = &acl->match.address[dst];
  const ipfilter_address_t *addr = &rule->address[src];

  if (acl_addr_is_any (addr))
    ;
  else if (acl_addr_is_assigned (addr))
    acl_set_ue_ip (ip, mask, is_ip4, pdr);
  else
    {
      *ip = addr->address;

      if (is_ip4)
	{
	  ip46_address_mask_ip4 (mask);
	  ip4_address_mask_from_width (&mask->ip4, addr->mask);
	}
      else
	ip6_address_mask_from_width (&mask->ip6, addr->mask);
    }
}

static void
ip_assign_port (int dst, int src, const acl_rule_t * rule, upf_acl_t * acl)
{
  const ipfilter_port_t *port = &rule->port[src];

  acl->mask.port[dst] = port->min;
  acl->match.port[dst] = port->max;
}

static void
compile_sdf (int is_ip4, const upf_pdr_t * pdr,
	     const acl_rule_t * rule, upf_acl_t * acl)
{
  if (!(pdr->pdi.fields & F_PDI_SDF_FILTER))
    return;

  acl->match_sdf = 1;

  if (rule->proto != (u8) ~ 0)
    {
      acl->mask.protocol = ~0;
      acl->match.protocol = rule->proto;
    }

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      ip_assign_address (UPF_ACL_FIELD_DST, IPFILTER_RULE_FIELD_SRC, is_ip4,
			 pdr, rule, acl);
      ip_assign_address (UPF_ACL_FIELD_SRC, IPFILTER_RULE_FIELD_DST, is_ip4,
			 pdr, rule, acl);
      ip_assign_port (UPF_ACL_FIELD_DST, IPFILTER_RULE_FIELD_SRC, rule, acl);
      ip_assign_port (UPF_ACL_FIELD_SRC, IPFILTER_RULE_FIELD_DST, rule, acl);
      break;

    default:
      ip_assign_address (UPF_ACL_FIELD_SRC, IPFILTER_RULE_FIELD_SRC, is_ip4,
			 pdr, rule, acl);
      ip_assign_address (UPF_ACL_FIELD_DST, IPFILTER_RULE_FIELD_DST, is_ip4,
			 pdr, rule, acl);
      ip_assign_port (UPF_ACL_FIELD_DST, IPFILTER_RULE_FIELD_SRC, rule, acl);
      ip_assign_port (UPF_ACL_FIELD_SRC, IPFILTER_RULE_FIELD_DST, rule, acl);
      break;
    }
}

static int
compile_ipfilter_rule (int is_ip4, const upf_pdr_t * pdr,
		       const acl_rule_t * rule, u32 pdr_idx, u32 sw_if_index,
		       upf_acl_t * acl)
{
  memset (acl, 0, sizeof (*acl));

  acl->is_ip4 = is_ip4;
  acl->precedence = pdr->precedence;
  acl->fib_index = upf_fib_index_by_sw_if_index (sw_if_index, is_ip4);
  acl->pdr_idx = pdr_idx;

  compile_teid (pdr, acl);
  compile_sdf (is_ip4, pdr, rule, acl);
  compile_ue_ip (is_ip4, pdr, acl);

  upf_debug ("ACL: ip4 %u, %U\n", is_ip4, format_upf_acl, acl);
  return 0;
}

static void
rules_add_v4_teid (struct rules *r, const ip4_address_t * addr, u32 teid,
		   u32 rule_index)
{
  gtpu4_endp_rule_t endp, *e;

  endp.key.teid = teid;
  endp.key.dst = addr->as_u32;
  endp.rule_index = rule_index;

  vec_foreach (e, r->v4_teid)
  {
    if (e->key.as_u64 == endp.key.as_u64)
      break;
  }
  if (e == vec_end (r->v4_teid))
    vec_add1 (r->v4_teid, endp);
  else
    /* mark duplicate TEID */
    e->rule_index = ~0;
}

static void
rules_add_v6_teid (struct rules *r, const ip6_address_t * addr, u32 teid,
		   u32 rule_index)
{
  gtpu6_endp_rule_t endp, *e;

  endp.key.teid = teid;
  endp.key.dst = *addr;
  endp.rule_index = rule_index;

  vec_foreach (e, r->v6_teid)
  {
    if (memcmp (&e->key, &endp.key, sizeof (endp.key)) == 0)
      break;
  }
  if (e == vec_end (r->v6_teid))
    vec_add1 (r->v6_teid, endp);
  else
    /* mark duplicate TEID */
    e->rule_index = ~0;
}

static void
rules_add_ue_ip (struct rules *r, fib_protocol_t fproto,
		 ue_ip_t * ue_ip, u8 is_dst)
{
  upf_main_t *gtm = &upf_main;

  if (is_dst)
    vec_add1 (r->ue_dst_ip, *ue_ip);
  else
    {
      u32 fib_index = ~0;

      if (ue_ip->fib_index < vec_len (gtm->tdf_ul_table[fproto]))
	fib_index = vec_elt (gtm->tdf_ul_table[fproto], ue_ip->fib_index);

      if (~0 != fib_index)
	{
	  ue_ip->fib_index = fib_index;
	  vec_add1 (r->ue_src_ip, *ue_ip);
	}
    }
}

static int
build_pfcp_rules (upf_session_t * sx)
{
  upf_main_t *gtm = &upf_main;
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  u32 idx;

  pending->proxy_precedence = ~0;
  pending->proxy_pdr_idx = ~0;

  vec_foreach_index (idx, pending->pdr)
  {
    upf_pdr_t *pdr = vec_elt_at_index (pending->pdr, idx);
    u32 sw_if_index = ~0;

    if (pdr->pdi.nwi_index != ~0)
      {
	upf_nwi_t *nwi = pool_elt_at_index (gtm->nwis, pdr->pdi.nwi_index);
	sw_if_index = nwi->sw_if_index;
      }

    /* create UE IP route from SGi Network Instance into Session */

    /*
     * From 3GPP TS 29.244 version 14.3.0, Table 7.5.2.2-2
     *
     * NOTE 2: When a Local F-TEID is provisioned in the PDI, the
     *         Network Instance shall relate to the IP address of
     *         the F-TEID. Otherwise, the Network Instance shall
     *         relate to the UE IP address.
     */
    if (!(pdr->pdi.fields & F_PDI_LOCAL_F_TEID) &&
	pdr->pdi.fields & F_PDI_UE_IP_ADDR)
      {
	ue_ip_t ue_ip;
	u8 is_dst = !!(pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_SD);

	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
	  {
	    ip46_address_set_ip4 (&ue_ip.addr, &pdr->pdi.ue_addr.ip4);
	    ue_ip.fib_index =
	      upf_fib_index_by_sw_if_index (sw_if_index, 1 /* is_ip4 */ );
	    ue_ip.sw_if_index = sw_if_index;

	    upf_debug ("UP FIB Idx %u, sw_if_index %u",
		       ue_ip.fib_index, ue_ip.sw_if_index);
	    rules_add_ue_ip (pending, FIB_PROTOCOL_IP4, &ue_ip, is_dst);
	  }

	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
	  {
	    ue_ip.addr.ip6 = pdr->pdi.ue_addr.ip6;
	    ue_ip.fib_index =
	      upf_fib_index_by_sw_if_index (sw_if_index, 0 /* is_ip4 */ );
	    ue_ip.sw_if_index = sw_if_index;

	    rules_add_ue_ip (pending, FIB_PROTOCOL_IP6, &ue_ip, is_dst);
	  }
      }

    /* register Local F-TEIDs */
    if (pdr->pdi.fields & F_PDI_LOCAL_F_TEID)
      {
	if (pdr->pdi.teid.flags & F_TEID_V4)
	  rules_add_v4_teid (pending, &pdr->pdi.teid.ip4,
			     pdr->pdi.teid.teid, idx);

	if (pdr->pdi.teid.flags & F_TEID_V6)
	  rules_add_v6_teid (pending, &pdr->pdi.teid.ip6,
			     pdr->pdi.teid.teid, idx);
      }

    if (pdr->pdi.fields & F_PDI_SDF_FILTER)
      {
	acl_rule_t *rule;

	vec_foreach (rule, pdr->pdi.acl)
	{
	  if (rule->type == IPFILTER_IPV4 || rule->type == IPFILTER_WILDCARD)
	    {
	      upf_acl_t *acl;

	      vec_add2 (pending->v4_acls, acl, 1);
	      /* compile PDI into ACL matcher */
	      compile_ipfilter_rule (1 /* is_ip4 */ , pdr, rule, idx,
				     sw_if_index, acl);
	    }

	  if (rule->type == IPFILTER_IPV6 || rule->type == IPFILTER_WILDCARD)
	    {
	      upf_acl_t *acl;

	      vec_add2 (pending->v6_acls, acl, 1);
	      /* compile PDI into ACL matcher */
	      compile_ipfilter_rule (0 /* is_ip4 */ , pdr, rule, idx,
				     sw_if_index, acl);
	    }
	}
      }
    else if ((pdr->pdi.fields & F_PDI_APPLICATION_ID))
      {

	if ((pdr->pdi.adr.flags & UPF_ADR_PROXY) &&
	    pdr->precedence < pending->proxy_precedence)
	  {
	    pending->proxy_precedence = pdr->precedence;
	    pending->proxy_pdr_idx = idx;
	  }

	pending->flags |= PFCP_ADR;
      }
  }

  if (vec_len (pending->ue_src_ip) != 0 || vec_len (pending->ue_dst_ip) != 0
      || vec_len (pending->v4_acls) != 0 || vec_len (pending->v6_acls) != 0)
    pending->flags |= PFCP_CLASSIFY;

  return 0;
}

static void
build_urr_link_map (upf_session_t * sx)
{
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  u32 idx;

  vec_foreach_index (idx, pending->urr)
  {
    upf_urr_t *urr = vec_elt_at_index (pending->urr, idx);
    u32 *id;

    vec_foreach (id, urr->linked_urr_ids)
    {
      upf_urr_t *l;

      l = pfcp_get_urr_by_id (pending, *id);
      if (!l)
	continue;

      l->liusa_bitmap = clib_bitmap_set (l->liusa_bitmap, idx, 1);
    }
  }
}

int
pfcp_update_apply (upf_session_t * sx)
{
  struct rules *pending = pfcp_get_rules (sx, PFCP_PENDING);
  struct rules *active = pfcp_get_rules (sx, PFCP_ACTIVE);
  int pending_pdr, pending_far, pending_urr, pending_qer;
  pfcp_server_main_t *psm = &pfcp_server_main;
  vlib_main_t *vm = vlib_get_main ();
  upf_main_t *gtm = &upf_main;
  u32 si = sx - gtm->sessions;
  f64 now = psm->now;
  upf_urr_t *urr;

  if (!pending->pdr && !pending->far && !pending->urr && !pending->qer)
    return 0;

  pending_pdr = !!pending->pdr;
  pending_far = !!pending->far;
  pending_urr = !!pending->urr;
  pending_qer = !!pending->qer;

  vlib_worker_thread_barrier_sync (vm);

  if (pending_pdr)
    {
      if (build_pfcp_rules (sx) != 0)
	{
	  vlib_worker_thread_barrier_release (vm);
	  return -1;
	}
    }
  else
    {
      pending->pdr = active->pdr;

      pending->proxy_precedence = active->proxy_precedence;
      pending->proxy_pdr_idx = active->proxy_pdr_idx;

      pending->ue_src_ip = active->ue_src_ip;
      active->ue_src_ip = NULL;

      pending->ue_dst_ip = active->ue_dst_ip;
      active->ue_dst_ip = NULL;

      pending->v4_teid = active->v4_teid;
      active->v4_teid = NULL;
      pending->v6_teid = active->v6_teid;
      active->v6_teid = NULL;

      pending->v4_acls = active->v4_acls;
      active->v4_acls = NULL;
      pending->v6_acls = active->v6_acls;
      active->v6_acls = NULL;

      pending->flags = active->flags;
    }

  if (pending_far)
    {
      upf_far_t *far;

      vec_foreach (far, pending->far)
	if (far->forward.outer_header_creation.description != 0)
	{
	  far->forward.peer_idx = peer_addr_ref (&far->forward);

	  if (far->forward.outer_header_creation.description
	      & OUTER_HEADER_CREATION_GTP_IP4)
	    {
	      rules_add_v4_teid (pending,
				 &far->forward.outer_header_creation.ip.ip4,
				 far->forward.outer_header_creation.teid,
				 far->id);
	    }
	  else if (far->forward.outer_header_creation.description
		   & OUTER_HEADER_CREATION_GTP_IP6)
	    {
	      rules_add_v6_teid (pending,
				 &far->forward.outer_header_creation.ip.ip6,
				 far->forward.outer_header_creation.teid,
				 far->id);
	    }
	}
    }
  else
    pending->far = active->far;

  if (pending_urr)
    build_urr_link_map (sx);
  else
    pending->urr = active->urr;

  if (pending_qer)
    {
      upf_qer_t *qer;

      vec_foreach (qer, pending->qer)
      {
	attach_qer_policer (qer);
      }
    }
  else
    pending->qer = active->qer;

  if (pending_pdr)
    {
      sx->flags |= PFCP_UPDATING;

      /* update UE addresses and TEIDs */
      vec_diff (pending->ue_dst_ip, active->ue_dst_ip, ip46_address_fib_cmp,
		pfcp_add_del_ue_ip, sx);
      vec_diff (pending->v4_teid, active->v4_teid, v4_teid_cmp,
		pfcp_add_del_v4_teid, sx);
      vec_diff (pending->v6_teid, active->v6_teid, v6_teid_cmp,
		pfcp_add_del_v6_teid, sx);

      upf_debug ("v4 TEIDs %u\n", pending->v4_teid);
      upf_debug ("v6 TEIDs %u\n", pending->v6_teid);
      upf_debug ("UE Src IPs %u\n", pending->ue_src_ip);
      upf_debug ("v4 ACLs %u\n", pending->v4_acls);
      upf_debug ("v6 ACLs %u\n", pending->v6_acls);

      vec_diff (pending->ue_src_ip, active->ue_src_ip, ip46_address_fib_cmp,
		pfcp_add_del_ue_ip, sx);

      /* has PDRs but no TEIDs or UE IPs, add to global wildcard TDF table */
      vec_diff (pending->v4_acls, active->v4_acls, upf_acl_cmp,
		pfcp_add_del_v4_tdf, sx);
      vec_diff (pending->v6_acls, active->v6_acls, upf_acl_cmp,
		pfcp_add_del_v6_tdf, sx);
    }

  /* flip the switch */
  sx->active ^= PFCP_PENDING;
  sx->flags &= ~PFCP_UPDATING;

  pending = pfcp_get_rules (sx, PFCP_PENDING);
  active = pfcp_get_rules (sx, PFCP_ACTIVE);

  if (active->inactivity_timer.handle != pending->inactivity_timer.handle)
    upf_pfcp_session_stop_up_inactivity_timer (&pending->inactivity_timer);
  upf_pfcp_session_start_up_inactivity_timer (si, sx->last_ul_traffic,
					      &active->inactivity_timer);

  if (pending_far)
    {
      upf_far_t *far;

      vec_foreach (far, pending->far)
      {
	if (far->forward.outer_header_creation.description != 0)
	  peer_addr_unref (&far->forward);
      }
    }

  vlib_worker_thread_barrier_release (vm);

  if (active->send_end_marker)
    {
      send_end_marker_t *send_em;

      vec_foreach (send_em, active->send_end_marker)
      {
	upf_far_t r = {.id = send_em->far_id };
	upf_far_t *far;
	int is_ip4;
	u32 bi;

	if (!(far = vec_bsearch (&r, pending->far, pfcp_far_id_compare)))
	  continue;

	is_ip4 =
	  !!(far->forward.outer_header_creation.description &
	     OUTER_HEADER_CREATION_ANY_IP4);

	upf_debug ("TODO: send_end_marker for FAR %d", far->id);
	bi = upf_gtpu_end_marker (send_em->fib_index, send_em->dpoi_index,
				  far->forward.rewrite, is_ip4);
	upf_ip_lookup_tx (bi, is_ip4);
      }
      vec_free (active->send_end_marker);
    }

  vec_foreach (urr, active->urr)
  {
    if (urr->update_flags & PFCP_URR_UPDATE_MEASUREMENT_PERIOD)
      {
	upf_pfcp_session_start_stop_urr_time
	  (si, &urr->measurement_period,
	   !!(urr->triggers & REPORTING_TRIGGER_PERIODIC_REPORTING));
      }

    if ((urr->methods & PFCP_URR_TIME))
      {
	if (urr->update_flags & PFCP_URR_UPDATE_TIME_THRESHOLD)
	  {
	    upf_pfcp_session_start_stop_urr_time
	      (si, &urr->time_threshold,
	       !!(urr->triggers & REPORTING_TRIGGER_TIME_THRESHOLD));
	  }
	if (urr->update_flags & PFCP_URR_UPDATE_TIME_QUOTA)
	  {
	    urr->time_quota.base =
	      (urr->time_threshold.base !=
	       0) ? urr->time_threshold.base : now;
	    upf_pfcp_session_start_stop_urr_time (si, &urr->time_quota,
						  !!(urr->triggers &
						     REPORTING_TRIGGER_TIME_QUOTA));
	  }
      }
  }

  if (!pending_pdr)
    pending->pdr = NULL;
  if (!pending_far)
    pending->far = NULL;
  if (pending_urr)
    {
      clib_spinlock_lock (&sx->lock);

      /* copy rest traffic from old active (now pending) to current
       * new URR was initialized with zero, simply add the old values */
      vec_foreach (urr, pending->urr)
      {
	upf_urr_t *new_urr = pfcp_get_urr_by_id (active, urr->id);

	if (!new_urr)
	  {
	    /* stop all timers */
	    upf_pfcp_session_stop_urr_time (&urr->measurement_period, now);
	    upf_pfcp_session_stop_urr_time (&urr->time_threshold, now);
	    upf_pfcp_session_stop_urr_time (&urr->time_quota, now);
	    upf_pfcp_session_stop_urr_time (&urr->traffic_timer, now);

	    continue;
	  }

	new_urr->traffic = urr->traffic;
	new_urr->traffic_by_ue = urr->traffic_by_ue;
	urr->traffic = NULL;
	urr->traffic_by_ue = NULL;

	if ((new_urr->methods & PFCP_URR_VOLUME))
	  {
	    urr_volume_t *old_volume = &urr->volume;
	    urr_volume_t *new_volume = &new_urr->volume;

#define combine_volume_type(Dst, Src, T, D)		\
	      (Dst)->measure.T.D += (Src)->measure.T.D
#define combine_volume(Dst, Src, T)				\
	      do {						\
		combine_volume_type((Dst), (Src), T, ul);	\
		combine_volume_type((Dst), (Src), T, dl);	\
		combine_volume_type((Dst), (Src), T, total);	\
	      } while (0)

	    combine_volume (new_volume, old_volume, packets);
	    combine_volume (new_volume, old_volume, bytes);

	    if (new_urr->update_flags & PFCP_URR_UPDATE_VOLUME_QUOTA)
	      new_volume->measure.consumed = new_volume->measure.bytes;
	    else
	      combine_volume (new_volume, old_volume, consumed);

#undef combine_volume
#undef combine_volume_type
	  }
      }

      clib_spinlock_unlock (&sx->lock);
    }
  else
    pending->urr = NULL;
  if (!pending_qer)
    pending->qer = NULL;

  return 0;
}

void
pfcp_update_finish (upf_session_t * sx)
{
  pfcp_free_rules (sx, PFCP_PENDING);
}

/******************** PFCP Session functions **********************/

/**
 * @brief Function to return session info entry address.
 *
 */
upf_session_t *
pfcp_lookup (uint64_t sess_id)
{
  upf_main_t *gtm = &upf_main;
  uword *p;

  p = hash_get (gtm->session_by_id, sess_id);
  if (!p)
    return NULL;

  return pool_elt_at_index (gtm->sessions, p[0]);
}

static int
urr_increment_and_check_counter (u64 * packets, u64 * bytes, u64 * consumed,
				 u64 threshold, u64 quota, u64 n_bytes)
{
  int r = URR_OK;

  if (quota != 0 &&
      PREDICT_FALSE (*consumed < quota && *consumed + n_bytes >= quota))
    r |= URR_QUOTA_EXHAUSTED;
  *consumed += n_bytes;

  if (threshold != 0 &&
      PREDICT_FALSE (*bytes < threshold && *bytes + n_bytes >= threshold))
    r |= URR_THRESHOLD_REACHED;
  *bytes += n_bytes;

  *packets += 1;

  return r;
}

u32
process_urrs (vlib_main_t * vm, upf_session_t * sess,
	      struct rules *active,
	      upf_pdr_t * pdr, vlib_buffer_t * b,
	      u8 is_dl, u8 is_ul, u32 next)
{
  upf_urr_traffic_t tt = {.ip = ip46_address_initializer };
  upf_event_urr_data_t *uev = NULL;
  f64 now = vlib_time_now (vm);
  upf_main_t *gtm = &upf_main;
  upf_event_urr_hdr_t *ueh;
  int status = URR_OK;
  u16 *urr_id;

  upf_debug ("DL: %d, UL: %d\n", is_dl, is_ul);

  clib_spinlock_lock (&sess->lock);

  if (is_ul)
    sess->last_ul_traffic = now;

  vec_foreach (urr_id, pdr->urr_ids)
  {
    upf_urr_t *urr = pfcp_get_urr_by_id (active, *urr_id);
    int r = URR_OK;

    if (!urr)
      continue;

#if CLIB_DEBUG > 2
    f64 unow = unix_time_now ();
    upf_debug
      ("Monitoring Time: %12.4f - %12.4f : %12.4f Unix: %U - %U : %12.4f",
       urr->monitoring_time.vlib_time, now,
       urr->monitoring_time.vlib_time - now, format_time_float, 0,
       urr->monitoring_time.unix_time, format_time_float, 0, unow,
       urr->monitoring_time.unix_time - unow);
#endif

    if (!(urr->status & URR_AFTER_MONITORING_TIME) &&
	urr->monitoring_time.vlib_time < now)
      {
	urr->usage_before_monitoring_time.volume = urr->volume.measure;
	memset (&urr->volume.measure.packets, 0,
		sizeof (urr->volume.measure.packets));
	memset (&urr->volume.measure.bytes, 0,
		sizeof (urr->volume.measure.bytes));

	urr->usage_before_monitoring_time.start_time = urr->start_time;
	urr->usage_before_monitoring_time.time_of_first_packet =
	  urr->time_of_first_packet;
	urr->usage_before_monitoring_time.time_of_last_packet =
	  urr->time_of_last_packet;
	urr->start_time = urr->monitoring_time.unix_time;
	urr->time_of_first_packet = now;
	urr->monitoring_time.vlib_time = INFINITY;
	urr->status |= URR_AFTER_MONITORING_TIME;
      }

    if (urr->time_of_first_packet == INFINITY)
      urr->time_of_first_packet = now;
    urr->time_of_last_packet = now;

    if ((urr->methods & PFCP_URR_VOLUME))
      {
	uword len = vlib_buffer_length_in_chain (vm, b);

#define urr_incr_and_check(V, D, L)					\
	  urr_increment_and_check_counter(&V.measure.packets.D,		\
					  &V.measure.bytes.D,		\
					  &V.measure.consumed.D,	\
					  V.threshold.D,		\
					  V.quota.D,			\
					  (L))

	if (is_ul)
	  r |= urr_incr_and_check (urr->volume, ul, len);
	if (is_dl)
	  r |= urr_incr_and_check (urr->volume, dl, len);

	r |= urr_incr_and_check (urr->volume, total, len);

	if (PREDICT_FALSE (r & URR_QUOTA_EXHAUSTED))
	  urr->status |= URR_OVER_QUOTA;
      }

    if ((urr->methods & PFCP_URR_EVENT) &&
	(urr->triggers & REPORTING_TRIGGER_START_OF_TRAFFIC))
      {
	ip4_header_t *iph =
	  (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
	upf_urr_traffic_t *t = NULL;

	if (ip46_address_is_zero (&tt.ip))
	  {
	    // calculate session key based on PDI and check session table....
	    if ((iph->ip_version_and_header_length & 0xF0) == 0x40)
	      {
		if (is_dl)
		  ip46_address_set_ip4 (&tt.ip, &iph->dst_address);
		if (is_ul)
		  ip46_address_set_ip4 (&tt.ip, &iph->src_address);
	      }
	    else
	      {
		ip6_header_t *ip6 =
		  (ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);

		ASSERT ((iph->ip_version_and_header_length & 0xF0) == 0x60);

		if (is_dl)
		  ip46_address_set_ip6 (&tt.ip, &ip6->dst_address);
		if (is_ul)
		  ip46_address_set_ip6 (&tt.ip, &ip6->src_address);
	      }
	  }

	upf_debug ("Start Of Traffic UE IP: %U, Pool: %p, Hash: %p\n",
		   format_ip46_address, &tt.ip, IP46_TYPE_ANY,
		   urr->traffic, urr->traffic_by_ue);

	if (urr->traffic_by_ue)
	  {
	    uword *p;

	    ASSERT (urr->traffic != NULL);

	    p = hash_get_mem (urr->traffic_by_ue, &tt.ip);
	    if (p)
	      t = pool_elt_at_index (urr->traffic, p[0]);
	  }

	if (!t)
	  {
	    upf_event_urr_data_t ev = {
	      .urr_id = urr->id,
	      .trigger = URR_START_OF_TRAFFIC
	    };

	    /* no traffic for this UE */
	    if (!urr->traffic_by_ue)
	      urr->traffic_by_ue =
		hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

	    pool_get (urr->traffic, t);
	    *t = tt;
	    t->first_seen = now;
	    hash_set_mem_alloc (&urr->traffic_by_ue, &t->ip,
				t - urr->traffic);

	    vec_add1_ha (uev, ev, sizeof (upf_event_urr_hdr_t), 0);
	    status |= URR_START_OF_TRAFFIC;
	  }
	else if (t && t->first_seen + 60 < now)
	  {
	    upf_event_urr_data_t *ev;

	    /* crude 60 second timeout */

	    t->first_seen = now;
	    vec_add2_ha (uev, ev, 1, sizeof (upf_event_urr_hdr_t), 0);
	    ev->urr_id = urr->id;
	    ev->trigger = URR_START_OF_TRAFFIC;
	    status |= URR_START_OF_TRAFFIC;
	  }
	// TODO: trafic was expired, rearm and send report
      }

    if (PREDICT_FALSE (urr->status & URR_OVER_QUOTA))
      next = UPF_FORWARD_NEXT_DROP;

    status |= r;
  }

  clib_spinlock_unlock (&sess->lock);

  if (PREDICT_FALSE (status != URR_OK))
    {
      vec_validate_ha (uev, 0, sizeof (upf_event_urr_hdr_t), 0);
      ueh =
	(upf_event_urr_hdr_t *) vec_header (uev,
					    sizeof (upf_event_urr_hdr_t));
      ueh->session_idx = (uword) (sess - gtm->sessions);
      ueh->ue = tt.ip;

      upf_debug ("sending URR event on %wd\n", (uword) ueh->session_idx);
      upf_pfcp_server_session_usage_report (uev);
    }

  return next;
}

u32
process_qers (vlib_main_t * vm, upf_session_t * sess,
	      struct rules *r,
	      upf_pdr_t * pdr, vlib_buffer_t * b,
	      u8 is_dl, u8 is_ul, u32 next)
{
  u8 direction = is_dl ? UPF_DL : UPF_UL;
  upf_main_t *gtm = &upf_main;
  u64 time_in_policer_periods;
  u32 *qer_id;
  u32 len;

  upf_debug ("DL: %d, UL: %d\n", is_dl, is_ul);

  /* must be UL or DL, not both and not none */
  if ((is_ul + is_dl) != 1)
    return next;

  time_in_policer_periods =
    clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  len = vlib_buffer_length_in_chain (vm, b);

  vec_foreach (qer_id, pdr->qer_ids)
  {
    upf_qer_t *qer = pfcp_get_qer_by_id (r, *qer_id);
    upf_qer_policer_t *pol;
    u32 col __attribute__((unused));

    if (!qer)
      continue;

    if (!(qer->flags & PFCP_QER_MBR))
      continue;

    if (qer->gate_status[direction])
      {
	next = UPF_FORWARD_NEXT_DROP;
	break;
      }

    pol = pool_elt_at_index (gtm->qer_policers, qer->policer.value);
    col =
      vnet_police_packet (&pol->policer[direction], len, POLICE_CONFORM,
			  time_in_policer_periods);
    upf_debug ("QER color: %d\n", col);
  }

  return next;
}




static const char *apply_action_flags[] = {
  "DROP",
  "FORWARD",
  "BUFFER",
  "NOTIFY_CP",
  "DUPLICATE",
  NULL
};

static const char *urr_method_flags[] = {
  "TIME",
  "VOLUME",
  "EVENT",
  NULL
};

static const char *urr_trigger_flags[] = {
  "PERIODIC REPORTING",
  "VOLUME THRESHOLD",
  "TIME THRESHOLD",
  "QUOTA HOLDING TIME",
  "START OF TRAFFIC",
  "STOP OF TRAFFIC",
  "DROPPED DL TRAFFIC THRESHOLD",
  "LINKED USAGE REPORTING",
  "VOLUME QUOTA",
  "TIME QUOTA",
  "ENVELOPE CLOSURE",
  NULL
};

static const char *urr_status_flags[] = {
  "OVER QUOTA",
  "AFTER MONITORING TIME",
  NULL
};

static const char *source_intf_name[] = {
  "Access",
  "Core",
  "SGi-LAN",
  "CP-function"
};

static const char *outer_header_removal_str[] = {
  "GTP-U/UDP/IPv4",
  "GTP-U/UDP/IPv6",
  "UDP/IPv4",
  "UDP/IPv6",
  "IPv4",
  "IPv6",
  "GTP-U/UDP/IP",
  "VLAN S-TAG",
  "S-TAG and C-TAG"
};

static const char *qer_gate_status_flags[] = {
  "OPEN",
  "CLOSED",
  NULL
};

static u8 *
format_urr_counter (u8 * s, va_list * args)
{
  void *m = va_arg (*args, void *);
  void *t = va_arg (*args, void *);
  off_t offs = va_arg (*args, off_t);

  return format (s,
		 "Measured: %20" PRIu64 ", Theshold: %20" PRIu64 ", Pkts: %10"
		 PRIu64,
		 *(u64 *) (m + offsetof (urr_measure_t, bytes) + offs),
		 *(u64 *) (t + offs),
		 *(u64 *) (m + offsetof (urr_measure_t, packets) + offs));
}

static u8 *
format_urr_quota (u8 * s, va_list * args)
{
  void *m = va_arg (*args, void *);
  void *q = va_arg (*args, void *);
  off_t offs = va_arg (*args, off_t);

  return format (s, "Consumed: %20" PRIu64 ", Quota:    %20" PRIu64,
		 *(u64 *) (m + offsetof (urr_measure_t, consumed) + offs),
		 *(u64 *) (q + offs));
}

static u8 *
format_urr_time (u8 * s, va_list * args)
{
  urr_time_t *t = va_arg (*args, urr_time_t *);
  f64 now = unix_time_now ();

  return format (s, "%20" PRIu64 " secs @ %U, in %9.3f secs, handle 0x%08x",
		 t->period,
		 format_time_float, 0, t->expected,
		 t->expected - now, t->handle);
}

u8 *
format_upf_far (u8 * s, va_list * args)
{
  upf_main_t *gtm = &upf_main;
  upf_far_t *far = va_arg (*args, upf_far_t *);
  int debug = va_arg (*args, int);
  upf_nwi_t *nwi = NULL;
  u32 indent;

  indent = format_get_indent (s);

  if (!pool_is_free_index (gtm->nwis, far->forward.nwi_index))
    nwi = pool_elt_at_index (gtm->nwis, far->forward.nwi_index);

  if (!debug)
    s = format (s, "FAR: %u\n", far->id);
  else
    s = format (s, "FAR: %u @ %p\n", far->id, far);

  s = format (s, "%UApply Action: %08x == %U\n",
	      format_white_space, indent + 2, far->apply_action,
	      format_flags, far->apply_action, apply_action_flags);

  if (far->apply_action & FAR_FORWARD)
    {
      upf_far_forward_t *ff = &far->forward;

      s = format (s, "%UForward:\n"
		  "%UNetwork Instance: %U\n"
		  "%UDestination Interface: %u\n",
		  format_white_space, indent + 2,
		  format_white_space, indent + 4,
		  format_network_instance, nwi ? nwi->name : NULL,
		  format_white_space, indent + 4, ff->dst_intf);
      if (ff->flags & FAR_F_REDIRECT_INFORMATION)
	s = format (s, "%URedirect Information: %U\n",
		    format_white_space, indent + 4,
		    format_redirect_information, &ff->redirect_information);
      if (ff->flags & FAR_F_OUTER_HEADER_CREATION)
	{
	  s = format (s, "%UOuter Header Creation: %U\n",
		      format_white_space, indent + 4,
		      format_outer_header_creation,
		      &ff->outer_header_creation);
	  if (debug && ff->rewrite)
	    s = format (s, "%URewrite Header: %U\n",
			format_white_space, indent + 4,
			(ff->outer_header_creation.description &
			 OUTER_HEADER_CREATION_ANY_IP4) ? format_ip4_header :
			format_ip6_header, ff->rewrite,
			vec_len (ff->rewrite));
	}
    }

  return s;
}

u8 *
format_pfcp_session (u8 * s, va_list * args)
{
  upf_session_t *sx = va_arg (*args, upf_session_t *);
  int rule = va_arg (*args, int);
  int debug = va_arg (*args, int);
  struct rules *rules = pfcp_get_rules (sx, rule);
  upf_main_t *gtm = &upf_main;
  upf_pdr_t *pdr;
  upf_far_t *far;
  upf_urr_t *urr;
  upf_qer_t *qer;

  s = format (s,
	      "CP F-SEID: 0x%016" PRIx64 " (%" PRIu64 ") @ %U\n"
	      "UP F-SEID: 0x%016" PRIx64 " (%" PRIu64 ") @ %U\n",
	      sx->cp_seid, sx->cp_seid, format_ip46_address, &sx->cp_address,
	      IP46_TYPE_ANY, sx->cp_seid, sx->cp_seid, format_ip46_address,
	      &sx->up_address, IP46_TYPE_ANY, sx);

  if (debug)
    s = format (s, "  SIdx: %u\n  Pointer: %p\n  PDR: %p\n  FAR: %p\n",
		sx - gtm->sessions, sx, rules->pdr, rules->far);

  s = format (s, "  PFCP Association: %u\n", sx->assoc.node);
  if (debug)
    s = format (s, "                  (prev:%u,next:%u)\n",
		sx->assoc.prev, sx->assoc.next);
  if (rules->inactivity_timer.period != 0)
    s =
      format (s,
	      "  UP Inactivity Timer: %u secs, inactive %12.4f secs (0x%08x)\n",
	      rules->inactivity_timer.period,
	      vlib_time_now (gtm->vlib_main) - sx->last_ul_traffic,
	      rules->inactivity_timer.handle);

  vec_foreach (pdr, rules->pdr)
  {
    upf_nwi_t *nwi = NULL;
    size_t j;

    if (!pool_is_free_index (gtm->nwis, pdr->pdi.nwi_index))
      nwi = pool_elt_at_index (gtm->nwis, pdr->pdi.nwi_index);

    s = format (s, "PDR: %u @ %p\n"
		"  Precedence: %u\n"
		"  PDI:\n"
		"    Fields: %08x\n",
		pdr->id, pdr, pdr->precedence, pdr->pdi.fields);

    if (pdr->pdi.src_intf < ARRAY_LEN (source_intf_name))
      s =
	format (s, "    Source Interface: %s\n",
		source_intf_name[pdr->pdi.src_intf]);
    else
      s = format (s, "    Source Interface: %d\n", pdr->pdi.src_intf);

    s = format (s, "    Network Instance: %U\n",
		format_network_instance, nwi ? nwi->name : NULL);

    if (pdr->pdi.fields & F_PDI_LOCAL_F_TEID)
      {
	s = format (s, "    Local F-TEID: %u (0x%08x)\n",
		    pdr->pdi.teid.teid, pdr->pdi.teid.teid);
	if (pdr->pdi.teid.flags & F_TEID_V4)
	  s = format (s, "            IPv4: %U\n",
		      format_ip4_address, &pdr->pdi.teid.ip4);
	if (pdr->pdi.teid.flags & F_TEID_V6)
	  s = format (s, "            IPv6: %U\n",
		      format_ip6_address, &pdr->pdi.teid.ip6);
      }
    if (pdr->pdi.fields & F_PDI_UE_IP_ADDR)
      {
	s = format (s, "    UE IP address (%s):\n",
		    pdr->pdi.
		    ue_addr.flags & IE_UE_IP_ADDRESS_SD ? "destination" :
		    "source");
	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
	  s = format (s, "      IPv4 address: %U\n",
		      format_ip4_address, &pdr->pdi.ue_addr.ip4);
	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
	  s = format (s, "      IPv6 address: %U\n",
		      format_ip6_address, &pdr->pdi.ue_addr.ip6);
      }
    if (pdr->pdi.fields & F_PDI_SDF_FILTER)
      {
	acl_rule_t *rule;

	s = format (s, "    SDF Filter [%u]:\n", vec_len (pdr->pdi.acl));
	vec_foreach (rule, pdr->pdi.acl)
	{
	  s = format (s, "      %U\n", format_ipfilter, rule);
	}
      }
    if (pdr->pdi.fields & F_PDI_APPLICATION_ID)
      {
	s = format (s, "  Application Id: %v [db:%u]\n",
		    pool_elt_at_index (gtm->upf_apps,
				       pdr->pdi.adr.application_id)->name,
		    pdr->pdi.adr.db_id);
      }
    s = format (s, "  Outer Header Removal: %s\n"
		"  FAR Id: %u\n"
		"  URR Ids: [",
		(pdr->outer_header_removal >=
		 ARRAY_LEN (outer_header_removal_str)) ? "no" :
		outer_header_removal_str[pdr->outer_header_removal],
		pdr->far_id);
    vec_foreach_index (j, pdr->urr_ids) s =
      format (s, "%s%u", j != 0 ? "," : "", vec_elt (pdr->urr_ids, j));
    s = format (s, "] @ %p\n", pdr->urr_ids);
    s = format (s, "  QER Ids: [");
    vec_foreach_index (j, pdr->qer_ids) s =
      format (s, "%s%u", j != 0 ? "," : "", vec_elt (pdr->qer_ids, j));
    s = format (s, "] @ %p\n", pdr->qer_ids);
  }

  vec_foreach (far, rules->far)
  {
    s = format (s, "%U", format_upf_far, far, debug);
  }

  vec_foreach (urr, rules->urr)
  {
    if (debug)
      s = format (s, "URR: %u @ %p [%d]\n", urr->id, urr, urr - rules->urr);
    else
      s = format (s, "URR: %u\n", urr->id);

    /* *INDENT-OFF* */
    s = format (s, "  Measurement Method: %04x == %U\n"
		   "  Reporting Triggers: %04x == %U\n"
		   "  Status: %d == %U\n",
		   urr->methods, format_flags, (u64)urr->methods, urr_method_flags,
		   urr->triggers, format_flags, (u64)urr->triggers, urr_trigger_flags,
		   urr->status, format_flags, (u64)urr->status, urr_status_flags);
    /* *INDENT-ON* */

    if (urr->triggers & REPORTING_TRIGGER_LINKED_USAGE_REPORTING)
      {
	u32 *id;

	s = format (s, "  Linked URR Ids: [");
	vec_foreach (id, urr->linked_urr_ids)
	{
	  if (id == urr->linked_urr_ids)
	    s = format (s, "%d", *id);
	  else
	    s = format (s, ",%d", *id);
	}
	s = format (s, "]\n");
      }
    if (debug)
      s = format (s, "  LIUSA: %U\n", format_bitmap_hex, urr->liusa_bitmap);

    s =
      format (s, "  Start Time: %U\n", format_time_float, 0, urr->start_time);
    s = format (s, "  vTime of First Usage: %U \n"
		"  vTime of Last Usage:  %U \n",
		format_vlib_time, gtm->vlib_main,
		urr->usage_before_monitoring_time.time_of_first_packet,
		format_vlib_time, gtm->vlib_main,
		urr->usage_before_monitoring_time.time_of_last_packet);
    if (urr->methods & PFCP_URR_VOLUME)
      {
	urr_volume_t *v = &urr->volume;

	  /* *INDENT-OFF* */
	  s = format (s, "  Volume\n"
		      "    Up:    %U\n           %U\n"
		      "    Down:  %U\n           %U\n"
		      "    Total: %U\n           %U\n",
		      format_urr_counter, &v->measure, &v->threshold, offsetof(urr_counter_t, ul),
		      format_urr_quota,   &v->measure, &v->quota, offsetof(urr_counter_t, ul),
		      format_urr_counter, &v->measure, &v->threshold, offsetof(urr_counter_t, dl),
		      format_urr_quota,   &v->measure, &v->quota, offsetof(urr_counter_t, dl),
		      format_urr_counter, &v->measure, &v->threshold, offsetof(urr_counter_t, total),
		      format_urr_quota,   &v->measure, &v->quota, offsetof(urr_counter_t, total));
	  /* *INDENT-ON* */
      }
    if (urr->measurement_period.base != 0)
      {
	s = format (s, "  Measurement Period: %U\n",
		    format_urr_time, &urr->measurement_period);
      }

    if (urr->methods & PFCP_URR_TIME)
      {
	s = format (s, "  Time\n    Quota:     %U\n    Threshold: %U\n",
		    format_urr_time, &urr->time_quota,
		    format_urr_time, &urr->time_threshold);
      }
    if (urr->monitoring_time.vlib_time != INFINITY)
      {
	f64 now = unix_time_now ();

	s = format (s, "  Monitoring Time: %U, in %9.3f secs\n",
		    /* VPP does not support ISO dates... */
		    format_time_float, 0, urr->monitoring_time.unix_time,
		    urr->monitoring_time.unix_time - now,
		    urr->monitoring_time.vlib_time -
		    vlib_time_now (gtm->vlib_main));

	if (urr->status & URR_AFTER_MONITORING_TIME)
	  {
	    s = format (s, "  Usage Before Monitoring Time\n"
			"    vTime of First Usage: %U \n"
			"    vTime of Last Usage:  %U \n",
			format_vlib_time, gtm->vlib_main,
			urr->
			usage_before_monitoring_time.time_of_first_packet,
			format_vlib_time, gtm->vlib_main,
			urr->
			usage_before_monitoring_time.time_of_last_packet);
	    if (urr->methods & PFCP_URR_VOLUME)
	      {
		urr_measure_t *v = &urr->usage_before_monitoring_time.volume;

		s = format (s, "    Volume\n"
			    "      Up:    %20" PRIu64 ", Pkts: %10" PRIu64
			    "\n" "      Down:  %20" PRIu64 ", Pkts: %10"
			    PRIu64 "\n" "      Total: %20" PRIu64
			    ", Pkts: %10" PRIu64 "\n", v->bytes.ul,
			    v->packets.ul, v->bytes.dl, v->packets.dl,
			    v->bytes.total, v->packets.total);
	      }
	    if (urr->methods & PFCP_URR_TIME)
	      {
		s = format (s, "    Start Time %U, End Time %U, %9.3f secs\n",
			    format_time_float, 0,
			    urr->usage_before_monitoring_time.start_time,
			    format_time_float, 0, urr->start_time,
			    urr->start_time -
			    urr->usage_before_monitoring_time.start_time);
	      }
	  }
      }
    if (urr->traffic)
      {
	vlib_main_t *vm = gtm->vlib_main;
	f64 now = vlib_time_now (vm);
	upf_urr_traffic_t *tt;

	s = format (s, "  Start Of Traffic UE IPs: %u, now: %U\n"
		    "    Timer: %U\n",
		    pool_elts (urr->traffic),
		    format_vlib_time, vm, now,
		    format_urr_time, &urr->traffic_timer);

	/* *INDENT-OFF* */
	pool_foreach (tt, urr->traffic,
	({
	  s = format (s, "%U @ %U [%U]\n",
		      format_ip46_address, &tt->ip, IP46_TYPE_ANY,
		      format_vlib_time, vm, tt->first_seen,
		      format_vlib_time, vm, now - tt->first_seen);

	}));
	/* *INDENT-ON* */
      }
  }
  vec_foreach (qer, rules->qer)
  {
      /* *INDENT-OFF* */
      s = format (s, "QER: %u\n"
		  "  UL Gate: %d == %U\n"
		  "  DL Gate: %d == %U\n",
		  qer->id,
		  qer->gate_status[UPF_UL],
		  format_flags, (u64)qer->gate_status[UPF_UL], qer_gate_status_flags,
		  qer->gate_status[UPF_DL],
		  format_flags, (u64)qer->gate_status[UPF_DL], qer_gate_status_flags);
      /* *INDENT-ON* */
  }
  return s;
}

static u8 *
format_time_stamp (u8 * s, va_list * args)
{
  u32 *v = va_arg (*args, u32 *);
  struct timeval tv = {.tv_sec = *v,.tv_usec = 0 };

  return format (s, "%U", format_timeval, 0, &tv);
}

u8 *
format_pfcp_node_association (u8 * s, va_list * args)
{
  upf_node_assoc_t *node = va_arg (*args, upf_node_assoc_t *);
  u8 verbose = va_arg (*args, int);
  upf_main_t *gtm = &upf_main;
  u32 idx = node->sessions;
  u32 i = 0;

  s = format (s,
	      "Node: %U\n"
	      "  Recovery Time Stamp: %U\n"
	      "  Sessions: ",
	      format_node_id, &node->node_id,
	      format_time_stamp, &node->recovery_time_stamp);

  while (idx != ~0)
    {
      upf_session_t *sx = pool_elt_at_index (gtm->sessions, idx);

      if (verbose)
	{
	  if (i > 0 && (i % 8) == 0)
	    s = format (s, "\n            ");

	  s = format (s, " 0x%016" PRIx64, sx->cp_seid);
	}

      i++;
      idx = sx->assoc.next;
    }

  if (verbose)
    s = format (s, "\n  %u Session(s)\n", i);
  else
    s = format (s, "%u\n", i);

  return s;
}

u8 *
format_pfcp_endpoint (u8 * s, va_list * args)
{
  upf_pfcp_endpoint_t *ep = va_arg (*args, upf_pfcp_endpoint_t *);

  s = format (s, "%U [@%u]",
	      format_ip46_address, &ep->key.addr, IP46_TYPE_ANY,
	      ep->key.fib_index);

  return s;
}

u8 *
format_network_instance_index (u8 * s, va_list * args)
{
  u32 n = va_arg (*args, u32);
  upf_main_t *gtm = &upf_main;

  if (~0 == n)
    return format (s, "(@~0)");

  upf_nwi_t *nwi = pool_elt_at_index (gtm->nwis, n);
  return format (s, "(@%u) %U", n, format_network_instance, nwi->name);
}

u8 *
format_gtpu_endpoint (u8 * s, va_list * args)
{
  upf_upip_res_t *ep = va_arg (*args, upf_upip_res_t *);

  if (!is_zero_ip4_address (&ep->ip4))
    s = format (s, " IP4: %U", format_ip4_address, &ep->ip4);
  if (!is_zero_ip6_address (&ep->ip6))
    s = format (s, " IP6: %U", format_ip6_address, &ep->ip6);

  if (~0 != ep->nwi_index)
    s = format (s, ", nwi: %U", format_network_instance_index, ep->nwi_index);

  if (INTF_INVALID != ep->intf)
    s = format (s, ", Intf: %u", ep->intf);

  s = format (s, ", 0x%08x/%d (0x%08x)",
	      ep->teid, __builtin_popcount (ep->mask), ep->mask);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
