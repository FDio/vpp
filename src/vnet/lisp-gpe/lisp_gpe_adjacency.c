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
/**
 * @file
 * @brief Common utility functions for IPv4, IPv6 and L2 LISP-GPE adjacencys.
 *
 */

#include <vnet/dpo/load_balance.h>
#include <vnet/lisp-cp/control.h>
#include <vnet/lisp-cp/lisp_types.h>
#include <vnet/lisp-gpe/lisp_gpe_sub_interface.h>
#include <vnet/lisp-gpe/lisp_gpe_adjacency.h>
#include <vnet/lisp-gpe/lisp_gpe_tunnel.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/adj/adj_midchain.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

/**
 * Memory pool of all adjacencies
 */
static lisp_gpe_adjacency_t *lisp_adj_pool;

/**
 * Hash table of all adjacencies. key:{nh, itf}
 * We never have an all zeros address since the interfaces are multi-access,
 * therefore there is no ambiguity between a v4 and v6 next-hop, so we don't
 * need to add the protocol to the key.
 */
static
BVT (clib_bihash)
  lisp_adj_db;

#define LISP_ADJ_SET_KEY(_key, _itf, _nh)       \
{						\
  _key.key[0] = (_nh)->ip.v6.as_u64[0];		\
  _key.key[1] = (_nh)->ip.v6.as_u64[1];		\
  _key.key[2] = (_itf);				\
}

     static index_t lisp_adj_find (const ip_address_t * addr, u32 sw_if_index)
{
  BVT (clib_bihash_kv) kv;

  LISP_ADJ_SET_KEY (kv, sw_if_index, addr);

  if (BV (clib_bihash_search) (&lisp_adj_db, &kv, &kv) < 0)
    {
      return (INDEX_INVALID);
    }
  else
    {
      return (kv.value);
    }
}

static void
lisp_adj_insert (const ip_address_t * addr, u32 sw_if_index, index_t ai)
{
  BVT (clib_bihash_kv) kv;

  LISP_ADJ_SET_KEY (kv, sw_if_index, addr);
  kv.value = ai;

  BV (clib_bihash_add_del) (&lisp_adj_db, &kv, 1);
}

static void
lisp_adj_remove (const ip_address_t * addr, u32 sw_if_index)
{
  BVT (clib_bihash_kv) kv;

  LISP_ADJ_SET_KEY (kv, sw_if_index, addr);

  BV (clib_bihash_add_del) (&lisp_adj_db, &kv, 0);
}

static lisp_gpe_adjacency_t *
lisp_gpe_adjacency_get_i (index_t lai)
{
  return (pool_elt_at_index (lisp_adj_pool, lai));
}

fib_forward_chain_type_t
lisp_gpe_adj_get_fib_chain_type (const lisp_gpe_adjacency_t * ladj)
{
  switch (ip_addr_version (&ladj->remote_rloc))
    {
    case IP4:
      return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
    case IP6:
      return (FIB_FORW_CHAIN_TYPE_UNICAST_IP6);
    default:
      ASSERT (0);
      break;
    }
  return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
}

static void
ip46_address_to_ip_address (const ip46_address_t * a, ip_address_t * b)
{
  if (ip46_address_is_ip4 (a))
    {
      memset (b, 0, sizeof (*b));
      ip_address_set (b, &a->ip4, IP4);
    }
  else
    {
      ip_address_set (b, &a->ip6, IP6);
    }
}

/**
 * @brief Stack the tunnel's midchain on the IP forwarding chain of the via
 */
static void
lisp_gpe_adj_stack_one (lisp_gpe_adjacency_t * ladj, adj_index_t ai)
{
  const lisp_gpe_tunnel_t *lgt;
  dpo_id_t tmp = DPO_INVALID;

  lgt = lisp_gpe_tunnel_get (ladj->tunnel_index);
  fib_entry_contribute_forwarding (lgt->fib_entry_index,
				   lisp_gpe_adj_get_fib_chain_type (ladj),
				   &tmp);

  if (DPO_LOAD_BALANCE == tmp.dpoi_type)
    {
      /*
       * post LISP rewrite we will load-balance. However, the LISP encap
       * is always the same for this adjacency/tunnel and hence the IP/UDP src,dst
       * hash is always the same result too. So we do that hash now and
       * stack on the choice.
       * If the choice is an incomplete adj then we will need a poke when
       * it becomes complete. This happens since the adj update walk propagates
       * as far a recursive paths.
       */
      const dpo_id_t *choice;
      load_balance_t *lb;
      int hash;

      lb = load_balance_get (tmp.dpoi_index);

      if (IP4 == ip_addr_version (&ladj->remote_rloc))
	{
	  hash = ip4_compute_flow_hash ((ip4_header_t *) adj_get_rewrite (ai),
					lb->lb_hash_config);
	}
      else
	{
	  hash = ip6_compute_flow_hash ((ip6_header_t *) adj_get_rewrite (ai),
					lb->lb_hash_config);
	}

      choice =
	load_balance_get_bucket_i (lb, hash & lb->lb_n_buckets_minus_1);
      dpo_copy (&tmp, choice);
    }

  adj_nbr_midchain_stack (ai, &tmp);
  dpo_reset (&tmp);
}

/**
 * @brief Call back when restacking all adjacencies on a GRE interface
 */
static adj_walk_rc_t
lisp_gpe_adj_walk_cb (adj_index_t ai, void *ctx)
{
  lisp_gpe_adjacency_t *ladj = ctx;

  lisp_gpe_adj_stack_one (ladj, ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
lisp_gpe_adj_stack (lisp_gpe_adjacency_t * ladj)
{
  fib_protocol_t nh_proto;
  ip46_address_t nh;

  ip_address_to_46 (&ladj->remote_rloc, &nh, &nh_proto);

  /*
   * walk all the adjacencies on th lisp interface and restack them
   */
  adj_nbr_walk_nh (ladj->sw_if_index,
		   nh_proto, &nh, lisp_gpe_adj_walk_cb, ladj);
}

static lisp_gpe_next_protocol_e
lisp_gpe_adj_proto_from_vnet_link_type (vnet_link_t linkt)
{
  switch (linkt)
    {
    case VNET_LINK_IP4:
      return (LISP_GPE_NEXT_PROTO_IP4);
    case VNET_LINK_IP6:
      return (LISP_GPE_NEXT_PROTO_IP6);
    case VNET_LINK_ETHERNET:
      return (LISP_GPE_NEXT_PROTO_ETHERNET);
    case VNET_LINK_NSH:
      return (LISP_GPE_NEXT_PROTO_NSH);
    default:
      ASSERT (0);
    }
  return (LISP_GPE_NEXT_PROTO_IP4);
}

#define is_v4_packet(_h) ((*(u8*) _h) & 0xF0) == 0x40

static lisp_afi_e
lisp_afi_from_vnet_link_type (vnet_link_t link)
{
  switch (link)
    {
    case VNET_LINK_IP4:
      return LISP_AFI_IP;
    case VNET_LINK_IP6:
      return LISP_AFI_IP6;
    case VNET_LINK_ETHERNET:
      return LISP_AFI_MAC;
    default:
      return LISP_AFI_NO_ADDR;
    }
}

static void
lisp_gpe_increment_stats_counters (lisp_cp_main_t * lcm, ip_adjacency_t * adj,
				   vlib_buffer_t * b)
{
  lisp_gpe_main_t *lgm = vnet_lisp_gpe_get_main ();
  lisp_gpe_adjacency_t *ladj;
  ip_address_t rloc;
  index_t lai;
  u32 si, di;
  gid_address_t src, dst;
  uword *feip;

  ip46_address_to_ip_address (&adj->sub_type.nbr.next_hop, &rloc);
  si = vnet_buffer (b)->sw_if_index[VLIB_TX];
  lai = lisp_adj_find (&rloc, si);
  ASSERT (INDEX_INVALID != lai);

  ladj = pool_elt_at_index (lisp_adj_pool, lai);

  u8 *lisp_data = (u8 *) vlib_buffer_get_current (b);

  /* skip IP header */
  if (is_v4_packet (lisp_data))
    lisp_data += sizeof (ip4_header_t);
  else
    lisp_data += sizeof (ip6_header_t);

  /* skip UDP header */
  lisp_data += sizeof (udp_header_t);
  // TODO: skip TCP?

  /* skip LISP GPE header */
  lisp_data += sizeof (lisp_gpe_header_t);

  i16 saved_current_data = b->current_data;
  b->current_data = lisp_data - b->data;

  lisp_afi_e afi = lisp_afi_from_vnet_link_type (adj->ia_link);
  get_src_and_dst_eids_from_buffer (lcm, b, &src, &dst, afi);
  b->current_data = saved_current_data;
  di = gid_dictionary_sd_lookup (&lcm->mapping_index_by_gid, &dst, &src);
  if (PREDICT_FALSE (~0 == di))
    {
      clib_warning ("dst mapping not found (%U, %U)", format_gid_address,
		    &src, format_gid_address, &dst);
      return;
    }

  feip = hash_get (lcm->fwd_entry_by_mapping_index, di);
  if (PREDICT_FALSE (!feip))
    return;

  lisp_stats_key_t key;
  memset (&key, 0, sizeof (key));
  key.fwd_entry_index = feip[0];
  key.tunnel_index = ladj->tunnel_index;

  uword *p = hash_get_mem (lgm->lisp_stats_index_by_key, &key);
  ASSERT (p);

  /* compute payload length starting after GPE */
  u32 bytes = b->current_length - (lisp_data - b->data - b->current_data);
  vlib_increment_combined_counter (&lgm->counters, vlib_get_thread_index (),
				   p[0], 1, bytes);
}

static void
lisp_gpe_fixup (vlib_main_t * vm, ip_adjacency_t * adj, vlib_buffer_t * b)
{
  lisp_cp_main_t *lcm = vnet_lisp_cp_get_main ();

  if (lcm->flags & LISP_FLAG_STATS_ENABLED)
    lisp_gpe_increment_stats_counters (lcm, adj, b);

  /* Fixup the checksum and len fields in the LISP tunnel encap
   * that was applied at the midchain node */
  ip_udp_fixup_one (vm, b, is_v4_packet (vlib_buffer_get_current (b)));
}

/**
 * @brief The LISP-GPE interface registered function to update, i.e.
 * provide an rewrite string for, an adjacency.
 */
void
lisp_gpe_update_adjacency (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  const lisp_gpe_tunnel_t *lgt;
  lisp_gpe_adjacency_t *ladj;
  ip_adjacency_t *adj;
  ip_address_t rloc;
  vnet_link_t linkt;
  index_t lai;

  adj = adj_get (ai);
  ip46_address_to_ip_address (&adj->sub_type.nbr.next_hop, &rloc);

  /*
   * find an existing or create a new adj
   */
  lai = lisp_adj_find (&rloc, sw_if_index);

  ASSERT (INDEX_INVALID != lai);

  ladj = pool_elt_at_index (lisp_adj_pool, lai);
  lgt = lisp_gpe_tunnel_get (ladj->tunnel_index);
  linkt = adj_get_link_type (ai);
  adj_nbr_midchain_update_rewrite
    (ai, lisp_gpe_fixup,
     (VNET_LINK_ETHERNET == linkt ?
      ADJ_FLAG_MIDCHAIN_NO_COUNT :
      ADJ_FLAG_NONE),
     lisp_gpe_tunnel_build_rewrite (lgt, ladj,
				    lisp_gpe_adj_proto_from_vnet_link_type
				    (linkt)));

  lisp_gpe_adj_stack_one (ladj, ai);
}

u8 *
lisp_gpe_build_rewrite (vnet_main_t * vnm,
			u32 sw_if_index,
			vnet_link_t link_type, const void *dst_address)
{
  ASSERT (0);
  return (NULL);
}

index_t
lisp_gpe_adjacency_find_or_create_and_lock (const locator_pair_t * pair,
					    u32 overlay_table_id, u32 vni)
{
  const lisp_gpe_sub_interface_t *l3s;
  const lisp_gpe_tunnel_t *lgt;
  lisp_gpe_adjacency_t *ladj;
  index_t lai, l3si;

  /*
   * first find the L3 sub-interface that corresponds to the loacl-rloc and vni
   */
  l3si = lisp_gpe_sub_interface_find_or_create_and_lock (&pair->lcl_loc,
							 overlay_table_id,
							 vni);
  l3s = lisp_gpe_sub_interface_get (l3si);

  /*
   * find an existing or create a new adj
   */
  lai = lisp_adj_find (&pair->rmt_loc, l3s->sw_if_index);

  if (INDEX_INVALID == lai)
    {

      pool_get (lisp_adj_pool, ladj);
      memset (ladj, 0, sizeof (*ladj));
      lai = (ladj - lisp_adj_pool);

      ip_address_copy (&ladj->remote_rloc, &pair->rmt_loc);
      ladj->vni = vni;
      /* transfer the lock to the adj */
      ladj->lisp_l3_sub_index = l3si;
      ladj->sw_if_index = l3s->sw_if_index;

      /* if vni is non-default */
      if (ladj->vni)
	ladj->flags = LISP_GPE_FLAGS_I;

      /* work in lisp-gpe not legacy mode */
      ladj->flags |= LISP_GPE_FLAGS_P;

      /*
       * find the tunnel that will provide the underlying transport
       * and hence the rewrite.
       * The RLOC FIB index is default table - always.
       */
      ladj->tunnel_index = lisp_gpe_tunnel_find_or_create_and_lock (pair, 0);

      lgt = lisp_gpe_tunnel_get (ladj->tunnel_index);

      /*
       * become of child of the RLOC FIB entry so we are updated when
       * its reachability changes, allowing us to re-stack the midcahins
       */
      ladj->fib_entry_child_index = fib_entry_child_add (lgt->fib_entry_index,
							 FIB_NODE_TYPE_LISP_ADJ,
							 lai);

      lisp_adj_insert (&ladj->remote_rloc, ladj->sw_if_index, lai);
    }
  else
    {
      /* unlock the interface from the find. */
      lisp_gpe_sub_interface_unlock (l3si);
      ladj = lisp_gpe_adjacency_get_i (lai);
    }

  ladj->locks++;

  return (lai);
}

/**
 * @brief Get a pointer to a tunnel from a pointer to a FIB node
 */
static lisp_gpe_adjacency_t *
lisp_gpe_adjacency_from_fib_node (const fib_node_t * node)
{
  return ((lisp_gpe_adjacency_t *)
	  ((char *) node -
	   STRUCT_OFFSET_OF (lisp_gpe_adjacency_t, fib_node)));
}

static void
lisp_gpe_adjacency_last_lock_gone (lisp_gpe_adjacency_t * ladj)
{
  const lisp_gpe_tunnel_t *lgt;

  /*
   * no children so we are not counting locks. no-op.
   * at least not counting
   */
  lisp_adj_remove (&ladj->remote_rloc, ladj->sw_if_index);

  /*
   * unlock the resources this adj holds
   */
  lgt = lisp_gpe_tunnel_get (ladj->tunnel_index);

  fib_entry_child_remove (lgt->fib_entry_index, ladj->fib_entry_child_index);

  lisp_gpe_tunnel_unlock (ladj->tunnel_index);
  lisp_gpe_sub_interface_unlock (ladj->lisp_l3_sub_index);

  pool_put (lisp_adj_pool, ladj);
}

void
lisp_gpe_adjacency_unlock (index_t lai)
{
  lisp_gpe_adjacency_t *ladj;

  ladj = lisp_gpe_adjacency_get_i (lai);

  ladj->locks--;

  if (0 == ladj->locks)
    {
      lisp_gpe_adjacency_last_lock_gone (ladj);
    }
}

const lisp_gpe_adjacency_t *
lisp_gpe_adjacency_get (index_t lai)
{
  return (lisp_gpe_adjacency_get_i (lai));
}


/**
 * @brief LISP GPE tunnel back walk
 *
 * The FIB entry through which this tunnel resolves has been updated.
 * re-stack the midchain on the new forwarding.
 */
static fib_node_back_walk_rc_t
lisp_gpe_adjacency_back_walk (fib_node_t * node,
			      fib_node_back_walk_ctx_t * ctx)
{
  lisp_gpe_adj_stack (lisp_gpe_adjacency_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

static fib_node_t *
lisp_gpe_adjacency_get_fib_node (fib_node_index_t index)
{
  lisp_gpe_adjacency_t *ladj;

  ladj = pool_elt_at_index (lisp_adj_pool, index);
  return (&ladj->fib_node);
}

static void
lisp_gpe_adjacency_last_fib_lock_gone (fib_node_t * node)
{
  lisp_gpe_adjacency_last_lock_gone (lisp_gpe_adjacency_from_fib_node (node));
}

const static fib_node_vft_t lisp_gpe_tuennel_vft = {
  .fnv_get = lisp_gpe_adjacency_get_fib_node,
  .fnv_back_walk = lisp_gpe_adjacency_back_walk,
  .fnv_last_lock = lisp_gpe_adjacency_last_fib_lock_gone,
};

u8 *
format_lisp_gpe_adjacency (u8 * s, va_list * args)
{
  lisp_gpe_adjacency_t *ladj = va_arg (*args, lisp_gpe_adjacency_t *);
  lisp_gpe_adjacency_format_flags_t flags =
    va_arg (*args, lisp_gpe_adjacency_format_flags_t);

  if (flags & LISP_GPE_ADJ_FORMAT_FLAG_DETAIL)
    {
      s =
	format (s, "index %d locks:%d\n", ladj - lisp_adj_pool, ladj->locks);
    }

  s = format (s, " vni: %d,", ladj->vni);
  s = format (s, " remote-RLOC: %U,", format_ip_address, &ladj->remote_rloc);

  if (flags & LISP_GPE_ADJ_FORMAT_FLAG_DETAIL)
    {
      s = format (s, " %U\n",
		  format_lisp_gpe_sub_interface,
		  lisp_gpe_sub_interface_get (ladj->lisp_l3_sub_index));
      s = format (s, " %U\n",
		  format_lisp_gpe_tunnel,
		  lisp_gpe_tunnel_get (ladj->tunnel_index));
    }
  else
    {
      s = format (s, " LISP L3 sub-interface index: %d,",
		  ladj->lisp_l3_sub_index);
      s = format (s, " LISP tunnel index: %d", ladj->tunnel_index);
    }


  return (s);
}

static clib_error_t *
lisp_gpe_adjacency_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lisp_gpe_adjacency_t *ladj;
  index_t index;

  if (pool_elts (lisp_adj_pool) == 0)
    vlib_cli_output (vm, "No lisp-gpe Adjacencies");

  if (unformat (input, "%d", &index))
    {
      ladj = lisp_gpe_adjacency_get_i (index);
      vlib_cli_output (vm, "%U", format_lisp_gpe_adjacency, ladj,
		       LISP_GPE_ADJ_FORMAT_FLAG_DETAIL);
    }
  else
    {
      /* *INDENT-OFF* */
      pool_foreach (ladj, lisp_adj_pool,
      ({
	vlib_cli_output (vm, "[%d] %U\n",
			 ladj - lisp_adj_pool,
			 format_lisp_gpe_adjacency, ladj,
			 LISP_GPE_ADJ_FORMAT_FLAG_NONE);
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_lisp_gpe_tunnel_command, static) =
{
  .path = "show gpe adjacency",
  .function = lisp_gpe_adjacency_show,
};
/* *INDENT-ON* */

#define LISP_ADJ_NBR_DEFAULT_HASH_NUM_BUCKETS (256)
#define LISP_ADJ_NBR_DEFAULT_HASH_MEMORY_SIZE (1<<20)

static clib_error_t *
lisp_gpe_adj_module_init (vlib_main_t * vm)
{
  BV (clib_bihash_init) (&lisp_adj_db,
			 "Adjacency Neighbour table",
			 LISP_ADJ_NBR_DEFAULT_HASH_NUM_BUCKETS,
			 LISP_ADJ_NBR_DEFAULT_HASH_MEMORY_SIZE);

  fib_node_register_type (FIB_NODE_TYPE_LISP_ADJ, &lisp_gpe_tuennel_vft);
  return (NULL);
}

VLIB_INIT_FUNCTION (lisp_gpe_adj_module_init)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
