/*
 * gre_interface.c: gre interfaces
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
#include <vnet/gre/gre.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_table.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/mpls/mpls.h>
#include <vnet/l2/l2_input.h>
#include <vnet/teib/teib.h>

u8 *
format_gre_tunnel_type (u8 * s, va_list * args)
{
  gre_tunnel_type_t type = va_arg (*args, int);

  switch (type)
    {
#define _(n, v) case GRE_TUNNEL_TYPE_##n:       \
      s = format (s, "%s", v);                  \
      break;
      foreach_gre_tunnel_type
#undef _
    }

  return (s);
}

static u8 *
format_gre_tunnel (u8 * s, va_list * args)
{
  gre_tunnel_t *t = va_arg (*args, gre_tunnel_t *);

  s = format (s, "[%d] instance %d src %U dst %U fib-idx %d sw-if-idx %d ",
	      t->dev_instance, t->user_instance,
	      format_ip46_address, &t->tunnel_src, IP46_TYPE_ANY,
	      format_ip46_address, &t->tunnel_dst.fp_addr, IP46_TYPE_ANY,
	      t->outer_fib_index, t->sw_if_index);

  s = format (s, "payload %U ", format_gre_tunnel_type, t->type);
  s = format (s, "%U ", format_tunnel_mode, t->mode);

  if (t->type == GRE_TUNNEL_TYPE_ERSPAN)
    s = format (s, "session %d ", t->session_id);

  if (t->type != GRE_TUNNEL_TYPE_L3)
    s = format (s, "l2-adj-idx %d ", t->l2_adj_index);

  return s;
}

static gre_tunnel_t *
gre_tunnel_db_find (const vnet_gre_tunnel_add_del_args_t * a,
		    u32 outer_fib_index, gre_tunnel_key_t * key)
{
  gre_main_t *gm = &gre_main;
  uword *p;

  if (!a->is_ipv6)
    {
      gre_mk_key4 (a->src.ip4, a->dst.ip4, outer_fib_index,
		   a->type, a->mode, a->session_id, &key->gtk_v4);
      p = hash_get_mem (gm->tunnel_by_key4, &key->gtk_v4);
    }
  else
    {
      gre_mk_key6 (&a->src.ip6, &a->dst.ip6, outer_fib_index,
		   a->type, a->mode, a->session_id, &key->gtk_v6);
      p = hash_get_mem (gm->tunnel_by_key6, &key->gtk_v6);
    }

  if (NULL == p)
    return (NULL);

  return (pool_elt_at_index (gm->tunnels, p[0]));
}

static void
gre_tunnel_db_add (gre_tunnel_t * t, gre_tunnel_key_t * key)
{
  gre_main_t *gm = &gre_main;

  if (t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6)
    {
      hash_set_mem_alloc (&gm->tunnel_by_key6, &key->gtk_v6, t->dev_instance);
    }
  else
    {
      hash_set_mem_alloc (&gm->tunnel_by_key4, &key->gtk_v4, t->dev_instance);
    }
}

static void
gre_tunnel_db_remove (gre_tunnel_t * t, gre_tunnel_key_t * key)
{
  gre_main_t *gm = &gre_main;

  if (t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6)
    {
      hash_unset_mem_free (&gm->tunnel_by_key6, &key->gtk_v6);
    }
  else
    {
      hash_unset_mem_free (&gm->tunnel_by_key4, &key->gtk_v4);
    }
}

/**
 * gre_tunnel_stack
 *
 * 'stack' (resolve the recursion for) the tunnel's midchain adjacency
 */
void
gre_tunnel_stack (adj_index_t ai)
{
  gre_main_t *gm = &gre_main;
  ip_adjacency_t *adj;
  gre_tunnel_t *gt;
  u32 sw_if_index;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len (gm->tunnel_index_by_sw_if_index) <= sw_if_index) ||
      (~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
    return;

  gt = pool_elt_at_index (gm->tunnels,
			  gm->tunnel_index_by_sw_if_index[sw_if_index]);

  if ((vnet_hw_interface_get_flags (vnet_get_main (), gt->hw_if_index) &
       VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    {
      adj_midchain_delegate_unstack (ai);
    }
  else
    {
      adj_midchain_delegate_stack (ai, gt->outer_fib_index, &gt->tunnel_dst);
    }
}

/**
 * mgre_tunnel_stack
 *
 * 'stack' (resolve the recursion for) the tunnel's midchain adjacency
 */
static void
mgre_tunnel_stack (adj_index_t ai)
{
  gre_main_t *gm = &gre_main;
  const ip_adjacency_t *adj;
  const gre_tunnel_t *gt;
  u32 sw_if_index;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len (gm->tunnel_index_by_sw_if_index) <= sw_if_index) ||
      (~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
    return;

  gt = pool_elt_at_index (gm->tunnels,
			  gm->tunnel_index_by_sw_if_index[sw_if_index]);

  if ((vnet_hw_interface_get_flags (vnet_get_main (), gt->hw_if_index) &
       VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    {
      adj_midchain_delegate_unstack (ai);
    }
  else
    {
      const teib_entry_t *ne;

      ne = teib_entry_find_46 (sw_if_index, adj->ia_nh_proto,
			       &adj->sub_type.nbr.next_hop);
      if (NULL != ne)
	teib_entry_adj_stack (ne, ai);
    }
}

/**
 * @brief Call back when restacking all adjacencies on a GRE interface
 */
static adj_walk_rc_t
gre_adj_walk_cb (adj_index_t ai, void *ctx)
{
  gre_tunnel_stack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}
static adj_walk_rc_t
mgre_adj_walk_cb (adj_index_t ai, void *ctx)
{
  mgre_tunnel_stack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
gre_tunnel_restack (gre_tunnel_t * gt)
{
  fib_protocol_t proto;

  /*
   * walk all the adjacencies on th GRE interface and restack them
   */
  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    switch (gt->mode)
      {
      case TUNNEL_MODE_P2P:
	return (adj_nbr_walk (gt->sw_if_index, proto, gre_adj_walk_cb, NULL));
      case TUNNEL_MODE_MP:
	return (adj_nbr_walk (gt->sw_if_index, proto, mgre_adj_walk_cb, NULL));
      }
  }
}

static void
gre_teib_mk_key (const gre_tunnel_t * t,
		 const teib_entry_t * ne, gre_tunnel_key_t * key)
{
  const fib_prefix_t *nh;

  nh = teib_entry_get_nh (ne);

  /* construct the key using mode P2P so it can be found in the DP */
  if (FIB_PROTOCOL_IP4 == nh->fp_proto)
    gre_mk_key4 (t->tunnel_src.ip4,
		 nh->fp_addr.ip4,
		 teib_entry_get_fib_index (ne),
		 t->type, TUNNEL_MODE_P2P, 0, &key->gtk_v4);
  else
    gre_mk_key6 (&t->tunnel_src.ip6,
		 &nh->fp_addr.ip6,
		 teib_entry_get_fib_index (ne),
		 t->type, TUNNEL_MODE_P2P, 0, &key->gtk_v6);
}

/**
 * An TEIB entry has been added
 */
static void
gre_teib_entry_added (const teib_entry_t * ne)
{
  gre_main_t *gm = &gre_main;
  const ip_address_t *nh;
  gre_tunnel_key_t key;
  gre_tunnel_t *t;
  u32 sw_if_index;
  u32 t_idx;

  sw_if_index = teib_entry_get_sw_if_index (ne);
  if (vec_len (gm->tunnel_index_by_sw_if_index) < sw_if_index)
    return;

  t_idx = gm->tunnel_index_by_sw_if_index[sw_if_index];

  if (INDEX_INVALID == t_idx)
    return;

  /* entry has been added on an interface for which there is a GRE tunnel */
  t = pool_elt_at_index (gm->tunnels, t_idx);

  if (t->mode != TUNNEL_MODE_MP)
    return;

  /* the next-hop (underlay) of the NHRP entry will form part of the key for
   * ingress lookup to match packets to this interface */
  gre_teib_mk_key (t, ne, &key);
  gre_tunnel_db_add (t, &key);

  /* update the rewrites for each of the adjacencies for this peer (overlay)
   * using  the next-hop (underlay) */
  mgre_walk_ctx_t ctx = {
    .t = t,
    .ne = ne
  };
  nh = teib_entry_get_peer (ne);
  adj_nbr_walk_nh (teib_entry_get_sw_if_index (ne),
		   (AF_IP4 == ip_addr_version (nh) ?
		    FIB_PROTOCOL_IP4 :
		    FIB_PROTOCOL_IP6),
		   &ip_addr_46 (nh), mgre_mk_complete_walk, &ctx);
}

static void
gre_teib_entry_deleted (const teib_entry_t * ne)
{
  gre_main_t *gm = &gre_main;
  const ip_address_t *nh;
  gre_tunnel_key_t key;
  gre_tunnel_t *t;
  u32 sw_if_index;
  u32 t_idx;

  sw_if_index = teib_entry_get_sw_if_index (ne);
  if (vec_len (gm->tunnel_index_by_sw_if_index) < sw_if_index)
    return;

  t_idx = gm->tunnel_index_by_sw_if_index[sw_if_index];

  if (INDEX_INVALID == t_idx)
    return;

  t = pool_elt_at_index (gm->tunnels, t_idx);

  /* remove the next-hop as an ingress lookup key */
  gre_teib_mk_key (t, ne, &key);
  gre_tunnel_db_remove (t, &key);

  nh = teib_entry_get_peer (ne);

  /* make all the adjacencies incomplete */
  adj_nbr_walk_nh (teib_entry_get_sw_if_index (ne),
		   (AF_IP4 == ip_addr_version (nh) ?
		    FIB_PROTOCOL_IP4 :
		    FIB_PROTOCOL_IP6),
		   &ip_addr_46 (nh), mgre_mk_incomplete_walk, t);
}

static walk_rc_t
gre_tunnel_delete_teib_walk (index_t nei, void *ctx)
{
  gre_tunnel_t *t = ctx;
  gre_tunnel_key_t key;

  gre_teib_mk_key (t, teib_entry_get (nei), &key);
  gre_tunnel_db_remove (t, &key);

  return (WALK_CONTINUE);
}

static walk_rc_t
gre_tunnel_add_teib_walk (index_t nei, void *ctx)
{
  gre_tunnel_t *t = ctx;
  gre_tunnel_key_t key;

  gre_teib_mk_key (t, teib_entry_get (nei), &key);
  gre_tunnel_db_add (t, &key);

  return (WALK_CONTINUE);
}

static int
vnet_gre_tunnel_add (vnet_gre_tunnel_add_del_args_t * a,
		     u32 outer_fib_index, u32 * sw_if_indexp)
{
  gre_main_t *gm = &gre_main;
  vnet_main_t *vnm = gm->vnet_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  gre_tunnel_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, sw_if_index;
  clib_error_t *error;
  u8 is_ipv6 = a->is_ipv6;
  gre_tunnel_key_t key;

  t = gre_tunnel_db_find (a, outer_fib_index, &key);
  if (NULL != t)
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));

  /* Reconcile the real dev_instance and a possible requested instance */
  u32 t_idx = t - gm->tunnels;	/* tunnel index (or instance) */
  u32 u_idx = a->instance;	/* user specified instance */
  if (u_idx == ~0)
    u_idx = t_idx;
  if (hash_get (gm->instance_used, u_idx))
    {
      pool_put (gm->tunnels, t);
      return VNET_API_ERROR_INSTANCE_IN_USE;
    }
  hash_set (gm->instance_used, u_idx, 1);

  t->dev_instance = t_idx;	/* actual */
  t->user_instance = u_idx;	/* name */

  t->type = a->type;
  t->mode = a->mode;
  t->flags = a->flags;
  if (t->type == GRE_TUNNEL_TYPE_ERSPAN)
    t->session_id = a->session_id;

  if (t->type == GRE_TUNNEL_TYPE_L3)
    {
      if (t->mode == TUNNEL_MODE_P2P)
	hw_if_index =
	  vnet_register_interface (vnm, gre_device_class.index, t_idx,
				   gre_hw_interface_class.index, t_idx);
      else
	hw_if_index =
	  vnet_register_interface (vnm, gre_device_class.index, t_idx,
				   mgre_hw_interface_class.index, t_idx);
    }
  else
    {
      /* Default MAC address (d00b:eed0:0000 + sw_if_index) */
      u8 address[6] =
	{ 0xd0, 0x0b, 0xee, 0xd0, (u8) (t_idx >> 8), (u8) t_idx };
      error =
	ethernet_register_interface (vnm, gre_device_class.index, t_idx,
				     address, &hw_if_index, 0);
      if (error)
	{
	  clib_error_report (error);
	  return VNET_API_ERROR_INVALID_REGISTRATION;
	}
    }

  /* Set GRE tunnel interface output node (not used for L3 payload) */
  if (GRE_TUNNEL_TYPE_ERSPAN == t->type)
    vnet_set_interface_output_node (vnm, hw_if_index,
				    gre_erspan_encap_node.index);
  else
    vnet_set_interface_output_node (vnm, hw_if_index,
				    gre_teb_encap_node.index);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  sw_if_index = hi->sw_if_index;

  t->hw_if_index = hw_if_index;
  t->outer_fib_index = outer_fib_index;
  t->sw_if_index = sw_if_index;
  t->l2_adj_index = ADJ_INDEX_INVALID;

  vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = t_idx;

  if (!is_ipv6)
    {
      vec_validate (im4->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes =
	64 + sizeof (gre_header_t) + sizeof (ip4_header_t);
    }
  else
    {
      vec_validate (im6->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes =
	64 + sizeof (gre_header_t) + sizeof (ip6_header_t);
    }

  /* Standard default gre MTU. */
  vnet_sw_interface_set_mtu (vnm, sw_if_index, 9000);

  /*
   * source the FIB entry for the tunnel's destination
   * and become a child thereof. The tunnel will then get poked
   * when the forwarding for the entry updates, and the tunnel can
   * re-stack accordingly
   */

  clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
  t->tunnel_dst.fp_len = !is_ipv6 ? 32 : 128;
  t->tunnel_dst.fp_proto = !is_ipv6 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  t->tunnel_dst.fp_addr = a->dst;

  gre_tunnel_db_add (t, &key);

  if (t->mode == TUNNEL_MODE_MP)
    teib_walk_itf (t->sw_if_index, gre_tunnel_add_teib_walk, t);

  if (t->type == GRE_TUNNEL_TYPE_ERSPAN)
    {
      gre_sn_key_t skey;
      gre_sn_t *gre_sn;

      gre_mk_sn_key (t, &skey);
      gre_sn = (gre_sn_t *) hash_get_mem (gm->seq_num_by_key, &skey);
      if (gre_sn != NULL)
	{
	  gre_sn->ref_count++;
	  t->gre_sn = gre_sn;
	}
      else
	{
	  gre_sn = clib_mem_alloc (sizeof (gre_sn_t));
	  gre_sn->seq_num = 0;
	  gre_sn->ref_count = 1;
	  t->gre_sn = gre_sn;
	  hash_set_mem_alloc (&gm->seq_num_by_key, &skey, (uword) gre_sn);
	}
    }

  if (t->type != GRE_TUNNEL_TYPE_L3)
    {
      t->l2_adj_index = adj_nbr_add_or_lock
	(t->tunnel_dst.fp_proto, VNET_LINK_ETHERNET, &zero_addr, sw_if_index);
      gre_update_adj (vnm, t->sw_if_index, t->l2_adj_index);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  /* register gre46-input nodes */
  ip4_register_protocol (IP_PROTOCOL_GRE, gre4_input_node.index);
  ip6_register_protocol (IP_PROTOCOL_GRE, gre6_input_node.index);

  return 0;
}

static int
vnet_gre_tunnel_delete (vnet_gre_tunnel_add_del_args_t * a,
			u32 outer_fib_index, u32 * sw_if_indexp)
{
  gre_main_t *gm = &gre_main;
  vnet_main_t *vnm = gm->vnet_main;
  gre_tunnel_t *t;
  gre_tunnel_key_t key;
  u32 sw_if_index;

  t = gre_tunnel_db_find (a, outer_fib_index, &key);
  if (NULL == t)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (t->mode == TUNNEL_MODE_MP)
    teib_walk_itf (t->sw_if_index, gre_tunnel_delete_teib_walk, t);

  sw_if_index = t->sw_if_index;
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */ );

  /* make sure tunnel is removed from l2 bd or xconnect */
  set_int_l2_mode (gm->vlib_main, vnm, MODE_L3, sw_if_index, 0,
		   L2_BD_PORT_TYPE_NORMAL, 0, 0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

  if (t->type == GRE_TUNNEL_TYPE_L3)
    vnet_delete_hw_interface (vnm, t->hw_if_index);
  else
    ethernet_delete_interface (vnm, t->hw_if_index);

  if (t->l2_adj_index != ADJ_INDEX_INVALID)
    {
      adj_midchain_delegate_unstack (t->l2_adj_index);
      adj_unlock (t->l2_adj_index);
    }

  ASSERT ((t->type != GRE_TUNNEL_TYPE_ERSPAN) || (t->gre_sn != NULL));
  if ((t->type == GRE_TUNNEL_TYPE_ERSPAN) && (t->gre_sn->ref_count-- == 1))
    {
      gre_sn_key_t skey;
      gre_mk_sn_key (t, &skey);
      hash_unset_mem_free (&gm->seq_num_by_key, &skey);
      clib_mem_free (t->gre_sn);
    }

  hash_unset (gm->instance_used, t->user_instance);
  gre_tunnel_db_remove (t, &key);
  pool_put (gm->tunnels, t);

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

int
vnet_gre_tunnel_add_del (vnet_gre_tunnel_add_del_args_t * a,
			 u32 * sw_if_indexp)
{
  u32 outer_fib_index;

  outer_fib_index = fib_table_find ((a->is_ipv6 ?
				     FIB_PROTOCOL_IP6 :
				     FIB_PROTOCOL_IP4), a->outer_table_id);

  if (~0 == outer_fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if (a->session_id > GTK_SESSION_ID_MAX)
    return VNET_API_ERROR_INVALID_SESSION_ID;

  if (a->mode == TUNNEL_MODE_MP && !ip46_address_is_zero (&a->dst))
    return (VNET_API_ERROR_INVALID_DST_ADDRESS);

  if (a->is_add)
    return (vnet_gre_tunnel_add (a, outer_fib_index, sw_if_indexp));
  else
    return (vnet_gre_tunnel_delete (a, outer_fib_index, sw_if_indexp));
}

clib_error_t *
gre_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  gre_main_t *gm = &gre_main;
  vnet_hw_interface_t *hi;
  gre_tunnel_t *t;
  u32 ti;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (NULL == gm->tunnel_index_by_sw_if_index ||
      hi->sw_if_index >= vec_len (gm->tunnel_index_by_sw_if_index))
    return (NULL);

  ti = gm->tunnel_index_by_sw_if_index[hi->sw_if_index];

  if (~0 == ti)
    /* not one of ours */
    return (NULL);

  t = pool_elt_at_index (gm->tunnels, ti);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */ );

  gre_tunnel_restack (t);

  return /* no error */ 0;
}

static clib_error_t *
create_gre_tunnel_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_gre_tunnel_add_del_args_t _a, *a = &_a;
  ip46_address_t src = ip46_address_initializer, dst =
    ip46_address_initializer;
  u32 instance = ~0;
  u32 outer_table_id = 0;
  gre_tunnel_type_t t_type = GRE_TUNNEL_TYPE_L3;
  tunnel_mode_t t_mode = TUNNEL_MODE_P2P;
  tunnel_encap_decap_flags_t flags = TUNNEL_ENCAP_DECAP_FLAG_NONE;
  u32 session_id = 0;
  int rv;
  u8 is_add = 1;
  u32 sw_if_index;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "instance %d", &instance))
	;
      else if (unformat (line_input, "src %U", unformat_ip46_address, &src))
	;
      else if (unformat (line_input, "dst %U", unformat_ip46_address, &dst))
	;
      else if (unformat (line_input, "outer-table-id %d", &outer_table_id))
	;
      else if (unformat (line_input, "multipoint"))
	t_mode = TUNNEL_MODE_MP;
      else if (unformat (line_input, "teb"))
	t_type = GRE_TUNNEL_TYPE_TEB;
      else if (unformat (line_input, "erspan %d", &session_id))
	t_type = GRE_TUNNEL_TYPE_ERSPAN;
      else
	if (unformat
	    (line_input, "flags %U", unformat_tunnel_encap_decap_flags,
	     &flags))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (ip46_address_is_equal (&src, &dst))
    {
      error = clib_error_return (0, "src and dst are identical");
      goto done;
    }

  if (t_mode != TUNNEL_MODE_MP && ip46_address_is_zero (&dst))
    {
      error = clib_error_return (0, "destination address not specified");
      goto done;
    }

  if (ip46_address_is_zero (&src))
    {
      error = clib_error_return (0, "source address not specified");
      goto done;
    }

  if (ip46_address_is_ip4 (&src) != ip46_address_is_ip4 (&dst))
    {
      error =
	clib_error_return (0, "src and dst address must be the same AF");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->outer_table_id = outer_table_id;
  a->type = t_type;
  a->mode = t_mode;
  a->session_id = session_id;
  a->is_ipv6 = !ip46_address_is_ip4 (&src);
  a->instance = instance;
  a->flags = flags;
  clib_memcpy (&a->src, &src, sizeof (a->src));
  clib_memcpy (&a->dst, &dst, sizeof (a->dst));

  rv = vnet_gre_tunnel_add_del (a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_IF_ALREADY_EXISTS:
      error = clib_error_return (0, "GRE tunnel already exists...");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "outer table ID %d doesn't exist\n",
				 outer_table_id);
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "GRE tunnel doesn't exist");
      goto done;
    case VNET_API_ERROR_INVALID_SESSION_ID:
      error = clib_error_return (0, "session ID %d out of range\n",
				 session_id);
      goto done;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "Instance is in use");
      goto done;
    default:
      error =
	clib_error_return (0, "vnet_gre_tunnel_add_del returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_gre_tunnel_command, static) = {
  .path = "create gre tunnel",
  .short_help = "create gre tunnel src <addr> dst <addr> [instance <n>] "
                "[outer-fib-id <fib>] [teb | erspan <session-id>] [del] "
                "[multipoint]",
  .function = create_gre_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_gre_tunnel_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u32 ti = ~0;

  if (pool_elts (gm->tunnels) == 0)
    vlib_cli_output (vm, "No GRE tunnels configured...");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &ti))
	;
      else
	break;
    }

  if (~0 == ti)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gm->tunnels)
       {
          vlib_cli_output (vm, "%U", format_gre_tunnel, t);
      }
      /* *INDENT-ON* */
    }
  else
    {
      t = pool_elt_at_index (gm->tunnels, ti);

      vlib_cli_output (vm, "%U", format_gre_tunnel, t);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_gre_tunnel_command, static) = {
    .path = "show gre tunnel",
    .function = show_gre_tunnel_command_fn,
};
/* *INDENT-ON* */

const static teib_vft_t gre_teib_vft = {
  .nv_added = gre_teib_entry_added,
  .nv_deleted = gre_teib_entry_deleted,
};

/* force inclusion from application's main.c */
clib_error_t *
gre_interface_init (vlib_main_t * vm)
{
  teib_register (&gre_teib_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (gre_interface_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
