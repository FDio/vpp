/*
 * nsh_md2_ioam.c - NSH iOAM functions for MD type 2
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/plugin/plugin.h>
#include <nsh/nsh.h>
#include <nsh/nsh_packet.h>
#include <vnet/ip/ip.h>
#include <nsh/nsh-md2-ioam/nsh_md2_ioam.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>

/* define message structures */
#define vl_typedefs
#include <nsh/nsh.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <nsh/nsh.api.h>
#undef vl_endianfun

nsh_md2_ioam_main_t nsh_md2_ioam_main;

static void
nsh_md2_ioam_set_clear_output_feature_on_intf (vlib_main_t * vm,
						    u32 sw_if_index0,
						    u8 is_add)
{



  vnet_feature_enable_disable ("ip4-output",
			       "nsh-md2-ioam-encap-transit",
			       sw_if_index0, is_add,
			       0 /* void *feature_config */ ,
			       0 /* u32 n_feature_config_bytes */ );
  return;
}

void
nsh_md2_ioam_clear_output_feature_on_all_intfs (vlib_main_t * vm)
{
  vnet_sw_interface_t *si = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;

  pool_foreach (si, im->sw_interfaces, (
					 {
					 nsh_md2_ioam_set_clear_output_feature_on_intf
					 (vm, si->sw_if_index, 0);
					 }));
  return;
}


extern fib_forward_chain_type_t
fib_entry_get_default_chain_type (const fib_entry_t * fib_entry);

int
nsh_md2_ioam_enable_disable_for_dest (vlib_main_t * vm,
					   ip46_address_t dst_addr,
					   u32 outer_fib_index,
					   u8 is_ipv4, u8 is_add)
{
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
  u32 fib_index0 = 0;

  fib_node_index_t fei = ~0;
  u32 *sw_if_index0 = NULL;
#if 0
  fib_entry_t *fib_entry;
  u32 adj_index0;
  ip_adjacency_t *adj0;
  load_balance_t *lb_m, *lb_b;
  const dpo_id_t *dpo0, *dpo1;
  u32 i, j, k;
#endif
  u32 *intf_list = NULL;
  fib_prefix_t fib_prefix;

  if (is_ipv4)
    {
      memset (&fib_prefix, 0, sizeof (fib_prefix_t));
      fib_prefix.fp_len = 32;
      fib_prefix.fp_proto = FIB_PROTOCOL_IP4;
#define  TRANSIT_UNIT_TEST_HACK 1
#ifdef TRANSIT_UNIT_TEST_HACK
      memset(&dst_addr, 0, sizeof(dst_addr));
      dst_addr.ip4.as_u32 = clib_net_to_host_u32(0x14020102);
#endif
      fib_prefix.fp_addr = dst_addr;
    }
  else
    {
      return 0;
    }

  fei = fib_table_lookup (fib_index0, &fib_prefix);
#if 0
  fib_entry = fib_entry_get (fei);


  if (!dpo_id_is_valid (&fib_entry->fe_lb))
    {
      return (-1);
    }

  lb_m = load_balance_get (fib_entry->fe_lb.dpoi_index);

  for (i = 0; i < lb_m->lb_n_buckets; i++)
    {
      dpo0 = load_balance_get_bucket_i (lb_m, i);

      if (dpo0->dpoi_type == DPO_LOAD_BALANCE ||
	  dpo0->dpoi_type == DPO_ADJACENCY)
	{
	  if (dpo0->dpoi_type == DPO_ADJACENCY)
	    {
	      k = 1;
	    }
	  else
	    {
	      lb_b = load_balance_get (dpo0->dpoi_index);
	      k = lb_b->lb_n_buckets;
	    }

	  for (j = 0; j < k; j++)
	    {
	      if (dpo0->dpoi_type == DPO_ADJACENCY)
		{
		  dpo1 = dpo0;
		}
	      else
		{
		  dpo1 = load_balance_get_bucket_i (lb_b, j);
		}

	      if (dpo1->dpoi_type == DPO_ADJACENCY)
		{
		  adj_index0 = dpo1->dpoi_index;

		  if (ADJ_INDEX_INVALID == adj_index0)
		    {
		      continue;
		    }

		  adj0 =
		    ip_get_adjacency (&(ip4_main.lookup_main), adj_index0);
		  sw_if_index0 = adj0->rewrite_header.sw_if_index;

		  if (~0 == sw_if_index0)
		    {
		      continue;
		    }


		  if (is_add)
		    {
		      vnet_feature_enable_disable ("ip4-output",
						   "nsh-md2-ioam-encap-transit",
						   sw_if_index0, is_add, 0,
						   /* void *feature_config */
						   0	/* u32 n_feature_config_bytes */
			);

		      vec_validate_init_empty (hm->bool_ref_by_sw_if_index,
					       sw_if_index0, ~0);
		      hm->bool_ref_by_sw_if_index[sw_if_index0] = 1;
		    }
		  else
		    {
		      hm->bool_ref_by_sw_if_index[sw_if_index0] = ~0;
		    }
		}
	    }
	}
    }
#else

u32 fib_path_get_resolving_interface (fib_node_index_t path_index);
    vec_add1(intf_list, fib_path_get_resolving_interface(fei));
    vec_foreach(sw_if_index0, intf_list)
    if (is_add)
      {
        vnet_feature_enable_disable ("ip4-output",
                         "nsh-md2-ioam-encap-transit",
                         *sw_if_index0, is_add, 0,
                         /* void *feature_config */
                         0    /* u32 n_feature_config_bytes */
          );

        vec_validate_init_empty (hm->bool_ref_by_sw_if_index,
                         *sw_if_index0, ~0);
        hm->bool_ref_by_sw_if_index[*sw_if_index0] = 1;
      }
    else
      {
        hm->bool_ref_by_sw_if_index[*sw_if_index0] = ~0;
      }

#endif

  if (is_ipv4)
    {
      uword *t = NULL;
      nsh_md2_ioam_dest_tunnels_t *t1;
      fib_prefix_t key4, *key4_copy;
      hash_pair_t *hp;
      memset (&key4, 0, sizeof (key4));
      key4.fp_proto = FIB_PROTOCOL_IP4;
      key4.fp_addr.ip4.as_u32 = fib_prefix.fp_addr.ip4.as_u32;
      t = hash_get_mem (hm->dst_by_ip4, &key4);
      if (is_add)
	{
	  if (t)
	    {
	      return 0;
	    }
	  pool_get_aligned (hm->dst_tunnels, t1, CLIB_CACHE_LINE_BYTES);
	  memset (t1, 0, sizeof (*t1));
	  t1->fp_proto = FIB_PROTOCOL_IP4;
	  t1->dst_addr.ip4.as_u32 = fib_prefix.fp_addr.ip4.as_u32;
	  key4_copy = clib_mem_alloc (sizeof (*key4_copy));
          memset(key4_copy, 0, sizeof(*key4_copy));
	  clib_memcpy (key4_copy, &key4, sizeof (*key4_copy));
	  hash_set_mem (hm->dst_by_ip4, key4_copy, t1 - hm->dst_tunnels);
	  /*
	   * Attach to the FIB entry for the VxLAN-GPE destination
	   * and become its child. The dest route will invoke a callback
	   * when the fib entry changes, it can be used to
	   * re-program the output feature on the egress interface.
	   */

	  const fib_prefix_t tun_dst_pfx = {
	    .fp_len = 32,
	    .fp_proto = FIB_PROTOCOL_IP4,
	    .fp_addr = {.ip4 = t1->dst_addr.ip4,}
	  };

	  t1->fib_entry_index =
	    fib_table_entry_special_add (outer_fib_index,
					 &tun_dst_pfx,
					 FIB_SOURCE_RR,
					 FIB_ENTRY_FLAG_NONE);
	  t1->sibling_index =
	    fib_entry_child_add (t1->fib_entry_index,
				 hm->fib_entry_type, t1 - hm->dst_tunnels);
	  t1->outer_fib_index = outer_fib_index;

	}
      else
	{
	  if (!t)
	    {
	      return 0;
	    }
	  t1 = pool_elt_at_index (hm->dst_tunnels, t[0]);
	  hp = hash_get_pair (hm->dst_by_ip4, &key4);
	  key4_copy = (void *) (hp->key);
	  hash_unset_mem (hm->dst_by_ip4, &key4);
	  clib_mem_free (key4_copy);
	  pool_put (hm->dst_tunnels, t1);
	}
    }
  else
    {
      // TBD for IPv6
    }

  return 0;
}

void
nsh_md2_ioam_refresh_output_feature_on_all_dest (void)
{
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
  nsh_main_t *gm = &nsh_main;
  nsh_md2_ioam_dest_tunnels_t *t;
  u32 i;

  if (pool_elts (hm->dst_tunnels) == 0)
    return;

  nsh_md2_ioam_clear_output_feature_on_all_intfs (gm->vlib_main);
  i = vec_len (hm->bool_ref_by_sw_if_index);
  vec_free (hm->bool_ref_by_sw_if_index);
  vec_validate_init_empty (hm->bool_ref_by_sw_if_index, i, ~0);
  pool_foreach (t, hm->dst_tunnels, (
				      {
				      nsh_md2_ioam_enable_disable_for_dest
				      (gm->vlib_main,
				       t->dst_addr,
				       t->outer_fib_index,
				       (t->fp_proto == FIB_PROTOCOL_IP4), 1
				       /* is_add */
				      );
				      }
		));
  return;
}

void
nsh_md2_ioam_clear_output_feature_on_select_intfs (void)
{
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
  nsh_main_t *gm = &nsh_main;

  u32 sw_if_index0 = 0;
  for (sw_if_index0 = 0;
       sw_if_index0 < vec_len (hm->bool_ref_by_sw_if_index); sw_if_index0++)
    {
      if (hm->bool_ref_by_sw_if_index[sw_if_index0] == 0xFF)
	{
	  nsh_md2_ioam_set_clear_output_feature_on_intf
	    (gm->vlib_main, sw_if_index0, 0);
	}
    }

  return;
}




clib_error_t *
nsh_md2_ioam_enable_disable (int has_trace_option, int has_pot_option,
				  int has_ppc_option)
{
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;

  hm->has_trace_option = has_trace_option;
  hm->has_pot_option = has_pot_option;
  hm->has_ppc_option = has_ppc_option;

  if (hm->has_trace_option)
    {
      nsh_md2_ioam_trace_profile_setup ();
    }
  else if (!hm->has_trace_option)
    {
      nsh_md2_ioam_trace_profile_cleanup ();
    }

  return 0;
}


int nsh_md2_ioam_disable_for_dest
  (vlib_main_t * vm, ip46_address_t dst_addr, u32 outer_fib_index,
   u8 ipv4_set)
{
  nsh_md2_ioam_dest_tunnels_t *t;
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
  nsh_main_t *gm = &nsh_main;

  nsh_md2_ioam_enable_disable_for_dest (gm->vlib_main,
					     dst_addr, outer_fib_index,
					     ipv4_set, 0);
  if (pool_elts (hm->dst_tunnels) == 0)
    {
      nsh_md2_ioam_clear_output_feature_on_select_intfs ();
      return 0;
    }

  pool_foreach (t, hm->dst_tunnels, (
				      {
				      nsh_md2_ioam_enable_disable_for_dest
				      (gm->vlib_main,
				       t->dst_addr,
				       t->outer_fib_index,
				       (t->fp_proto ==
					FIB_PROTOCOL_IP4), 1 /* is_add */ );
				      }
		));
  nsh_md2_ioam_clear_output_feature_on_select_intfs ();
  return (0);

}

static clib_error_t *nsh_md2_ioam_set_transit_rewrite_command_fn
  (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nsh_main_t *gm = &nsh_main;
  ip46_address_t dst_addr;
  u8 dst_addr_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u8 disable = 0;
  clib_error_t *rv = 0;
  u32 outer_fib_index = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dst-ip %U", unformat_ip4_address, &dst_addr.ip4))
	{
	  dst_addr_set = 1;
	  ipv4_set = 1;
	}
      else
	if (unformat
	    (input, "dst-ip %U", unformat_ip6_address, &dst_addr.ip6))
	{
	  dst_addr_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (input, "outer-fib-index %d", &outer_fib_index))
	{
	}

      else if (unformat (input, "disable"))
	disable = 1;
      else
	break;
    }

  if (dst_addr_set == 0)
    return clib_error_return (0,
			      "LISP-GPE Tunnel destination address not specified");
  if (ipv4_set && ipv6_set)
    return clib_error_return (0, "both IPv4 and IPv6 addresses specified");
  if (!disable)
    {
      nsh_md2_ioam_enable_disable_for_dest (gm->vlib_main,
						 dst_addr, outer_fib_index,
						 ipv4_set, 1);
    }
  else
    {
      nsh_md2_ioam_disable_for_dest
	(vm, dst_addr, outer_fib_index, ipv4_set);
    }
  return rv;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (nsh_md2_ioam_set_transit_rewrite_cmd, static) = {
  .path = "set nsh-md2-ioam-transit",
  .short_help = "set nsh-ioam-lisp-gpe-transit dst-ip <dst_ip> [outer-fib-index <outer_fib_index>] [disable]",
  .function = nsh_md2_ioam_set_transit_rewrite_command_fn,
};

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
nsh_md2_ioam_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  nsh_md2_ioam_refresh_output_feature_on_all_dest ();
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
nsh_md2_ioam_fib_node_get (fib_node_index_t index)
{
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
  return (&hm->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
nsh_md2_ioam_last_lock_gone (fib_node_t * node)
{
  ASSERT (0);
}


/*
 * Virtual function table registered by MPLS GRE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t nsh_md2_ioam_vft = {
  .fnv_get = nsh_md2_ioam_fib_node_get,
  .fnv_last_lock = nsh_md2_ioam_last_lock_gone,
  .fnv_back_walk = nsh_md2_ioam_back_walk,
};

void
nsh_md2_ioam_interface_init (void)
{
  nsh_md2_ioam_main_t *hm = &nsh_md2_ioam_main;
  hm->fib_entry_type = fib_node_register_new_type (&nsh_md2_ioam_vft);
  return;
}

