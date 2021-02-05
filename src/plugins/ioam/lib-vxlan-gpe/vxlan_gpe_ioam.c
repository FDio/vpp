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
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/format.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/udp/udp_local.h>

vxlan_gpe_ioam_main_t vxlan_gpe_ioam_main;

int
vxlan_gpe_ioam_set_rewrite (vxlan_gpe_tunnel_t * t, int has_trace_option,
			    int has_pot_option, int has_ppc_option,
			    u8 ipv6_set)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  u32 size;
  vxlan_gpe_ioam_hdr_t *vxlan_gpe_ioam_hdr;
  u8 *current;
  u8 trace_data_size = 0;
  u8 pot_data_size = 0;

  if (has_trace_option == 0 && has_pot_option == 0)
    return -1;

  /* Work out how much space we need */
  size = sizeof (vxlan_gpe_ioam_hdr_t);

  if (has_trace_option
      && hm->add_options[VXLAN_GPE_OPTION_TYPE_IOAM_TRACE] != 0)
    {
      size += sizeof (vxlan_gpe_ioam_option_t);
      size += hm->options_size[VXLAN_GPE_OPTION_TYPE_IOAM_TRACE];
    }
  if (has_pot_option
      && hm->add_options[VXLAN_GPE_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] != 0)
    {
      size += sizeof (vxlan_gpe_ioam_option_t);
      size += hm->options_size[VXLAN_GPE_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT];
    }

  t->rewrite_size = size;

  if (!ipv6_set)
    {
      vxlan4_gpe_rewrite (t, size, VXLAN_GPE_PROTOCOL_IOAM,
			  hm->encap_v4_next_node);
      vxlan_gpe_ioam_hdr =
	(vxlan_gpe_ioam_hdr_t *) (t->rewrite +
				  sizeof (ip4_vxlan_gpe_header_t));
    }
  else
    {
      vxlan6_gpe_rewrite (t, size, VXLAN_GPE_PROTOCOL_IOAM,
			  VXLAN_GPE_ENCAP_NEXT_IP6_LOOKUP);
      vxlan_gpe_ioam_hdr =
	(vxlan_gpe_ioam_hdr_t *) (t->rewrite +
				  sizeof (ip6_vxlan_gpe_header_t));
    }


  vxlan_gpe_ioam_hdr->type = VXLAN_GPE_PROTOCOL_IOAM;
  /* Length of the header in octets */
  vxlan_gpe_ioam_hdr->length = size;
  vxlan_gpe_ioam_hdr->protocol = t->protocol;
  current = (u8 *) vxlan_gpe_ioam_hdr + sizeof (vxlan_gpe_ioam_hdr_t);

  if (has_trace_option
      && hm->add_options[VXLAN_GPE_OPTION_TYPE_IOAM_TRACE] != 0)
    {
      if (0 != hm->add_options[VXLAN_GPE_OPTION_TYPE_IOAM_TRACE] (current,
								  &trace_data_size))
	return -1;
      current += trace_data_size;
    }
  if (has_pot_option
      && hm->add_options[VXLAN_GPE_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT] != 0)
    {
      pot_data_size =
	hm->options_size[VXLAN_GPE_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT];
      if (0 ==
	  hm->add_options[VXLAN_GPE_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT]
	  (current, &pot_data_size))
	current += pot_data_size;
    }

  return 0;
}

int
vxlan_gpe_ioam_clear_rewrite (vxlan_gpe_tunnel_t * t, int has_trace_option,
			      int has_pot_option, int has_ppc_option,
			      u8 ipv6_set)
{

  t->rewrite_size = 0;

  if (!ipv6_set)
    {
      vxlan4_gpe_rewrite (t, 0, 0, VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP);
    }
  else
    {
      vxlan6_gpe_rewrite (t, 0, 0, VXLAN_GPE_ENCAP_NEXT_IP6_LOOKUP);
    }


  return 0;
}

clib_error_t *
vxlan_gpe_ioam_clear (vxlan_gpe_tunnel_t * t,
		      int has_trace_option, int has_pot_option,
		      int has_ppc_option, u8 ipv6_set)
{
  int rv;
  rv = vxlan_gpe_ioam_clear_rewrite (t, 0, 0, 0, 0);

  if (rv == 0)
    {
      return (0);
    }
  else
    {
      return clib_error_return_code (0, rv, 0,
				     "vxlan_gpe_ioam_clear_rewrite returned %d",
				     rv);
    }

}


clib_error_t *
vxlan_gpe_ioam_set (vxlan_gpe_tunnel_t * t,
		    int has_trace_option, int has_pot_option,
		    int has_ppc_option, u8 ipv6_set)
{
  int rv;
  rv = vxlan_gpe_ioam_set_rewrite (t, has_trace_option,
				   has_pot_option, has_ppc_option, ipv6_set);

  if (rv == 0)
    {
      return (0);
    }
  else
    {
      return clib_error_return_code (0, rv, 0,
				     "vxlan_gpe_ioam_set_rewrite returned %d",
				     rv);
    }

}

static void
vxlan_gpe_set_clear_output_feature_on_intf (vlib_main_t * vm,
					    u32 sw_if_index0, u8 is_add)
{



  vnet_feature_enable_disable ("ip4-output", "vxlan-gpe-transit-ioam",
			       sw_if_index0, is_add,
			       0 /* void *feature_config */ ,
			       0 /* u32 n_feature_config_bytes */ );
  return;
}

void
vxlan_gpe_clear_output_feature_on_all_intfs (vlib_main_t * vm)
{
  vnet_sw_interface_t *si = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;

  pool_foreach (si, im->sw_interfaces)
  {
    vxlan_gpe_set_clear_output_feature_on_intf (vm, si->sw_if_index, 0);
  }
  return;
}


extern fib_forward_chain_type_t
fib_entry_get_default_chain_type (const fib_entry_t * fib_entry);

int
vxlan_gpe_enable_disable_ioam_for_dest (vlib_main_t * vm,
					ip46_address_t dst_addr,
					u32 outer_fib_index,
					u8 is_ipv4, u8 is_add)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  u32 fib_index0 = 0;
  u32 sw_if_index0 = ~0;

  fib_node_index_t fei = ~0;
  fib_entry_t *fib_entry;
  u32 adj_index0;
  ip_adjacency_t *adj0;
  fib_prefix_t fib_prefix;
  //fib_forward_chain_type_t fct;
  load_balance_t *lb_m, *lb_b;
  const dpo_id_t *dpo0, *dpo1;
  u32 i, j;
  //vnet_hw_interface_t *hw;

  if (is_ipv4)
    {
      clib_memset (&fib_prefix, 0, sizeof (fib_prefix_t));
      fib_prefix.fp_len = 32;
      fib_prefix.fp_proto = FIB_PROTOCOL_IP4;
      fib_prefix.fp_addr = dst_addr;
    }
  else
    {
      return 0;
    }

  fei = fib_table_lookup (fib_index0, &fib_prefix);
  fib_entry = fib_entry_get (fei);

  //fct = fib_entry_get_default_chain_type (fib_entry);

  if (!dpo_id_is_valid (&fib_entry->fe_lb /*[fct] */ ))
    {
      return (-1);
    }

  lb_m = load_balance_get (fib_entry->fe_lb /*[fct] */ .dpoi_index);

  for (i = 0; i < lb_m->lb_n_buckets; i++)
    {
      dpo0 = load_balance_get_bucket_i (lb_m, i);

      if (dpo0->dpoi_type == DPO_LOAD_BALANCE)
	{
	  lb_b = load_balance_get (dpo0->dpoi_index);

	  for (j = 0; j < lb_b->lb_n_buckets; j++)
	    {
	      dpo1 = load_balance_get_bucket_i (lb_b, j);

	      if (dpo1->dpoi_type == DPO_ADJACENCY)
		{
		  adj_index0 = dpo1->dpoi_index;

		  if (ADJ_INDEX_INVALID == adj_index0)
		    {
		      continue;
		    }

		  adj0 = adj_get (adj_index0);
		  sw_if_index0 = adj0->rewrite_header.sw_if_index;

		  if (~0 == sw_if_index0)
		    {
		      continue;
		    }


		  if (is_add)
		    {
		      vnet_feature_enable_disable ("ip4-output",
						   "vxlan-gpe-transit-ioam",
						   sw_if_index0, is_add, 0
						   /* void *feature_config */
						   , 0	/* u32 n_feature_config_bytes */
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

  if (is_ipv4)
    {

      uword *t = NULL;
      vxlan_gpe_ioam_dest_tunnels_t *t1;
      fib_prefix_t key4, *key4_copy;
      hash_pair_t *hp;
      clib_memset (&key4, 0, sizeof (key4));
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
	  clib_memset (t1, 0, sizeof (*t1));
	  t1->fp_proto = FIB_PROTOCOL_IP4;
	  t1->dst_addr.ip4.as_u32 = fib_prefix.fp_addr.ip4.as_u32;
	  key4_copy = clib_mem_alloc (sizeof (*key4_copy));
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
					 FIB_SOURCE_RR, FIB_ENTRY_FLAG_NONE);
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
vxlan_gpe_refresh_output_feature_on_all_dest (void)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  vxlan_gpe_ioam_dest_tunnels_t *t;
  u32 i;
  if (pool_elts (hm->dst_tunnels) == 0)
    return;
  vxlan_gpe_clear_output_feature_on_all_intfs (hm->vlib_main);
  i = vec_len (hm->bool_ref_by_sw_if_index);
  vec_free (hm->bool_ref_by_sw_if_index);
  vec_validate_init_empty (hm->bool_ref_by_sw_if_index, i, ~0);
  pool_foreach (t, hm->dst_tunnels)
  {
    vxlan_gpe_enable_disable_ioam_for_dest
      (hm->vlib_main, t->dst_addr, t->outer_fib_index,
       (t->fp_proto == FIB_PROTOCOL_IP4), 1 /* is_add */ );
  }
  return;
}

void
vxlan_gpe_clear_output_feature_on_select_intfs (void)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  u32 sw_if_index0 = 0;
  for (sw_if_index0 = 0;
       sw_if_index0 < vec_len (hm->bool_ref_by_sw_if_index); sw_if_index0++)
    {
      if (hm->bool_ref_by_sw_if_index[sw_if_index0] == 0xFF)
	{
	  vxlan_gpe_set_clear_output_feature_on_intf
	    (hm->vlib_main, sw_if_index0, 0);
	}
    }

  return;
}

static clib_error_t *
vxlan_gpe_set_ioam_rewrite_command_fn (vlib_main_t *
				       vm,
				       unformat_input_t
				       * input, vlib_cli_command_t * cmd)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  ip46_address_t local, remote;
  u8 local_set = 0;
  u8 remote_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 vni;
  u8 vni_set = 0;
  u8 disable = 0;
  clib_error_t *rv = 0;
  vxlan4_gpe_tunnel_key_t key4;
  vxlan6_gpe_tunnel_key_t key6;
  uword *p;
  vxlan_gpe_main_t *gm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "local %U", unformat_ip4_address, &local.ip4))
	{
	  local_set = 1;
	  ipv4_set = 1;
	}
      else
	if (unformat (input, "remote %U", unformat_ip4_address, &remote.ip4))
	{
	  remote_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (input, "local %U", unformat_ip6_address, &local.ip6))
	{
	  local_set = 1;
	  ipv6_set = 1;
	}
      else
	if (unformat (input, "remote %U", unformat_ip6_address, &remote.ip6))
	{
	  remote_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (input, "vni %d", &vni))
	vni_set = 1;
      else if (unformat (input, "disable"))
	disable = 1;
      else
	break;
    }

  if (local_set == 0)
    return clib_error_return (0, "tunnel local address not specified");
  if (remote_set == 0)
    return clib_error_return (0, "tunnel remote address not specified");
  if (ipv4_set && ipv6_set)
    return clib_error_return (0, "both IPv4 and IPv6 addresses specified");
  if ((ipv4_set
       && memcmp (&local.ip4, &remote.ip4,
		  sizeof (local.ip4)) == 0) || (ipv6_set
						&&
						memcmp
						(&local.ip6,
						 &remote.ip6,
						 sizeof (local.ip6)) == 0))
    return clib_error_return (0, "src and dst addresses are identical");
  if (vni_set == 0)
    return clib_error_return (0, "vni not specified");
  if (!ipv6_set)
    {
      key4.local = local.ip4.as_u32;
      key4.remote = remote.ip4.as_u32;
      key4.vni = clib_host_to_net_u32 (vni << 8);
      key4.port = (u32) clib_host_to_net_u16 (UDP_DST_PORT_VXLAN_GPE);
      p = hash_get_mem (gm->vxlan4_gpe_tunnel_by_key, &key4);
    }
  else
    {
      key6.local.as_u64[0] = local.ip6.as_u64[0];
      key6.local.as_u64[1] = local.ip6.as_u64[1];
      key6.remote.as_u64[0] = remote.ip6.as_u64[0];
      key6.remote.as_u64[1] = remote.ip6.as_u64[1];
      key6.vni = clib_host_to_net_u32 (vni << 8);
      key6.port = (u32) clib_host_to_net_u16 (UDP_DST_PORT_VXLAN6_GPE);
      p = hash_get_mem (gm->vxlan6_gpe_tunnel_by_key, &key6);
    }

  if (!p)
    return clib_error_return (0, "VxLAN Tunnel not found");
  t = pool_elt_at_index (gm->tunnels, p[0]);
  if (!disable)
    {
      rv =
	vxlan_gpe_ioam_set (t, hm->has_trace_option,
			    hm->has_pot_option, hm->has_ppc_option, ipv6_set);
    }
  else
    {
      rv = vxlan_gpe_ioam_clear (t, 0, 0, 0, 0);
    }
  return rv;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vxlan_gpe_set_ioam_rewrite_cmd, static) = {
  .path = "set vxlan-gpe-ioam",
  .short_help = "set vxlan-gpe-ioam vxlan <src-ip> <dst_ip> <vnid> [disable]",
  .function = vxlan_gpe_set_ioam_rewrite_command_fn,
};
/* *INDENT-ON* */



clib_error_t *
vxlan_gpe_ioam_enable (int has_trace_option,
		       int has_pot_option, int has_ppc_option)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  hm->has_trace_option = has_trace_option;
  hm->has_pot_option = has_pot_option;
  hm->has_ppc_option = has_ppc_option;
  if (hm->has_trace_option)
    {
      vxlan_gpe_trace_profile_setup ();
    }

  return 0;
}

clib_error_t *
vxlan_gpe_ioam_disable (int
			has_trace_option,
			int has_pot_option, int has_ppc_option)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  hm->has_trace_option = has_trace_option;
  hm->has_pot_option = has_pot_option;
  hm->has_ppc_option = has_ppc_option;
  if (!hm->has_trace_option)
    {
      vxlan_gpe_trace_profile_cleanup ();
    }

  return 0;
}

void
vxlan_gpe_set_next_override (uword next)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  hm->decap_v4_next_override = next;
  return;
}

static clib_error_t *
vxlan_gpe_set_ioam_flags_command_fn (vlib_main_t * vm,
				     unformat_input_t
				     * input, vlib_cli_command_t * cmd)
{
  int has_trace_option = 0;
  int has_pot_option = 0;
  int has_ppc_option = 0;
  clib_error_t *rv = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace"))
	has_trace_option = 1;
      else if (unformat (input, "pot"))
	has_pot_option = 1;
      else if (unformat (input, "ppc encap"))
	has_ppc_option = PPC_ENCAP;
      else if (unformat (input, "ppc decap"))
	has_ppc_option = PPC_DECAP;
      else if (unformat (input, "ppc none"))
	has_ppc_option = PPC_NONE;
      else
	break;
    }


  rv =
    vxlan_gpe_ioam_enable (has_trace_option, has_pot_option, has_ppc_option);
  return rv;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vxlan_gpe_set_ioam_flags_cmd, static) =
{
.path = "set vxlan-gpe-ioam rewrite",
.short_help = "set vxlan-gpe-ioam [trace] [pot] [ppc <encap|decap>]",
.function = vxlan_gpe_set_ioam_flags_command_fn,};
/* *INDENT-ON* */


int vxlan_gpe_ioam_disable_for_dest
  (vlib_main_t * vm, ip46_address_t dst_addr, u32 outer_fib_index,
   u8 ipv4_set)
{
  vxlan_gpe_ioam_dest_tunnels_t *t;
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;

  vxlan_gpe_enable_disable_ioam_for_dest (hm->vlib_main,
					  dst_addr, outer_fib_index, ipv4_set,
					  0);
  if (pool_elts (hm->dst_tunnels) == 0)
    {
      vxlan_gpe_clear_output_feature_on_select_intfs ();
      return 0;
    }

  pool_foreach (t, hm->dst_tunnels)
  {
    vxlan_gpe_enable_disable_ioam_for_dest
      (hm->vlib_main,
       t->dst_addr,
       t->outer_fib_index,
       (t->fp_proto == FIB_PROTOCOL_IP4), 1 /* is_add */ );
  }
  vxlan_gpe_clear_output_feature_on_select_intfs ();
  return (0);

}

static clib_error_t *vxlan_gpe_set_ioam_transit_rewrite_command_fn
  (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
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
    return clib_error_return (0, "tunnel destination address not specified");
  if (ipv4_set && ipv6_set)
    return clib_error_return (0, "both IPv4 and IPv6 addresses specified");
  if (!disable)
    {
      vxlan_gpe_enable_disable_ioam_for_dest (hm->vlib_main,
					      dst_addr, outer_fib_index,
					      ipv4_set, 1);
    }
  else
    {
      vxlan_gpe_ioam_disable_for_dest
	(vm, dst_addr, outer_fib_index, ipv4_set);
    }
  return rv;
}

       /* *INDENT-OFF* */
VLIB_CLI_COMMAND (vxlan_gpe_set_ioam_transit_rewrite_cmd, static) = {
  .path = "set vxlan-gpe-ioam-transit",
  .short_help = "set vxlan-gpe-ioam-transit dst-ip <dst_ip> [outer-fib-index <outer_fib_index>] [disable]",
  .function = vxlan_gpe_set_ioam_transit_rewrite_command_fn,
};
/* *INDENT-ON* */

clib_error_t *clear_vxlan_gpe_ioam_rewrite_command_fn
  (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return (vxlan_gpe_ioam_disable (0, 0, 0));
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vxlan_gpe_clear_ioam_flags_cmd, static) =
{
.path = "clear vxlan-gpe-ioam rewrite",
.short_help = "clear vxlan-gpe-ioam rewrite",
.function = clear_vxlan_gpe_ioam_rewrite_command_fn,
};
/* *INDENT-ON* */


/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
vxlan_gpe_ioam_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  vxlan_gpe_refresh_output_feature_on_all_dest ();
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
vxlan_gpe_ioam_fib_node_get (fib_node_index_t index)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  return (&hm->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
vxlan_gpe_ioam_last_lock_gone (fib_node_t * node)
{
  ASSERT (0);
}


/*
 * Virtual function table registered by MPLS GRE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t vxlan_gpe_ioam_vft = {
  .fnv_get = vxlan_gpe_ioam_fib_node_get,
  .fnv_last_lock = vxlan_gpe_ioam_last_lock_gone,
  .fnv_back_walk = vxlan_gpe_ioam_back_walk,
};

void
vxlan_gpe_ioam_interface_init (void)
{
  vxlan_gpe_ioam_main_t *hm = &vxlan_gpe_ioam_main;
  hm->fib_entry_type = fib_node_register_new_type (&vxlan_gpe_ioam_vft);
  return;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
