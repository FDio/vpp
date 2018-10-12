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
/*
 * ip/ip6_forward.c: IP v6 forwarding
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_frag.h>
#include <vnet/ip/ip6_neighbor.h>
#include <vnet/ethernet/ethernet.h>	/* for ethernet_header_t */
#include <vnet/srp/srp.h>	/* for srp_hw_interface_class */
#include <vppinfra/cache.h>
#include <vnet/fib/fib_urpf_list.h>	/* for FIB uRPF check */
#include <vnet/fib/ip6_fib.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/classify_dpo.h>

#include <vppinfra/bihash_template.c>
#include <vnet/ip/ip6_forward.h>

/* Flag used by IOAM code. Classifier sets it pop-hop-by-hop checks it */
#define OI_DECAP   0x80000000

static void
ip6_add_interface_routes (vnet_main_t * vnm, u32 sw_if_index,
			  ip6_main_t * im, u32 fib_index,
			  ip_interface_address_t * a)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip6_address_t *address = ip_interface_address_get_address (lm, a);
  fib_prefix_t pfx = {
    .fp_len = a->address_length,
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_addr.ip6 = *address,
  };

  if (a->address_length < 128)
    {
      fib_table_entry_update_one_path (fib_index,
				       &pfx,
				       FIB_SOURCE_INTERFACE,
				       (FIB_ENTRY_FLAG_CONNECTED |
					FIB_ENTRY_FLAG_ATTACHED),
				       DPO_PROTO_IP6,
				       /* No next-hop address */
				       NULL, sw_if_index,
				       /* invalid FIB index */
				       ~0, 1,
				       /* no label stack */
				       NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }

  pfx.fp_len = 128;
  if (sw_if_index < vec_len (lm->classify_table_index_by_sw_if_index))
    {
      u32 classify_table_index =
	lm->classify_table_index_by_sw_if_index[sw_if_index];
      if (classify_table_index != (u32) ~ 0)
	{
	  dpo_id_t dpo = DPO_INVALID;

	  dpo_set (&dpo,
		   DPO_CLASSIFY,
		   DPO_PROTO_IP6,
		   classify_dpo_create (DPO_PROTO_IP6, classify_table_index));

	  fib_table_entry_special_dpo_add (fib_index,
					   &pfx,
					   FIB_SOURCE_CLASSIFY,
					   FIB_ENTRY_FLAG_NONE, &dpo);
	  dpo_reset (&dpo);
	}
    }

  fib_table_entry_update_one_path (fib_index, &pfx,
				   FIB_SOURCE_INTERFACE,
				   (FIB_ENTRY_FLAG_CONNECTED |
				    FIB_ENTRY_FLAG_LOCAL),
				   DPO_PROTO_IP6,
				   &pfx.fp_addr,
				   sw_if_index, ~0,
				   1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
}

static void
ip6_del_interface_routes (ip6_main_t * im,
			  u32 fib_index,
			  ip6_address_t * address, u32 address_length)
{
  fib_prefix_t pfx = {
    .fp_len = address_length,
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_addr.ip6 = *address,
  };

  if (pfx.fp_len < 128)
    {
      fib_table_entry_delete (fib_index, &pfx, FIB_SOURCE_INTERFACE);

    }

  pfx.fp_len = 128;
  fib_table_entry_delete (fib_index, &pfx, FIB_SOURCE_INTERFACE);
}

void
ip6_sw_interface_enable_disable (u32 sw_if_index, u32 is_enable)
{
  ip6_main_t *im = &ip6_main;

  vec_validate_init_empty (im->ip_enabled_by_sw_if_index, sw_if_index, 0);

  /*
   * enable/disable only on the 1<->0 transition
   */
  if (is_enable)
    {
      if (1 != ++im->ip_enabled_by_sw_if_index[sw_if_index])
	return;
    }
  else
    {
      /* The ref count is 0 when an address is removed from an interface that has
       * no address - this is not a ciritical error */
      if (0 == im->ip_enabled_by_sw_if_index[sw_if_index] ||
	  0 != --im->ip_enabled_by_sw_if_index[sw_if_index])
	return;
    }

  vnet_feature_enable_disable ("ip6-unicast", "ip6-not-enabled", sw_if_index,
			       !is_enable, 0, 0);

  vnet_feature_enable_disable ("ip6-multicast", "ip6-not-enabled",
			       sw_if_index, !is_enable, 0, 0);
}

/* get first interface address */
ip6_address_t *
ip6_interface_first_address (ip6_main_t * im, u32 sw_if_index)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip6_address_t *result = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */,
  ({
    ip6_address_t * a = ip_interface_address_get_address (lm, ia);
    result = a;
    break;
  }));
  /* *INDENT-ON* */
  return result;
}

clib_error_t *
ip6_add_del_interface_address (vlib_main_t * vm,
			       u32 sw_if_index,
			       ip6_address_t * address,
			       u32 address_length, u32 is_del)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  clib_error_t *error;
  u32 if_address_index;
  ip6_address_fib_t ip6_af, *addr_fib = 0;
  ip6_address_t ll_addr;

  /* local0 interface doesn't support IP addressing */
  if (sw_if_index == 0)
    {
      return
	clib_error_create ("local0 interface doesn't support IP addressing");
    }

  if (ip6_address_is_link_local_unicast (address))
    {
      if (address_length != 128)
	{
	  vnm->api_errno = VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH;
	  return
	    clib_error_create
	    ("prefix length of link-local address must be 128");
	}
      if (!is_del)
	{
	  return ip6_neighbor_set_link_local_address (vm, sw_if_index,
						      address);
	}
      else
	{
	  ll_addr = ip6_neighbor_get_link_local_address (sw_if_index);
	  if (ip6_address_is_equal (&ll_addr, address))
	    {
	      vnm->api_errno = VNET_API_ERROR_ADDRESS_NOT_DELETABLE;
	      return clib_error_create ("address not deletable");
	    }
	  else
	    {
	      vnm->api_errno = VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
	      return clib_error_create ("address not found");
	    }
	}
    }

  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  vec_validate (im->mfib_index_by_sw_if_index, sw_if_index);

  ip6_addr_fib_init (&ip6_af, address,
		     vec_elt (im->fib_index_by_sw_if_index, sw_if_index));
  vec_add1 (addr_fib, ip6_af);

  /* *INDENT-OFF* */
  if (!is_del)
    {
      /* When adding an address check that it does not conflict
         with an existing address on any interface in this table. */
      ip_interface_address_t *ia;
      vnet_sw_interface_t *sif;

      pool_foreach(sif, vnm->interface_main.sw_interfaces,
      ({
          if (im->fib_index_by_sw_if_index[sw_if_index] ==
              im->fib_index_by_sw_if_index[sif->sw_if_index])
            {
              foreach_ip_interface_address
                (&im->lookup_main, ia, sif->sw_if_index,
                 0 /* honor unnumbered */ ,
                 ({
                   ip6_address_t * x =
                     ip_interface_address_get_address
                     (&im->lookup_main, ia);
                   if (ip6_destination_matches_route
                       (im, address, x, ia->address_length) ||
                       ip6_destination_matches_route (im,
                                                      x,
                                                      address,
                                                      address_length))
                     {
                       vnm->api_errno = VNET_API_ERROR_DUPLICATE_IF_ADDRESS;
                       return
                         clib_error_create
                         ("failed to add %U which conflicts with %U for interface %U",
                          format_ip6_address_and_length, address,
                          address_length,
                          format_ip6_address_and_length, x,
                          ia->address_length,
                          format_vnet_sw_if_index_name, vnm,
                          sif->sw_if_index);
                     }
                 }));
            }
      }));
    }
  /* *INDENT-ON* */

  {
    uword elts_before = pool_elts (lm->if_address_pool);

    error = ip_interface_address_add_del
      (lm, sw_if_index, addr_fib, address_length, is_del, &if_address_index);
    if (error)
      goto done;

    /* Pool did not grow: add duplicate address. */
    if (elts_before == pool_elts (lm->if_address_pool))
      goto done;
  }

  ip6_sw_interface_enable_disable (sw_if_index, !is_del);

  if (is_del)
    ip6_del_interface_routes (im, ip6_af.fib_index, address, address_length);
  else
    ip6_add_interface_routes (vnm, sw_if_index,
			      im, ip6_af.fib_index,
			      pool_elt_at_index (lm->if_address_pool,
						 if_address_index));

  {
    ip6_add_del_interface_address_callback_t *cb;
    vec_foreach (cb, im->add_del_interface_address_callbacks)
      cb->function (im, cb->function_opaque, sw_if_index,
		    address, address_length, if_address_index, is_del);
  }

done:
  vec_free (addr_fib);
  return error;
}

clib_error_t *
ip6_sw_interface_admin_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  ip6_main_t *im = &ip6_main;
  ip_interface_address_t *ia;
  ip6_address_t *a;
  u32 is_admin_up, fib_index;

  /* Fill in lookup tables with default table (0). */
  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);

  vec_validate_init_empty (im->
			   lookup_main.if_address_pool_index_by_sw_if_index,
			   sw_if_index, ~0);

  is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  fib_index = vec_elt (im->fib_index_by_sw_if_index, sw_if_index);

  /* *INDENT-OFF* */
  foreach_ip_interface_address (&im->lookup_main, ia, sw_if_index,
                                0 /* honor unnumbered */,
  ({
    a = ip_interface_address_get_address (&im->lookup_main, ia);
    if (is_admin_up)
      ip6_add_interface_routes (vnm, sw_if_index,
				im, fib_index,
				ia);
    else
      ip6_del_interface_routes (im, fib_index,
				a, ia->address_length);
  }));
  /* *INDENT-ON* */

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ip6_sw_interface_admin_up_down);

/* Built-in ip6 unicast rx feature path definition */
/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ip6_unicast, static) =
{
  .arc_name  = "ip6-unicast",
  .start_nodes = VNET_FEATURES ("ip6-input"),
  .last_in_arc = "ip6-lookup",
  .arc_index_ptr = &ip6_main.lookup_main.ucast_feature_arc_index,
};

VNET_FEATURE_INIT (ip6_flow_classify, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-flow-classify",
  .runs_before = VNET_FEATURES ("ip6-inacl"),
};

VNET_FEATURE_INIT (ip6_inacl, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-inacl",
  .runs_before = VNET_FEATURES ("ip6-policer-classify"),
};

VNET_FEATURE_INIT (ip6_policer_classify, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-policer-classify",
  .runs_before = VNET_FEATURES ("ipsec6-input-feature"),
};

VNET_FEATURE_INIT (ip6_ipsec, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ipsec6-input-feature",
  .runs_before = VNET_FEATURES ("l2tp-decap"),
};

VNET_FEATURE_INIT (ip6_l2tp, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "l2tp-decap",
  .runs_before = VNET_FEATURES ("vpath-input-ip6"),
};

VNET_FEATURE_INIT (ip6_vpath, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "vpath-input-ip6",
  .runs_before = VNET_FEATURES ("ip6-vxlan-bypass"),
};

VNET_FEATURE_INIT (ip6_vxlan_bypass, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-vxlan-bypass",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

VNET_FEATURE_INIT (ip6_not_enabled, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-not-enabled",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};

VNET_FEATURE_INIT (ip6_lookup, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-lookup",
  .runs_before = 0,  /*last feature*/
};

/* Built-in ip6 multicast rx feature path definition (none now) */
VNET_FEATURE_ARC_INIT (ip6_multicast, static) =
{
  .arc_name  = "ip6-multicast",
  .start_nodes = VNET_FEATURES ("ip6-input"),
  .last_in_arc = "ip6-mfib-forward-lookup",
  .arc_index_ptr = &ip6_main.lookup_main.mcast_feature_arc_index,
};

VNET_FEATURE_INIT (ip6_vpath_mc, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "vpath-input-ip6",
  .runs_before = VNET_FEATURES ("ip6-mfib-forward-lookup"),
};

VNET_FEATURE_INIT (ip6_not_enabled_mc, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "ip6-not-enabled",
  .runs_before = VNET_FEATURES ("ip6-mfib-forward-lookup"),
};

VNET_FEATURE_INIT (ip6_mc_lookup, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "ip6-mfib-forward-lookup",
  .runs_before = 0, /* last feature */
};

/* Built-in ip4 tx feature path definition */
VNET_FEATURE_ARC_INIT (ip6_output, static) =
{
  .arc_name  = "ip6-output",
  .start_nodes = VNET_FEATURES ("ip6-rewrite", "ip6-midchain", "ip6-dvr-dpo"),
  .last_in_arc = "interface-output",
  .arc_index_ptr = &ip6_main.lookup_main.output_feature_arc_index,
};

VNET_FEATURE_INIT (ip6_outacl, static) = {
  .arc_name = "ip6-output",
  .node_name = "ip6-outacl",
  .runs_before = VNET_FEATURES ("ipsec6-output-feature"),
};

VNET_FEATURE_INIT (ip6_ipsec_output, static) = {
  .arc_name = "ip6-output",
  .node_name = "ipsec6-output-feature",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VNET_FEATURE_INIT (ip6_interface_output, static) = {
  .arc_name = "ip6-output",
  .node_name = "interface-output",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

clib_error_t *
ip6_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  ip6_main_t *im = &ip6_main;

  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  vec_validate (im->mfib_index_by_sw_if_index, sw_if_index);

  if (!is_add)
    {
      /* Ensure that IPv6 is disabled */
      ip6_main_t *im6 = &ip6_main;
      ip_lookup_main_t *lm6 = &im6->lookup_main;
      ip_interface_address_t *ia = 0;
      ip6_address_t *address;
      vlib_main_t *vm = vlib_get_main ();

      ip6_neighbor_sw_interface_add_del (vnm, sw_if_index, 0 /* is_add */ );
      vnet_sw_interface_update_unnumbered (sw_if_index, ~0, 0);
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 0,
      ({
        address = ip_interface_address_get_address (lm6, ia);
        ip6_add_del_interface_address(vm, sw_if_index, address, ia->address_length, 1);
      }));
      /* *INDENT-ON* */
      ip6_mfib_interface_enable_disable (sw_if_index, 0);
    }

  vnet_feature_enable_disable ("ip6-unicast", "ip6-not-enabled", sw_if_index,
			       is_add, 0, 0);

  vnet_feature_enable_disable ("ip6-multicast", "ip6-not-enabled",
			       sw_if_index, is_add, 0, 0);

  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip6_sw_interface_add_del);

static uword
ip6_lookup (vlib_main_t * vm,
	    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip6_lookup_inline (vm, node, frame);
}

static u8 *format_ip6_lookup_trace (u8 * s, va_list * args);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_lookup_node) =
{
  .function = ip6_lookup,
  .name = "ip6-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_lookup_trace,
  .n_next_nodes = IP6_LOOKUP_N_NEXT,
  .next_nodes = IP6_LOOKUP_NEXT_NODES,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_lookup_node, ip6_lookup);

static uword
ip6_load_balance (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_via_counters;
  u32 n_left_from, n_left_to_next, *from, *to_next;
  ip_lookup_next_t next;
  u32 thread_index = vm->thread_index;
  ip6_main_t *im = &ip6_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);


      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  ip_lookup_next_t next0, next1;
	  const load_balance_t *lb0, *lb1;
	  vlib_buffer_t *p0, *p1;
	  u32 pi0, lbi0, hc0, pi1, lbi1, hc1;
	  const ip6_header_t *ip0, *ip1;
	  const dpo_id_t *dpo0, *dpo1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, STORE);
	    vlib_prefetch_buffer_header (p3, STORE);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), STORE);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]), STORE);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);
	  lbi0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  lbi1 = vnet_buffer (p1)->ip.adj_index[VLIB_TX];

	  lb0 = load_balance_get (lbi0);
	  lb1 = load_balance_get (lbi1);

	  /*
	   * this node is for via FIBs we can re-use the hash value from the
	   * to node if present.
	   * We don't want to use the same hash value at each level in the recursion
	   * graph as that would lead to polarisation
	   */
	  hc0 = hc1 = 0;

	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      if (PREDICT_TRUE (vnet_buffer (p0)->ip.flow_hash))
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    vnet_buffer (p0)->ip.flow_hash >> 1;
		}
	      else
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    ip6_compute_flow_hash (ip0, lb0->lb_hash_config);
		}
	      dpo0 =
		load_balance_get_fwd_bucket (lb0,
					     (hc0 &
					      lb0->lb_n_buckets_minus_1));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }
	  if (PREDICT_FALSE (lb1->lb_n_buckets > 1))
	    {
	      if (PREDICT_TRUE (vnet_buffer (p1)->ip.flow_hash))
		{
		  hc1 = vnet_buffer (p1)->ip.flow_hash =
		    vnet_buffer (p1)->ip.flow_hash >> 1;
		}
	      else
		{
		  hc1 = vnet_buffer (p1)->ip.flow_hash =
		    ip6_compute_flow_hash (ip1, lb1->lb_hash_config);
		}
	      dpo1 =
		load_balance_get_fwd_bucket (lb1,
					     (hc1 &
					      lb1->lb_n_buckets_minus_1));
	    }
	  else
	    {
	      dpo1 = load_balance_get_bucket_i (lb1, 0);
	    }

	  next0 = dpo0->dpoi_next_node;
	  next1 = dpo1->dpoi_next_node;

	  /* Only process the HBH Option Header if explicitly configured to do so */
	  if (PREDICT_FALSE
	      (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      next0 = (dpo_is_adj (dpo0) && im->hbh_enabled) ?
		(ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next0;
	    }
	  /* Only process the HBH Option Header if explicitly configured to do so */
	  if (PREDICT_FALSE
	      (ip1->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      next1 = (dpo_is_adj (dpo1) && im->hbh_enabled) ?
		(ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next1;
	    }

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
	  vnet_buffer (p1)->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;

	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));
	  vlib_increment_combined_counter
	    (cm, thread_index, lbi1, 1, vlib_buffer_length_in_chain (vm, p1));

	  vlib_validate_buffer_enqueue_x2 (vm, node, next,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip_lookup_next_t next0;
	  const load_balance_t *lb0;
	  vlib_buffer_t *p0;
	  u32 pi0, lbi0, hc0;
	  const ip6_header_t *ip0;
	  const dpo_id_t *dpo0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);
	  lbi0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  lb0 = load_balance_get (lbi0);

	  hc0 = 0;
	  if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
	    {
	      if (PREDICT_TRUE (vnet_buffer (p0)->ip.flow_hash))
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    vnet_buffer (p0)->ip.flow_hash >> 1;
		}
	      else
		{
		  hc0 = vnet_buffer (p0)->ip.flow_hash =
		    ip6_compute_flow_hash (ip0, lb0->lb_hash_config);
		}
	      dpo0 =
		load_balance_get_fwd_bucket (lb0,
					     (hc0 &
					      lb0->lb_n_buckets_minus_1));
	    }
	  else
	    {
	      dpo0 = load_balance_get_bucket_i (lb0, 0);
	    }

	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

	  /* Only process the HBH Option Header if explicitly configured to do so */
	  if (PREDICT_FALSE
	      (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      next0 = (dpo_is_adj (dpo0) && im->hbh_enabled) ?
		(ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next0;
	    }

	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_load_balance_node) =
{
  .function = ip6_load_balance,
  .name = "ip6-load-balance",
  .vector_size = sizeof (u32),
  .sibling_of = "ip6-lookup",
  .format_trace = format_ip6_lookup_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_load_balance_node, ip6_load_balance);

typedef struct
{
  /* Adjacency taken. */
  u32 adj_index;
  u32 flow_hash;
  u32 fib_index;

  /* Packet data, possibly *after* rewrite. */
  u8 packet_data[128 - 1 * sizeof (u32)];
}
ip6_forward_next_trace_t;

u8 *
format_ip6_forward_next_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_forward_next_trace_t *t = va_arg (*args, ip6_forward_next_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U%U",
	      format_white_space, indent,
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static u8 *
format_ip6_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_forward_next_trace_t *t = va_arg (*args, ip6_forward_next_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "fib %d dpo-idx %d flow hash: 0x%08x",
	      t->fib_index, t->adj_index, t->flow_hash);
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return s;
}


static u8 *
format_ip6_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_forward_next_trace_t *t = va_arg (*args, ip6_forward_next_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "tx_sw_if_index %d adj-idx %d : %U flow hash: 0x%08x",
	      t->fib_index, t->adj_index, format_ip_adjacency,
	      t->adj_index, FORMAT_IP_ADJACENCY_NONE, t->flow_hash);
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_ip_adjacency_packet_data,
	      t->adj_index, t->packet_data, sizeof (t->packet_data));
  return s;
}

/* Common trace function for all ip6-forward next nodes. */
void
ip6_forward_next_trace (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame, vlib_rx_or_tx_t which_adj_index)
{
  u32 *from, n_left;
  ip6_main_t *im = &ip6_main;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      ip6_forward_next_trace_t *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

      bi0 = from[0];
      bi1 = from[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->adj_index = vnet_buffer (b0)->ip.adj_index[which_adj_index];
	  t0->flow_hash = vnet_buffer (b0)->ip.flow_hash;
	  t0->fib_index =
	    (vnet_buffer (b0)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b0)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b0)->sw_if_index[VLIB_RX]);

	  clib_memcpy_fast (t0->packet_data,
			    vlib_buffer_get_current (b0),
			    sizeof (t0->packet_data));
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->adj_index = vnet_buffer (b1)->ip.adj_index[which_adj_index];
	  t1->flow_hash = vnet_buffer (b1)->ip.flow_hash;
	  t1->fib_index =
	    (vnet_buffer (b1)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b1)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b1)->sw_if_index[VLIB_RX]);

	  clib_memcpy_fast (t1->packet_data,
			    vlib_buffer_get_current (b1),
			    sizeof (t1->packet_data));
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ip6_forward_next_trace_t *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->adj_index = vnet_buffer (b0)->ip.adj_index[which_adj_index];
	  t0->flow_hash = vnet_buffer (b0)->ip.flow_hash;
	  t0->fib_index =
	    (vnet_buffer (b0)->sw_if_index[VLIB_TX] !=
	     (u32) ~ 0) ? vnet_buffer (b0)->sw_if_index[VLIB_TX] :
	    vec_elt (im->fib_index_by_sw_if_index,
		     vnet_buffer (b0)->sw_if_index[VLIB_RX]);

	  clib_memcpy_fast (t0->packet_data,
			    vlib_buffer_get_current (b0),
			    sizeof (t0->packet_data));
	}
      from += 1;
      n_left -= 1;
    }
}

/* Compute TCP/UDP/ICMP6 checksum in software. */
u16
ip6_tcp_udp_icmp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
				   ip6_header_t * ip0, int *bogus_lengthp)
{
  ip_csum_t sum0;
  u16 sum16, payload_length_host_byte_order;
  u32 i, n_this_buffer, n_bytes_left;
  u32 headers_size = sizeof (ip0[0]);
  void *data_this_buffer;

  ASSERT (bogus_lengthp);
  *bogus_lengthp = 0;

  /* Initialize checksum with ip header. */
  sum0 = ip0->payload_length + clib_host_to_net_u16 (ip0->protocol);
  payload_length_host_byte_order = clib_net_to_host_u16 (ip0->payload_length);
  data_this_buffer = (void *) (ip0 + 1);

  for (i = 0; i < ARRAY_LEN (ip0->src_address.as_uword); i++)
    {
      sum0 = ip_csum_with_carry (sum0,
				 clib_mem_unaligned (&ip0->
						     src_address.as_uword[i],
						     uword));
      sum0 =
	ip_csum_with_carry (sum0,
			    clib_mem_unaligned (&ip0->dst_address.as_uword[i],
						uword));
    }

  /* some icmp packets may come with a "router alert" hop-by-hop extension header (e.g., mldv2 packets)
   * or UDP-Ping packets */
  if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
    {
      u32 skip_bytes;
      ip6_hop_by_hop_ext_t *ext_hdr =
	(ip6_hop_by_hop_ext_t *) data_this_buffer;

      /* validate really icmp6 next */
      ASSERT ((ext_hdr->next_hdr == IP_PROTOCOL_ICMP6)
	      || (ext_hdr->next_hdr == IP_PROTOCOL_UDP));

      skip_bytes = 8 * (1 + ext_hdr->n_data_u64s);
      data_this_buffer = (void *) ((u8 *) data_this_buffer + skip_bytes);

      payload_length_host_byte_order -= skip_bytes;
      headers_size += skip_bytes;
    }

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
  if (p0 && n_this_buffer + headers_size > p0->current_length)
    n_this_buffer =
      p0->current_length >
      headers_size ? p0->current_length - headers_size : 0;
  while (1)
    {
      sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      if (!(p0->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  *bogus_lengthp = 1;
	  return 0xfefe;
	}
      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = p0->current_length;
    }

  sum16 = ~ip_csum_fold (sum0);

  return sum16;
}

u32
ip6_tcp_udp_icmp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0)
{
  ip6_header_t *ip0 = vlib_buffer_get_current (p0);
  udp_header_t *udp0;
  u16 sum16;
  int bogus_length;

  /* some icmp packets may come with a "router alert" hop-by-hop extension header (e.g., mldv2 packets) */
  ASSERT (ip0->protocol == IP_PROTOCOL_TCP
	  || ip0->protocol == IP_PROTOCOL_ICMP6
	  || ip0->protocol == IP_PROTOCOL_UDP
	  || ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS);

  udp0 = (void *) (ip0 + 1);
  if (ip0->protocol == IP_PROTOCOL_UDP && udp0->checksum == 0)
    {
      p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
		    | VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
      return p0->flags;
    }

  sum16 = ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0, &bogus_length);

  p0->flags |= (VNET_BUFFER_F_L4_CHECKSUM_COMPUTED
		| ((sum16 == 0) << VNET_BUFFER_F_LOG2_L4_CHECKSUM_CORRECT));

  return p0->flags;
}

/**
 * @brief returns number of links on which src is reachable.
 */
always_inline int
ip6_urpf_loose_check (ip6_main_t * im, vlib_buffer_t * b, ip6_header_t * i)
{
  const load_balance_t *lb0;
  index_t lbi;
  u32 fib_index;

  fib_index = vec_elt (im->fib_index_by_sw_if_index,
		       vnet_buffer (b)->sw_if_index[VLIB_RX]);
  fib_index =
    (vnet_buffer (b)->sw_if_index[VLIB_TX] == (u32) ~ 0) ?
    fib_index : vnet_buffer (b)->sw_if_index[VLIB_TX];

  lbi = ip6_fib_table_fwding_lookup (im, fib_index, &i->src_address);
  lb0 = load_balance_get (lbi);

  return (fib_urpf_check_size (lb0->lb_urpf));
}

always_inline u8
ip6_next_proto_is_tcp_udp (vlib_buffer_t * p0, ip6_header_t * ip0,
			   u32 * udp_offset0)
{
  u32 proto0;
  proto0 = ip6_locate_header (p0, ip0, IP_PROTOCOL_UDP, udp_offset0);
  if (proto0 != IP_PROTOCOL_UDP)
    {
      proto0 = ip6_locate_header (p0, ip0, IP_PROTOCOL_TCP, udp_offset0);
      proto0 = (proto0 == IP_PROTOCOL_TCP) ? proto0 : 0;
    }
  return proto0;
}

/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (ip6_local) =
{
  .arc_name  = "ip6-local",
  .start_nodes = VNET_FEATURES ("ip6-local"),
};
/* *INDENT-ON* */

static uword
ip6_local_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * frame, int head_of_feature_arc)
{
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_local_next_t next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_input_node.index);
  u8 arc_index = vnet_feat_arc_ip6_local.feature_arc_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip0, *ip1;
	  udp_header_t *udp0, *udp1;
	  u32 pi0, ip_len0, udp_len0, flags0, next0;
	  u32 pi1, ip_len1, udp_len1, flags1, next1;
	  i32 len_diff0, len_diff1;
	  u8 error0, type0, good_l4_csum0, is_tcp_udp0;
	  u8 error1, type1, good_l4_csum1, is_tcp_udp1;
	  u32 udp_offset0, udp_offset1;

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  error0 = error1 = IP6_ERROR_UNKNOWN_PROTOCOL;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  if (head_of_feature_arc == 0)
	    goto skip_checks;

	  vnet_buffer (p0)->l3_hdr_offset = p0->current_data;
	  vnet_buffer (p1)->l3_hdr_offset = p1->current_data;

	  type0 = lm->builtin_protocol_by_ip_protocol[ip0->protocol];
	  type1 = lm->builtin_protocol_by_ip_protocol[ip1->protocol];

	  flags0 = p0->flags;
	  flags1 = p1->flags;

	  is_tcp_udp0 = ip6_next_proto_is_tcp_udp (p0, ip0, &udp_offset0);
	  is_tcp_udp1 = ip6_next_proto_is_tcp_udp (p1, ip1, &udp_offset1);

	  good_l4_csum0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT
			   || (flags0 & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM
			       || flags0 & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))
	    != 0;
	  good_l4_csum1 = (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT
			   || (flags1 & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM
			       || flags1 & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))
	    != 0;
	  len_diff0 = 0;
	  len_diff1 = 0;

	  if (PREDICT_TRUE (is_tcp_udp0))
	    {
	      udp0 = (udp_header_t *) ((u8 *) ip0 + udp_offset0);
	      /* Don't verify UDP checksum for packets with explicit zero checksum. */
	      good_l4_csum0 |= type0 == IP_BUILTIN_PROTOCOL_UDP
		&& udp0->checksum == 0;
	      /* Verify UDP length. */
	      if (is_tcp_udp0 == IP_PROTOCOL_UDP)
		{
		  ip_len0 = clib_net_to_host_u16 (ip0->payload_length);
		  udp_len0 = clib_net_to_host_u16 (udp0->length);
		  len_diff0 = ip_len0 - udp_len0;
		}
	    }
	  if (PREDICT_TRUE (is_tcp_udp1))
	    {
	      udp1 = (udp_header_t *) ((u8 *) ip1 + udp_offset1);
	      /* Don't verify UDP checksum for packets with explicit zero checksum. */
	      good_l4_csum1 |= type1 == IP_BUILTIN_PROTOCOL_UDP
		&& udp1->checksum == 0;
	      /* Verify UDP length. */
	      if (is_tcp_udp1 == IP_PROTOCOL_UDP)
		{
		  ip_len1 = clib_net_to_host_u16 (ip1->payload_length);
		  udp_len1 = clib_net_to_host_u16 (udp1->length);
		  len_diff1 = ip_len1 - udp_len1;
		}
	    }

	  good_l4_csum0 |= type0 == IP_BUILTIN_PROTOCOL_UNKNOWN;
	  good_l4_csum1 |= type1 == IP_BUILTIN_PROTOCOL_UNKNOWN;

	  len_diff0 = type0 == IP_BUILTIN_PROTOCOL_UDP ? len_diff0 : 0;
	  len_diff1 = type1 == IP_BUILTIN_PROTOCOL_UDP ? len_diff1 : 0;

	  if (PREDICT_FALSE (type0 != IP_BUILTIN_PROTOCOL_UNKNOWN
			     && !good_l4_csum0
			     && !(flags0 &
				  VNET_BUFFER_F_L4_CHECKSUM_COMPUTED)))
	    {
	      flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, p0);
	      good_l4_csum0 =
		(flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	    }
	  if (PREDICT_FALSE (type1 != IP_BUILTIN_PROTOCOL_UNKNOWN
			     && !good_l4_csum1
			     && !(flags1 &
				  VNET_BUFFER_F_L4_CHECKSUM_COMPUTED)))
	    {
	      flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, p1);
	      good_l4_csum1 =
		(flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	    }

	  error0 = error1 = IP6_ERROR_UNKNOWN_PROTOCOL;
	  error0 = len_diff0 < 0 ? IP6_ERROR_UDP_LENGTH : error0;
	  error1 = len_diff1 < 0 ? IP6_ERROR_UDP_LENGTH : error1;

	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_UDP ==
		  IP6_ERROR_UDP_CHECKSUM);
	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_ICMP ==
		  IP6_ERROR_ICMP_CHECKSUM);
	  error0 = (!good_l4_csum0 ? IP6_ERROR_UDP_CHECKSUM + type0 : error0);
	  error1 = (!good_l4_csum1 ? IP6_ERROR_UDP_CHECKSUM + type1 : error1);

	  /* Drop packets from unroutable hosts. */
	  /* If this is a neighbor solicitation (ICMP), skip source RPF check */
	  if (error0 == IP6_ERROR_UNKNOWN_PROTOCOL &&
	      type0 != IP_BUILTIN_PROTOCOL_ICMP &&
	      !ip6_address_is_link_local_unicast (&ip0->src_address))
	    {
	      error0 = (!ip6_urpf_loose_check (im, p0, ip0)
			? IP6_ERROR_SRC_LOOKUP_MISS : error0);
	    }
	  if (error1 == IP6_ERROR_UNKNOWN_PROTOCOL &&
	      type1 != IP_BUILTIN_PROTOCOL_ICMP &&
	      !ip6_address_is_link_local_unicast (&ip1->src_address))
	    {
	      error1 = (!ip6_urpf_loose_check (im, p1, ip1)
			? IP6_ERROR_SRC_LOOKUP_MISS : error1);
	    }

	  vnet_buffer (p0)->ip.fib_index =
	    vnet_buffer (p0)->sw_if_index[VLIB_TX] != ~0 ?
	    vnet_buffer (p0)->sw_if_index[VLIB_TX] :
	    vnet_buffer (p0)->ip.fib_index;

	  vnet_buffer (p1)->ip.fib_index =
	    vnet_buffer (p1)->sw_if_index[VLIB_TX] != ~0 ?
	    vnet_buffer (p1)->sw_if_index[VLIB_TX] :
	    vnet_buffer (p1)->ip.fib_index;

	skip_checks:

	  next0 = lm->local_next_by_ip_protocol[ip0->protocol];
	  next1 = lm->local_next_by_ip_protocol[ip1->protocol];

	  next0 =
	    error0 != IP6_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;
	  next1 =
	    error1 != IP6_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next1;

	  p0->error = error_node->errors[error0];
	  p1->error = error_node->errors[error1];

	  if (head_of_feature_arc)
	    {
	      if (PREDICT_TRUE (error0 == (u8) IP6_ERROR_UNKNOWN_PROTOCOL))
		vnet_feature_arc_start (arc_index,
					vnet_buffer (p0)->sw_if_index
					[VLIB_RX], &next0, p0);
	      if (PREDICT_TRUE (error1 == (u8) IP6_ERROR_UNKNOWN_PROTOCOL))
		vnet_feature_arc_start (arc_index,
					vnet_buffer (p1)->sw_if_index
					[VLIB_RX], &next1, p1);
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  udp_header_t *udp0;
	  u32 pi0, ip_len0, udp_len0, flags0, next0;
	  i32 len_diff0;
	  u8 error0, type0, good_l4_csum0;
	  u32 udp_offset0;
	  u8 is_tcp_udp0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  error0 = IP6_ERROR_UNKNOWN_PROTOCOL;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);

	  if (head_of_feature_arc == 0)
	    goto skip_check;

	  vnet_buffer (p0)->l3_hdr_offset = p0->current_data;

	  type0 = lm->builtin_protocol_by_ip_protocol[ip0->protocol];
	  flags0 = p0->flags;
	  is_tcp_udp0 = ip6_next_proto_is_tcp_udp (p0, ip0, &udp_offset0);
	  good_l4_csum0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT
			   || (flags0 & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM
			       || flags0 & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))
	    != 0;

	  len_diff0 = 0;
	  if (PREDICT_TRUE (is_tcp_udp0))
	    {
	      udp0 = (udp_header_t *) ((u8 *) ip0 + udp_offset0);
	      /* Don't verify UDP checksum for packets with explicit zero
	       * checksum. */
	      good_l4_csum0 |= type0 == IP_BUILTIN_PROTOCOL_UDP
		&& udp0->checksum == 0;
	      /* Verify UDP length. */
	      if (is_tcp_udp0 == IP_PROTOCOL_UDP)
		{
		  ip_len0 = clib_net_to_host_u16 (ip0->payload_length);
		  udp_len0 = clib_net_to_host_u16 (udp0->length);
		  len_diff0 = ip_len0 - udp_len0;
		}
	    }

	  good_l4_csum0 |= type0 == IP_BUILTIN_PROTOCOL_UNKNOWN;
	  len_diff0 = type0 == IP_BUILTIN_PROTOCOL_UDP ? len_diff0 : 0;

	  if (PREDICT_FALSE (type0 != IP_BUILTIN_PROTOCOL_UNKNOWN
			     && !good_l4_csum0
			     && !(flags0 &
				  VNET_BUFFER_F_L4_CHECKSUM_COMPUTED)))
	    {
	      flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, p0);
	      good_l4_csum0 =
		(flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	    }

	  error0 = IP6_ERROR_UNKNOWN_PROTOCOL;
	  error0 = len_diff0 < 0 ? IP6_ERROR_UDP_LENGTH : error0;

	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_UDP ==
		  IP6_ERROR_UDP_CHECKSUM);
	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_ICMP ==
		  IP6_ERROR_ICMP_CHECKSUM);
	  error0 = (!good_l4_csum0 ? IP6_ERROR_UDP_CHECKSUM + type0 : error0);

	  /* If this is a neighbor solicitation (ICMP), skip src RPF check */
	  if (error0 == IP6_ERROR_UNKNOWN_PROTOCOL &&
	      type0 != IP_BUILTIN_PROTOCOL_ICMP &&
	      !ip6_address_is_link_local_unicast (&ip0->src_address))
	    {
	      error0 = (!ip6_urpf_loose_check (im, p0, ip0)
			? IP6_ERROR_SRC_LOOKUP_MISS : error0);
	    }

	  vnet_buffer (p0)->ip.fib_index =
	    vnet_buffer (p0)->sw_if_index[VLIB_TX] != ~0 ?
	    vnet_buffer (p0)->sw_if_index[VLIB_TX] :
	    vnet_buffer (p0)->ip.fib_index;

	skip_check:

	  next0 = lm->local_next_by_ip_protocol[ip0->protocol];
	  next0 =
	    error0 != IP6_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;

	  p0->error = error_node->errors[error0];

	  if (head_of_feature_arc)
	    {
	      if (PREDICT_TRUE (error0 == (u8) IP6_ERROR_UNKNOWN_PROTOCOL))
		vnet_feature_arc_start (arc_index,
					vnet_buffer (p0)->sw_if_index
					[VLIB_RX], &next0, p0);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
ip6_local (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip6_local_inline (vm, node, frame, 1 /* head of feature arc */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_local_node, static) =
{
  .function = ip6_local,
  .name = "ip6-local",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .n_next_nodes = IP_LOCAL_N_NEXT,
  .next_nodes =
  {
    [IP_LOCAL_NEXT_DROP] = "ip6-drop",
    [IP_LOCAL_NEXT_PUNT] = "ip6-punt",
    [IP_LOCAL_NEXT_UDP_LOOKUP] = "ip6-udp-lookup",
    [IP_LOCAL_NEXT_ICMP] = "ip6-icmp-input",
    [IP_LOCAL_NEXT_REASSEMBLY] = "ip6-reassembly",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_local_node, ip6_local);


static uword
ip6_local_end_of_arc (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip6_local_inline (vm, node, frame, 0 /* head of feature arc */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_local_end_of_arc_node,static) = {
  .function = ip6_local_end_of_arc,
  .name = "ip6-local-end-of-arc",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_forward_next_trace,
  .sibling_of = "ip6-local",
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_local_end_of_arc_node, ip6_local_end_of_arc)

VNET_FEATURE_INIT (ip6_local_end_of_arc, static) = {
  .arc_name = "ip6-local",
  .node_name = "ip6-local-end-of-arc",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

void
ip6_register_protocol (u32 protocol, u32 node_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  ASSERT (protocol < ARRAY_LEN (lm->local_next_by_ip_protocol));
  lm->local_next_by_ip_protocol[protocol] =
    vlib_node_add_next (vm, ip6_local_node.index, node_index);
}

clib_error_t *
ip6_probe_neighbor (vlib_main_t * vm, ip6_address_t * dst, u32 sw_if_index,
		    u8 refresh)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip6_main_t *im = &ip6_main;
  icmp6_neighbor_solicitation_header_t *h;
  ip6_address_t *src;
  ip_interface_address_t *ia;
  ip_adjacency_t *adj;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  vlib_buffer_t *b;
  adj_index_t ai;
  u32 bi = 0;
  int bogus_length;

  si = vnet_get_sw_interface (vnm, sw_if_index);

  if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
      return clib_error_return (0, "%U: interface %U down",
				format_ip6_address, dst,
				format_vnet_sw_if_index_name, vnm,
				sw_if_index);
    }

  src =
    ip6_interface_address_matching_destination (im, dst, sw_if_index, &ia);
  if (!src)
    {
      vnm->api_errno = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      return clib_error_return
	(0, "no matching interface address for destination %U (interface %U)",
	 format_ip6_address, dst,
	 format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

  h =
    vlib_packet_template_get_packet (vm,
				     &im->discover_neighbor_packet_template,
				     &bi);
  if (!h)
    return clib_error_return (0, "ICMP6 NS packet allocation failed");

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  /* Destination address is a solicited node multicast address.  We need to fill in
     the low 24 bits with low 24 bits of target's address. */
  h->ip.dst_address.as_u8[13] = dst->as_u8[13];
  h->ip.dst_address.as_u8[14] = dst->as_u8[14];
  h->ip.dst_address.as_u8[15] = dst->as_u8[15];

  h->ip.src_address = src[0];
  h->neighbor.target_address = dst[0];

  if (PREDICT_FALSE (!hi->hw_address))
    {
      return clib_error_return (0, "%U: interface %U do not support ip probe",
				format_ip6_address, dst,
				format_vnet_sw_if_index_name, vnm,
				sw_if_index);
    }

  clib_memcpy_fast (h->link_layer_option.ethernet_address, hi->hw_address,
		    vec_len (hi->hw_address));

  h->neighbor.icmp.checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h->ip, &bogus_length);
  ASSERT (bogus_length == 0);

  b = vlib_get_buffer (vm, bi);
  vnet_buffer (b)->sw_if_index[VLIB_RX] =
    vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  /* Add encapsulation string for software interface (e.g. ethernet header). */
  ip46_address_t nh = {
    .ip6 = *dst,
  };

  ai = adj_nbr_add_or_lock (FIB_PROTOCOL_IP6,
			    VNET_LINK_IP6, &nh, sw_if_index);
  adj = adj_get (ai);

  /* Peer has been previously resolved, retrieve glean adj instead */
  if (adj->lookup_next_index == IP_LOOKUP_NEXT_REWRITE && refresh == 0)
    {
      adj_unlock (ai);
      ai = adj_glean_add_or_lock (FIB_PROTOCOL_IP6,
				  VNET_LINK_IP6, sw_if_index, &nh);
      adj = adj_get (ai);
    }

  vnet_rewrite_one_header (adj[0], h, sizeof (ethernet_header_t));
  vlib_buffer_advance (b, -adj->rewrite_header.data_bytes);

  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, hi->output_node_index);
    u32 *to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, hi->output_node_index, f);
  }

  adj_unlock (ai);
  return /* no error */ 0;
}

typedef enum
{
  IP6_REWRITE_NEXT_DROP,
  IP6_REWRITE_NEXT_ICMP_ERROR,
  IP6_REWRITE_NEXT_FRAGMENT,
  IP6_REWRITE_N_NEXT		/* Last */
} ip6_rewrite_next_t;

/**
 * This bits of an IPv6 address to mask to construct a multicast
 * MAC address
 */
#define IP6_MCAST_ADDR_MASK 0xffffffff

always_inline void
ip6_mtu_check (vlib_buffer_t * b, u16 packet_bytes,
	       u16 adj_packet_bytes, bool is_locally_generated,
	       u32 * next, u32 * error)
{
  if (adj_packet_bytes >= 1280 && packet_bytes > adj_packet_bytes)
    {
      if (is_locally_generated)
	{
	  /* IP fragmentation */
	  ip_frag_set_vnet_buffer (b, adj_packet_bytes,
				   IP6_FRAG_NEXT_IP6_REWRITE, 0);
	  *next = IP6_REWRITE_NEXT_FRAGMENT;
	  *error = IP6_ERROR_MTU_EXCEEDED;
	}
      else
	{
	  *error = IP6_ERROR_MTU_EXCEEDED;
	  icmp6_error_set_vnet_buffer (b, ICMP6_packet_too_big, 0,
				       adj_packet_bytes);
	  *next = IP6_REWRITE_NEXT_ICMP_ERROR;
	}
    }
}

always_inline uword
ip6_rewrite_inline_with_gso (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame,
			     int do_counters, int is_midchain, int is_mcast,
			     int do_gso)
{
  ip_lookup_main_t *lm = &ip6_main.lookup_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_input_node.index);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  ip_adjacency_t *adj0, *adj1;
	  vlib_buffer_t *p0, *p1;
	  ip6_header_t *ip0, *ip1;
	  u32 pi0, rw_len0, next0, error0, adj_index0;
	  u32 pi1, rw_len1, next1, error1, adj_index1;
	  u32 tx_sw_if_index0, tx_sw_if_index1;
	  bool is_locally_originated0, is_locally_originated1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->pre_data, 32, STORE);
	    CLIB_PREFETCH (p3->pre_data, 32, STORE);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), STORE);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]), STORE);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  adj_index1 = vnet_buffer (p1)->ip.adj_index[VLIB_TX];

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  error0 = error1 = IP6_ERROR_NONE;
	  next0 = next1 = IP6_REWRITE_NEXT_DROP;

	  is_locally_originated0 =
	    p0->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  if (PREDICT_TRUE (!is_locally_originated0))
	    {
	      i32 hop_limit0 = ip0->hop_limit;

	      /* Input node should have reject packets with hop limit 0. */
	      ASSERT (ip0->hop_limit > 0);

	      hop_limit0 -= 1;

	      ip0->hop_limit = hop_limit0;

	      /*
	       * If the hop count drops below 1 when forwarding, generate
	       * an ICMP response.
	       */
	      if (PREDICT_FALSE (hop_limit0 <= 0))
		{
		  error0 = IP6_ERROR_TIME_EXPIRED;
		  next0 = IP6_REWRITE_NEXT_ICMP_ERROR;
		  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
					       ICMP6_time_exceeded_ttl_exceeded_in_transit,
					       0);
		}
	    }
	  else
	    {
	      p0->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }
	  is_locally_originated1 =
	    p1->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  if (PREDICT_TRUE (!is_locally_originated1))
	    {
	      i32 hop_limit1 = ip1->hop_limit;

	      /* Input node should have reject packets with hop limit 0. */
	      ASSERT (ip1->hop_limit > 0);

	      hop_limit1 -= 1;

	      ip1->hop_limit = hop_limit1;

	      /*
	       * If the hop count drops below 1 when forwarding, generate
	       * an ICMP response.
	       */
	      if (PREDICT_FALSE (hop_limit1 <= 0))
		{
		  error1 = IP6_ERROR_TIME_EXPIRED;
		  next1 = IP6_REWRITE_NEXT_ICMP_ERROR;
		  vnet_buffer (p1)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp6_error_set_vnet_buffer (p1, ICMP6_time_exceeded,
					       ICMP6_time_exceeded_ttl_exceeded_in_transit,
					       0);
		}
	    }
	  else
	    {
	      p1->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }
	  adj0 = adj_get (adj_index0);
	  adj1 = adj_get (adj_index1);

	  rw_len0 = adj0[0].rewrite_header.data_bytes;
	  rw_len1 = adj1[0].rewrite_header.data_bytes;
	  vnet_buffer (p0)->ip.save_rewrite_length = rw_len0;
	  vnet_buffer (p1)->ip.save_rewrite_length = rw_len1;

	  if (do_counters)
	    {
	      vlib_increment_combined_counter
		(&adjacency_counters,
		 thread_index, adj_index0, 1,
		 vlib_buffer_length_in_chain (vm, p0) + rw_len0);
	      vlib_increment_combined_counter
		(&adjacency_counters,
		 thread_index, adj_index1, 1,
		 vlib_buffer_length_in_chain (vm, p1) + rw_len1);
	    }

	  /* Check MTU of outgoing interface. */
	  u16 ip0_len = ((do_gso && (p0->flags & VNET_BUFFER_F_GSO))
			 ? (vnet_buffer2 (p0)->gso_size +
			    sizeof (ip6_header_t))
			 : (clib_net_to_host_u16 (ip0->payload_length) +
			    sizeof (ip6_header_t)));
	  u16 ip1_len = ((do_gso && (p1->flags & VNET_BUFFER_F_GSO))
			 ? (vnet_buffer2 (p1)->gso_size +
			    sizeof (ip6_header_t))
			 : (clib_net_to_host_u16 (ip1->payload_length) +
			    sizeof (ip6_header_t)));

	  ip6_mtu_check (p0, ip0_len,
			 adj0[0].rewrite_header.max_l3_packet_bytes,
			 is_locally_originated0, &next0, &error0);
	  ip6_mtu_check (p1, ip1_len,
			 adj1[0].rewrite_header.max_l3_packet_bytes,
			 is_locally_originated1, &next1, &error1);

	  /* Don't adjust the buffer for hop count issue; icmp-error node
	   * wants to see the IP headerr */
	  if (PREDICT_TRUE (error0 == IP6_ERROR_NONE))
	    {
	      p0->current_data -= rw_len0;
	      p0->current_length += rw_len0;

	      tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;
	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;
	      next0 = adj0[0].rewrite_header.next_index;

	      if (PREDICT_FALSE
		  (adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
		vnet_feature_arc_start (lm->output_feature_arc_index,
					tx_sw_if_index0, &next0, p0);
	    }
	  if (PREDICT_TRUE (error1 == IP6_ERROR_NONE))
	    {
	      p1->current_data -= rw_len1;
	      p1->current_length += rw_len1;

	      tx_sw_if_index1 = adj1[0].rewrite_header.sw_if_index;
	      vnet_buffer (p1)->sw_if_index[VLIB_TX] = tx_sw_if_index1;
	      next1 = adj1[0].rewrite_header.next_index;

	      if (PREDICT_FALSE
		  (adj1[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
		vnet_feature_arc_start (lm->output_feature_arc_index,
					tx_sw_if_index1, &next1, p1);
	    }

	  /* Guess we are only writing on simple Ethernet header. */
	  vnet_rewrite_two_headers (adj0[0], adj1[0],
				    ip0, ip1, sizeof (ethernet_header_t));

	  if (is_midchain)
	    {
	      adj0->sub_type.midchain.fixup_func
		(vm, adj0, p0, adj0->sub_type.midchain.fixup_data);
	      adj1->sub_type.midchain.fixup_func
		(vm, adj1, p1, adj1->sub_type.midchain.fixup_data);
	    }
	  if (is_mcast)
	    {
	      /*
	       * copy bytes from the IP address into the MAC rewrite
	       */
	      vnet_ip_mcast_fixup_header (IP6_MCAST_ADDR_MASK,
					  adj0->
					  rewrite_header.dst_mcast_offset,
					  &ip0->dst_address.as_u32[3],
					  (u8 *) ip0);
	      vnet_ip_mcast_fixup_header (IP6_MCAST_ADDR_MASK,
					  adj1->
					  rewrite_header.dst_mcast_offset,
					  &ip1->dst_address.as_u32[3],
					  (u8 *) ip1);
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip_adjacency_t *adj0;
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  u32 pi0, rw_len0;
	  u32 adj_index0, next0, error0;
	  u32 tx_sw_if_index0;
	  bool is_locally_originated0;

	  pi0 = to_next[0] = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  adj0 = adj_get (adj_index0);

	  ip0 = vlib_buffer_get_current (p0);

	  error0 = IP6_ERROR_NONE;
	  next0 = IP6_REWRITE_NEXT_DROP;

	  /* Check hop limit */
	  is_locally_originated0 =
	    p0->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  if (PREDICT_TRUE (!is_locally_originated0))
	    {
	      i32 hop_limit0 = ip0->hop_limit;

	      ASSERT (ip0->hop_limit > 0);

	      hop_limit0 -= 1;

	      ip0->hop_limit = hop_limit0;

	      if (PREDICT_FALSE (hop_limit0 <= 0))
		{
		  /*
		   * If the hop count drops below 1 when forwarding, generate
		   * an ICMP response.
		   */
		  error0 = IP6_ERROR_TIME_EXPIRED;
		  next0 = IP6_REWRITE_NEXT_ICMP_ERROR;
		  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		  icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
					       ICMP6_time_exceeded_ttl_exceeded_in_transit,
					       0);
		}
	    }
	  else
	    {
	      p0->flags &= ~VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }

	  /* Guess we are only writing on simple Ethernet header. */
	  vnet_rewrite_one_header (adj0[0], ip0, sizeof (ethernet_header_t));

	  /* Update packet buffer attributes/set output interface. */
	  rw_len0 = adj0[0].rewrite_header.data_bytes;
	  vnet_buffer (p0)->ip.save_rewrite_length = rw_len0;

	  if (do_counters)
	    {
	      vlib_increment_combined_counter
		(&adjacency_counters,
		 thread_index, adj_index0, 1,
		 vlib_buffer_length_in_chain (vm, p0) + rw_len0);
	    }

	  /* Check MTU of outgoing interface. */
	  u16 ip0_len = ((do_gso && (p0->flags & VNET_BUFFER_F_GSO))
			 ? (vnet_buffer2 (p0)->gso_size +
			    sizeof (ip6_header_t))
			 : (clib_net_to_host_u16 (ip0->payload_length) +
			    sizeof (ip6_header_t)));
	  ip6_mtu_check (p0, ip0_len,
			 adj0[0].rewrite_header.max_l3_packet_bytes,
			 is_locally_originated0, &next0, &error0);

	  /* Don't adjust the buffer for hop count issue; icmp-error node
	   * wants to see the IP header */
	  if (PREDICT_TRUE (error0 == IP6_ERROR_NONE))
	    {
	      p0->current_data -= rw_len0;
	      p0->current_length += rw_len0;

	      tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;

	      vnet_buffer (p0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;
	      next0 = adj0[0].rewrite_header.next_index;

	      if (PREDICT_FALSE
		  (adj0[0].rewrite_header.flags & VNET_REWRITE_HAS_FEATURES))
		vnet_feature_arc_start (lm->output_feature_arc_index,
					tx_sw_if_index0, &next0, p0);
	    }

	  if (is_midchain)
	    {
	      adj0->sub_type.midchain.fixup_func
		(vm, adj0, p0, adj0->sub_type.midchain.fixup_data);
	    }
	  if (is_mcast)
	    {
	      vnet_ip_mcast_fixup_header (IP6_MCAST_ADDR_MASK,
					  adj0->
					  rewrite_header.dst_mcast_offset,
					  &ip0->dst_address.as_u32[3],
					  (u8 *) ip0);
	    }

	  p0->error = error_node->errors[error0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Need to do trace after rewrites to pick up new packet data. */
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

always_inline uword
ip6_rewrite_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    int do_counters, int is_midchain, int is_mcast)
{
  vnet_main_t *vnm = vnet_get_main ();
  if (PREDICT_FALSE (vnm->interface_main.gso_interface_count > 0))
    return ip6_rewrite_inline_with_gso (vm, node, frame, do_counters,
					is_midchain, is_mcast,
					1 /* do_gso */ );
  else
    return ip6_rewrite_inline_with_gso (vm, node, frame, do_counters,
					is_midchain, is_mcast,
					0 /* no do_gso */ );

}

static uword
ip6_rewrite (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip6_rewrite_inline (vm, node, frame, 1, 0, 0);
  else
    return ip6_rewrite_inline (vm, node, frame, 0, 0, 0);
}

static uword
ip6_rewrite_bcast (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip6_rewrite_inline (vm, node, frame, 1, 0, 0);
  else
    return ip6_rewrite_inline (vm, node, frame, 0, 0, 0);
}

static uword
ip6_rewrite_mcast (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip6_rewrite_inline (vm, node, frame, 1, 0, 1);
  else
    return ip6_rewrite_inline (vm, node, frame, 0, 0, 1);
}

static uword
ip6_midchain (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip6_rewrite_inline (vm, node, frame, 1, 1, 0);
  else
    return ip6_rewrite_inline (vm, node, frame, 0, 1, 0);
}

static uword
ip6_mcast_midchain (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
    return ip6_rewrite_inline (vm, node, frame, 1, 1, 1);
  else
    return ip6_rewrite_inline (vm, node, frame, 0, 1, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_midchain_node) =
{
  .function = ip6_midchain,
  .name = "ip6-midchain",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_forward_next_trace,
  .sibling_of = "ip6-rewrite",
  };

VLIB_NODE_FUNCTION_MULTIARCH (ip6_midchain_node, ip6_midchain);

VLIB_REGISTER_NODE (ip6_rewrite_node) =
{
  .function = ip6_rewrite,
  .name = "ip6-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_rewrite_trace,
  .n_next_nodes = IP6_REWRITE_N_NEXT,
  .next_nodes =
  {
    [IP6_REWRITE_NEXT_DROP] = "ip6-drop",
    [IP6_REWRITE_NEXT_ICMP_ERROR] = "ip6-icmp-error",
    [IP6_REWRITE_NEXT_FRAGMENT] = "ip6-frag",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_rewrite_node, ip6_rewrite);

VLIB_REGISTER_NODE (ip6_rewrite_bcast_node) = {
  .function = ip6_rewrite_bcast,
  .name = "ip6-rewrite-bcast",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_rewrite_trace,
  .sibling_of = "ip6-rewrite",
};
VLIB_NODE_FUNCTION_MULTIARCH (ip6_rewrite_bcast_node, ip6_rewrite_bcast)

VLIB_REGISTER_NODE (ip6_rewrite_mcast_node) =
{
  .function = ip6_rewrite_mcast,
  .name = "ip6-rewrite-mcast",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_rewrite_trace,
  .sibling_of = "ip6-rewrite",
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_rewrite_mcast_node, ip6_rewrite_mcast);

VLIB_REGISTER_NODE (ip6_mcast_midchain_node, static) =
{
  .function = ip6_mcast_midchain,
  .name = "ip6-mcast-midchain",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_rewrite_trace,
  .sibling_of = "ip6-rewrite",
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_mcast_midchain_node, ip6_mcast_midchain);
/* *INDENT-ON* */

/*
 * Hop-by-Hop handling
 */
ip6_hop_by_hop_main_t ip6_hop_by_hop_main;

#define foreach_ip6_hop_by_hop_error \
_(PROCESSED, "pkts with ip6 hop-by-hop options") \
_(FORMAT, "incorrectly formatted hop-by-hop options") \
_(UNKNOWN_OPTION, "unknown ip6 hop-by-hop options")

/* *INDENT-OFF* */
typedef enum
{
#define _(sym,str) IP6_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_hop_by_hop_error
#undef _
  IP6_HOP_BY_HOP_N_ERROR,
} ip6_hop_by_hop_error_t;
/* *INDENT-ON* */

/*
 * Primary h-b-h handler trace support
 * We work pretty hard on the problem for obvious reasons
 */
typedef struct
{
  u32 next_index;
  u32 trace_len;
  u8 option_data[256];
} ip6_hop_by_hop_trace_t;

vlib_node_registration_t ip6_hop_by_hop_node;

static char *ip6_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_hop_by_hop_error
#undef _
};

u8 *
format_ip6_hop_by_hop_ext_hdr (u8 * s, va_list * args)
{
  ip6_hop_by_hop_header_t *hbh0 = va_arg (*args, ip6_hop_by_hop_header_t *);
  int total_len = va_arg (*args, int);
  ip6_hop_by_hop_option_t *opt0, *limit0;
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  u8 type0;

  s = format (s, "IP6_HOP_BY_HOP: next protocol %d len %d total %d",
	      hbh0->protocol, (hbh0->length + 1) << 3, total_len);

  opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
  limit0 = (ip6_hop_by_hop_option_t *) ((u8 *) hbh0 + total_len);

  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad, just stop */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *) opt0 + 1);
	  break;

	default:
	  if (hm->trace[type0])
	    {
	      s = (*hm->trace[type0]) (s, opt0);
	    }
	  else
	    {
	      s =
		format (s, "\n    unrecognized option %d length %d", type0,
			opt0->length);
	    }
	  opt0 =
	    (ip6_hop_by_hop_option_t *) (((u8 *) opt0) + opt0->length +
					 sizeof (ip6_hop_by_hop_option_t));
	  break;
	}
    }
  return s;
}

static u8 *
format_ip6_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_hop_by_hop_trace_t *t = va_arg (*args, ip6_hop_by_hop_trace_t *);
  ip6_hop_by_hop_header_t *hbh0;
  ip6_hop_by_hop_option_t *opt0, *limit0;
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;

  u8 type0;

  hbh0 = (ip6_hop_by_hop_header_t *) t->option_data;

  s = format (s, "IP6_HOP_BY_HOP: next index %d len %d traced %d",
	      t->next_index, (hbh0->length + 1) << 3, t->trace_len);

  opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
  limit0 = (ip6_hop_by_hop_option_t *) ((u8 *) hbh0) + t->trace_len;

  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad, just stop */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *) opt0) + 1;
	  break;

	default:
	  if (hm->trace[type0])
	    {
	      s = (*hm->trace[type0]) (s, opt0);
	    }
	  else
	    {
	      s =
		format (s, "\n    unrecognized option %d length %d", type0,
			opt0->length);
	    }
	  opt0 =
	    (ip6_hop_by_hop_option_t *) (((u8 *) opt0) + opt0->length +
					 sizeof (ip6_hop_by_hop_option_t));
	  break;
	}
    }
  return s;
}

always_inline u8
ip6_scan_hbh_options (vlib_buffer_t * b0,
		      ip6_header_t * ip0,
		      ip6_hop_by_hop_header_t * hbh0,
		      ip6_hop_by_hop_option_t * opt0,
		      ip6_hop_by_hop_option_t * limit0, u32 * next0)
{
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  u8 type0;
  u8 error0 = 0;

  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0:		/* Pad1 */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *) opt0) + 1;
	  continue;
	case 1:		/* PadN */
	  break;
	default:
	  if (hm->options[type0])
	    {
	      if ((*hm->options[type0]) (b0, ip0, opt0) < 0)
		{
		  error0 = IP6_HOP_BY_HOP_ERROR_FORMAT;
		  return (error0);
		}
	    }
	  else
	    {
	      /* Unrecognized mandatory option, check the two high order bits */
	      switch (opt0->type & HBH_OPTION_TYPE_HIGH_ORDER_BITS)
		{
		case HBH_OPTION_TYPE_SKIP_UNKNOWN:
		  break;
		case HBH_OPTION_TYPE_DISCARD_UNKNOWN:
		  error0 = IP6_HOP_BY_HOP_ERROR_UNKNOWN_OPTION;
		  *next0 = IP_LOOKUP_NEXT_DROP;
		  break;
		case HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP:
		  error0 = IP6_HOP_BY_HOP_ERROR_UNKNOWN_OPTION;
		  *next0 = IP_LOOKUP_NEXT_ICMP_ERROR;
		  icmp6_error_set_vnet_buffer (b0, ICMP6_parameter_problem,
					       ICMP6_parameter_problem_unrecognized_option,
					       (u8 *) opt0 - (u8 *) ip0);
		  break;
		case HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP_NOT_MCAST:
		  error0 = IP6_HOP_BY_HOP_ERROR_UNKNOWN_OPTION;
		  if (!ip6_address_is_multicast (&ip0->dst_address))
		    {
		      *next0 = IP_LOOKUP_NEXT_ICMP_ERROR;
		      icmp6_error_set_vnet_buffer (b0,
						   ICMP6_parameter_problem,
						   ICMP6_parameter_problem_unrecognized_option,
						   (u8 *) opt0 - (u8 *) ip0);
		    }
		  else
		    {
		      *next0 = IP_LOOKUP_NEXT_DROP;
		    }
		  break;
		}
	      return (error0);
	    }
	}
      opt0 =
	(ip6_hop_by_hop_option_t *) (((u8 *) opt0) + opt0->length +
				     sizeof (ip6_hop_by_hop_option_t));
    }
  return (error0);
}

/*
 * Process the Hop-by-Hop Options header
 */
static uword
ip6_hop_by_hop (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_hop_by_hop_node.index);
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  u32 n_left_from, *from, *to_next;
  ip_lookup_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  ip6_header_t *ip0, *ip1;
	  ip6_hop_by_hop_header_t *hbh0, *hbh1;
	  ip6_hop_by_hop_option_t *opt0, *limit0, *opt1, *limit1;
	  u8 error0 = 0, error1 = 0;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  /* Speculatively enqueue b0, b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* Default use the next_index from the adjacency. A HBH option rarely redirects to a different node */
	  u32 adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	  ip_adjacency_t *adj0 = adj_get (adj_index0);
	  u32 adj_index1 = vnet_buffer (b1)->ip.adj_index[VLIB_TX];
	  ip_adjacency_t *adj1 = adj_get (adj_index1);

	  /* Default use the next_index from the adjacency. A HBH option rarely redirects to a different node */
	  next0 = adj0->lookup_next_index;
	  next1 = adj1->lookup_next_index;

	  ip0 = vlib_buffer_get_current (b0);
	  ip1 = vlib_buffer_get_current (b1);
	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  hbh1 = (ip6_hop_by_hop_header_t *) (ip1 + 1);
	  opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
	  opt1 = (ip6_hop_by_hop_option_t *) (hbh1 + 1);
	  limit0 =
	    (ip6_hop_by_hop_option_t *) ((u8 *) hbh0 +
					 ((hbh0->length + 1) << 3));
	  limit1 =
	    (ip6_hop_by_hop_option_t *) ((u8 *) hbh1 +
					 ((hbh1->length + 1) << 3));

	  /*
	   * Basic validity checks
	   */
	  if ((hbh0->length + 1) << 3 >
	      clib_net_to_host_u16 (ip0->payload_length))
	    {
	      error0 = IP6_HOP_BY_HOP_ERROR_FORMAT;
	      next0 = IP_LOOKUP_NEXT_DROP;
	      goto outdual;
	    }
	  /* Scan the set of h-b-h options, process ones that we understand */
	  error0 = ip6_scan_hbh_options (b0, ip0, hbh0, opt0, limit0, &next0);

	  if ((hbh1->length + 1) << 3 >
	      clib_net_to_host_u16 (ip1->payload_length))
	    {
	      error1 = IP6_HOP_BY_HOP_ERROR_FORMAT;
	      next1 = IP_LOOKUP_NEXT_DROP;
	      goto outdual;
	    }
	  /* Scan the set of h-b-h options, process ones that we understand */
	  error1 = ip6_scan_hbh_options (b1, ip1, hbh1, opt1, limit1, &next1);

	outdual:
	  /* Has the classifier flagged this buffer for special treatment? */
	  if (PREDICT_FALSE
	      ((error0 == 0)
	       && (vnet_buffer (b0)->l2_classify.opaque_index & OI_DECAP)))
	    next0 = hm->next_override;

	  /* Has the classifier flagged this buffer for special treatment? */
	  if (PREDICT_FALSE
	      ((error1 == 0)
	       && (vnet_buffer (b1)->l2_classify.opaque_index & OI_DECAP)))
	    next1 = hm->next_override;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_hop_by_hop_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  u32 trace_len = (hbh0->length + 1) << 3;
		  t->next_index = next0;
		  /* Capture the h-b-h option verbatim */
		  trace_len =
		    trace_len <
		    ARRAY_LEN (t->option_data) ? trace_len :
		    ARRAY_LEN (t->option_data);
		  t->trace_len = trace_len;
		  clib_memcpy_fast (t->option_data, hbh0, trace_len);
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  ip6_hop_by_hop_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  u32 trace_len = (hbh1->length + 1) << 3;
		  t->next_index = next1;
		  /* Capture the h-b-h option verbatim */
		  trace_len =
		    trace_len <
		    ARRAY_LEN (t->option_data) ? trace_len :
		    ARRAY_LEN (t->option_data);
		  t->trace_len = trace_len;
		  clib_memcpy_fast (t->option_data, hbh1, trace_len);
		}

	    }

	  b0->error = error_node->errors[error0];
	  b1->error = error_node->errors[error1];

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip6_header_t *ip0;
	  ip6_hop_by_hop_header_t *hbh0;
	  ip6_hop_by_hop_option_t *opt0, *limit0;
	  u8 error0 = 0;

	  /* Speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  /*
	   * Default use the next_index from the adjacency.
	   * A HBH option rarely redirects to a different node
	   */
	  u32 adj_index0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	  ip_adjacency_t *adj0 = adj_get (adj_index0);
	  next0 = adj0->lookup_next_index;

	  ip0 = vlib_buffer_get_current (b0);
	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  opt0 = (ip6_hop_by_hop_option_t *) (hbh0 + 1);
	  limit0 =
	    (ip6_hop_by_hop_option_t *) ((u8 *) hbh0 +
					 ((hbh0->length + 1) << 3));

	  /*
	   * Basic validity checks
	   */
	  if ((hbh0->length + 1) << 3 >
	      clib_net_to_host_u16 (ip0->payload_length))
	    {
	      error0 = IP6_HOP_BY_HOP_ERROR_FORMAT;
	      next0 = IP_LOOKUP_NEXT_DROP;
	      goto out0;
	    }

	  /* Scan the set of h-b-h options, process ones that we understand */
	  error0 = ip6_scan_hbh_options (b0, ip0, hbh0, opt0, limit0, &next0);

	out0:
	  /* Has the classifier flagged this buffer for special treatment? */
	  if (PREDICT_FALSE
	      ((error0 == 0)
	       && (vnet_buffer (b0)->l2_classify.opaque_index & OI_DECAP)))
	    next0 = hm->next_override;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip6_hop_by_hop_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      u32 trace_len = (hbh0->length + 1) << 3;
	      t->next_index = next0;
	      /* Capture the h-b-h option verbatim */
	      trace_len =
		trace_len <
		ARRAY_LEN (t->option_data) ? trace_len :
		ARRAY_LEN (t->option_data);
	      t->trace_len = trace_len;
	      clib_memcpy_fast (t->option_data, hbh0, trace_len);
	    }

	  b0->error = error_node->errors[error0];

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_hop_by_hop_node) =
{
  .function = ip6_hop_by_hop,
  .name = "ip6-hop-by-hop",
  .sibling_of = "ip6-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ip6_hop_by_hop_error_strings),
  .error_strings = ip6_hop_by_hop_error_strings,
  .n_next_nodes = 0,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_hop_by_hop_node, ip6_hop_by_hop);

static clib_error_t *
ip6_hop_by_hop_init (vlib_main_t * vm)
{
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  clib_memset (hm->options, 0, sizeof (hm->options));
  clib_memset (hm->trace, 0, sizeof (hm->trace));
  hm->next_override = IP6_LOOKUP_NEXT_POP_HOP_BY_HOP;
  return (0);
}

VLIB_INIT_FUNCTION (ip6_hop_by_hop_init);

void
ip6_hbh_set_next_override (uword next)
{
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;

  hm->next_override = next;
}

int
ip6_hbh_register_option (u8 option,
			 int options (vlib_buffer_t * b, ip6_header_t * ip,
				      ip6_hop_by_hop_option_t * opt),
			 u8 * trace (u8 * s, ip6_hop_by_hop_option_t * opt))
{
  ip6_main_t *im = &ip6_main;
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->options));

  /* Already registered */
  if (hm->options[option])
    return (-1);

  hm->options[option] = options;
  hm->trace[option] = trace;

  /* Set global variable */
  im->hbh_enabled = 1;

  return (0);
}

int
ip6_hbh_unregister_option (u8 option)
{
  ip6_main_t *im = &ip6_main;
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;

  ASSERT ((u32) option < ARRAY_LEN (hm->options));

  /* Not registered */
  if (!hm->options[option])
    return (-1);

  hm->options[option] = NULL;
  hm->trace[option] = NULL;

  /* Disable global knob if this was the last option configured */
  int i;
  bool found = false;
  for (i = 0; i < 256; i++)
    {
      if (hm->options[option])
	{
	  found = true;
	  break;
	}
    }
  if (!found)
    im->hbh_enabled = 0;

  return (0);
}

/* Global IP6 main. */
ip6_main_t ip6_main;

static clib_error_t *
ip6_lookup_init (vlib_main_t * vm)
{
  ip6_main_t *im = &ip6_main;
  clib_error_t *error;
  uword i;

  if ((error = vlib_call_init_function (vm, vnet_feature_init)))
    return error;

  for (i = 0; i < ARRAY_LEN (im->fib_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
	im->fib_masks[i].as_u32[j] = ~0;

      if (i1)
	im->fib_masks[i].as_u32[i0] =
	  clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }

  ip_lookup_init (&im->lookup_main, /* is_ip6 */ 1);

  if (im->lookup_table_nbuckets == 0)
    im->lookup_table_nbuckets = IP6_FIB_DEFAULT_HASH_NUM_BUCKETS;

  im->lookup_table_nbuckets = 1 << max_log2 (im->lookup_table_nbuckets);

  if (im->lookup_table_size == 0)
    im->lookup_table_size = IP6_FIB_DEFAULT_HASH_MEMORY_SIZE;

  clib_bihash_init_24_8 (&(im->ip6_table[IP6_FIB_TABLE_FWDING].ip6_hash),
			 "ip6 FIB fwding table",
			 im->lookup_table_nbuckets, im->lookup_table_size);
  clib_bihash_init_24_8 (&im->ip6_table[IP6_FIB_TABLE_NON_FWDING].ip6_hash,
			 "ip6 FIB non-fwding table",
			 im->lookup_table_nbuckets, im->lookup_table_size);
  clib_bihash_init_40_8 (&im->ip6_mtable.ip6_mhash,
			 "ip6 mFIB table",
			 im->lookup_table_nbuckets, im->lookup_table_size);

  /* Create FIB with index 0 and table id of 0. */
  fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, 0,
				     FIB_SOURCE_DEFAULT_ROUTE);
  mfib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, 0,
				      MFIB_SOURCE_DEFAULT_ROUTE);

  {
    pg_node_t *pn;
    pn = pg_get_node (ip6_lookup_node.index);
    pn->unformat_edit = unformat_pg_ip6_header;
  }

  /* Unless explicitly configured, don't process HBH options */
  im->hbh_enabled = 0;

  {
    icmp6_neighbor_solicitation_header_t p;

    clib_memset (&p, 0, sizeof (p));

    p.ip.ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 (0x6 << 28);
    p.ip.payload_length =
      clib_host_to_net_u16 (sizeof (p) -
			    STRUCT_OFFSET_OF
			    (icmp6_neighbor_solicitation_header_t, neighbor));
    p.ip.protocol = IP_PROTOCOL_ICMP6;
    p.ip.hop_limit = 255;
    ip6_set_solicited_node_multicast_address (&p.ip.dst_address, 0);

    p.neighbor.icmp.type = ICMP6_neighbor_solicitation;

    p.link_layer_option.header.type =
      ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
    p.link_layer_option.header.n_data_u64s =
      sizeof (p.link_layer_option) / sizeof (u64);

    vlib_packet_template_init (vm,
			       &im->discover_neighbor_packet_template,
			       &p, sizeof (p),
			       /* alloc chunk size */ 8,
			       "ip6 neighbor discovery");
  }

  return error;
}

VLIB_INIT_FUNCTION (ip6_lookup_init);

void
ip6_link_local_address_from_ethernet_mac_address (ip6_address_t * ip,
						  u8 * mac)
{
  ip->as_u64[0] = clib_host_to_net_u64 (0xFE80000000000000ULL);
  /* Invert the "u" bit */
  ip->as_u8[8] = mac[0] ^ (1 << 1);
  ip->as_u8[9] = mac[1];
  ip->as_u8[10] = mac[2];
  ip->as_u8[11] = 0xFF;
  ip->as_u8[12] = 0xFE;
  ip->as_u8[13] = mac[3];
  ip->as_u8[14] = mac[4];
  ip->as_u8[15] = mac[5];
}

void
ip6_ethernet_mac_address_from_link_local_address (u8 * mac,
						  ip6_address_t * ip)
{
  /* Invert the previously inverted "u" bit */
  mac[0] = ip->as_u8[8] ^ (1 << 1);
  mac[1] = ip->as_u8[9];
  mac[2] = ip->as_u8[10];
  mac[3] = ip->as_u8[13];
  mac[4] = ip->as_u8[14];
  mac[5] = ip->as_u8[15];
}

static clib_error_t *
test_ip6_link_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 mac[6];
  ip6_address_t _a, *a = &_a;

  if (unformat (input, "%U", unformat_ethernet_address, mac))
    {
      ip6_link_local_address_from_ethernet_mac_address (a, mac);
      vlib_cli_output (vm, "Link local address: %U", format_ip6_address, a);
      ip6_ethernet_mac_address_from_link_local_address (mac, a);
      vlib_cli_output (vm, "Original MAC address: %U",
		       format_ethernet_address, mac);
    }

  return 0;
}

/*?
 * This command converts the given MAC Address into an IPv6 link-local
 * address.
 *
 * @cliexpar
 * Example of how to create an IPv6 link-local address:
 * @cliexstart{test ip6 link 16:d9:e0:91:79:86}
 * Link local address: fe80::14d9:e0ff:fe91:7986
 * Original MAC address: 16:d9:e0:91:79:86
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_link_command, static) =
{
  .path = "test ip6 link",
  .function = test_ip6_link_command_fn,
  .short_help = "test ip6 link <mac-address>",
};
/* *INDENT-ON* */

int
vnet_set_ip6_flow_hash (u32 table_id, u32 flow_hash_config)
{
  u32 fib_index;

  fib_index = fib_table_find (FIB_PROTOCOL_IP6, table_id);

  if (~0 == fib_index)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_table_set_flow_hash_config (fib_index, FIB_PROTOCOL_IP6,
				  flow_hash_config);

  return 0;
}

static clib_error_t *
set_ip6_flow_hash_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  int matched = 0;
  u32 table_id = 0;
  u32 flow_hash_config = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table %d", &table_id))
	matched = 1;
#define _(a,v) \
    else if (unformat (input, #a)) { flow_hash_config |= v; matched=1;}
      foreach_flow_hash_bit
#undef _
	else
	break;
    }

  if (matched == 0)
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  rv = vnet_set_ip6_flow_hash (table_id, flow_hash_config);
  switch (rv)
    {
    case 0:
      break;

    case -1:
      return clib_error_return (0, "no such FIB table %d", table_id);

    default:
      clib_warning ("BUG: illegal flow hash config 0x%x", flow_hash_config);
      break;
    }

  return 0;
}

/*?
 * Configure the set of IPv6 fields used by the flow hash.
 *
 * @cliexpar
 * @parblock
 * Example of how to set the flow hash on a given table:
 * @cliexcmd{set ip6 flow-hash table 8 dst sport dport proto}
 *
 * Example of display the configured flow hash:
 * @cliexstart{show ip6 fib}
 * ipv6-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 * @::/0
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:5 buckets:1 uRPF:5 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * fe80::/10
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:10 buckets:1 uRPF:10 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::1/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:8 buckets:1 uRPF:8 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::2/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:7 buckets:1 uRPF:7 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::16/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:9 buckets:1 uRPF:9 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::1:ff00:0/104
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:6 buckets:1 uRPF:6 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ipv6-VRF:8, fib_index 1, flow hash: dst sport dport proto
 * @::/0
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * @::a:1:1:0:4/126
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:27 buckets:1 uRPF:26 to:[0:0]]
 *     [0] [@4]: ipv6-glean: af_packet0
 * @::a:1:1:0:7/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:28 buckets:1 uRPF:27 to:[0:0]]
 *     [0] [@2]: dpo-receive: @::a:1:1:0:7 on af_packet0
 * fe80::/10
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:26 buckets:1 uRPF:25 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * fe80::fe:3eff:fe3e:9222/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:29 buckets:1 uRPF:28 to:[0:0]]
 *     [0] [@2]: dpo-receive: fe80::fe:3eff:fe3e:9222 on af_packet0
 * ff02::1/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:24 buckets:1 uRPF:23 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::2/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:23 buckets:1 uRPF:22 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::16/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:25 buckets:1 uRPF:24 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::1:ff00:0/104
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:22 buckets:1 uRPF:21 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip6_flow_hash_command, static) =
{
  .path = "set ip6 flow-hash",
  .short_help =
  "set ip6 flow-hash table <table-id> [src] [dst] [sport] [dport] [proto] [reverse]",
  .function = set_ip6_flow_hash_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_ip6_local_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip6_main_t *im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;
  int i;

  vlib_cli_output (vm, "Protocols handled by ip6_local");
  for (i = 0; i < ARRAY_LEN (lm->local_next_by_ip_protocol); i++)
    {
      if (lm->local_next_by_ip_protocol[i] != IP_LOCAL_NEXT_PUNT)
	{

	  u32 node_index = vlib_get_node (vm,
					  ip6_local_node.index)->
	    next_nodes[lm->local_next_by_ip_protocol[i]];
	  vlib_cli_output (vm, "%d: %U", i, format_vlib_node_name, vm,
			   node_index);
	}
    }
  return 0;
}



/*?
 * Display the set of protocols handled by the local IPv6 stack.
 *
 * @cliexpar
 * Example of how to display local protocol table:
 * @cliexstart{show ip6 local}
 * Protocols handled by ip6_local
 * 17
 * 43
 * 58
 * 115
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip6_local, static) =
{
  .path = "show ip6 local",
  .function = show_ip6_local_command_fn,
  .short_help = "show ip6 local",
};
/* *INDENT-ON* */

int
vnet_set_ip6_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
			     u32 table_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  ip6_main_t *ipm = &ip6_main;
  ip_lookup_main_t *lm = &ipm->lookup_main;
  vnet_classify_main_t *cm = &vnet_classify_main;
  ip6_address_t *if_addr;

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  if (table_index != ~0 && pool_is_free_index (cm->tables, table_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vec_validate (lm->classify_table_index_by_sw_if_index, sw_if_index);
  lm->classify_table_index_by_sw_if_index[sw_if_index] = table_index;

  if_addr = ip6_interface_first_address (ipm, sw_if_index);

  if (NULL != if_addr)
    {
      fib_prefix_t pfx = {
	.fp_len = 128,
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_addr.ip6 = *if_addr,
      };
      u32 fib_index;

      fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						       sw_if_index);


      if (table_index != (u32) ~ 0)
	{
	  dpo_id_t dpo = DPO_INVALID;

	  dpo_set (&dpo,
		   DPO_CLASSIFY,
		   DPO_PROTO_IP6,
		   classify_dpo_create (DPO_PROTO_IP6, table_index));

	  fib_table_entry_special_dpo_add (fib_index,
					   &pfx,
					   FIB_SOURCE_CLASSIFY,
					   FIB_ENTRY_FLAG_NONE, &dpo);
	  dpo_reset (&dpo);
	}
      else
	{
	  fib_table_entry_special_remove (fib_index,
					  &pfx, FIB_SOURCE_CLASSIFY);
	}
    }

  return 0;
}

static clib_error_t *
set_ip6_classify_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  u32 table_index = ~0;
  int table_index_set = 0;
  u32 sw_if_index = ~0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table-index %d", &table_index))
	table_index_set = 1;
      else if (unformat (input, "intfc %U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else
	break;
    }

  if (table_index_set == 0)
    return clib_error_return (0, "classify table-index must be specified");

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface / subif must be specified");

  rv = vnet_set_ip6_classify_intfc (vm, sw_if_index, table_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_MATCHING_INTERFACE:
      return clib_error_return (0, "No such interface");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "No such classifier table");
    }
  return 0;
}

/*?
 * Assign a classification table to an interface. The classification
 * table is created using the '<em>classify table</em>' and '<em>classify session</em>'
 * commands. Once the table is create, use this command to filter packets
 * on an interface.
 *
 * @cliexpar
 * Example of how to assign a classification table to an interface:
 * @cliexcmd{set ip6 classify intfc GigabitEthernet2/0/0 table-index 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ip6_classify_command, static) =
{
  .path = "set ip6 classify",
  .short_help =
  "set ip6 classify intfc <interface> table-index <classify-idx>",
  .function = set_ip6_classify_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ip6_config (vlib_main_t * vm, unformat_input_t * input)
{
  ip6_main_t *im = &ip6_main;
  uword heapsize = 0;
  u32 tmp;
  u32 nbuckets = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "hash-buckets %d", &tmp))
	nbuckets = tmp;
      else if (unformat (input, "heap-size %U",
			 unformat_memory_size, &heapsize))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  im->lookup_table_nbuckets = nbuckets;
  im->lookup_table_size = heapsize;

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (ip6_config, "ip6");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
