/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */
#include <vnet/srp/srp.h>	/* for srp_hw_interface_class */
#include <vppinfra/cache.h>

#include <vppinfra/bihash_template.c>

static void compute_prefix_lengths_in_search_order (ip6_main_t * im)
{
  int i;
  vec_reset_length (im->prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */
  clib_bitmap_foreach (i, im->non_empty_dst_address_length_bitmap,
  ({
    int dst_address_length = 128 - i;
    vec_add1 (im->prefix_lengths_in_search_order, dst_address_length);
  }));
}

u32 
ip6_fib_lookup_with_table (ip6_main_t * im, u32 fib_index, ip6_address_t * dst)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  int i, len;
  int rv;
  BVT(clib_bihash_kv) kv, value;
  u64 fib;

  len = vec_len (im->prefix_lengths_in_search_order);

  kv.key[0] = dst->as_u64[0];
  kv.key[1] = dst->as_u64[1];
  fib = ((u64)((fib_index))<<32);

  for (i = 0; i < len; i++)
    {
      int dst_address_length = im->prefix_lengths_in_search_order[i];
      ip6_address_t * mask = &im->fib_masks[dst_address_length];
      
      ASSERT(dst_address_length >= 0 && dst_address_length <= 128);
      //As lengths are decreasing, masks are increasingly specific.
      kv.key[0] &= mask->as_u64[0];
      kv.key[1] &= mask->as_u64[1];
      kv.key[2] = fib | dst_address_length;
      
      rv = BV(clib_bihash_search_inline_2)(&im->ip6_lookup_table, &kv, &value);
      if (rv == 0)
        return value.value;
    }

  return lm->miss_adj_index;
}

u32 ip6_fib_lookup (ip6_main_t * im, u32 sw_if_index, ip6_address_t * dst)
{
    u32 fib_index = vec_elt (im->fib_index_by_sw_if_index, sw_if_index);
    return ip6_fib_lookup_with_table (im, fib_index, dst);
}

void
vnet_ip6_fib_init (ip6_main_t * im, u32 fib_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_add_del_route_args_t a;
  ip_adjacency_t * adj;

  memset(&a, 0x0, sizeof(ip6_add_del_route_args_t));

  a.table_index_or_table_id = fib_index;
  a.flags = (IP6_ROUTE_FLAG_ADD
	     | IP6_ROUTE_FLAG_FIB_INDEX
	     | IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY
	     | IP6_ROUTE_FLAG_NO_REDISTRIBUTE);

  /* Add ff02::1:ff00:0/104 via local route for all tables.
     This is required for neighbor discovery to work. */
  adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
			  &a.adj_index);
  adj->lookup_next_index = IP_LOOKUP_NEXT_LOCAL;
  adj->if_address_index = ~0;
  adj->rewrite_header.data_bytes = 0;

  ip6_set_solicited_node_multicast_address (&a.dst_address, 0);

  a.dst_address_length = 104;
  ip6_add_del_route (im, &a);

  /* Add all-routers multicast address via local route for all tables */
  adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
			  &a.adj_index);
  adj->lookup_next_index = IP_LOOKUP_NEXT_LOCAL;
  adj->if_address_index = ~0;
  adj->rewrite_header.data_bytes = 0;

  ip6_set_reserved_multicast_address (&a.dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_all_routers);
  
  a.dst_address_length = 128;  
  ip6_add_del_route (im, &a);

  /* Add all-nodes multicast address via local route for all tables */
  adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
			  &a.adj_index);
  adj->lookup_next_index = IP_LOOKUP_NEXT_LOCAL;
  adj->if_address_index = ~0;
  adj->rewrite_header.data_bytes = 0;

  ip6_set_reserved_multicast_address (&a.dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_all_hosts);

  a.dst_address_length = 128;
  ip6_add_del_route (im, &a);

  /* Add all-mldv2  multicast address via local route for all tables */
  adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
			  &a.adj_index);
  adj->lookup_next_index = IP_LOOKUP_NEXT_LOCAL;
  adj->if_address_index = ~0;
  adj->rewrite_header.data_bytes = 0;
  
  ip6_set_reserved_multicast_address (&a.dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_mldv2_routers);

  a.dst_address_length = 128;
  ip6_add_del_route (im, &a);
}

static ip6_fib_t *
create_fib_with_table_id (ip6_main_t * im, u32 table_id)
{
  ip6_fib_t * fib;
  hash_set (im->fib_index_by_table_id, table_id, vec_len (im->fibs));
  vec_add2 (im->fibs, fib, 1);
  fib->table_id = table_id;
  fib->index = fib - im->fibs;
  fib->flow_hash_config = IP_FLOW_HASH_DEFAULT;
  vnet_ip6_fib_init (im, fib->index);
  return fib;
}

ip6_fib_t *
find_ip6_fib_by_table_index_or_id (ip6_main_t * im, u32 table_index_or_id, u32 flags)
{
  uword * p, fib_index;

  fib_index = table_index_or_id;
  if (! (flags & IP6_ROUTE_FLAG_FIB_INDEX))
    {
      if (table_index_or_id == ~0) {
        table_index_or_id = 0;
        while (hash_get (im->fib_index_by_table_id, table_index_or_id)) {
          table_index_or_id++;
        }
        return create_fib_with_table_id (im, table_index_or_id);
      }

      p = hash_get (im->fib_index_by_table_id, table_index_or_id);
      if (! p)
	return create_fib_with_table_id (im, table_index_or_id);
      fib_index = p[0];
    }
  return vec_elt_at_index (im->fibs, fib_index);
}

void ip6_add_del_route (ip6_main_t * im, ip6_add_del_route_args_t * a)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_fib_t * fib;
  ip6_address_t dst_address;
  u32 dst_address_length, adj_index;
  uword is_del;
  u32 old_adj_index = ~0;
  BVT(clib_bihash_kv) kv, value;

  vlib_smp_unsafe_warning();

  is_del = (a->flags & IP6_ROUTE_FLAG_DEL) != 0;

  /* Either create new adjacency or use given one depending on arguments. */
  if (a->n_add_adj > 0)
    {
      ip_add_adjacency (lm, a->add_adj, a->n_add_adj, &adj_index);
      ip_call_add_del_adjacency_callbacks (lm, adj_index, /* is_del */ 0);
    }
  else
    adj_index = a->adj_index;

  dst_address = a->dst_address;
  dst_address_length = a->dst_address_length;
  fib = find_ip6_fib_by_table_index_or_id (im, a->table_index_or_table_id, 
                                           a->flags);

  ASSERT (dst_address_length < ARRAY_LEN (im->fib_masks));
  ip6_address_mask (&dst_address, &im->fib_masks[dst_address_length]);

  /* refcount accounting */
  if (is_del)
    {
      ASSERT (im->dst_address_length_refcounts[dst_address_length] > 0);
      if (--im->dst_address_length_refcounts[dst_address_length] == 0)
        {
          im->non_empty_dst_address_length_bitmap =
            clib_bitmap_set (im->non_empty_dst_address_length_bitmap, 
                             128 - dst_address_length, 0);
          compute_prefix_lengths_in_search_order (im);
        }
    }
  else
    {
      im->dst_address_length_refcounts[dst_address_length]++;

      im->non_empty_dst_address_length_bitmap =
        clib_bitmap_set (im->non_empty_dst_address_length_bitmap, 
                             128 - dst_address_length, 1);
      compute_prefix_lengths_in_search_order (im);
    }
    
  kv.key[0] = dst_address.as_u64[0];
  kv.key[1] = dst_address.as_u64[1];
  kv.key[2] = ((u64)((fib - im->fibs))<<32) | dst_address_length;

  if (BV(clib_bihash_search)(&im->ip6_lookup_table, &kv, &value) == 0)
    old_adj_index = value.value;

  if (is_del)
    BV(clib_bihash_add_del) (&im->ip6_lookup_table, &kv, 0 /* is_add */);
  else
    {
      /* Make sure adj index is valid. */
      if (CLIB_DEBUG > 0)
        (void) ip_get_adjacency (lm, adj_index);

      kv.value = adj_index;

      BV(clib_bihash_add_del) (&im->ip6_lookup_table, &kv, 1 /* is_add */);
    }

  /* Avoid spurious reference count increments */
  if (old_adj_index == adj_index 
      && adj_index != ~0
      && !(a->flags & IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY))
    {
      ip_adjacency_t * adj = ip_get_adjacency (lm, adj_index);
      if (adj->share_count > 0)
        adj->share_count --;
    }

  /* Delete old adjacency index if present and changed. */
  {
    if (! (a->flags & IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY)
	&& old_adj_index != ~0
	&& old_adj_index != adj_index)
      ip_del_adjacency (lm, old_adj_index);
  }
}

u32
ip6_route_get_next_hop_adj (ip6_main_t * im,
			    u32 fib_index,
			    ip6_address_t *next_hop,
			    u32 next_hop_sw_if_index,
			    u32 explicit_fib_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  vnet_main_t * vnm = vnet_get_main();
  int is_interface_next_hop;
  uword * nh_result;
  u32 nh_adj_index;
  ip6_fib_t * fib;

  fib = vec_elt_at_index (im->fibs, fib_index);

  is_interface_next_hop = ip6_address_is_zero (next_hop);

  if (is_interface_next_hop)
    {
      nh_result = hash_get (im->interface_route_adj_index_by_sw_if_index,
			    next_hop_sw_if_index);
      if (nh_result)
	  nh_adj_index = *nh_result;
      else
        {
	  ip_adjacency_t * adj;
	  adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
				  &nh_adj_index);
	  ip6_adjacency_set_interface_route (vnm, adj,
					     next_hop_sw_if_index, ~0);
	  ip_call_add_del_adjacency_callbacks
	      (lm, next_hop_sw_if_index, /* is_del */ 0);
	  hash_set (im->interface_route_adj_index_by_sw_if_index,
		    next_hop_sw_if_index, nh_adj_index);
	}
    }
  else if (next_hop_sw_if_index == ~0)
    {
      /* next-hop is recursive. we always need a indirect adj
       * for recursive paths. Any LPM we perform now will give
       * us a valid adj, but without tracking the next-hop we
       * have no way to keep it valid.
       */
      ip_adjacency_t add_adj;
      memset (&add_adj, 0, sizeof(add_adj));
      add_adj.n_adj = 1;
      add_adj.lookup_next_index = IP_LOOKUP_NEXT_INDIRECT;
      add_adj.indirect.next_hop.ip6.as_u64[0] = next_hop->as_u64[0];
      add_adj.indirect.next_hop.ip6.as_u64[1] = next_hop->as_u64[1];
      add_adj.explicit_fib_index = explicit_fib_index;
      ip_add_adjacency (lm, &add_adj, 1, &nh_adj_index);
    }
  else
    {
      BVT(clib_bihash_kv) kv, value;

      /* Look for the interface /128 route */
      kv.key[0] = next_hop->as_u64[0];
      kv.key[1] = next_hop->as_u64[1];
      kv.key[2] = ((u64)((fib - im->fibs))<<32) | 128;
after_nd:
      if (BV(clib_bihash_search)(&im->ip6_lookup_table, &kv, &value) < 0)
        {
          ip_adjacency_t * adj;
          nh_adj_index = ip6_fib_lookup_with_table (im, fib_index, next_hop);
          adj = ip_get_adjacency (lm, nh_adj_index);
          /* if ND interface adjacencty is present, we need to
           install ND adjaceny for specific next hop */
          if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP &&
              adj->arp.next_hop.ip6.as_u64[0] == 0 &&
              adj->arp.next_hop.ip6.as_u64[1] == 0)
            {
              nh_adj_index = vnet_ip6_neighbor_glean_add(fib_index, next_hop);
            }
          else if (next_hop->as_u8[0] == 0xfe)
            {
              //Next hop is link-local. No indirect in this case.
              //Let's add it as a possible neighbor on this interface
              ip6_address_t null_addr= {};
              ip6_add_del_route_next_hop (im, IP6_ROUTE_FLAG_ADD,
                                          next_hop, 128,
                                          &null_addr, next_hop_sw_if_index,
                                          1, ~0, fib_index);
              goto after_nd;
            }
        }
      else
        {
          nh_adj_index = value.value;
        }
    }

  return (nh_adj_index);
}

void
ip6_add_del_route_next_hop (ip6_main_t * im,
			    u32 flags,
			    ip6_address_t * dst_address,
			    u32 dst_address_length,
			    ip6_address_t * next_hop,
			    u32 next_hop_sw_if_index,
			    u32 next_hop_weight, u32 adj_index,
                            u32 explicit_fib_index)
{
  vnet_main_t * vnm = vnet_get_main();
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 fib_index;
  ip6_fib_t * fib;
  ip6_address_t masked_dst_address;
  u32 old_mp_adj_index, new_mp_adj_index;
  u32 dst_adj_index, nh_adj_index;
  int rv;
  ip_adjacency_t * dst_adj;
  ip_multipath_adjacency_t * old_mp, * new_mp;
  int is_del = (flags & IP6_ROUTE_FLAG_DEL) != 0;
  clib_error_t * error = 0;
  BVT(clib_bihash_kv) kv, value;

  vlib_smp_unsafe_warning();

  if (explicit_fib_index == (u32)~0)
    fib_index = vec_elt (im->fib_index_by_sw_if_index, next_hop_sw_if_index);
  else
    fib_index = explicit_fib_index;

  fib = vec_elt_at_index (im->fibs, fib_index);

  /* Lookup next hop to be added or deleted. */
  if (adj_index == (u32)~0)
    {
      nh_adj_index = ip6_route_get_next_hop_adj(im, fib_index,
						next_hop,
						next_hop_sw_if_index,
						explicit_fib_index);
    }
  else
    {
      /* Look for the interface /128 route */
      kv.key[0] = next_hop->as_u64[0];
      kv.key[1] = next_hop->as_u64[1];
      kv.key[2] = ((u64)((fib - im->fibs))<<32) | 128;
      
      if (BV(clib_bihash_search)(&im->ip6_lookup_table, &kv, &value) < 0)
        {
          vnm->api_errno = VNET_API_ERROR_UNKNOWN_DESTINATION;
          error = clib_error_return (0, "next-hop %U/128 not in FIB",
                                     format_ip6_address, next_hop);
          goto done;
        }
      
      nh_adj_index = value.value;
    }

  ASSERT (dst_address_length < ARRAY_LEN (im->fib_masks));
  masked_dst_address = dst_address[0];
  ip6_address_mask (&masked_dst_address, &im->fib_masks[dst_address_length]);

  kv.key[0] = masked_dst_address.as_u64[0];
  kv.key[1] = masked_dst_address.as_u64[1];
  kv.key[2] = ((u64)((fib - im->fibs))<<32) | dst_address_length;

  rv = BV(clib_bihash_search)(&im->ip6_lookup_table, &kv, &value);

  if (rv == 0)
    {
      dst_adj_index = value.value;
      dst_adj = ip_get_adjacency (lm, dst_adj_index);
    }
  else
    {
      /* For deletes destination must be known. */
      if (is_del)
	{
          vnm->api_errno = VNET_API_ERROR_UNKNOWN_DESTINATION;
	  error = clib_error_return (0, "unknown destination %U/%d",
				     format_ip6_address, dst_address,
				     dst_address_length);
	  goto done;
	}

      dst_adj_index = ~0;
      dst_adj = 0;
    }

  /* Ignore adds of X/128 with next hop of X. */
  if (! is_del
      && dst_address_length == 128
      && ip6_address_is_equal (dst_address, next_hop))
    {
      vnm->api_errno = VNET_API_ERROR_PREFIX_MATCHES_NEXT_HOP;
      error = clib_error_return (0, "prefix matches next hop %U/%d",
                                 format_ip6_address, dst_address,
                                 dst_address_length);
      goto done;
    }

  /* Destination is not known and default weight is set so add route
     to existing non-multipath adjacency */
  if (dst_adj_index == ~0 && next_hop_weight == 1 && next_hop_sw_if_index == ~0)
  {
    /* create / delete additional mapping of existing adjacency */
    ip6_add_del_route_args_t a;

    a.table_index_or_table_id = fib_index;
    a.flags = ((is_del ? IP6_ROUTE_FLAG_DEL : IP6_ROUTE_FLAG_ADD)
        | IP6_ROUTE_FLAG_FIB_INDEX
        | IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY
        | (flags & (IP6_ROUTE_FLAG_NO_REDISTRIBUTE
            | IP6_ROUTE_FLAG_NOT_LAST_IN_GROUP)));
    a.dst_address = dst_address[0];
    a.dst_address_length = dst_address_length;
    a.adj_index = nh_adj_index;
    a.add_adj = 0;
    a.n_add_adj = 0;

    ip6_add_del_route (im, &a);
    goto done;
  }

  old_mp_adj_index = dst_adj ? dst_adj->heap_handle : ~0;

  if (! ip_multipath_adjacency_add_del_next_hop
      (lm, is_del,
       dst_adj ? dst_adj->heap_handle : ~0,
       nh_adj_index,
       next_hop_weight,
       &new_mp_adj_index))
    {
      vnm->api_errno = VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP;
      error = clib_error_return 
        (0, "requested deleting next-hop %U not found in multi-path",
         format_ip6_address, next_hop);
      goto done;
    }
  
  old_mp = new_mp = 0;
  if (old_mp_adj_index != ~0)
    old_mp = vec_elt_at_index (lm->multipath_adjacencies, old_mp_adj_index);
  if (new_mp_adj_index != ~0)
    new_mp = vec_elt_at_index (lm->multipath_adjacencies, new_mp_adj_index);

  if (old_mp != new_mp)
    {
      ip6_add_del_route_args_t a;
      ip_adjacency_t * adj;

      a.table_index_or_table_id = fib_index;
      a.flags = ((is_del ? IP6_ROUTE_FLAG_DEL : IP6_ROUTE_FLAG_ADD)
		 | IP6_ROUTE_FLAG_FIB_INDEX
		 | IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY
		 | (flags & IP6_ROUTE_FLAG_NO_REDISTRIBUTE));
      a.dst_address = dst_address[0];
      a.dst_address_length = dst_address_length;
      a.adj_index = new_mp ? new_mp->adj_index : dst_adj_index;
      a.add_adj = 0;
      a.n_add_adj = 0;

      ip6_add_del_route (im, &a);

      adj = ip_get_adjacency (lm, new_mp ? new_mp->adj_index : dst_adj_index);
      if (adj->n_adj == 1)
        adj->share_count += is_del ? -1 : 1;
    }

 done:
  if (error)
    clib_error_report (error);
}

u32
ip6_get_route (ip6_main_t * im,
	       u32 table_index_or_table_id,
	       u32 flags,
	       ip6_address_t * address,
	       u32 address_length)
{
  ip6_fib_t * fib = find_ip6_fib_by_table_index_or_id (im, table_index_or_table_id, flags);
  ip6_address_t masked_address;
  BVT(clib_bihash_kv) kv, value;

  ASSERT (address_length < ARRAY_LEN (im->fib_masks));
  clib_memcpy (&masked_address, address, sizeof (masked_address));
  ip6_address_mask (&masked_address, &im->fib_masks[address_length]);

  kv.key[0] = masked_address.as_u64[0];
  kv.key[1] = masked_address.as_u64[1];
  kv.key[2] = ((u64)((fib - im->fibs))<<32) | address_length;

  if (BV(clib_bihash_search)(&im->ip6_lookup_table, &kv, &value) == 0)
    return (value.value);
  return 0;
}

void
ip6_foreach_matching_route (ip6_main_t * im,
			    u32 table_index_or_table_id,
			    u32 flags,
			    ip6_address_t * dst_address,
			    u32 address_length,
			    ip6_address_t ** results,
			    u8 ** result_lengths)
{
  ip6_fib_t * fib = 
    find_ip6_fib_by_table_index_or_id (im, table_index_or_table_id, flags);
  BVT(clib_bihash) * h = &im->ip6_lookup_table;
  BVT(clib_bihash_value) * v;
  clib_bihash_bucket_t * b;
  int i, j, k;
  
  if (*results)
    _vec_len (*results) = 0;
  if (*result_lengths)
    _vec_len (*result_lengths) = 0;

  /* Walk the table looking for routes which match the supplied address */
  for (i = 0; i < h->nbuckets; i++)
    {
      b = &h->buckets [i];
      if (b->offset == 0)
          continue;

      v = BV(clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1<<b->log2_pages); j++)
        {
          for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
            {
              if (BV(clib_bihash_is_free)(&v->kvp[k]))
                continue;
              
              if ((v->kvp[k].key[2] 
                   == (((u64)((fib - im->fibs))<<32) | address_length))
                  && ip6_destination_matches_route 
                  (im, dst_address, (ip6_address_t *) &v->kvp[k], 
                   address_length))
                {
                  ip6_address_t * a;

                  a = (ip6_address_t *)(&v->kvp[k]);

                  vec_add1 (*results, a[0]);
                  vec_add1 (*result_lengths, address_length);
                }
            }
          v++;
        }
    }
}

void ip6_maybe_remap_adjacencies (ip6_main_t * im,
				  u32 table_index_or_table_id,
				  u32 flags)
{
#if SOONE
  ip6_fib_t * fib 
    = find_ip6_fib_by_table_index_or_id (im, table_index_or_table_id, flags);
#endif
  ip_lookup_main_t * lm = &im->lookup_main;

  if (lm->n_adjacency_remaps == 0)
    return;

  clib_warning ("unimplemented, please report to vpp-dev@cisco.com");

  /* All remaps have been performed. */
  lm->n_adjacency_remaps = 0;
}

void ip6_delete_matching_routes (ip6_main_t * im,
				 u32 table_index_or_table_id,
				 u32 flags,
				 ip6_address_t * address,
				 u32 address_length)
{
  /* $$$$ static may be OK - this should happen only on thread 0 */
  static ip6_address_t * matching_addresses;
  static u8 * matching_address_lengths;
  u32 l, i;
  ip6_add_del_route_args_t a;

  vlib_smp_unsafe_warning();

  a.flags = IP6_ROUTE_FLAG_DEL | IP6_ROUTE_FLAG_NO_REDISTRIBUTE | flags;
  a.table_index_or_table_id = table_index_or_table_id;
  a.adj_index = ~0;
  a.add_adj = 0;
  a.n_add_adj = 0;

  for (l = address_length + 1; l <= 128; l++)
    {
      ip6_foreach_matching_route (im, table_index_or_table_id, flags,
				  address,
				  l,
				  &matching_addresses,
				  &matching_address_lengths);
      for (i = 0; i < vec_len (matching_addresses); i++)
	{
	  a.dst_address = matching_addresses[i];
	  a.dst_address_length = matching_address_lengths[i];
	  ip6_add_del_route (im, &a);
	}
    }

  ip6_maybe_remap_adjacencies (im, table_index_or_table_id, flags);
}

void
ip6_forward_next_trace (vlib_main_t * vm,
                        vlib_node_runtime_t * node,
                        vlib_frame_t * frame,
                        vlib_rx_or_tx_t which_adj_index);

always_inline uword
ip6_lookup_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame,
		   int is_indirect)
{
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  vlib_combined_counter_main_t * cm = &im->lookup_main.adjacency_counters;
  u32 n_left_from, n_left_to_next, * from, * to_next;
  ip_lookup_next_t next;
  u32 cpu_index = os_get_cpu_number();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t * p0, * p1;
	  u32 pi0, pi1, adj_index0, adj_index1, wrong_next;
	  ip_lookup_next_t next0, next1;
	  ip6_header_t * ip0, * ip1;
	  ip_adjacency_t * adj0, * adj1;
	  ip6_address_t * dst_addr0, * dst_addr1;
          u32 fib_index0, fib_index1;
          u32 flow_hash_config0, flow_hash_config1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  if (PREDICT_FALSE(is_indirect))
	    {
	      ip_adjacency_t * iadj0, * iadj1;
	      iadj0 = ip_get_adjacency (lm, vnet_buffer(p0)->ip.adj_index[VLIB_TX]);
	      iadj1 = ip_get_adjacency (lm, vnet_buffer(p1)->ip.adj_index[VLIB_TX]);
	      dst_addr0 = &iadj0->indirect.next_hop.ip6;
	      dst_addr1 = &iadj1->indirect.next_hop.ip6;
	    }
	  else
	    {
	      dst_addr0 = &ip0->dst_address;
	      dst_addr1 = &ip1->dst_address;
	    }

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	  fib_index1 = vec_elt (im->fib_index_by_sw_if_index, vnet_buffer (p1)->sw_if_index[VLIB_RX]);

          fib_index0 = (vnet_buffer(p0)->sw_if_index[VLIB_TX] == (u32)~0) ?
            fib_index0 : vnet_buffer(p0)->sw_if_index[VLIB_TX];
          fib_index1 = (vnet_buffer(p1)->sw_if_index[VLIB_TX] == (u32)~0) ?
            fib_index1 : vnet_buffer(p1)->sw_if_index[VLIB_TX];

	  adj_index0 = ip6_fib_lookup_with_table (im, fib_index0, dst_addr0);
	  adj_index1 = ip6_fib_lookup_with_table (im, fib_index1, dst_addr1);

	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);

          if (PREDICT_FALSE (adj0->explicit_fib_index != ~0))
            {
              adj_index0 = ip6_fib_lookup_with_table 
                (im, adj0->explicit_fib_index, dst_addr0);
              adj0 = ip_get_adjacency (lm, adj_index0);
            }
          if (PREDICT_FALSE (adj1->explicit_fib_index != ~0))
            {
              adj_index1 = ip6_fib_lookup_with_table 
                (im, adj1->explicit_fib_index, dst_addr1);
              adj1 = ip_get_adjacency (lm, adj_index1);
            }

	  next0 = adj0->lookup_next_index;
	  next1 = adj1->lookup_next_index;

	  /* Only process the HBH Option Header if explicitly configured to do so */
          next0 = (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS) && im->hbh_enabled &&
	    adj_index0 ? (ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : adj0->lookup_next_index;
          next1 = (ip1->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS) && im->hbh_enabled &&
	    adj_index1 ? (ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : adj1->lookup_next_index;

          vnet_buffer (p0)->ip.flow_hash = 
            vnet_buffer(p1)->ip.flow_hash = 0;

          if (PREDICT_FALSE(adj0->n_adj > 1))
            {
              flow_hash_config0 = 
                vec_elt_at_index (im->fibs,fib_index0)->flow_hash_config;
              vnet_buffer (p0)->ip.flow_hash = 
                ip6_compute_flow_hash (ip0, flow_hash_config0);
            }

          if (PREDICT_FALSE(adj1->n_adj > 1))
            {
              flow_hash_config1 = 
                vec_elt_at_index (im->fibs,fib_index0)->flow_hash_config;

              vnet_buffer (p1)->ip.flow_hash = 
                ip6_compute_flow_hash (ip1, flow_hash_config1);
            }

	  ASSERT (adj0->n_adj > 0);
	  ASSERT (adj1->n_adj > 0);
	  ASSERT (is_pow2 (adj0->n_adj));
	  ASSERT (is_pow2 (adj1->n_adj));
	  adj_index0 += (vnet_buffer (p0)->ip.flow_hash & (adj0->n_adj - 1));
	  adj_index1 += (vnet_buffer (p1)->ip.flow_hash & (adj1->n_adj - 1));

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;
	  vnet_buffer (p1)->ip.adj_index[VLIB_TX] = adj_index1;

	  vlib_increment_combined_counter 
              (cm, cpu_index, adj_index0, 1,
               vlib_buffer_length_in_chain (vm, p0));
	  vlib_increment_combined_counter 
              (cm, cpu_index, adj_index1, 1,
               vlib_buffer_length_in_chain (vm, p1));

	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  wrong_next = (next0 != next) + 2*(next1 != next);
	  if (PREDICT_FALSE (wrong_next != 0))
            {
	      switch (wrong_next)
		{
		case 1:
		  /* A B A */
		  to_next[-2] = pi1;
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next0, pi0);
		  break;

		case 2:
		  /* A A B */
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next1, pi1);
		  break;

		case 3:
		  /* A B C */
		  to_next -= 2;
		  n_left_to_next += 2;
		  vlib_set_next_frame_buffer (vm, node, next0, pi0);
		  vlib_set_next_frame_buffer (vm, node, next1, pi1);
		  if (next0 == next1)
		    {
		      /* A B B */
		      vlib_put_next_frame (vm, node, next, n_left_to_next);
		      next = next1;
		      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
		    }
		}
	    }
	}
    
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip0;
	  u32 pi0, adj_index0;
	  ip_lookup_next_t next0;
	  ip_adjacency_t * adj0;
	  ip6_address_t * dst_addr0;
          u32 fib_index0, flow_hash_config0;

	  pi0 = from[0];
	  to_next[0] = pi0;

	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);

	  if (PREDICT_FALSE(is_indirect))
	    {
	      ip_adjacency_t * iadj0;
	      iadj0 = ip_get_adjacency (lm, vnet_buffer(p0)->ip.adj_index[VLIB_TX]);
	      dst_addr0 = &iadj0->indirect.next_hop.ip6;
	    }
	  else
	    {
	      dst_addr0 = &ip0->dst_address;
	    }

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, vnet_buffer (p0)->sw_if_index[VLIB_RX]);
          fib_index0 = (vnet_buffer(p0)->sw_if_index[VLIB_TX] == (u32)~0) ?
            fib_index0 : vnet_buffer(p0)->sw_if_index[VLIB_TX];

          flow_hash_config0 = 
              vec_elt_at_index (im->fibs,fib_index0)->flow_hash_config;

	  adj_index0 = ip6_fib_lookup_with_table (im, fib_index0, dst_addr0);

	  adj0 = ip_get_adjacency (lm, adj_index0);

          if (PREDICT_FALSE (adj0->explicit_fib_index != ~0))
            {
              adj_index0 = ip6_fib_lookup_with_table
                (im, adj0->explicit_fib_index, dst_addr0);
              adj0 = ip_get_adjacency (lm, adj_index0);
            }

	  /* Only process the HBH Option Header if explicitly configured to do so */
          next0 = (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS) && im->hbh_enabled &&
	    adj_index0 ? (ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : adj0->lookup_next_index;

          vnet_buffer (p0)->ip.flow_hash = 0;

          if (PREDICT_FALSE(adj0->n_adj > 1))
            {
              flow_hash_config0 = 
                vec_elt_at_index (im->fibs,fib_index0)->flow_hash_config;
              vnet_buffer (p0)->ip.flow_hash = 
                ip6_compute_flow_hash (ip0, flow_hash_config0);
            }

	  ASSERT (adj0->n_adj > 0);
	  ASSERT (is_pow2 (adj0->n_adj));
	  adj_index0 += (vnet_buffer (p0)->ip.flow_hash & (adj0->n_adj - 1));

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;

	  vlib_increment_combined_counter 
              (cm, cpu_index, adj_index0, 1,
               vlib_buffer_length_in_chain (vm, p0));

	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  if (PREDICT_FALSE (next0 != next))
	    {
	      n_left_to_next += 1;
	      vlib_put_next_frame (vm, node, next, n_left_to_next);
	      next = next0;
	      vlib_get_next_frame (vm, node, next,
				   to_next, n_left_to_next);
	      to_next[0] = pi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  if (node->flags & VLIB_NODE_FLAG_TRACE)
      ip6_forward_next_trace(vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

void ip6_adjacency_set_interface_route (vnet_main_t * vnm,
					ip_adjacency_t * adj,
					u32 sw_if_index,
					u32 if_address_index)
{
  vnet_hw_interface_t * hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  ip_lookup_next_t n;
  u32 node_index;

  if (hw->hw_class_index == ethernet_hw_interface_class.index
      || hw->hw_class_index == srp_hw_interface_class.index)
    {
      n = IP_LOOKUP_NEXT_ARP;
      node_index = ip6_discover_neighbor_node.index;
      adj->if_address_index = if_address_index;
      adj->arp.next_hop.ip6.as_u64[0] = 0;
      adj->arp.next_hop.ip6.as_u64[1] = 0;
  }
  else
    {
      n = IP_LOOKUP_NEXT_REWRITE;
      node_index = ip6_rewrite_node.index;
    }

 adj->lookup_next_index = n;
 adj->explicit_fib_index = ~0;

 vnet_rewrite_for_sw_interface
   (vnm,
    VNET_L3_PACKET_TYPE_IP6,
    sw_if_index,
    node_index,
    VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST,
    &adj->rewrite_header,
    sizeof (adj->rewrite_data));
}

static void
ip6_add_interface_routes (vnet_main_t * vnm, u32 sw_if_index,
			  ip6_main_t * im, u32 fib_index,
			  ip_interface_address_t * a)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_adjacency_t * adj;
  ip6_address_t * address = ip_interface_address_get_address (lm, a);
  ip6_add_del_route_args_t x;
  vnet_hw_interface_t * hw_if = vnet_get_sup_hw_interface (vnm, sw_if_index);
  u32 classify_table_index;

  /* Add e.g. 1.0.0.0/8 as interface route (arp for Ethernet). */
  x.table_index_or_table_id = fib_index;
  x.flags = (IP6_ROUTE_FLAG_ADD
	     | IP6_ROUTE_FLAG_FIB_INDEX
	     | IP6_ROUTE_FLAG_NO_REDISTRIBUTE);
  x.dst_address = address[0];
  x.dst_address_length = a->address_length;
  x.n_add_adj = 0;
  x.add_adj = 0;

  a->neighbor_probe_adj_index = ~0;
  if (a->address_length < 128)
    {
      adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
			      &x.adj_index);
      ip6_adjacency_set_interface_route (vnm, adj, sw_if_index, a - lm->if_address_pool);
      ip_call_add_del_adjacency_callbacks (lm, x.adj_index, /* is_del */ 0);
      ip6_add_del_route (im, &x);
      a->neighbor_probe_adj_index = x.adj_index;
    }

  /* Add e.g. ::1/128 as local to this host. */
  adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
			  &x.adj_index);

  classify_table_index = ~0;
  if (sw_if_index < vec_len (lm->classify_table_index_by_sw_if_index))
    classify_table_index = lm->classify_table_index_by_sw_if_index [sw_if_index];
  if (classify_table_index != (u32) ~0)
    {
      adj->lookup_next_index = IP_LOOKUP_NEXT_CLASSIFY;
      adj->classify.table_index = classify_table_index;
    }
  else
    adj->lookup_next_index = IP_LOOKUP_NEXT_LOCAL;
  
  adj->if_address_index = a - lm->if_address_pool;
  adj->rewrite_header.sw_if_index = sw_if_index;
  adj->rewrite_header.max_l3_packet_bytes = hw_if->max_l3_packet_bytes[VLIB_RX];
  adj->rewrite_header.data_bytes = 0;
  ip_call_add_del_adjacency_callbacks (lm, x.adj_index, /* is_del */ 0);
  x.dst_address_length = 128;
  ip6_add_del_route (im, &x);
}

static void
ip6_del_interface_routes (ip6_main_t * im, u32 fib_index,
			  ip6_address_t * address, u32 address_length)
{
  ip6_add_del_route_args_t x;

  /* Add e.g. 1.0.0.0/8 as interface route (arp for Ethernet). */
  x.table_index_or_table_id = fib_index;
  x.flags = (IP6_ROUTE_FLAG_DEL
	     | IP6_ROUTE_FLAG_FIB_INDEX
	     | IP6_ROUTE_FLAG_NO_REDISTRIBUTE);
  x.dst_address = address[0];
  x.dst_address_length = address_length;
  x.adj_index = ~0;
  x.n_add_adj = 0;
  x.add_adj = 0;

  if (address_length < 128)
    {
      /* Don't wipe out fe80::0/64 */
      if (address_length != 64 || 
          address[0].as_u64[0] != clib_net_to_host_u64(0xfe80000000000000ULL))
        ip6_add_del_route (im, &x);
    }

  x.dst_address_length = 128;
  ip6_add_del_route (im, &x);

  ip6_delete_matching_routes (im,
			      fib_index,
			      IP6_ROUTE_FLAG_FIB_INDEX,
			      address,
			      address_length);
}

typedef struct {
    u32 sw_if_index;
    ip6_address_t address;
    u32 length;
} ip6_interface_address_t;

static clib_error_t *
ip6_add_del_interface_address_internal (vlib_main_t * vm,
					u32 sw_if_index,
					ip6_address_t * new_address,
					u32 new_length,
					u32 redistribute,
					u32 insert_routes,
					u32 is_del);

static clib_error_t *
ip6_add_del_interface_address_internal (vlib_main_t * vm,
					u32 sw_if_index,
					ip6_address_t * address,
					u32 address_length,
					u32 redistribute,
					u32 insert_routes,
					u32 is_del)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  clib_error_t * error;
  u32 if_address_index;
  ip6_address_fib_t ip6_af, * addr_fib = 0;

  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  ip6_addr_fib_init (&ip6_af, address,
		     vec_elt (im->fib_index_by_sw_if_index, sw_if_index));
  vec_add1 (addr_fib, ip6_af);

  {
    uword elts_before = pool_elts (lm->if_address_pool);

    error = ip_interface_address_add_del
      (lm,
       sw_if_index,
       addr_fib,
       address_length,
       is_del,
       &if_address_index);
    if (error)
      goto done;

    /* Pool did not grow: add duplicate address. */
    if (elts_before == pool_elts (lm->if_address_pool))
      goto done;
  }

  if (vnet_sw_interface_is_admin_up (vnm, sw_if_index) && insert_routes)
    {
      if (is_del)
	ip6_del_interface_routes (im, ip6_af.fib_index, address,
				  address_length);

      else
	ip6_add_interface_routes (vnm, sw_if_index,
				  im, ip6_af.fib_index,
				  pool_elt_at_index (lm->if_address_pool, if_address_index));
    }

  {
    ip6_add_del_interface_address_callback_t * cb;
    vec_foreach (cb, im->add_del_interface_address_callbacks)
      cb->function (im, cb->function_opaque, sw_if_index,
		    address, address_length,
		    if_address_index,
		    is_del);
  }

 done:
  vec_free (addr_fib);
  return error;
}

clib_error_t *
ip6_add_del_interface_address (vlib_main_t * vm, u32 sw_if_index,
			       ip6_address_t * address, u32 address_length,
			       u32 is_del)
{
  return ip6_add_del_interface_address_internal
    (vm, sw_if_index, address, address_length,
     /* redistribute */ 1,
     /* insert_routes */ 1,
     is_del);
}

clib_error_t *
ip6_sw_interface_admin_up_down (vnet_main_t * vnm,
				u32 sw_if_index,
				u32 flags)
{
  ip6_main_t * im = &ip6_main;
  ip_interface_address_t * ia;
  ip6_address_t * a;
  u32 is_admin_up, fib_index;

  /* Fill in lookup tables with default table (0). */
  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);

  vec_validate_init_empty (im->lookup_main.if_address_pool_index_by_sw_if_index, sw_if_index, ~0);

  is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  fib_index = vec_elt (im->fib_index_by_sw_if_index, sw_if_index);

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

  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ip6_sw_interface_admin_up_down);

/* Built-in ip6 unicast rx feature path definition */
VNET_IP6_UNICAST_FEATURE_INIT (ip6_inacl, static) = {
  .node_name = "ip6-inacl", 
  .runs_before = ORDER_CONSTRAINTS {"ip6-policer-classify", 0},
  .feature_index = &ip6_main.ip6_unicast_rx_feature_check_access,
};

VNET_IP6_UNICAST_FEATURE_INIT (ip6_policer_classify, static) = {
  .node_name = "ip6-policer-classify",
  .runs_before = ORDER_CONSTRAINTS {"ipsec-input-ip6", 0},
  .feature_index = &ip6_main.ip6_unicast_rx_feature_policer_classify,
};

VNET_IP6_UNICAST_FEATURE_INIT (ip6_ipsec, static) = {
  .node_name = "ipsec-input-ip6",
  .runs_before = ORDER_CONSTRAINTS {"l2tp-decap", 0},
  .feature_index = &ip6_main.ip6_unicast_rx_feature_ipsec,
};

VNET_IP6_UNICAST_FEATURE_INIT (ip6_l2tp, static) = {
  .node_name = "l2tp-decap",
  .runs_before = ORDER_CONSTRAINTS {"vpath-input-ip6", 0},
  .feature_index = &ip6_main.ip6_unicast_rx_feature_l2tp_decap,
};

VNET_IP6_UNICAST_FEATURE_INIT (ip6_vpath, static) = {
  .node_name = "vpath-input-ip6",
  .runs_before = ORDER_CONSTRAINTS {"ip6-lookup", 0},
  .feature_index = &ip6_main.ip6_unicast_rx_feature_vpath,
};

VNET_IP6_UNICAST_FEATURE_INIT (ip6_lookup, static) = {
  .node_name = "ip6-lookup",
  .runs_before = 0, /* not before any other features */
  .feature_index = &ip6_main.ip6_unicast_rx_feature_lookup,
};

/* Built-in ip6 multicast rx feature path definition (none now) */
VNET_IP6_MULTICAST_FEATURE_INIT (ip6_vpath_mc, static) = {
  .node_name = "vpath-input-ip6",
  .runs_before = ORDER_CONSTRAINTS {"ip6-lookup", 0},
  .feature_index = &ip6_main.ip6_multicast_rx_feature_vpath,
};

VNET_IP6_MULTICAST_FEATURE_INIT (ip6_lookup, static) = {
  .node_name = "ip6-lookup",
  .runs_before = 0, /* not before any other features */
  .feature_index = &ip6_main.ip6_multicast_rx_feature_lookup,
};

static char * rx_feature_start_nodes[] = 
  {"ip6-input"};

static char * tx_feature_start_nodes[] = 
  {"ip6-rewrite"};

/* Built-in ip4 tx feature path definition */
VNET_IP6_TX_FEATURE_INIT (interface_output, static) = {
  .node_name = "interface-output",
  .runs_before = 0, /* not before any other features */
  .feature_index = &ip6_main.ip6_tx_feature_interface_output,
};

static clib_error_t *
ip6_feature_init (vlib_main_t * vm, ip6_main_t * im)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  clib_error_t * error;
  vnet_cast_t cast;
  ip_config_main_t * cm;
  vnet_config_main_t * vcm;
  char **feature_start_nodes;
  int feature_start_len;
  
  for (cast = 0; cast < VNET_N_IP_FEAT; cast++)
    {
      cm = &lm->feature_config_mains[cast];
      vcm = &cm->config_main;
      
      if (cast < VNET_IP_TX_FEAT)
        {
          feature_start_nodes = rx_feature_start_nodes;
          feature_start_len = ARRAY_LEN(rx_feature_start_nodes);
        }
      else
        {
          feature_start_nodes = tx_feature_start_nodes;
          feature_start_len = ARRAY_LEN(tx_feature_start_nodes);
        }

      if ((error = ip_feature_init_cast (vm, cm, vcm, 
                                         feature_start_nodes,
                                         feature_start_len,
                                         cast,
                                         0 /* is_ip4 */)))
        return error;
    }
  return 0;
}

clib_error_t *
ip6_sw_interface_add_del (vnet_main_t * vnm,
			  u32 sw_if_index,
			  u32 is_add)
{
  vlib_main_t * vm = vnm->vlib_main;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 ci, cast;
  u32 feature_index;

  for (cast = 0; cast < VNET_N_IP_FEAT; cast++)
    {
      ip_config_main_t * cm = &lm->feature_config_mains[cast];
      vnet_config_main_t * vcm = &cm->config_main;

      vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
      ci = cm->config_index_by_sw_if_index[sw_if_index];

      if (cast == VNET_IP_RX_UNICAST_FEAT)
        feature_index = im->ip6_unicast_rx_feature_lookup;
      else if (cast == VNET_IP_RX_MULTICAST_FEAT)
        feature_index = im->ip6_multicast_rx_feature_lookup;
      else 
        feature_index = im->ip6_tx_feature_interface_output;

      if (is_add)
	ci = vnet_config_add_feature (vm, vcm,
				      ci,
                                      feature_index,
				      /* config data */ 0,
				      /* # bytes of config data */ 0);
      else
	ci = vnet_config_del_feature (vm, vcm,
				      ci,
                                      feature_index,
				      /* config data */ 0,
				      /* # bytes of config data */ 0);

      cm->config_index_by_sw_if_index[sw_if_index] = ci;
      /* 
       * note: do not update the tx feature count here.
       */
    }
  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip6_sw_interface_add_del);

static uword
ip6_lookup (vlib_main_t * vm,
	    vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return ip6_lookup_inline (vm, node, frame, /* is_indirect */ 0);
}

static u8 * format_ip6_lookup_trace (u8 * s, va_list * args);

VLIB_REGISTER_NODE (ip6_lookup_node) = {
  .function = ip6_lookup,
  .name = "ip6-lookup",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_lookup_trace,

  .n_next_nodes = IP6_LOOKUP_N_NEXT,
  .next_nodes = IP6_LOOKUP_NEXT_NODES,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_lookup_node, ip6_lookup);

static uword
ip6_indirect (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return ip6_lookup_inline (vm, node, frame, /* is_indirect */ 1);
}


VLIB_REGISTER_NODE (ip6_indirect_node) = {
  .function = ip6_indirect,
  .name = "ip6-indirect",
  .vector_size = sizeof (u32),
  .sibling_of = "ip6-lookup",
  .format_trace = format_ip6_lookup_trace,
  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_indirect_node, ip6_indirect);

typedef struct {
  /* Adjacency taken. */
  u32 adj_index;
  u32 flow_hash;
  u32 fib_index;

  /* Packet data, possibly *after* rewrite. */
  u8 packet_data[128 - 1*sizeof(u32)];
} ip6_forward_next_trace_t;

static u8 * format_ip6_forward_next_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_forward_next_trace_t * t = va_arg (*args, ip6_forward_next_trace_t *);
  uword indent = format_get_indent (s);

  s = format(s, "%U%U",
             format_white_space, indent,
             format_ip6_header, t->packet_data);
  return s;
}

static u8 * format_ip6_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_forward_next_trace_t * t = va_arg (*args, ip6_forward_next_trace_t *);
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im = &ip6_main;
  uword indent = format_get_indent (s);

  s = format (s, "fib %d adj-idx %d : %U flow hash: 0x%08x",
              t->fib_index, t->adj_index, format_ip_adjacency,
              vnm, &im->lookup_main, t->adj_index, t->flow_hash);
  s = format(s, "\n%U%U",
             format_white_space, indent,
             format_ip6_header, t->packet_data);
  return s;
}


static u8 * format_ip6_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_forward_next_trace_t * t = va_arg (*args, ip6_forward_next_trace_t *);
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im = &ip6_main;
  uword indent = format_get_indent (s);

  s = format (s, "tx_sw_if_index %d adj-idx %d : %U flow hash: 0x%08x",
              t->fib_index, t->adj_index, format_ip_adjacency,
              vnm, &im->lookup_main, t->adj_index, t->flow_hash);
  s = format (s, "\n%U%U",
              format_white_space, indent,
              format_ip_adjacency_packet_data,
              vnm, &im->lookup_main, t->adj_index,
              t->packet_data, sizeof (t->packet_data));
  return s;
}

/* Common trace function for all ip6-forward next nodes. */
void
ip6_forward_next_trace (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame,
			vlib_rx_or_tx_t which_adj_index)
{
  u32 * from, n_left;
  ip6_main_t * im = &ip6_main;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t * b0, * b1;
      ip6_forward_next_trace_t * t0, * t1;

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
          t0->fib_index = (vnet_buffer(b0)->sw_if_index[VLIB_TX] != (u32)~0) ?
              vnet_buffer(b0)->sw_if_index[VLIB_TX] :
              vec_elt (im->fib_index_by_sw_if_index,
                       vnet_buffer(b0)->sw_if_index[VLIB_RX]);

	  clib_memcpy (t0->packet_data,
		  vlib_buffer_get_current (b0),
		  sizeof (t0->packet_data));
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
	  t1->adj_index = vnet_buffer (b1)->ip.adj_index[which_adj_index];
          t1->flow_hash = vnet_buffer (b1)->ip.flow_hash;
          t1->fib_index = (vnet_buffer(b1)->sw_if_index[VLIB_TX] != (u32)~0) ?
              vnet_buffer(b1)->sw_if_index[VLIB_TX] :
              vec_elt (im->fib_index_by_sw_if_index,
                       vnet_buffer(b1)->sw_if_index[VLIB_RX]);

	  clib_memcpy (t1->packet_data,
		  vlib_buffer_get_current (b1),
		  sizeof (t1->packet_data));
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      ip6_forward_next_trace_t * t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
	  t0->adj_index = vnet_buffer (b0)->ip.adj_index[which_adj_index];
          t0->flow_hash = vnet_buffer (b0)->ip.flow_hash;
          t0->fib_index = (vnet_buffer(b0)->sw_if_index[VLIB_TX] != (u32)~0) ?
              vnet_buffer(b0)->sw_if_index[VLIB_TX] :
              vec_elt (im->fib_index_by_sw_if_index,
                       vnet_buffer(b0)->sw_if_index[VLIB_RX]);

	  clib_memcpy (t0->packet_data,
		  vlib_buffer_get_current (b0),
		  sizeof (t0->packet_data));
	}
      from += 1;
      n_left -= 1;
    }
}

static uword
ip6_drop_or_punt (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame,
		  ip6_error_t error_code)
{
  u32 * buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;

  vlib_error_drop_buffers (vm, node,
			   buffers,
			   /* stride */ 1,
			   n_packets,
			   /* next */ 0,
			   ip6_input_node.index,
			   error_code);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  return n_packets;
}

static uword
ip6_drop (vlib_main_t * vm,
	  vlib_node_runtime_t * node,
	  vlib_frame_t * frame)
{ return ip6_drop_or_punt (vm, node, frame, IP6_ERROR_ADJACENCY_DROP); }

static uword
ip6_punt (vlib_main_t * vm,
	  vlib_node_runtime_t * node,
	  vlib_frame_t * frame)
{ return ip6_drop_or_punt (vm, node, frame, IP6_ERROR_ADJACENCY_PUNT); }

static uword
ip6_miss (vlib_main_t * vm,
	  vlib_node_runtime_t * node,
	  vlib_frame_t * frame)
{ return ip6_drop_or_punt (vm, node, frame, IP6_ERROR_DST_LOOKUP_MISS); }

VLIB_REGISTER_NODE (ip6_drop_node,static) = {
  .function = ip6_drop,
  .name = "ip6-drop",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_drop_node, ip6_drop);

VLIB_REGISTER_NODE (ip6_punt_node,static) = {
  .function = ip6_punt,
  .name = "ip6-punt",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-punt",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_punt_node, ip6_punt);

VLIB_REGISTER_NODE (ip6_miss_node,static) = {
  .function = ip6_miss,
  .name = "ip6-miss",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_miss_node, ip6_miss);

VLIB_REGISTER_NODE (ip6_multicast_node,static) = {
  .function = ip6_drop,
  .name = "ip6-multicast",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

/* Compute TCP/UDP/ICMP6 checksum in software. */
u16 ip6_tcp_udp_icmp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0, ip6_header_t * ip0, int *bogus_lengthp)
{
  ip_csum_t sum0;
  u16 sum16, payload_length_host_byte_order;
  u32 i, n_this_buffer, n_bytes_left;
  u32 headers_size = sizeof(ip0[0]);
  void * data_this_buffer;

  ASSERT(bogus_lengthp);
  *bogus_lengthp = 0;

  /* Initialize checksum with ip header. */
  sum0 = ip0->payload_length + clib_host_to_net_u16 (ip0->protocol);
  payload_length_host_byte_order = clib_net_to_host_u16 (ip0->payload_length);
  data_this_buffer = (void *) (ip0 + 1);
 
  for (i = 0; i < ARRAY_LEN (ip0->src_address.as_uword); i++)
    {
      sum0 = ip_csum_with_carry (sum0,
				 clib_mem_unaligned (&ip0->src_address.as_uword[i], uword));
      sum0 = ip_csum_with_carry (sum0,
				 clib_mem_unaligned (&ip0->dst_address.as_uword[i], uword));
    }

  /* some icmp packets may come with a "router alert" hop-by-hop extension header (e.g., mldv2 packets) */
  if (PREDICT_FALSE (ip0->protocol ==  IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
    {
      u32  skip_bytes;
      ip6_hop_by_hop_ext_t *ext_hdr = (ip6_hop_by_hop_ext_t  *)data_this_buffer;

      /* validate really icmp6 next */
      ASSERT(ext_hdr->next_hdr == IP_PROTOCOL_ICMP6);

      skip_bytes = 8* (1 + ext_hdr->n_data_u64s);
      data_this_buffer  = (void *)((u8 *)data_this_buffer + skip_bytes);
 
      payload_length_host_byte_order  -= skip_bytes;
      headers_size += skip_bytes;
   }

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
#if DPDK > 0
  if (p0 && n_this_buffer + headers_size  > p0->current_length)
  {
    struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer(p0);
    u8 nb_segs = mb->nb_segs;

    n_this_buffer = (p0->current_length > headers_size ?
		     p0->current_length - headers_size : 0);
    while (n_bytes_left)
      {
	sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
	n_bytes_left -= n_this_buffer;

	mb = mb->next;
	nb_segs--;
	if ((nb_segs == 0) || (mb == 0))
	  break;

	data_this_buffer = rte_ctrlmbuf_data(mb);
	n_this_buffer = mb->data_len;
      }
    if (n_bytes_left || nb_segs)
      {
	*bogus_lengthp = 1;
	return 0xfefe;
      }
  } 
  else sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
#else
  if (p0 && n_this_buffer + headers_size  > p0->current_length)
    n_this_buffer = p0->current_length > headers_size  ? p0->current_length - headers_size  : 0;
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
#endif /* DPDK */

  sum16 = ~ ip_csum_fold (sum0);

  return sum16;
}

u32 ip6_tcp_udp_icmp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0)
{
  ip6_header_t * ip0 = vlib_buffer_get_current (p0);
  udp_header_t * udp0;
  u16 sum16;
  int bogus_length;

  /* some icmp packets may come with a "router alert" hop-by-hop extension header (e.g., mldv2 packets) */
  ASSERT (ip0->protocol == IP_PROTOCOL_TCP
	  || ip0->protocol == IP_PROTOCOL_ICMP6
	  || ip0->protocol == IP_PROTOCOL_UDP
	  || ip0->protocol ==  IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS);

  udp0 = (void *) (ip0 + 1);
  if (ip0->protocol == IP_PROTOCOL_UDP && udp0->checksum == 0)
    {
      p0->flags |= (IP_BUFFER_L4_CHECKSUM_COMPUTED
		    | IP_BUFFER_L4_CHECKSUM_CORRECT);
      return p0->flags;
    }

  sum16 = ip6_tcp_udp_icmp_compute_checksum (vm, p0, ip0, &bogus_length);

  p0->flags |= (IP_BUFFER_L4_CHECKSUM_COMPUTED
		| ((sum16 == 0) << LOG2_IP_BUFFER_L4_CHECKSUM_CORRECT));

  return p0->flags;
}

static uword
ip6_local (vlib_main_t * vm,
	   vlib_node_runtime_t * node,
	   vlib_frame_t * frame)
{
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_local_next_t next_index;
  u32 * from, * to_next, n_left_from, n_left_to_next;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip6_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t * p0, * p1;
	  ip6_header_t * ip0, * ip1;
	  udp_header_t * udp0, * udp1;
	  u32 pi0, ip_len0, udp_len0, flags0, next0;
	  u32 pi1, ip_len1, udp_len1, flags1, next1;
	  i32 len_diff0, len_diff1;
	  u8 error0, type0, good_l4_checksum0;
	  u8 error1, type1, good_l4_checksum1;
      
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

	  type0 = lm->builtin_protocol_by_ip_protocol[ip0->protocol];
	  type1 = lm->builtin_protocol_by_ip_protocol[ip1->protocol];

	  next0 = lm->local_next_by_ip_protocol[ip0->protocol];
	  next1 = lm->local_next_by_ip_protocol[ip1->protocol];

	  flags0 = p0->flags;
	  flags1 = p1->flags;

	  good_l4_checksum0 = (flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
	  good_l4_checksum1 = (flags1 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;

	  udp0 = ip6_next_header (ip0);
	  udp1 = ip6_next_header (ip1);

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_l4_checksum0 |= type0 == IP_BUILTIN_PROTOCOL_UDP && udp0->checksum == 0;
	  good_l4_checksum1 |= type1 == IP_BUILTIN_PROTOCOL_UDP && udp1->checksum == 0;

	  good_l4_checksum0 |= type0 == IP_BUILTIN_PROTOCOL_UNKNOWN;
	  good_l4_checksum1 |= type1 == IP_BUILTIN_PROTOCOL_UNKNOWN;

	  /* Verify UDP length. */
	  ip_len0 = clib_net_to_host_u16 (ip0->payload_length);
	  ip_len1 = clib_net_to_host_u16 (ip1->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  udp_len1 = clib_net_to_host_u16 (udp1->length);

	  len_diff0 = ip_len0 - udp_len0;
	  len_diff1 = ip_len1 - udp_len1;

	  len_diff0 = type0 == IP_BUILTIN_PROTOCOL_UDP ? len_diff0 : 0;
	  len_diff1 = type1 == IP_BUILTIN_PROTOCOL_UDP ? len_diff1 : 0;

	  if (PREDICT_FALSE (type0 != IP_BUILTIN_PROTOCOL_UNKNOWN
			     && ! good_l4_checksum0
			     && ! (flags0 & IP_BUFFER_L4_CHECKSUM_COMPUTED)))
	    {
	      flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, p0);
	      good_l4_checksum0 =
		(flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
	    }
	  if (PREDICT_FALSE (type1 != IP_BUILTIN_PROTOCOL_UNKNOWN
			     && ! good_l4_checksum1
			     && ! (flags1 & IP_BUFFER_L4_CHECKSUM_COMPUTED)))
	    {
	      flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, p1);
	      good_l4_checksum1 =
		(flags1 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
	    }

	  error0 = error1 = IP6_ERROR_UNKNOWN_PROTOCOL;

	  error0 = len_diff0 < 0 ? IP6_ERROR_UDP_LENGTH : error0;
	  error1 = len_diff1 < 0 ? IP6_ERROR_UDP_LENGTH : error1;

	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_UDP == IP6_ERROR_UDP_CHECKSUM);
	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_ICMP == IP6_ERROR_ICMP_CHECKSUM);
	  error0 = (! good_l4_checksum0
		    ? IP6_ERROR_UDP_CHECKSUM + type0
		    : error0);
	  error1 = (! good_l4_checksum1
		    ? IP6_ERROR_UDP_CHECKSUM + type1
		    : error1);

	  /* Drop packets from unroutable hosts. */
          /* If this is a neighbor solicitation (ICMP), skip source RPF check */
	  if (error0 == IP6_ERROR_UNKNOWN_PROTOCOL && type0 != IP_BUILTIN_PROTOCOL_ICMP)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);
	      error0 = (lm->miss_adj_index == src_adj_index0
			? IP6_ERROR_SRC_LOOKUP_MISS
			: error0);
	    }
	  if (error1 == IP6_ERROR_UNKNOWN_PROTOCOL && type1 != IP_BUILTIN_PROTOCOL_ICMP)
	    {
	      u32 src_adj_index1 = ip6_src_lookup_for_packet (im, p1, ip1);
	      error1 = (lm->miss_adj_index == src_adj_index1
			? IP6_ERROR_SRC_LOOKUP_MISS
			: error1);
	    }

	  next0 = error0 != IP6_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;
	  next1 = error1 != IP6_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next1;

	  p0->error = error_node->errors[error0];
	  p1->error = error_node->errors[error1];

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip0;
	  udp_header_t * udp0;
	  u32 pi0, ip_len0, udp_len0, flags0, next0;
	  i32 len_diff0;
	  u8 error0, type0, good_l4_checksum0;
      
	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);

	  type0 = lm->builtin_protocol_by_ip_protocol[ip0->protocol];
	  next0 = lm->local_next_by_ip_protocol[ip0->protocol];

	  flags0 = p0->flags;

	  good_l4_checksum0 = (flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;

	  udp0 = ip6_next_header (ip0);

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_l4_checksum0 |= type0 == IP_BUILTIN_PROTOCOL_UDP && udp0->checksum == 0;

	  good_l4_checksum0 |= type0 == IP_BUILTIN_PROTOCOL_UNKNOWN;

	  /* Verify UDP length. */
	  ip_len0 = clib_net_to_host_u16 (ip0->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);

	  len_diff0 = ip_len0 - udp_len0;

	  len_diff0 = type0 == IP_BUILTIN_PROTOCOL_UDP ? len_diff0 : 0;

	  if (PREDICT_FALSE (type0 != IP_BUILTIN_PROTOCOL_UNKNOWN
			     && ! good_l4_checksum0
			     && ! (flags0 & IP_BUFFER_L4_CHECKSUM_COMPUTED)))
	    {
	      flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, p0);
	      good_l4_checksum0 =
		(flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
	    }

	  error0 = IP6_ERROR_UNKNOWN_PROTOCOL;

	  error0 = len_diff0 < 0 ? IP6_ERROR_UDP_LENGTH : error0;

	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_UDP == IP6_ERROR_UDP_CHECKSUM);
	  ASSERT (IP6_ERROR_UDP_CHECKSUM + IP_BUILTIN_PROTOCOL_ICMP == IP6_ERROR_ICMP_CHECKSUM);
	  error0 = (! good_l4_checksum0
		    ? IP6_ERROR_UDP_CHECKSUM + type0
		    : error0);

          /* If this is a neighbor solicitation (ICMP), skip source RPF check */
	  if (error0 == IP6_ERROR_UNKNOWN_PROTOCOL && type0 != IP_BUILTIN_PROTOCOL_ICMP)
	    {
	      u32 src_adj_index0 = ip6_src_lookup_for_packet (im, p0, ip0);
	      error0 = (lm->miss_adj_index == src_adj_index0
			? IP6_ERROR_SRC_LOOKUP_MISS
			: error0);
	    }

	  next0 = error0 != IP6_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;

	  p0->error = error_node->errors[error0];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}
  
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_local_node,static) = {
  .function = ip6_local,
  .name = "ip6-local",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_forward_next_trace,

  .n_next_nodes = IP_LOCAL_N_NEXT,
  .next_nodes = {
    [IP_LOCAL_NEXT_DROP] = "error-drop",
    [IP_LOCAL_NEXT_PUNT] = "error-punt",
    [IP_LOCAL_NEXT_UDP_LOOKUP] = "ip6-udp-lookup",
    [IP_LOCAL_NEXT_ICMP] = "ip6-icmp-input",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_local_node, ip6_local);

void ip6_register_protocol (u32 protocol, u32 node_index)
{
  vlib_main_t * vm = vlib_get_main();
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;

  ASSERT (protocol < ARRAY_LEN (lm->local_next_by_ip_protocol));
  lm->local_next_by_ip_protocol[protocol] = vlib_node_add_next (vm, ip6_local_node.index, node_index);
}

typedef enum {
  IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
  IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX,
  IP6_DISCOVER_NEIGHBOR_N_NEXT,
} ip6_discover_neighbor_next_t;

typedef enum {
  IP6_DISCOVER_NEIGHBOR_ERROR_DROP,
  IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT,
  IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS,
} ip6_discover_neighbor_error_t;

static uword
ip6_discover_neighbor (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 * from, * to_next_drop;
  uword n_left_from, n_left_to_next_drop;
  static f64 time_last_seed_change = -1e100;
  static u32 hash_seeds[3];
  static uword hash_bitmap[256 / BITS (uword)]; 
  f64 time_now;
  int bogus_length;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip6_forward_next_trace (vm, node, frame, VLIB_TX);

  time_now = vlib_time_now (vm);
  if (time_now - time_last_seed_change > 1e-3)
    {
      uword i;
      u32 * r = clib_random_buffer_get_data (&vm->random_buffer,
					     sizeof (hash_seeds));
      for (i = 0; i < ARRAY_LEN (hash_seeds); i++)
	hash_seeds[i] = r[i];

      /* Mark all hash keys as been not-seen before. */
      for (i = 0; i < ARRAY_LEN (hash_bitmap); i++)
	hash_bitmap[i] = 0;

      time_last_seed_change = time_now;
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, IP6_DISCOVER_NEIGHBOR_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  vlib_buffer_t * p0;
	  ip6_header_t * ip0;
	  u32 pi0, adj_index0, a0, b0, c0, m0, sw_if_index0, drop0;
	  uword bm0;
	  ip_adjacency_t * adj0;
          vnet_hw_interface_t * hw_if0;
	  u32 next0;

	  pi0 = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];

	  ip0 = vlib_buffer_get_current (p0);

	  adj0 = ip_get_adjacency (lm, adj_index0);

	  if (adj0->arp.next_hop.ip6.as_u64[0] ||
	      adj0->arp.next_hop.ip6.as_u64[1]) {
	    ip0->dst_address.as_u64[0] = adj0->arp.next_hop.ip6.as_u64[0];
	    ip0->dst_address.as_u64[1] = adj0->arp.next_hop.ip6.as_u64[1];
	  }

	  a0 = hash_seeds[0];
	  b0 = hash_seeds[1];
	  c0 = hash_seeds[2];

	  sw_if_index0 = adj0->rewrite_header.sw_if_index;
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  a0 ^= sw_if_index0;
	  b0 ^= ip0->dst_address.as_u32[0];
	  c0 ^= ip0->dst_address.as_u32[1];

	  hash_v3_mix32 (a0, b0, c0);

	  b0 ^= ip0->dst_address.as_u32[2];
	  c0 ^= ip0->dst_address.as_u32[3];

	  hash_v3_finalize32 (a0, b0, c0);

	  c0 &= BITS (hash_bitmap) - 1;
	  c0 = c0 / BITS (uword);
	  m0 = (uword) 1 << (c0 % BITS (uword));

	  bm0 = hash_bitmap[c0];
	  drop0 = (bm0 & m0) != 0;

	  /* Mark it as seen. */
	  hash_bitmap[c0] = bm0 | m0;

	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = pi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

          hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

          /* If the interface is link-down, drop the pkt */
          if (!(hw_if0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
            drop0 = 1;

	  p0->error = 
            node->errors[drop0 ? IP6_DISCOVER_NEIGHBOR_ERROR_DROP 
                         : IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT];
	  if (drop0)
	    continue;

	  {
	    u32 bi0 = 0;
	    icmp6_neighbor_solicitation_header_t * h0;
	    vlib_buffer_t * b0;

	    h0 = vlib_packet_template_get_packet 
              (vm, &im->discover_neighbor_packet_template, &bi0);

	    /* 
             * Build ethernet header.
             * Choose source address based on destination lookup 
             * adjacency. 
             */
	    if (ip6_src_address_for_packet (im, p0, &h0->ip.src_address,
	                                        sw_if_index0)) {
		//There is no address on the interface
		p0->error = node->errors[IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS];
		vlib_buffer_free(vm, &bi0, 1);
		continue;
	    }

	    /* 
             * Destination address is a solicited node multicast address.  
             * We need to fill in
             * the low 24 bits with low 24 bits of target's address. 
             */
	    h0->ip.dst_address.as_u8[13] = ip0->dst_address.as_u8[13];
	    h0->ip.dst_address.as_u8[14] = ip0->dst_address.as_u8[14];
	    h0->ip.dst_address.as_u8[15] = ip0->dst_address.as_u8[15];

	    h0->neighbor.target_address = ip0->dst_address;

	    clib_memcpy (h0->link_layer_option.ethernet_address, 
                    hw_if0->hw_address, vec_len (hw_if0->hw_address));

            /* $$$$ appears we need this; why is the checksum non-zero? */
            h0->neighbor.icmp.checksum = 0;
	    h0->neighbor.icmp.checksum = 
              ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h0->ip, 
                                                 &bogus_length);

            ASSERT (bogus_length == 0);

	    vlib_buffer_copy_trace_flag (vm, p0, bi0);
	    b0 = vlib_get_buffer (vm, bi0);
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] 
              = vnet_buffer (p0)->sw_if_index[VLIB_TX];

	    /* Add rewrite/encap string. */
	    vnet_rewrite_one_header (adj0[0], h0, 
                                     sizeof (ethernet_header_t));
	    vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);

	    next0 = IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX;

	    vlib_set_next_frame_buffer (vm, node, next0, bi0);
	  }
	}

      vlib_put_next_frame (vm, node, IP6_DISCOVER_NEIGHBOR_NEXT_DROP, 
                           n_left_to_next_drop);
    }

  return frame->n_vectors;
}

static char * ip6_discover_neighbor_error_strings[] = {
  [IP6_DISCOVER_NEIGHBOR_ERROR_DROP] = "address overflow drops",
  [IP6_DISCOVER_NEIGHBOR_ERROR_REQUEST_SENT] 
  = "neighbor solicitations sent",
  [IP6_DISCOVER_NEIGHBOR_ERROR_NO_SOURCE_ADDRESS]
    = "no source address for ND solicitation",
};

VLIB_REGISTER_NODE (ip6_discover_neighbor_node) = {
  .function = ip6_discover_neighbor,
  .name = "ip6-discover-neighbor",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_forward_next_trace,

  .n_errors = ARRAY_LEN (ip6_discover_neighbor_error_strings),
  .error_strings = ip6_discover_neighbor_error_strings,

  .n_next_nodes = IP6_DISCOVER_NEIGHBOR_N_NEXT,
  .next_nodes = {
    [IP6_DISCOVER_NEIGHBOR_NEXT_DROP] = "error-drop",
    [IP6_DISCOVER_NEIGHBOR_NEXT_REPLY_TX] = "interface-output",
  },
};

clib_error_t *
ip6_probe_neighbor (vlib_main_t * vm, ip6_address_t * dst, u32 sw_if_index)
{
  vnet_main_t * vnm = vnet_get_main();
  ip6_main_t * im = &ip6_main;
  icmp6_neighbor_solicitation_header_t * h;
  ip6_address_t * src;
  ip_interface_address_t * ia;
  ip_adjacency_t * adj;
  vnet_hw_interface_t * hi;
  vnet_sw_interface_t * si;
  vlib_buffer_t * b;
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

  src = ip6_interface_address_matching_destination (im, dst, sw_if_index, &ia);
  if (! src)
    {
      vnm->api_errno = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      return clib_error_return 
        (0, "no matching interface address for destination %U (interface %U)",
         format_ip6_address, dst,
         format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

  h = vlib_packet_template_get_packet (vm, &im->discover_neighbor_packet_template, &bi);

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  /* Destination address is a solicited node multicast address.  We need to fill in
     the low 24 bits with low 24 bits of target's address. */
  h->ip.dst_address.as_u8[13] = dst->as_u8[13];
  h->ip.dst_address.as_u8[14] = dst->as_u8[14];
  h->ip.dst_address.as_u8[15] = dst->as_u8[15];

  h->ip.src_address = src[0];
  h->neighbor.target_address = dst[0];

  clib_memcpy (h->link_layer_option.ethernet_address, hi->hw_address, vec_len (hi->hw_address));

  h->neighbor.icmp.checksum = 
    ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h->ip, &bogus_length);
  ASSERT(bogus_length == 0);

  b = vlib_get_buffer (vm, bi);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  /* Add encapsulation string for software interface (e.g. ethernet header). */
  adj = ip_get_adjacency (&im->lookup_main, ia->neighbor_probe_adj_index);
  vnet_rewrite_one_header (adj[0], h, sizeof (ethernet_header_t));
  vlib_buffer_advance (b, -adj->rewrite_header.data_bytes);

  {
    vlib_frame_t * f = vlib_get_frame_to_node (vm, hi->output_node_index);
    u32 * to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, hi->output_node_index, f);
  }

  return /* no error */ 0;
}

typedef enum {
  IP6_REWRITE_NEXT_DROP,
  IP6_REWRITE_NEXT_ICMP_ERROR,
} ip6_rewrite_next_t;

always_inline uword
ip6_rewrite_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    int rewrite_for_locally_received_packets)
{
  ip_lookup_main_t * lm = &ip6_main.lookup_main;
  u32 * from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, * to_next, next_index;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip6_input_node.index);
  vlib_rx_or_tx_t adj_rx_tx = rewrite_for_locally_received_packets ? VLIB_RX : VLIB_TX;
  ip_config_main_t * cm = &lm->feature_config_mains[VNET_IP_TX_FEAT];

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 cpu_index = os_get_cpu_number();
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  ip_adjacency_t * adj0, * adj1;
	  vlib_buffer_t * p0, * p1;
	  ip6_header_t * ip0, * ip1;
	  u32 pi0, rw_len0, next0, error0, adj_index0;
	  u32 pi1, rw_len1, next1, error1, adj_index1;
          u32 tx_sw_if_index0, tx_sw_if_index1;
      
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

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

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[adj_rx_tx];
	  adj_index1 = vnet_buffer (p1)->ip.adj_index[adj_rx_tx];

          /* We should never rewrite a pkt using the MISS adjacency */
          ASSERT(adj_index0 && adj_index1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  error0 = error1 = IP6_ERROR_NONE;
          next0 = next1 = IP6_REWRITE_NEXT_DROP;

	  if (! rewrite_for_locally_received_packets)
	    {
	      i32 hop_limit0 = ip0->hop_limit, hop_limit1 = ip1->hop_limit;

	      /* Input node should have reject packets with hop limit 0. */
	      ASSERT (ip0->hop_limit > 0);
	      ASSERT (ip1->hop_limit > 0);

	      hop_limit0 -= 1;
	      hop_limit1 -= 1;

	      ip0->hop_limit = hop_limit0;
	      ip1->hop_limit = hop_limit1;

              /*
               * If the hop count drops below 1 when forwarding, generate
               * an ICMP response.
               */
              if (PREDICT_FALSE(hop_limit0 <= 0))
                {
                  error0 = IP6_ERROR_TIME_EXPIRED;
                  next0 = IP6_REWRITE_NEXT_ICMP_ERROR;
                  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32)~0;
                  icmp6_error_set_vnet_buffer(p0, ICMP6_time_exceeded,
                        ICMP6_time_exceeded_ttl_exceeded_in_transit, 0);
                }
              if (PREDICT_FALSE(hop_limit1 <= 0))
                {
                  error1 = IP6_ERROR_TIME_EXPIRED;
                  next1 = IP6_REWRITE_NEXT_ICMP_ERROR;
                  vnet_buffer (p1)->sw_if_index[VLIB_TX] = (u32)~0;
                  icmp6_error_set_vnet_buffer(p1, ICMP6_time_exceeded,
                        ICMP6_time_exceeded_ttl_exceeded_in_transit, 0);
                }
	    }

	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);

          if (rewrite_for_locally_received_packets)
            {
              /*
               * If someone sends e.g. an icmp6 w/ src = dst = interface addr,
               * we end up here with a local adjacency in hand
               */
              if (PREDICT_FALSE(adj0->lookup_next_index 
                                == IP_LOOKUP_NEXT_LOCAL))
                error0 = IP6_ERROR_SPOOFED_LOCAL_PACKETS;
              if (PREDICT_FALSE(adj1->lookup_next_index 
                                == IP_LOOKUP_NEXT_LOCAL))
                error1 = IP6_ERROR_SPOOFED_LOCAL_PACKETS;
            }

	  rw_len0 = adj0[0].rewrite_header.data_bytes;
	  rw_len1 = adj1[0].rewrite_header.data_bytes;

	  vlib_increment_combined_counter (&lm->adjacency_counters,
                                           cpu_index, 
					   adj_index0,
					   /* packet increment */ 0,
					   /* byte increment */ rw_len0);
	  vlib_increment_combined_counter (&lm->adjacency_counters,
                                           cpu_index, 
					   adj_index1,
					   /* packet increment */ 0,
					   /* byte increment */ rw_len1);

	  /* Check MTU of outgoing interface. */
	  error0 = (vlib_buffer_length_in_chain (vm, p0) > adj0[0].rewrite_header.max_l3_packet_bytes
		    ? IP6_ERROR_MTU_EXCEEDED
		    : error0);
	  error1 = (vlib_buffer_length_in_chain (vm, p1) > adj1[0].rewrite_header.max_l3_packet_bytes
		    ? IP6_ERROR_MTU_EXCEEDED
		    : error1);

          /* Don't adjust the buffer for hop count issue; icmp-error node
           * wants to see the IP headerr */
          if (PREDICT_TRUE(error0 == IP6_ERROR_NONE))
            {
              p0->current_data -= rw_len0;
              p0->current_length += rw_len0;

              tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;
              vnet_buffer (p0)->sw_if_index[VLIB_TX] =
                  tx_sw_if_index0;

              if (PREDICT_FALSE 
                  (clib_bitmap_get (lm->tx_sw_if_has_ip_output_features, 
                                    tx_sw_if_index0)))
                {
                  p0->current_config_index = 
                    vec_elt (cm->config_index_by_sw_if_index, 
                             tx_sw_if_index0);
                  vnet_get_config_data (&cm->config_main,
                                        &p0->current_config_index,
                                        &next0,
                                        /* # bytes of config data */ 0);
                }
            }
          if (PREDICT_TRUE(error1 == IP6_ERROR_NONE))
            {
              p1->current_data -= rw_len1;
              p1->current_length += rw_len1;

              tx_sw_if_index1 = adj1[0].rewrite_header.sw_if_index;
              vnet_buffer (p1)->sw_if_index[VLIB_TX] =
                  tx_sw_if_index1;

              if (PREDICT_FALSE 
                  (clib_bitmap_get (lm->tx_sw_if_has_ip_output_features, 
                                    tx_sw_if_index1)))
                {
                  p1->current_config_index = 
                    vec_elt (cm->config_index_by_sw_if_index, 
                             tx_sw_if_index1);
                  vnet_get_config_data (&cm->config_main,
                                        &p1->current_config_index,
                                        &next1,
                                        /* # bytes of config data */ 0);
                }
            }

	  /* Guess we are only writing on simple Ethernet header. */
	  vnet_rewrite_two_headers (adj0[0], adj1[0],
				    ip0, ip1,
				    sizeof (ethernet_header_t));
      
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip_adjacency_t * adj0;
	  vlib_buffer_t * p0;
	  ip6_header_t * ip0;
	  u32 pi0, rw_len0;
	  u32 adj_index0, next0, error0;
          u32 tx_sw_if_index0;
      
	  pi0 = to_next[0] = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[adj_rx_tx];

          /* We should never rewrite a pkt using the MISS adjacency */
          ASSERT(adj_index0);

	  adj0 = ip_get_adjacency (lm, adj_index0);
      
	  ip0 = vlib_buffer_get_current (p0);

	  error0 = IP6_ERROR_NONE;
          next0 = IP6_REWRITE_NEXT_DROP;

	  /* Check hop limit */
	  if (! rewrite_for_locally_received_packets)
	    {
	      i32 hop_limit0 = ip0->hop_limit;

	      ASSERT (ip0->hop_limit > 0);

	      hop_limit0 -= 1;

	      ip0->hop_limit = hop_limit0;

              if (PREDICT_FALSE(hop_limit0 <= 0))
                {
                  /*
                   * If the hop count drops below 1 when forwarding, generate
                   * an ICMP response.
                   */
                  error0 = IP6_ERROR_TIME_EXPIRED;
                  next0 = IP6_REWRITE_NEXT_ICMP_ERROR;
                  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32)~0;
                  icmp6_error_set_vnet_buffer(p0, ICMP6_time_exceeded,
                        ICMP6_time_exceeded_ttl_exceeded_in_transit, 0);
                }
	    }

          if (rewrite_for_locally_received_packets)
            {
              if (PREDICT_FALSE(adj0->lookup_next_index 
                                == IP_LOOKUP_NEXT_LOCAL))
                error0 = IP6_ERROR_SPOOFED_LOCAL_PACKETS;
            }

	  /* Guess we are only writing on simple Ethernet header. */
	  vnet_rewrite_one_header (adj0[0], ip0, sizeof (ethernet_header_t));
      
	  /* Update packet buffer attributes/set output interface. */
	  rw_len0 = adj0[0].rewrite_header.data_bytes;

	  vlib_increment_combined_counter (&lm->adjacency_counters,
                                           cpu_index, 
					   adj_index0,
					   /* packet increment */ 0,
					   /* byte increment */ rw_len0);

	  /* Check MTU of outgoing interface. */
	  error0 = (vlib_buffer_length_in_chain (vm, p0) > adj0[0].rewrite_header.max_l3_packet_bytes
		    ? IP6_ERROR_MTU_EXCEEDED
		    : error0);

          /* Don't adjust the buffer for hop count issue; icmp-error node
           * wants to see the IP headerr */
          if (PREDICT_TRUE(error0 == IP6_ERROR_NONE))
            {
	      p0->current_data -= rw_len0;
	      p0->current_length += rw_len0;

              tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;

              vnet_buffer (p0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;
              next0 = adj0[0].rewrite_header.next_index;

              if (PREDICT_FALSE 
                  (clib_bitmap_get (lm->tx_sw_if_has_ip_output_features, 
                                    tx_sw_if_index0)))
                  {
                    p0->current_config_index = 
                      vec_elt (cm->config_index_by_sw_if_index, 
                               tx_sw_if_index0);
                    vnet_get_config_data (&cm->config_main,
                                          &p0->current_config_index,
                                          &next0,
                                          /* # bytes of config data */ 0);
                  }
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
    ip6_forward_next_trace (vm, node, frame, adj_rx_tx);

  return frame->n_vectors;
}

static uword
ip6_rewrite_transit (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{
  return ip6_rewrite_inline (vm, node, frame,
			     /* rewrite_for_locally_received_packets */ 0);
}

static uword
ip6_rewrite_local (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  return ip6_rewrite_inline (vm, node, frame,
			     /* rewrite_for_locally_received_packets */ 1);
}

VLIB_REGISTER_NODE (ip6_rewrite_node) = {
  .function = ip6_rewrite_transit,
  .name = "ip6-rewrite",
  .vector_size = sizeof (u32),

  .format_trace = format_ip6_rewrite_trace,

  .n_next_nodes = 2,
  .next_nodes = {
    [IP6_REWRITE_NEXT_DROP] = "error-drop",
    [IP6_REWRITE_NEXT_ICMP_ERROR] = "ip6-icmp-error",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_rewrite_node, ip6_rewrite_transit);

VLIB_REGISTER_NODE (ip6_rewrite_local_node) = {
  .function = ip6_rewrite_local,
  .name = "ip6-rewrite-local",
  .vector_size = sizeof (u32),

  .sibling_of = "ip6-rewrite",

  .format_trace = format_ip6_rewrite_trace,

  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_rewrite_local_node, ip6_rewrite_local);

/*
 * Hop-by-Hop handling
 */

ip6_hop_by_hop_main_t ip6_hop_by_hop_main;

#define foreach_ip6_hop_by_hop_error \
_(PROCESSED, "pkts with ip6 hop-by-hop options") \
_(FORMAT, "incorrectly formatted hop-by-hop options") \
_(UNKNOWN_OPTION, "unknown ip6 hop-by-hop options")

typedef enum {
#define _(sym,str) IP6_HOP_BY_HOP_ERROR_##sym,
  foreach_ip6_hop_by_hop_error
#undef _
  IP6_HOP_BY_HOP_N_ERROR,
} ip6_hop_by_hop_error_t;

/*
 * Primary h-b-h handler trace support
 * We work pretty hard on the problem for obvious reasons
 */
typedef struct {
  u32 next_index;
  u32 trace_len;
  u8 option_data[256];
} ip6_hop_by_hop_trace_t;

vlib_node_registration_t ip6_hop_by_hop_node;

static char * ip6_hop_by_hop_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_hop_by_hop_error
#undef _
};

static u8 *
format_ip6_hop_by_hop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_hop_by_hop_trace_t * t = va_arg (*args, ip6_hop_by_hop_trace_t *);
  ip6_hop_by_hop_header_t *hbh0;
  ip6_hop_by_hop_option_t *opt0, *limit0;
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;

  u8 type0;

  hbh0 = (ip6_hop_by_hop_header_t *)t->option_data;

  s = format (s, "IP6_HOP_BY_HOP: next index %d len %d traced %d",
              t->next_index, (hbh0->length+1)<<3, t->trace_len);

  opt0 = (ip6_hop_by_hop_option_t *) (hbh0+1);
  limit0 = (ip6_hop_by_hop_option_t *) ((u8 *)hbh0) + t->trace_len;

  while (opt0 < limit0) {
    type0 = opt0->type;
    switch (type0) {
    case 0: /* Pad, just stop */
      opt0 = (ip6_hop_by_hop_option_t *) ((u8 *)opt0) + 1;
      break;

    default:
      if (hm->trace[type0]) {
	s = (*hm->trace[type0])(s, opt0);
      } else {
	s = format (s, "\n    unrecognized option %d length %d", type0, opt0->length);
      }
      opt0 = (ip6_hop_by_hop_option_t *) (((u8 *)opt0) + opt0->length + sizeof (ip6_hop_by_hop_option_t));
      break;
    }
  }
  return s;
}

always_inline u8 ip6_scan_hbh_options (
				       vlib_buffer_t * b0,
				       ip6_header_t *ip0,
				       ip6_hop_by_hop_header_t *hbh0,
				       ip6_hop_by_hop_option_t *opt0,
				       ip6_hop_by_hop_option_t *limit0,
				       u32 *next0)
{
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  u8 type0;
  u8 error0 = 0;

  while (opt0 < limit0)
    {
      type0 = opt0->type;
      switch (type0)
	{
	case 0: /* Pad1 */
	  opt0 = (ip6_hop_by_hop_option_t *) ((u8 *)opt0) + 1;
	  continue;
	case 1: /* PadN */
	  break;
	default:
	  if (hm->options[type0])
	    {
	      if ((*hm->options[type0])(b0, ip0, opt0) < 0)
	        {
		  error0 = IP6_HOP_BY_HOP_ERROR_FORMAT;
		  return(error0);
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
		  icmp6_error_set_vnet_buffer(b0, ICMP6_parameter_problem,
					      ICMP6_parameter_problem_unrecognized_option, (u8 *)opt0 - (u8 *)ip0);
		  break;
		case HBH_OPTION_TYPE_DISCARD_UNKNOWN_ICMP_NOT_MCAST:
		  error0 = IP6_HOP_BY_HOP_ERROR_UNKNOWN_OPTION;
		  if (!ip6_address_is_multicast(&ip0->dst_address))
		    {
		      *next0 =  IP_LOOKUP_NEXT_ICMP_ERROR;
		      icmp6_error_set_vnet_buffer(b0, ICMP6_parameter_problem,
						  ICMP6_parameter_problem_unrecognized_option, (u8 *)opt0 - (u8 *)ip0);
		    }
		  else
		    {
		      *next0 =  IP_LOOKUP_NEXT_DROP;
		    }
		  break;
		}
	      return(error0);
	    }
	}
      opt0 = (ip6_hop_by_hop_option_t *) (((u8 *)opt0) + opt0->length + sizeof (ip6_hop_by_hop_option_t));
    }
  return(error0);
}

/*
 * Process the Hop-by-Hop Options header
 */
static uword
ip6_hop_by_hop (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  vlib_node_runtime_t *error_node = vlib_node_get_runtime(vm, ip6_hop_by_hop_node.index);
  ip6_hop_by_hop_main_t *hm = &ip6_hop_by_hop_main;
  u32 n_left_from, *from, *to_next;
  ip_lookup_next_t next_index;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t *lm = &im->lookup_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0) {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from >= 4 && n_left_to_next >= 2) {
      u32 bi0, bi1;
      vlib_buffer_t * b0, *b1;
      u32 next0, next1;
      ip6_header_t * ip0, *ip1;
      ip6_hop_by_hop_header_t *hbh0, *hbh1;
      ip6_hop_by_hop_option_t *opt0, *limit0, *opt1, *limit1;
      u8 error0 = 0, error1 = 0;

      /* Prefetch next iteration. */
      {
	vlib_buffer_t * p2, * p3;

	p2 = vlib_get_buffer (vm, from[2]);
	p3 = vlib_get_buffer (vm, from[3]);

	vlib_prefetch_buffer_header (p2, LOAD);
	vlib_prefetch_buffer_header (p3, LOAD);

	CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
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
      u32 adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
      ip_adjacency_t *adj0 = ip_get_adjacency(lm, adj_index0);
      u32 adj_index1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];
      ip_adjacency_t *adj1 = ip_get_adjacency(lm, adj_index1);

      /* Default use the next_index from the adjacency. A HBH option rarely redirects to a different node */
      next0 = adj0->lookup_next_index;
      next1 = adj1->lookup_next_index;

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);
      hbh0 = (ip6_hop_by_hop_header_t *)(ip0+1);
      hbh1 = (ip6_hop_by_hop_header_t *)(ip1+1);
      opt0 = (ip6_hop_by_hop_option_t *)(hbh0+1);
      opt1 = (ip6_hop_by_hop_option_t *)(hbh1+1);
      limit0 = (ip6_hop_by_hop_option_t *)((u8 *)hbh0 + ((hbh0->length + 1) << 3));
      limit1 = (ip6_hop_by_hop_option_t *)((u8 *)hbh1 + ((hbh1->length + 1) << 3));

      /*
       * Basic validity checks
       */
      if ((hbh0->length + 1) << 3 > clib_net_to_host_u16(ip0->payload_length)) {
	error0 = IP6_HOP_BY_HOP_ERROR_FORMAT;
	next0 = IP_LOOKUP_NEXT_DROP;
	goto outdual;
      }
      /* Scan the set of h-b-h options, process ones that we understand */
      error0 = ip6_scan_hbh_options(b0, ip0, hbh0, opt0, limit0, &next0);

      if ((hbh1->length + 1) << 3 > clib_net_to_host_u16(ip1->payload_length)) {
	error1 = IP6_HOP_BY_HOP_ERROR_FORMAT;
	next1 = IP_LOOKUP_NEXT_DROP;
	goto outdual;
      }
      /* Scan the set of h-b-h options, process ones that we understand */
      error1 = ip6_scan_hbh_options(b1,ip1,hbh1,opt1,limit1, &next1);

    outdual:
      /* Has the classifier flagged this buffer for special treatment? */
      if ((error0 == 0) && (vnet_buffer(b0)->l2_classify.opaque_index == OI_DECAP))
	next0 = hm->next_override;

      /* Has the classifier flagged this buffer for special treatment? */
      if ((error1 == 0) && (vnet_buffer(b1)->l2_classify.opaque_index == OI_DECAP))
	next1 = hm->next_override;

      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	{
	  if (b0->flags & VLIB_BUFFER_IS_TRACED) {
	    ip6_hop_by_hop_trace_t *t = vlib_add_trace(vm, node, b0, sizeof (*t));
	    u32 trace_len = (hbh0->length + 1) << 3;
	    t->next_index = next0;
	    /* Capture the h-b-h option verbatim */
	    trace_len = trace_len < ARRAY_LEN(t->option_data) ? trace_len : ARRAY_LEN(t->option_data);
	    t->trace_len = trace_len;
	    clib_memcpy(t->option_data, hbh0, trace_len);
	  }
	  if (b1->flags & VLIB_BUFFER_IS_TRACED) {
	    ip6_hop_by_hop_trace_t *t = vlib_add_trace(vm, node, b1, sizeof (*t));
	    u32 trace_len = (hbh1->length + 1) << 3;
	    t->next_index = next1;
	    /* Capture the h-b-h option verbatim */
	    trace_len = trace_len < ARRAY_LEN(t->option_data) ? trace_len : ARRAY_LEN(t->option_data);
	    t->trace_len = trace_len;
	    clib_memcpy(t->option_data, hbh1, trace_len);
	  }

	}

      b0->error = error_node->errors[error0];
      b1->error = error_node->errors[error1];

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next, n_left_to_next, bi0,
				       bi1,next0, next1);
    }

    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 bi0;
      vlib_buffer_t * b0;
      u32 next0;
      ip6_header_t * ip0;
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
      u32 adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
      ip_adjacency_t *adj0 = ip_get_adjacency(lm, adj_index0);
      /* Default use the next_index from the adjacency. A HBH option rarely redirects to a different node */
      next0 = adj0->lookup_next_index;

      ip0 = vlib_buffer_get_current (b0);
      hbh0 = (ip6_hop_by_hop_header_t *)(ip0+1);
      opt0 = (ip6_hop_by_hop_option_t *)(hbh0+1);
      limit0 = (ip6_hop_by_hop_option_t *)((u8 *)hbh0 + ((hbh0->length + 1) << 3));

      /*
       * Basic validity checks
       */
      if ((hbh0->length + 1) << 3 > clib_net_to_host_u16(ip0->payload_length)) {
	error0 = IP6_HOP_BY_HOP_ERROR_FORMAT;
	next0 = IP_LOOKUP_NEXT_DROP;
	goto out0;
      }

      /* Scan the set of h-b-h options, process ones that we understand */
      error0 = ip6_scan_hbh_options(b0, ip0, hbh0, opt0, limit0, &next0);

    out0:
      /* Has the classifier flagged this buffer for special treatment? */
      if ((error0 == 0) && (vnet_buffer(b0)->l2_classify.opaque_index == OI_DECAP))
	next0 = hm->next_override;

      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) {
	ip6_hop_by_hop_trace_t *t = vlib_add_trace(vm, node, b0, sizeof (*t));
	u32 trace_len = (hbh0->length + 1) << 3;
	t->next_index = next0;
	/* Capture the h-b-h option verbatim */
	trace_len = trace_len < ARRAY_LEN(t->option_data) ? trace_len : ARRAY_LEN(t->option_data);
	t->trace_len = trace_len;
	clib_memcpy(t->option_data, hbh0, trace_len);
      }

      b0->error = error_node->errors[error0];

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_hop_by_hop_node) = {
  .function = ip6_hop_by_hop,
  .name = "ip6-hop-by-hop",
  .sibling_of = "ip6-lookup",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_hop_by_hop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ip6_hop_by_hop_error_strings),
  .error_strings = ip6_hop_by_hop_error_strings,
  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip6_hop_by_hop_node, ip6_hop_by_hop);

static clib_error_t *
ip6_hop_by_hop_init (vlib_main_t * vm)
{
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;
  memset(hm->options, 0, sizeof(hm->options));
  memset(hm->trace, 0, sizeof(hm->trace));
  hm->next_override = IP6_LOOKUP_NEXT_POP_HOP_BY_HOP;
  return (0);
}

VLIB_INIT_FUNCTION (ip6_hop_by_hop_init);

void ip6_hbh_set_next_override (uword next)
{
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;

  hm->next_override = next;
}

int
ip6_hbh_register_option (u8 option,
			 int options(vlib_buffer_t *b, ip6_header_t *ip, ip6_hop_by_hop_option_t *opt),
			 u8 *trace(u8 *s, ip6_hop_by_hop_option_t *opt))
{
  ip6_main_t * im = &ip6_main;
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;

  ASSERT (option < ARRAY_LEN (hm->options));

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
  ip6_main_t * im = &ip6_main;
  ip6_hop_by_hop_main_t * hm = &ip6_hop_by_hop_main;

  ASSERT (option < ARRAY_LEN (hm->options));

  /* Not registered */
  if (!hm->options[option])
    return (-1);

  hm->options[option] = NULL;
  hm->trace[option] = NULL;

  /* Disable global knob if this was the last option configured */
  int i;
  bool found = false;
  for (i = 0; i < 256; i++) {
    if (hm->options[option]) {
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
  ip6_main_t * im = &ip6_main;
  clib_error_t * error;
  uword i;

  for (i = 0; i < ARRAY_LEN (im->fib_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
	im->fib_masks[i].as_u32[j] = ~0;

      if (i1)
	im->fib_masks[i].as_u32[i0] = clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }

  ip_lookup_init (&im->lookup_main, /* is_ip6 */ 1);

  if (im->lookup_table_nbuckets == 0)
    im->lookup_table_nbuckets = IP6_FIB_DEFAULT_HASH_NUM_BUCKETS;

  im->lookup_table_nbuckets = 1<< max_log2 (im->lookup_table_nbuckets);

  if (im->lookup_table_size == 0)
    im->lookup_table_size = IP6_FIB_DEFAULT_HASH_MEMORY_SIZE;
  
  BV(clib_bihash_init) (&im->ip6_lookup_table, "ip6 lookup table",
                        im->lookup_table_nbuckets,
                        im->lookup_table_size);
  
  /* Create FIB with index 0 and table id of 0. */
  find_ip6_fib_by_table_index_or_id (im, /* table id */ 0, IP6_ROUTE_FLAG_TABLE_ID);

  {
    pg_node_t * pn;
    pn = pg_get_node (ip6_lookup_node.index);
    pn->unformat_edit = unformat_pg_ip6_header;
  }

  /* Unless explicitly configured, don't process HBH options */
  im->hbh_enabled = 0;

  {
    icmp6_neighbor_solicitation_header_t p;

    memset (&p, 0, sizeof (p));

    p.ip.ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);
    p.ip.payload_length = clib_host_to_net_u16 (sizeof (p)
						- STRUCT_OFFSET_OF (icmp6_neighbor_solicitation_header_t, neighbor));
    p.ip.protocol = IP_PROTOCOL_ICMP6;
    p.ip.hop_limit = 255;
    ip6_set_solicited_node_multicast_address (&p.ip.dst_address, 0);

    p.neighbor.icmp.type = ICMP6_neighbor_solicitation;

    p.link_layer_option.header.type = ICMP6_NEIGHBOR_DISCOVERY_OPTION_source_link_layer_address;
    p.link_layer_option.header.n_data_u64s = sizeof (p.link_layer_option) / sizeof (u64);

    vlib_packet_template_init (vm,
			       &im->discover_neighbor_packet_template,
			       &p, sizeof (p),
			       /* alloc chunk size */ 8,
			       "ip6 neighbor discovery");
  }

  error = ip6_feature_init (vm, im);

  return error;
}

VLIB_INIT_FUNCTION (ip6_lookup_init);

static clib_error_t *
add_del_ip6_interface_table (vlib_main_t * vm,
                             unformat_input_t * input,
                             vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * error = 0;
  u32 sw_if_index, table_id;

  sw_if_index = ~0;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat (input, "%d", &table_id))
    ;
  else
    {
      error = clib_error_return (0, "expected table id `%U'",
				 format_unformat_error, input);
      goto done;
    }

  {
    ip6_main_t * im = &ip6_main;
    ip6_fib_t * fib = 
      find_ip6_fib_by_table_index_or_id (im, table_id, IP6_ROUTE_FLAG_TABLE_ID);

    if (fib) 
      {
        vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
        im->fib_index_by_sw_if_index[sw_if_index] = fib->index;
    }
  }

 done:
  return error;
}

VLIB_CLI_COMMAND (set_interface_ip_table_command, static) = {
  .path = "set interface ip6 table",
  .function = add_del_ip6_interface_table,
  .short_help = "set interface ip6 table <intfc> <table-id>"
};

void 
ip6_link_local_address_from_ethernet_mac_address (ip6_address_t *ip,
                                                  u8 *mac)
{
  ip->as_u64[0] = clib_host_to_net_u64 (0xFE80000000000000ULL);
  /* Invert the "u" bit */
  ip->as_u8 [8] = mac[0] ^ (1<<1);
  ip->as_u8 [9] = mac[1];
  ip->as_u8 [10] = mac[2];
  ip->as_u8 [11] = 0xFF;
  ip->as_u8 [12] = 0xFE;
  ip->as_u8 [13] = mac[3];
  ip->as_u8 [14] = mac[4];
  ip->as_u8 [15] = mac[5];
}

void 
ip6_ethernet_mac_address_from_link_local_address (u8 *mac, 
                                                  ip6_address_t *ip)
{
  /* Invert the previously inverted "u" bit */
  mac[0] = ip->as_u8 [8] ^ (1<<1);
  mac[1] = ip->as_u8 [9];
  mac[2] = ip->as_u8 [10];
  mac[3] = ip->as_u8 [13];
  mac[4] = ip->as_u8 [14];
  mac[5] = ip->as_u8 [15];
}

static clib_error_t * 
test_ip6_link_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
  u8 mac[6];
  ip6_address_t _a, *a = &_a;

  if (unformat (input, "%U", unformat_ethernet_address, mac))
    {
      ip6_link_local_address_from_ethernet_mac_address (a, mac);
      vlib_cli_output (vm, "Link local address: %U",
                       format_ip6_address, a);
      ip6_ethernet_mac_address_from_link_local_address (mac, a);
      vlib_cli_output (vm, "Original MAC address: %U",
                       format_ethernet_address, mac);
    }
                
  return 0;
}

VLIB_CLI_COMMAND (test_link_command, static) = {
  .path = "test ip6 link",
  .function = test_ip6_link_command_fn, 
  .short_help = "test ip6 link <mac-address>",
};

int vnet_set_ip6_flow_hash (u32 table_id, u32 flow_hash_config)
{
  ip6_main_t * im6 = &ip6_main;
  ip6_fib_t * fib;
  uword * p = hash_get (im6->fib_index_by_table_id, table_id);

  if (p == 0)
    return -1;

  fib = vec_elt_at_index (im6->fibs, p[0]);

  fib->flow_hash_config = flow_hash_config;
  return 1;
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

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "table %d", &table_id))
      matched = 1;
#define _(a,v) \
    else if (unformat (input, #a)) { flow_hash_config |= v; matched=1;}
    foreach_flow_hash_bit
#undef _
    else break;
  }

  if (matched == 0)
    return clib_error_return (0, "unknown input `%U'",
                              format_unformat_error, input);
  
  rv = vnet_set_ip6_flow_hash (table_id, flow_hash_config);
  switch (rv)
    {
    case 1:
      break;

    case -1:
      return clib_error_return (0, "no such FIB table %d", table_id);
      
    default:
      clib_warning ("BUG: illegal flow hash config 0x%x", flow_hash_config);
      break;
    }
  
  return 0;
}

VLIB_CLI_COMMAND (set_ip6_flow_hash_command, static) = {
    .path = "set ip6 flow-hash",
    .short_help = 
    "set ip table flow-hash table <fib-id> src dst sport dport proto reverse",
    .function = set_ip6_flow_hash_command_fn,
};

static clib_error_t *
show_ip6_local_command_fn (vlib_main_t * vm,
                           unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  int i;
  
  vlib_cli_output (vm, "Protocols handled by ip6_local");
  for (i = 0; i < ARRAY_LEN(lm->local_next_by_ip_protocol); i++)
    {
      if (lm->local_next_by_ip_protocol[i] != IP_LOCAL_NEXT_PUNT)
        vlib_cli_output (vm, "%d", i);
    }
  return 0;
}



VLIB_CLI_COMMAND (show_ip_local, static) = {
  .path = "show ip6 local",
  .function = show_ip6_local_command_fn,
  .short_help = "Show ip6 local protocol table",
};

int vnet_set_ip6_classify_intfc (vlib_main_t * vm, u32 sw_if_index, 
                                 u32 table_index)
{
  vnet_main_t * vnm = vnet_get_main();
  vnet_interface_main_t * im = &vnm->interface_main;
  ip6_main_t * ipm = &ip6_main;
  ip_lookup_main_t * lm = &ipm->lookup_main;
  vnet_classify_main_t * cm = &vnet_classify_main;

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  if (table_index != ~0 && pool_is_free_index (cm->tables, table_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vec_validate (lm->classify_table_index_by_sw_if_index, sw_if_index);
  lm->classify_table_index_by_sw_if_index [sw_if_index] = table_index;

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
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "table-index %d", &table_index))
      table_index_set = 1;
    else if (unformat (input, "intfc %U", unformat_vnet_sw_interface, 
                       vnet_get_main(), &sw_if_index))
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

VLIB_CLI_COMMAND (set_ip6_classify_command, static) = {
    .path = "set ip6 classify",
    .short_help = 
    "set ip6 classify intfc <int> table-index <index>",
    .function = set_ip6_classify_command_fn,
};

static clib_error_t *
ip6_config (vlib_main_t * vm, unformat_input_t * input)
{
  ip6_main_t * im = &ip6_main;
  uword heapsize = 0;
  u32 tmp;
  u32 nbuckets = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "hash-buckets %d", &tmp))
      nbuckets = tmp;
    else if (unformat (input, "heap-size %dm", &tmp))
      heapsize = ((u64)tmp) << 20;
    else if (unformat (input, "heap-size %dM", &tmp))
      heapsize = ((u64)tmp) << 20;
    else if (unformat (input, "heap-size %dg", &tmp))
      heapsize = ((u64)tmp) << 30;
    else if (unformat (input, "heap-size %dG", &tmp))
      heapsize = ((u64)tmp) << 30;
    else
      return clib_error_return (0, "unknown input '%U'",
                                format_unformat_error, input);
  }

  im->lookup_table_nbuckets = nbuckets;
  im->lookup_table_size = heapsize;

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (ip6_config, "ip6");

#define TEST_CODE 1
#if TEST_CODE > 0

static clib_error_t *
set_interface_ip6_output_feature_command_fn (vlib_main_t * vm,
                                             unformat_input_t * input,
                                             vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 sw_if_index = ~0;
  int is_add = 1;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
        ;
      else if (unformat (input, "del"))
        is_add = 0;
      else
        break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "unknown interface `%U'",
                              format_unformat_error, input);

  lm->tx_sw_if_has_ip_output_features =
    clib_bitmap_set (lm->tx_sw_if_has_ip_output_features, sw_if_index, is_add);

  return 0;
}

VLIB_CLI_COMMAND (set_interface_ip6_output_feature, static) = {
  .path = "set interface ip6 output feature",
  .function = set_interface_ip6_output_feature_command_fn,
  .short_help = "set interface output feature <intfc>",
};
#endif /* TEST_CODE */
