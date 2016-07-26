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
 * ip/ip4_forward.c: IP v4 forwarding
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
#include <vnet/ethernet/ethernet.h>	/* for ethernet_header_t */
#include <vnet/ethernet/arp_packet.h>	/* for ethernet_arp_header_t */
#include <vnet/ppp/ppp.h>
#include <vnet/srp/srp.h>	/* for srp_hw_interface_class */
#include <vnet/api_errno.h>     /* for API error numbers */

/** \file
    vnet ip4 forwarding 
*/

/* This is really, really simple but stupid fib. */
u32
ip4_fib_lookup_with_table (ip4_main_t * im, u32 fib_index,
			   ip4_address_t * dst,
			   u32 disable_default_route)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip4_fib_t * fib = vec_elt_at_index (im->fibs, fib_index);
  uword * p, * hash, key;
  i32 i, i_min, dst_address, ai;

  i_min = disable_default_route ? 1 : 0;
  dst_address = clib_mem_unaligned (&dst->data_u32, u32);
  for (i = ARRAY_LEN (fib->adj_index_by_dst_address) - 1; i >= i_min; i--)
    {
      hash = fib->adj_index_by_dst_address[i];
      if (! hash)
	continue;

      key = dst_address & im->fib_masks[i];
      if ((p = hash_get (hash, key)) != 0)
	{
	  ai = p[0];
	  goto done;
	}
    }
    
  /* Nothing matches in table. */
  ai = lm->miss_adj_index;

 done:
  return ai;
}

static ip4_fib_t *
create_fib_with_table_id (ip4_main_t * im, u32 table_id)
{
  ip4_fib_t * fib;
  hash_set (im->fib_index_by_table_id, table_id, vec_len (im->fibs));
  vec_add2 (im->fibs, fib, 1);
  fib->table_id = table_id;
  fib->index = fib - im->fibs;
  fib->flow_hash_config = IP_FLOW_HASH_DEFAULT;
  fib->fwd_classify_table_index = ~0;
  fib->rev_classify_table_index = ~0;
  ip4_mtrie_init (&fib->mtrie);
  return fib;
}

ip4_fib_t *
find_ip4_fib_by_table_index_or_id (ip4_main_t * im, 
                                   u32 table_index_or_id, u32 flags)
{
  uword * p, fib_index;

  fib_index = table_index_or_id;
  if (! (flags & IP4_ROUTE_FLAG_FIB_INDEX))
    {
      if (table_index_or_id == ~0) {
        table_index_or_id = 0;
        while ((p = hash_get (im->fib_index_by_table_id, table_index_or_id))) {
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

static void
ip4_fib_init_adj_index_by_dst_address (ip_lookup_main_t * lm,
				       ip4_fib_t * fib,
				       u32 address_length)
{
  hash_t * h;
  uword max_index;

  ASSERT (lm->fib_result_n_bytes >= sizeof (uword));
  lm->fib_result_n_words = round_pow2 (lm->fib_result_n_bytes, sizeof (uword)) / sizeof (uword);

  fib->adj_index_by_dst_address[address_length] =
    hash_create (32 /* elts */, lm->fib_result_n_words * sizeof (uword));

  hash_set_flags (fib->adj_index_by_dst_address[address_length],
                  HASH_FLAG_NO_AUTO_SHRINK);

  h = hash_header (fib->adj_index_by_dst_address[address_length]);
  max_index = (hash_value_bytes (h) / sizeof (fib->new_hash_values[0])) - 1;

  /* Initialize new/old hash value vectors. */
  vec_validate_init_empty (fib->new_hash_values, max_index, ~0);
  vec_validate_init_empty (fib->old_hash_values, max_index, ~0);
}

static void
ip4_fib_set_adj_index (ip4_main_t * im,
		       ip4_fib_t * fib,
		       u32 flags,
		       u32 dst_address_u32,
		       u32 dst_address_length,
		       u32 adj_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  uword * hash;

  if (vec_bytes(fib->old_hash_values))
    memset (fib->old_hash_values, ~0, vec_bytes (fib->old_hash_values));
  if (vec_bytes(fib->new_hash_values))
    memset (fib->new_hash_values, ~0, vec_bytes (fib->new_hash_values));
  fib->new_hash_values[0] = adj_index;

  /* Make sure adj index is valid. */
  if (CLIB_DEBUG > 0)
    (void) ip_get_adjacency (lm, adj_index);

  hash = fib->adj_index_by_dst_address[dst_address_length];

  hash = _hash_set3 (hash, dst_address_u32,
		     fib->new_hash_values,
		     fib->old_hash_values);

  fib->adj_index_by_dst_address[dst_address_length] = hash;

  if (vec_len (im->add_del_route_callbacks) > 0)
    {
      ip4_add_del_route_callback_t * cb;
      ip4_address_t d;
      uword * p;

      d.data_u32 = dst_address_u32;
      vec_foreach (cb, im->add_del_route_callbacks)
	if ((flags & cb->required_flags) == cb->required_flags)
	  cb->function (im, cb->function_opaque,
			fib, flags,
			&d, dst_address_length,
			fib->old_hash_values,
			fib->new_hash_values);

      p = hash_get (hash, dst_address_u32);
      clib_memcpy (p, fib->new_hash_values, vec_bytes (fib->new_hash_values));
    }
}

void ip4_add_del_route (ip4_main_t * im, ip4_add_del_route_args_t * a)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip4_fib_t * fib;
  u32 dst_address, dst_address_length, adj_index, old_adj_index;
  uword * hash, is_del;
  ip4_add_del_route_callback_t * cb;

  /* Either create new adjacency or use given one depending on arguments. */
  if (a->n_add_adj > 0)
    {
      ip_add_adjacency (lm, a->add_adj, a->n_add_adj, &adj_index);
      ip_call_add_del_adjacency_callbacks (lm, adj_index, /* is_del */ 0);
    }
  else
    adj_index = a->adj_index;

  dst_address = a->dst_address.data_u32;
  dst_address_length = a->dst_address_length;
  fib = find_ip4_fib_by_table_index_or_id (im, a->table_index_or_table_id, a->flags);

  ASSERT (dst_address_length < ARRAY_LEN (im->fib_masks));
  dst_address &= im->fib_masks[dst_address_length];

  if (! fib->adj_index_by_dst_address[dst_address_length])
    ip4_fib_init_adj_index_by_dst_address (lm, fib, dst_address_length);

  hash = fib->adj_index_by_dst_address[dst_address_length];

  is_del = (a->flags & IP4_ROUTE_FLAG_DEL) != 0;

  if (is_del)
    {
      fib->old_hash_values[0] = ~0;
      hash = _hash_unset (hash, dst_address, fib->old_hash_values);
      fib->adj_index_by_dst_address[dst_address_length] = hash;

      if (vec_len (im->add_del_route_callbacks) > 0
	  && fib->old_hash_values[0] != ~0) /* make sure destination was found in hash */
	{
	  fib->new_hash_values[0] = ~0;
	  vec_foreach (cb, im->add_del_route_callbacks)
	    if ((a->flags & cb->required_flags) == cb->required_flags)
	      cb->function (im, cb->function_opaque,
			    fib, a->flags,
			    &a->dst_address, dst_address_length,
			    fib->old_hash_values,
			    fib->new_hash_values);
	}
    }
  else
    ip4_fib_set_adj_index (im, fib, a->flags, dst_address, dst_address_length,
			   adj_index);

  old_adj_index = fib->old_hash_values[0];

  /* Avoid spurious reference count increments */
  if (old_adj_index == adj_index
      && adj_index != ~0
      && !(a->flags & IP4_ROUTE_FLAG_KEEP_OLD_ADJACENCY))
    {
      ip_adjacency_t * adj = ip_get_adjacency (lm, adj_index);
      if (adj->share_count > 0)
        adj->share_count --;
    }

  ip4_fib_mtrie_add_del_route (fib, a->dst_address, dst_address_length,
			       is_del ? old_adj_index : adj_index,
			       is_del);

  /* Delete old adjacency index if present and changed. */
  if (! (a->flags & IP4_ROUTE_FLAG_KEEP_OLD_ADJACENCY)
      && old_adj_index != ~0
      && old_adj_index != adj_index)
    ip_del_adjacency (lm, old_adj_index);
}


u32
ip4_route_get_next_hop_adj (ip4_main_t * im,
			    u32 fib_index,
			    ip4_address_t *next_hop,
			    u32 next_hop_sw_if_index,
			    u32 explicit_fib_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  vnet_main_t * vnm = vnet_get_main();
  uword * nh_hash, * nh_result;
  int is_interface_next_hop;
  u32 nh_adj_index;
  ip4_fib_t * fib;

  fib = vec_elt_at_index (im->fibs, fib_index);

  is_interface_next_hop = next_hop->data_u32 == 0;
  if (is_interface_next_hop)
    {
      nh_result = hash_get (im->interface_route_adj_index_by_sw_if_index, next_hop_sw_if_index);
      if (nh_result)
	  nh_adj_index = *nh_result;
      else
        {
	   ip_adjacency_t * adj;
	   adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
				   &nh_adj_index);
	   ip4_adjacency_set_interface_route (vnm, adj, next_hop_sw_if_index, /* if_address_index */ ~0);
	   ip_call_add_del_adjacency_callbacks (lm, nh_adj_index, /* is_del */ 0);
	   hash_set (im->interface_route_adj_index_by_sw_if_index, next_hop_sw_if_index, nh_adj_index);
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
      add_adj.indirect.next_hop.ip4.as_u32 = next_hop->as_u32;
      add_adj.explicit_fib_index = explicit_fib_index;
      ip_add_adjacency (lm, &add_adj, 1, &nh_adj_index);
    }
  else
    {
      nh_hash = fib->adj_index_by_dst_address[32];
      nh_result = hash_get (nh_hash, next_hop->data_u32);

      /* Next hop must be known. */
      if (! nh_result)
        {
	  ip_adjacency_t * adj;

	  /* no /32 exists, get the longest prefix match */
	  nh_adj_index = ip4_fib_lookup_with_table (im, fib_index,
						    next_hop, 0);
	  adj = ip_get_adjacency (lm, nh_adj_index);
	  /* if ARP interface adjacency is present, we need to
	     install ARP adjaceny for specific next hop */
	  if (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP &&
	      adj->arp.next_hop.ip4.as_u32 == 0)
	    {
	      nh_adj_index = vnet_arp_glean_add(fib_index, next_hop);
	    }
	}
      else
        {
	  nh_adj_index = *nh_result;
	}
    }

  return (nh_adj_index);
}

void
ip4_add_del_route_next_hop (ip4_main_t * im,
			    u32 flags,
			    ip4_address_t * dst_address,
			    u32 dst_address_length,
			    ip4_address_t * next_hop,
			    u32 next_hop_sw_if_index,
			    u32 next_hop_weight, u32 adj_index, 
                            u32 explicit_fib_index)
{
  vnet_main_t * vnm = vnet_get_main();
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 fib_index;
  ip4_fib_t * fib;
  u32 dst_address_u32, old_mp_adj_index, new_mp_adj_index;
  u32 dst_adj_index, nh_adj_index;
  uword * dst_hash, * dst_result;
  ip_adjacency_t * dst_adj;
  ip_multipath_adjacency_t * old_mp, * new_mp;
  int is_del = (flags & IP4_ROUTE_FLAG_DEL) != 0;
  clib_error_t * error = 0;

  if (explicit_fib_index == (u32)~0)
      fib_index = vec_elt (im->fib_index_by_sw_if_index, next_hop_sw_if_index);
  else
      fib_index = explicit_fib_index;

  fib = vec_elt_at_index (im->fibs, fib_index);

  /* Lookup next hop to be added or deleted. */
  if (adj_index == (u32)~0)
    {
	nh_adj_index = ip4_route_get_next_hop_adj(im, fib_index,
						  next_hop,
						  next_hop_sw_if_index,
						  explicit_fib_index);
    }
  else
    {
      nh_adj_index = adj_index;
    }
  ASSERT (dst_address_length < ARRAY_LEN (im->fib_masks));
  dst_address_u32 = dst_address->data_u32 & im->fib_masks[dst_address_length];

  dst_hash = fib->adj_index_by_dst_address[dst_address_length];
  dst_result = hash_get (dst_hash, dst_address_u32);
  if (dst_result)
    {
      dst_adj_index = dst_result[0];
      dst_adj = ip_get_adjacency (lm, dst_adj_index);
    }
  else
    {
      /* For deletes destination must be known. */
      if (is_del)
	{
          vnm->api_errno = VNET_API_ERROR_UNKNOWN_DESTINATION;
	  error = clib_error_return (0, "unknown destination %U/%d",
				     format_ip4_address, dst_address,
				     dst_address_length);
	  goto done;
	}

      dst_adj_index = ~0;
      dst_adj = 0;
    }

  /* Ignore adds of X/32 with next hop of X. */
  if (! is_del
      && dst_address_length == 32
      && dst_address->data_u32 == next_hop->data_u32 
      && adj_index != (u32)~0)
    {
      vnm->api_errno = VNET_API_ERROR_PREFIX_MATCHES_NEXT_HOP;
      error = clib_error_return (0, "prefix matches next hop %U/%d",
                                 format_ip4_address, dst_address,
                                 dst_address_length);
      goto done;
    }

  /* Destination is not known and default weight is set so add route
     to existing non-multipath adjacency */
  if (dst_adj_index == ~0 && next_hop_weight == 1 && next_hop_sw_if_index == ~0)
    {
      /* create / delete additional mapping of existing adjacency */
      ip4_add_del_route_args_t a;
      ip_adjacency_t * nh_adj = ip_get_adjacency (lm, nh_adj_index);

      a.table_index_or_table_id = fib_index;
      a.flags = ((is_del ? IP4_ROUTE_FLAG_DEL : IP4_ROUTE_FLAG_ADD)
		 | IP4_ROUTE_FLAG_FIB_INDEX
		 | IP4_ROUTE_FLAG_KEEP_OLD_ADJACENCY
		 | (flags & (IP4_ROUTE_FLAG_NO_REDISTRIBUTE
			     | IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP)));
      a.dst_address = dst_address[0];
      a.dst_address_length = dst_address_length;
      a.adj_index = nh_adj_index;
      a.add_adj = 0;
      a.n_add_adj = 0;

      ip4_add_del_route (im, &a);

      /* adjust share count. This cannot be the only use of the adjacency 
         unless next hop is an indiect adj where share count is already
         incremented */
      if (next_hop_sw_if_index != ~0) 
	nh_adj->share_count += is_del ? -1 : 1;
        
      goto done;
    }

  old_mp_adj_index = dst_adj ? dst_adj->heap_handle : ~0;

  if (! ip_multipath_adjacency_add_del_next_hop
      (lm, is_del,
       old_mp_adj_index,
       nh_adj_index,
       next_hop_weight,
       &new_mp_adj_index))
    {
      vnm->api_errno = VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP;
      error = clib_error_return (0, "requested deleting next-hop %U not found in multi-path",
				 format_ip4_address, next_hop);
      goto done;
    }
  
  old_mp = new_mp = 0;
  if (old_mp_adj_index != ~0)
    old_mp = vec_elt_at_index (lm->multipath_adjacencies, old_mp_adj_index);
  if (new_mp_adj_index != ~0)
    new_mp = vec_elt_at_index (lm->multipath_adjacencies, new_mp_adj_index);

  if (old_mp != new_mp)
    {
      ip4_add_del_route_args_t a;
      ip_adjacency_t * adj;

      a.table_index_or_table_id = fib_index;
      a.flags = ((is_del && ! new_mp ? IP4_ROUTE_FLAG_DEL : IP4_ROUTE_FLAG_ADD)
		 | IP4_ROUTE_FLAG_FIB_INDEX
		 | IP4_ROUTE_FLAG_KEEP_OLD_ADJACENCY
		 | (flags & (IP4_ROUTE_FLAG_NO_REDISTRIBUTE | IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP)));
      a.dst_address = dst_address[0];
      a.dst_address_length = dst_address_length;
      a.adj_index = new_mp ? new_mp->adj_index : dst_adj_index;
      a.add_adj = 0;
      a.n_add_adj = 0;

      ip4_add_del_route (im, &a);

      adj = ip_get_adjacency (lm, new_mp ? new_mp->adj_index : dst_adj_index);
      if (adj->n_adj == 1)
        adj->share_count += is_del ? -1 : 1;
    }

 done:
  if (error)
    clib_error_report (error);
}

void *
ip4_get_route (ip4_main_t * im,
	       u32 table_index_or_table_id,
	       u32 flags,
	       u8 * address,
	       u32 address_length)
{
  ip4_fib_t * fib = find_ip4_fib_by_table_index_or_id (im, table_index_or_table_id, flags);
  u32 dst_address = * (u32 *) address;
  uword * hash, * p;

  ASSERT (address_length < ARRAY_LEN (im->fib_masks));
  dst_address &= im->fib_masks[address_length];

  hash = fib->adj_index_by_dst_address[address_length];
  p = hash_get (hash, dst_address);
  return (void *) p;
}

void
ip4_foreach_matching_route (ip4_main_t * im,
			    u32 table_index_or_table_id,
			    u32 flags,
			    ip4_address_t * address,
			    u32 address_length,
			    ip4_address_t ** results,
			    u8 ** result_lengths)
{
  ip4_fib_t * fib = find_ip4_fib_by_table_index_or_id (im, table_index_or_table_id, flags);
  u32 dst_address = address->data_u32;
  u32 this_length = address_length;
  
  if (*results)
    _vec_len (*results) = 0;
  if (*result_lengths)
    _vec_len (*result_lengths) = 0;

  while (this_length <= 32 && vec_len (results) == 0)
    {
      uword k, v;
      hash_foreach (k, v, fib->adj_index_by_dst_address[this_length], ({
	if (0 == ((k ^ dst_address) & im->fib_masks[address_length]))
	  {
	    ip4_address_t a;
	    a.data_u32 = k;
	    vec_add1 (*results, a);
	    vec_add1 (*result_lengths, this_length);
	  }
      }));

      this_length++;
    }
}

void ip4_maybe_remap_adjacencies (ip4_main_t * im,
				  u32 table_index_or_table_id,
				  u32 flags)
{
  ip4_fib_t * fib = find_ip4_fib_by_table_index_or_id (im, table_index_or_table_id, flags);
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 i, l;
  ip4_address_t a;
  ip4_add_del_route_callback_t * cb;
  static ip4_address_t * to_delete;

  if (lm->n_adjacency_remaps == 0)
    return;

  for (l = 0; l <= 32; l++)
    {
      hash_pair_t * p;
      uword * hash = fib->adj_index_by_dst_address[l];

      if (hash_elts (hash) == 0)
	continue;

      if (to_delete)
	_vec_len (to_delete) = 0;

      hash_foreach_pair (p, hash, ({
	u32 adj_index = p->value[0];
	u32 m = vec_elt (lm->adjacency_remap_table, adj_index);

	if (m)
	  {
	    /* Record destination address from hash key. */
	    a.data_u32 = p->key;

	    /* New adjacency points to nothing: so delete prefix. */
	    if (m == ~0)
	      vec_add1 (to_delete, a);
	    else
	      {
		/* Remap to new adjacency. */
		clib_memcpy (fib->old_hash_values, p->value, vec_bytes (fib->old_hash_values));

		/* Set new adjacency value. */
		fib->new_hash_values[0] = p->value[0] = m - 1;

		vec_foreach (cb, im->add_del_route_callbacks)
		  if ((flags & cb->required_flags) == cb->required_flags)
		    cb->function (im, cb->function_opaque,
				  fib, flags | IP4_ROUTE_FLAG_ADD,
				  &a, l,
				  fib->old_hash_values,
				  fib->new_hash_values);
	      }
	  }
      }));

      fib->new_hash_values[0] = ~0;
      for (i = 0; i < vec_len (to_delete); i++)
	{
	  hash = _hash_unset (hash, to_delete[i].data_u32, fib->old_hash_values);
	  vec_foreach (cb, im->add_del_route_callbacks)
	    if ((flags & cb->required_flags) == cb->required_flags)
	      cb->function (im, cb->function_opaque,
			    fib, flags | IP4_ROUTE_FLAG_DEL,
			    &a, l,
			    fib->old_hash_values,
			    fib->new_hash_values);
	}
    }

  /* Also remap adjacencies in mtrie. */
  ip4_mtrie_maybe_remap_adjacencies (lm, &fib->mtrie);

  /* Reset mapping table. */
  vec_zero (lm->adjacency_remap_table);

  /* All remaps have been performed. */
  lm->n_adjacency_remaps = 0;
}

void ip4_delete_matching_routes (ip4_main_t * im,
				 u32 table_index_or_table_id,
				 u32 flags,
				 ip4_address_t * address,
				 u32 address_length)
{
  static ip4_address_t * matching_addresses;
  static u8 * matching_address_lengths;
  u32 l, i;
  ip4_add_del_route_args_t a;

  a.flags = IP4_ROUTE_FLAG_DEL | IP4_ROUTE_FLAG_NO_REDISTRIBUTE | flags;
  a.table_index_or_table_id = table_index_or_table_id;
  a.adj_index = ~0;
  a.add_adj = 0;
  a.n_add_adj = 0;

  for (l = address_length + 1; l <= 32; l++)
    {
      ip4_foreach_matching_route (im, table_index_or_table_id, flags,
				  address,
				  l,
				  &matching_addresses,
				  &matching_address_lengths);
      for (i = 0; i < vec_len (matching_addresses); i++)
	{
	  a.dst_address = matching_addresses[i];
	  a.dst_address_length = matching_address_lengths[i];
	  ip4_add_del_route (im, &a);
	}
    }

  ip4_maybe_remap_adjacencies (im, table_index_or_table_id, flags);
}

void
ip4_forward_next_trace (vlib_main_t * vm,
                        vlib_node_runtime_t * node,
                        vlib_frame_t * frame,
                        vlib_rx_or_tx_t which_adj_index);

always_inline uword
ip4_lookup_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame,
		   int lookup_for_responses_to_locally_received_packets,
		   int is_indirect)
{
  ip4_main_t * im = &ip4_main;
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
	  ip4_header_t * ip0, * ip1;
	  __attribute__((unused)) tcp_header_t * tcp0, * tcp1;
	  ip_lookup_next_t next0, next1;
	  ip_adjacency_t * adj0, * adj1;
	  ip4_fib_mtrie_t * mtrie0, * mtrie1;
	  ip4_fib_mtrie_leaf_t leaf0, leaf1;
	  ip4_address_t * dst_addr0, *dst_addr1;
	  __attribute__((unused)) u32 pi0, fib_index0, adj_index0, is_tcp_udp0;
	  __attribute__((unused)) u32 pi1, fib_index1, adj_index1, is_tcp_udp1;
          u32 flow_hash_config0, flow_hash_config1;
          u32 hash_c0, hash_c1;
	  u32 wrong_next;

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

	  if (is_indirect)
	    {
	      ip_adjacency_t * iadj0, * iadj1;
	      iadj0 = ip_get_adjacency (lm, vnet_buffer(p0)->ip.adj_index[VLIB_TX]);
	      iadj1 = ip_get_adjacency (lm, vnet_buffer(p1)->ip.adj_index[VLIB_TX]);
	      dst_addr0 = &iadj0->indirect.next_hop.ip4;
	      dst_addr1 = &iadj1->indirect.next_hop.ip4;
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


	  if (! lookup_for_responses_to_locally_received_packets)
	    {
	      mtrie0 = &vec_elt_at_index (im->fibs, fib_index0)->mtrie;
	      mtrie1 = &vec_elt_at_index (im->fibs, fib_index1)->mtrie;

	      leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;

	      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 0);
	      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, dst_addr1, 0);
	    }

	  tcp0 = (void *) (ip0 + 1);
	  tcp1 = (void *) (ip1 + 1);

	  is_tcp_udp0 = (ip0->protocol == IP_PROTOCOL_TCP
			 || ip0->protocol == IP_PROTOCOL_UDP);
	  is_tcp_udp1 = (ip1->protocol == IP_PROTOCOL_TCP
			 || ip1->protocol == IP_PROTOCOL_UDP);

	  if (! lookup_for_responses_to_locally_received_packets)
	    {
	      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 1);
	      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, dst_addr1, 1);
	    }

	  if (! lookup_for_responses_to_locally_received_packets)
	    {
	      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 2);
	      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, dst_addr1, 2);
	    }

	  if (! lookup_for_responses_to_locally_received_packets)
	    {
	      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 3);
	      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, dst_addr1, 3);
	    }

	  if (lookup_for_responses_to_locally_received_packets)
	    {
	      adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_RX];
	      adj_index1 = vnet_buffer (p1)->ip.adj_index[VLIB_RX];
	    }
	  else
	    {
	      /* Handle default route. */
	      leaf0 = (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie0->default_leaf : leaf0);
	      leaf1 = (leaf1 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie1->default_leaf : leaf1);

	      adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	      adj_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);
	    }

	  ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, fib_index0,
							   dst_addr0,
							   /* no_default_route */ 0));
	  ASSERT (adj_index1 == ip4_fib_lookup_with_table (im, fib_index1,
							   dst_addr1,
							   /* no_default_route */ 0));
	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);

	  next0 = adj0->lookup_next_index;
	  next1 = adj1->lookup_next_index;

	  /* Use flow hash to compute multipath adjacency. */
          hash_c0 = vnet_buffer (p0)->ip.flow_hash = 0;
          hash_c1 = vnet_buffer (p1)->ip.flow_hash = 0;
          if (PREDICT_FALSE (adj0->n_adj > 1))
            {
              flow_hash_config0 = 
                vec_elt_at_index (im->fibs, fib_index0)->flow_hash_config;
              hash_c0 = vnet_buffer (p0)->ip.flow_hash = 
                ip4_compute_flow_hash (ip0, flow_hash_config0);
            }
          if (PREDICT_FALSE(adj1->n_adj > 1))
            {
              flow_hash_config1 = 
                vec_elt_at_index (im->fibs, fib_index1)->flow_hash_config;
              hash_c1 = vnet_buffer (p1)->ip.flow_hash = 
                ip4_compute_flow_hash (ip1, flow_hash_config1);
            }

	  ASSERT (adj0->n_adj > 0);
	  ASSERT (adj1->n_adj > 0);
	  ASSERT (is_pow2 (adj0->n_adj));
	  ASSERT (is_pow2 (adj1->n_adj));
	  adj_index0 += (hash_c0 & (adj0->n_adj - 1));
	  adj_index1 += (hash_c1 & (adj1->n_adj - 1));

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;
	  vnet_buffer (p1)->ip.adj_index[VLIB_TX] = adj_index1;

          vlib_increment_combined_counter 
              (cm, cpu_index, adj_index0, 1,
               vlib_buffer_length_in_chain (vm, p0) 
               + sizeof(ethernet_header_t));
          vlib_increment_combined_counter 
              (cm, cpu_index, adj_index1, 1,
               vlib_buffer_length_in_chain (vm, p1)
               + sizeof(ethernet_header_t));

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
	  ip4_header_t * ip0;
	  __attribute__((unused)) tcp_header_t * tcp0;
	  ip_lookup_next_t next0;
	  ip_adjacency_t * adj0;
	  ip4_fib_mtrie_t * mtrie0;
	  ip4_fib_mtrie_leaf_t leaf0;
	  ip4_address_t * dst_addr0;
	  __attribute__((unused)) u32 pi0, fib_index0, adj_index0, is_tcp_udp0;
          u32 flow_hash_config0, hash_c0;

	  pi0 = from[0];
	  to_next[0] = pi0;

	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);

	  if (is_indirect)
	    {
	      ip_adjacency_t * iadj0;
	      iadj0 = ip_get_adjacency (lm, vnet_buffer(p0)->ip.adj_index[VLIB_TX]);
	      dst_addr0 = &iadj0->indirect.next_hop.ip4;
	    }
	  else
	    {
	      dst_addr0 = &ip0->dst_address;
	    }

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, vnet_buffer (p0)->sw_if_index[VLIB_RX]);
          fib_index0 = (vnet_buffer(p0)->sw_if_index[VLIB_TX] == (u32)~0) ?
            fib_index0 : vnet_buffer(p0)->sw_if_index[VLIB_TX];

	  if (! lookup_for_responses_to_locally_received_packets)
	    {
	      mtrie0 = &vec_elt_at_index (im->fibs, fib_index0)->mtrie;

	      leaf0 = IP4_FIB_MTRIE_LEAF_ROOT;

	      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 0);
	    }

	  tcp0 = (void *) (ip0 + 1);

	  is_tcp_udp0 = (ip0->protocol == IP_PROTOCOL_TCP
			 || ip0->protocol == IP_PROTOCOL_UDP);

	  if (! lookup_for_responses_to_locally_received_packets)
	    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 1);

	  if (! lookup_for_responses_to_locally_received_packets)
	    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 2);

	  if (! lookup_for_responses_to_locally_received_packets)
	    leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, dst_addr0, 3);

	  if (lookup_for_responses_to_locally_received_packets)
	    adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_RX];
	  else
	    {
	      /* Handle default route. */
	      leaf0 = (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie0->default_leaf : leaf0);
	      adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	    }

	  ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, fib_index0,
							   dst_addr0,
							   /* no_default_route */ 0));

	  adj0 = ip_get_adjacency (lm, adj_index0);

	  next0 = adj0->lookup_next_index;

	  /* Use flow hash to compute multipath adjacency. */
          hash_c0 = vnet_buffer (p0)->ip.flow_hash = 0;
          if (PREDICT_FALSE(adj0->n_adj > 1))
            {
              flow_hash_config0 = 
                vec_elt_at_index (im->fibs, fib_index0)->flow_hash_config;

              hash_c0 = vnet_buffer (p0)->ip.flow_hash = 
                ip4_compute_flow_hash (ip0, flow_hash_config0);
            }

	  ASSERT (adj0->n_adj > 0);
	  ASSERT (is_pow2 (adj0->n_adj));
	  adj_index0 += (hash_c0 & (adj0->n_adj - 1));

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;

          vlib_increment_combined_counter 
              (cm, cpu_index, adj_index0, 1,
               vlib_buffer_length_in_chain (vm, p0)
               + sizeof(ethernet_header_t));

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
    ip4_forward_next_trace(vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

/** @brief IPv4 lookup node.
    @node ip4-lookup

    This is the main IPv4 lookup dispatch node.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
        - Indicates the @c sw_if_index value of the interface that the
	  packet was received on.
    - <code>vnet_buffer(b)->sw_if_index[VLIB_TX]</code>
        - When the value is @c ~0 then the node performs a longest prefix
          match (LPM) for the packet destination address in the FIB attached
          to the receive interface.
        - Otherwise perform LPM for the packet destination address in the
          indicated FIB. In this case <code>[VLIB_TX]</code> is a FIB index
          value (0, 1, ...) and not a VRF id.

    @em Sets:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - The lookup result adjacency index.

    <em>Next Index:</em>
    - Dispatches the packet to the node index found in
      ip_adjacency_t @c adj->lookup_next_index
      (where @c adj is the lookup result adjacency).
*/
static uword
ip4_lookup (vlib_main_t * vm,
	    vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return ip4_lookup_inline (vm, node, frame,
			    /* lookup_for_responses_to_locally_received_packets */ 0,
			    /* is_indirect */ 0);

}

void ip4_adjacency_set_interface_route (vnet_main_t * vnm,
					ip_adjacency_t * adj,
					u32 sw_if_index,
					u32 if_address_index)
{
  vnet_hw_interface_t * hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  ip_lookup_next_t n;
  vnet_l3_packet_type_t packet_type;
  u32 node_index;

  if (hw->hw_class_index == ethernet_hw_interface_class.index
      || hw->hw_class_index == srp_hw_interface_class.index)
    {
      /* 
       * We have a bit of a problem in this case. ip4-arp uses
       * the rewrite_header.next_index to hand pkts to the
       * indicated inteface output node. We can end up in
       * ip4_rewrite_local, too, which also pays attention to 
       * rewrite_header.next index. Net result: a hack in
       * ip4_rewrite_local...
       */
      n = IP_LOOKUP_NEXT_ARP;
      node_index = ip4_arp_node.index;
      adj->if_address_index = if_address_index;
      adj->arp.next_hop.ip4.as_u32 = 0;
      ip46_address_reset(&adj->arp.next_hop);
      packet_type = VNET_L3_PACKET_TYPE_ARP;
    }
  else
    {
      n = IP_LOOKUP_NEXT_REWRITE;
      node_index = ip4_rewrite_node.index;
      packet_type = VNET_L3_PACKET_TYPE_IP4;
    }

  adj->lookup_next_index = n;
  vnet_rewrite_for_sw_interface
    (vnm,
     packet_type,
     sw_if_index,
     node_index,
     VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST,
     &adj->rewrite_header,
     sizeof (adj->rewrite_data));
}

static void
ip4_add_interface_routes (u32 sw_if_index,
			  ip4_main_t * im, u32 fib_index,
			  ip_interface_address_t * a)
{
  vnet_main_t * vnm = vnet_get_main();
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_adjacency_t * adj;
  ip4_address_t * address = ip_interface_address_get_address (lm, a);
  ip4_add_del_route_args_t x;
  vnet_hw_interface_t * hw_if = vnet_get_sup_hw_interface (vnm, sw_if_index);
  u32 classify_table_index;

  /* Add e.g. 1.0.0.0/8 as interface route (arp for Ethernet). */
  x.table_index_or_table_id = fib_index;
  x.flags = (IP4_ROUTE_FLAG_ADD
	     | IP4_ROUTE_FLAG_FIB_INDEX
	     | IP4_ROUTE_FLAG_NO_REDISTRIBUTE);
  x.dst_address = address[0];
  x.dst_address_length = a->address_length;
  x.n_add_adj = 0;
  x.add_adj = 0;

  a->neighbor_probe_adj_index = ~0;
  if (a->address_length < 32)
    {
      adj = ip_add_adjacency (lm, /* template */ 0, /* block size */ 1,
			      &x.adj_index);
      ip4_adjacency_set_interface_route (vnm, adj, sw_if_index, a - lm->if_address_pool);
      ip_call_add_del_adjacency_callbacks (lm, x.adj_index, /* is_del */ 0);
      ip4_add_del_route (im, &x);
      a->neighbor_probe_adj_index = x.adj_index;
    }
  
  /* Add e.g. 1.1.1.1/32 as local to this host. */
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
  /* 
   * Local adjs are never to be rewritten. Spoofed pkts w/ src = dst = local
   * fail an RPF-ish check, but still go thru the rewrite code...
   */
  adj->rewrite_header.data_bytes = 0;

  ip_call_add_del_adjacency_callbacks (lm, x.adj_index, /* is_del */ 0);
  x.dst_address_length = 32;
  ip4_add_del_route (im, &x);
}

static void
ip4_del_interface_routes (ip4_main_t * im, u32 fib_index, ip4_address_t * address, u32 address_length)
{
  ip4_add_del_route_args_t x;

  /* Add e.g. 1.0.0.0/8 as interface route (arp for Ethernet). */
  x.table_index_or_table_id = fib_index;
  x.flags = (IP4_ROUTE_FLAG_DEL
	     | IP4_ROUTE_FLAG_FIB_INDEX
	     | IP4_ROUTE_FLAG_NO_REDISTRIBUTE);
  x.dst_address = address[0];
  x.dst_address_length = address_length;
  x.adj_index = ~0;
  x.n_add_adj = 0;
  x.add_adj = 0;

  if (address_length < 32)
    ip4_add_del_route (im, &x);

  x.dst_address_length = 32;
  ip4_add_del_route (im, &x);

  ip4_delete_matching_routes (im,
			      fib_index,
			      IP4_ROUTE_FLAG_FIB_INDEX,
			      address,
			      address_length);
}

typedef struct {
    u32 sw_if_index;
    ip4_address_t address;
    u32 length;
} ip4_interface_address_t;

static clib_error_t *
ip4_add_del_interface_address_internal (vlib_main_t * vm,
					u32 sw_if_index,
					ip4_address_t * new_address,
					u32 new_length,
					u32 redistribute,
					u32 insert_routes,
					u32 is_del);

static clib_error_t *
ip4_add_del_interface_address_internal (vlib_main_t * vm,
					u32 sw_if_index,
					ip4_address_t * address,
					u32 address_length,
					u32 redistribute,
					u32 insert_routes,
					u32 is_del)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  clib_error_t * error = 0;
  u32 if_address_index, elts_before;
  ip4_address_fib_t ip4_af, * addr_fib = 0;

  vec_validate (im->fib_index_by_sw_if_index, sw_if_index);
  ip4_addr_fib_init (&ip4_af, address,
		     vec_elt (im->fib_index_by_sw_if_index, sw_if_index));
  vec_add1 (addr_fib, ip4_af);

  /* When adding an address check that it does not conflict with an existing address. */
  if (! is_del)
    {
      ip_interface_address_t * ia;
      foreach_ip_interface_address (&im->lookup_main, ia, sw_if_index, 
                                    0 /* honor unnumbered */,
      ({
	ip4_address_t * x = ip_interface_address_get_address (&im->lookup_main, ia);

	if (ip4_destination_matches_route (im, address, x, ia->address_length)
	    || ip4_destination_matches_route (im, x, address, address_length))
	  return clib_error_create ("failed to add %U which conflicts with %U for interface %U",
				    format_ip4_address_and_length, address, address_length,
				    format_ip4_address_and_length, x, ia->address_length,
				    format_vnet_sw_if_index_name, vnm, sw_if_index);
      }));
    }

  elts_before = pool_elts (lm->if_address_pool);

  error = ip_interface_address_add_del
    (lm,
     sw_if_index,
     addr_fib,
     address_length,
     is_del,
     &if_address_index);
  if (error)
    goto done;
  
  if (vnet_sw_interface_is_admin_up (vnm, sw_if_index) && insert_routes)
    {
      if (is_del)
	ip4_del_interface_routes (im, ip4_af.fib_index, address,
				  address_length);
      
      else
          ip4_add_interface_routes (sw_if_index,
                                    im, ip4_af.fib_index,
                                    pool_elt_at_index 
                                    (lm->if_address_pool, if_address_index));
    }

  /* If pool did not grow/shrink: add duplicate address. */
  if (elts_before != pool_elts (lm->if_address_pool))
    {
      ip4_add_del_interface_address_callback_t * cb;
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
ip4_add_del_interface_address (vlib_main_t * vm, u32 sw_if_index,
			       ip4_address_t * address, u32 address_length,
			       u32 is_del)
{
  return ip4_add_del_interface_address_internal
    (vm, sw_if_index, address, address_length,
     /* redistribute */ 1,
     /* insert_routes */ 1,
     is_del);
}

static clib_error_t *
ip4_sw_interface_admin_up_down (vnet_main_t * vnm,
				u32 sw_if_index,
				u32 flags)
{
  ip4_main_t * im = &ip4_main;
  ip_interface_address_t * ia;
  ip4_address_t * a;
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
      ip4_add_interface_routes (sw_if_index,
				im, fib_index,
				ia);
    else
      ip4_del_interface_routes (im, fib_index,
				a, ia->address_length);
  }));

  return 0;
}
 
VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ip4_sw_interface_admin_up_down);

/* Built-in ip4 unicast rx feature path definition */
VNET_IP4_UNICAST_FEATURE_INIT (ip4_inacl, static) = {
  .node_name = "ip4-inacl", 
  .runs_before = {"ip4-source-check-via-rx", 0}, 
  .feature_index = &ip4_main.ip4_unicast_rx_feature_check_access,
};

VNET_IP4_UNICAST_FEATURE_INIT (ip4_source_check_1, static) = {
  .node_name = "ip4-source-check-via-rx",
  .runs_before = {"ip4-source-check-via-any", 0},
  .feature_index = 
  &ip4_main.ip4_unicast_rx_feature_source_reachable_via_rx,
};

VNET_IP4_UNICAST_FEATURE_INIT (ip4_source_check_2, static) = {
  .node_name = "ip4-source-check-via-any",
  .runs_before = {"ip4-policer-classify", 0},
  .feature_index = 
  &ip4_main.ip4_unicast_rx_feature_source_reachable_via_any,
};

VNET_IP4_UNICAST_FEATURE_INIT (ip4_policer_classify, static) = {
  .node_name = "ip4-policer-classify",
  .runs_before = {"ipsec-input-ip4", 0},
  .feature_index =
  &ip4_main.ip4_unicast_rx_feature_policer_classify,
};

VNET_IP4_UNICAST_FEATURE_INIT (ip4_ipsec, static) = {
  .node_name = "ipsec-input-ip4",
  .runs_before = {"vpath-input-ip4", 0},
  .feature_index = &ip4_main.ip4_unicast_rx_feature_ipsec,
};

VNET_IP4_UNICAST_FEATURE_INIT (ip4_vpath, static) = {
  .node_name = "vpath-input-ip4",
  .runs_before = {"ip4-lookup", 0},
  .feature_index = &ip4_main.ip4_unicast_rx_feature_vpath,
};

VNET_IP4_UNICAST_FEATURE_INIT (ip4_lookup, static) = {
  .node_name = "ip4-lookup",
  .runs_before = {0}, /* not before any other features */
  .feature_index = &ip4_main.ip4_unicast_rx_feature_lookup,
};

/* Built-in ip4 multicast rx feature path definition */
VNET_IP4_MULTICAST_FEATURE_INIT (ip4_vpath_mc, static) = {
  .node_name = "vpath-input-ip4",
  .runs_before = {"ip4-lookup-multicast", 0},
  .feature_index = &ip4_main.ip4_multicast_rx_feature_vpath,
};

VNET_IP4_MULTICAST_FEATURE_INIT (ip4_lookup_mc, static) = {
  .node_name = "ip4-lookup-multicast",
  .runs_before = {0}, /* not before any other features */
  .feature_index = &ip4_main.ip4_multicast_rx_feature_lookup,
};

static char * feature_start_nodes[] = 
  { "ip4-input", "ip4-input-no-checksum"};

static clib_error_t *
ip4_feature_init (vlib_main_t * vm, ip4_main_t * im)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  clib_error_t * error;
  vnet_cast_t cast;

  for (cast = 0; cast < VNET_N_CAST; cast++)
    {
      ip_config_main_t * cm = &lm->rx_config_mains[cast];
      vnet_config_main_t * vcm = &cm->config_main;

      if ((error = ip_feature_init_cast (vm, cm, vcm, 
                                         feature_start_nodes,
                                         ARRAY_LEN(feature_start_nodes),
                                         cast,
                                         1 /* is_ip4 */)))
        return error;
    }
  return 0;
}

static clib_error_t *
ip4_sw_interface_add_del (vnet_main_t * vnm,
			  u32 sw_if_index,
			  u32 is_add)
{
  vlib_main_t * vm = vnm->vlib_main;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 ci, cast;
  u32 feature_index;

  for (cast = 0; cast < VNET_N_CAST; cast++)
    {
      ip_config_main_t * cm = &lm->rx_config_mains[cast];
      vnet_config_main_t * vcm = &cm->config_main;

      vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
      ci = cm->config_index_by_sw_if_index[sw_if_index];

      if (cast == VNET_UNICAST)
        feature_index = im->ip4_unicast_rx_feature_lookup;
      else
        feature_index = im->ip4_multicast_rx_feature_lookup;

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
    }

  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip4_sw_interface_add_del);

static u8 * format_ip4_lookup_trace (u8 * s, va_list * args);

VLIB_REGISTER_NODE (ip4_lookup_node) = {
  .function = ip4_lookup,
  .name = "ip4-lookup",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_lookup_trace,

  .n_next_nodes = IP4_LOOKUP_N_NEXT,
  .next_nodes = IP4_LOOKUP_NEXT_NODES,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_lookup_node, ip4_lookup)

static uword
ip4_indirect (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * frame)
{
  return ip4_lookup_inline (vm, node, frame,
			    /* lookup_for_responses_to_locally_received_packets */ 0,
			    /* is_indirect */ 1);
}

VLIB_REGISTER_NODE (ip4_indirect_node) = {
  .function = ip4_indirect,
  .name = "ip4-indirect",
  .vector_size = sizeof (u32),
  .sibling_of = "ip4-lookup",
  .format_trace = format_ip4_lookup_trace,

  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_indirect_node, ip4_indirect)


/* Global IP4 main. */
ip4_main_t ip4_main;

clib_error_t *
ip4_lookup_init (vlib_main_t * vm)
{
  ip4_main_t * im = &ip4_main;
  clib_error_t * error;
  uword i;

  for (i = 0; i < ARRAY_LEN (im->fib_masks); i++)
    {
      u32 m;

      if (i < 32)
	m = pow2_mask (i) << (32 - i);
      else 
	m = ~0;
      im->fib_masks[i] = clib_host_to_net_u32 (m);
    }

  /* Create FIB with index 0 and table id of 0. */
  find_ip4_fib_by_table_index_or_id (im, /* table id */ 0, IP4_ROUTE_FLAG_TABLE_ID);

  ip_lookup_init (&im->lookup_main, /* is_ip6 */ 0);

  {
    pg_node_t * pn;
    pn = pg_get_node (ip4_lookup_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }

  {
    ethernet_arp_header_t h;

    memset (&h, 0, sizeof (h));

    /* Set target ethernet address to all zeros. */
    memset (h.ip4_over_ethernet[1].ethernet, 0, sizeof (h.ip4_over_ethernet[1].ethernet));

#define _16(f,v) h.f = clib_host_to_net_u16 (v);
#define _8(f,v) h.f = v;
    _16 (l2_type, ETHERNET_ARP_HARDWARE_TYPE_ethernet);
    _16 (l3_type, ETHERNET_TYPE_IP4);
    _8 (n_l2_address_bytes, 6);
    _8 (n_l3_address_bytes, 4);
    _16 (opcode, ETHERNET_ARP_OPCODE_request);
#undef _16
#undef _8

    vlib_packet_template_init (vm,
			       &im->ip4_arp_request_packet_template,
			       /* data */ &h,
			       sizeof (h),
			       /* alloc chunk size */ 8,
			       "ip4 arp");
  }

  error = ip4_feature_init (vm, im);

  return error;
}

VLIB_INIT_FUNCTION (ip4_lookup_init);

typedef struct {
  /* Adjacency taken. */
  u32 adj_index;
  u32 flow_hash;
  u32 fib_index;

  /* Packet data, possibly *after* rewrite. */
  u8 packet_data[64 - 1*sizeof(u32)];
} ip4_forward_next_trace_t;

static u8 * format_ip4_forward_next_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t * t = va_arg (*args, ip4_forward_next_trace_t *);
  uword indent = format_get_indent (s);
  s = format (s, "%U%U",
                format_white_space, indent,
                format_ip4_header, t->packet_data);
  return s;
}

static u8 * format_ip4_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t * t = va_arg (*args, ip4_forward_next_trace_t *);
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;
  uword indent = format_get_indent (s);

  s = format (s, "fib %d adj-idx %d : %U flow hash: 0x%08x",
              t->fib_index, t->adj_index, format_ip_adjacency,
              vnm, &im->lookup_main, t->adj_index, t->flow_hash);
  s = format (s, "\n%U%U",
              format_white_space, indent,
              format_ip4_header, t->packet_data);
  return s;
}

static u8 * format_ip4_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_forward_next_trace_t * t = va_arg (*args, ip4_forward_next_trace_t *);
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;
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

/* Common trace function for all ip4-forward next nodes. */
void
ip4_forward_next_trace (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame,
			vlib_rx_or_tx_t which_adj_index)
{
  u32 * from, n_left;
  ip4_main_t * im = &ip4_main;

  n_left = frame->n_vectors;
  from = vlib_frame_vector_args (frame);
  
  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t * b0, * b1;
      ip4_forward_next_trace_t * t0, * t1;

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
      ip4_forward_next_trace_t * t0;

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
ip4_drop_or_punt (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame,
		  ip4_error_t error_code)
{
  u32 * buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;

  vlib_error_drop_buffers (vm, node,
			   buffers,
			   /* stride */ 1,
			   n_packets,
			   /* next */ 0,
			   ip4_input_node.index,
			   error_code);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return n_packets;
}

static uword
ip4_drop (vlib_main_t * vm,
	  vlib_node_runtime_t * node,
	  vlib_frame_t * frame)
{ return ip4_drop_or_punt (vm, node, frame, IP4_ERROR_ADJACENCY_DROP); }

static uword
ip4_punt (vlib_main_t * vm,
	  vlib_node_runtime_t * node,
	  vlib_frame_t * frame)
{ return ip4_drop_or_punt (vm, node, frame, IP4_ERROR_ADJACENCY_PUNT); }

static uword
ip4_miss (vlib_main_t * vm,
	  vlib_node_runtime_t * node,
	  vlib_frame_t * frame)
{ return ip4_drop_or_punt (vm, node, frame, IP4_ERROR_DST_LOOKUP_MISS); }

VLIB_REGISTER_NODE (ip4_drop_node,static) = {
  .function = ip4_drop,
  .name = "ip4-drop",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_drop_node, ip4_drop)

VLIB_REGISTER_NODE (ip4_punt_node,static) = {
  .function = ip4_punt,
  .name = "ip4-punt",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-punt",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_punt_node, ip4_punt)

VLIB_REGISTER_NODE (ip4_miss_node,static) = {
  .function = ip4_miss,
  .name = "ip4-miss",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_miss_node, ip4_miss)

/* Compute TCP/UDP/ICMP4 checksum in software. */
u16
ip4_tcp_udp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
			      ip4_header_t * ip0)
{
  ip_csum_t sum0;
  u32 ip_header_length, payload_length_host_byte_order;
  u32 n_this_buffer, n_bytes_left;
  u16 sum16;
  void * data_this_buffer;
  
  /* Initialize checksum with ip header. */
  ip_header_length = ip4_header_bytes (ip0);
  payload_length_host_byte_order = clib_net_to_host_u16 (ip0->length) - ip_header_length;
  sum0 = clib_host_to_net_u32 (payload_length_host_byte_order + (ip0->protocol << 16));

  if (BITS (uword) == 32)
    {
      sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->src_address, u32));
      sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->dst_address, u32));
    }
  else
    sum0 = ip_csum_with_carry (sum0, clib_mem_unaligned (&ip0->src_address, u64));

  n_bytes_left = n_this_buffer = payload_length_host_byte_order;
  data_this_buffer = (void *) ip0 + ip_header_length;
  if (n_this_buffer + ip_header_length > p0->current_length)
    n_this_buffer = p0->current_length > ip_header_length ? p0->current_length - ip_header_length : 0;
  while (1)
    {
      sum0 = ip_incremental_checksum (sum0, data_this_buffer, n_this_buffer);
      n_bytes_left -= n_this_buffer;
      if (n_bytes_left == 0)
	break;

      ASSERT (p0->flags & VLIB_BUFFER_NEXT_PRESENT);
      p0 = vlib_get_buffer (vm, p0->next_buffer);
      data_this_buffer = vlib_buffer_get_current (p0);
      n_this_buffer = p0->current_length;
    }

  sum16 = ~ ip_csum_fold (sum0);

  return sum16;
}

static u32
ip4_tcp_udp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0)
{
  ip4_header_t * ip0 = vlib_buffer_get_current (p0);
  udp_header_t * udp0;
  u16 sum16;

  ASSERT (ip0->protocol == IP_PROTOCOL_TCP
	  || ip0->protocol == IP_PROTOCOL_UDP);

  udp0 = (void *) (ip0 + 1);
  if (ip0->protocol == IP_PROTOCOL_UDP && udp0->checksum == 0)
    {
      p0->flags |= (IP_BUFFER_L4_CHECKSUM_COMPUTED
		    | IP_BUFFER_L4_CHECKSUM_CORRECT);
      return p0->flags;
    }

  sum16 = ip4_tcp_udp_compute_checksum (vm, p0, ip0);

  p0->flags |= (IP_BUFFER_L4_CHECKSUM_COMPUTED
		| ((sum16 == 0) << LOG2_IP_BUFFER_L4_CHECKSUM_CORRECT));

  return p0->flags;
}

static uword
ip4_local (vlib_main_t * vm,
	   vlib_node_runtime_t * node,
	   vlib_frame_t * frame)
{
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_local_next_t next_index;
  u32 * from, * to_next, n_left_from, n_left_to_next;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip4_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  
  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t * p0, * p1;
	  ip4_header_t * ip0, * ip1;
	  udp_header_t * udp0, * udp1;
	  ip4_fib_mtrie_t * mtrie0, * mtrie1;
	  ip4_fib_mtrie_leaf_t leaf0, leaf1;
	  ip_adjacency_t * adj0, * adj1;
	  u32 pi0, ip_len0, udp_len0, flags0, next0, fib_index0, adj_index0;
	  u32 pi1, ip_len1, udp_len1, flags1, next1, fib_index1, adj_index1;
	  i32 len_diff0, len_diff1;
	  u8 error0, is_udp0, is_tcp_udp0, good_tcp_udp0, proto0;
	  u8 error1, is_udp1, is_tcp_udp1, good_tcp_udp1, proto1;
	  u8 enqueue_code;
      
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

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, 
                                vnet_buffer(p0)->sw_if_index[VLIB_RX]);
	  fib_index1 = vec_elt (im->fib_index_by_sw_if_index, 
                                vnet_buffer(p1)->sw_if_index[VLIB_RX]);

	  mtrie0 = &vec_elt_at_index (im->fibs, fib_index0)->mtrie;
	  mtrie1 = &vec_elt_at_index (im->fibs, fib_index1)->mtrie;

	  leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 0);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 0);

	  /* Treat IP frag packets as "experimental" protocol for now
	     until support of IP frag reassembly is implemented */
	  proto0 = ip4_is_fragment(ip0) ? 0xfe : ip0->protocol;
	  proto1 = ip4_is_fragment(ip1) ? 0xfe : ip1->protocol;
	  is_udp0 = proto0 == IP_PROTOCOL_UDP;
	  is_udp1 = proto1 == IP_PROTOCOL_UDP;
	  is_tcp_udp0 = is_udp0 || proto0 == IP_PROTOCOL_TCP;
	  is_tcp_udp1 = is_udp1 || proto1 == IP_PROTOCOL_TCP;

	  flags0 = p0->flags;
	  flags1 = p1->flags;

	  good_tcp_udp0 = (flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
	  good_tcp_udp1 = (flags1 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;

	  udp0 = ip4_next_header (ip0);
	  udp1 = ip4_next_header (ip1);

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_tcp_udp0 |= is_udp0 && udp0->checksum == 0;
	  good_tcp_udp1 |= is_udp1 && udp1->checksum == 0;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 1);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 1);

	  /* Verify UDP length. */
	  ip_len0 = clib_net_to_host_u16 (ip0->length);
	  ip_len1 = clib_net_to_host_u16 (ip1->length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  udp_len1 = clib_net_to_host_u16 (udp1->length);

	  len_diff0 = ip_len0 - udp_len0;
	  len_diff1 = ip_len1 - udp_len1;

	  len_diff0 = is_udp0 ? len_diff0 : 0;
	  len_diff1 = is_udp1 ? len_diff1 : 0;

	  if (PREDICT_FALSE (! (is_tcp_udp0 & is_tcp_udp1
				& good_tcp_udp0 & good_tcp_udp1)))
	    {
	      if (is_tcp_udp0)
		{
		  if (is_tcp_udp0
		      && ! (flags0 & IP_BUFFER_L4_CHECKSUM_COMPUTED))
		    flags0 = ip4_tcp_udp_validate_checksum (vm, p0);
		  good_tcp_udp0 =
		    (flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
		  good_tcp_udp0 |= is_udp0 && udp0->checksum == 0;
		}
	      if (is_tcp_udp1)
		{
		  if (is_tcp_udp1
		      && ! (flags1 & IP_BUFFER_L4_CHECKSUM_COMPUTED))
		    flags1 = ip4_tcp_udp_validate_checksum (vm, p1);
		  good_tcp_udp1 =
		    (flags1 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
		  good_tcp_udp1 |= is_udp1 && udp1->checksum == 0;
		}
	    }

	  good_tcp_udp0 &= len_diff0 >= 0;
	  good_tcp_udp1 &= len_diff1 >= 0;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 2);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 2);

	  error0 = error1 = IP4_ERROR_UNKNOWN_PROTOCOL;

	  error0 = len_diff0 < 0 ? IP4_ERROR_UDP_LENGTH : error0;
	  error1 = len_diff1 < 0 ? IP4_ERROR_UDP_LENGTH : error1;

	  ASSERT (IP4_ERROR_TCP_CHECKSUM + 1 == IP4_ERROR_UDP_CHECKSUM);
	  error0 = (is_tcp_udp0 && ! good_tcp_udp0
		    ? IP4_ERROR_TCP_CHECKSUM + is_udp0
		    : error0);
	  error1 = (is_tcp_udp1 && ! good_tcp_udp1
		    ? IP4_ERROR_TCP_CHECKSUM + is_udp1
		    : error1);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 3);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 3);

	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
          vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;

	  vnet_buffer (p1)->ip.adj_index[VLIB_RX] = adj_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);
          vnet_buffer (p1)->ip.adj_index[VLIB_TX] = adj_index1;

	  ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, fib_index0,
							   &ip0->src_address,
							   /* no_default_route */ 1));
	  ASSERT (adj_index1 == ip4_fib_lookup_with_table (im, fib_index1,
							   &ip1->src_address,
							   /* no_default_route */ 1));

	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);

	  /* 
           * Must have a route to source otherwise we drop the packet.
           * ip4 broadcasts are accepted, e.g. to make dhcp client work
           */
	  error0 = (error0 == IP4_ERROR_UNKNOWN_PROTOCOL
		    && adj0->lookup_next_index != IP_LOOKUP_NEXT_REWRITE
		    && adj0->lookup_next_index != IP_LOOKUP_NEXT_ARP
		    && adj0->lookup_next_index != IP_LOOKUP_NEXT_LOCAL
		    && ip0->dst_address.as_u32 != 0xFFFFFFFF
		    ? IP4_ERROR_SRC_LOOKUP_MISS
		    : error0);
	  error1 = (error1 == IP4_ERROR_UNKNOWN_PROTOCOL
		    && adj1->lookup_next_index != IP_LOOKUP_NEXT_REWRITE
		    && adj1->lookup_next_index != IP_LOOKUP_NEXT_ARP
		    && adj1->lookup_next_index != IP_LOOKUP_NEXT_LOCAL
		    && ip0->dst_address.as_u32 != 0xFFFFFFFF
		    ? IP4_ERROR_SRC_LOOKUP_MISS
		    : error1);

	  next0 = lm->local_next_by_ip_protocol[proto0];
	  next1 = lm->local_next_by_ip_protocol[proto1];

	  next0 = error0 != IP4_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;
	  next1 = error1 != IP4_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next1;

	  p0->error = error0 ? error_node->errors[error0] : 0;
	  p1->error = error1 ? error_node->errors[error1] : 0;

	  enqueue_code = (next0 != next_index) + 2*(next1 != next_index);

	  if (PREDICT_FALSE (enqueue_code != 0))
	    {
	      switch (enqueue_code)
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
		  /* A B B or A B C */
		  to_next -= 2;
		  n_left_to_next += 2;
		  vlib_set_next_frame_buffer (vm, node, next0, pi0);
		  vlib_set_next_frame_buffer (vm, node, next1, pi1);
		  if (next0 == next1)
		    {
		      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		      next_index = next1;
		      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
		    }
		  break;
		}
	    }
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip4_header_t * ip0;
	  udp_header_t * udp0;
	  ip4_fib_mtrie_t * mtrie0;
	  ip4_fib_mtrie_leaf_t leaf0;
	  ip_adjacency_t * adj0;
	  u32 pi0, next0, ip_len0, udp_len0, flags0, fib_index0, adj_index0;
	  i32 len_diff0;
	  u8 error0, is_udp0, is_tcp_udp0, good_tcp_udp0, proto0;
      
	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
      
	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, 
                                vnet_buffer(p0)->sw_if_index[VLIB_RX]);

	  mtrie0 = &vec_elt_at_index (im->fibs, fib_index0)->mtrie;

	  leaf0 = IP4_FIB_MTRIE_LEAF_ROOT;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 0);

	  /* Treat IP frag packets as "experimental" protocol for now
	     until support of IP frag reassembly is implemented */
	  proto0 = ip4_is_fragment(ip0) ? 0xfe : ip0->protocol;
	  is_udp0 = proto0 == IP_PROTOCOL_UDP;
	  is_tcp_udp0 = is_udp0 || proto0 == IP_PROTOCOL_TCP;

	  flags0 = p0->flags;

	  good_tcp_udp0 = (flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;

	  udp0 = ip4_next_header (ip0);

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_tcp_udp0 |= is_udp0 && udp0->checksum == 0;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 1);

	  /* Verify UDP length. */
	  ip_len0 = clib_net_to_host_u16 (ip0->length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);

	  len_diff0 = ip_len0 - udp_len0;

	  len_diff0 = is_udp0 ? len_diff0 : 0;

	  if (PREDICT_FALSE (! (is_tcp_udp0 & good_tcp_udp0)))
	    {
	      if (is_tcp_udp0)
		{
		  if (is_tcp_udp0
		      && ! (flags0 & IP_BUFFER_L4_CHECKSUM_COMPUTED))
		    flags0 = ip4_tcp_udp_validate_checksum (vm, p0);
		  good_tcp_udp0 =
		    (flags0 & IP_BUFFER_L4_CHECKSUM_CORRECT) != 0;
		  good_tcp_udp0 |= is_udp0 && udp0->checksum == 0;
		}
	    }

	  good_tcp_udp0 &= len_diff0 >= 0;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 2);

	  error0 = IP4_ERROR_UNKNOWN_PROTOCOL;

	  error0 = len_diff0 < 0 ? IP4_ERROR_UDP_LENGTH : error0;

	  ASSERT (IP4_ERROR_TCP_CHECKSUM + 1 == IP4_ERROR_UDP_CHECKSUM);
	  error0 = (is_tcp_udp0 && ! good_tcp_udp0
		    ? IP4_ERROR_TCP_CHECKSUM + is_udp0
		    : error0);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 3);

	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
          vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;

	  ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, fib_index0,
							   &ip0->src_address,
							   /* no_default_route */ 1));

	  adj0 = ip_get_adjacency (lm, adj_index0);

	  /* Must have a route to source otherwise we drop the packet. */
	  error0 = (error0 == IP4_ERROR_UNKNOWN_PROTOCOL
		    && adj0->lookup_next_index != IP_LOOKUP_NEXT_REWRITE
		    && adj0->lookup_next_index != IP_LOOKUP_NEXT_ARP
		    && adj0->lookup_next_index != IP_LOOKUP_NEXT_LOCAL
		    && ip0->dst_address.as_u32 != 0xFFFFFFFF
		    ? IP4_ERROR_SRC_LOOKUP_MISS
		    : error0);

	  next0 = lm->local_next_by_ip_protocol[proto0];

	  next0 = error0 != IP4_ERROR_UNKNOWN_PROTOCOL ? IP_LOCAL_NEXT_DROP : next0;

	  p0->error = error0? error_node->errors[error0] : 0;

	  if (PREDICT_FALSE (next0 != next_index))
	    {
	      n_left_to_next += 1;
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

	      next_index = next0;
	      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	      to_next[0] = pi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}
  
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip4_local_node,static) = {
  .function = ip4_local,
  .name = "ip4-local",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,

  .n_next_nodes = IP_LOCAL_N_NEXT,
  .next_nodes = {
    [IP_LOCAL_NEXT_DROP] = "error-drop",
    [IP_LOCAL_NEXT_PUNT] = "error-punt",
    [IP_LOCAL_NEXT_UDP_LOOKUP] = "ip4-udp-lookup",
    [IP_LOCAL_NEXT_ICMP] = "ip4-icmp-input",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_local_node, ip4_local)

void ip4_register_protocol (u32 protocol, u32 node_index)
{
  vlib_main_t * vm = vlib_get_main();
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;

  ASSERT (protocol < ARRAY_LEN (lm->local_next_by_ip_protocol));
  lm->local_next_by_ip_protocol[protocol] = vlib_node_add_next (vm, ip4_local_node.index, node_index);
}

static clib_error_t *
show_ip_local_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  int i;

  vlib_cli_output (vm, "Protocols handled by ip4_local");
  for (i = 0; i < ARRAY_LEN(lm->local_next_by_ip_protocol); i++)
    {
      if (lm->local_next_by_ip_protocol[i] != IP_LOCAL_NEXT_PUNT)
        vlib_cli_output (vm, "%d", i);
    }
  return 0;
}



VLIB_CLI_COMMAND (show_ip_local, static) = {
  .path = "show ip local",
  .function = show_ip_local_command_fn,
  .short_help = "Show ip local protocol table",
};

static uword
ip4_arp (vlib_main_t * vm,
	 vlib_node_runtime_t * node,
	 vlib_frame_t * frame)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 * from, * to_next_drop;
  uword n_left_from, n_left_to_next_drop, next_index;
  static f64 time_last_seed_change = -1e100;
  static u32 hash_seeds[3];
  static uword hash_bitmap[256 / BITS (uword)]; 
  f64 time_now;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  time_now = vlib_time_now (vm);
  if (time_now - time_last_seed_change > 1e-3)
    {
      uword i;
      u32 * r = clib_random_buffer_get_data (&vm->random_buffer,
					     sizeof (hash_seeds));
      for (i = 0; i < ARRAY_LEN (hash_seeds); i++)
	hash_seeds[i] = r[i];

      /* Mark all hash keys as been no-seen before. */
      for (i = 0; i < ARRAY_LEN (hash_bitmap); i++)
	hash_bitmap[i] = 0;

      time_last_seed_change = time_now;
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  if (next_index == IP4_ARP_NEXT_DROP)
    next_index = IP4_ARP_N_NEXT; /* point to first interface */

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, IP4_ARP_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  vlib_buffer_t * p0;
	  ip4_header_t * ip0;
	  ethernet_header_t * eh0;
	  u32 pi0, adj_index0, a0, b0, c0, m0, sw_if_index0, drop0;
	  uword bm0;
	  ip_adjacency_t * adj0;

	  pi0 = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[VLIB_TX];
	  adj0 = ip_get_adjacency (lm, adj_index0);
	  ip0 = vlib_buffer_get_current (p0);

	  /* If packet destination is not local, send ARP to next hop */
	  if (adj0->arp.next_hop.ip4.as_u32)
	    ip0->dst_address.data_u32 = adj0->arp.next_hop.ip4.as_u32;

	  /* 
	   * if ip4_rewrite_local applied the IP_LOOKUP_NEXT_ARP
	   * rewrite to this packet, we need to skip it here.
	   * Note, to distinguish from src IP addr *.8.6.*, we
	   * check for a bcast eth dest instead of IPv4 version.
           */
	  eh0 = (ethernet_header_t*)ip0;
	  if ((ip0->ip_version_and_header_length & 0xF0) != 0x40)
            {
              u32 vlan_num = 0;
              u16 * etype = &eh0->type;
              while ((*etype == clib_host_to_net_u16 (0x8100)) //dot1q 
                  || (*etype == clib_host_to_net_u16 (0x88a8)))//dot1ad 
                {
                  vlan_num += 1;
                  etype += 2; //vlan tag also 16 bits, same as etype
                }
              if (*etype == clib_host_to_net_u16 (0x0806))     //arp
                {
                  vlib_buffer_advance (
                      p0, sizeof(ethernet_header_t) + (4*vlan_num));
                  ip0 = vlib_buffer_get_current (p0);
                }
            }

	  a0 = hash_seeds[0];
	  b0 = hash_seeds[1];
	  c0 = hash_seeds[2];

	  sw_if_index0 = adj0->rewrite_header.sw_if_index;
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;

	  a0 ^= ip0->dst_address.data_u32;
	  b0 ^= sw_if_index0;

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

	  p0->error = node->errors[drop0 ? IP4_ARP_ERROR_DROP : IP4_ARP_ERROR_REQUEST_SENT];

	  if (drop0)
	    continue;

          /* 
           * Can happen if the control-plane is programming tables
           * with traffic flowing; at least that's today's lame excuse.
           */
          if (adj0->lookup_next_index != IP_LOOKUP_NEXT_ARP) 
            {
              p0->error = node->errors[IP4_ARP_ERROR_NON_ARP_ADJ];
            }
          else
	  /* Send ARP request. */
	  {
	    u32 bi0 = 0;
	    vlib_buffer_t * b0;
	    ethernet_arp_header_t * h0;
	    vnet_hw_interface_t * hw_if0;

	    h0 = vlib_packet_template_get_packet (vm, &im->ip4_arp_request_packet_template, &bi0);

	    /* Add rewrite/encap string for ARP packet. */
	    vnet_rewrite_one_header (adj0[0], h0, sizeof (ethernet_header_t));

	    hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

	    /* Src ethernet address in ARP header. */
	    clib_memcpy (h0->ip4_over_ethernet[0].ethernet, hw_if0->hw_address,
		    sizeof (h0->ip4_over_ethernet[0].ethernet));

	    if (ip4_src_address_for_packet (im, p0, &h0->ip4_over_ethernet[0].ip4, sw_if_index0)) {
		//No source address available
		p0->error = node->errors[IP4_ARP_ERROR_NO_SOURCE_ADDRESS];
		vlib_buffer_free(vm, &bi0, 1);
		continue;
	    }

	    /* Copy in destination address we are requesting. */
	    h0->ip4_over_ethernet[1].ip4.data_u32 = ip0->dst_address.data_u32;

	    vlib_buffer_copy_trace_flag (vm, p0, bi0);
	    b0 = vlib_get_buffer (vm, bi0);
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	    vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);

	    vlib_set_next_frame_buffer (vm, node, adj0->rewrite_header.next_index, bi0);
	  }
	}

      vlib_put_next_frame (vm, node, IP4_ARP_NEXT_DROP, n_left_to_next_drop);
    }

  return frame->n_vectors;
}

static char * ip4_arp_error_strings[] = {
  [IP4_ARP_ERROR_DROP] = "address overflow drops",
  [IP4_ARP_ERROR_REQUEST_SENT] = "ARP requests sent",
  [IP4_ARP_ERROR_NON_ARP_ADJ] = "ARPs to non-ARP adjacencies",
  [IP4_ARP_ERROR_REPLICATE_DROP] = "ARP replication completed",
  [IP4_ARP_ERROR_REPLICATE_FAIL] = "ARP replication failed",
  [IP4_ARP_ERROR_NO_SOURCE_ADDRESS] = "no source address for ARP request",
};

VLIB_REGISTER_NODE (ip4_arp_node) = {
  .function = ip4_arp,
  .name = "ip4-arp",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,

  .n_errors = ARRAY_LEN (ip4_arp_error_strings),
  .error_strings = ip4_arp_error_strings,

  .n_next_nodes = IP4_ARP_N_NEXT,
  .next_nodes = {
    [IP4_ARP_NEXT_DROP] = "error-drop",
  },
};

#define foreach_notrace_ip4_arp_error           \
_(DROP)                                         \
_(REQUEST_SENT)                                 \
_(REPLICATE_DROP)                               \
_(REPLICATE_FAIL)

clib_error_t * arp_notrace_init (vlib_main_t * vm)
{
  vlib_node_runtime_t *rt = 
    vlib_node_get_runtime (vm, ip4_arp_node.index);

  /* don't trace ARP request packets */
#define _(a)                                    \
    vnet_pcap_drop_trace_filter_add_del         \
        (rt->errors[IP4_ARP_ERROR_##a],         \
         1 /* is_add */);
    foreach_notrace_ip4_arp_error;
#undef _
  return 0;
}

VLIB_INIT_FUNCTION(arp_notrace_init);


/* Send an ARP request to see if given destination is reachable on given interface. */
clib_error_t *
ip4_probe_neighbor (vlib_main_t * vm, ip4_address_t * dst, u32 sw_if_index)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;
  ethernet_arp_header_t * h;
  ip4_address_t * src;
  ip_interface_address_t * ia;
  ip_adjacency_t * adj;
  vnet_hw_interface_t * hi;
  vnet_sw_interface_t * si;
  vlib_buffer_t * b;
  u32 bi = 0;

  si = vnet_get_sw_interface (vnm, sw_if_index);

  if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
      return clib_error_return (0, "%U: interface %U down",
                                format_ip4_address, dst, 
                                format_vnet_sw_if_index_name, vnm, 
                                sw_if_index);
    }

  src = ip4_interface_address_matching_destination (im, dst, sw_if_index, &ia);
  if (! src)
    {
      vnm->api_errno = VNET_API_ERROR_NO_MATCHING_INTERFACE;
      return clib_error_return 
        (0, "no matching interface address for destination %U (interface %U)",
         format_ip4_address, dst,
         format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

  adj = ip_get_adjacency (&im->lookup_main, ia->neighbor_probe_adj_index);

  h = vlib_packet_template_get_packet (vm, &im->ip4_arp_request_packet_template, &bi);

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  clib_memcpy (h->ip4_over_ethernet[0].ethernet, hi->hw_address, sizeof (h->ip4_over_ethernet[0].ethernet));

  h->ip4_over_ethernet[0].ip4 = src[0];
  h->ip4_over_ethernet[1].ip4 = dst[0];

  b = vlib_get_buffer (vm, bi);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  /* Add encapsulation string for software interface (e.g. ethernet header). */
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
  IP4_REWRITE_NEXT_DROP,
  IP4_REWRITE_NEXT_ARP,
  IP4_REWRITE_NEXT_ICMP_ERROR,
} ip4_rewrite_next_t;

always_inline uword
ip4_rewrite_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    int rewrite_for_locally_received_packets)
{
  ip_lookup_main_t * lm = &ip4_main.lookup_main;
  u32 * from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, * to_next, next_index;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip4_input_node.index);
  vlib_rx_or_tx_t adj_rx_tx = rewrite_for_locally_received_packets ? VLIB_RX : VLIB_TX;

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
	  ip4_header_t * ip0, * ip1;
	  u32 pi0, rw_len0, next0, error0, checksum0, adj_index0;
	  u32 pi1, rw_len1, next1, error1, checksum1, adj_index1;
          u32 next0_override, next1_override;
      
          if (rewrite_for_locally_received_packets)
              next0_override = next1_override = 0;

	  /* Prefetch next iteration. */
	  {
            vlib_buffer_t * p2, * p3;

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

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[adj_rx_tx];
	  adj_index1 = vnet_buffer (p1)->ip.adj_index[adj_rx_tx];

          /* We should never rewrite a pkt using the MISS adjacency */
          ASSERT(adj_index0 && adj_index1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  error0 = error1 = IP4_ERROR_NONE;
          next0 = next1 = IP4_REWRITE_NEXT_DROP;

	  /* Decrement TTL & update checksum.
	     Works either endian, so no need for byte swap. */
	  if (! rewrite_for_locally_received_packets)
	    {
	      i32 ttl0 = ip0->ttl, ttl1 = ip1->ttl;

	      /* Input node should have reject packets with ttl 0. */
	      ASSERT (ip0->ttl > 0);
	      ASSERT (ip1->ttl > 0);

	      checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);
	      checksum1 = ip1->checksum + clib_host_to_net_u16 (0x0100);

	      checksum0 += checksum0 >= 0xffff;
	      checksum1 += checksum1 >= 0xffff;

	      ip0->checksum = checksum0;
	      ip1->checksum = checksum1;

	      ttl0 -= 1;
	      ttl1 -= 1;

	      ip0->ttl = ttl0;
	      ip1->ttl = ttl1;

              /*
               * If the ttl drops below 1 when forwarding, generate
               * an ICMP response.
               */
              if (PREDICT_FALSE(ttl0 <= 0))
                {
                  error0 = IP4_ERROR_TIME_EXPIRED;
                  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32)~0;
                  icmp4_error_set_vnet_buffer(p0, ICMP4_time_exceeded,
                              ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
                  next0 = IP4_REWRITE_NEXT_ICMP_ERROR;
                }
              if (PREDICT_FALSE(ttl1 <= 0))
                {
                  error1 = IP4_ERROR_TIME_EXPIRED;
                  vnet_buffer (p1)->sw_if_index[VLIB_TX] = (u32)~0;
                  icmp4_error_set_vnet_buffer(p1, ICMP4_time_exceeded,
                              ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
                  next1 = IP4_REWRITE_NEXT_ICMP_ERROR;
                }

	      /* Verify checksum. */
	      ASSERT (ip0->checksum == ip4_header_checksum (ip0));
	      ASSERT (ip1->checksum == ip4_header_checksum (ip1));
	    }

	  /* Rewrite packet header and updates lengths. */
	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);
      
          if (rewrite_for_locally_received_packets)
            {
              /*
               * If someone sends e.g. an icmp4 w/ src = dst = interface addr,
               * we end up here with a local adjacency in hand
               * The local adj rewrite data is 0xfefe on purpose.
               * Bad engineer, no donut for you.
               */
              if (PREDICT_FALSE(adj0->lookup_next_index 
                                == IP_LOOKUP_NEXT_LOCAL))
                error0 = IP4_ERROR_SPOOFED_LOCAL_PACKETS;
              if (PREDICT_FALSE(adj0->lookup_next_index
                                == IP_LOOKUP_NEXT_ARP))
                next0_override = IP4_REWRITE_NEXT_ARP;
              if (PREDICT_FALSE(adj1->lookup_next_index 
                                == IP_LOOKUP_NEXT_LOCAL))
                error1 = IP4_ERROR_SPOOFED_LOCAL_PACKETS;
              if (PREDICT_FALSE(adj1->lookup_next_index
                                == IP_LOOKUP_NEXT_ARP))
                next1_override = IP4_REWRITE_NEXT_ARP;
            }

          /* Worth pipelining. No guarantee that adj0,1 are hot... */
	  rw_len0 = adj0[0].rewrite_header.data_bytes;
	  rw_len1 = adj1[0].rewrite_header.data_bytes;

          /* Check MTU of outgoing interface. */
          error0 = (vlib_buffer_length_in_chain (vm, p0) > adj0[0].rewrite_header.max_l3_packet_bytes
                    ? IP4_ERROR_MTU_EXCEEDED
                    : error0);
          error1 = (vlib_buffer_length_in_chain (vm, p1) > adj1[0].rewrite_header.max_l3_packet_bytes
                    ? IP4_ERROR_MTU_EXCEEDED
                    : error1);

          next0 = (error0 == IP4_ERROR_NONE)
            ? adj0[0].rewrite_header.next_index : next0;

          if (rewrite_for_locally_received_packets)
              next0 = next0 && next0_override ? next0_override : next0;

          next1 = (error1 == IP4_ERROR_NONE)
            ? adj1[0].rewrite_header.next_index : next1;

          if (rewrite_for_locally_received_packets)
              next1 = next1 && next1_override ? next1_override : next1;

          /* 
           * We've already accounted for an ethernet_header_t elsewhere
           */
          if (PREDICT_FALSE (rw_len0 > sizeof(ethernet_header_t)))
              vlib_increment_combined_counter 
                  (&lm->adjacency_counters,
                   cpu_index, adj_index0, 
                   /* packet increment */ 0,
                   /* byte increment */ rw_len0-sizeof(ethernet_header_t));

          if (PREDICT_FALSE (rw_len1 > sizeof(ethernet_header_t)))
              vlib_increment_combined_counter 
                  (&lm->adjacency_counters,
                   cpu_index, adj_index1, 
                   /* packet increment */ 0,
                   /* byte increment */ rw_len1-sizeof(ethernet_header_t));

          /* Don't adjust the buffer for ttl issue; icmp-error node wants
           * to see the IP headerr */
          if (PREDICT_TRUE(error0 == IP4_ERROR_NONE))
            {
              p0->current_data -= rw_len0;
              p0->current_length += rw_len0;
              p0->error = error_node->errors[error0];
              vnet_buffer (p0)->sw_if_index[VLIB_TX] =
                  adj0[0].rewrite_header.sw_if_index;
            }
          if (PREDICT_TRUE(error1 == IP4_ERROR_NONE))
            {
              p1->current_data -= rw_len1;
              p1->current_length += rw_len1;
              p1->error = error_node->errors[error1];
              vnet_buffer (p1)->sw_if_index[VLIB_TX] =
                  adj1[0].rewrite_header.sw_if_index;
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
	  ip4_header_t * ip0;
	  u32 pi0, rw_len0, adj_index0, next0, error0, checksum0;
          u32 next0_override;
      
          if (rewrite_for_locally_received_packets)
              next0_override = 0;

	  pi0 = to_next[0] = from[0];

	  p0 = vlib_get_buffer (vm, pi0);

	  adj_index0 = vnet_buffer (p0)->ip.adj_index[adj_rx_tx];

          /* We should never rewrite a pkt using the MISS adjacency */
          ASSERT(adj_index0);

	  adj0 = ip_get_adjacency (lm, adj_index0);
      
	  ip0 = vlib_buffer_get_current (p0);

	  error0 = IP4_ERROR_NONE;
          next0 = IP4_REWRITE_NEXT_DROP;            /* drop on error */

	  /* Decrement TTL & update checksum. */
	  if (! rewrite_for_locally_received_packets)
	    {
	      i32 ttl0 = ip0->ttl;

	      checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);

	      checksum0 += checksum0 >= 0xffff;

	      ip0->checksum = checksum0;

	      ASSERT (ip0->ttl > 0);

	      ttl0 -= 1;

	      ip0->ttl = ttl0;

	      ASSERT (ip0->checksum == ip4_header_checksum (ip0));

              if (PREDICT_FALSE(ttl0 <= 0))
                {
                  /*
                   * If the ttl drops below 1 when forwarding, generate
                   * an ICMP response.
                   */
                  error0 = IP4_ERROR_TIME_EXPIRED;
                  next0 = IP4_REWRITE_NEXT_ICMP_ERROR;
                  vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32)~0;
                  icmp4_error_set_vnet_buffer(p0, ICMP4_time_exceeded,
                              ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
                }
	    }

          if (rewrite_for_locally_received_packets)
            {
              /*
               * If someone sends e.g. an icmp4 w/ src = dst = interface addr,
               * we end up here with a local adjacency in hand
               * The local adj rewrite data is 0xfefe on purpose.
               * Bad engineer, no donut for you.
               */
              if (PREDICT_FALSE(adj0->lookup_next_index 
                                == IP_LOOKUP_NEXT_LOCAL))
                error0 = IP4_ERROR_SPOOFED_LOCAL_PACKETS;
              /* 
               * We have to override the next_index in ARP adjacencies,
               * because they're set up for ip4-arp, not this node...
               */
              if (PREDICT_FALSE(adj0->lookup_next_index
                                == IP_LOOKUP_NEXT_ARP))
                next0_override = IP4_REWRITE_NEXT_ARP;
            }

	  /* Guess we are only writing on simple Ethernet header. */
          vnet_rewrite_one_header (adj0[0], ip0, 
                                   sizeof (ethernet_header_t));
          
          /* Update packet buffer attributes/set output interface. */
          rw_len0 = adj0[0].rewrite_header.data_bytes;
          
          if (PREDICT_FALSE (rw_len0 > sizeof(ethernet_header_t)))
              vlib_increment_combined_counter 
                  (&lm->adjacency_counters,
                   cpu_index, adj_index0, 
                   /* packet increment */ 0,
                   /* byte increment */ rw_len0-sizeof(ethernet_header_t));
          
          /* Check MTU of outgoing interface. */
          error0 = (vlib_buffer_length_in_chain (vm, p0) 
                    > adj0[0].rewrite_header.max_l3_packet_bytes
                    ? IP4_ERROR_MTU_EXCEEDED
                    : error0);

	  p0->error = error_node->errors[error0];

          /* Don't adjust the buffer for ttl issue; icmp-error node wants
           * to see the IP headerr */
          if (PREDICT_TRUE(error0 == IP4_ERROR_NONE))
            {
              p0->current_data -= rw_len0;
              p0->current_length += rw_len0;

              vnet_buffer (p0)->sw_if_index[VLIB_TX] =
                  adj0[0].rewrite_header.sw_if_index;
              next0 = adj0[0].rewrite_header.next_index;
            }

          if (rewrite_for_locally_received_packets)
              next0 = next0 && next0_override ? next0_override : next0;

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
    ip4_forward_next_trace (vm, node, frame, adj_rx_tx);

  return frame->n_vectors;
}


/** @brief IPv4 transit rewrite node.
    @node ip4-rewrite-transit

    This is the IPv4 transit-rewrite node: decrement TTL, fix the ipv4
    header checksum, fetch the ip adjacency, check the outbound mtu,
    apply the adjacency rewrite, and send pkts to the adjacency
    rewrite header's rewrite_next_index.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - the rewrite adjacency index
    - <code>adj->lookup_next_index</code>
        - Must be IP_LOOKUP_NEXT_REWRITE or IP_LOOKUP_NEXT_ARP, otherwise
          the packet will be dropped. 
    - <code>adj->rewrite_header</code>
        - Rewrite string length, rewrite string, next_index

    @em Sets:
    - <code>b->current_data, b->current_length</code>
        - Updated net of applying the rewrite string

    <em>Next Indices:</em>
    - <code> adj->rewrite_header.next_index </code>
      or @c error-drop 
*/
static uword
ip4_rewrite_transit (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{
  return ip4_rewrite_inline (vm, node, frame,
			     /* rewrite_for_locally_received_packets */ 0);
}

/** @brief IPv4 local rewrite node.
    @node ip4-rewrite-local

    This is the IPv4 local rewrite node. Fetch the ip adjacency, check
    the outbound interface mtu, apply the adjacency rewrite, and send
    pkts to the adjacency rewrite header's rewrite_next_index. Deal
    with hemorrhoids of the form "some clown sends an icmp4 w/ src =
    dst = interface addr."

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_RX]</code>
        - the rewrite adjacency index
    - <code>adj->lookup_next_index</code>
        - Must be IP_LOOKUP_NEXT_REWRITE or IP_LOOKUP_NEXT_ARP, otherwise
          the packet will be dropped. 
    - <code>adj->rewrite_header</code>
        - Rewrite string length, rewrite string, next_index

    @em Sets:
    - <code>b->current_data, b->current_length</code>
        - Updated net of applying the rewrite string

    <em>Next Indices:</em>
    - <code> adj->rewrite_header.next_index </code>
      or @c error-drop 
*/

static uword
ip4_rewrite_local (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  return ip4_rewrite_inline (vm, node, frame,
			     /* rewrite_for_locally_received_packets */ 1);
}

VLIB_REGISTER_NODE (ip4_rewrite_node) = {
  .function = ip4_rewrite_transit,
  .name = "ip4-rewrite-transit",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_rewrite_trace,

  .n_next_nodes = 3,
  .next_nodes = {
    [IP4_REWRITE_NEXT_DROP] = "error-drop",
    [IP4_REWRITE_NEXT_ARP] = "ip4-arp",
    [IP4_REWRITE_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_rewrite_node, ip4_rewrite_transit)

VLIB_REGISTER_NODE (ip4_rewrite_local_node) = {
  .function = ip4_rewrite_local,
  .name = "ip4-rewrite-local",
  .vector_size = sizeof (u32),

  .sibling_of = "ip4-rewrite-transit",

  .format_trace = format_ip4_rewrite_trace,

  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_rewrite_local_node, ip4_rewrite_local)

static clib_error_t *
add_del_interface_table (vlib_main_t * vm,
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
    ip4_main_t * im = &ip4_main;
    ip4_fib_t * fib = find_ip4_fib_by_table_index_or_id (im, table_id, IP4_ROUTE_FLAG_TABLE_ID);

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
  .path = "set interface ip table",
  .function = add_del_interface_table,
  .short_help = "Add/delete FIB table id for interface",
};


static uword
ip4_lookup_multicast (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  ip4_main_t * im = &ip4_main;
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
	  ip4_header_t * ip0, * ip1;
	  ip_adjacency_t * adj0, * adj1;
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

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	  fib_index1 = vec_elt (im->fib_index_by_sw_if_index, vnet_buffer (p1)->sw_if_index[VLIB_RX]);
          fib_index0 = (vnet_buffer(p0)->sw_if_index[VLIB_TX] == (u32)~0) ?
            fib_index0 : vnet_buffer(p0)->sw_if_index[VLIB_TX];
          fib_index1 = (vnet_buffer(p1)->sw_if_index[VLIB_TX] == (u32)~0) ?
            fib_index1 : vnet_buffer(p1)->sw_if_index[VLIB_TX];

	  adj_index0 = ip4_fib_lookup_buffer (im, fib_index0, 
                                              &ip0->dst_address, p0);
	  adj_index1 = ip4_fib_lookup_buffer (im, fib_index1, 
                                              &ip1->dst_address, p1);

	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);

	  next0 = adj0->lookup_next_index;
	  next1 = adj1->lookup_next_index;

          flow_hash_config0 = 
              vec_elt_at_index (im->fibs, fib_index0)->flow_hash_config;

          flow_hash_config1 = 
              vec_elt_at_index (im->fibs, fib_index1)->flow_hash_config;

	  vnet_buffer (p0)->ip.flow_hash = ip4_compute_flow_hash 
              (ip0, flow_hash_config0);
                                                                  
	  vnet_buffer (p1)->ip.flow_hash = ip4_compute_flow_hash 
              (ip1, flow_hash_config1);

	  ASSERT (adj0->n_adj > 0);
	  ASSERT (adj1->n_adj > 0);
	  ASSERT (is_pow2 (adj0->n_adj));
	  ASSERT (is_pow2 (adj1->n_adj));
	  adj_index0 += (vnet_buffer (p0)->ip.flow_hash & (adj0->n_adj - 1));
	  adj_index1 += (vnet_buffer (p1)->ip.flow_hash & (adj1->n_adj - 1));

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;
	  vnet_buffer (p1)->ip.adj_index[VLIB_TX] = adj_index1;

          if (1) /* $$$$$$ HACK FIXME */
	  vlib_increment_combined_counter 
              (cm, cpu_index, adj_index0, 1,
               vlib_buffer_length_in_chain (vm, p0));
          if (1) /* $$$$$$ HACK FIXME */
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
	  ip4_header_t * ip0;
	  u32 pi0, adj_index0;
	  ip_lookup_next_t next0;
	  ip_adjacency_t * adj0;
          u32 fib_index0;
          u32 flow_hash_config0;

	  pi0 = from[0];
	  to_next[0] = pi0;

	  p0 = vlib_get_buffer (vm, pi0);

	  ip0 = vlib_buffer_get_current (p0);

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, 
                                vnet_buffer (p0)->sw_if_index[VLIB_RX]);
          fib_index0 = (vnet_buffer(p0)->sw_if_index[VLIB_TX] == (u32)~0) ?
              fib_index0 : vnet_buffer(p0)->sw_if_index[VLIB_TX];
          
	  adj_index0 = ip4_fib_lookup_buffer (im, fib_index0, 
                                              &ip0->dst_address, p0);

	  adj0 = ip_get_adjacency (lm, adj_index0);

	  next0 = adj0->lookup_next_index;

          flow_hash_config0 = 
              vec_elt_at_index (im->fibs, fib_index0)->flow_hash_config;

	  vnet_buffer (p0)->ip.flow_hash = 
            ip4_compute_flow_hash (ip0, flow_hash_config0);

	  ASSERT (adj0->n_adj > 0);
	  ASSERT (is_pow2 (adj0->n_adj));
	  adj_index0 += (vnet_buffer (p0)->ip.flow_hash & (adj0->n_adj - 1));

	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = adj_index0;

          if (1) /* $$$$$$ HACK FIXME */
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
      ip4_forward_next_trace(vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip4_lookup_multicast_node,static) = {
  .function = ip4_lookup_multicast,
  .name = "ip4-lookup-multicast",
  .vector_size = sizeof (u32),
  .sibling_of = "ip4-lookup",
  .format_trace = format_ip4_lookup_trace,

  .n_next_nodes = 0,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_lookup_multicast_node, ip4_lookup_multicast)

VLIB_REGISTER_NODE (ip4_multicast_node,static) = {
  .function = ip4_drop,
  .name = "ip4-multicast",
  .vector_size = sizeof (u32),

  .format_trace = format_ip4_forward_next_trace,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

int ip4_lookup_validate (ip4_address_t *a, u32 fib_index0)
{
  ip4_main_t * im = &ip4_main;
  ip4_fib_mtrie_t * mtrie0;
  ip4_fib_mtrie_leaf_t leaf0;
  u32 adj_index0;
    
  mtrie0 = &vec_elt_at_index (im->fibs, fib_index0)->mtrie;

  leaf0 = IP4_FIB_MTRIE_LEAF_ROOT;
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 0);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 1);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 2);
  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, a, 3);
  
  /* Handle default route. */
  leaf0 = (leaf0 == IP4_FIB_MTRIE_LEAF_EMPTY ? mtrie0->default_leaf : leaf0);
  
  adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
  
  return adj_index0 == ip4_fib_lookup_with_table (im, fib_index0,
                                                  a, 
                                                  /* no_default_route */ 0);
}
 
static clib_error_t *
test_lookup_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
  u32 table_id = 0;
  f64 count = 1;
  u32 n;
  int i;
  ip4_address_t ip4_base_address;
  u64 errors = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
      if (unformat (input, "table %d", &table_id))
	;
      else if (unformat (input, "count %f", &count))
	;

      else if (unformat (input, "%U",
			 unformat_ip4_address, &ip4_base_address))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
  }

  n = count;

  for (i = 0; i < n; i++)
    {
      if (!ip4_lookup_validate (&ip4_base_address, table_id))
        errors++;

      ip4_base_address.as_u32 = 
        clib_host_to_net_u32 (1 + 
                              clib_net_to_host_u32 (ip4_base_address.as_u32));
    }

  if (errors) 
    vlib_cli_output (vm, "%llu errors out of %d lookups\n", errors, n);
  else
    vlib_cli_output (vm, "No errors in %d lookups\n", n);

  return 0;
}

VLIB_CLI_COMMAND (lookup_test_command, static) = {
    .path = "test lookup",
    .short_help = "test lookup",
    .function = test_lookup_command_fn,
};

int vnet_set_ip4_flow_hash (u32 table_id, u32 flow_hash_config)
{
  ip4_main_t * im4 = &ip4_main;
  ip4_fib_t * fib;
  uword * p = hash_get (im4->fib_index_by_table_id, table_id);

  if (p == 0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib = vec_elt_at_index (im4->fibs, p[0]);

  fib->flow_hash_config = flow_hash_config;
  return 0;
}
 
static clib_error_t *
set_ip_flow_hash_command_fn (vlib_main_t * vm,
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
  
  rv = vnet_set_ip4_flow_hash (table_id, flow_hash_config);
  switch (rv)
    {
    case 0:
      break;
      
    case VNET_API_ERROR_NO_SUCH_FIB:
      return clib_error_return (0, "no such FIB table %d", table_id);
      
    default:
      clib_warning ("BUG: illegal flow hash config 0x%x", flow_hash_config);
      break;
    }
  
  return 0;
}
 
VLIB_CLI_COMMAND (set_ip_flow_hash_command, static) = {
  .path = "set ip flow-hash",
  .short_help = 
  "set ip table flow-hash table <fib-id> src dst sport dport proto reverse",
  .function = set_ip_flow_hash_command_fn,
};
 
int vnet_set_ip4_classify_intfc (vlib_main_t * vm, u32 sw_if_index, 
                                 u32 table_index)
{
  vnet_main_t * vnm = vnet_get_main();
  vnet_interface_main_t * im = &vnm->interface_main;
  ip4_main_t * ipm = &ip4_main;
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
set_ip_classify_command_fn (vlib_main_t * vm,
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

  rv = vnet_set_ip4_classify_intfc (vm, sw_if_index, table_index);

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

VLIB_CLI_COMMAND (set_ip_classify_command, static) = {
    .path = "set ip classify",
    .short_help = 
    "set ip classify intfc <int> table-index <index>",
    .function = set_ip_classify_command_fn,
};

