/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>

/**
 * @file
 * @brief IP prefix management on interfaces
 */

u32
ip_interface_address_find (ip_lookup_main_t * lm,
			   void *addr_fib, u32 address_length)
{
  uword *p = mhash_get (&lm->address_to_if_address_index, addr_fib);

  if (p)
    return (p[0]);

  return (~0);
}

clib_error_t *
ip_interface_address_add (ip_lookup_main_t * lm,
			  u32 sw_if_index,
			  void *addr_fib,
			  u32 address_length, u32 * result_if_address_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip_interface_address_t *a, *prev;
  u32 pi;			/* previous index */
  u32 ai;
  u32 hi;			/* head index */

  /* Verify given length. */
  if ((address_length == 0) ||
      (lm->is_ip6 && address_length > 128) ||
      (!lm->is_ip6 && address_length > 32))
    {
      vnm->api_errno = VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH;
      return clib_error_create
	("%U wrong length for interface %U",
	 lm->format_address_and_length, addr_fib,
	 address_length, format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

  vec_validate_init_empty (lm->if_address_pool_index_by_sw_if_index,
			   sw_if_index, ~0);

  pool_get_zero (lm->if_address_pool, a);

  ai = a - lm->if_address_pool;
  hi = pi = lm->if_address_pool_index_by_sw_if_index[sw_if_index];

  prev = 0;
  while (pi != (u32) ~ 0)
    {
      prev = pool_elt_at_index (lm->if_address_pool, pi);
      pi = prev->next_this_sw_interface;
    }
  pi = prev ? prev - lm->if_address_pool : (u32) ~ 0;

  a->address_key = mhash_set (&lm->address_to_if_address_index,
			      addr_fib, ai, /* old_value */ 0);
  a->address_length = address_length;
  a->sw_if_index = sw_if_index;
  a->flags = 0;
  a->prev_this_sw_interface = pi;
  a->next_this_sw_interface = ~0;
  if (prev)
    prev->next_this_sw_interface = ai;

  lm->if_address_pool_index_by_sw_if_index[sw_if_index] =
    (hi != ~0) ? hi : ai;

  *result_if_address_index = ai;

  return (NULL);
}

clib_error_t *
ip_interface_address_del (ip_lookup_main_t * lm,
			  u32 address_index, void *addr_fib,
			  u32 address_length, u32 sw_if_index)
{
  ip_interface_address_t *a, *prev, *next;

  a = pool_elt_at_index (lm->if_address_pool, address_index);

  if (a->sw_if_index != sw_if_index)
    return clib_error_create ("%U not found for interface %U",
			      lm->format_address_and_length,
			      addr_fib, address_length,
			      format_vnet_sw_if_index_name,
			      vnet_get_main (), sw_if_index);

  if (a->prev_this_sw_interface != ~0)
    {
      prev = pool_elt_at_index (lm->if_address_pool,
				a->prev_this_sw_interface);
      prev->next_this_sw_interface = a->next_this_sw_interface;
    }
  if (a->next_this_sw_interface != ~0)
    {
      next = pool_elt_at_index (lm->if_address_pool,
				a->next_this_sw_interface);
      next->prev_this_sw_interface = a->prev_this_sw_interface;

      if (a->prev_this_sw_interface == ~0)
	lm->if_address_pool_index_by_sw_if_index[a->sw_if_index] =
	  a->next_this_sw_interface;
    }

  if ((a->next_this_sw_interface == ~0) && (a->prev_this_sw_interface == ~0))
    lm->if_address_pool_index_by_sw_if_index[a->sw_if_index] = ~0;

  mhash_unset (&lm->address_to_if_address_index, addr_fib,
	       /* old_value */ 0);
  pool_put (lm->if_address_pool, a);
  return NULL;
}

u8
ip_interface_has_address (u32 sw_if_index, ip46_address_t * ip, u8 is_ip4)
{
  ip_interface_address_t *ia = 0;

  if (is_ip4)
    {
      ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
      ip4_address_t *ip4;
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip4 = ip_interface_address_get_address (lm4, ia);
        if (ip4_address_compare (ip4, &ip->ip4) == 0)
          return 1;
      }));
      /* *INDENT-ON* */
    }
  else
    {
      ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
      ip6_address_t *ip6;
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip6 = ip_interface_address_get_address (lm6, ia);
        if (ip6_address_compare (ip6, &ip->ip6) == 0)
          return 1;
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

void *
ip_interface_get_first_ip (u32 sw_if_index, u8 is_ip4)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;

  if (is_ip4)
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        return ip_interface_address_get_address (lm4, ia);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip6_address_t *rv;
        rv = ip_interface_address_get_address (lm6, ia);
        /* Trying to use a link-local ip6 src address is a fool's errand */
        if (!ip6_address_is_link_local_unicast (rv))
          return rv;
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

static walk_rc_t
ip_interface_address_mark_one_interface (vnet_main_t * vnm,
					 vnet_sw_interface_t * si, void *ctx)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm4, ia, si->sw_if_index, 1 /* unnumbered */ ,
  ({
    ia->flags |= IP_INTERFACE_ADDRESS_FLAG_STALE;
  }));
  foreach_ip_interface_address (lm6, ia, si->sw_if_index, 1 /* unnumbered */ ,
  ({
    ia->flags |= IP_INTERFACE_ADDRESS_FLAG_STALE;
  }));
  /* *INDENT-ON* */

  return (WALK_CONTINUE);
}

void
ip_interface_address_mark (void)
{
  vnet_sw_interface_walk (vnet_get_main (),
			  ip_interface_address_mark_one_interface, NULL);
}

static walk_rc_t
ip_interface_address_sweep_one_interface (vnet_main_t * vnm,
					  vnet_sw_interface_t * si, void *ctx)
{
  vlib_main_t *vm = vlib_get_main ();
  ip4_address_t *ip4_addrs = 0;
  ip6_address_t *ip6_addrs = 0;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  ip_interface_address_t *ia;
  u32 *ip6_masks = 0;
  u32 *ip4_masks = 0;
  int i;

  /* *INDENT-OFF* */
  foreach_ip_interface_address (&im4->lookup_main, ia, si->sw_if_index, 1,
  ({
    if (ia->flags & IP_INTERFACE_ADDRESS_FLAG_STALE)
      {
        ip4_address_t * x = (ip4_address_t *)
          ip_interface_address_get_address (&im4->lookup_main, ia);
        vec_add1 (ip4_addrs, x[0]);
        vec_add1 (ip4_masks, ia->address_length);
      }
  }));

  foreach_ip_interface_address (&im6->lookup_main, ia, si->sw_if_index, 1,
  ({
    if (ia->flags & IP_INTERFACE_ADDRESS_FLAG_STALE)
      {
        ip6_address_t * x = (ip6_address_t *)
          ip_interface_address_get_address (&im6->lookup_main, ia);
        vec_add1 (ip6_addrs, x[0]);
        vec_add1 (ip6_masks, ia->address_length);
      }
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (ip4_addrs); i++)
    ip4_add_del_interface_address (vm, si->sw_if_index, &ip4_addrs[i],
				   ip4_masks[i], 1 /* is_del */ );
  for (i = 0; i < vec_len (ip6_addrs); i++)
    ip6_add_del_interface_address (vm, si->sw_if_index, &ip6_addrs[i],
				   ip6_masks[i], 1 /* is_del */ );

  vec_free (ip4_addrs);
  vec_free (ip4_masks);
  vec_free (ip6_addrs);
  vec_free (ip6_masks);

  return (WALK_CONTINUE);
}

void
ip_interface_address_sweep (void)
{
  vnet_sw_interface_walk (vnet_get_main (),
			  ip_interface_address_sweep_one_interface, NULL);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
