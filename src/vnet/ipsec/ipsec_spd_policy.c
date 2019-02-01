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

#include <vnet/ipsec/ipsec.h>

static int
ipsec_spd_entry_sort (void *a1, void *a2)
{
  u32 *id1 = a1;
  u32 *id2 = a2;
  ipsec_spd_t *spd = ipsec_main.spd_to_sort;
  ipsec_policy_t *p1, *p2;

  p1 = pool_elt_at_index (spd->policies, *id1);
  p2 = pool_elt_at_index (spd->policies, *id2);
  if (p1 && p2)
    return p2->priority - p1->priority;

  return 0;
}

int
ipsec_add_del_policy (vlib_main_t * vm, ipsec_policy_t * policy, int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd = 0;
  ipsec_policy_t *vp;
  uword *p;
  u32 spd_index;

  clib_warning ("policy-id %u priority %d is_outbound %u", policy->id,
		policy->priority, policy->is_outbound);

  if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
    {
      p = hash_get (im->sa_index_by_sa_id, policy->sa_id);
      if (!p)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
      policy->sa_index = p[0];
    }

  p = hash_get (im->spd_index_by_spd_id, policy->id);

  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  spd_index = p[0];
  spd = pool_elt_at_index (im->spds, spd_index);
  if (!spd)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  if (is_add)
    {
      u32 policy_index;

      pool_get (spd->policies, vp);
      clib_memcpy (vp, policy, sizeof (*vp));
      policy_index = vp - spd->policies;

      ipsec_main.spd_to_sort = spd;

      if (policy->is_outbound)
	{
	  if (policy->is_ipv6)
	    {
	      vec_add1 (spd->ipv6_outbound_policies, policy_index);
	      vec_sort_with_function (spd->ipv6_outbound_policies,
				      ipsec_spd_entry_sort);
	    }
	  else
	    {
	      vec_add1 (spd->ipv4_outbound_policies, policy_index);
	      vec_sort_with_function (spd->ipv4_outbound_policies,
				      ipsec_spd_entry_sort);
	    }
	}
      else
	{
	  if (policy->is_ipv6)
	    {
	      if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
		{
		  vec_add1 (spd->ipv6_inbound_protect_policy_indices,
			    policy_index);
		  vec_sort_with_function
		    (spd->ipv6_inbound_protect_policy_indices,
		     ipsec_spd_entry_sort);
		}
	      else
		{
		  vec_add1
		    (spd->ipv6_inbound_policy_discard_and_bypass_indices,
		     policy_index);
		  vec_sort_with_function
		    (spd->ipv6_inbound_policy_discard_and_bypass_indices,
		     ipsec_spd_entry_sort);
		}
	    }
	  else
	    {
	      if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
		{
		  vec_add1 (spd->ipv4_inbound_protect_policy_indices,
			    policy_index);
		  vec_sort_with_function
		    (spd->ipv4_inbound_protect_policy_indices,
		     ipsec_spd_entry_sort);
		}
	      else
		{
		  vec_add1
		    (spd->ipv4_inbound_policy_discard_and_bypass_indices,
		     policy_index);
		  vec_sort_with_function
		    (spd->ipv4_inbound_policy_discard_and_bypass_indices,
		     ipsec_spd_entry_sort);
		}
	    }
	}

      ipsec_main.spd_to_sort = NULL;
    }
  else
    {
      u32 i, j;
      /* *INDENT-OFF* */
      pool_foreach_index(i, spd->policies, ({
        vp = pool_elt_at_index(spd->policies, i);
        if (vp->priority != policy->priority)
          continue;
        if (vp->is_outbound != policy->is_outbound)
          continue;
        if (vp->policy != policy->policy)
          continue;
        if (vp->sa_id != policy->sa_id)
          continue;
        if (vp->protocol != policy->protocol)
          continue;
        if (vp->lport.start != policy->lport.start)
          continue;
        if (vp->lport.stop != policy->lport.stop)
          continue;
        if (vp->rport.start != policy->rport.start)
          continue;
        if (vp->rport.stop != policy->rport.stop)
          continue;
        if (vp->is_ipv6 != policy->is_ipv6)
          continue;
        if (policy->is_ipv6)
          {
            if (vp->laddr.start.ip6.as_u64[0] != policy->laddr.start.ip6.as_u64[0])
              continue;
            if (vp->laddr.start.ip6.as_u64[1] != policy->laddr.start.ip6.as_u64[1])
              continue;
            if (vp->laddr.stop.ip6.as_u64[0] != policy->laddr.stop.ip6.as_u64[0])
              continue;
            if (vp->laddr.stop.ip6.as_u64[1] != policy->laddr.stop.ip6.as_u64[1])
              continue;
            if (vp->raddr.start.ip6.as_u64[0] != policy->raddr.start.ip6.as_u64[0])
              continue;
            if (vp->raddr.start.ip6.as_u64[1] != policy->raddr.start.ip6.as_u64[1])
              continue;
            if (vp->raddr.stop.ip6.as_u64[0] != policy->raddr.stop.ip6.as_u64[0])
              continue;
           if (vp->laddr.stop.ip6.as_u64[1] != policy->laddr.stop.ip6.as_u64[1])
              continue;
           if (policy->is_outbound)
             {
               vec_foreach_index(j, spd->ipv6_outbound_policies) {
                 if (vec_elt(spd->ipv6_outbound_policies, j) == i) {
                   vec_del1 (spd->ipv6_outbound_policies, j);
                   break;
                 }
               }
             }
           else
             {
               if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
                 {
                   vec_foreach_index(j, spd->ipv6_inbound_protect_policy_indices) {
                     if (vec_elt(spd->ipv6_inbound_protect_policy_indices, j) == i) {
                       vec_del1 (spd->ipv6_inbound_protect_policy_indices, j);
                       break;
                     }
                   }
                 }
               else
                 {
                   vec_foreach_index(j, spd->ipv6_inbound_policy_discard_and_bypass_indices) {
                     if (vec_elt(spd->ipv6_inbound_policy_discard_and_bypass_indices, j) == i) {
                       vec_del1 (spd->ipv6_inbound_policy_discard_and_bypass_indices, j);
                       break;
                     }
                   }
                 }
             }
          }
        else
          {
            if (vp->laddr.start.ip4.as_u32 != policy->laddr.start.ip4.as_u32)
              continue;
            if (vp->laddr.stop.ip4.as_u32 != policy->laddr.stop.ip4.as_u32)
              continue;
            if (vp->raddr.start.ip4.as_u32 != policy->raddr.start.ip4.as_u32)
              continue;
            if (vp->raddr.stop.ip4.as_u32 != policy->raddr.stop.ip4.as_u32)
              continue;
            if (policy->is_outbound)
              {
                vec_foreach_index(j, spd->ipv4_outbound_policies) {
                  if (vec_elt(spd->ipv4_outbound_policies, j) == i) {
                    vec_del1 (spd->ipv4_outbound_policies, j);
                    break;
                  }
                }
              }
            else
              {
                if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
                  {
                    vec_foreach_index(j, spd->ipv4_inbound_protect_policy_indices) {
                      if (vec_elt(spd->ipv4_inbound_protect_policy_indices, j) == i) {
                        vec_del1 (spd->ipv4_inbound_protect_policy_indices, j);
                        break;
                      }
                    }
                  }
                else
                  {
                    vec_foreach_index(j, spd->ipv4_inbound_policy_discard_and_bypass_indices) {
                      if (vec_elt(spd->ipv4_inbound_policy_discard_and_bypass_indices, j) == i) {
                        vec_del1 (spd->ipv4_inbound_policy_discard_and_bypass_indices, j);
                        break;
                      }
                    }
                  }
              }
          }
          pool_put (spd->policies, vp);
          break;
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
