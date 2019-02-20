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

/**
 * @brief
 * Policy packet & bytes counters
 */
vlib_combined_counter_main_t ipsec_spd_policy_counters = {
  .name = "policy",
  .stat_segment_name = "/net/ipsec/policy",
};

static int
ipsec_policy_is_equal (ipsec_policy_t * p1, ipsec_policy_t * p2)
{
  if (p1->priority != p2->priority)
    return 0;
  if (p1->is_outbound != p2->is_outbound)
    return (0);
  if (p1->policy != p2->policy)
    return (0);
  if (p1->sa_id != p2->sa_id)
    return (0);
  if (p1->protocol != p2->protocol)
    return (0);
  if (p1->lport.start != p2->lport.start)
    return (0);
  if (p1->lport.stop != p2->lport.stop)
    return (0);
  if (p1->rport.start != p2->rport.start)
    return (0);
  if (p1->rport.stop != p2->rport.stop)
    return (0);
  if (p1->is_ipv6 != p2->is_ipv6)
    return (0);
  if (p2->is_ipv6)
    {
      if (p1->laddr.start.ip6.as_u64[0] != p2->laddr.start.ip6.as_u64[0])
	return (0);
      if (p1->laddr.start.ip6.as_u64[1] != p2->laddr.start.ip6.as_u64[1])
	return (0);
      if (p1->laddr.stop.ip6.as_u64[0] != p2->laddr.stop.ip6.as_u64[0])
	return (0);
      if (p1->laddr.stop.ip6.as_u64[1] != p2->laddr.stop.ip6.as_u64[1])
	return (0);
      if (p1->raddr.start.ip6.as_u64[0] != p2->raddr.start.ip6.as_u64[0])
	return (0);
      if (p1->raddr.start.ip6.as_u64[1] != p2->raddr.start.ip6.as_u64[1])
	return (0);
      if (p1->raddr.stop.ip6.as_u64[0] != p2->raddr.stop.ip6.as_u64[0])
	return (0);
      if (p1->laddr.stop.ip6.as_u64[1] != p2->laddr.stop.ip6.as_u64[1])
	return (0);
    }
  else
    {
      if (p1->laddr.start.ip4.as_u32 != p2->laddr.start.ip4.as_u32)
	return (0);
      if (p1->laddr.stop.ip4.as_u32 != p2->laddr.stop.ip4.as_u32)
	return (0);
      if (p1->raddr.start.ip4.as_u32 != p2->raddr.start.ip4.as_u32)
	return (0);
      if (p1->raddr.stop.ip4.as_u32 != p2->raddr.stop.ip4.as_u32)
	return (0);
    }
  return (1);
}

static int
ipsec_spd_entry_sort (void *a1, void *a2)
{
  ipsec_main_t *im = &ipsec_main;
  u32 *id1 = a1;
  u32 *id2 = a2;
  ipsec_policy_t *p1, *p2;

  p1 = pool_elt_at_index (im->policies, *id1);
  p2 = pool_elt_at_index (im->policies, *id2);
  if (p1 && p2)
    return p2->priority - p1->priority;

  return 0;
}

int
ipsec_add_del_policy (vlib_main_t * vm,
		      ipsec_policy_t * policy, int is_add, u32 * stat_index)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd = 0;
  ipsec_policy_t *vp;
  u32 spd_index;
  uword *p;

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

      pool_get (im->policies, vp);
      clib_memcpy (vp, policy, sizeof (*vp));
      policy_index = vp - im->policies;

      vlib_validate_combined_counter (&ipsec_spd_policy_counters,
				      policy_index);
      vlib_zero_combined_counter (&ipsec_spd_policy_counters, policy_index);

      if (policy->is_outbound)
	{
	  if (policy->is_ipv6)
	    {
	      vec_add1 (spd->policies[IPSEC_SPD_POLICY_IP6_OUTBOUND],
			policy_index);
	      vec_sort_with_function (spd->policies
				      [IPSEC_SPD_POLICY_IP6_OUTBOUND],
				      ipsec_spd_entry_sort);
	    }
	  else
	    {
	      vec_add1 (spd->policies[IPSEC_SPD_POLICY_IP4_OUTBOUND],
			policy_index);
	      vec_sort_with_function (spd->policies
				      [IPSEC_SPD_POLICY_IP4_OUTBOUND],
				      ipsec_spd_entry_sort);
	    }
	}
      else
	{
	  if (policy->is_ipv6)
	    {
	      if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
		{
		  vec_add1 (spd->policies
			    [IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT],
			    policy_index);
		  vec_sort_with_function (spd->policies
					  [IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT],
					  ipsec_spd_entry_sort);
		}
	      else
		{
		  vec_add1
		    (spd->policies[IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS],
		     policy_index);
		  vec_sort_with_function
		    (spd->policies[IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS],
		     ipsec_spd_entry_sort);
		}
	    }
	  else
	    {
	      if (policy->policy == IPSEC_POLICY_ACTION_PROTECT)
		{
		  vec_add1 (spd->policies
			    [IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT],
			    policy_index);
		  vec_sort_with_function (spd->policies
					  [IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT],
					  ipsec_spd_entry_sort);
		}
	      else
		{
		  vec_add1
		    (spd->policies[IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS],
		     policy_index);
		  vec_sort_with_function
		    (spd->policies[IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS],
		     ipsec_spd_entry_sort);
		}
	    }
	}
      *stat_index = policy_index;
    }
  else
    {
      ipsec_spd_policy_t ptype;
      u32 ii;

      FOR_EACH_IPSEC_SPD_POLICY_TYPE (ptype)
      {
	vec_foreach_index (ii, (spd->policies[ptype]))
	{
	  vp = pool_elt_at_index (im->policies, spd->policies[ptype][ii]);
	  if (ipsec_policy_is_equal (vp, policy))
	    {
	      vec_del1 (spd->policies[ptype], ii);
	      pool_put (im->policies, vp);
	      goto done;
	    }
	}
      }
    done:;
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
