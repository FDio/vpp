/*
 * decap.c : IPSec tunnel support
 *
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>
#include <vnet/udp/udp.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>


ipsec_main_t ipsec_main;

u32
ipsec_get_sa_index_by_sa_id (u32 sa_id)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p = hash_get (im->sa_index_by_sa_id, sa_id);
  if (!p)
    return ~0;

  return p[0];
}

int
ipsec_set_interface_spd (vlib_main_t * vm, u32 sw_if_index, u32 spd_id,
			 int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ip4_ipsec_config_t config;

  u32 spd_index;
  uword *p;

  p = hash_get (im->spd_index_by_spd_id, spd_id);
  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* no such spd-id */

  spd_index = p[0];

  p = hash_get (im->spd_index_by_sw_if_index, sw_if_index);
  if (p && is_add)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* spd already assigned */

  if (is_add)
    {
      hash_set (im->spd_index_by_sw_if_index, sw_if_index, spd_index);
    }
  else
    {
      hash_unset (im->spd_index_by_sw_if_index, sw_if_index);
    }

  clib_warning ("sw_if_index %u spd_id %u spd_index %u",
		sw_if_index, spd_id, spd_index);

  /* enable IPsec on TX */
  vnet_feature_enable_disable ("ip4-output", "ipsec4-output-feature",
			       sw_if_index, is_add, 0, 0);
  vnet_feature_enable_disable ("ip6-output", "ipsec6-output-feature",
			       sw_if_index, is_add, 0, 0);

  config.spd_index = spd_index;

  /* enable IPsec on RX */
  vnet_feature_enable_disable ("ip4-unicast", "ipsec4-input-feature",
			       sw_if_index, is_add, &config, sizeof (config));
  vnet_feature_enable_disable ("ip6-unicast", "ipsec6-input-feature",
			       sw_if_index, is_add, &config, sizeof (config));

  return 0;
}

int
ipsec_add_del_spd (vlib_main_t * vm, u32 spd_id, int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd = 0;
  uword *p;
  u32 spd_index, k, v;

  p = hash_get (im->spd_index_by_spd_id, spd_id);
  if (p && is_add)
    return VNET_API_ERROR_INVALID_VALUE;
  if (!p && !is_add)
    return VNET_API_ERROR_INVALID_VALUE;

  if (!is_add)			/* delete */
    {
      spd_index = p[0];
      spd = pool_elt_at_index (im->spds, spd_index);
      if (!spd)
	return VNET_API_ERROR_INVALID_VALUE;
      /* *INDENT-OFF* */
      hash_foreach (k, v, im->spd_index_by_sw_if_index, ({
        if (v == spd_index)
          ipsec_set_interface_spd(vm, k, spd_id, 0);
      }));
      /* *INDENT-ON* */
      hash_unset (im->spd_index_by_spd_id, spd_id);
      pool_free (spd->policies);
      vec_free (spd->ipv4_outbound_policies);
      vec_free (spd->ipv6_outbound_policies);
      vec_free (spd->ipv4_inbound_protect_policy_indices);
      vec_free (spd->ipv4_inbound_policy_discard_and_bypass_indices);
      pool_put (im->spds, spd);
    }
  else				/* create new SPD */
    {
      pool_get (im->spds, spd);
      clib_memset (spd, 0, sizeof (*spd));
      spd_index = spd - im->spds;
      spd->id = spd_id;
      hash_set (im->spd_index_by_spd_id, spd_id, spd_index);
    }
  return 0;
}

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

u8
ipsec_is_sa_used (u32 sa_index)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd;
  ipsec_policy_t *p;
  ipsec_tunnel_if_t *t;

  /* *INDENT-OFF* */
  pool_foreach(spd, im->spds, ({
    pool_foreach(p, spd->policies, ({
      if (p->policy == IPSEC_POLICY_ACTION_PROTECT)
        {
          if (p->sa_index == sa_index)
            return 1;
        }
    }));
  }));

  pool_foreach(t, im->tunnel_interfaces, ({
    if (t->input_sa_index == sa_index)
      return 1;
    if (t->output_sa_index == sa_index)
      return 1;
  }));
  /* *INDENT-ON* */

  return 0;
}

clib_error_t *
ipsec_call_add_del_callbacks (ipsec_main_t * im, ipsec_sa_t * sa,
			      u32 sa_index, int is_add)
{
  ipsec_ah_backend_t *ab;
  ipsec_esp_backend_t *eb;
  switch (sa->protocol)
    {
    case IPSEC_PROTOCOL_AH:
      ab = pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      if (ab->add_del_sa_sess_cb)
	return ab->add_del_sa_sess_cb (sa_index, is_add);
      break;
    case IPSEC_PROTOCOL_ESP:
      eb = pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      if (eb->add_del_sa_sess_cb)
	return eb->add_del_sa_sess_cb (sa_index, is_add);
      break;
    }
  return 0;
}

int
ipsec_add_del_sa (vlib_main_t * vm, ipsec_sa_t * new_sa, int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa = 0;
  uword *p;
  u32 sa_index;
  clib_error_t *err;

  clib_warning ("id %u spi %u", new_sa->id, new_sa->spi);

  p = hash_get (im->sa_index_by_sa_id, new_sa->id);
  if (p && is_add)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* already exists */
  if (!p && !is_add)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  if (!is_add)			/* delete */
    {
      sa_index = p[0];
      sa = pool_elt_at_index (im->sad, sa_index);
      if (ipsec_is_sa_used (sa_index))
	{
	  clib_warning ("sa_id %u used in policy", sa->id);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;	/* sa used in policy */
	}
      hash_unset (im->sa_index_by_sa_id, sa->id);
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
      pool_put (im->sad, sa);
    }
  else				/* create new SA */
    {
      pool_get (im->sad, sa);
      clib_memcpy (sa, new_sa, sizeof (*sa));
      sa_index = sa - im->sad;
      hash_set (im->sa_index_by_sa_id, sa->id, sa_index);
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 1);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  return 0;
}

int
ipsec_set_sa_key (vlib_main_t * vm, ipsec_sa_t * sa_update)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  u32 sa_index;
  ipsec_sa_t *sa = 0;
  clib_error_t *err;

  p = hash_get (im->sa_index_by_sa_id, sa_update->id);
  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* no such sa-id */

  sa_index = p[0];
  sa = pool_elt_at_index (im->sad, sa_index);

  /* new crypto key */
  if (0 < sa_update->crypto_key_len)
    {
      clib_memcpy (sa->crypto_key, sa_update->crypto_key,
		   sa_update->crypto_key_len);
      sa->crypto_key_len = sa_update->crypto_key_len;
    }

  /* new integ key */
  if (0 < sa_update->integ_key_len)
    {
      clib_memcpy (sa->integ_key, sa_update->integ_key,
		   sa_update->integ_key_len);
      sa->integ_key_len = sa_update->integ_key_len;
    }

  if (0 < sa_update->crypto_key_len || 0 < sa_update->integ_key_len)
    {
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  return 0;
}

static void
ipsec_rand_seed (void)
{
  struct
  {
    time_t time;
    pid_t pid;
    void *p;
  } seed_data;

  seed_data.time = time (NULL);
  seed_data.pid = getpid ();
  seed_data.p = (void *) &seed_data;

  RAND_seed ((const void *) &seed_data, sizeof (seed_data));
}

static clib_error_t *
ipsec_check_support (ipsec_sa_t * sa)
{
  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_GCM_128)
    return clib_error_return (0, "unsupported aes-gcm-128 crypto-alg");
  if (sa->integ_alg == IPSEC_INTEG_ALG_NONE)
    return clib_error_return (0, "unsupported none integ-alg");

  return 0;
}

clib_error_t *
ipsec_add_del_sa_sess_cb (ipsec_main_t * im, u32 sa_index, u8 is_add)
{
  ipsec_ah_backend_t *ah =
    pool_elt_at_index (im->ah_backends, im->ah_current_backend);
  if (ah->add_del_sa_sess_cb)
    {
      clib_error_t *err = ah->add_del_sa_sess_cb (sa_index, is_add);
      if (err)
	return err;
    }
  ipsec_esp_backend_t *esp =
    pool_elt_at_index (im->esp_backends, im->esp_current_backend);
  if (esp->add_del_sa_sess_cb)
    {
      clib_error_t *err = esp->add_del_sa_sess_cb (sa_index, is_add);
      if (err)
	return err;
    }
  return 0;
}

clib_error_t *
ipsec_check_support_cb (ipsec_main_t * im, ipsec_sa_t * sa)
{
  clib_error_t *error = 0;

  if (PREDICT_FALSE (sa->protocol == IPSEC_PROTOCOL_AH))
    {
      ipsec_ah_backend_t *ah =
	pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      ASSERT (ah->check_support_cb);
      error = ah->check_support_cb (sa);
    }
  else
    {
      ipsec_esp_backend_t *esp =
	pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      ASSERT (esp->check_support_cb);
      error = esp->check_support_cb (sa);
    }
  return error;
}


static void
ipsec_add_node (vlib_main_t * vm, const char *node_name,
		const char *prev_node_name, u32 * out_node_index,
		u32 * out_next_index)
{
  vlib_node_t *prev_node, *node;
  prev_node = vlib_get_node_by_name (vm, (u8 *) prev_node_name);
  ASSERT (prev_node);
  node = vlib_get_node_by_name (vm, (u8 *) node_name);
  ASSERT (node);
  *out_node_index = node->index;
  *out_next_index = vlib_node_add_next (vm, prev_node->index, node->index);
}

u32
ipsec_register_ah_backend (vlib_main_t * vm, ipsec_main_t * im,
			   const char *name,
			   const char *ah4_encrypt_node_name,
			   const char *ah4_decrypt_node_name,
			   const char *ah6_encrypt_node_name,
			   const char *ah6_decrypt_node_name,
			   check_support_cb_t ah_check_support_cb,
			   add_del_sa_sess_cb_t ah_add_del_sa_sess_cb)
{
  ipsec_ah_backend_t *b;
  pool_get (im->ah_backends, b);
  b->name = format (NULL, "%s", name);

  ipsec_add_node (vm, ah4_encrypt_node_name, "ipsec4-output-feature",
		  &b->ah4_encrypt_node_index, &b->ah4_encrypt_next_index);
  ipsec_add_node (vm, ah4_decrypt_node_name, "ipsec4-input-feature",
		  &b->ah4_decrypt_node_index, &b->ah4_decrypt_next_index);
  ipsec_add_node (vm, ah6_encrypt_node_name, "ipsec6-output-feature",
		  &b->ah6_encrypt_node_index, &b->ah6_encrypt_next_index);
  ipsec_add_node (vm, ah6_decrypt_node_name, "ipsec6-input-feature",
		  &b->ah6_decrypt_node_index, &b->ah6_decrypt_next_index);

  b->check_support_cb = ah_check_support_cb;
  b->add_del_sa_sess_cb = ah_add_del_sa_sess_cb;
  return b - im->ah_backends;
}

u32
ipsec_register_esp_backend (vlib_main_t * vm, ipsec_main_t * im,
			    const char *name,
			    const char *esp4_encrypt_node_name,
			    const char *esp4_decrypt_node_name,
			    const char *esp6_encrypt_node_name,
			    const char *esp6_decrypt_node_name,
			    check_support_cb_t esp_check_support_cb,
			    add_del_sa_sess_cb_t esp_add_del_sa_sess_cb)
{
  ipsec_esp_backend_t *b;
  pool_get (im->esp_backends, b);
  b->name = format (NULL, "%s", name);

  ipsec_add_node (vm, esp4_encrypt_node_name, "ipsec4-output-feature",
		  &b->esp4_encrypt_node_index, &b->esp4_encrypt_next_index);
  ipsec_add_node (vm, esp4_decrypt_node_name, "ipsec4-input-feature",
		  &b->esp4_decrypt_node_index, &b->esp4_decrypt_next_index);
  ipsec_add_node (vm, esp6_encrypt_node_name, "ipsec6-output-feature",
		  &b->esp6_encrypt_node_index, &b->esp6_encrypt_next_index);
  ipsec_add_node (vm, esp6_decrypt_node_name, "ipsec6-input-feature",
		  &b->esp6_decrypt_node_index, &b->esp6_decrypt_next_index);

  b->check_support_cb = esp_check_support_cb;
  b->add_del_sa_sess_cb = esp_add_del_sa_sess_cb;
  return b - im->esp_backends;
}

int
ipsec_select_ah_backend (ipsec_main_t * im, u32 backend_idx)
{
  if (pool_elts (im->sad) > 0
      || pool_is_free_index (im->ah_backends, backend_idx))
    {
      return -1;
    }
  ipsec_ah_backend_t *b = pool_elt_at_index (im->ah_backends, backend_idx);
  im->ah_current_backend = backend_idx;
  im->ah4_encrypt_node_index = b->ah4_encrypt_node_index;
  im->ah4_decrypt_node_index = b->ah4_decrypt_node_index;
  im->ah4_encrypt_next_index = b->ah4_encrypt_next_index;
  im->ah4_decrypt_next_index = b->ah4_decrypt_next_index;
  im->ah6_encrypt_node_index = b->ah6_encrypt_node_index;
  im->ah6_decrypt_node_index = b->ah6_decrypt_node_index;
  im->ah6_encrypt_next_index = b->ah6_encrypt_next_index;
  im->ah6_decrypt_next_index = b->ah6_decrypt_next_index;
  return 0;
}

int
ipsec_select_esp_backend (ipsec_main_t * im, u32 backend_idx)
{
  if (pool_elts (im->sad) > 0
      || pool_is_free_index (im->esp_backends, backend_idx))
    {
      return -1;
    }
  ipsec_esp_backend_t *b = pool_elt_at_index (im->esp_backends, backend_idx);
  im->esp_current_backend = backend_idx;
  im->esp4_encrypt_node_index = b->esp4_encrypt_node_index;
  im->esp4_decrypt_node_index = b->esp4_decrypt_node_index;
  im->esp4_encrypt_next_index = b->esp4_encrypt_next_index;
  im->esp4_decrypt_next_index = b->esp4_decrypt_next_index;
  im->esp6_encrypt_node_index = b->esp6_encrypt_node_index;
  im->esp6_decrypt_node_index = b->esp6_decrypt_node_index;
  im->esp6_encrypt_next_index = b->esp6_encrypt_next_index;
  im->esp6_decrypt_next_index = b->esp6_decrypt_next_index;
  return 0;
}

static clib_error_t *
ipsec_init (vlib_main_t * vm)
{
  clib_error_t *error;
  ipsec_main_t *im = &ipsec_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  ipsec_rand_seed ();

  clib_memset (im, 0, sizeof (im[0]));

  im->vnet_main = vnet_get_main ();
  im->vlib_main = vm;

  im->spd_index_by_spd_id = hash_create (0, sizeof (uword));
  im->sa_index_by_sa_id = hash_create (0, sizeof (uword));
  im->spd_index_by_sw_if_index = hash_create (0, sizeof (uword));

  vec_validate_aligned (im->empty_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  ASSERT (node);
  im->error_drop_node_index = node->index;

  u32 idx = ipsec_register_ah_backend (vm, im, "default openssl backend",
				       "ah4-encrypt",
				       "ah4-decrypt",
				       "ah6-encrypt",
				       "ah6-decrypt",
				       ipsec_check_support,
				       NULL);

  im->ah_default_backend = idx;
  int rv = ipsec_select_ah_backend (im, idx);
  ASSERT (0 == rv);
  (void) (rv);			// avoid warning

  idx = ipsec_register_esp_backend (vm, im, "default openssl backend",
				    "esp4-encrypt",
				    "esp4-decrypt",
				    "esp6-encrypt",
				    "esp6-decrypt",
				    ipsec_check_support, NULL);
  im->esp_default_backend = idx;

  rv = ipsec_select_esp_backend (im, idx);
  ASSERT (0 == rv);
  (void) (rv);			// avoid warning

  if ((error = vlib_call_init_function (vm, ipsec_cli_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ipsec_tunnel_if_init)))
    return error;

  ipsec_proto_init ();

  if ((error = ikev2_init (vm)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
