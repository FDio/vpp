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

#include <acl2/acl2.h>

#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/l2/l2_input.h>

/* per-ACE counters exposed via stats segment */
vlib_combined_counter_main_t ace_counters = {
  .name = "ACE2",
  .stat_segment_name = "/net/ace2",
};

acl2_main_t acl2_main;

#define acl2_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, acl2_main.log_default, __VA_ARGS__)
#define acl2_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, acl2_main.log_default, __VA_ARGS__)
#define acl2_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, acl2_main.log_default, __VA_ARGS__)
#define acl2_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, acl2_main.log_default, __VA_ARGS__)
#define acl2_log_debug(...) \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, acl2_main.log_default, __VA_ARGS__)

#define FOR_EACH_ACE(_acl, _ace, _body)                         \
{                                                               \
  index_t *_acei;                                               \
  vec_foreach(_acei, _acl->acl_aces)                            \
    {                                                           \
      _ace = pool_elt_at_index(acl2_main.ace_pool, *_acei);     \
      _body;                                                    \
    }                                                           \
}

#define FOR_EACH_ACE_INDEX(_acl, _acei)        \
  vec_foreach(_acei, _acl->acl_aces)

u8 *
format_acl2_action (u8 * s, va_list * a)
{
  acl2_action_t action = va_arg (*a, int);	// acl2_action_t;

  switch (action)
    {
#define _(a,b)                                  \
      case ACL2_ACTION_##a:                      \
        return (format(s, "%s", b));
      foreach_acl2_action
#undef _
    }
  return (format (s, "unknown"));
}

uword
unformat_acl2_action (unformat_input_t * input, va_list * args)
{
  acl2_action_t *aa = va_arg (*args, acl2_action_t *);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
	;
#define _(a,b)                                  \
      else if (unformat (input, b)) {           \
        *aa = ACL2_ACTION_##a;                   \
        return (1);                             \
      }
      foreach_acl2_action
#undef _
	else
	return (1);
    }

  return (0);

}

acl2_t *
acl2_get (index_t acl_index)
{
  acl2_main_t *am = &acl2_main;

  if (pool_is_free_index (am->acl_pool, acl_index))
    return (NULL);

  return (pool_elt_at_index (am->acl_pool, acl_index));
}

bool
acl2_is_valid (index_t acl_index)
{
  return (!pool_is_free_index (acl2_main.acl_pool, acl_index));
}

int
acl2_stats_update (int enable)
{
  acl2_main_t *am = &acl2_main;

  am->counters_enabled = enable;

  return (0);;
}

acl2_itf_t *
acl2_itf_find (u32 sw_if_index, vlib_dir_t dir)
{
  acl2_main_t *am = &acl2_main;

  if (vec_len (am->interfaces[dir]) <= sw_if_index)
    return (NULL);

  if (INDEX_INVALID == am->interfaces[dir][sw_if_index])
    return (NULL);

  return (pool_elt_at_index (am->itf_pool, am->interfaces[dir][sw_if_index]));
}

static index_t
acl2_itf_get_index (const acl2_itf_t * aitf)
{
  return (aitf - acl2_main.itf_pool);
}

static acl2_itf_layer_t
acl2_itf_get_layer (u32 sw_if_index)
{
  l2_input_config_t *config;

  config = l2input_intf_config (sw_if_index);

  if (config->bridge || config->xconnect)
    return (ACL2_ITF_LAYER_L2);

  return (ACL2_ITF_LAYER_L3);
}

acl2_itf_t *
acl2_itf_create (u32 sw_if_index, vlib_dir_t dir)
{
  acl2_main_t *am = &acl2_main;

  vec_validate_init_empty (am->interfaces[dir], sw_if_index, INDEX_INVALID);

  if (INDEX_INVALID == am->interfaces[dir][sw_if_index])
    {
      ip_address_family_t af;
      acl2_itf_t *aitf;

      pool_get_aligned_zero (am->itf_pool, aitf, CLIB_CACHE_LINE_BYTES);

      aitf->dir = dir;
      aitf->sw_if_index = sw_if_index;
      aitf->layer = acl2_itf_get_layer (sw_if_index);

      FOR_EACH_IP_ADDRESS_FAMILY (af)
      {
	aitf->per_af[af].match_set = INDEX_INVALID;
	aitf->per_af[af].match_app = MATCH_SET_APP_INVALID;
	aitf->per_af[af].conn_db = INDEX_INVALID;
	aitf->per_af[af].action = ACL2_ACTION_PERMIT;
      }

      am->interfaces[dir][sw_if_index] = aitf - am->itf_pool;

      return (aitf);
    }
  return (pool_elt_at_index (am->itf_pool, am->interfaces[dir][sw_if_index]));
}

static u32
acl2_itf_acl_find (const acl2_itf_t * aitf, u32 acl_index)
{
  u32 index;

  vec_foreach_index (index, aitf->acls)
  {
    if (aitf->acls[index].ah_acl == acl_index)
      return (index);
  }

  return (~0);
}

static void
acl2_hdl_free (index_t match_set, match_handle_t * hdl)
{
  if (INDEX_INVALID != match_set && MATCH_HANDLE_INVALID != *hdl)
    match_set_list_del (match_set, hdl);
}

static void
acl2_itf_update_action (acl2_itf_t * aitf, ip_address_family_t af)
{
  acl2_hdl_t *ah;
  acl2_t *acl;

  aitf->per_af[af].action = ACL2_ACTION_PERMIT;

  vec_foreach (ah, aitf->acls)
  {
    acl = acl2_get (ah->ah_acl);

    if (acl->acl_per_af[af].apf_action > aitf->per_af[af].action)
      aitf->per_af[af].action = acl->acl_per_af[af].apf_action;
  }
}

static void
acl2_itf_acl_update (acl2_itf_t * aitf, u32 acl_index)
{
  ip_address_family_t af;
  acl2_hdl_t *ah;
  acl2_t *acl;
  u32 pos;

  pos = acl2_itf_acl_find (aitf, acl_index);
  ASSERT (~0 != pos);
  ah = &aitf->acls[pos];

  acl = acl2_get (acl_index);

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  {
    acl2_per_af_t *acl_pf;

    acl_pf = &acl->acl_per_af[af];

    ASSERT (INDEX_INVALID != aitf->per_af[af].match_set);

    if (match_list_length (&acl_pf->apf_list))
      {
	if (MATCH_HANDLE_INVALID == ah->ah_hdl[af])
	  ah->ah_hdl[af] = match_set_list_add (aitf->per_af[af].match_set,
					       &acl_pf->apf_list,
					       vec_len (aitf->acls));
	else
	  match_set_list_replace (aitf->per_af[af].match_set,
				  ah->ah_hdl[af], &acl_pf->apf_list);
      }

    acl2_itf_update_action (aitf, af);
  }
}

static void
acl2_itf_acl_add (acl2_itf_t * aitf, u32 acl_index)
{
  ip_address_family_t af;
  acl2_hdl_t *ah;
  acl2_t *acl;

  if (~0 != acl2_itf_acl_find (aitf, acl_index))
    return;

  vec_add2 (aitf->acls, ah, 1);

  ah->ah_acl = acl_index;

  acl = acl2_get (acl_index);

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  {
    acl2_per_af_t *acl_pf;

    acl_pf = &acl->acl_per_af[af];

    if (INDEX_INVALID == aitf->per_af[af].match_set)
      {
	/* now's a good time to create the match-set
	 * if we don't already have one */
	u8 *match_name;

	match_name = format (NULL, "acl-%U-%U-%U",
			     format_ip_address_family, af,
			     format_vlib_rx_tx, aitf->dir,
			     format_vnet_sw_if_index_name,
			     vnet_get_main (), aitf->sw_if_index);

	aitf->per_af[af].match_set =
	  match_set_create_and_lock (match_name,
				     acl_pf->apf_mtype,
				     acl_pf->apf_mo,
				     ip_address_family_to_ether_type (af),
				     acl2_main.heap);
	vec_free (match_name);
      }

    if (match_list_length (&acl_pf->apf_list))
      {
	ah->ah_hdl[af] = match_set_list_add (aitf->per_af[af].match_set,
					     &acl_pf->apf_list,
					     vec_len (aitf->acls));
      }
    else
      ah->ah_hdl[af] = MATCH_HANDLE_INVALID;

    acl2_itf_update_action (aitf, af);
  }

  /* add this interface to the list that this ACL uses */
  if (~0 == vec_search (acl2_main.interfaces_by_acl[acl_index],
			aitf->sw_if_index))
    vec_add1 (acl2_main.interfaces_by_acl[acl_index],
	      acl2_itf_get_index (aitf));
}

static void
acl2_itf_acl_remove (acl2_itf_t * aitf, u32 acl_index)
{
  ip_address_family_t af;
  acl2_hdl_t *ah;
  u32 index;

  index = acl2_itf_acl_find (aitf, acl_index);

  if (~0 == index)
    return;

  ah = &aitf->acls[index];

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  {
    acl2_hdl_free (aitf->per_af[af].match_set, &ah->ah_hdl[af]);
    acl2_itf_update_action (aitf, af);
  }

  /* delete preserving the order */
  vec_delete (aitf->acls, 1, index);

  /* also delete this interface from the list that this ACL uses */
  index = vec_search (acl2_main.interfaces_by_acl[acl_index],
		      aitf->sw_if_index);
  vec_del1 (acl2_main.interfaces_by_acl[acl_index], index);
}

static void
acl2_itf_update (index_t itf_index, index_t acl_index)
{
  acl2_itf_t *aitf;

  aitf = acl2_itf_get_i (itf_index);

  acl2_itf_acl_update (aitf, acl_index);
}

static void
acl2_itf_destroy (acl2_itf_t * aitf)
{
  acl2_main.interfaces[aitf->dir][aitf->sw_if_index] = INDEX_INVALID;
  vec_free (aitf->acls);
  pool_put (acl2_main.itf_pool, aitf);
}

static void
acl2_updated (index_t acl_index)
{
  index_t *itf_index;

  /* walk all the interface on which the list is applied and poke them */
  vec_foreach (itf_index, acl2_main.interfaces_by_acl[acl_index])
    acl2_itf_update (*itf_index, acl_index);
}

static void
acl2_match_list_compile (acl2_t * acl, ip_address_family_t af)
{
  acl2_per_af_t *acl_pf;
  ace2_t *ace;
  u8 *name;

  acl_pf = &acl->acl_per_af[af];
  name =
    format (NULL, "acl-%d-%U", acl - acl2_main.acl_pool,
	    format_ip_address_family, af);

  match_list_init (&acl_pf->apf_list, name, 0);
  acl_pf->apf_action = ACL2_ACTION_PERMIT;

  /* *INDENT-OFF* */
  FOR_EACH_ACE(acl, ace,
  ({
    if (match_rule_get_af (&ace->ace_rule) == af)
      {
        acl2_result_t ar = {
          .ar_ace = *_acei,
          .ar_action = ace->ace_action,
        };

        ace->ace_rule.mr_result = ar.ar_u64;
	match_list_push_back (&acl_pf->apf_list, &ace->ace_rule);
        acl_pf->apf_mtype = ace->ace_rule.mr_type;
        acl_pf->apf_mo = ace->ace_rule.mr_orientation;

        if (ace->ace_action > acl_pf->apf_action)
          acl_pf->apf_action = ace->ace_action;
      }
  }));
  /* *INDENT-ON* */

  vec_free (name);
}

int
acl2_update (index_t * aip, index_t * aces, u8 * tag)
{
  acl2_main_t *am = &acl2_main;
  ip_address_family_t af;
  index_t ai, *acei;
  acl2_t *acl;

  ai = *aip;

  if (INDEX_INVALID == ai)
    {
      pool_get_zero (am->acl_pool, acl);
      ai = acl - am->acl_pool;
    }
  else
    {
      if (pool_is_free_index (am->acl_pool, ai))
	return (VNET_API_ERROR_NO_SUCH_ENTRY);

      acl = pool_elt_at_index (am->acl_pool, ai);

      FOR_EACH_ACE_INDEX (acl, acei) pool_put_index (am->ace_pool, *acei);
      vec_free (acl->acl_aces);
    }

  acl->acl_aces = aces;
  if (tag)
    memcpy (acl->acl_tag, tag, sizeof (acl->acl_tag));

  FOR_EACH_ACE_INDEX (acl, acei)
  {
    vlib_validate_combined_counter (&ace_counters, *acei);
    vlib_zero_combined_counter (&ace_counters, *acei);
  }

  FOR_EACH_IP_ADDRESS_FAMILY (af)
  {
    acl2_match_list_compile (acl, af);
  }

  vec_validate (acl2_main.interfaces_by_acl, ai);

  /* notify the interfaces about the ACL changes */
  acl2_updated (ai);

  acl2_log_info ("update: %U", format_acl2, ai, ACL2_FORMAT_BRIEF);

  *aip = ai;

  return (0);
}

static int
acl2_is_in_use (acl2_main_t * am, u32 acl_index)
{
  if (vec_len (am->interfaces_by_acl) < acl_index)
    return (0);

  if (0 != vec_len (am->interfaces_by_acl[acl_index]))
    {
      acl2_itf_t *aitf;

      aitf = acl2_itf_get_i (am->interfaces_by_acl[acl_index][0]);

      if (VLIB_RX == aitf->dir)
	return (VNET_API_ERROR_ACL_IN_USE_INBOUND);
      else
	return (VNET_API_ERROR_ACL_IN_USE_OUTBOUND);
    }

  return (0);
}

int
acl2_del (index_t acl_index)
{
  acl2_main_t *am = &acl2_main;
  ip_address_family_t af;
  index_t *acei;
  acl2_t *acl;
  int rv;

  if (!acl2_is_valid (acl_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rv = acl2_is_in_use (am, acl_index);

  if (rv)
    return rv;

  acl = acl2_get (acl_index);

  acl2_log_info ("delete: %U", format_acl2, acl_index, ACL2_FORMAT_BRIEF);

  FOR_EACH_ACE_INDEX (acl, acei) pool_put_index (am->ace_pool, *acei);

  FOR_EACH_IP_ADDRESS_FAMILY (af)
    match_list_free (&acl->acl_per_af[af].apf_list);

  vec_free (acl->acl_aces);
  pool_put (am->acl_pool, acl);

  return 0;
}

/* *INDENT-OFF* */
const static char * acl2_feat_arc[ACL2_ITF_N_LAYERS][N_AF][VLIB_N_RX_TX] = {
  [ACL2_ITF_LAYER_L2] = {
    [AF_IP4] = {
      [VLIB_RX] = "l2-input-ip4",
      [VLIB_TX] = "l2-output-ip4",
    },
    [AF_IP6] = {
      [VLIB_RX] = "l2-input-ip6",
      [VLIB_TX] = "l2-output-ip6",
    },
  },
  [ACL2_ITF_LAYER_L3] = {
    [AF_IP4] = {
      [VLIB_RX] = "ip4-unicast",
      [VLIB_TX] = "ip4-output",
    },
    [AF_IP6] = {
      [VLIB_RX] = "ip6-unicast",
      [VLIB_TX] = "ip6-output",
    },
  },
};
const static char * acl2_feat[ACL2_ITF_N_LAYERS][N_AF][VLIB_N_RX_TX][ACL2_N_ACTIONS] = {
  [ACL2_ITF_LAYER_L2] = {
    [AF_IP4] = {
      [VLIB_RX] = {
        [ACL2_ACTION_PERMIT] = "acl2-in-ip4-l2",
        [ACL2_ACTION_TRACK] = "acl2-track-in-ip4-l2",
      },
      [VLIB_TX] = {
        [ACL2_ACTION_PERMIT] = "acl2-out-ip4-l2",
        [ACL2_ACTION_TRACK] = "acl2-track-out-ip4-l2",
      },
    },
    [AF_IP6] = {
      [VLIB_RX] = {
        [ACL2_ACTION_PERMIT] = "acl2-in-ip6-l2",
        [ACL2_ACTION_TRACK] = "acl2-track-in-ip6-l2",
      },
      [VLIB_TX] = {
        [ACL2_ACTION_PERMIT] = "acl2-out-ip4-l2",
        [ACL2_ACTION_TRACK] = "acl2-track-out-ip6-l2",
      },
    },
  },
  [ACL2_ITF_LAYER_L3] = {
    [AF_IP4] = {
      [VLIB_RX] = {
        [ACL2_ACTION_PERMIT] = "acl2-in-ip4",
        [ACL2_ACTION_TRACK] = "acl2-track-in-ip4",
      },
      [VLIB_TX] = {
        [ACL2_ACTION_PERMIT] = "acl2-out-ip4",
        [ACL2_ACTION_TRACK] = "acl2-track-out-ip4",
      },
    },
    [AF_IP6] = {
      [VLIB_RX] = {
        [ACL2_ACTION_PERMIT] = "acl2-in-ip6",
        [ACL2_ACTION_TRACK] = "acl2-track-in-ip6",
      },
      [VLIB_TX] = {
        [ACL2_ACTION_PERMIT] = "acl2-out-ip4",
        [ACL2_ACTION_TRACK] = "acl2-track-out-ip6",
      },
    },
  },
};

typedef int (*vnet_feature_enable_disable_t) (const char *arc_name,
                                              const char *node_name,
                                              u32 sw_if_index,
                                              int enable_disable,
                                              void *feature_config,
                                              u32 n_feature_config_bytes);

static const vnet_feature_enable_disable_t acl2_feat_func[ACL2_ITF_N_LAYERS] = {
  [ACL2_ITF_LAYER_L2] = vnet_l2_feature_enable_disable,
  [ACL2_ITF_LAYER_L3] = vnet_feature_enable_disable,
};

/* *INDENT-ON* */

static int
acl2_interface_acl_enable_disable (acl2_itf_t * aitf,
				   ip_address_family_t af, int enable)
{
  acl2_action_t action;
  int rv = 0;

  action = aitf->per_af[af].action;

  if (aitf->per_af[af].flags & ACL2_ITF_FLAG_FEATURE_ON)
    {
      /* feature is already enabled */
      if (enable)
	{
	  if (action == ACL2_ACTION_TRACK)
	    {
	      if (!(aitf->per_af[af].flags & ACL2_ITF_FLAG_TRACK_ON))
		{
		  /* new action is to track and we currently aren't */
		  rv |= acl2_feat_func[aitf->layer]
		    (acl2_feat_arc[aitf->layer][af][aitf->dir],
		     acl2_feat[aitf->
			       layer][af][aitf->dir][ACL2_ACTION_PERMIT],
		     aitf->sw_if_index, 0, 0, 0);
		  rv |=
		    acl2_feat_func[aitf->layer] (acl2_feat_arc[aitf->layer]
						 [af][aitf->dir],
						 acl2_feat[aitf->
							   layer][af]
						 [aitf->dir][action],
						 aitf->sw_if_index, 1, 0, 0);
		}
	      /* else already have the tracking nodes enabled */
	      aitf->per_af[af].flags |= ACL2_ITF_FLAG_TRACK_ON;
	    }
	  else
	    {
	      /* new action is only to permit */
	      if (aitf->per_af[af].flags & ACL2_ITF_FLAG_TRACK_ON)
		{
		  /* we are tracking an we no longer need to */
		  rv |= acl2_feat_func[aitf->layer]
		    (acl2_feat_arc[aitf->layer][af][aitf->dir],
		     acl2_feat[aitf->layer][af][aitf->dir][ACL2_ACTION_TRACK],
		     aitf->sw_if_index, 0, 0, 0);
		  rv |= acl2_feat_func[aitf->layer]
		    (acl2_feat_arc[aitf->layer][af][aitf->dir],
		     acl2_feat[aitf->layer][af][aitf->dir][action],
		     aitf->sw_if_index, 1, 0, 0);
		}

	      aitf->per_af[af].flags &= ~ACL2_ITF_FLAG_TRACK_ON;
	    }
	}
      else
	{
	  /* disable what we have */
	  rv |= acl2_feat_func[aitf->layer]
	    (acl2_feat_arc[aitf->layer][af][aitf->dir],
	     acl2_feat[aitf->layer][af][aitf->dir][action],
	     aitf->sw_if_index, 0, 0, 0);
	  aitf->per_af[af].flags &= ~ACL2_ITF_FLAG_TRACK_ON;
	}
    }
  else
    {
      /* No features currently enabled */
      if (enable)
	{
	  rv |= acl2_feat_func[aitf->layer]
	    (acl2_feat_arc[aitf->layer][af][aitf->dir],
	     acl2_feat[aitf->layer][af][aitf->dir][action],
	     aitf->sw_if_index, 1, 0, 0);
	  if (action == ACL2_ACTION_TRACK)
	    aitf->per_af[af].flags |= ACL2_ITF_FLAG_TRACK_ON;
	}
      /* else no-op */
    }

  if (enable)
    aitf->per_af[af].flags |= ACL2_ITF_FLAG_FEATURE_ON;
  else
    aitf->per_af[af].flags &= ~ACL2_ITF_FLAG_FEATURE_ON;

  return (rv);
}

int
acl2_bind (u32 sw_if_index, vlib_dir_t dir, u32 * vec_acl_list_index)
{
  uword *seen_acl_bitmap, *old_seen_acl_bitmap, *change_acl_bitmap;
  ip_address_family_t af;
  acl2_itf_t *aitf;
  acl2_hdl_t *ahdl;
  index_t *acli;
  int acln, rv;

  rv = 0;
  seen_acl_bitmap = old_seen_acl_bitmap = change_acl_bitmap = 0;

  acl2_log_debug ("set-acl: sw_if_index %d %U acl_vec: [%U]",
		  sw_if_index, format_vlib_rx_tx, dir,
		  format_vec32, vec_acl_list_index, "%d");

  aitf = acl2_itf_find (sw_if_index, dir);

  if (NULL == aitf && 0 == vec_len (vec_acl_list_index))
    return (0);

  vec_foreach (acli, vec_acl_list_index)
  {
    if (!acl2_is_valid (*acli))
      {
	/* ACL is not defined. Can not apply */
	acl2_log_warn ("ERROR: ACL %d not defined", *acli);
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	goto done;
      }
    if (clib_bitmap_get (seen_acl_bitmap, *acli))
      {
	/* ACL being applied twice within the list. error. */
	acl2_log_warn ("ERROR: ACL %d being applied twice", *acli);
	rv = VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	goto done;
      }
    seen_acl_bitmap = clib_bitmap_set (seen_acl_bitmap, *acli, 1);
  }

  aitf = acl2_itf_create (sw_if_index, dir);

  vec_foreach (ahdl, aitf->acls)
  {
    old_seen_acl_bitmap = clib_bitmap_set (old_seen_acl_bitmap,
					   ahdl->ah_acl, 1);
  }
  change_acl_bitmap = clib_bitmap_dup_xor (old_seen_acl_bitmap,
					   seen_acl_bitmap);

  acl2_log_debug ("bitmaps: old seen %U new seen %U changed %U",
		  format_bitmap_hex, old_seen_acl_bitmap, format_bitmap_hex,
		  seen_acl_bitmap, format_bitmap_hex, change_acl_bitmap);

  /* *INDENT-OFF* */
  clib_bitmap_foreach(acln, change_acl_bitmap,
  ({
    if (clib_bitmap_get(old_seen_acl_bitmap, acln))
      acl2_itf_acl_remove(aitf, acln);
    else
      acl2_itf_acl_add(aitf, acln);
  }));
  /* *INDENT-ON* */

  /* ensure ACL processing is enabled/disabled as needed */
  if (vec_len (aitf->acls))
    {
      /*
       * we have ACLs bound to this interface
       * apply the match-set if it is not already applied. If it is already
       * applied then adding/replacing the list from the set has already
       * been processed.
       */
      FOR_EACH_IP_ADDRESS_FAMILY (af)
      {
	if (!match_set_app_is_valid (&aitf->per_af[af].match_app))
	  match_set_apply (aitf->per_af[af].match_set,
			   MATCH_SEMANTIC_FIRST,
			   match_set_get_itf_tag_flags (aitf->sw_if_index),
			   &aitf->per_af[af].match_app);
	ASSERT (match_set_app_is_valid (&aitf->per_af[af].match_app));

	acl2_interface_acl_enable_disable (aitf, af, 1);
      }
    }
  else
    {
      /* no more ACLs bound to this interface */
      FOR_EACH_IP_ADDRESS_FAMILY (af)
      {
	acl2_interface_acl_enable_disable (aitf, af, 0);
	match_set_unapply (aitf->per_af[af].match_set,
			   &aitf->per_af[af].match_app);
	match_set_unlock (&aitf->per_af[af].match_set);
      }

      acl2_itf_destroy (aitf);
    }

done:
  clib_bitmap_free (change_acl_bitmap);
  clib_bitmap_free (seen_acl_bitmap);
  clib_bitmap_free (old_seen_acl_bitmap);
  return rv;
}

static clib_error_t *
acl2_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  if (0 == is_add)
    {
      /* unapply any ACLs in case the users did not do so. */
      acl2_bind (sw_if_index, VLIB_RX, NULL);
      acl2_bind (sw_if_index, VLIB_TX, NULL);
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (acl2_sw_interface_add_del);

u8 *
format_ace2 (u8 * s, va_list * args)
{
  vlib_counter_t counts;
  index_t acei;
  ace2_t *ace;

  acei = va_arg (*args, index_t);
  ace = ace2_get (acei);

  vlib_get_combined_counter (&ace_counters, acei, &counts);

  s = format (s, "[%d]: %U => %U",
	      acei, format_acl2_action, ace->ace_action,
	      format_match_rule, &ace->ace_rule, 4);
  s = format (s, "\n   counts:[%lld, %lld]", counts.packets, counts.bytes);

  return (s);
}

u8 *
format_acl2_per_af (u8 * s, va_list * args)
{
  acl2_per_af_t *acl_pf;

  acl_pf = va_arg (*args, acl2_per_af_t *);

  s = format (s, "%U %U",
	      format_match_type, acl_pf->apf_mtype,
	      format_match_orientation, acl_pf->apf_mo);
  s = format (s, "\n        %U",
	      format_match_list_w_result, &acl_pf->apf_list, 10,
	      format_acl2_result);

  return (s);
}

u8 *
format_acl2 (u8 * s, va_list * args)
{
  acl2_format_flag_t flags;
  ip_address_family_t af;
  index_t *ai, *acei;
  index_t acl_index;
  acl2_t *acl;

  acl_index = va_arg (*args, index_t);
  flags = va_arg (*args, acl2_format_flag_t);
  acl = acl2_get (acl_index);

  s = format (s, "[%d]: %s", acl_index, acl->acl_tag);

  FOR_EACH_IP_ADDRESS_FAMILY (af)
    s = format (s, "\n   %U %U",
		format_ip_address_family, af,
		format_acl2_per_af, &acl->acl_per_af[af]);

  if (flags & ACL2_FORMAT_DETAIL)
    {
      FOR_EACH_ACE_INDEX (acl, acei) s =
	format (s, "\n  %U", format_ace2, *acei);
    }
  else
    {
      s = format (s, " n-rules:%d", vec_len (acl->acl_aces));
    }

  if (flags & ACL2_FORMAT_VERBOSE)
    {
      s = format (s, "\n applied-on:");
      vec_foreach (ai, acl2_main.interfaces_by_acl[acl_index])
	s = format (s, "\n  [%U]", format_acl2_itf, *ai, ACL2_FORMAT_BRIEF);
    }

  return (s);
}

u8 *
format_acl2_result (u8 * s, va_list * args)
{
  acl2_result_t ar = va_arg (*args, acl2_result_t);

  s = format (s, "[%d %U]", ar.ar_ace, format_acl2_action, ar.ar_action);

  return (s);
}

u8 *
format_acl2_hdl (u8 * s, va_list * args)
{
  acl2_hdl_t *ah = va_arg (*args, acl2_hdl_t *);
  ip_address_family_t af;

  s = format (s, "acl:%d", ah->ah_acl);
  FOR_EACH_IP_ADDRESS_FAMILY (af)
    s = format (s, "\n      %U match-set-hdl:%d",
		format_ip_address_family, af, ah->ah_hdl[af]);

  return (s);
}

u8 *
format_acl2_itf_layer (u8 * s, va_list * args)
{
  acl2_itf_layer_t layer = va_arg (*args, acl2_itf_layer_t);

  switch (layer)
    {
    case ACL2_ITF_LAYER_L2:
      return (format (s, "l2"));
    case ACL2_ITF_LAYER_L3:
      return (format (s, "l3"));
    }
  return (format (s, "unknown"));
}

u8 *
format_acl2_itf_flags (u8 * s, va_list * args)
{
  acl2_itf_flags_t flags = va_arg (*args, acl2_itf_flags_t);

#define _(a,b,c)                                \
  if (flags & ACL2_ITF_FLAG_##a)                \
    s = format (s, "%s", c);
  foreach_acl2_itf_flag
#undef _
    return (s);
}

u8 *
format_acl2_itf (u8 * s, va_list * args)
{
  acl2_format_flag_t flags;
  ip_address_family_t af;
  acl2_itf_t *aitf;
  acl2_hdl_t *ah;
  index_t ai;

  ai = va_arg (*args, index_t);
  flags = va_arg (*args, acl2_format_flag_t);
  aitf = pool_elt_at_index (acl2_main.itf_pool, ai);

  s = format (s, "[%d]: %U, %U %U", ai,
	      format_vnet_sw_if_index_name, vnet_get_main (),
	      aitf->sw_if_index, format_vlib_rx_tx, aitf->dir,
	      format_acl2_itf_layer, aitf->layer);

  if (flags & ACL2_FORMAT_DETAIL)
    {
      s = format (s, "\n  acls:");
      vec_foreach (ah, aitf->acls)
	s = format (s, "\n    %U", format_acl2_hdl, ah);

      FOR_EACH_IP_ADDRESS_FAMILY (af)
	s = format (s, "\n  %U %U flags:[%U] match-set:%d",
		    format_ip_address_family, af,
		    format_acl2_action, aitf->per_af[af].action,
		    format_acl2_itf_flags, aitf->per_af[af].flags,
		    aitf->per_af[af].match_set);
    }

  return (s);
}

u8 *
format_acl2_sw_if_index (u8 * s, va_list * args)
{
  acl2_format_flag_t flags;
  u32 sw_if_index;
  vlib_dir_t dir;

  sw_if_index = va_arg (*args, u32);
  flags = va_arg (*args, acl2_format_flag_t);

  FOREACH_VLIB_DIR (dir)
  {
    acl2_itf_t *aitf;

    aitf = acl2_itf_find (sw_if_index, dir);

    if (aitf)
      {
	s =
	  format (s, "%U", format_acl2_itf, acl2_itf_get_index (aitf), flags);
      }
  }
  return (s);
}

void
acl2_walk (index_t acli, acl2_walk_fn_t fn, void *arg)
{
  index_t *acei;
  acl2_t *acl;

  acl = acl2_get (acli);

  vec_foreach (acei, acl->acl_aces)
  {
    if (WALK_STOP == fn (acli, *acei, arg))
      break;
  }
}

static clib_error_t *
acl2_show_acl (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  acl2_main_t *am = &acl2_main;
  u32 acl_index = ~0;

  (void) unformat (input, "%u", &acl_index);

  if (~0 == acl_index)
    {
      /* *INDENT-OFF* */
      pool_foreach_index(acl_index, am->acl_pool,
      ({
        vlib_cli_output (vm, "%U", format_acl2, acl_index, ACL2_FORMAT_BRIEF);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if (!pool_is_free_index (am->acl_pool, acl_index))
	vlib_cli_output (vm, "%U", format_acl2, acl_index,
			 ACL2_FORMAT_DETAIL);
      else
	vlib_cli_output (vm, "invalid ACL index:%d", acl_index);
    }

  return (NULL);
}

static clib_error_t *
acl2_show_interface (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  acl2_main_t *am = &acl2_main;
  acl2_format_flag_t flags;
  u32 sw_if_index = ~0;
  vlib_dir_t dir;

  (void) unformat (input, "%U", unformat_vnet_sw_interface,
		   vnet_get_main (), &sw_if_index);
  int detail = unformat (input, "detail");

  flags = ACL2_FORMAT_DETAIL;
  if (detail)
    flags |= ACL2_FORMAT_VERBOSE;

  if (~0 != sw_if_index)
    vlib_cli_output (vm, "%U", format_acl2_sw_if_index, sw_if_index, flags);
  else
    {
      dir = ((vec_len (am->interfaces[VLIB_RX]) >
	      vec_len (am->interfaces[VLIB_TX])) ? VLIB_RX : VLIB_TX);

      vec_foreach_index (sw_if_index, am->interfaces[dir])
	vlib_cli_output (vm, "%U", format_acl2_sw_if_index, sw_if_index,
			 flags);
    }

  return (NULL);
}

static clib_error_t *
acl2_show_config (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "heap-size: %d", acl2_main.heap_size);

  return (NULL);
}

static clib_error_t *
acl2_cli_del (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  index_t ai;

  ai = INDEX_INVALID;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %d", &ai))
	;
      else
	break;
    }

  if (!acl2_is_valid (ai))
    return (clib_error_return (0, "invalid index: %d", ai));
  if (acl2_is_in_use (&acl2_main, ai))
    return (clib_error_return (0, "index in use: %d", ai));

  acl2_del (ai);

  unformat_free (line_input);

  return (NULL);
}

static clib_error_t *
acl2_cli_add (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ace2_t *aces, *ace, *a;
  acl2_action_t aa;
  index_t ai, *aceis;
  u8 *tag;
  int rv;

  const char *valid_chars = "a-zA-Z0-9_";

  ai = INDEX_INVALID;
  aceis = NULL;
  aces = ace = NULL;
  tag = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tag %U", unformat_token, valid_chars, &tag))
	;
      else if (unformat (line_input, "action %U", unformat_acl2_action, &aa))
	{
	  vec_add2 (aces, ace, 1);
	  ace->ace_action = aa;
	}
      else
	if (unformat (line_input, "rule %U", unformat_match_rule,
		      &ace->ace_rule))
	;
      else
	break;
    }

  vec_foreach (ace, aces)
  {
    pool_get (acl2_main.ace_pool, a);
    clib_memcpy (a, ace, sizeof (*a));

    vec_add1 (aceis, a - acl2_main.ace_pool);
  }
  rv = acl2_update (&ai, aceis, tag);

  if (rv)
    return (clib_error_return (0, "failed"));

  vlib_cli_output (vm, "acl-index: %d", ai);

  unformat_free (line_input);

  return (NULL);
}

static clib_error_t *
acl2_cli_bind (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  index_t ai, *ais;
  u32 sw_if_index;
  vlib_dir_t dir;

  ai = INDEX_INVALID;
  dir = VLIB_N_RX_TX;
  sw_if_index = ~0;
  ais = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %d", &ai))
	{
	  if (!acl2_is_valid (ai))
	    return (clib_error_return (0, "invalid index: %d", ai));
	  vec_add1 (ais, ai);
	}
      else if (unformat (line_input, "%U", unformat_vlib_rx_tx, &dir))
	;
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnet_get_main (),
			 &sw_if_index))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return (clib_error_return (0, "invalid interface", ai));
  if (VLIB_N_RX_TX == dir)
    return (clib_error_return (0, "invalid direction", ai));

  acl2_bind (sw_if_index, dir, ais);

  unformat_free (line_input);
  vec_free (ais);

  return (NULL);
}


static void
ace2_clear (index_t acei)
{
  vlib_zero_combined_counter (&ace_counters, acei);
}

static clib_error_t *
clear_ace (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  acl2_main_t *am = &acl2_main;
  index_t acei = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &acei))
	;
      else
	break;
    }

  if (~0 == acei)
    {
      /* *INDENT-OFF* */
      pool_foreach_index (acei, am->ace_pool,
      ({
        ace2_clear(acei);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if (pool_is_free_index (am->ace_pool, acei))
	return clib_error_return (0, "unknown ACE index: %d", acei);
      else
	ace2_clear (acei);
    }

  return (NULL);
}

static clib_error_t *
acl2_cli_stats (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  acl2_stats_update (enable);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (acl2_show_config_cmd, static) =
{
  .path = "show acl2 config",
  .short_help = "show acl2 acl [index N]",
  .function = acl2_show_config,
};
VLIB_CLI_COMMAND (acl2_show_acl_cmd, static) =
{
  .path = "show acl2 acl",
  .short_help = "show acl2 acl [index N]",
  .function = acl2_show_acl,
};
VLIB_CLI_COMMAND (acl2_show_interface_cmd, static) =
{
  .path = "show acl2 interface",
  .short_help = "show acl2 interface <interface> [detail]",
  .function = acl2_show_interface,
};
VLIB_CLI_COMMAND (acl2_show_bind_cmd, static) =
{
  .path = "show acl2 bind",
  .short_help = "show acl2 bind <interface> [detail]",
  .function = acl2_show_interface,
};
VLIB_CLI_COMMAND (acl2_add_cmd, static) =
{
  .path = "acl2 add",
  .short_help = "acl2 add action <a> rule <r> ...",
  .function = acl2_cli_add,
};
VLIB_CLI_COMMAND (acl2_del_cmd, static) =
{
  .path = "acl2 del",
  .short_help = "acl2 del <INDEX>",
  .function = acl2_cli_del,
};
VLIB_CLI_COMMAND (acl2_bind_cmd, static) =
{
  .path = "acl2 bind",
  .short_help = "acl2 bind <INDEX> <INTERFACE>",
  .function = acl2_cli_bind,
};
VLIB_CLI_COMMAND (clear_ace_cmd, static) = {
  .path = "clear ace",
  .short_help = "clear ace [index]",
  .function = clear_ace,
};
VLIB_CLI_COMMAND (acl2_stats_cmd, static) = {
  .path = "acl2 stats",
  .short_help = "acl2 stats [enable|disable]",
  .function = acl2_cli_stats,
};
/* *INDENT-ON* */

static clib_error_t *
acl_init (vlib_main_t * vm)
{
  acl2_main_t *am = &acl2_main;

  am->log_default = vlib_log_register_class ("acl2", "acl2");

  if (0 != am->heap_size)
    am->heap = create_mspace (am->heap_size, 1 /* locked */ );

  am->conn_user = conn_track_user_add ("ACL2");

  return (NULL);
}

VLIB_INIT_FUNCTION (acl_init);

static clib_error_t *
acl2_config (vlib_main_t * vm, unformat_input_t * input)
{
  acl2_main_t *am = &acl2_main;
  uword heapsize = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "heap-size %U", unformat_memory_size, &heapsize))
	;
      else
	return clib_error_return (0,
				  "invalid heap-size parameter `%U'",
				  format_unformat_error, input);
    }

  am->heap_size = heapsize;

  return 0;
}

VLIB_CONFIG_FUNCTION (acl2_config, "acl2");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
