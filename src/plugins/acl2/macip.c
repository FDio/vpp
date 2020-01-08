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

#include <acl2/macip.h>
#include <acl2/acl.h>
#include <acl2/acl2.api_types.h>

#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_in_out_feat_arc.h>

#include <vnet/match/match_types_api.h>

static vlib_log_class_t macip_logger;
macip_acl_main_t macip_acl_main;

#define MACIP_DBG(...)                          \
    vlib_log_debug (macip_logger, __VA_ARGS__);

#define MACIP_INFO(...)                         \
    vlib_log_notice (macip_logger, __VA_ARGS__);

#define MACIP_WARN(...)                         \
    vlib_log_warn (macip_logger, __VA_ARGS__);


/* *INDENT-OFF* */
static const char *macip_ip_feat_arc_name[VLIB_N_RX_TX][VNET_LINK_NUM] =
{
  [VLIB_RX] = {
    [VNET_LINK_IP4] = "ip4-unicast",
    [VNET_LINK_IP6] = "ip6-unicast",
    [VNET_LINK_ARP] = "arp-input",
  },
  [VLIB_TX] = {
    [VNET_LINK_IP4] = "ip4-output",
    [VNET_LINK_IP6] = "ip6-output",
  },
};

static const char *macip_ip_feat_name[VLIB_N_RX_TX][VNET_LINK_NUM] =
{
  [VLIB_RX] = {
    [VNET_LINK_IP4] = "ip4-macip-input",
    [VNET_LINK_IP6] = "ip6-macip-input",
    [VNET_LINK_ARP] = "arp-macip-input",
  },
  [VLIB_TX] = {
    [VNET_LINK_IP4] = "ip4-macip-output",
    [VNET_LINK_IP6] = "ip6-macip-output",
  },
};

static const char *macip_l2_feat_arc_name[VLIB_N_RX_TX][VNET_LINK_NUM] =
{
  [VLIB_RX] = {
    [VNET_LINK_IP4] = "l2-input-ip4",
    [VNET_LINK_IP6] = "l2-input-ip6",
    [VNET_LINK_ARP] = "l2-input-nonip",
  },
  [VLIB_TX] = {
    [VNET_LINK_IP4] = "l2-output-ip4",
    [VNET_LINK_IP6] = "l2-output-ip6",
    [VNET_LINK_ARP] = "l2-output-nonip",
  },
};

static const char *macip_l2_feat_name[VLIB_N_RX_TX][VNET_LINK_NUM] =
{
  [VLIB_RX] = {
    [VNET_LINK_IP4] = "l2-ip4-macip-input",
    [VNET_LINK_IP6] = "l2-ip6-macip-input",
    [VNET_LINK_ARP] = "l2-arp-macip-input",
  },
  [VLIB_TX] = {
    [VNET_LINK_IP4] = "l2-macip-output",
    [VNET_LINK_IP6] = "l2-macip-output",
    [VNET_LINK_ARP] = "l2-macip-output",
  },
};
/* *INDENT-ON* */

static void
macip_rule_to_match_rule (const vl_api_macip2_rule_t * rule,
			  match_rule_t * mr, macip_action_t * action)
{
  match_rule_mask_ip_mac_decode (&rule->rule, mr);
  *action = (rule->is_permit ? MACIP_ACTION_PERMIT : MACIP_ACTION_DENY);
}

static bool
macip_acl_is_link_l2 (u32 sw_if_index)
{
  l2_input_config_t *config;

  config = l2input_intf_config (sw_if_index);

  if (config->bridge || config->xconnect)
    return true;

  return false;
}

static void
macip_acl_apply (macip_acl_t * a, u32 sw_if_index)
{
  match_set_tag_flags_t tag_flags;
  macip_acl_main_t *am = &macip_acl_main;
  macip_acl_match_t *mam;
  vnet_link_t linkt;

  tag_flags = match_set_get_itf_tag_flags (sw_if_index);

  /* *INDENT-OFF* */
  FOR_EACH_MACIP_LINK_W_RULES(a, linkt, mam,
  ({
    vec_validate_init_empty(am->macip_match_apps_by_sw_if_index[linkt],
                            sw_if_index,
                            MATCH_SET_APP_INVALID);
    vec_validate_init_empty (mam->apps,
                             sw_if_index,
                             MATCH_SET_APP_INVALID);
  }));
  /* *INDENT-ON* */

  /* derive the layer at which the ACls will be matched from the mode
   * of the lnk */
  if (macip_acl_is_link_l2 (sw_if_index))
    {
      /* the link is configued L2 mode (bridged or xconnect) */
      /* *INDENT-OFF* */
      FOR_EACH_MACIP_LINK_W_RULES(a, linkt, mam,
      ({
        /* Instantiate the match-set to apply to ethernet packets
         * with the match-any rule sematics */
        match_set_apply (mam->msi, MATCH_SEMANTIC_FIRST,
                         VNET_LINK_ETHERNET,
                         tag_flags,
                         &mam->apps[sw_if_index]);
        am->macip_match_apps_by_sw_if_index[linkt][sw_if_index] =
          mam->apps[sw_if_index];

        /* enable the feature in the switch l2 switch paths where we have rules */
        vnet_l2_feature_enable_disable (macip_l2_feat_arc_name[VLIB_RX][linkt],
                                        macip_l2_feat_name[VLIB_RX][linkt],
                                        sw_if_index, 1, 0, 0);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* The link is in L3 mode. Add to both the ip4 and ip6 path */
      /* *INDENT-OFF* */
      FOR_EACH_MACIP_LINK_W_RULES(a, linkt, mam,
      ({
        /* Instantiate the match-set to apply to packets at ip[4|6] */
        match_set_apply (mam->msi, MATCH_SEMANTIC_FIRST,
                         linkt, tag_flags,
                         &mam->apps[sw_if_index]);
        am->macip_match_apps_by_sw_if_index[linkt][sw_if_index] =
          mam->apps[sw_if_index];

        vnet_feature_enable_disable (macip_ip_feat_arc_name[VLIB_RX][linkt],
                                     macip_ip_feat_name[VLIB_RX][linkt],
                                     sw_if_index, 1, 0, 0);
      }));
      /* *INDENT-ON* */
    }
}

static void
macip_acl_unapply (macip_acl_t * a, u32 sw_if_index)
{
  macip_acl_main_t *mm = &macip_acl_main;
  macip_acl_match_t *mam;
  vnet_link_t linkt;

  /* *INDENT-OFF* */
  FOR_EACH_MACIP_LINK_W_RULES(a, linkt, mam,
  ({
    if (macip_acl_is_link_l2(sw_if_index))
      vnet_l2_feature_enable_disable (macip_l2_feat_arc_name[VLIB_RX][linkt],
                                      macip_l2_feat_name[VLIB_RX][linkt],
                                      sw_if_index, 0, 0, 0);
    else
      vnet_feature_enable_disable (macip_ip_feat_arc_name[VLIB_RX][linkt],
                                   macip_ip_feat_name[VLIB_RX][linkt],
                                   sw_if_index, 1, 0, 0);
    match_set_unapply (mam->msi, &mam->apps[sw_if_index]);
    mm->macip_match_apps_by_sw_if_index[linkt][sw_if_index] =
      MATCH_SET_APP_INVALID;
  }));
  /* *INDENT-ON* */

}

int
macip_add (u32 count, vl_api_macip2_rule_t rules[],
	   u32 * acl_list_index, u8 * tag)
{
  macip_action_t *actions[VNET_N_LINKS] = { };
  macip_acl_main_t *mm = &macip_acl_main;
  match_list_t mls[VNET_N_LINKS] = { {} };
  macip_acl_match_t *mam;
  vnet_link_t linkt;
  macip_acl_t *a;
  index_t mai;
  int rv, i;

  mai = *acl_list_index;

  if (0 == count)
    {
      MACIP_WARN ("create empty MACIP ACL (tag %s)", tag);
      return VNET_API_ERROR_LIST_EMPTY;
    }

  /* convert from the input rule representation into temporary match lists */
  for (i = 0; i < count; i++)
    {
      /* build separate lists for IP4, IP6 and ARP rules */
      macip_action_t action;
      match_rule_t mr1 = {
	.mr_type = MATCH_TYPE_MASK_IP_MAC,
	.mr_orientation = MATCH_SRC,
      };

      macip_rule_to_match_rule (&rules[i], &mr1, &action);

      if (mr1.mr_mask_ip_mac.mmim_ip.mip_ip.addr.version == AF_IP4)
	{
	  linkt = VNET_LINK_IP4;
	  mr1.mr_proto = ETHERNET_TYPE_IP4;
	}
      else
	{
	  linkt = VNET_LINK_IP6;
	  mr1.mr_proto = ETHERNET_TYPE_IP6;
	}

      match_list_push_back (&mls[linkt], &mr1);
      vec_add1 (actions[linkt], action);

      if (VNET_LINK_IP4 == linkt)
	{
	  match_rule_t mr2 = {
	    .mr_type = MATCH_TYPE_MASK_IP_MAC,
	    .mr_orientation = MATCH_SRC,
	    .mr_proto = ETHERNET_TYPE_ARP,
	  };
	  macip_rule_to_match_rule (&rules[i], &mr2, &action);
	  match_list_push_back (&mls[VNET_LINK_ARP], &mr2);
	  vec_add1 (actions[VNET_LINK_ARP], action);
	}
    }

  if (~0 == mai)
    {
      /* Get ACL index */
      pool_get_zero (mm->macip_acls, a);

      /* Will return the newly allocated ACL index */
      mai = a - mm->macip_acls;

      /* *INDENT-OFF* */
      FOR_EACH_MACIP_LINK(a, linkt, mam,
      ({
        match_list_copy (&mam->ml, &mls[linkt]);
        mam->actions = actions[linkt];
      }));
      /* *INDENT-ON* */

      /*
       * Create the match sets for each link type for which we have rules.
       * We need to delay instantiating the match-set until such time as we know
       * which interfaces they will be applied on. Since only then will we know
       * what link-type packets they will see (i.e. where in the switch path
       * the ACLs will be applied.
       */
      /* *INDENT-OFF* */
      FOR_EACH_MACIP_LINK_W_RULES(a, linkt, mam,
      ({
        u8 *name;

        name = format (NULL, "macip-%U-%v",
                       format_vnet_link, linkt, a->tag);
        mam->msi = match_set_create_and_lock (name,
                                              MATCH_TYPE_MASK_IP_MAC,
                                              MATCH_SRC,
                                              vnet_link_to_l3_proto(linkt),
                                              acl_mk_heap());
        vec_free(name);

        mam->mh_list = match_set_list_add (mam->msi,
                                           &mam->ml,
                                           0, // priority
                                           mam->actions);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* They supplied an index, let's see if this MACIP ACL exists */
      if (pool_is_free_index (mm->macip_acls, mai))
	{
	  /* tried to replace a non-existent ACL, no point doing anything */
	  MACIP_WARN ("replace nonexistent MACIP ACL %d (tag %s)", mai, tag);
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto out;
	}

      a = pool_elt_at_index (mm->macip_acls, mai);

      /* *INDENT-OFF* */
      FOR_EACH_MACIP_LINK (a, linkt, mam,
      ({
        vec_free(mam->actions);
        mam->actions = actions[linkt];

        if (match_list_length(&mam->ml) &&
            match_list_length(&mls[linkt])) {
          /* did and do have rules => repleace the old with the new */
          match_list_copy(&mam->ml, &mls[linkt]);
          match_set_list_replace (mam->msi,
                                  mam->mh_list,
                                  &mam->ml,
                                  0, // priority
                                  mam->actions);
        }
        else if (match_list_length(&mam->ml)) {
          /* did now don't  => delete the old */
          match_set_list_del (mam->msi, &mam->mh_list);
          match_list_free(&mam->ml);
        } else if (match_list_length(&mls[linkt])) {
          /* didn't now do have rules => add new */
          match_list_copy(&mam->ml, &mls[linkt]);
          mam->mh_list = match_set_list_add (mam->msi,
                                             &mam->ml,
                                             0, // priority
                                             mam->actions);
        }
        /* else - didn't and don't have rules */
      }));
      /* *INDENT-ON* */

      vec_free (a->tag);
    }

  /* the user can change the tag on the acl during the replace */
  a->tag = format (NULL, "%s", tag);
  rv = 0;

out:
  FOR_EACH_VNET_LINK (linkt) match_list_free (&mls[linkt]);

  *acl_list_index = mai;

  return (rv);
}

/* No check that sw_if_index denotes a valid interface - the callers
 * were supposed to validate.
 *
 * That said, if sw_if_index corresponds to an interface that exists at all,
 * this function must return errors accordingly if the ACL is not applied.
 */
static int
macip_unbind (macip_acl_main_t * mm, u32 sw_if_index)
{
  u32 macip_acl_index;
  macip_acl_t *a;

  /* The vector is too short - MACIP ACL is not applied */
  if (sw_if_index >= vec_len (mm->macip_acl_by_sw_if_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  macip_acl_index = mm->macip_acl_by_sw_if_index[sw_if_index];
  /* No point in deleting MACIP ACL which is not applied */
  if (~0 == macip_acl_index)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  a = pool_elt_at_index (mm->macip_acls, macip_acl_index);

  /* Unset the MACIP ACL index */
  mm->macip_acl_by_sw_if_index[sw_if_index] = ~0;
  /* macip_bind_i did a vec_add1() to this previously, so [sw_if_index] should be valid */
  u32 index = vec_search (mm->sw_if_index_vec_by_macip_acl[macip_acl_index],
			  sw_if_index);
  if (index != ~0)
    vec_del1 (mm->sw_if_index_vec_by_macip_acl[macip_acl_index], index);

  macip_acl_unapply (a, sw_if_index);

  return 0;
}

/* No check for validity of sw_if_index - the callers were supposed to validate */
static int
macip_bind_i (macip_acl_main_t * mm, u32 sw_if_index, u32 macip_acl_index)
{
  macip_acl_t *a;

  if (pool_is_free_index (mm->macip_acls, macip_acl_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  a = pool_elt_at_index (mm->macip_acls, macip_acl_index);
  vec_validate_init_empty (mm->macip_acl_by_sw_if_index, sw_if_index, ~0);
  vec_validate (mm->sw_if_index_vec_by_macip_acl, macip_acl_index);
  vec_add1 (mm->sw_if_index_vec_by_macip_acl[macip_acl_index], sw_if_index);

  /* If there already a MACIP ACL applied, unapply it */
  if (~0 != mm->macip_acl_by_sw_if_index[sw_if_index])
    macip_unbind (mm, sw_if_index);
  mm->macip_acl_by_sw_if_index[sw_if_index] = macip_acl_index;

  macip_acl_apply (a, sw_if_index);
  return 0;
}

int
macip_del (u32 acl_list_index)
{
  macip_acl_main_t *mm = &macip_acl_main;
  macip_acl_match_t *mam;
  vnet_link_t linkt;
  u32 sw_if_index;
  macip_acl_t *a;

  if (pool_is_free_index (mm->macip_acls, acl_list_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* now we can delete the ACL itself */
  a = pool_elt_at_index (mm->macip_acls, acl_list_index);

  /* delete any references to the ACL */
  vec_foreach_index (sw_if_index, mm->macip_acl_by_sw_if_index)
  {
    if (mm->macip_acl_by_sw_if_index[sw_if_index] == acl_list_index)
      macip_unbind (mm, sw_if_index);
  }

  /* *INDENT-OFF* */
  FOR_EACH_MACIP_LINK_W_RULES(a, linkt, mam,
  ({
    match_set_list_del (mam->msi, &mam->mh_list);
    match_set_unlock (&mam->msi);
    match_list_free (&mam->ml);
    vec_free(mam->actions);
  }));
  /* *INDENT-ON* */

  vec_free (a->tag);
  pool_put (mm->macip_acls, a);

  return 0;
}


int
macip_bind (u32 sw_if_index, u32 macip_index)
{
  macip_acl_main_t *mm = &macip_acl_main;
  int rv;

  if (~0 == macip_index)
    rv = macip_unbind (mm, sw_if_index);
  else
    rv = macip_bind_i (mm, sw_if_index, macip_index);

  return rv;
}

u8 *
format_macip_action (u8 * s, va_list * args)
{
  macip_action_t action = va_arg (*args, macip_action_t);

  s = format (s, "%s", (action == MACIP_ACTION_PERMIT ? "permit" : "deny"));

  return (s);
}

static u8 *
format_macip_actions (u8 * s, va_list * args)
{
  macip_action_t *actions = va_arg (*args, macip_action_t *);
  u32 index = va_arg (*args, u32);

  s = format (s, "%U", format_macip_action, actions[index]);

  return (s);
}

u8 *
format_macip_acl (u8 * s, va_list * args)
{
  u32 ai = va_arg (*args, u32);
  macip_acl_main_t *mm = &macip_acl_main;
  macip_acl_match_t *mam;
  vnet_link_t linkt;
  macip_acl_t *a;

  if (pool_is_free_index (mm->macip_acls, ai))
    return (format (s, "<invalid-index>:%d", ai));

  a = pool_elt_at_index (mm->macip_acls, ai);

  s = format (s, "MACIP index: %d, tag: {%v}", ai, a->tag);

  /* *INDENT-OFF* */
  FOR_EACH_MACIP_LINK_W_RULES(a, linkt, mam,
  ({
    s = format (s, "\n %U match-list:  %U",
                format_vnet_link, linkt,
                format_match_list_w_result, &mam->ml, 3,
                format_macip_actions, mam->actions);

    s = format (s, "\n %U match-set:  %U",
                format_vnet_link, linkt,
                format_match_set, mam->msi);
  }));
  /* *INDENT-ON* */

  if (ai < vec_len (mm->sw_if_index_vec_by_macip_acl))
    s = format (s, "\n  applied on sw_if_index(s): %U",
		format_vec32,
		vec_elt (mm->sw_if_index_vec_by_macip_acl, ai), "%d");

  return (s);
}

/*
 * if the interface is deleted, remove the ACL application
 */
static clib_error_t *
acl_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  if (0 == is_add)
    macip_unbind (&macip_acl_main, sw_if_index);

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (acl_sw_interface_add_del);

static clib_error_t *
macip_acl_init (vlib_main_t * vm)
{
  macip_logger = vlib_log_register_class ("acl", "macip");

  return (NULL);
}

VLIB_INIT_FUNCTION (macip_acl_init);

static clib_error_t *
acl_show_macip_acl_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  macip_acl_main_t *mm = &macip_acl_main;
  u32 acl_index = ~0;

  (void) unformat (input, "index %u", &acl_index);

  if (~0 != acl_index)
    vlib_cli_output (vm, "%U", format_macip_acl, acl_index);
  else
    {
      u32 ai;
      /* *INDENT-OFF* */
      pool_foreach_index(ai, mm->macip_acls,
      ({
        vlib_cli_output (vm, "%U", format_macip_acl, ai);
      }));
      /* *INDENT-ON* */
    }

  return (NULL);
}

static clib_error_t *
acl_show_macip_interface_fn (vlib_main_t * vm,
			     unformat_input_t *
			     input, vlib_cli_command_t * cmd)
{
  macip_acl_main_t *mm = &macip_acl_main;
  int i;

  for (i = 0; i < vec_len (mm->macip_acl_by_sw_if_index); i++)
    {
      vlib_cli_output (vm, "  sw_if_index %d: %d\n", i,
		       vec_elt (mm->macip_acl_by_sw_if_index, i));
    }
  return (NULL);
}

VLIB_CLI_COMMAND (aclplugin_show_macip_acl_command, static) =
{
.path = "show acl2 macip acl",.short_help =
    "show acl2 macip acl [index N]",.function = acl_show_macip_acl_fn,};

VLIB_CLI_COMMAND (aclplugin_show_macip_interface_command, static) =
{
.path = "show acl2 macip interface",.short_help =
    "show acl2 macip interface",.function = acl_show_macip_interface_fn,};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
