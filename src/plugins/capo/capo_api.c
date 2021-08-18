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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <capo/capo.h>
#include <capo/capo_rule.h>
#include <capo/capo_policy.h>
#include <capo/capo_ipset.h>
#include <capo/capo_interface.h>

#define REPLY_MSG_ID_BASE cpm->msg_id_base
#include <vlibapi/api_helper_macros.h>

#define CALICO_POLICY_VERSION_MAJOR 0
#define CALICO_POLICY_VERSION_MINOR 0

capo_main_t capo_main = { 0 };

void
capo_policy_rule_decode (const vl_api_capo_policy_item_t *in,
			 capo_policy_rule_t *out)
{
  out->rule_id = clib_net_to_host_u32 (in->rule_id);
  out->direction = in->is_inbound ? VLIB_RX : VLIB_TX;
}

int
capo_ipset_member_decode (capo_ipset_type_t type,
			  const vl_api_capo_ipset_member_t *in,
			  capo_ipset_member_t *out)
{
  switch (type)
    {
    case IPSET_TYPE_IP:
      ip_address_decode2 (&in->val.address, &out->address);
      break;
    case IPSET_TYPE_IPPORT:
      ip_address_decode2 (&in->val.tuple.address, &out->ipport.addr);
      out->ipport.l4proto = in->val.tuple.l4_proto;
      out->ipport.port = clib_net_to_host_u16 (in->val.tuple.port);
      break;
    case IPSET_TYPE_NET:
      return ip_prefix_decode2 (&in->val.prefix, &out->prefix);
    }
  return 0;
}

void
capo_port_range_decode (const vl_api_capo_port_range_t *in,
			capo_port_range_t *out)
{
  out->start = clib_net_to_host_u16 (in->start);
  out->end = clib_net_to_host_u16 (in->end);
}

int
capo_rule_entry_decode (const vl_api_capo_rule_entry_t *in,
			capo_rule_entry_t *out)
{
  out->flags = 0;
  if (in->is_src)
    out->flags |= CAPO_IS_SRC;
  if (in->is_not)
    out->flags |= CAPO_IS_NOT;
  out->type = (capo_entry_type_t) in->type;
  switch (in->type)
    {
    case CAPO_CIDR:
      return ip_prefix_decode2 (&in->data.cidr, &out->data.cidr);
    case CAPO_PORT_RANGE:
      capo_port_range_decode (&in->data.port_range, &out->data.port_range);
      return 0;
    case CAPO_PORT_IP_SET:
    case CAPO_IP_SET:
      out->data.set_id = clib_net_to_host_u32 (in->data.set_id.set_id);
      return 0;
    default:
      return -1;
    }
}

void
capo_rule_filter_decode (const vl_api_capo_rule_filter_t *in,
			 capo_rule_filter_t *out)
{
  out->type = (capo_rule_filter_type_t) in->type;
  out->should_match = in->should_match;
  out->value = clib_net_to_host_u32 (in->value);
}

static void
vl_api_capo_get_version_t_handler (vl_api_capo_get_version_t *mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_CAPO_GET_VERSION_REPLY + cpm->msg_id_base);
  rmp->context = mp->context;
  rmp->major = htonl (CALICO_POLICY_VERSION_MAJOR);
  rmp->minor = htonl (CALICO_POLICY_VERSION_MINOR);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_capo_control_ping_t_handler (vl_api_capo_control_ping_t *mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_control_ping_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_CAPO_CONTROL_PING_REPLY,
		({ rmp->vpe_pid = ntohl (getpid ()); }));
}

/* NAME: ipset_create */
static void
vl_api_capo_ipset_create_t_handler (vl_api_capo_ipset_create_t *mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_ipset_create_reply_t *rmp;
  int rv = 0;
  u32 id;

  id = capo_ipset_create ((capo_ipset_type_t) mp->type);

  REPLY_MACRO2 (VL_API_CAPO_IPSET_CREATE_REPLY,
		({ rmp->set_id = clib_host_to_net_u32 (id); }));
}

/* NAME: ipset_add_del_members */
static void
vl_api_capo_ipset_add_del_members_t_handler (
  vl_api_capo_ipset_add_del_members_t *mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_ipset_add_del_members_reply_t *rmp;
  u32 set_id, i, n_members;
  capo_ipset_type_t type;
  int rv = 0;

  set_id = clib_net_to_host_u32 (mp->set_id);
  n_members = clib_net_to_host_u32 (mp->len);

  rv = capo_ipset_get_type (set_id, &type);
  if (rv)
    goto done;

  for (i = 0; i < n_members; i++)
    {
      capo_ipset_member_t _m, *member = &_m;
      rv = capo_ipset_member_decode (type, &mp->members[i], member);
      if (rv)
	break;
      if (mp->is_add)
	rv = capo_ipset_add_member (set_id, member);
      else
	rv = capo_ipset_del_member (set_id, member);
      if (rv)
	break;
    }

done:
  REPLY_MACRO (VL_API_CAPO_IPSET_ADD_DEL_MEMBERS_REPLY);
}

/* NAME: ipset_delete */
static void
vl_api_capo_ipset_delete_t_handler (vl_api_capo_ipset_delete_t *mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_ipset_delete_reply_t *rmp;
  u32 set_id;
  int rv;

  set_id = clib_net_to_host_u32 (mp->set_id);
  rv = capo_ipset_delete (set_id);

  REPLY_MACRO (VL_API_CAPO_IPSET_DELETE_REPLY);
}

static int
vl_api_capo_rule_update_create_handler (u32 *id, vl_api_capo_rule_t *rule)
{
  capo_rule_filter_t *filters = 0, *filter;
  capo_rule_entry_t *entries = 0, *entry;
  capo_rule_action_t action;
  ip_address_family_t af = 0;
  int rv;
  u32 n_matches;
  u32 i;

  action = (capo_rule_action_t) rule->action;

  // if ((rv = ip_address_family_decode (rule->af, &af)))
  //   goto done;

  for (i = 0; i < ARRAY_LEN (rule->filters); i++)
    {
      vec_add2 (filters, filter, 1);
      capo_rule_filter_decode (&rule->filters[i], filter);
    }

  n_matches = clib_net_to_host_u32 (rule->num_entries);
  for (i = 0; i < n_matches; i++)
    {
      vec_add2 (entries, entry, 1);
      if ((rv = capo_rule_entry_decode (&rule->matches[i], entry)))
	goto done;
    }

  rv = capo_rule_update (id, action, af, filters, entries);

done:
  vec_free (filters);
  vec_free (entries);
  return rv;
}

/* NAME: rule_create */
static void
vl_api_capo_rule_create_t_handler (vl_api_capo_rule_create_t *mp)
{
  vl_api_capo_rule_create_reply_t *rmp;
  capo_main_t *cpm = &capo_main;
  u32 id = CAPO_INVALID_INDEX;
  int rv;

  rv = vl_api_capo_rule_update_create_handler (&id, &mp->rule);

  REPLY_MACRO2 (VL_API_CAPO_RULE_CREATE_REPLY,
		({ rmp->rule_id = clib_host_to_net_u32 (id); }));
}

/* NAME: rule_update */
static void
vl_api_capo_rule_update_t_handler (vl_api_capo_rule_update_t *mp)
{
  vl_api_capo_rule_update_reply_t *rmp;
  capo_main_t *cpm = &capo_main;
  u32 id;
  int rv;

  id = clib_net_to_host_u32 (mp->rule_id);
  rv = vl_api_capo_rule_update_create_handler (&id, &mp->rule);

  REPLY_MACRO (VL_API_CAPO_RULE_UPDATE_REPLY);
}

/* NAME: rule_delete */
static void
vl_api_capo_rule_delete_t_handler (vl_api_capo_rule_delete_t *mp)
{
  vl_api_capo_rule_delete_reply_t *rmp;
  capo_main_t *cpm = &capo_main;
  u32 id;
  int rv;

  id = clib_net_to_host_u32 (mp->rule_id);
  rv = capo_rule_delete (id);

  REPLY_MACRO (VL_API_CAPO_RULE_DELETE_REPLY);
}

static int
vl_api_capo_policy_update_create_handler (u32 *id, u32 n_rules,
					  vl_api_capo_policy_item_t *api_rules)
{
  capo_policy_rule_t *rules = 0, *rule;
  int rv;

  for (u32 i = 0; i < n_rules; i++)
    {
      vec_add2 (rules, rule, 1);
      capo_policy_rule_decode (&api_rules[i], rule);
    }

  rv = capo_policy_update (id, rules);

  vec_free (rules);
  return rv;
}

/* NAME: policy_create */
static void
vl_api_capo_policy_create_t_handler (vl_api_capo_policy_create_t *mp)
{
  vl_api_capo_policy_create_reply_t *rmp;
  capo_main_t *cpm = &capo_main;
  u32 id = CAPO_INVALID_INDEX, n_rules;
  int rv;

  n_rules = clib_net_to_host_u32 (mp->num_items);
  rv = vl_api_capo_policy_update_create_handler (&id, n_rules, mp->rules);

  REPLY_MACRO2 (VL_API_CAPO_POLICY_CREATE_REPLY,
		({ rmp->policy_id = clib_host_to_net_u32 (id); }));
}

/* NAME: policy_update */
static void
vl_api_capo_policy_update_t_handler (vl_api_capo_policy_update_t *mp)
{
  vl_api_capo_policy_update_reply_t *rmp;
  capo_main_t *cpm = &capo_main;
  u32 id, n_rules;
  int rv;

  id = clib_net_to_host_u32 (mp->policy_id);
  n_rules = clib_net_to_host_u32 (mp->num_items);
  rv = vl_api_capo_policy_update_create_handler (&id, n_rules, mp->rules);

  REPLY_MACRO (VL_API_CAPO_POLICY_UPDATE_REPLY);
}

/* NAME: policy_delete */
static void
vl_api_capo_policy_delete_t_handler (vl_api_capo_policy_delete_t *mp)
{
  vl_api_capo_policy_delete_reply_t *rmp;
  capo_main_t *cpm = &capo_main;
  u32 id;
  int rv = 0;

  id = clib_net_to_host_u32 (mp->policy_id);
  rv = capo_policy_delete (id);

  REPLY_MACRO (VL_API_CAPO_POLICY_DELETE_REPLY);
}

/* NAME: configure_policies */
static void
vl_api_capo_configure_policies_t_handler (vl_api_capo_configure_policies_t *mp)
{
  vl_api_capo_configure_policies_reply_t *rmp;
  capo_main_t *cpm = &capo_main;
  u32 num_profiles;
  int rv = -1;
  int i = 0;

  mp->sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  mp->num_ingress_policies = clib_net_to_host_u32 (mp->num_ingress_policies);
  mp->num_egress_policies = clib_net_to_host_u32 (mp->num_egress_policies);
  mp->total_ids = clib_net_to_host_u32 (mp->total_ids);
  num_profiles =
    mp->total_ids - mp->num_ingress_policies - mp->num_egress_policies;
  for (i = 0; i < mp->total_ids; i++)
    {
      mp->policy_ids[i] = clib_net_to_host_u32 (mp->policy_ids[i]);
    }

  rv = capo_configure_policies (mp->sw_if_index, mp->num_ingress_policies,
				mp->num_egress_policies, num_profiles,
				mp->policy_ids);

  REPLY_MACRO (VL_API_CAPO_CONFIGURE_POLICIES_REPLY);
}

/* Set up the API message handling tables */
#include <vnet/format_fns.h>
#include <capo/capo.api.c>

#include <vat/vat.h>
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <acl/acl.api_enum.h>
#include <acl/acl.api_types.h>
#undef vl_print
#define vl_print(handle, ...)
#undef vl_print
#define vl_endianfun /* define message structures */
#include <acl/acl.api.h>
#undef vl_endianfun

static clib_error_t *
calpol_init (vlib_main_t *vm)
{
  capo_main_t *cpm = &capo_main;

  clib_error_t *acl_init_res = acl_plugin_exports_init (&cpm->acl_plugin);
  if (acl_init_res)
    return (acl_init_res);

  cpm->calico_acl_user_id =
    cpm->acl_plugin.register_user_module ("Calico Policy Plugin", NULL, NULL);

  cpm->msg_id_base = setup_message_id_table ();

  clib_bihash_init_8_24 (&cpm->if_config, "capo interfaces", 512, 1 << 20);

  return (NULL);
}

static clib_error_t *
calpol_plugin_config (vlib_main_t *vm, unformat_input_t *input)
{
  return NULL;
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Calico Policy",
};

VLIB_CONFIG_FUNCTION (calpol_plugin_config, "calico-policy-plugin");

VLIB_INIT_FUNCTION (calpol_init) = {
  .runs_after = VLIB_INITS ("acl_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
