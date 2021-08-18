/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <npol/npol.h>
#include <npol/npol_rule.h>
#include <npol/npol_policy.h>
#include <npol/npol_ipset.h>
#include <npol/npol_interface.h>

#define REPLY_MSG_ID_BASE cpm->msg_id_base
#include <vlibapi/api_helper_macros.h>

#define CALICO_POLICY_VERSION_MAJOR 0
#define CALICO_POLICY_VERSION_MINOR 0

npol_main_t npol_main = { 0 };

void
npol_policy_rule_decode (const vl_api_npol_policy_item_t *in,
			 npol_policy_rule_t *out)
{
  out->rule_id = clib_net_to_host_u32 (in->rule_id);
  out->direction = in->is_inbound ? VLIB_RX : VLIB_TX;
}

int
npol_ipset_member_decode (npol_ipset_type_t type,
			  const vl_api_npol_ipset_member_t *in,
			  npol_ipset_member_t *out)
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
npol_port_range_decode (const vl_api_npol_port_range_t *in,
			npol_port_range_t *out)
{
  out->start = clib_net_to_host_u16 (in->start);
  out->end = clib_net_to_host_u16 (in->end);
}

int
npol_rule_entry_decode (const vl_api_npol_rule_entry_t *in,
			npol_rule_entry_t *out)
{
  out->flags = 0;
  if (in->is_src)
    out->flags |= NPOL_IS_SRC;
  if (in->is_not)
    out->flags |= NPOL_IS_NOT;
  out->type = (npol_entry_type_t) in->type;
  switch (in->type)
    {
    case NPOL_CIDR:
      return ip_prefix_decode2 (&in->data.cidr, &out->data.cidr);
    case NPOL_PORT_RANGE:
      npol_port_range_decode (&in->data.port_range, &out->data.port_range);
      return 0;
    case NPOL_PORT_IP_SET:
    case NPOL_IP_SET:
      out->data.set_id = clib_net_to_host_u32 (in->data.set_id.set_id);
      return 0;
    default:
      return -1;
    }
}

void
npol_rule_filter_decode (const vl_api_npol_rule_filter_t *in,
			 npol_rule_filter_t *out)
{
  out->type = (npol_rule_filter_type_t) in->type;
  out->should_match = in->should_match;
  out->value = clib_net_to_host_u32 (in->value);
}

static void
vl_api_npol_get_version_t_handler (vl_api_npol_get_version_t *mp)
{
  npol_main_t *cpm = &npol_main;
  vl_api_npol_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_NPOL_GET_VERSION_REPLY + cpm->msg_id_base);
  rmp->context = mp->context;
  rmp->major = htonl (CALICO_POLICY_VERSION_MAJOR);
  rmp->minor = htonl (CALICO_POLICY_VERSION_MINOR);

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* NAME: ipset_create */
static void
vl_api_npol_ipset_create_t_handler (vl_api_npol_ipset_create_t *mp)
{
  npol_main_t *cpm = &npol_main;
  vl_api_npol_ipset_create_reply_t *rmp;
  int rv = 0;
  u32 id;

  id = npol_ipset_create ((npol_ipset_type_t) mp->type);

  REPLY_MACRO2 (VL_API_NPOL_IPSET_CREATE_REPLY,
		({ rmp->set_id = clib_host_to_net_u32 (id); }));
}

/* NAME: ipset_add_del_members */
static void
vl_api_npol_ipset_add_del_members_t_handler (
  vl_api_npol_ipset_add_del_members_t *mp)
{
  npol_main_t *cpm = &npol_main;
  vl_api_npol_ipset_add_del_members_reply_t *rmp;
  u32 set_id, i, n_members;
  npol_ipset_type_t type;
  int rv = 0;

  set_id = clib_net_to_host_u32 (mp->set_id);
  n_members = clib_net_to_host_u32 (mp->len);

  rv = npol_ipset_get_type (set_id, &type);
  if (rv)
    goto done;

  for (i = 0; i < n_members; i++)
    {
      npol_ipset_member_t _m, *member = &_m;
      rv = npol_ipset_member_decode (type, &mp->members[i], member);
      if (rv)
	break;
      if (mp->is_add)
	rv = npol_ipset_add_member (set_id, member);
      else
	rv = npol_ipset_del_member (set_id, member);
      if (rv)
	break;
    }

done:
  REPLY_MACRO (VL_API_NPOL_IPSET_ADD_DEL_MEMBERS_REPLY);
}

/* NAME: ipset_delete */
static void
vl_api_npol_ipset_delete_t_handler (vl_api_npol_ipset_delete_t *mp)
{
  npol_main_t *cpm = &npol_main;
  vl_api_npol_ipset_delete_reply_t *rmp;
  u32 set_id;
  int rv;

  set_id = clib_net_to_host_u32 (mp->set_id);
  rv = npol_ipset_delete (set_id);

  REPLY_MACRO (VL_API_NPOL_IPSET_DELETE_REPLY);
}

static int
vl_api_npol_rule_update_create_handler (u32 *id, vl_api_npol_rule_t *rule)
{
  npol_rule_filter_t *filters = 0, *filter;
  npol_rule_entry_t *entries = 0, *entry;
  npol_rule_action_t action;
  int rv;
  u32 n_matches;
  u32 i;

  action = (npol_rule_action_t) rule->action;

  for (i = 0; i < ARRAY_LEN (rule->filters); i++)
    {
      vec_add2 (filters, filter, 1);
      npol_rule_filter_decode (&rule->filters[i], filter);
    }

  n_matches = clib_net_to_host_u32 (rule->num_entries);
  for (i = 0; i < n_matches; i++)
    {
      vec_add2 (entries, entry, 1);
      if ((rv = npol_rule_entry_decode (&rule->matches[i], entry)))
	goto done;
    }

  rv = npol_rule_update (id, action, filters, entries);

done:
  vec_free (filters);
  vec_free (entries);
  return rv;
}

/* NAME: rule_create */
static void
vl_api_npol_rule_create_t_handler (vl_api_npol_rule_create_t *mp)
{
  vl_api_npol_rule_create_reply_t *rmp;
  npol_main_t *cpm = &npol_main;
  u32 id = NPOL_INVALID_INDEX;
  int rv;

  rv = vl_api_npol_rule_update_create_handler (&id, &mp->rule);

  REPLY_MACRO2 (VL_API_NPOL_RULE_CREATE_REPLY,
		({ rmp->rule_id = clib_host_to_net_u32 (id); }));
}

/* NAME: rule_update */
static void
vl_api_npol_rule_update_t_handler (vl_api_npol_rule_update_t *mp)
{
  vl_api_npol_rule_update_reply_t *rmp;
  npol_main_t *cpm = &npol_main;
  u32 id;
  int rv;

  id = clib_net_to_host_u32 (mp->rule_id);
  rv = vl_api_npol_rule_update_create_handler (&id, &mp->rule);

  REPLY_MACRO (VL_API_NPOL_RULE_UPDATE_REPLY);
}

/* NAME: rule_delete */
static void
vl_api_npol_rule_delete_t_handler (vl_api_npol_rule_delete_t *mp)
{
  vl_api_npol_rule_delete_reply_t *rmp;
  npol_main_t *cpm = &npol_main;
  u32 id;
  int rv;

  id = clib_net_to_host_u32 (mp->rule_id);
  rv = npol_rule_delete (id);

  REPLY_MACRO (VL_API_NPOL_RULE_DELETE_REPLY);
}

static int
vl_api_npol_policy_update_create_handler (u32 *id, u32 n_rules,
					  vl_api_npol_policy_item_t *api_rules)
{
  npol_policy_rule_t *rules = 0, *rule;
  int rv;

  for (u32 i = 0; i < n_rules; i++)
    {
      vec_add2 (rules, rule, 1);
      npol_policy_rule_decode (&api_rules[i], rule);
    }

  rv = npol_policy_update (id, rules);

  vec_free (rules);
  return rv;
}

/* NAME: policy_create */
static void
vl_api_npol_policy_create_t_handler (vl_api_npol_policy_create_t *mp)
{
  vl_api_npol_policy_create_reply_t *rmp;
  npol_main_t *cpm = &npol_main;
  u32 id = NPOL_INVALID_INDEX, n_rules;
  int rv;

  n_rules = clib_net_to_host_u32 (mp->num_items);
  rv = vl_api_npol_policy_update_create_handler (&id, n_rules, mp->rules);

  REPLY_MACRO2 (VL_API_NPOL_POLICY_CREATE_REPLY,
		({ rmp->policy_id = clib_host_to_net_u32 (id); }));
}

/* NAME: policy_update */
static void
vl_api_npol_policy_update_t_handler (vl_api_npol_policy_update_t *mp)
{
  vl_api_npol_policy_update_reply_t *rmp;
  npol_main_t *cpm = &npol_main;
  u32 id, n_rules;
  int rv;

  id = clib_net_to_host_u32 (mp->policy_id);
  n_rules = clib_net_to_host_u32 (mp->num_items);
  rv = vl_api_npol_policy_update_create_handler (&id, n_rules, mp->rules);

  REPLY_MACRO (VL_API_NPOL_POLICY_UPDATE_REPLY);
}

/* NAME: policy_delete */
static void
vl_api_npol_policy_delete_t_handler (vl_api_npol_policy_delete_t *mp)
{
  vl_api_npol_policy_delete_reply_t *rmp;
  npol_main_t *cpm = &npol_main;
  u32 id;
  int rv = 0;

  id = clib_net_to_host_u32 (mp->policy_id);
  rv = npol_policy_delete (id);

  REPLY_MACRO (VL_API_NPOL_POLICY_DELETE_REPLY);
}

static void
npol_interface_config_decode (const vl_api_npol_configure_policies_t *in,
			      npol_interface_config_t *out)
{
  u32 num_rx_policies, num_tx_policies, total_ids, num_profiles;
  int i = 0;

  num_rx_policies = clib_net_to_host_u32 (in->num_rx_policies);
  num_tx_policies = clib_net_to_host_u32 (in->num_tx_policies);
  total_ids = clib_net_to_host_u32 (in->total_ids);
  num_profiles = total_ids - num_rx_policies - num_tx_policies;

  out->invert_rx_tx = in->invert_rx_tx;
  out->policy_default_rx = in->policy_default_rx;
  out->policy_default_tx = in->policy_default_tx;
  out->profile_default_rx = in->profile_default_rx;
  out->profile_default_tx = in->profile_default_tx;
  vec_resize (out->rx_policies, num_rx_policies);
  for (i = 0; i < num_rx_policies; i++)
    out->rx_policies[i] = clib_net_to_host_u32 (in->policy_ids[i]);
  vec_resize (out->tx_policies, num_tx_policies);
  for (i = 0; i < num_tx_policies; i++)
    out->tx_policies[i] =
      clib_net_to_host_u32 (in->policy_ids[num_rx_policies + i]);
  vec_resize (out->profiles, num_profiles);
  for (i = 0; i < num_profiles; i++)
    out->profiles[i] = clib_net_to_host_u32 (
      in->policy_ids[num_rx_policies + num_tx_policies + i]);
}

/* NAME: configure_policies */
static void
vl_api_npol_configure_policies_t_handler (vl_api_npol_configure_policies_t *mp)
{
  npol_main_t *cpm = &npol_main;
  npol_interface_config_t _conf = { 0 }, *conf = &_conf;
  vl_api_npol_configure_policies_reply_t *rmp;
  u32 sw_if_index;
  int rv = -1;

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  npol_interface_config_decode (mp, conf);

  rv = npol_configure_policies (sw_if_index, conf);

  REPLY_MACRO (VL_API_NPOL_CONFIGURE_POLICIES_REPLY);
}

/* Set up the API message handling tables */
#include <vnet/format_fns.h>
#include <npol/npol.api.c>

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
  npol_main_t *cpm = &npol_main;

  cpm->msg_id_base = setup_message_id_table ();

  return (NULL);
}

static clib_error_t *
calpol_plugin_config (vlib_main_t *vm, unformat_input_t *input)
{
  return NULL;
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Network Policy",
};

VLIB_CONFIG_FUNCTION (calpol_plugin_config, "calico-policy-plugin");

VLIB_INIT_FUNCTION (calpol_init) = {
  .runs_after = VLIB_INITS ("acl_init"),
};
