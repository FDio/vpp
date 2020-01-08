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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <acl2/acl.h>
#include <acl2/macip.h>
#include <vnet/match/match_set.h>
#include <vnet/match/match_types_api.h>
#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <acl2/acl2.api_enum.h>
#include <acl2/acl2.api_types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

// #include "fa_node.h"

acl_main_t acl_main;

#define REPLY_MSG_ID_BASE acl_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

/*
 * The code for the bihash, used by the session management.
 */
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Access Control Lists 2 (ACL)",
};
/* *INDENT-ON* */

static void
  vl_api_acl2_plugin_get_conn_table_max_entries_t_handler
  (vl_api_acl2_plugin_get_conn_table_max_entries_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl2_plugin_get_conn_table_max_entries_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_ACL2_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY +
	   am->msg_id_base);
  rmp->context = mp->context;
  rmp->conn_table_max_entries = __bswap_64 (am->fa_conn_table_max_entries);

  vl_api_send_msg (rp, (u8 *) rmp);
}

/*
 * If the client does not allocate enough memory for a variable-length
 * message, and then proceed to use it as if the full memory allocated,
 * absent the check we happily consume that on the VPP side, and go
 * along as if nothing happened. However, the resulting
 * effects range from just garbage in the API decode
 * (because the decoder snoops too far), to potential memory
 * corruptions.
 *
 * This verifies that the actual length of the message is
 * at least expected_len, and complains loudly if it is not.
 *
 * A failing check here is 100% a software bug on the API user side,
 * so we might as well yell.
 *
 */
static int
verify_message_len (void *mp, u32 expected_len, char *where)
{
  u32 supplied_len = vl_msg_api_get_msg_length (mp);
  if (supplied_len < expected_len)
    {
      clib_warning ("%s: Supplied message length %d is less than expected %d",
		    where, supplied_len, expected_len);
      return 0;
    }
  else
    {
      return 1;
    }
}

static int
acl_action_decode (vl_api_acl2_action_t action, acl_action_t * out)
{
  switch (action)
    {
#define _(a,b)                                  \
      case ACL_API_ACTION_##a:                  \
        *out = ACL_ACTION_##a;                  \
        return (0);
      foreach_acl_action
#undef _
    }

  return (1);
}

static int
acl_rule_decode (const vl_api_acl2_rule_t * in, acl_rule_t * out)
{
  int rv;

  rv = acl_action_decode (in->action, &out->action);
  rv |= match_rule_mask_n_tuple_decode (&in->rule, &out->rule);

  return (rv);
}

/* API message handler */
static void
vl_api_acl2_add_replace_t_handler (vl_api_acl2_add_replace_t * mp)
{
  vl_api_acl2_add_replace_reply_t *rmp;
  int rv = 0;
  u32 acl_list_index = ntohl (mp->acl_index);
  u32 ii, acl_count = ntohl (mp->count);
  u32 expected_len = sizeof (*mp) + acl_count * sizeof (mp->r[0]);

  if (verify_message_len (mp, expected_len, "acl_add_replace"))
    {
      acl_rule_t *rules = NULL;

      vec_validate (rules, acl_count - 1);

      for (ii = 0; ii < acl_count; ii++)
	rv |= acl_rule_decode (&mp->r[ii], &rules[ii]);

      if (!rv)
	rv = acl_list_update (&acl_list_index, rules, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_ACL2_ADD_REPLACE_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_acl2_del_t_handler (vl_api_acl2_del_t * mp)
{
  vl_api_acl2_del_reply_t *rmp;
  int rv;

  rv = acl_list_del (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_ACL2_DEL_REPLY);
}


static void
  vl_api_acl2_stats_intf_counters_enable_t_handler
  (vl_api_acl2_stats_intf_counters_enable_t * mp)
{
  vl_api_acl2_stats_intf_counters_enable_reply_t *rmp;
  int rv;

  rv = acl_stats_intf_counters_enable_disable (mp->enable);

  REPLY_MACRO (VL_API_ACL2_DEL_REPLY);
}

static void
  vl_api_acl2_interface_set_acl_list_t_handler
  (vl_api_acl2_interface_set_acl_list_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl2_interface_set_acl_list_reply_t *rmp;
  int rv = 0;
  int i;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  int may_clear_sessions = 1;
  for (i = 0; i < mp->count; i++)
    {
      if (acl_is_not_defined (am, ntohl (mp->acls[i])))
	{
	  /* ACL does not exist, so we can not apply it */
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}
    }
  if (0 == rv)
    {
      u32 *in_acl_vec = 0;
      u32 *out_acl_vec = 0;

      for (i = 0; i < mp->count; i++)
	if (i < mp->n_input)
	  vec_add1 (in_acl_vec, clib_net_to_host_u32 (mp->acls[i]));
	else
	  vec_add1 (out_acl_vec, clib_net_to_host_u32 (mp->acls[i]));

      rv |= acl_interface_set_inout_acl_list (am, sw_if_index, VLIB_TX,
					      out_acl_vec,
					      &may_clear_sessions);
      rv |= acl_interface_set_inout_acl_list (am, sw_if_index, VLIB_RX,
					      in_acl_vec,
					      &may_clear_sessions);
      vec_free (in_acl_vec);
      vec_free (out_acl_vec);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_ACL2_INTERFACE_SET_ACL_LIST_REPLY);
}

vl_api_acl2_action_t
acl_action_encode (acl_action_t in)
{
  return ((vl_api_acl2_action_t) in);
}

static void
acl_rule_encode (const acl_rule_t * in, vl_api_acl2_rule_t * out)
{
  out->action = acl_action_encode (in->action);
  match_rule_mask_n_tuple_encode (&in->rule, &out->rule);
}

static void
send_acl_details (acl_main_t * am, vl_api_registration_t * reg,
		  acl_list_t * acl, u32 context)
{
  vl_api_acl2_rule_t *api_rule;
  vl_api_acl2_details_t *mp;
  acl_rule_t *rule;

  u32 n_rules = vec_len (acl->rules);
  int msg_size = sizeof (*mp) + sizeof (mp->r[0]) * n_rules;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_ACL2_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->count = htonl (n_rules);
  mp->acl_index = htonl (acl - am->acls);
  memcpy (mp->tag, acl->tag, sizeof (mp->tag));

  api_rule = mp->r;
  vec_foreach (rule, acl->rules)
  {
    acl_rule_encode (rule, api_rule);
    api_rule++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_acl2_dump_t_handler (vl_api_acl2_dump_t * mp)
{
  acl_main_t *am = &acl_main;
  u32 acl_index;
  acl_list_t *acl;
  int rv = -1;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->acl_index == ~0)
    {
    /* *INDENT-OFF* */
    /* Just dump all ACLs */
    pool_foreach (acl, am->acls,
    ({
      send_acl_details(am, reg, acl, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (am->acls, acl_index))
	{
	  acl = pool_elt_at_index (am->acls, acl_index);
	  send_acl_details (am, reg, acl, mp->context);
	}
    }

  if (rv == -1)
    {
      /* FIXME API: should we signal an error here at all ? */
      return;
    }
}

static void
send_acl_interface_list_details (acl_main_t * am,
				 vl_api_registration_t * reg,
				 u32 sw_if_index, u32 context)
{
  int i, msg_size, n_input, n_output, count;
  vl_api_acl2_interface_list_details_t *mp;
  acl_itf_t *aitf[VLIB_N_RX_TX];

  n_input = n_output = 0;
  aitf[VLIB_RX] = acl_itf_get (sw_if_index, VLIB_RX);
  aitf[VLIB_TX] = acl_itf_get (sw_if_index, VLIB_TX);

  if (aitf[VLIB_RX])
    n_input = vec_len (aitf[VLIB_RX]->acls);
  if (aitf[VLIB_TX])
    n_output = vec_len (aitf[VLIB_TX]->acls);
  count = n_input + n_output;

  msg_size = sizeof (*mp);
  msg_size += sizeof (mp->acls[0]) * count;

  mp = vl_msg_api_alloc (msg_size);
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id =
    ntohs (VL_API_ACL2_INTERFACE_LIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->count = count;
  mp->n_input = n_input;
  for (i = 0; i < n_input; i++)
    {
      mp->acls[i] = htonl (aitf[VLIB_RX]->acls[i].acl_index);
    }
  for (i = 0; i < n_output; i++)
    {
      mp->acls[n_input + i] = htonl (aitf[VLIB_TX]->acls[i].acl_index);
    }
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_acl2_interface_list_dump_t_handler (vl_api_acl2_interface_list_dump_t *
					   mp)
{
  acl_main_t *am = &acl_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;

  u32 sw_if_index;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->sw_if_index == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach (swif, im->sw_interfaces,
    ({
      send_acl_interface_list_details(am, reg, swif->sw_if_index, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      sw_if_index = ntohl (mp->sw_if_index);
      if (!pool_is_free_index (im->sw_interfaces, sw_if_index))
	send_acl_interface_list_details (am, reg, sw_if_index, mp->context);
    }
}

/* MACIP ACL API handlers */

static void
vl_api_macip2_acl_add_t_handler (vl_api_macip2_acl_add_t * mp)
{
  vl_api_macip2_acl_add_reply_t *rmp;
  int rv;
  u32 acl_list_index = ~0;
  u32 acl_count = ntohl (mp->count);
  u32 expected_len = sizeof (*mp) + acl_count * sizeof (mp->r[0]);

  if (verify_message_len (mp, expected_len, "macip_acl_add"))
    {
      rv = macip_acl_add_list (acl_count, mp->r, &acl_list_index, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MACIP2_ACL_ADD_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_macip2_acl_add_replace_t_handler (vl_api_macip2_acl_add_replace_t * mp)
{
  vl_api_macip2_acl_add_replace_reply_t *rmp;
  int rv;
  u32 acl_list_index = ntohl (mp->acl_index);
  u32 acl_count = ntohl (mp->count);
  u32 expected_len = sizeof (*mp) + acl_count * sizeof (mp->r[0]);

  if (verify_message_len (mp, expected_len, "macip_acl_add_replace"))
    {
      rv = macip_acl_add_list (acl_count, mp->r, &acl_list_index, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MACIP2_ACL_ADD_REPLACE_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_macip2_acl_del_t_handler (vl_api_macip2_acl_del_t * mp)
{
  vl_api_macip2_acl_del_reply_t *rmp;
  int rv;

  rv = macip_acl_del_list (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_MACIP2_ACL_DEL_REPLY);
}

static void
  vl_api_macip2_acl_interface_add_del_t_handler
  (vl_api_macip2_acl_interface_add_del_t * mp)
{
  vl_api_macip2_acl_interface_add_del_reply_t *rmp;
  int rv = -1;

  VALIDATE_SW_IF_INDEX (mp);

  rv = macip_acl_interface_add_del_acl (ntohl (mp->sw_if_index),
					mp->is_add, ntohl (mp->acl_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_MACIP2_ACL_INTERFACE_ADD_DEL_REPLY);
}

static void
send_macip_acl_details (acl_main_t * am, vl_api_registration_t * reg,
			macip_acl_t * acl, u32 context)
{
  vl_api_macip2_acl_details_t *mp;
  vl_api_macip2_acl_rule_t *rule;
  macip_acl_match_t *mam;
  macip_acl_main_t *mm;
  vnet_link_t linkt;
  match_rule_t *mr;
  u32 i, n_rules;

  mm = &macip_acl_main;

  n_rules = (match_list_length (&acl->matches[VNET_LINK_IP4].ml) +
	     match_list_length (&acl->matches[VNET_LINK_IP6].ml));

  u32 msg_size = sizeof (*mp) + (sizeof (mp->r[0]) * n_rules);

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_MACIP2_ACL_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;

  memcpy (mp->tag, acl->tag, clib_min (sizeof (mp->tag), vec_len (acl->tag)));
  mp->count = htonl (n_rules);
  mp->acl_index = htonl (acl - mm->macip_acls);
  i = 0;

  /* *INDENT-OFF* */
  FOR_EACH_MACIP_IP_LINK_W_RULES(acl, linkt, mam,
  ({
    vec_foreach(mr, mam->ml.ml_rules) {
      rule = &mp->r[i];

      // FIXME
      rule->is_permit = 1;	//r->is_permit;
      match_rule_mask_ip_mac_encode(mr, &rule->rule);
      i++;
    }
  }));
  /* *INDENT-ON* */

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_macip2_acl_dump_t_handler (vl_api_macip2_acl_dump_t * mp)
{
  macip_acl_main_t *mm = &macip_acl_main;
  acl_main_t *am = &acl_main;
  macip_acl_t *acl;

  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->acl_index == ~0)
    {
      /* Just dump all ACLs for now, with sw_if_index = ~0 */
      /* *INDENT-OFF* */
      pool_foreach (acl, mm->macip_acls,
        ({
          send_macip_acl_details (am, reg, acl, mp->context);
        }));
      /* *INDENT-ON* */
    }
  else
    {
      u32 acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (mm->macip_acls, acl_index))
	{
	  acl = pool_elt_at_index (mm->macip_acls, acl_index);
	  send_macip_acl_details (am, reg, acl, mp->context);
	}
    }
}

static void
vl_api_macip2_acl_interface_get_t_handler (vl_api_macip2_acl_interface_get_t *
					   mp)
{
  macip_acl_main_t *mm = &macip_acl_main;
  acl_main_t *am = &acl_main;
  vl_api_macip2_acl_interface_get_reply_t *rmp;
  u32 count = vec_len (mm->macip_acl_by_sw_if_index);
  int msg_size = sizeof (*rmp) + sizeof (rmp->acls[0]) * count;
  vl_api_registration_t *reg;
  int i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_MACIP2_ACL_INTERFACE_GET_REPLY + am->msg_id_base);
  rmp->context = mp->context;
  rmp->count = htonl (count);
  for (i = 0; i < count; i++)
    {
      rmp->acls[i] = htonl (mm->macip_acl_by_sw_if_index[i]);
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_macip_acl_interface_list_details (acl_main_t * am,
				       vl_api_registration_t * reg,
				       u32 sw_if_index,
				       u32 acl_index, u32 context)
{
  vl_api_macip2_acl_interface_list_details_t *rmp;
  /* at this time there is only ever 1 mac ip acl per interface */
  int msg_size = sizeof (*rmp) + sizeof (rmp->acls[0]);

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_MACIP2_ACL_INTERFACE_LIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  rmp->context = context;
  rmp->count = 1;
  rmp->sw_if_index = htonl (sw_if_index);
  rmp->acls[0] = htonl (acl_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_macip2_acl_interface_list_dump_t_handler
  (vl_api_macip2_acl_interface_list_dump_t * mp)
{
  vl_api_registration_t *reg;
  macip_acl_main_t *mm = &macip_acl_main;
  acl_main_t *am = &acl_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (sw_if_index == ~0)
    {
      vec_foreach_index (sw_if_index, mm->macip_acl_by_sw_if_index)
      {
	if (~0 != mm->macip_acl_by_sw_if_index[sw_if_index])
	  {
	    send_macip_acl_interface_list_details (am, reg, sw_if_index,
						   mm->macip_acl_by_sw_if_index
						   [sw_if_index],
						   mp->context);
	  }
      }
    }
  else
    {
      if (vec_len (mm->macip_acl_by_sw_if_index) > sw_if_index)
	{
	  send_macip_acl_interface_list_details (am, reg, sw_if_index,
						 mm->macip_acl_by_sw_if_index
						 [sw_if_index], mp->context);
	}
    }
}

static void
  vl_api_acl2_interface_set_etype_whitelist_t_handler
  (vl_api_acl2_interface_set_etype_whitelist_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl2_interface_set_etype_whitelist_reply_t *rmp;
  int rv = 0;
  int i;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u16 *whitelists[VLIB_N_RX_TX] = { };

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      for (i = 0; i < mp->count; i++)
	{
	  if (i < mp->n_input)
	    vec_add1 (whitelists[VLIB_RX], ntohs (mp->whitelist[i]));
	  else
	    vec_add1 (whitelists[VLIB_TX], ntohs (mp->whitelist[i]));
	}
      rv = acl_set_etype_whitelists (am, sw_if_index, whitelists);
    }

  REPLY_MACRO (VL_API_ACL2_INTERFACE_SET_ETYPE_WHITELIST_REPLY);
}

static void
send_acl_interface_etype_whitelist_details (acl_main_t * am,
					    vl_api_registration_t * reg,
					    u32 sw_if_index, u32 context)
{
  vl_api_acl2_interface_etype_whitelist_details_t *mp;
  int i, msg_size, n_input, n_output, count;
  acl_itf_t *aitf[VLIB_N_RX_TX];

  n_input = n_output = 0;
  aitf[VLIB_RX] = acl_itf_get (sw_if_index, VLIB_RX);
  aitf[VLIB_TX] = acl_itf_get (sw_if_index, VLIB_TX);

  if (aitf[VLIB_RX])
    n_input = vec_len (aitf[VLIB_RX]->whitelist);
  if (aitf[VLIB_TX])
    n_output = vec_len (aitf[VLIB_TX]->whitelist);
  count = n_input + n_output;

  if (!count)
    return;

  msg_size = sizeof (*mp);
  msg_size += sizeof (mp->whitelist[0]) * count;

  mp = vl_msg_api_alloc (msg_size);
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id =
    ntohs (VL_API_ACL2_INTERFACE_ETYPE_WHITELIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->count = count;
  mp->n_input = n_input;
  for (i = 0; i < n_input; i++)
    {
      mp->whitelist[i] = htons (aitf[VLIB_RX]->whitelist[i]);
    }
  for (i = 0; i < n_output; i++)
    {
      mp->whitelist[n_input + i] = htons (aitf[VLIB_TX]->whitelist[i]);
    }

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
  vl_api_acl2_interface_etype_whitelist_dump_t_handler
  (vl_api_acl2_interface_list_dump_t * mp)
{
  acl_main_t *am = &acl_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;

  u32 sw_if_index;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->sw_if_index == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach (swif, im->sw_interfaces,
    ({
      send_acl_interface_etype_whitelist_details(am, reg, swif->sw_if_index, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      sw_if_index = ntohl (mp->sw_if_index);
      if (!pool_is_free_index (im->sw_interfaces, sw_if_index))
	send_acl_interface_etype_whitelist_details (am, reg, sw_if_index,
						    mp->context);
    }
}

/* Set up the API message handling tables */
#include <vnet/format_fns.h>
#include <acl2/acl2.api.c>

static clib_error_t *
acl_api_init (vlib_main_t * vm)
{
  acl_main_t *am = &acl_main;
  clib_error_t *error = 0;

  am->log_default = vlib_log_register_class ("acl2_plugin", 0);

  /* Ask for a correctly-sized block of API message decode slots */
  am->msg_id_base = setup_message_id_table ();

  return error;
}

VLIB_INIT_FUNCTION (acl_api_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
