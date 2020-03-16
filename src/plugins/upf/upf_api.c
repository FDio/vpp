/*
 * upf.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
 *
 * Copyright (c) 2017 Travelping GmbH
 *
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <upf/upf.h>
#include <upf/upf_app_db.h>

#include <vnet/format_fns.h>
#include <upf/upf.api_enum.h>
#include <upf/upf.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* API message handler */
static void
vl_api_upf_app_add_del_t_handler (vl_api_upf_app_add_del_t * mp)
{
  vl_api_upf_app_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *name = format (0, "%s", mp->name);

  rv = upf_app_add_del (sm, name, (u32) (mp->flags), (int) (mp->is_add));

  vec_free (name);
  REPLY_MACRO (VL_API_UPF_APP_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_ip_rule_add_del_t_handler
  (vl_api_upf_app_ip_rule_add_del_t * mp)
{
  vl_api_upf_app_ip_rule_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *app = format (0, "%s", mp->app);

  // TODO: ip rules aren't implemented yet
  rv =
    upf_rule_add_del (sm, app, clib_net_to_host_u32 (mp->id),
		      (int) (mp->is_add), NULL);

  vec_free (app);
  REPLY_MACRO (VL_API_UPF_APP_IP_RULE_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_l7_rule_add_del_t_handler
  (vl_api_upf_app_l7_rule_add_del_t * mp)
{
  vl_api_upf_app_l7_rule_add_del_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *app = format (0, "%s", mp->app), *regex = format (0, "%s", mp->regex);

  rv =
    upf_rule_add_del (sm, app, clib_net_to_host_u32 (mp->id),
		      (int) (mp->is_add), regex);

  vec_free (app);
  vec_free (regex);
  REPLY_MACRO (VL_API_UPF_APP_L7_RULE_ADD_DEL_REPLY);
}

/* API message handler */
static void vl_api_upf_app_flow_timeout_set_t_handler
  (vl_api_upf_app_flow_timeout_set_t * mp)
{
  int rv = 0;
  vl_api_upf_app_flow_timeout_set_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;

  //rv = upf_flow_timeout_update(mp->type, ntohs(mp->default_value));

  REPLY_MACRO (VL_API_UPF_APP_FLOW_TIMEOUT_SET_REPLY);
}

static void
send_upf_applications_details (vl_api_registration_t * reg,
			       u8 * app_name, u32 flags, u32 context)
{
  vl_api_upf_applications_details_t *mp;
  upf_main_t *sm = &upf_main;
  u32 name_len;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_APPLICATIONS_DETAILS + sm->msg_id_base);
  mp->context = context;

  name_len = clib_min (vec_len (app_name) + 1, ARRAY_LEN (mp->name));
  memcpy (mp->name, app_name, name_len - 1);
  ASSERT (0 == mp->name[name_len - 1]);
  mp->flags = htonl (flags);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void vl_api_upf_applications_dump_t_handler
  (vl_api_upf_applications_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  upf_adf_app_t *app = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach(app, sm->upf_apps,
    ({
      send_upf_applications_details (reg, app->name, app->flags, mp->context);
    }));
  /* *INDENT-ON* */
}

static void
send_upf_application_l7_rule_details (vl_api_registration_t * reg,
				      u32 id, u8 * regex, u32 context)
{
  vl_api_upf_application_l7_rule_details_t *mp;
  upf_main_t *sm = &upf_main;
  u32 regex_len;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_UPF_APPLICATION_L7_RULE_DETAILS
			  + sm->msg_id_base);
  mp->context = context;

  mp->id = htonl (id);
  regex_len = clib_min (vec_len (regex) + 1, ARRAY_LEN (mp->regex));
  memcpy (mp->regex, regex, regex_len - 1);
  ASSERT (0 == mp->regex[regex_len - 1]);

  vl_api_send_msg (reg, (u8 *) mp);
}

/* API message handler */
static void vl_api_upf_application_l7_rule_dump_t_handler
  (vl_api_upf_application_l7_rule_dump_t * mp)
{
  upf_main_t *sm = &upf_main;
  vl_api_registration_t *reg;
  upf_adf_app_t *app = NULL;
  upf_adr_t *rule = NULL;
  u8 *app_name = format (0, "%s", mp->app);
  uword *p = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    {
      return;
    }

  p = hash_get_mem (sm->upf_app_by_name, app_name);
  if (!p)
    return;

  app = pool_elt_at_index (sm->upf_apps, p[0]);

  /* *INDENT-OFF* */
  pool_foreach(rule, app->rules,
               ({
                 send_upf_application_l7_rule_details (reg, rule->id, rule->regex, mp->context);
               }));
  /* *INDENT-ON* */

  vec_free (app_name);
}

/* API message handler */
static void
vl_api_upf_update_app_t_handler (vl_api_upf_update_app_t * mp)
{
  vl_api_upf_update_app_reply_t *rmp = NULL;
  upf_main_t *sm = &upf_main;
  int rv = 0;
  u8 *app_name = format (0, "%s", mp->app);
  u32 rule_count = clib_net_to_host_u32 (mp->l7_rule_count);
  u8 *rule_ptr = (u8 *) & mp->l7_rules[0];
  u32 *ids = vec_new (u32, rule_count);
  u32 *regex_lengths = vec_new (u32, rule_count);
  u8 **regexes = vec_new (u8 *, rule_count);

  for (u32 n = 0; n < rule_count; n++)
    {
      vl_api_upf_l7_rule_t *rule = (vl_api_upf_l7_rule_t *) rule_ptr;
      u32 regex_length = clib_net_to_host_u32 (rule->regex_length);
      ids[n] = clib_net_to_host_u32 (rule->id);
      regex_lengths[n] = regex_length;
      regexes[n] = rule->regex;
      // the regex field in vl_api_upf_l7_rule_t is defined as 'u8 regex[0]'
      rule_ptr += sizeof (vl_api_upf_l7_rule_t) + regex_length;
    }

  rv = upf_update_app (sm, app_name, rule_count, ids, regex_lengths, regexes);

  vec_free (ids);
  vec_free (regex_lengths);
  vec_free (regexes);

  REPLY_MACRO (VL_API_UPF_UPDATE_APP_REPLY);
}

#include <upf/upf.api.c>

static clib_error_t *
upf_api_hookup (vlib_main_t * vm)
{
  upf_main_t *gtm = &upf_main;

  gtm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (upf_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
