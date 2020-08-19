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
#include <capo/capo.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <acl/public_inlines.h>


#define REPLY_MSG_ID_BASE cpm->msg_id_base
#include <vlibapi/api_helper_macros.h>


#define CALICO_POLICY_VERSION_MAJOR 0
#define CALICO_POLICY_VERSION_MINOR 0


capo_main_t capo_main;


static void
vl_api_capo_get_version_t_handler (vl_api_capo_get_version_t * mp)
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
vl_api_capo_control_ping_t_handler (vl_api_capo_control_ping_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_control_ping_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid ());
  }));
  /* *INDENT-ON* */
}

/* NAME: ipset_create */
static void
vl_api_capo_ipset_create_t_handler (vl_api_capo_ipset_create_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_ipset_create_reply_t *rmp;
  int rv = 0;
  u32 id = capo_ipset_create ((capo_ipset_type_t) mp->type);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_IPSET_CREATE_REPLY,
  ({
      rmp->set_id = clib_host_to_net_u32 (id);
  }));
  /* *INDENT-ON* */
}

/* NAME: ipset_add_del_members */
static void
  vl_api_capo_ipset_add_del_members_t_handler
  (vl_api_capo_ipset_add_del_members_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_ipset_add_del_members_reply_t *rmp;
  int rv = 0;

  for (u32 i = 0; i < mp->len; i++)
    {
      capo_ipset_member_t m;
      rv = capo_ipset_member_from_api (mp->set_id, &mp->members[i], &m);
      if (rv)
	break;
      if (mp->is_add)
	rv = capo_ipset_add_member (mp->set_id, &m);
      else
	rv = capo_ipset_del_member (mp->set_id, &m);
      if (rv)
	break;
    }

  REPLY_MACRO (VL_API_CAPO_IPSET_ADD_DEL_MEMBERS_REPLY);
}

/* NAME: ipset_delete */
static void
vl_api_capo_ipset_delete_t_handler (vl_api_capo_ipset_delete_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_ipset_delete_reply_t *rmp;
  int rv = capo_ipset_delete (clib_net_to_host_u32 (mp->set_id));
  REPLY_MACRO (VL_API_CAPO_IPSET_DELETE_REPLY);
}

/* NAME: rule_create */
static void
vl_api_capo_rule_create_t_handler (vl_api_capo_rule_create_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_rule_create_reply_t *rmp;
  int rv = -1;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_RULE_CREATE_REPLY,
  ({
      /* FIXME: do something here */
  }));
  /* *INDENT-ON* */
}

/* NAME: rule_update */
static void
vl_api_capo_rule_update_t_handler (vl_api_capo_rule_update_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_rule_update_reply_t *rmp;
  int rv = -1;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_RULE_UPDATE_REPLY,
  ({
      /* FIXME: do something here */
  }));
  /* *INDENT-ON* */


}

/* NAME: rule_delete */
static void
vl_api_capo_rule_delete_t_handler (vl_api_capo_rule_delete_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_rule_delete_reply_t *rmp;
  int rv = -1;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_RULE_DELETE_REPLY,
  ({
      /* FIXME: do something here */
  }));
  /* *INDENT-ON* */


}

/* NAME: policy_create */
static void
vl_api_capo_policy_create_t_handler (vl_api_capo_policy_create_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_policy_create_reply_t *rmp;
  int rv = -1;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_POLICY_CREATE_REPLY,
  ({
      /* FIXME: do something here */
  }));
  /* *INDENT-ON* */


}

/* NAME: policy_update */
static void
vl_api_capo_policy_update_t_handler (vl_api_capo_policy_update_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_policy_update_reply_t *rmp;
  int rv = -1;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_POLICY_UPDATE_REPLY,
  ({
      /* FIXME: do something here */
  }));
  /* *INDENT-ON* */


}

/* NAME: policy_delete */
static void
vl_api_capo_policy_delete_t_handler (vl_api_capo_policy_delete_t * mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_policy_delete_reply_t *rmp;
  int rv = -1;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_POLICY_DELETE_REPLY,
  ({
      /* FIXME: do something here */
  }));
  /* *INDENT-ON* */


}

/* NAME: configure_policies */
static void
vl_api_capo_configure_policies_t_handler (vl_api_capo_configure_policies_t *
					  mp)
{
  capo_main_t *cpm = &capo_main;
  vl_api_capo_configure_policies_reply_t *rmp;
  int rv = -1;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_CAPO_CONFIGURE_POLICIES_REPLY,
  ({
      /* FIXME: do something here */
  }));
  /* *INDENT-ON* */


}

/* Set up the API message handling tables */
#include <vnet/format_fns.h>
#include <capo/capo.api.c>

static u32 calico_acl_user_id;
static acl_plugin_methods_t acl_plugin;


static clib_error_t *
calpol_init (vlib_main_t * vm)
{
  clib_error_t *acl_init_res = acl_plugin_exports_init (&acl_plugin);
  capo_main_t *cpm = &capo_main;
  if (acl_init_res)
    return (acl_init_res);

  calico_acl_user_id =
    acl_plugin.register_user_module ("Calico Policy Plugin", NULL, NULL);

  cpm->msg_id_base = setup_message_id_table ();

  return (NULL);
}

static clib_error_t *
calpol_plugin_config (vlib_main_t * vm, unformat_input_t * input)
{
  return NULL;
}


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Calico Policy",
};
/* *INDENT-ON* */


VLIB_CONFIG_FUNCTION (calpol_plugin_config, "calico-policy-plugin");

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (calpol_init) =
{
  .runs_after = VLIB_INITS("acl_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
