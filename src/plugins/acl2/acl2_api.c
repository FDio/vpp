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
#include <acl2/acl2.h>
#include <vnet/match/match_set.h>
#include <vnet/match/match_types_api.h>
#include <vnet/interface_types_api.h>
#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <acl2/acl2.api_enum.h>
#include <acl2/acl2.api_types.h>

static u32 acl2_base_msg_id;

#define REPLY_MSG_ID_BASE acl2_base_msg_id

#include <vlibapi/api_helper_macros.h>


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Access Control Lists 2 (ACL)",
};
/* *INDENT-ON* */

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
acl2_action_decode (vl_api_acl2_action_t action, acl2_action_t * out)
{
  switch (action)
    {
#define _(a,b)                                   \
      case ACL2_API_ACTION_##a:                  \
        *out = ACL2_ACTION_##a;                  \
        return (0);
      foreach_acl2_action
#undef _
    }

  return (1);
}

static int
acl2_ace_decode (const vl_api_ace2_t * in, index_t * acei)
{
  ace2_t tmp, *ace;
  int rv;

  rv = acl2_action_decode (in->action, &tmp.ace_action);
  rv |= match_rule_decode (&in->rule, &tmp.ace_rule);

  if (!rv)
    {
      pool_get (acl2_main.ace_pool, ace);
      clib_memcpy (ace, &tmp, sizeof (tmp));
      *acei = ace - acl2_main.ace_pool;
    }

  return (rv);
}

typedef struct acl2_update_ctx_t_
{
  vl_api_acl2_update_reply_t *rmp;
  u32 index;
} acl2_update_ctx_t;

static walk_rc_t
acl2_update_walk (index_t acl, index_t ace, void *arg)
{
  acl2_update_ctx_t *ctx = arg;

  ctx->rmp->ace_indices[ctx->index++] = clib_host_to_net_u32 (ace);

  return (WALK_CONTINUE);
}

/* API message handler */
static void
vl_api_acl2_update_t_handler (vl_api_acl2_update_t * mp)
{
  u32 acl_index, n_aces, expected_len;
  vl_api_acl2_update_reply_t *rmp;
  int rv = 0;

  acl_index = ntohl (mp->acl_index);
  n_aces = ntohl (mp->n_aces);
  expected_len = sizeof (*mp) + n_aces * sizeof (mp->aces[0]);

  if (verify_message_len (mp, expected_len, "acl2_update"))
    {
      index_t *aces = NULL;
      u32 ii;

      vec_validate (aces, n_aces - 1);

      for (ii = 0; ii < n_aces; ii++)
	rv |= acl2_ace_decode (&mp->aces[ii], &aces[ii]);

      if (!rv)
	rv = acl2_update (&acl_index, aces, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO3(VL_API_ACL2_UPDATE_REPLY,
               sizeof(u32) * n_aces,
  ({
    rmp->acl_index = htonl(acl_index);
    rmp->n_aces = htonl(n_aces);

    acl2_update_ctx_t ctx = {
      .rmp = rmp,
      .index = 0,
    };

    acl2_walk (acl_index, acl2_update_walk, &ctx);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_acl2_del_t_handler (vl_api_acl2_del_t * mp)
{
  vl_api_acl2_del_reply_t *rmp;
  int rv;

  rv = acl2_del (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_ACL2_DEL_REPLY);
}

static void
vl_api_acl2_stats_enable_t_handler (vl_api_acl2_stats_enable_t * mp)
{
  vl_api_acl2_stats_enable_reply_t *rmp;
  int rv;

  rv = acl2_stats_update (mp->enable);

  REPLY_MACRO (VL_API_ACL2_DEL_REPLY);
}

static void
vl_api_acl2_bind_t_handler (vl_api_acl2_bind_t * mp)
{
  vl_api_acl2_bind_reply_t *rmp;
  int rv = 0;
  int i;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vlib_dir_t dir;

  VALIDATE_SW_IF_INDEX (mp);

  for (i = 0; i < mp->count; i++)
    {
      if (!acl2_is_valid (ntohl (mp->acls[i])))
	{
	  /* ACL does not exist, so we can not apply it */
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	}
    }

  rv = direction_decode (mp->dir, &dir);

  if (0 == rv)
    {
      u32 *acl_vec = 0;

      for (i = 0; i < mp->count; i++)
	vec_add1 (acl_vec, clib_net_to_host_u32 (mp->acls[i]));

      rv = acl2_bind (sw_if_index, dir, acl_vec);
      vec_free (acl_vec);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_ACL2_BIND_REPLY);
}

vl_api_acl2_action_t
acl2_action_encode (acl2_action_t in)
{
  return ((vl_api_acl2_action_t) in);
}

static void
acl2_ace_encode (const ace2_t * in, vl_api_ace2_t * out)
{
  out->action = acl2_action_encode (in->ace_action);
  match_rule_encode (&in->ace_rule, &out->rule);
}

static void
acl2_send_details (acl2_main_t * am,
		   vl_api_registration_t * reg, acl2_t * acl, u32 context)
{
  vl_api_acl2_details_t *mp;
  u32 n_aces, msg_size;
  vl_api_ace2_t *vace;
  index_t *acei;

  n_aces = vec_len (acl->acl_aces);
  msg_size = sizeof (*mp) + sizeof (mp->aces[0]) * n_aces;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_ACL2_DETAILS + REPLY_MSG_ID_BASE);

  /* fill in the message */
  mp->context = context;
  mp->count = htonl (n_aces);
  mp->acl_index = htonl (acl - am->acl_pool);
  memcpy (mp->tag, acl->acl_tag, sizeof (mp->tag));

  vace = mp->aces;
  vec_foreach (acei, acl->acl_aces)
  {
    acl2_ace_encode (ace2_get (*acei), vace);
    vace++;
  }

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_acl2_dump_t_handler (vl_api_acl2_dump_t * mp)
{
  acl2_main_t *am = &acl2_main;
  u32 acl_index;
  acl2_t *acl;
  int rv = -1;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->acl_index == ~0)
    {
    /* *INDENT-OFF* */
    /* Just dump all ACLs */
    pool_foreach (acl, am->acl_pool,
    ({
      acl2_send_details(am, reg, acl, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (am->acl_pool, acl_index))
	{
	  acl = pool_elt_at_index (am->acl_pool, acl_index);
	  acl2_send_details (am, reg, acl, mp->context);
	}
    }

  if (rv == -1)
    {
      /* FIXME API: should we signal an error here at all ? */
      return;
    }
}

static void
acl2_bind_send_details (acl2_main_t * am,
			vl_api_registration_t * reg,
			u32 context, const acl2_itf_t * aitf)
{
  vl_api_acl2_bind_details_t *mp;
  int i, msg_size, count;

  if (NULL == aitf)
    return;

  count = vec_len (aitf->acls);

  msg_size = sizeof (*mp);
  msg_size += sizeof (mp->acls[0]) * count;

  mp = vl_msg_api_alloc (msg_size);
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_ACL2_BIND_DETAILS + REPLY_MSG_ID_BASE);

  /* fill in the message */
  mp->context = context;
  mp->sw_if_index = htonl (aitf->sw_if_index);
  mp->count = count;
  mp->dir = direction_encode (aitf->dir);

  for (i = 0; i < count; i++)
    mp->acls[i] = htonl (aitf->acls[i].acl_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_acl2_bind_dump_t_handler (vl_api_acl2_bind_dump_t * mp)
{
  acl2_main_t *am = &acl2_main;
  vl_api_registration_t *reg;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->sw_if_index == ~0)
    {
      acl2_itf_t *aitf;
      /* *INDENT-OFF* */
      pool_foreach (aitf, am->itf_pool,
      ({
        acl2_bind_send_details(am, reg, mp->context, aitf);
      }));
    /* *INDENT-ON* */
    }
  else
    {
      sw_if_index = ntohl (mp->sw_if_index);

      acl2_bind_send_details (am, reg, mp->context,
			      acl2_itf_find (sw_if_index, VLIB_RX));
      acl2_bind_send_details (am, reg, mp->context,
			      acl2_itf_find (sw_if_index, VLIB_TX));
    }
}


/* Set up the API message handling tables */
#include <vnet/format_fns.h>
#include <acl2/acl2.api.c>

static clib_error_t *
acl2_api_init (vlib_main_t * vm)
{
  acl2_main_t *am = &acl2_main;
  clib_error_t *error = 0;

  am->log_default = vlib_log_register_class ("acl2", 0);

  /* Ask for a correctly-sized block of API message decode slots */
  acl2_base_msg_id = setup_message_id_table ();

  return error;
}

VLIB_INIT_FUNCTION (acl2_api_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
