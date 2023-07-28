/*
 *------------------------------------------------------------------
 * punt_api.c - Punt api
 *
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/ip/punt.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <vnet/ip/punt.api_enum.h>
#include <vnet/ip/punt.api_types.h>

#define REPLY_MSG_ID_BASE punt_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static int
vl_api_punt_type_decode (vl_api_punt_type_t in, punt_type_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
#define _(v, s)                                 \
      case PUNT_API_TYPE_##v:                   \
        *out = PUNT_TYPE_##v;                   \
        return (0);
      foreach_punt_type
#undef _
    }

  return (-1);
}

static vl_api_punt_type_t
vl_api_punt_type_encode (punt_type_t in)
{
  vl_api_punt_type_t pt = PUNT_API_TYPE_L4;

  switch (in)
    {
#define _(v, s)                                   \
      case PUNT_TYPE_##v:                         \
        pt = PUNT_API_TYPE_##v;                   \
        break;
      foreach_punt_type
#undef _
    }

  return (clib_host_to_net_u32 (pt));
}

static int
vl_api_punt_l4_decode (const vl_api_punt_l4_t * in, punt_l4_t * out)
{
  int rv;

  rv = ip_address_family_decode (in->af, &out->af);
  if (rv < 0)
    return (rv);
  rv = ip_proto_decode (in->protocol, &out->protocol);
  if (rv < 0)
    return (rv);
  out->port = clib_net_to_host_u16 (in->port);

  return (rv);
}

static int
vl_api_punt_ip_proto_decode (const vl_api_punt_ip_proto_t * in,
			     punt_ip_proto_t * out)
{
  int rv;

  rv = ip_address_family_decode (in->af, &out->af);
  if (rv < 0)
    return (rv);
  rv = ip_proto_decode (in->protocol, &out->protocol);

  return (rv);
}

static int
vl_api_punt_exception_decode (const vl_api_punt_exception_t * in,
			      punt_exception_t * out)
{
  int rv;

  out->reason = clib_net_to_host_u32 (in->id);
  rv = vlib_punt_reason_validate (out->reason);

  return (rv);
}

static int
vl_api_punt_decode (const vl_api_punt_t * in, punt_reg_t * out)
{
  int rv;

  rv = vl_api_punt_type_decode (in->type, &out->type);

  if (rv)
    return (rv);

  switch (out->type)
    {
    case PUNT_TYPE_L4:
      return (vl_api_punt_l4_decode (&in->punt.l4, &out->punt.l4));
    case PUNT_TYPE_EXCEPTION:
      return (vl_api_punt_exception_decode (&in->punt.exception,
					    &out->punt.exception));
    case PUNT_TYPE_IP_PROTO:
      return (vl_api_punt_ip_proto_decode (&in->punt.ip_proto,
					   &out->punt.ip_proto));
    }

  return (-1);
}

static void
vl_api_punt_l4_encode (const punt_l4_t * in, vl_api_punt_l4_t * out)
{
  out->af = ip_address_family_encode (in->af);
  out->protocol = ip_proto_encode (in->protocol);
  out->port = clib_net_to_host_u16 (in->port);
}

static void
vl_api_punt_ip_proto_encode (const punt_ip_proto_t * in,
			     vl_api_punt_ip_proto_t * out)
{
  out->af = ip_address_family_encode (in->af);
  out->protocol = ip_proto_encode (in->protocol);
}

static void
vl_api_punt_exception_encode (const punt_exception_t * in,
			      vl_api_punt_exception_t * out)
{
  out->id = clib_host_to_net_u32 (in->reason);
}

static void
vl_api_punt_encode (const punt_reg_t * in, vl_api_punt_t * out)
{
  out->type = vl_api_punt_type_encode (in->type);

  switch (in->type)
    {
    case PUNT_TYPE_L4:
      vl_api_punt_l4_encode (&in->punt.l4, &out->punt.l4);
      break;
    case PUNT_TYPE_IP_PROTO:
      vl_api_punt_ip_proto_encode (&in->punt.ip_proto, &out->punt.ip_proto);
      break;
    case PUNT_TYPE_EXCEPTION:
      vl_api_punt_exception_encode (&in->punt.exception,
				    &out->punt.exception);
      break;
    }
}

static void
vl_api_set_punt_t_handler (vl_api_set_punt_t * mp)
{
  vl_api_set_punt_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  punt_reg_t pr;
  int rv;

  rv = vl_api_punt_decode (&mp->punt, &pr);

  if (rv)
    goto out;

  error = vnet_punt_add_del (vm, &pr, mp->is_add);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

out:
  REPLY_MACRO (VL_API_SET_PUNT_REPLY);
}

static void
vl_api_punt_socket_register_t_handler (vl_api_punt_socket_register_t * mp)
{
  vl_api_punt_socket_register_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  punt_reg_t pr;
  int rv;

  rv = vl_api_punt_decode (&mp->punt, &pr);

  if (rv)
    return;

  error = vnet_punt_socket_add (vm, ntohl (mp->header_version),
				&pr, (char *) mp->pathname);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  char *p = vnet_punt_get_server_pathname ();

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_PUNT_SOCKET_REGISTER_REPLY,
  ({
    memcpy ((char *) rmp->pathname, p, sizeof (rmp->pathname));
  }));
  /* *INDENT-ON* */
}

typedef struct punt_socket_send_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} punt_socket_send_ctx_t;

static walk_rc_t
vl_api_punt_socket_send_details (const punt_client_t * pc, void *args)
{
  punt_socket_send_ctx_t *ctx = args;
  vl_api_punt_socket_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return (WALK_STOP);

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_PUNT_SOCKET_DETAILS);
  mp->context = ctx->context;
  vl_api_punt_encode (&pc->reg, &mp->punt);
  memcpy (mp->pathname, pc->caddr.sun_path, sizeof (pc->caddr.sun_path));

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_punt_socket_dump_t_handler (vl_api_punt_socket_dump_t * mp)
{
  vl_api_registration_t *reg;
  punt_type_t pt;

  if (0 != vl_api_punt_type_decode (mp->type, &pt))
    return;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  punt_socket_send_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  punt_client_walk (pt, vl_api_punt_socket_send_details, &ctx);
}

static void
vl_api_punt_socket_deregister_t_handler (vl_api_punt_socket_deregister_t * mp)
{
  vl_api_punt_socket_deregister_reply_t *rmp;
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *error;
  punt_reg_t pr;
  int rv;

  rv = vl_api_punt_decode (&mp->punt, &pr);

  if (rv)
    goto out;

  error = vnet_punt_socket_del (vm, &pr);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

out:
  REPLY_MACRO (VL_API_PUNT_SOCKET_DEREGISTER_REPLY);
}

typedef struct punt_reason_dump_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
  u8 *name;
} punt_reason_dump_walk_ctx_t;

static int
punt_reason_dump_walk_cb (vlib_punt_reason_t id, const u8 * name, void *args)
{
  punt_reason_dump_walk_ctx_t *ctx = args;
  vl_api_punt_reason_details_t *mp;

  if (vec_len (ctx->name) > 0)
    {
      /* user requested a specific punt-reason */
      if (vec_cmp (name, ctx->name))
	/* not the reason we're looking for */
	return 1;
    }

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return (0);

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_PUNT_REASON_DETAILS);

  mp->context = ctx->context;
  mp->reason.id = clib_host_to_net_u32 (id);
  strncpy ((char *) mp->reason.name, (char *) name,
	   ARRAY_LEN (mp->reason.name) - 1);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
}

static void
vl_api_punt_reason_dump_t_handler (vl_api_punt_reason_dump_t * mp)
{
  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  punt_reason_dump_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
    .name = format (0, "%s", mp->reason.name),
  };

  punt_reason_walk (punt_reason_dump_walk_cb, &ctx);

  vec_free (ctx.name);
}

#include <vnet/ip/punt.api.c>

static clib_error_t *
punt_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (punt_api_hookup);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
