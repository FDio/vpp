/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * pppox_api.c - pppox api
 *
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>

#include <vppinfra/byte_order.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <string.h>

#include <pppoeclient/pppox/pppox.h>
#include <pppoeclient/pppox/pppox.api_enum.h>
#include <pppoeclient/pppox/pppox.api_types.h>

#define REPLY_MSG_ID_BASE (pom->msg_id_base)
#include <vlibapi/api_helper_macros.h>

static int
pppox_api_string_field_to_vec (u8 **dst, const u8 *src, size_t src_size)
{
  size_t len = strnlen ((const char *) src, src_size);

  vec_validate (*dst, len);
  clib_memcpy (*dst, src, len);
  (*dst)[len] = 0;

  return 0;
}

static void
vl_api_pppox_set_auth_t_handler (vl_api_pppox_set_auth_t *mp)
{
  vl_api_pppox_set_auth_reply_t *rmp;
  int rv = 0;
  pppox_main_t *pom = &pppox_main;
  u8 *username = 0, *password = 0;

  rv = pppox_api_string_field_to_vec (&username, mp->username, sizeof (mp->username));
  if (rv)
    goto out;

  rv = pppox_api_string_field_to_vec (&password, mp->password, sizeof (mp->password));
  if (rv)
    goto out;

  rv = pppox_set_auth (ntohl (mp->sw_if_index), username, password);

out:
  vec_free (username);
  vec_free (password);

  REPLY_MACRO (VL_API_PPPOX_SET_AUTH_REPLY);
}

/* set up the API message handling tables */
#include <pppoeclient/pppox/pppox.api.c>

static clib_error_t *
pppox_api_hookup (vlib_main_t *vm)
{
  pppox_main_t *pom = &pppox_main;
  CLIB_UNUSED (api_main_t * am) = vlibapi_get_main ();

  pom->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (pppox_api_hookup);

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
