/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * pppox_api.c - pppox api (stub for VPP v26)
 *
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <string.h>
#include <vlibapi/api_helper_macros.h>

#include <pppox/pppox.h>

#define vl_msg_id(n, h) n,
typedef enum
{
#include <pppox/pppox.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <pppox/pppox.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <pppox/pppox.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <pppox/pppox.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <pppox/pppox.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <pppox/pppox.api.h>
#undef vl_msg_name_crc_list

// #define REPLY_MSG_ID_BASE pom->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void __attribute__ ((unused)) setup_message_id_table (pppox_main_t *pom, api_main_t *am)
{
#define _(id, n, crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + pom->msg_id_base);
  foreach_vl_msg_name_crc_pppox;
#undef _
}

#define foreach_pppox_plugin_api_msg _ (PPPOX_SET_AUTH, pppox_set_auth)

static int
pppox_api_string_field_to_vec (u8 **dst, const u8 *src, size_t src_size)
{
  size_t len = strnlen ((const char *) src, src_size);

  if (len == src_size)
    return VNET_API_ERROR_INVALID_VALUE;

  vec_validate (*dst, len);
  clib_memcpy (*dst, src, len);
  (*dst)[len] = 0;

  return 0;
}

static void __attribute__ ((unused)) vl_api_pppox_set_auth_t_handler (vl_api_pppox_set_auth_t *mp)
{
  vl_api_pppox_set_auth_reply_t *rmp;
  int rv = 0;
  CLIB_UNUSED (pppox_main_t * pom) = &pppox_main;
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

static clib_error_t *
pppox_api_hookup (vlib_main_t *vm)
{
  CLIB_UNUSED (pppox_main_t * pom) = &pppox_main;

  u8 *name = format (0, "pppox_%08x%c", api_version, 0);
  pom->msg_id_base = vl_msg_api_get_msg_ids ((char *) name, VL_MSG_FIRST_AVAILABLE);

  /* API handlers stubbed out for VPP v26 compatibility */
  /* The pppox plugin works without API registration */

  /* setup_message_id_table disabled */;

  return 0;
}

VLIB_API_INIT_FUNCTION (pppox_api_hookup);

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
