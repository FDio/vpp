/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <tlsopenssl/tls_openssl.h>

/* define message IDs */
#include <tlsopenssl/tls_openssl_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <tlsopenssl/tls_openssl_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <tlsopenssl/tls_openssl_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <tlsopenssl/tls_openssl_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include <tlsopenssl/tls_openssl_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE om->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_tls_openssl_plugin_api_msg \
  _ (TLS_OPENSSL_SET_ENGINE, tls_openssl_set_engine)

extern openssl_main_t openssl_main;

/* API message handler */
static void
vl_api_tls_openssl_set_engine_t_handler (vl_api_tls_openssl_set_engine_t * mp)
{
  vl_api_tls_openssl_set_engine_reply_t *rmp;
  openssl_main_t *om = &openssl_main;
  char *engine, *alg;
  char *ciphers;
  int rv;

  if (mp->async_enable)
    {
      om->async = 1;
      openssl_async_node_enable_disable (1);
    }

  ciphers = (char *) &mp->ciphers;
  ciphers[63] = '\0';
  if (ciphers[0])
    tls_openssl_set_ciphers (ciphers);

  engine = (char *) mp->engine;
  engine[63] = '\0';
  alg = (char *) mp->algorithm;
  alg[63] = '\0';
  rv = openssl_engine_register (engine, alg);

  REPLY_MACRO (VL_API_TLS_OPENSSL_SET_ENGINE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
tls_openssl_plugin_api_hookup (vlib_main_t * vm)
{
  openssl_main_t *om = &openssl_main;
#define _(N, n)                                                         \
  vl_msg_api_set_handlers ((VL_API_##N + om->msg_id_base), #n,          \
                           vl_api_##n##_t_handler, vl_noop_handler,     \
                           vl_api_##n##_t_endian, vl_api_##n##_t_print, \
                           sizeof (vl_api_##n##_t), 1);
  foreach_tls_openssl_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <tlsopenssl/tls_openssl_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (openssl_main_t * om, api_main_t * am)
{
#define _(id, n, crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + om->msg_id_base);
  foreach_vl_msg_name_crc_tls_openssl;
#undef _
}

clib_error_t *
tls_openssl_api_init (vlib_main_t * vm)
{
  openssl_main_t *om = &openssl_main;
  clib_error_t *error = 0;
  u8 *name;

  name = format (0, "tls_openssl_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  om->msg_id_base =
    vl_msg_api_get_msg_ids ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = tls_openssl_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (om, &api_main);
  vec_free (name);

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
