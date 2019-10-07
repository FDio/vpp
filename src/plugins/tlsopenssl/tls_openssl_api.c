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
#include <tlsopenssl/tls_openssl.api_enum.h>
#include <tlsopenssl/tls_openssl.api_types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#define REPLY_MSG_ID_BASE om->msg_id_base
#include <vlibapi/api_helper_macros.h>

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

#include <tlsopenssl/tls_openssl.api.c>
clib_error_t *
tls_openssl_api_init (vlib_main_t * vm)
{
  openssl_main_t *om = &openssl_main;

  /* Ask for a correctly-sized block of API message decode slots */
  om->msg_id_base = setup_message_id_table ();

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
