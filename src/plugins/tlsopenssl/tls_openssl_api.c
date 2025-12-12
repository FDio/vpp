/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <tlsopenssl/tls_openssl.h>

/* define message IDs */
#include <tlsopenssl/tls_openssl.api_enum.h>
#include <tlsopenssl/tls_openssl.api_types.h>


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

  ciphers = (char *) &mp->ciphers;
  ciphers[63] = '\0';
  if (ciphers[0])
    tls_openssl_set_ciphers (ciphers);

  engine = (char *) mp->engine;
  engine[63] = '\0';
  alg = (char *) mp->algorithm;
  alg[63] = '\0';
  rv = openssl_engine_register (engine, alg, mp->async_enable);
  om->async = mp->async_enable;

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
