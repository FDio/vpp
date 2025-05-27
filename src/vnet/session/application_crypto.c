/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

typedef struct app_crypto_main_
{
  crypto_engine_type_t last_crypto_engine;  /* Last crypto engine type used */
  app_cert_key_pair_t *cert_key_pair_store; /* Pool of cert/key pairs */
} app_crypto_main_t;

static app_crypto_main_t app_crypto_main;

static app_cert_key_pair_t *
app_cert_key_pair_alloc ()
{
  app_cert_key_pair_t *ckpair;
  pool_get (app_crypto_main.cert_key_pair_store, ckpair);
  clib_memset (ckpair, 0, sizeof (*ckpair));
  ckpair->cert_key_index = ckpair - app_crypto_main.cert_key_pair_store;
  return ckpair;
}

app_cert_key_pair_t *
app_cert_key_pair_get (u32 index)
{
  return pool_elt_at_index (app_crypto_main.cert_key_pair_store, index);
}

app_cert_key_pair_t *
app_cert_key_pair_get_if_valid (u32 index)
{
  if (pool_is_free_index (app_crypto_main.cert_key_pair_store, index))
    return 0;
  return app_cert_key_pair_get (index);
}

app_cert_key_pair_t *
app_cert_key_pair_get_default ()
{
  /* To maintain legacy bapi */
  return app_cert_key_pair_get (0);
}

int
vnet_app_add_cert_key_pair (vnet_app_add_cert_key_pair_args_t *a)
{
  app_cert_key_pair_t *ckpair = app_cert_key_pair_alloc ();
  vec_validate (ckpair->cert, a->cert_len - 1);
  clib_memcpy_fast (ckpair->cert, a->cert, a->cert_len);
  vec_validate (ckpair->key, a->key_len - 1);
  clib_memcpy_fast (ckpair->key, a->key, a->key_len);
  a->index = ckpair->cert_key_index;
  return 0;
}

int
vnet_app_add_cert_key_interest (u32 index, u32 app_index)
{
  app_cert_key_pair_t *ckpair;
  if (!(ckpair = app_cert_key_pair_get_if_valid (index)))
    return -1;
  if (vec_search (ckpair->app_interests, app_index) != ~0)
    vec_add1 (ckpair->app_interests, app_index);
  return 0;
}

int
vnet_app_del_cert_key_pair (u32 index)
{
  app_cert_key_pair_t *ckpair;
  application_t *app;
  u32 *app_index;

  if (!(ckpair = app_cert_key_pair_get_if_valid (index)))
    return SESSION_E_INVALID;

  vec_foreach (app_index, ckpair->app_interests)
    {
      if ((app = application_get_if_valid (*app_index)) &&
	  app->cb_fns.app_cert_key_pair_delete_callback)
	app->cb_fns.app_cert_key_pair_delete_callback (ckpair);
    }

  vec_free (ckpair->cert);
  vec_free (ckpair->key);
  pool_put (app_crypto_main.cert_key_pair_store, ckpair);
  return 0;
}

u8 *
format_cert_key_pair (u8 *s, va_list *args)
{
  app_cert_key_pair_t *ckpair = va_arg (*args, app_cert_key_pair_t *);
  int key_len = 0, cert_len = 0;
  cert_len = vec_len (ckpair->cert);
  key_len = vec_len (ckpair->key);
  if (ckpair->cert_key_index == 0)
    s = format (s, "DEFAULT (cert:%d, key:%d)", cert_len, key_len);
  else
    s = format (s, "%d (cert:%d, key:%d)", ckpair->cert_key_index, cert_len,
		key_len);
  return s;
}

static clib_error_t *
show_certificate_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  app_cert_key_pair_t *ckpair;
  session_cli_return_if_not_enabled ();

  pool_foreach (ckpair, app_crypto_main.cert_key_pair_store)
    {
      vlib_cli_output (vm, "%U", format_cert_key_pair, ckpair);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_certificate_command, static) = {
  .path = "show app certificate",
  .short_help = "list app certs and keys present in store",
  .function = show_certificate_command_fn,
};

crypto_engine_type_t
app_crypto_engine_type_add (void)
{
  return (++app_crypto_main.last_crypto_engine);
}

u8 *
format_crypto_engine (u8 *s, va_list *args)
{
  u32 engine = va_arg (*args, u32);
  switch (engine)
    {
    case CRYPTO_ENGINE_NONE:
      return format (s, "none");
    case CRYPTO_ENGINE_MBEDTLS:
      return format (s, "mbedtls");
    case CRYPTO_ENGINE_OPENSSL:
      return format (s, "openssl");
    case CRYPTO_ENGINE_PICOTLS:
      return format (s, "picotls");
    case CRYPTO_ENGINE_VPP:
      return format (s, "vpp");
    default:
      return format (s, "unknown engine");
    }
  return s;
}

uword
unformat_crypto_engine (unformat_input_t *input, va_list *args)
{
  u8 *a = va_arg (*args, u8 *);
  if (unformat (input, "mbedtls"))
    *a = CRYPTO_ENGINE_MBEDTLS;
  else if (unformat (input, "openssl"))
    *a = CRYPTO_ENGINE_OPENSSL;
  else if (unformat (input, "picotls"))
    *a = CRYPTO_ENGINE_PICOTLS;
  else if (unformat (input, "vpp"))
    *a = CRYPTO_ENGINE_VPP;
  else
    return 0;
  return 1;
}

u8
app_crypto_engine_n_types (void)
{
  return (app_crypto_main.last_crypto_engine + 1);
}

clib_error_t *
application_crypto_init ()
{
  app_crypto_main_t *acm = &app_crypto_main;

  /* Index 0 was originally used by legacy apis, maintain as invalid */
  app_cert_key_pair_alloc ();

  acm->last_crypto_engine = CRYPTO_ENGINE_LAST;
  return 0;
}

VLIB_INIT_FUNCTION (application_crypto_init);