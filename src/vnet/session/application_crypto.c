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
  /* Avoid need for locks when used by workers */
  vec_validate (ckpair->cki, vlib_num_workers ());
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

static app_crypto_ca_trust_t *
app_crypto_alloc_ca_trust (application_t *app)
{
  app_crypto_ca_trust_t *ca_trust;

  /* first element not used */
  if (!pool_elts (app->crypto_ctx.ca_trust_stores))
    pool_get_zero (app->crypto_ctx.ca_trust_stores, ca_trust);
  pool_get_zero (app->crypto_ctx.ca_trust_stores, ca_trust);
  ca_trust->ca_trust_index = ca_trust - app->crypto_ctx.ca_trust_stores;
  /* Avoid need for locks when used by workers */
  vec_validate (ca_trust->cti, vlib_num_workers ());

  return ca_trust;
}

int
app_crypto_add_ca_trust (u32 app_index, app_ca_trust_add_args_t *args)
{
  application_t *app;
  app_crypto_ca_trust_t *ca_trust;

  app = application_get (app_index);
  ca_trust = app_crypto_alloc_ca_trust (app);
  ca_trust->ca_chain = args->ca_chain;
  ca_trust->crl = args->crl;
  args->index = ca_trust->ca_trust_index;

  return 0;
}

app_crypto_ca_trust_t *
app_crypto_get_wrk_ca_trust (u32 app_wrk_index, u32 ca_trust_index)
{
  app_worker_t *app_wrk;
  application_t *app;

  app_wrk = app_worker_get (app_wrk_index);
  app = application_get (app_wrk->app_index);

  return app_get_crypto_ca_trust (app, ca_trust_index);
}

app_crypto_ca_trust_int_ctx_t *
app_crypto_alloc_int_ca_trust (app_crypto_ca_trust_t *ct,
			       clib_thread_index_t thread_index)
{
  return vec_elt_at_index (ct->cti, thread_index);
}

app_crypto_ca_trust_int_ctx_t *
app_crypto_get_int_ca_trust (app_crypto_ca_trust_t *ct,
			     clib_thread_index_t thread_index)
{
  if (vec_len (ct->cti) <= thread_index)
    return 0;
  return vec_elt_at_index (ct->cti, thread_index);
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

static void
app_certkey_free_int_ctx (app_cert_key_pair_t *ck)
{
  app_certkey_int_ctx_t *cki;

  vec_foreach (cki, ck->cki)
    {
      if (cki->cleanup_cb)
	(cki->cleanup_cb) (cki);
      cki->cert = 0;
      cki->key = 0;
    }
  vec_free (ck->cki);
}

int
vnet_app_del_cert_key_pair (u32 index)
{
  app_cert_key_pair_t *ckpair;
  application_t *app;
  u32 *app_index;

  if (!(ckpair = app_cert_key_pair_get_if_valid (index)))
    return SESSION_E_INVALID;

  app_certkey_free_int_ctx (ckpair);

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

app_crypto_async_req_ticket_t
app_crypto_async_req (app_crypto_async_req_t *areq)
{
  app_crypto_async_req_t *req;
  app_crypto_wrk_t *crypto_wrk;
  app_worker_t *app_wrk;
  application_t *app;
  app_crypto_async_req_ticket_t ticket;

  app_wrk = app_worker_get (areq->app_wrk_index);
  app = application_get (app_wrk->app_index);
  if (!app->cb_fns.app_crypto_async)
    return APP_CRYPTO_ASYNC_INVALID_TICKET;

  crypto_wrk = app_crypto_wrk_get (app, areq->handle.thread_index);

  /* TODO(fcoras) caching layer */

  pool_get (crypto_wrk->reqs, req);
  *req = *areq;
  req->req_index = req - crypto_wrk->reqs;
  req->cancelled = 0;
  ticket.app_index = app->app_index;
  ticket.req_index = req->req_index;

  /* Hand over request to app */
  if (app->cb_fns.app_crypto_async (req))
    return APP_CRYPTO_ASYNC_INVALID_TICKET;

  return ticket;
}

void
app_crypto_async_cancel_req (app_crypto_async_req_ticket_t ticket)
{
  application_t *app = application_get (ticket.app_index);
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  app_crypto_async_req_t *req;
  app_crypto_wrk_t *crypto_wrk;

  crypto_wrk = app_crypto_wrk_get (app, thread_index);

  if (pool_is_free_index (crypto_wrk->reqs, ticket.req_index))
    return;
  req = pool_elt_at_index (crypto_wrk->reqs, ticket.req_index);
  req->cancelled = 1;
}

void
app_crypto_async_reply (app_crypto_async_reply_t *reply)
{
  application_t *app = application_get (reply->app_index);
  clib_thread_index_t thread_index = reply->handle.thread_index;
  app_crypto_wrk_t *crypto_wrk;
  app_crypto_async_req_t *req;

  ASSERT (thread_index == vlib_get_thread_index ());

  crypto_wrk = app_crypto_wrk_get (app, thread_index);
  req = pool_elt_at_index (crypto_wrk->reqs, reply->req_index);

  if (req->cancelled)
    goto done;

  reply->handle = req->handle;
  req->cb (reply);

done:
  pool_put (crypto_wrk->reqs, req);
}

void
app_crypto_ctx_init (app_crypto_ctx_t *crypto_ctx)
{
  vec_validate (crypto_ctx->wrk, vlib_num_workers ());
}

static void
app_crypto_ca_stores_cleanup (app_crypto_ca_trust_t *ca_stores)
{
  app_crypto_ca_trust_int_ctx_t *cti;
  app_crypto_ca_trust_t *ct;

  pool_foreach (ct, ca_stores)
    {
      vec_foreach (cti, ct->cti)
	{
	  if (cti->cleanup_cb)
	    (cti->cleanup_cb) (cti);
	  cti->ca_store = 0;
	}
      vec_free (ct->cti);
      vec_free (ct->ca_chain);
      vec_free (ct->crl);
    }
}

void
app_crypto_ctx_free (app_crypto_ctx_t *crypto_ctx)
{
  app_crypto_wrk_t *crypto_wrk;

  if (crypto_ctx->ca_trust_stores)
    {
      app_crypto_ca_stores_cleanup (crypto_ctx->ca_trust_stores);
      pool_free (crypto_ctx->ca_trust_stores);
    }

  vec_foreach (crypto_wrk, crypto_ctx->wrk)
    pool_free (crypto_wrk->reqs);
  vec_free (crypto_ctx->wrk);
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

  /* Index 0 is invalid, used to indicate that no cert was provided */
  app_cert_key_pair_alloc ();

  acm->last_crypto_engine = CRYPTO_ENGINE_LAST;
  return 0;
}