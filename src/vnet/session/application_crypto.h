/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_SESSION_APPLICATION_CRYPTO_H_
#define SRC_VNET_SESSION_APPLICATION_CRYPTO_H_

#include <vppinfra/types.h>
#include <vppinfra/format.h>
#include <vnet/tls/tls_test.h>

struct app_certkey_int_;

typedef void (*app_certkey_cleanup_it_ctx_fn) (struct app_certkey_int_ *cki);

typedef struct app_certkey_int_
{
  void *cert;	    /**< cert of cert chain, possible format X509 */
  void *key;	    /**< key, possible format EVP_PKEY */
  u32 ckpair_index; /**< parent certkey */
  app_certkey_cleanup_it_ctx_fn cleanup_cb; /**< cleanup callback */
  clib_thread_index_t thread_index;
} app_certkey_int_ctx_t;

typedef struct certificate_
{
  u32 cert_key_index; /**< index in cert & key pool */
  u8 *key;	      /**< PEM encoded key */
  u8 *cert;	      /**< PEM encoded cert */
  app_certkey_int_ctx_t **cki; /**< per-thread and engine internal cert/key */
} app_cert_key_pair_t;

struct app_crypto_ca_trust_int_ctx_;

typedef void (*app_crypto_ca_cleanup_it_ctx_fn) (
  struct app_crypto_ca_trust_int_ctx_ *cti);

typedef struct app_crypto_ca_trust_int_ctx_
{
  void *ca_store; /**< trusted ca, possible format X509_STORE */
  app_crypto_ca_cleanup_it_ctx_fn cleanup_cb; /**< cleanup callback */
} app_crypto_ca_trust_int_ctx_t;

typedef struct app_crypto_ca_trust_
{
  u8 *ca_chain;			      /**< PEM encoded CA chain */
  u8 *crl;			      /**< PEM encoded CRL */
  u32 ca_trust_index;		      /**< index in the CA trust pool */
  app_crypto_ca_trust_int_ctx_t *cti; /**< per-thread internal ca trust */
} app_crypto_ca_trust_t;

typedef enum crypto_engine_type_
{
  CRYPTO_ENGINE_NONE,
  CRYPTO_ENGINE_OPENSSL,
  CRYPTO_ENGINE_PICOTLS,
  CRYPTO_ENGINE_VPP,
  CRYPTO_ENGINE_MBEDTLS,
  CRYPTO_ENGINE_LAST = CRYPTO_ENGINE_MBEDTLS,
} __clib_packed crypto_engine_type_t;

typedef struct _vnet_app_add_cert_key_pair_args_
{
  u8 *cert;
  u8 *key;
  u32 cert_len;
  u32 key_len;
  u32 index;
} vnet_app_add_cert_key_pair_args_t;

typedef struct app_ca_trust_add_args_
{
  u8 *ca_chain;
  u8 *crl;
  u32 index;
} app_ca_trust_add_args_t;

typedef union
{
  struct
  {
    u32 app_index;
    u32 req_index;
  };
  u64 as_u64;
} app_crypto_async_req_ticket_t;

#define APP_CRYPTO_ASYNC_INVALID_TICKET                                       \
  ((app_crypto_async_req_ticket_t){ { .app_index = ~0, .req_index = ~0 } })

typedef union
{
  struct
  {
    u32 opaque;			      /**< opaque metadata */
    clib_thread_index_t thread_index; /**< thread on which req was made */
  };
  u64 handle;
} app_crypto_async_req_handle_t;

struct app_crypto_async_reply_;

typedef void (*app_crypto_async_req_cb) (
  struct app_crypto_async_reply_ *reply);

#define foreach_app_crypto_async_req_type _ (CERT, "async-cert")

typedef enum app_crypto_req_type_
{
#define _(a, b) APP_CRYPTO_ASYNC_REQ_TYPE_##a,
  foreach_app_crypto_async_req_type
#undef _
} app_crypto_async_req_type_t;

typedef struct app_crypto_async_req_
{
  app_crypto_async_req_type_t req_type; /**< request type */
  app_crypto_async_req_handle_t handle; /**< async request handle */
  app_crypto_async_req_cb cb; /**< callback to invoke on completion */
  u32 app_wrk_index;	      /**< application worker index */
  u32 req_index;	      /**< index in crypto worker's request pool */
  u8 cancelled;		      /**< flag to indicate if cancelled */
  union
  {
    struct
    {
      const u8 *servername; /**< server name for SNI */
    } async_cert;	    /**< async cert request data */
  };
} app_crypto_async_req_t;

typedef struct app_crypto_async_reply_
{
  u32 app_index; /**< app that resolved the request */
  u32 req_index; /**< request index in app crypto pool */
  app_crypto_async_req_handle_t handle; /**< request handle */
  app_crypto_async_req_type_t req_type; /**< request type */
  union
  {
    struct
    {
      u32 ckpair_index; /**< certificate key-pair index */
    } async_cert;	/**< async cert reply data */
  };
} app_crypto_async_reply_t;

typedef struct app_crypto_wrk_
{
  app_crypto_async_req_t *reqs;
} app_crypto_wrk_t;

typedef struct app_crypto_ctx_
{
  app_crypto_wrk_t *wrk;
  app_crypto_ca_trust_t *ca_trust_stores;
  /** Preferred tls engine */
  u8 tls_engine;
  /** quic initialization vector */
  char quic_iv[17];
  u8 quic_iv_set;
} app_crypto_ctx_t;

void app_crypto_ctx_init (app_crypto_ctx_t *crypto_ctx);
void app_crypto_ctx_free (app_crypto_ctx_t *crypto_ctx);

/*
 * Certificate key-pair management
 */

app_cert_key_pair_t *app_cert_key_pair_get (u32 index);
app_cert_key_pair_t *app_cert_key_pair_get_if_valid (u32 index);
app_cert_key_pair_t *app_cert_key_pair_get_default ();

int app_crypto_add_ca_trust (u32 app_index, app_ca_trust_add_args_t *args);
app_crypto_ca_trust_t *app_crypto_get_wrk_ca_trust (u32 app_wrk_index,
						    u32 ca_trust_index);
app_crypto_ca_trust_int_ctx_t *
app_crypto_alloc_int_ca_trust (app_crypto_ca_trust_t *ct,
			       clib_thread_index_t thread_index);
app_crypto_ca_trust_int_ctx_t *
app_crypto_get_int_ca_trust (app_crypto_ca_trust_t *ct,
			     clib_thread_index_t thread_index);

int vnet_app_add_cert_key_pair (vnet_app_add_cert_key_pair_args_t *a);
int vnet_app_del_cert_key_pair (u32 index);

static inline app_certkey_int_ctx_t *
app_certkey_get_int_ctx (app_cert_key_pair_t *ck,
			 clib_thread_index_t thread_index,
			 crypto_engine_type_t engine)
{
  if (vec_len (ck->cki) <= thread_index ||
      vec_len (ck->cki[thread_index]) < engine)
    return 0;
  return vec_elt_at_index (ck->cki[thread_index], engine);
}

static inline app_certkey_int_ctx_t *
app_certkey_alloc_int_ctx (app_cert_key_pair_t *ck,
			   clib_thread_index_t thread_index,
			   crypto_engine_type_t engine)
{
  app_certkey_int_ctx_t *cki;

  cki = vec_elt_at_index (ck->cki[thread_index], engine);
  cki->thread_index = thread_index;
  cki->ckpair_index = ck->cert_key_index;

  return cki;
}

app_crypto_async_req_ticket_t
app_crypto_async_req (app_crypto_async_req_t *req);
void app_crypto_async_cancel_req (app_crypto_async_req_ticket_t ticket);

/*
 * Crypto engine management
 */
crypto_engine_type_t app_crypto_engine_type_add (void);
u8 app_crypto_engine_n_types (void);
u8 *format_crypto_engine (u8 *s, va_list *args);
uword unformat_crypto_engine (unformat_input_t *input, va_list *args);

clib_error_t *application_crypto_init ();

#endif /* SRC_VNET_SESSION_APPLICATION_CRYPTO_H_ */
