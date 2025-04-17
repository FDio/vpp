/*
 * Copyright (c) 2018 Intel and/or its affiliates.
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

#ifndef SRC_PLUGINS_TLSOPENSSL_TLS_OPENSSL_H_
#define SRC_PLUGINS_TLSOPENSSL_TLS_OPENSSL_H_

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/tls/tls.h>

#define TLSO_CTRL_BYTES 1000
#define TLSO_MIN_ENQ_SPACE (1 << 16)

#define DTLSO_MAX_DGRAM 2000

#define ossl_check_err_is_fatal(_ssl, _rv)                                    \
  if (PREDICT_FALSE (_rv < 0 && SSL_get_error (_ssl, _rv) == SSL_ERROR_SSL))  \
    return -1;

typedef struct tls_async_evt_
{
  clib_llist_anchor_t anchor;
  u32 eidx;
} async_evt_list;

typedef struct tls_async_ctx_
{
  async_evt_list *hs_evt_list;
  async_evt_list *rd_evt_list;
  async_evt_list *wr_evt_list;
  clib_llist_index_t rd_evt_head_index;
  clib_llist_index_t wr_evt_head_index;
  clib_llist_index_t hs_evt_head_index;
  u32 total_async_write;
} tls_async_ctx_t;

typedef struct tls_ctx_openssl_
{
  tls_ctx_t ctx;			/**< First */
  u32 openssl_ctx_index;
  SSL_CTX *client_ssl_ctx;
  SSL *ssl;
  tls_async_ctx_t async_ctx;
  BIO *rbio;
  BIO *wbio;
} openssl_ctx_t;

typedef struct tls_listen_ctx_opensl_
{
  u32 openssl_lctx_index;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  X509 *srvcert;
  EVP_PKEY *pkey;
} openssl_listen_ctx_t;

typedef struct openssl_main_
{
  openssl_ctx_t ***ctx_pool;
  openssl_listen_ctx_t *lctx_pool;

  u8 **rx_bufs;
  u8 **tx_bufs;

  /* API message ID base */
  u16 msg_id_base;

  X509_STORE *cert_store;
  u8 *ciphers;
  int engine_init;
  int async;
  u32 record_size;
  u32 record_split_size;
  u32 max_pipelines;
} openssl_main_t;

typedef int openssl_resume_handler (void *event, void *session);
typedef int (*async_handlers) (void *event, void *session);

tls_ctx_t *openssl_ctx_get_w_thread (u32 ctx_index, u8 thread_index);
int vpp_tls_async_init_event (tls_ctx_t *ctx, openssl_resume_handler *handler,
			      session_t *session,
			      ssl_async_evt_type_t evt_type,
			      transport_send_params_t *sp, int wr_size);
int tls_async_openssl_callback (SSL * s, void *evt);
int openssl_evt_free (int event_idx, u8 thread_index);
void openssl_polling_start (ENGINE * engine);
int openssl_engine_register (char *engine, char *alg, int async);
void openssl_async_node_enable_disable (u8 is_en);
clib_error_t *tls_openssl_api_init (vlib_main_t * vm);
int tls_openssl_set_ciphers (char *ciphers);
int vpp_openssl_is_inflight (tls_ctx_t * ctx);
int openssl_read_from_ssl_into_fifo (svm_fifo_t *f, tls_ctx_t *ctx,
				     u32 max_len);
void openssl_handle_handshake_failure (tls_ctx_t *ctx);
void openssl_confirm_app_close (tls_ctx_t *ctx);

int tls_async_write_event_handler (void *event, void *session);
int tls_async_read_event_handler (void *event, void *session);
int tls_async_handshake_event_handler (void *event, void *session);
int openssl_ctx_read_tls (tls_ctx_t *ctx, session_t *tls_session);
void tls_async_evts_init_list (tls_async_ctx_t *ctx);
void tls_async_evts_free_list (tls_ctx_t *ctx);
#endif /* SRC_PLUGINS_TLSOPENSSL_TLS_OPENSSL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
