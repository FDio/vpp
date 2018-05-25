#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/async.h>
#include <openssl/engine.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/tls/tls.h>

typedef struct tls_ctx_openssl_
{
  tls_ctx_t ctx;                        /**< First */
  u32 openssl_ctx_index;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;
  X509 *srvcert;
  EVP_PKEY *pkey;
} openssl_ctx_t;

typedef struct openssl_main_
{
  openssl_ctx_t ***ctx_pool;
  
  X509_STORE *cert_store;
  int engine_init;
  int async;
} openssl_main_t;

typedef struct openssl_tls_callback_
{
  int (*callback)(void *arg);
  void *arg;
} openssl_tls_callback_t;

typedef int openssl_resume_handler(tls_ctx_t *ctx, stream_session_t * tls_session);

openssl_tls_callback_t *vpp_add_async_pending_event(tls_ctx_t *ctx, stream_session_t * tls_session, openssl_resume_handler *myfunc);
openssl_tls_callback_t *vpp_add_async_pending_event2(tls_ctx_t *ctx, stream_session_t * tls_session, openssl_resume_handler *myfunc);
void openssl_polling_start(ENGINE *engine);
int register_openssl_engine(char *engine, char *alg);
void openssl_async_node_enable_disable (u8 is_en);

