
#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <setjmp.h>
#include <vppinfra/string.h>
#include <vapi/vapi.h>
#include <vapi/memclnt.api.vapi.h>
#include <vapi/vlib.api.vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/l2.api.vapi.h>
#include <fake.api.vapi.h>

#include <vppinfra/vec.h>
#include <vppinfra/mem.h>

DEFINE_VAPI_MSG_IDS_VPE_API_JSON;
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON;
DEFINE_VAPI_MSG_IDS_L2_API_JSON;
DEFINE_VAPI_MSG_IDS_FAKE_API_JSON;

static char *app_name = NULL;
static char *api_prefix = NULL;
static const int max_outstanding_requests = 64;
static const int response_queue_size = 32;

vapi_error_e
show_version_cb (vapi_ctx_t ctx, void *caller_ctx, vapi_error_e rv,
		 bool is_last, vapi_payload_show_version_reply *p)
{
  printf ("show_version_reply: program: `%s', version: `%s', build directory: "
	  "`%s', build date: `%s'\n",
	  p->program, p->version, p->build_directory, p->build_date);
  ++*(int *) caller_ctx;
  return VAPI_OK;
}

vapi_ctx_t ctx;

int
setup_blocking (void)
{
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  if (rv != VAPI_OK)
    printf ("Alloc failed");
  return vapi_connect (ctx, app_name, api_prefix, max_outstanding_requests,
		       response_queue_size, VAPI_MODE_BLOCKING, true);
}

int
setup_nonblocking (void)
{
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  if (rv != VAPI_OK)
    printf ("Alloc failed");
  return vapi_connect (ctx, app_name, api_prefix, max_outstanding_requests,
		       response_queue_size, VAPI_MODE_NONBLOCKING, true);
}

void
teardown (void)
{
  vapi_disconnect (ctx);
  vapi_ctx_free (ctx);
}

int
test_show_version_1 (void)
{
  printf ("--- Basic show version message - reply test ---\n");
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  vapi_msg_show_version_hton (sv);
  vapi_error_e rv = vapi_send (ctx, sv);
  if (rv != VAPI_OK)
    printf ("Send failed");
  vapi_msg_show_version_reply *resp;
  size_t size;
  rv = vapi_recv (ctx, (void *) &resp, &size, 0, 0);
  int placeholder;
  show_version_cb (NULL, &placeholder, VAPI_OK, true, &resp->payload);
  vapi_msg_free (ctx, resp);
  return 0;
}

int
test_show_version_2 (void)
{
  int called = 0;
  printf ("--- Show version via blocking callback API ---\n");
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  vapi_error_e rv = vapi_show_version (ctx, sv, show_version_cb, &called);
  return rv;
}

int
main (int argc, char *argv[])
{
  app_name = argv[1];
  api_prefix = argv[2];
  printf ("App name: `%s', API prefix: `%s'\n", app_name, api_prefix);

  setup_blocking ();
  test_show_version_1 ();
  teardown ();
}
