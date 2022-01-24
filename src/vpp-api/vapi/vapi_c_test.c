/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <setjmp.h>
#include <check.h>
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

/* centos has ancient check so we hack our way around here
 * to make it work somehow */
#ifndef ck_assert_ptr_eq
#define ck_assert_ptr_eq(X,Y) ck_assert_int_eq((long)X, (long)Y)
#endif

#ifndef ck_assert_ptr_ne
#define ck_assert_ptr_ne(X,Y) ck_assert_int_ne((long)X, (long)Y)
#endif

START_TEST (test_invalid_values)
{
  vapi_ctx_t ctx;
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_eq (NULL, sv);
  rv = vapi_send (ctx, sv);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_connect (ctx, app_name, api_prefix, max_outstanding_requests,
		     response_queue_size, VAPI_MODE_BLOCKING, true);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_send (ctx, NULL);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_send (NULL, NULL);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_recv (NULL, NULL, NULL, 0, 0);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_recv (ctx, NULL, NULL, 0, 0);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  vapi_msg_show_version_reply *reply;
  rv = vapi_recv (ctx, (void **) &reply, NULL, 0, 0);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_disconnect (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_ctx_free (ctx);
}

END_TEST;

START_TEST (test_hton_1)
{
  const u16 _vl_msg_id = 1;
  vapi_type_msg_header1_t h;
  h._vl_msg_id = _vl_msg_id;
  vapi_type_msg_header1_t_hton (&h);
  ck_assert_int_eq (be16toh (h._vl_msg_id), _vl_msg_id);
}

END_TEST;

START_TEST (test_hton_2)
{
  const u16 _vl_msg_id = 1;
  const u32 client_index = 3;
  vapi_type_msg_header2_t h;
  h._vl_msg_id = _vl_msg_id;
  h.client_index = client_index;
  vapi_type_msg_header2_t_hton (&h);
  ck_assert_int_eq (be16toh (h._vl_msg_id), _vl_msg_id);
  ck_assert_int_eq (h.client_index, client_index);
}

END_TEST;

#define verify_hton_swap(expr, value)           \
  if (4 == sizeof (expr))                       \
    {                                           \
      ck_assert_int_eq (expr, htobe32 (value)); \
    }                                           \
  else if (2 == sizeof (expr))                  \
    {                                           \
      ck_assert_int_eq (expr, htobe16 (value)); \
    }                                           \
  else                                          \
    {                                           \
      ck_assert_int_eq (expr, value);           \
    }

START_TEST (test_hton_4)
{
  const int vla_count = 3;
  char x[sizeof (vapi_msg_bridge_domain_details) +
	 vla_count * sizeof (vapi_type_bridge_domain_sw_if)];
  vapi_msg_bridge_domain_details *d = (void *) x;
  int cnt = 1;
  d->header._vl_msg_id = cnt++;
  d->header.context = cnt++;
  d->payload.bd_id = cnt++;
  d->payload.mac_age = cnt++;
  d->payload.bvi_sw_if_index = cnt++;
  d->payload.n_sw_ifs = vla_count;
  int i;
  for (i = 0; i < vla_count; ++i)
    {
      vapi_type_bridge_domain_sw_if *det = &d->payload.sw_if_details[i];
      det->context = cnt++;
      det->sw_if_index = cnt++;
      det->shg = cnt++;
    }
  ck_assert_int_eq (sizeof (x), vapi_calc_bridge_domain_details_msg_size (d));
  vapi_msg_bridge_domain_details_hton (d);
  int tmp = 1;
  verify_hton_swap (d->header._vl_msg_id, tmp);
  ++tmp;
  ck_assert_int_eq (d->header.context, tmp);
  ++tmp;
  verify_hton_swap (d->payload.bd_id, tmp);
  ++tmp;
  verify_hton_swap (d->payload.mac_age, tmp);
  ++tmp;
  verify_hton_swap (d->payload.bvi_sw_if_index, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.n_sw_ifs, htobe32 (vla_count));
  for (i = 0; i < vla_count; ++i)
    {
      vapi_type_bridge_domain_sw_if *det = &d->payload.sw_if_details[i];
      verify_hton_swap (det->context, tmp);
      ++tmp;
      verify_hton_swap (det->sw_if_index, tmp);
      ++tmp;
      verify_hton_swap (det->shg, tmp);
      ++tmp;
    }
  vapi_msg_bridge_domain_details_ntoh (d);
  tmp = 1;
  ck_assert_int_eq (d->header._vl_msg_id, tmp);
  ++tmp;
  ck_assert_int_eq (d->header.context, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.bd_id, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.mac_age, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.bvi_sw_if_index, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.n_sw_ifs, vla_count);
  for (i = 0; i < vla_count; ++i)
    {
      vapi_type_bridge_domain_sw_if *det = &d->payload.sw_if_details[i];
      ck_assert_int_eq (det->context, tmp);
      ++tmp;
      ck_assert_int_eq (det->sw_if_index, tmp);
      ++tmp;
      ck_assert_int_eq (det->shg, tmp);
      ++tmp;
    }
  ck_assert_int_eq (sizeof (x), vapi_calc_bridge_domain_details_msg_size (d));
}

END_TEST;

START_TEST (test_ntoh_1)
{
  const u16 _vl_msg_id = 1;
  vapi_type_msg_header1_t h;
  h._vl_msg_id = _vl_msg_id;
  vapi_type_msg_header1_t_ntoh (&h);
  ck_assert_int_eq (htobe16 (h._vl_msg_id), _vl_msg_id);
}

END_TEST;

START_TEST (test_ntoh_2)
{
  const u16 _vl_msg_id = 1;
  const u32 client_index = 3;
  vapi_type_msg_header2_t h;
  h._vl_msg_id = _vl_msg_id;
  h.client_index = client_index;
  vapi_type_msg_header2_t_ntoh (&h);
  ck_assert_int_eq (htobe16 (h._vl_msg_id), _vl_msg_id);
  ck_assert_int_eq (h.client_index, client_index);
}

END_TEST;

#define verify_ntoh_swap(expr, value)           \
  if (4 == sizeof (expr))                       \
    {                                           \
      ck_assert_int_eq (expr, be32toh (value)); \
    }                                           \
  else if (2 == sizeof (expr))                  \
    {                                           \
      ck_assert_int_eq (expr, be16toh (value)); \
    }                                           \
  else                                          \
    {                                           \
      ck_assert_int_eq (expr, value);           \
    }

START_TEST (test_ntoh_4)
{
  const int vla_count = 3;
  char x[sizeof (vapi_msg_bridge_domain_details) +
	 vla_count * sizeof (vapi_type_bridge_domain_sw_if)];
  vapi_msg_bridge_domain_details *d = (void *) x;
  int cnt = 1;
  d->header._vl_msg_id = cnt++;
  d->header.context = cnt++;
  d->payload.bd_id = cnt++;
  d->payload.mac_age = cnt++;
  d->payload.bvi_sw_if_index = cnt++;
  d->payload.n_sw_ifs = htobe32 (vla_count);
  int i;
  for (i = 0; i < vla_count; ++i)
    {
      vapi_type_bridge_domain_sw_if *det = &d->payload.sw_if_details[i];
      det->context = cnt++;
      det->sw_if_index = cnt++;
      det->shg = cnt++;
    }
  vapi_msg_bridge_domain_details_ntoh (d);
  ck_assert_int_eq (sizeof (x), vapi_calc_bridge_domain_details_msg_size (d));
  int tmp = 1;
  verify_ntoh_swap (d->header._vl_msg_id, tmp);
  ++tmp;
  ck_assert_int_eq (d->header.context, tmp);
  ++tmp;
  verify_ntoh_swap (d->payload.bd_id, tmp);
  ++tmp;
  verify_ntoh_swap (d->payload.mac_age, tmp);
  ++tmp;
  verify_ntoh_swap (d->payload.bvi_sw_if_index, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.n_sw_ifs, vla_count);
  for (i = 0; i < vla_count; ++i)
    {
      vapi_type_bridge_domain_sw_if *det = &d->payload.sw_if_details[i];
      verify_ntoh_swap (det->context, tmp);
      ++tmp;
      verify_ntoh_swap (det->sw_if_index, tmp);
      ++tmp;
      verify_ntoh_swap (det->shg, tmp);
      ++tmp;
    }
  vapi_msg_bridge_domain_details_hton (d);
  tmp = 1;
  ck_assert_int_eq (d->header._vl_msg_id, tmp);
  ++tmp;
  ck_assert_int_eq (d->header.context, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.bd_id, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.mac_age, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.bvi_sw_if_index, tmp);
  ++tmp;
  ck_assert_int_eq (d->payload.n_sw_ifs, htobe32 (vla_count));
  for (i = 0; i < vla_count; ++i)
    {
      vapi_type_bridge_domain_sw_if *det = &d->payload.sw_if_details[i];
      ck_assert_int_eq (det->context, tmp);
      ++tmp;
      ck_assert_int_eq (det->sw_if_index, tmp);
      ++tmp;
      ck_assert_int_eq (det->shg, tmp);
      ++tmp;
    }
}

END_TEST;

vapi_error_e
show_version_cb (vapi_ctx_t ctx, void *caller_ctx,
		 vapi_error_e rv, bool is_last,
		 vapi_payload_show_version_reply * p)
{
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (true, is_last);
  ck_assert_str_eq ("vpe", (char *) p->program);
  printf
    ("show_version_reply: program: `%s', version: `%s', build directory: "
     "`%s', build date: `%s'\n", p->program, p->version, p->build_directory,
     p->build_date);
  ++*(int *) caller_ctx;
  return VAPI_OK;
}

typedef struct
{
  int called;
  int expected_retval;
  u32 *sw_if_index_storage;
} test_create_loopback_ctx_t;

vapi_error_e
loopback_create_cb (vapi_ctx_t ctx, void *caller_ctx,
		    vapi_error_e rv, bool is_last,
		    vapi_payload_create_loopback_reply * p)
{
  test_create_loopback_ctx_t *clc = caller_ctx;
  ck_assert_int_eq (clc->expected_retval, p->retval);
  *clc->sw_if_index_storage = p->sw_if_index;
  ++clc->called;
  return VAPI_OK;
}

typedef struct
{
  int called;
  int expected_retval;
  u32 *sw_if_index_storage;
} test_delete_loopback_ctx_t;

vapi_error_e
loopback_delete_cb (vapi_ctx_t ctx, void *caller_ctx,
		    vapi_error_e rv, bool is_last,
		    vapi_payload_delete_loopback_reply * p)
{
  test_delete_loopback_ctx_t *dlc = caller_ctx;
  ck_assert_int_eq (dlc->expected_retval, p->retval);
  ++dlc->called;
  return VAPI_OK;
}

START_TEST (test_connect)
{
  vapi_ctx_t ctx;
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_connect (ctx, app_name, api_prefix, max_outstanding_requests,
		     response_queue_size, VAPI_MODE_BLOCKING, true);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_disconnect (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_ctx_free (ctx);
}

END_TEST;

vapi_ctx_t ctx;

void
setup_blocking (void)
{
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_connect (ctx, app_name, api_prefix, max_outstanding_requests,
		     response_queue_size, VAPI_MODE_BLOCKING, true);
  ck_assert_int_eq (VAPI_OK, rv);
}

void
setup_nonblocking (void)
{
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_connect (ctx, app_name, api_prefix, max_outstanding_requests,
		     response_queue_size, VAPI_MODE_NONBLOCKING, true);
  ck_assert_int_eq (VAPI_OK, rv);
}

void
teardown (void)
{
  vapi_disconnect (ctx);
  vapi_ctx_free (ctx);
}

START_TEST (test_show_version_1)
{
  printf ("--- Basic show version message - reply test ---\n");
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  vapi_msg_show_version_hton (sv);
  vapi_error_e rv = vapi_send (ctx, sv);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_msg_show_version_reply *resp;
  size_t size;
  rv = vapi_recv (ctx, (void *) &resp, &size, 0, 0);
  ck_assert_int_eq (VAPI_OK, rv);
  int placeholder;
  show_version_cb (NULL, &placeholder, VAPI_OK, true, &resp->payload);
  vapi_msg_free (ctx, resp);
}

END_TEST;

START_TEST (test_show_version_2)
{
  int called = 0;
  printf ("--- Show version via blocking callback API ---\n");
  const int attempts = response_queue_size * 4;
  int i = 0;
  for (i = 0; i < attempts; ++i)
    {
      vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
      ck_assert_ptr_ne (NULL, sv);
      vapi_error_e rv = vapi_show_version (ctx, sv, show_version_cb, &called);
      ck_assert_int_eq (VAPI_OK, rv);
    }
  ck_assert_int_eq (attempts, called);
}

END_TEST;

typedef struct
{
  bool last_called;
  size_t num_ifs;
  u32 *sw_if_indexes;
  bool *seen;
  int called;
} sw_interface_dump_ctx;

vapi_error_e
sw_interface_dump_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
		      vapi_error_e rv, bool is_last,
		      vapi_payload_sw_interface_details * reply)
{
  sw_interface_dump_ctx *dctx = callback_ctx;
  ck_assert_int_eq (false, dctx->last_called);
  if (is_last)
    {
      ck_assert (NULL == reply);
      dctx->last_called = true;
    }
  else
    {
      ck_assert (NULL != reply);
      printf ("Interface dump entry: [%u]: %s\n", reply->sw_if_index,
	      reply->interface_name);
      size_t i = 0;
      for (i = 0; i < dctx->num_ifs; ++i)
	{
	  if (dctx->sw_if_indexes[i] == reply->sw_if_index)
	    {
	      ck_assert_int_eq (false, dctx->seen[i]);
	      dctx->seen[i] = true;
	    }
	}
    }
  ++dctx->called;
  return VAPI_OK;
}

START_TEST (test_loopbacks_1)
{
  printf ("--- Create/delete loopbacks using blocking API ---\n");
  const size_t num_ifs = 5;
  u8 mac_addresses[num_ifs][6];
  clib_memset (&mac_addresses, 0, sizeof (mac_addresses));
  u32 sw_if_indexes[num_ifs];
  clib_memset (&sw_if_indexes, 0xff, sizeof (sw_if_indexes));
  test_create_loopback_ctx_t clcs[num_ifs];
  clib_memset (&clcs, 0, sizeof (clcs));
  test_delete_loopback_ctx_t dlcs[num_ifs];
  clib_memset (&dlcs, 0, sizeof (dlcs));
  int i;
  for (i = 0; i < num_ifs; ++i)
    {
      memcpy (&mac_addresses[i], "\1\2\3\4\5\6", 6);
      mac_addresses[i][5] = i;
      clcs[i].sw_if_index_storage = &sw_if_indexes[i];
    }
  for (i = 0; i < num_ifs; ++i)
    {
      vapi_msg_create_loopback *cl = vapi_alloc_create_loopback (ctx);
      int j;
      for (j = 0; j < 6; ++j)
	{
	  cl->payload.mac_address[j] = mac_addresses[i][j];
	}
      vapi_error_e rv =
	vapi_create_loopback (ctx, cl, loopback_create_cb, &clcs[i]);
      ck_assert_int_eq (VAPI_OK, rv);
    }
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (1, clcs[i].called);
      printf ("Created loopback with MAC %02x:%02x:%02x:%02x:%02x:%02x --> "
	      "sw_if_index %u\n",
	      mac_addresses[i][0], mac_addresses[i][1], mac_addresses[i][2],
	      mac_addresses[i][3], mac_addresses[i][4], mac_addresses[i][5],
	      sw_if_indexes[i]);
    }
  bool seen[num_ifs];
  sw_interface_dump_ctx dctx = { false, num_ifs, sw_if_indexes, seen, 0 };
  vapi_msg_sw_interface_dump *dump;
  vapi_error_e rv;
  const int attempts = response_queue_size * 4;
  for (i = 0; i < attempts; ++i)
    {
      dctx.last_called = false;
      clib_memset (&seen, 0, sizeof (seen));
      dump = vapi_alloc_sw_interface_dump (ctx);
      while (VAPI_EAGAIN ==
	     (rv =
	      vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb,
				      &dctx)))
	;
      ck_assert_int_eq (true, dctx.last_called);
      int j = 0;
      for (j = 0; j < num_ifs; ++j)
	{
	  ck_assert_int_eq (true, seen[j]);
	}
    }
  clib_memset (&seen, 0, sizeof (seen));
  for (i = 0; i < num_ifs; ++i)
    {
      vapi_msg_delete_loopback *dl = vapi_alloc_delete_loopback (ctx);
      dl->payload.sw_if_index = sw_if_indexes[i];
      vapi_error_e rv =
	vapi_delete_loopback (ctx, dl, loopback_delete_cb, &dlcs[i]);
      ck_assert_int_eq (VAPI_OK, rv);
    }
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (1, dlcs[i].called);
      printf ("Deleted loopback with sw_if_index %u\n", sw_if_indexes[i]);
    }
  dctx.last_called = false;
  clib_memset (&seen, 0, sizeof (seen));
  dump = vapi_alloc_sw_interface_dump (ctx);
  while (VAPI_EAGAIN ==
	 (rv =
	  vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb, &dctx)))
    ;
  ck_assert_int_eq (true, dctx.last_called);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
}

END_TEST;

START_TEST (test_show_version_3)
{
  printf ("--- Show version via async callback ---\n");
  int called = 0;
  vapi_error_e rv;
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  while (VAPI_EAGAIN ==
	 (rv = vapi_show_version (ctx, sv, show_version_cb, &called)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (0, called);
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
  called = 0;
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (0, called);
}

END_TEST;

START_TEST (test_show_version_4)
{
  printf ("--- Show version via async callback - multiple messages ---\n");
  vapi_error_e rv;
  const size_t num_req = 5;
  int contexts[num_req];
  clib_memset (contexts, 0, sizeof (contexts));
  int i;
  for (i = 0; i < num_req; ++i)
    {
      vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
      ck_assert_ptr_ne (NULL, sv);
      while (VAPI_EAGAIN ==
	     (rv =
	      vapi_show_version (ctx, sv, show_version_cb, &contexts[i])))
	;
      ck_assert_int_eq (VAPI_OK, rv);
      int j;
      for (j = 0; j < num_req; ++j)
	{
	  ck_assert_int_eq (0, contexts[j]);
	}
    }
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_req; ++i)
    {
      ck_assert_int_eq (1, contexts[i]);
    }
  clib_memset (contexts, 0, sizeof (contexts));
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_req; ++i)
    {
      ck_assert_int_eq (0, contexts[i]);
    }
}

END_TEST;

START_TEST (test_loopbacks_2)
{
  printf ("--- Create/delete loopbacks using non-blocking API ---\n");
  vapi_error_e rv;
  const size_t num_ifs = 5;
  u8 mac_addresses[num_ifs][6];
  clib_memset (&mac_addresses, 0, sizeof (mac_addresses));
  u32 sw_if_indexes[num_ifs];
  clib_memset (&sw_if_indexes, 0xff, sizeof (sw_if_indexes));
  test_create_loopback_ctx_t clcs[num_ifs];
  clib_memset (&clcs, 0, sizeof (clcs));
  test_delete_loopback_ctx_t dlcs[num_ifs];
  clib_memset (&dlcs, 0, sizeof (dlcs));
  int i;
  for (i = 0; i < num_ifs; ++i)
    {
      memcpy (&mac_addresses[i], "\1\2\3\4\5\6", 6);
      mac_addresses[i][5] = i;
      clcs[i].sw_if_index_storage = &sw_if_indexes[i];
    }
  for (i = 0; i < num_ifs; ++i)
    {
      vapi_msg_create_loopback *cl = vapi_alloc_create_loopback (ctx);
      int j;
      for (j = 0; j < 6; ++j)
	{
	  cl->payload.mac_address[j] = mac_addresses[i][j];
	}
      while (VAPI_EAGAIN ==
	     (rv =
	      vapi_create_loopback (ctx, cl, loopback_create_cb, &clcs[i])))
	;
      ck_assert_int_eq (VAPI_OK, rv);
    }
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (1, clcs[i].called);
      printf ("Loopback with MAC %02x:%02x:%02x:%02x:%02x:%02x --> "
	      "sw_if_index %u\n",
	      mac_addresses[i][0], mac_addresses[i][1], mac_addresses[i][2],
	      mac_addresses[i][3], mac_addresses[i][4], mac_addresses[i][5],
	      sw_if_indexes[i]);
    }
  bool seen[num_ifs];
  clib_memset (&seen, 0, sizeof (seen));
  sw_interface_dump_ctx dctx = { false, num_ifs, sw_if_indexes, seen, 0 };
  vapi_msg_sw_interface_dump *dump = vapi_alloc_sw_interface_dump (ctx);
  while (VAPI_EAGAIN ==
	 (rv =
	  vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb, &dctx)))
    ;
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
  clib_memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (false, dctx.last_called);
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (true, seen[i]);
    }
  clib_memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (true, dctx.last_called);
  for (i = 0; i < num_ifs; ++i)
    {
      vapi_msg_delete_loopback *dl = vapi_alloc_delete_loopback (ctx);
      dl->payload.sw_if_index = sw_if_indexes[i];
      while (VAPI_EAGAIN ==
	     (rv =
	      vapi_delete_loopback (ctx, dl, loopback_delete_cb, &dlcs[i])))
	;
      ck_assert_int_eq (VAPI_OK, rv);
    }
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (1, dlcs[i].called);
      printf ("Deleted loopback with sw_if_index %u\n", sw_if_indexes[i]);
    }
  clib_memset (&seen, 0, sizeof (seen));
  dctx.last_called = false;
  dump = vapi_alloc_sw_interface_dump (ctx);
  while (VAPI_EAGAIN ==
	 (rv =
	  vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb, &dctx)))
    ;
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
  clib_memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (true, dctx.last_called);
}

END_TEST;

vapi_error_e
generic_cb (vapi_ctx_t ctx, void *callback_ctx, vapi_msg_id_t id, void *msg)
{
  int *called = callback_ctx;
  ck_assert_int_eq (0, *called);
  ++*called;
  ck_assert_int_eq (id, vapi_msg_id_show_version_reply);
  ck_assert_ptr_ne (NULL, msg);
  vapi_msg_show_version_reply *reply = msg;
  ck_assert_str_eq ("vpe", (char *) reply->payload.program);
  return VAPI_OK;
}

START_TEST (test_show_version_5)
{
  printf ("--- Receive show version using generic callback - nonblocking "
	  "API ---\n");
  vapi_error_e rv;
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  vapi_msg_show_version_hton (sv);
  while (VAPI_EAGAIN == (rv = vapi_send (ctx, sv)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  int called = 0;
  vapi_set_generic_event_cb (ctx, generic_cb, &called);
  ck_assert_int_eq (VAPI_OK, rv);
  while (VAPI_EAGAIN == (rv = vapi_dispatch_one (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
  sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  vapi_msg_show_version_hton (sv);
  while (VAPI_EAGAIN == (rv = vapi_send (ctx, sv)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_clear_generic_event_cb (ctx);
  while (VAPI_EAGAIN == (rv = vapi_dispatch_one (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);	/* needs to remain unchanged */
}

END_TEST;

vapi_error_e
show_version_no_cb (vapi_ctx_t ctx, void *caller_ctx,
		    vapi_error_e rv, bool is_last,
		    vapi_payload_show_version_reply * p)
{
  ck_assert_int_eq (VAPI_ENORESP, rv);
  ck_assert_int_eq (true, is_last);
  ck_assert_ptr_eq (NULL, p);
  ++*(int *) caller_ctx;
  return VAPI_OK;
}

START_TEST (test_no_response_1)
{
  printf ("--- Simulate no response to regular message ---\n");
  vapi_error_e rv;
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  sv->header._vl_msg_id = ~0;	/* malformed ID causes vpp to drop the msg */
  int called = 0;
  while (VAPI_EAGAIN ==
	 (rv = vapi_show_version (ctx, sv, show_version_no_cb, &called)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  while (VAPI_EAGAIN ==
	 (rv = vapi_show_version (ctx, sv, show_version_cb, &called)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (2, called);
}

END_TEST;

vapi_error_e
no_msg_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
	   vapi_error_e rv, bool is_last,
	   vapi_payload_sw_interface_details * reply)
{
  int *called = callback_ctx;
  ++*called;
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (true, is_last);
  ck_assert_ptr_eq (NULL, reply);
  return VAPI_OK;
}

START_TEST (test_no_response_2)
{
  printf ("--- Simulate no response to dump message ---\n");
  vapi_error_e rv;
  vapi_msg_sw_interface_dump *dump = vapi_alloc_sw_interface_dump (ctx);
  dump->header._vl_msg_id = ~0;	/* malformed ID causes vpp to drop the msg */
  int no_called = 0;
  while (VAPI_EAGAIN ==
	 (rv = vapi_sw_interface_dump (ctx, dump, no_msg_cb, &no_called)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, no_called);
}

END_TEST;

START_TEST (test_unsupported)
{
  printf ("--- Unsupported messages ---\n");
  bool available = vapi_is_msg_available (ctx, vapi_msg_id_test_fake_msg);
  ck_assert_int_eq (false, available);
}

END_TEST;

START_TEST (test_api_strings)
{
  printf ("--- Invalid api strings ---\n");

  /* test string 'TEST'
   * size = 5
   * length = 4
   */
  const char str[] = "TEST";
  u8 *vec_str = 0, *vstr = 0;
  char *cstr;

  vapi_msg_sw_interface_dump *dump =
    malloc (sizeof (vapi_msg_sw_interface_dump) + strlen (str));
  clib_mem_init (0, 1 << 20);

  vl_api_c_string_to_api_string (str, &dump->payload.name_filter);
  /* Assert nul terminator NOT present */
  ck_assert_int_eq (vl_api_string_len (&dump->payload.name_filter),
		    strlen (str));

  cstr = vl_api_from_api_to_new_c_string (&dump->payload.name_filter);
  ck_assert_ptr_ne (cstr, NULL);
  /* Assert nul terminator present */
  ck_assert_int_eq (vec_len (cstr), sizeof (str));
  ck_assert_int_eq (strlen (str), strlen (cstr));
  vec_free (cstr);

  vstr = vl_api_from_api_to_new_vec (0 /* not really an API message */ ,
				     &dump->payload.name_filter);
  ck_assert_ptr_ne (vstr, NULL);
  /* Assert nul terminator NOT present */
  ck_assert_int_eq (vec_len (vstr), strlen (str));
  vec_free (vstr);

  /* vector conaining NON nul terminated string 'TEST' */
  vec_add (vec_str, str, strlen (str));
  clib_memset (dump->payload.name_filter.buf, 0, strlen (str));
  dump->payload.name_filter.length = 0;

  vl_api_vec_to_api_string (vec_str, &dump->payload.name_filter);
  /* Assert nul terminator NOT present */
  ck_assert_int_eq (vl_api_string_len (&dump->payload.name_filter),
		    vec_len (vec_str));

  cstr = vl_api_from_api_to_new_c_string (&dump->payload.name_filter);
  ck_assert_ptr_ne (cstr, NULL);
  /* Assert nul terminator present */
  ck_assert_int_eq (vec_len (cstr), sizeof (str));
  ck_assert_int_eq (strlen (str), strlen (cstr));
  vec_free (cstr);

  vstr = vl_api_from_api_to_new_vec (0 /* not a real api msg */ ,
				     &dump->payload.name_filter);
  ck_assert_ptr_ne (vstr, NULL);
  /* Assert nul terminator NOT present */
  ck_assert_int_eq (vec_len (vstr), strlen (str));
  vec_free (vstr);
  free (dump);
}

END_TEST;

Suite *
test_suite (void)
{
  Suite *s = suite_create ("VAPI test");

  TCase *tc_negative = tcase_create ("Negative tests");
  tcase_add_test (tc_negative, test_invalid_values);
  suite_add_tcase (s, tc_negative);

  TCase *tc_swap = tcase_create ("Byteswap tests");
  tcase_add_test (tc_swap, test_hton_1);
  tcase_add_test (tc_swap, test_hton_2);
  tcase_add_test (tc_swap, test_hton_4);
  tcase_add_test (tc_swap, test_ntoh_1);
  tcase_add_test (tc_swap, test_ntoh_2);
  tcase_add_test (tc_swap, test_ntoh_4);
  suite_add_tcase (s, tc_swap);

  TCase *tc_connect = tcase_create ("Connect");
  tcase_add_test (tc_connect, test_connect);
  suite_add_tcase (s, tc_connect);

  TCase *tc_block = tcase_create ("Blocking API");
  tcase_set_timeout (tc_block, 25);
  tcase_add_checked_fixture (tc_block, setup_blocking, teardown);
  tcase_add_test (tc_block, test_show_version_1);
  tcase_add_test (tc_block, test_show_version_2);
  tcase_add_test (tc_block, test_loopbacks_1);
  suite_add_tcase (s, tc_block);

  TCase *tc_nonblock = tcase_create ("Nonblocking API");
  tcase_set_timeout (tc_nonblock, 25);
  tcase_add_checked_fixture (tc_nonblock, setup_nonblocking, teardown);
  tcase_add_test (tc_nonblock, test_show_version_3);
  tcase_add_test (tc_nonblock, test_show_version_4);
  tcase_add_test (tc_nonblock, test_show_version_5);
  tcase_add_test (tc_nonblock, test_loopbacks_2);
  tcase_add_test (tc_nonblock, test_no_response_1);
  tcase_add_test (tc_nonblock, test_no_response_2);
  suite_add_tcase (s, tc_nonblock);

  TCase *tc_unsupported = tcase_create ("Unsupported message");
  tcase_add_checked_fixture (tc_unsupported, setup_blocking, teardown);
  tcase_add_test (tc_unsupported, test_unsupported);
  suite_add_tcase (s, tc_unsupported);

  TCase *tc_dynamic = tcase_create ("Dynamic message size");
  tcase_add_test (tc_dynamic, test_api_strings);
  suite_add_tcase (s, tc_dynamic);

  return s;
}

int
main (int argc, char *argv[])
{
  if (3 != argc)
    {
      printf ("Invalid argc==`%d'\n", argc);
      return EXIT_FAILURE;
    }
  app_name = argv[1];
  api_prefix = argv[2];
  printf ("App name: `%s', API prefix: `%s'\n", app_name, api_prefix);

  int number_failed;
  Suite *s;
  SRunner *sr;

  s = test_suite ();
  sr = srunner_create (s);

  srunner_run_all (sr, CK_NORMAL);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
