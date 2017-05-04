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
#include <vpp-api/vapi/vapi.h>
#include <vpe.api.vapi.h>
#include <interface.api.vapi.h>

static char *app_name = NULL;
static char *api_prefix = NULL;

START_TEST (test_invalid_values)
{
  vapi_ctx_t ctx;
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_eq (NULL, sv);
  rv = vapi_send (ctx, sv);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_connect (ctx, app_name, api_prefix, 32, VAPI_MODE_BLOCKING);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_send (ctx, NULL);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_send (NULL, NULL);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_recv (NULL, NULL, NULL);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  rv = vapi_recv (ctx, NULL, NULL);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  vapi_msg_show_version_reply *reply;
  rv = vapi_recv (ctx, (void **) &reply, NULL);
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

START_TEST (test_hton_3)
{
  const size_t data_size = 10;
  vapi_msg_vnet_interface_combined_counters *m =
    malloc (sizeof (vapi_msg_vnet_interface_combined_counters) +
	    data_size * sizeof (vapi_type_vlib_counter));
  ck_assert_ptr_ne (NULL, m);
  vapi_payload_vnet_interface_combined_counters *p = &m->payload;
  const u16 _vl_msg_id = 1;
  p->_vl_msg_id = _vl_msg_id;
  const u32 first_sw_if_index = 2;
  p->first_sw_if_index = first_sw_if_index;
  p->count = data_size;
  const u64 packets = 1234;
  const u64 bytes = 2345;
  int i;
  for (i = 0; i < data_size; ++i)
    {
      p->data[i].packets = packets;
      p->data[i].bytes = bytes;
    }
  vapi_msg_vnet_interface_combined_counters_hton (m);
  ck_assert_int_eq (_vl_msg_id, be16toh (p->_vl_msg_id));
  ck_assert_int_eq (first_sw_if_index, be32toh (p->first_sw_if_index));
  ck_assert_int_eq (data_size, be32toh (p->count));
  for (i = 0; i < data_size; ++i)
    {
      ck_assert_int_eq (packets, be64toh (p->data[i].packets));
      ck_assert_int_eq (bytes, be64toh (p->data[i].bytes));
    }
  free (p);
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

START_TEST (test_ntoh_3)
{
  const size_t data_size = 10;
  vapi_msg_vnet_interface_combined_counters *m =
    malloc (sizeof (vapi_msg_vnet_interface_combined_counters) +
	    data_size * sizeof (vapi_type_vlib_counter));
  ck_assert_ptr_ne (NULL, m);
  vapi_payload_vnet_interface_combined_counters *p = &m->payload;
  const u16 _vl_msg_id = 1;
  p->_vl_msg_id = _vl_msg_id;
  const u32 first_sw_if_index = 2;
  p->first_sw_if_index = first_sw_if_index;
  const size_t be_data_size = htobe32 (data_size);
  p->count = be_data_size;
  const u64 packets = 1234;
  const u64 bytes = 2345;
  int i;
  for (i = 0; i < data_size; ++i)
    {
      p->data[i].packets = packets;
      p->data[i].bytes = bytes;
    }
  vapi_msg_vnet_interface_combined_counters_ntoh (m);
  ck_assert_int_eq (_vl_msg_id, be16toh (p->_vl_msg_id));
  ck_assert_int_eq (first_sw_if_index, be32toh (p->first_sw_if_index));
  ck_assert_int_eq (be_data_size, be32toh (p->count));
  for (i = 0; i < data_size; ++i)
    {
      ck_assert_int_eq (packets, htobe64 (p->data[i].packets));
      ck_assert_int_eq (bytes, htobe64 (p->data[i].bytes));
    }
  free (p);
}

END_TEST;

vapi_error_e
show_version_cb (vapi_ctx_t ctx, void *caller_ctx,
		 vapi_error_e rv, bool is_last,
		 vapi_payload_show_version_reply * p)
{
  printf
    ("show_version_reply: program: `%s', version: `%s', build directory: "
     "`%s', build date: `%s'\n", p->program, p->version, p->build_directory,
     p->build_date);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (true, is_last);
  ck_assert_str_eq ("vpe", (char *) p->program);
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
  rv = vapi_connect (ctx, app_name, api_prefix, 32, VAPI_MODE_BLOCKING);
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
  rv = vapi_connect (ctx, app_name, api_prefix, 32, VAPI_MODE_BLOCKING);
  ck_assert_int_eq (VAPI_OK, rv);
}

void
setup_nonblocking (void)
{
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_connect (ctx, app_name, api_prefix, 32, VAPI_MODE_NONBLOCKING);
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
  rv = vapi_recv (ctx, (void *) &resp, &size);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_payload_show_version_reply *payload = &resp->payload;
  int dummy;
  show_version_cb (NULL, &dummy, VAPI_OK, true, payload);
  vapi_msg_free (ctx, resp);
}

END_TEST;

START_TEST (test_show_version_2)
{
  int called = 0;
  printf ("--- Show version via blocking callback API ---\n");
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  vapi_error_e rv = vapi_show_version (ctx, sv, show_version_cb, &called);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
}

END_TEST;

typedef struct
{
  bool last_called;
  size_t num_ifs;
  u32 *sw_if_indexes;
  bool *seen;
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
      ck_assert (reply);
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
  return VAPI_OK;
}

START_TEST (test_loopbacks_1)
{
  printf ("--- Create/delete loopbacks using blocking API ---\n");
  const size_t num_ifs = 5;
  u8 mac_addresses[num_ifs][6];
  memset (&mac_addresses, 0, sizeof (mac_addresses));
  u32 sw_if_indexes[num_ifs];
  memset (&sw_if_indexes, 0xff, sizeof (sw_if_indexes));
  test_create_loopback_ctx_t clcs[num_ifs];
  memset (&clcs, 0, sizeof (clcs));
  test_delete_loopback_ctx_t dlcs[num_ifs];
  memset (&dlcs, 0, sizeof (dlcs));
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
      memcpy (cl->payload.mac_address, mac_addresses[i],
	      sizeof (cl->payload.mac_address));
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
  memset (&seen, 0, sizeof (seen));
  sw_interface_dump_ctx dctx = { false, num_ifs, sw_if_indexes, seen };
  vapi_msg_sw_interface_dump *dump = vapi_alloc_sw_interface_dump (ctx);
  dump->payload.name_filter_valid = 0;
  memset (dump->payload.name_filter, 0, sizeof (dump->payload.name_filter));
  vapi_error_e rv;
  while (VAPI_EAGAIN ==
	 (rv =
	  vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb, &dctx)))
    ;
  ck_assert_int_eq (true, dctx.last_called);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (true, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
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
  memset (&seen, 0, sizeof (seen));
  dump = vapi_alloc_sw_interface_dump (ctx);
  dump->payload.name_filter_valid = 0;
  memset (dump->payload.name_filter, 0, sizeof (dump->payload.name_filter));
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
  rv = vapi_dispatch (ctx);
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
  memset (contexts, 0, sizeof (contexts));
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
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_req; ++i)
    {
      ck_assert_int_eq (1, contexts[i]);
    }
  memset (contexts, 0, sizeof (contexts));
  rv = vapi_dispatch (ctx);
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
  memset (&mac_addresses, 0, sizeof (mac_addresses));
  u32 sw_if_indexes[num_ifs];
  memset (&sw_if_indexes, 0xff, sizeof (sw_if_indexes));
  test_create_loopback_ctx_t clcs[num_ifs];
  memset (&clcs, 0, sizeof (clcs));
  test_delete_loopback_ctx_t dlcs[num_ifs];
  memset (&dlcs, 0, sizeof (dlcs));
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
      memcpy (cl->payload.mac_address, mac_addresses[i],
	      sizeof (cl->payload.mac_address));
      while (VAPI_EAGAIN ==
	     (rv =
	      vapi_create_loopback (ctx, cl, loopback_create_cb, &clcs[i])))
	;
      ck_assert_int_eq (VAPI_OK, rv);
    }
  rv = vapi_dispatch (ctx);
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
  memset (&seen, 0, sizeof (seen));
  sw_interface_dump_ctx dctx = { false, num_ifs, sw_if_indexes, seen };
  vapi_msg_sw_interface_dump *dump = vapi_alloc_sw_interface_dump (ctx);
  dump->payload.name_filter_valid = 0;
  memset (dump->payload.name_filter, 0, sizeof (dump->payload.name_filter));
  while (VAPI_EAGAIN ==
	 (rv =
	  vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb, &dctx)))
    ;
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (false, dctx.last_called);
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (true, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
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
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (1, dlcs[i].called);
      printf ("Deleted loopback with sw_if_index %u\n", sw_if_indexes[i]);
    }
  memset (&seen, 0, sizeof (seen));
  dctx.last_called = false;
  dump = vapi_alloc_sw_interface_dump (ctx);
  dump->payload.name_filter_valid = 0;
  memset (dump->payload.name_filter, 0, sizeof (dump->payload.name_filter));
  while (VAPI_EAGAIN ==
	 (rv =
	  vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb, &dctx)))
    ;
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (true, dctx.last_called);
}

END_TEST;

vapi_error_e
stats_cb (vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv,
	  bool is_last, vapi_payload_want_stats_reply * payload)
{
  return VAPI_OK;
}

vapi_error_e
simple_counters_cb (vapi_ctx_t ctx, void *callback_ctx,
		    vapi_payload_vnet_interface_simple_counters * payload)
{
  int *called = callback_ctx;
  ++*called;
  printf ("simple counters: first_sw_if_index=%u\n",
	  payload->first_sw_if_index);
  return VAPI_OK;
}

START_TEST (test_stats_1)
{
  printf ("--- Receive stats using generic blocking API ---\n");
  vapi_msg_want_stats *ws = vapi_alloc_want_stats (ctx);
  ws->payload.enable_disable = 1;
  ws->payload.pid = getpid ();
  vapi_error_e rv;
  rv = vapi_want_stats (ctx, ws, stats_cb, NULL);
  ck_assert_int_eq (VAPI_OK, rv);
  int called = 0;
  vapi_set_event_cb (ctx, vapi_msg_id_vnet_interface_simple_counters,
		     (vapi_event_cb) simple_counters_cb, &called);
  rv = vapi_dispatch_one (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
}

END_TEST;

START_TEST (test_stats_2)
{
  printf ("--- Receive stats using stat-specific blocking API ---\n");
  vapi_msg_want_stats *ws = vapi_alloc_want_stats (ctx);
  ws->payload.enable_disable = 1;
  ws->payload.pid = getpid ();
  vapi_error_e rv;
  rv = vapi_want_stats (ctx, ws, stats_cb, NULL);
  ck_assert_int_eq (VAPI_OK, rv);
  int called = 0;
  vapi_set_vapi_msg_vnet_interface_simple_counters_event_cb (ctx,
							     simple_counters_cb,
							     &called);
  rv = vapi_dispatch_one (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
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
  rv = vapi_dispatch_one (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
  sv = vapi_alloc_show_version (ctx);
  ck_assert_ptr_ne (NULL, sv);
  vapi_msg_show_version_hton (sv);
  while (VAPI_EAGAIN == (rv = vapi_send (ctx, sv)))
    ;
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_clear_generic_event_cb (ctx);
  rv = vapi_dispatch_one (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);	/* needs to remain unchanged */
}

END_TEST;

vapi_error_e
combined_counters_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
		      vapi_payload_vnet_interface_combined_counters * payload)
{
  int *called = callback_ctx;
  ++*called;
  printf ("combined counters: first_sw_if_index=%u\n",
	  payload->first_sw_if_index);
  return VAPI_OK;
}

START_TEST (test_stats_3)
{
  printf ("--- Receive multiple stats using stat-specific non-blocking API "
	  "---\n");
  vapi_msg_want_stats *ws = vapi_alloc_want_stats (ctx);
  ws->payload.enable_disable = 1;
  ws->payload.pid = getpid ();
  vapi_error_e rv;
  rv = vapi_want_stats (ctx, ws, stats_cb, NULL);
  ck_assert_int_eq (VAPI_OK, rv);
  int called = 0;
  int called2 = 0;
  vapi_set_vapi_msg_vnet_interface_simple_counters_event_cb (ctx,
							     simple_counters_cb,
							     &called);
  vapi_set_vapi_msg_vnet_interface_combined_counters_event_cb (ctx,
							       combined_counters_cb,
							       &called2);
  while (!called || !called2)
    {
      if (VAPI_EAGAIN != (rv = vapi_dispatch_one (ctx)))
	{
	  ck_assert_int_eq (VAPI_OK, rv);
	}
    }
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
  tcase_add_test (tc_swap, test_hton_3);
  tcase_add_test (tc_swap, test_ntoh_1);
  tcase_add_test (tc_swap, test_ntoh_2);
  tcase_add_test (tc_swap, test_ntoh_3);
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
  tcase_add_test (tc_block, test_stats_1);
  tcase_add_test (tc_block, test_stats_2);
  suite_add_tcase (s, tc_block);

  TCase *tc_nonblock = tcase_create ("Nonblocking API");
  tcase_set_timeout (tc_nonblock, 25);
  tcase_add_checked_fixture (tc_nonblock, setup_nonblocking, teardown);
  tcase_add_test (tc_nonblock, test_show_version_3);
  tcase_add_test (tc_nonblock, test_show_version_4);
  tcase_add_test (tc_nonblock, test_show_version_5);
  tcase_add_test (tc_nonblock, test_loopbacks_2);
  tcase_add_test (tc_nonblock, test_stats_3);
  suite_add_tcase (s, tc_nonblock);

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
