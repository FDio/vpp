#include <stdio.h>
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
  vapi_ctx_t *ctx = vapi_ctx_alloc ();
  vapi_msg_show_version *sv = vapi_msg_alloc (ctx, sizeof (*sv));
  ck_assert_ptr_eq (NULL, sv);
  vapi_msg_init_show_version (ctx, sv);
  vapi_error_e rv = vapi_send (ctx, sv);
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
  rv = vapi_recv (ctx, (void **)&reply, NULL);
  ck_assert_int_eq (VAPI_EINVAL, rv);
  vapi_ctx_free (ctx);
}

END_TEST
vapi_error_e show_version_cb (vapi_ctx_t *ctx, void *caller_ctx,
                              vapi_error_e rv, bool is_last,
                              vapi_payload_show_version_reply *p)
{
  printf ("show_version_reply: program: `%s', version: `%s', build directory: "
          "`%s', build date: `%s'\n",
          p->program, p->version, p->build_directory, p->build_date);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (true, is_last);
  ck_assert_str_eq ("vpe", (char *)p->program);
  ++*(int *)caller_ctx;
  return VAPI_OK;
}

typedef struct
{
  int called;
  int expected_retval;
  u32 *sw_if_index_storage;
} test_create_loopback_ctx_t;

vapi_error_e loopback_create_cb (vapi_ctx_t *ctx, void *caller_ctx,
                                 vapi_error_e rv, bool is_last,
                                 vapi_payload_create_loopback_reply *p)
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

vapi_error_e loopback_delete_cb (vapi_ctx_t *ctx, void *caller_ctx,
                                 vapi_error_e rv, bool is_last,
                                 vapi_payload_delete_loopback_reply *p)
{
  test_delete_loopback_ctx_t *dlc = caller_ctx;
  ck_assert_int_eq (dlc->expected_retval, p->retval);
  ++dlc->called;
  return VAPI_OK;
}

START_TEST (test_connect)
{
  vapi_ctx_t *ctx = vapi_ctx_alloc ();
  vapi_error_e rv =
      vapi_connect (ctx, app_name, api_prefix, 32, VAPI_MODE_BLOCKING);
  ck_assert_int_eq (VAPI_OK, rv);
  rv = vapi_disconnect (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_ctx_free (ctx);
}

END_TEST vapi_ctx_t *ctx;

void setup_blocking (void)
{
  ctx = vapi_ctx_alloc ();
  vapi_error_e rv =
      vapi_connect (ctx, app_name, api_prefix, 32, VAPI_MODE_BLOCKING);
  ck_assert_int_eq (VAPI_OK, rv);
}

void setup_nonblocking (void)
{
  ctx = vapi_ctx_alloc ();
  vapi_error_e rv =
      vapi_connect (ctx, app_name, api_prefix, 32, VAPI_MODE_NONBLOCKING);
  ck_assert_int_eq (VAPI_OK, rv);
}

void teardown (void)
{
  vapi_disconnect (ctx);
  vapi_ctx_free (ctx);
}

START_TEST (test_show_version_1)
{
  printf ("--- Basic show version message - reply test ---");
  vapi_msg_show_version *sv = vapi_msg_alloc (ctx, sizeof (*sv));
  ck_assert_ptr_ne (NULL, sv);
  vapi_msg_init_show_version (ctx, sv);
  vapi_error_e rv = vapi_send (ctx, sv);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_msg_show_version_reply *resp;
  size_t size;
  rv = vapi_recv (ctx, (void *)&resp, &size);
  ck_assert_int_eq (VAPI_OK, rv);
  vapi_payload_show_version_reply *payload = &resp->payload;
  int dummy;
  show_version_cb (NULL, &dummy, VAPI_OK, true, payload);
  vapi_msg_free (ctx, resp);
}

END_TEST
START_TEST (test_show_version_2)
{
  int called = 0;
  printf ("--- Show version via blocking callback API ---\n");
  vapi_error_e rv = vapi_show_version (ctx, show_version_cb, &called);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
}

END_TEST typedef struct
{
  bool last_called;
  size_t num_ifs;
  u32 *sw_if_indexes;
  bool *seen;
} sw_interface_dump_ctx;

vapi_error_e sw_interface_dump_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
                                   vapi_error_e rv, bool is_last,
                                   vapi_payload_sw_interface_details *reply)
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
  for (int i = 0; i < num_ifs; ++i)
    {
      memcpy (&mac_addresses[i], "\1\2\3\4\5\6", 6);
      mac_addresses[i][5] = i;
      clcs[i].sw_if_index_storage = &sw_if_indexes[i];
    }
  for (int i = 0; i < num_ifs; ++i)
    {
      vapi_error_e rv = vapi_create_loopback (ctx, loopback_create_cb,
                                              &clcs[i], mac_addresses[i]);
      ck_assert_int_eq (VAPI_OK, rv);
    }
  for (int i = 0; i < num_ifs; ++i)
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
  u8 name_filter[sizeof (
      *((vapi_payload_sw_interface_dump *)(NULL))->name_filter)] = { 0 };
  vapi_error_e rv;
  while (VAPI_EAGAIN ==
         (rv = vapi_sw_interface_dump (ctx, sw_interface_dump_cb, &dctx, 0,
                                       name_filter)))
    ;
  ck_assert_int_eq (true, dctx.last_called);
  for (int i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (true, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
  for (int i = 0; i < num_ifs; ++i)
    {
      vapi_error_e rv = vapi_delete_loopback (ctx, loopback_delete_cb,
                                              &dlcs[i], sw_if_indexes[i]);
      ck_assert_int_eq (VAPI_OK, rv);
    }
  for (int i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (1, dlcs[i].called);
      printf ("Deleted loopback with sw_if_index %u\n", sw_if_indexes[i]);
    }
  dctx.last_called = false;
  memset (&seen, 0, sizeof (seen));
  while (VAPI_EAGAIN ==
         (rv = vapi_sw_interface_dump (ctx, sw_interface_dump_cb, &dctx, 0,
                                       name_filter)))
    ;
  ck_assert_int_eq (true, dctx.last_called);
  for (int i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
}

END_TEST
START_TEST (test_show_version_3)
{
  printf ("--- Show version via async callback ---\n");
  int called = 0;
  vapi_error_e rv;
  while (VAPI_EAGAIN ==
         (rv = vapi_show_version (ctx, show_version_cb, &called)))
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

END_TEST
START_TEST (test_show_version_4)
{
  printf ("--- Show version via async callback - multiple messages ---\n");
  vapi_error_e rv;
  const size_t num_req = 5;
  int contexts[num_req];
  memset (contexts, 0, sizeof (contexts));
  for (int i = 0; i < num_req; ++i)
    {
      while (VAPI_EAGAIN ==
             (rv = vapi_show_version (ctx, show_version_cb, &contexts[i])))
        ;
      ck_assert_int_eq (VAPI_OK, rv);
      for (int j = 0; j < num_req; ++j)
        {
          ck_assert_int_eq (0, contexts[j]);
        }
    }
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (int i = 0; i < num_req; ++i)
    {
      ck_assert_int_eq (1, contexts[i]);
    }
  memset (contexts, 0, sizeof (contexts));
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (int i = 0; i < num_req; ++i)
    {
      ck_assert_int_eq (0, contexts[i]);
    }
}

END_TEST
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
  for (int i = 0; i < num_ifs; ++i)
    {
      memcpy (&mac_addresses[i], "\1\2\3\4\5\6", 6);
      mac_addresses[i][5] = i;
      clcs[i].sw_if_index_storage = &sw_if_indexes[i];
    }
  for (int i = 0; i < num_ifs; ++i)
    {
      while (VAPI_EAGAIN ==
             (rv = vapi_create_loopback (ctx, loopback_create_cb, &clcs[i],
                                         mac_addresses[i])))
        ;
      ck_assert_int_eq (VAPI_OK, rv);
    }
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (int i = 0; i < num_ifs; ++i)
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
  u8 name_filter[sizeof (
      *((vapi_payload_sw_interface_dump *)(NULL))->name_filter)] = { 0 };
  while (VAPI_EAGAIN ==
         (rv = vapi_sw_interface_dump (ctx, sw_interface_dump_cb, &dctx, 0,
                                       name_filter)))
    ;
  for (int i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (false, dctx.last_called);
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (int i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (true, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (true, dctx.last_called);
  for (int i = 0; i < num_ifs; ++i)
    {
      while (VAPI_EAGAIN ==
             (rv = vapi_delete_loopback (ctx, loopback_delete_cb, &dlcs[i],
                                         sw_if_indexes[i])))
        ;
      ck_assert_int_eq (VAPI_OK, rv);
    }
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (int i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (1, dlcs[i].called);
      printf ("Deleted loopback with sw_if_index %u\n", sw_if_indexes[i]);
    }
  memset (&seen, 0, sizeof (seen));
  dctx.last_called = false;
  while (VAPI_EAGAIN ==
         (rv = vapi_sw_interface_dump (ctx, sw_interface_dump_cb, &dctx, 0,
                                       name_filter)))
    ;
  rv = vapi_dispatch (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  for (int i = 0; i < num_ifs; ++i)
    {
      ck_assert_int_eq (false, seen[i]);
    }
  memset (&seen, 0, sizeof (seen));
  ck_assert_int_eq (true, dctx.last_called);
}

END_TEST
vapi_error_e stats_cb (vapi_ctx_t *ctx, void *callback_ctx, vapi_error_e rv,
                       bool is_last, vapi_payload_want_stats_reply *payload)
{
  return VAPI_OK;
}

vapi_error_e
simple_counters_cb (vapi_ctx_t *ctx, void *callback_ctx,
                    vapi_payload_vnet_interface_simple_counters *payload)
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
  vapi_error_e rv;
  rv = vapi_want_stats (ctx, stats_cb, NULL, 1, getpid ());
  ck_assert_int_eq (VAPI_OK, rv);
  int called = 0;
  vapi_set_event_cb (ctx, vapi_msg_id_vnet_interface_simple_counters,
                     (vapi_generic_event_cb)simple_counters_cb, &called);
  rv = vapi_dispatch_one (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
}

END_TEST
START_TEST (test_stats_2)
{
  printf ("--- Receive stats using stat-specific blocking API ---\n");
  vapi_error_e rv;
  rv = vapi_want_stats (ctx, stats_cb, NULL, 1, getpid ());
  ck_assert_int_eq (VAPI_OK, rv);
  int called = 0;
  vapi_set_vapi_msg_vnet_interface_simple_counters_event_cb (
      ctx, simple_counters_cb, &called);
  rv = vapi_dispatch_one (ctx);
  ck_assert_int_eq (VAPI_OK, rv);
  ck_assert_int_eq (1, called);
}

END_TEST vapi_error_e
combined_counters_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
                      vapi_payload_vnet_interface_combined_counters *payload)
{
  int *called = callback_ctx;
  ++*called;
  printf ("combined counters: first_sw_if_index=%u\n",
          payload->first_sw_if_index);
  return VAPI_OK;
}

START_TEST (test_stats_3)
{
  printf (
      "--- Receive multiple stats using stat-specific non-blocking API ---\n");
  vapi_error_e rv;
  rv = vapi_want_stats (ctx, stats_cb, NULL, 1, getpid ());
  ck_assert_int_eq (VAPI_OK, rv);
  int called = 0;
  int called2 = 0;
  vapi_set_vapi_msg_vnet_interface_simple_counters_event_cb (
      ctx, simple_counters_cb, &called);
  vapi_set_vapi_msg_vnet_interface_combined_counters_event_cb (
      ctx, combined_counters_cb, &called2);
  while (!called || !called2)
    {
      if (VAPI_EAGAIN != (rv = vapi_dispatch_one (ctx)))
        {
          ck_assert_int_eq (VAPI_OK, rv);
        }
    }
}

END_TEST Suite *test_suite (void)
{
  Suite *s = suite_create ("VAPI test");

  TCase *tc_negative = tcase_create ("Negative tests");
  tcase_add_test (tc_negative, test_invalid_values);

  suite_add_tcase (s, tc_negative);

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
  tcase_add_test (tc_nonblock, test_loopbacks_2);
  tcase_add_test (tc_nonblock, test_stats_3);

  suite_add_tcase (s, tc_nonblock);

  return s;
}

int main (int argc, char *argv[])
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
