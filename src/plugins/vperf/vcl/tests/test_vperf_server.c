/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STORAGE_SIZE 512
#define CHECK(condition)                                                                           \
  do                                                                                               \
    {                                                                                              \
      if (!(condition))                                                                            \
	{                                                                                          \
	  fprintf (stderr, "%s:%d: %s\n", __func__, __LINE__, #condition);                         \
	  abort ();                                                                                \
	}                                                                                          \
    }                                                                                              \
  while (0)

static unsigned allocations, replies, closes, cases;
static size_t requested;
static int fail_alloc;
static unsigned char reply_bytes[STORAGE_SIZE];

static void *
test_realloc (void *old, size_t size)
{
  void *fresh;

  allocations++;
  requested = size;
  CHECK (size >= 128 && size <= INT32_MAX);
  if (fail_alloc)
    {
      errno = ENOMEM;
      return NULL;
    }
  /* Logical boundary sizes have fixed physical backing. */
  fresh = calloc (1, STORAGE_SIZE);
  CHECK (fresh && fresh != old);
  if (old)
    memcpy (fresh, old, STORAGE_SIZE);
  free (old);
  return fresh;
}

static int
test_session_close (uint32_t fd)
{
  CHECK (fd == 7);
  closes++;
  return 0;
}

static int test_session_write (uint32_t fd, void *data, size_t size);

#define realloc		     test_realloc
#define vppcom_session_write test_session_write
#define vppcom_session_close test_session_close
#define main		     vperf_server_program_main
#include "../vperf_server.c"
#undef main
#undef vppcom_session_close
#undef vppcom_session_write
#undef realloc

static int
test_session_write (uint32_t fd, void *data, size_t size)
{
  CHECK (fd == 7 && size == sizeof (vperf_cfg_t));
  memcpy (reply_bytes, data, size);
  replies++;
  return size;
}

static int
reply (vperf_session_t *session, void *data, uint32_t size)
{
  return test_session_write (session->fd, data, size);
}

static void
session_init (vperf_session_t *session)
{
  memset (session, 0, sizeof (*session));
  vperf_cfg_init (&session->cfg);
  session->cfg.rxbuf_size = session->rxbuf_size = STORAGE_SIZE;
  session->cfg.txbuf_size = session->txbuf_size = STORAGE_SIZE;
  session->cfg.total_bytes = session->cfg.num_writes * STORAGE_SIZE;
  session->rxbuf = calloc (1, STORAGE_SIZE);
  session->txbuf = calloc (1, STORAGE_SIZE);
  CHECK (session->rxbuf && session->txbuf);
  session->fd = 7;
  session->write = reply;
  session->is_done = 1;
  session->stats.rx_bytes = 8192;
  session->stats.rx_xacts = 16;
  allocations = replies = closes = fail_alloc = 0;
}

static void
configuration_case (uint64_t rx, uint64_t tx, int fail, int malformed)
{
  vperf_server_worker_t worker = { 0 };
  vperf_session_t session;
  vperf_cfg_t before, expected, *incoming;
  vperf_stats_t stats;
  uintptr_t old_rx, old_tx;
  int valid = rx >= 128 && rx <= INT32_MAX && tx >= 128 && tx <= INT32_MAX && !malformed;

  session_init (&session);
  before = session.cfg;
  stats = session.stats;
  old_rx = (uintptr_t) session.rxbuf;
  old_tx = (uintptr_t) session.txbuf;
  incoming = (void *) session.rxbuf;
  *incoming = session.cfg;
  incoming->test = VPERF_TEST_TYPE_UNI;
  incoming->cmd = VPERF_CMD_SYNC;
  incoming->rxbuf_size = rx;
  incoming->txbuf_size = tx;
  expected = *incoming;
  fail_alloc = fail;
  CHECK (vperf_server_handle_ctrl_cfg (&worker, incoming, &session,
				       sizeof (*incoming) - malformed) == (valid ? 0 : -1));
  CHECK (replies == 1 && allocations == (valid ? 1 : 0));
  if (valid)
    {
      CHECK (requested == rx);
      expected.ctrl_handle = 7;
      expected.rxbuf_size = expected.txbuf_size = fail ? STORAGE_SIZE : rx;
      CHECK (!memcmp (&session.cfg, &expected, sizeof (expected)));
      stats.tx_xacts++;
      stats.tx_bytes += sizeof (expected);
    }
  else
    {
      CHECK (!memcmp (&session.cfg, &before, sizeof (before)));
      expected = before;
      if (malformed)
	expected.rxbuf_size = expected.num_writes = 0;
    }
  CHECK (!memcmp (reply_bytes, &expected, sizeof (expected)));
  CHECK (session.rxbuf_size == (valid && !fail ? rx : STORAGE_SIZE));
  CHECK (((uintptr_t) session.rxbuf == old_rx) == (!valid || fail));
  CHECK ((uintptr_t) session.txbuf == old_tx && session.txbuf_size == STORAGE_SIZE);
  CHECK (session.is_done && !memcmp (&session.stats, &stats, sizeof (stats)));
  vperf_session_buf_free (&session);
  cases++;
}

static void
exit_case (void)
{
  static const vperf_proto_vft_t protocol = { 0 };
  vperf_server_worker_t worker = { .nfds = 1 };
  vperf_session_t session;
  vperf_cfg_t *incoming;

  session_init (&session);
  session.is_open = session.is_alloc = 1;
  vperf_main.protos[VPPCOM_PROTO_TCP] = &protocol;
  vperf_server_main.server_cfg.proto = VPPCOM_PROTO_TCP;
  vperf_server_main.ctrl = &session;
  incoming = (void *) session.rxbuf;
  *incoming = session.cfg;
  incoming->test = VPERF_TEST_TYPE_EXIT;
  incoming->rxbuf_size = 0;
  incoming->txbuf_size = UINT64_MAX;
  CHECK (!vperf_server_handle_ctrl_cfg (&worker, incoming, &session, sizeof (*incoming)));
  CHECK (!allocations && !replies && closes == 1);
  CHECK (!worker.nfds && !vperf_server_main.ctrl);
  CHECK (!session.is_open && !session.is_alloc && !session.rxbuf && !session.txbuf);
  cases++;
}

int
main (void)
{
  static const uint64_t invalid[] = {
    0, 127, UINT64_C (2147483648), UINT64_C (4294967296), UINT64_C (4294967297), UINT64_MAX
  };

  CHECK (sizeof (vperf_cfg_t) <= STORAGE_SIZE);
  configuration_case (128, 128, 0, 0);
  configuration_case (INT_MAX, INT_MAX, 0, 0);
  configuration_case (8192, 256, 1, 0);
  for (unsigned i = 0; i < ARRAY_LEN (invalid); i++)
    {
      configuration_case (invalid[i], STORAGE_SIZE, 0, 0);
      configuration_case (STORAGE_SIZE, invalid[i], 0, 0);
    }
  configuration_case (STORAGE_SIZE, STORAGE_SIZE, 0, 1);
  exit_case ();
  printf ("%u vperf server buffer cases passed\n", cases);
  return 0;
}
