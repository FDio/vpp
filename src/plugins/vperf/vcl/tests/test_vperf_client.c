/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <errno.h>
#include <getopt.h>
#include <setjmp.h>
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

static jmp_buf exit_env;
static int exit_status, allocations, fail_at;
static size_t requested;
static unsigned cases;

static __attribute__ ((noreturn)) void
test_exit (int status)
{
  exit_status = status;
  longjmp (exit_env, 1);
}

static void *
test_realloc (void *old, size_t size)
{
  void *fresh;

  allocations++;
  requested = size;
  CHECK (size >= 128 && size <= INT32_MAX);
  if (allocations == fail_at)
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
test_printf (const char *format, ...)
{
  (void) format;
  return 0;
}

#define realloc test_realloc
#define exit	test_exit
#undef printf
#define printf test_printf
#define main   vperf_client_program_main
#include "../vperf_client.c"
#undef main
#undef printf
#undef exit
#undef realloc

static vperf_session_t *
reset_client (void)
{
  vperf_session_t *ctrl = &vperf_client_main.ctrl_session;

  vperf_session_buf_free (ctrl);
  memset (&vperf_client_main, 0, sizeof (vperf_client_main));
  vperf_cfg_init (&ctrl->cfg);
  ctrl->cfg.rxbuf_size = ctrl->rxbuf_size = STORAGE_SIZE;
  ctrl->cfg.txbuf_size = ctrl->txbuf_size = STORAGE_SIZE;
  ctrl->cfg.num_writes = 19;
  ctrl->cfg.total_bytes = 19 * STORAGE_SIZE;
  ctrl->rxbuf = calloc (1, STORAGE_SIZE);
  ctrl->txbuf = calloc (1, STORAGE_SIZE);
  CHECK (ctrl->rxbuf && ctrl->txbuf);
  exit_status = allocations = fail_at = 0;
  return ctrl;
}

static void
input_case (const char *input, uint64_t size, int cli, int rx, int fail)
{
  vperf_session_t *ctrl = reset_client ();
  vperf_cfg_t expected = ctrl->cfg;
  uintptr_t old_rx = (uintptr_t) ctrl->rxbuf, old_tx = (uintptr_t) ctrl->txbuf;
  char *argv[] = { "vperf_client", rx ? "-R" : "-T", (char *) input, "127.0.0.1", NULL };

  fail_at = fail;
  if (cli)
    {
      optind = 0;
      if (!setjmp (exit_env))
	vperf_client_process_opts (&vperf_client_main, 4, argv);
      CHECK (exit_status == (size ? 0 : 1));
    }
  else
    {
      snprintf (ctrl->txbuf, STORAGE_SIZE, "#%c:%s", rx ? 'R' : 'T', input);
      CHECK (parse_input () == VPERF_TEST_TYPE_NONE);
    }
  CHECK (allocations == (size ? 1 : 0));
  if (size)
    CHECK (requested == size);
  if (size && !fail)
    {
      if (rx)
	expected.rxbuf_size = size;
      else
	expected.txbuf_size = size;
      expected.total_bytes = expected.num_writes * expected.txbuf_size;
    }
  CHECK (!memcmp (&expected, &ctrl->cfg, sizeof (expected)));
  CHECK (ctrl->rxbuf_size == expected.rxbuf_size && ctrl->txbuf_size == expected.txbuf_size);
  CHECK (((uintptr_t) ctrl->rxbuf == old_rx) == (!size || fail || !rx));
  CHECK (((uintptr_t) ctrl->txbuf == old_tx) == (!size || fail || rx));
  cases++;
}

static void
allocation_case (int failure)
{
  vperf_session_t *ctrl = reset_client ();

  vperf_session_buf_free (ctrl);
  ctrl->rxbuf_size = ctrl->txbuf_size = 0;
  fail_at = failure;
  if (!setjmp (exit_env))
    vperf_session_buf_alloc (ctrl);
  CHECK (exit_status == 1 && allocations == failure);
  CHECK (!ctrl->rxbuf && !ctrl->rxbuf_size);
  CHECK (failure == 1 ? !ctrl->txbuf && !ctrl->txbuf_size :
			ctrl->txbuf && ctrl->txbuf_size == STORAGE_SIZE);
  cases++;
}

static void
invalid_allocation_case (void)
{
  vperf_session_t *ctrl = reset_client ();
  char *before = ctrl->rxbuf;

  ctrl->cfg.rxbuf_size = UINT64_C (4294967424);
  if (!setjmp (exit_env))
    vperf_buf_alloc (&ctrl->cfg, 1, (uint8_t **) &ctrl->rxbuf, &ctrl->rxbuf_size);
  CHECK (exit_status == 1 && !allocations);
  CHECK (ctrl->rxbuf == before && ctrl->rxbuf_size == STORAGE_SIZE);
  cases++;
}

int
main (void)
{
  static const struct
  {
    const char *input;
    uint64_t cli, interactive;
  } inputs[] = {
    { "128", 128, 128 },
    { "2147483647", INT32_MAX, INT32_MAX },
    { "2147483648", 0, 0 },
    { "0128", 128, 128 },
    { "0x80", 128, 0 },
    { "", 0, 0 },
    { "0", 0, 0 },
    { "127", 0, 0 },
    { "4294967296", 0, 0 },
    { "4294967297", 0, 0 },
    { "-18446744073709551488", 0, 0 },
    { "128junk", 0, 0 },
    { "18446744073709551616", 0, 0 },
  };

  for (unsigned i = 0; i < ARRAY_LEN (inputs); i++)
    for (int cli = 0; cli < 2; cli++)
      for (int rx = 0; rx < 2; rx++)
	input_case (inputs[i].input, cli ? inputs[i].cli : inputs[i].interactive, cli, rx, 0);
  for (int cli = 0; cli < 2; cli++)
    for (int rx = 0; rx < 2; rx++)
      input_case ("8192", 8192, cli, rx, 1);
  allocation_case (1);
  allocation_case (2);
  invalid_allocation_case ();
  vperf_session_buf_free (&vperf_client_main.ctrl_session);
  printf ("%u vperf client buffer cases passed\n", cases);
  return 0;
}
