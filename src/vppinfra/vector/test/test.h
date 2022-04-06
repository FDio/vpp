/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_test_test_h
#define included_test_test_h

#include <vppinfra/cpu.h>
#include <vppinfra/perfmon/perfmon.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#endif

typedef clib_error_t *(test_fn_t) (clib_error_t *);

struct test_perf_;
typedef void (test_perf_fn_t) (struct test_perf_ *tp);

typedef struct test_perf_
{
  int fd;
  u64 n_ops;
  union
  {
    u64 arg0;
    void *ptr0;
  };
  union
  {
    u64 arg1;
    void *ptr1;
  };
  union
  {
    u64 arg2;
    void *ptr2;
  };
  char *name;
  test_perf_fn_t *fn;
} test_perf_t;

typedef struct test_registration_
{
  char *name;
  u8 multiarch : 1;
  test_fn_t *fn;
  test_perf_t *perf_tests;
  u32 n_perf_tests;
  struct test_registration_ *next;
} test_registration_t;

typedef struct
{
  test_registration_t *registrations[CLIB_MARCH_TYPE_N_VARIANTS];
  u32 repeat;
  u8 *filter;
  u8 *bundle;
  f64 ref_clock;
} test_main_t;
extern test_main_t test_main;

#define __test_funct_fn                                                       \
  static __clib_noinline __clib_noclone __clib_section (".test_func")
#define __test_perf_fn                                                        \
  static __clib_noinline __clib_noclone __clib_section (".test_perf")

#define REGISTER_TEST(x)                                                      \
  test_registration_t CLIB_MARCH_SFX (__test_##x);                            \
  static void __clib_constructor CLIB_MARCH_SFX (__test_registration_##x) (   \
    void)                                                                     \
  {                                                                           \
    test_registration_t *r = &CLIB_MARCH_SFX (__test_##x);                    \
    r->next =                                                                 \
      test_main.registrations[CLIB_MARCH_SFX (CLIB_MARCH_VARIANT_TYPE)];      \
    test_main.registrations[CLIB_MARCH_SFX (CLIB_MARCH_VARIANT_TYPE)] = r;    \
  }                                                                           \
  test_registration_t CLIB_MARCH_SFX (__test_##x)

#define PERF_TESTS(...)                                                       \
  (test_perf_t[])                                                             \
  {                                                                           \
    __VA_ARGS__, {}                                                           \
  }

static_always_inline void
test_perf_event_reset (test_perf_t *t)
{
  clib_perfmon_ioctl (t->fd, PERF_EVENT_IOC_RESET);
}
static_always_inline void
test_perf_event_enable (test_perf_t *t)
{
  clib_perfmon_ioctl (t->fd, PERF_EVENT_IOC_ENABLE);
}
static_always_inline void
test_perf_event_disable (test_perf_t *t)
{
  clib_perfmon_ioctl (t->fd, PERF_EVENT_IOC_DISABLE);
}

void *test_mem_alloc (uword size);
void *test_mem_alloc_and_fill_inc_u8 (uword size, u8 start, u8 mask);
void *test_mem_alloc_and_splat (uword elt_size, uword n_elts, void *elt);
void test_mem_free (void *p);

#endif
