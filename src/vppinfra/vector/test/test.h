/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_test_test_h
#define included_test_test_h

#include <vppinfra/cpu.h>

typedef clib_error_t *(test_fn_t) (clib_error_t *);

typedef struct test_registration_
{
  char *name;
  u8 multiarch : 1;
  test_fn_t *fn;
  struct test_registration_ *next;
} test_registration_t;

extern test_registration_t *test_registrations[CLIB_MARCH_TYPE_N_VARIANTS];

#define __clib_test_fn static __clib_noinline __clib_section (".test_wrapper")

#define REGISTER_TEST(x)                                                      \
  test_registration_t CLIB_MARCH_SFX (__test_##x);                            \
  static void __clib_constructor CLIB_MARCH_SFX (__test_registration_##x) (   \
    void)                                                                     \
  {                                                                           \
    test_registration_t *r = &CLIB_MARCH_SFX (__test_##x);                    \
    r->next = test_registrations[CLIB_MARCH_SFX (CLIB_MARCH_VARIANT_TYPE)];   \
    test_registrations[CLIB_MARCH_SFX (CLIB_MARCH_VARIANT_TYPE)] = r;         \
  }                                                                           \
  test_registration_t CLIB_MARCH_SFX (__test_##x)

#endif
