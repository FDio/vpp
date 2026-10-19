/* SPDX-License-Identifier: Apache-2.0 */

#include <vppinfra/test/test.h>

#if defined(__x86_64__)
static clib_error_t *
test_clib_cpu_features (clib_error_t *err)
{
#define _(flag, func, reg, bit)                                                                    \
  {                                                                                                \
    u32 eax = 0, ebx = 0, ecx = 0, edx = 0;                                                        \
    int expected, actual;                                                                          \
                                                                                                   \
    clib_get_cpuid (func, &eax, &ebx, &ecx, &edx);                                                 \
    expected = (reg >> bit) & 1;                                                                   \
    actual = clib_cpu_supports_##flag ();                                                          \
    if (actual != expected)                                                                        \
      return clib_error_return (err, "%s: expected %d, got %d", #flag, expected, actual);          \
  }
  /* Includes avx512vl (EBX bit 31). */
  foreach_x86_64_flags
#undef _
    return err;
}

REGISTER_TEST (clib_cpu_features) = {
  .name = "clib_cpu_features",
  .fn = test_clib_cpu_features,
};
#endif
