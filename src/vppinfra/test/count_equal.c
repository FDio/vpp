/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector/count_equal.h>

#define foreach_clib_count_equal(type)                                        \
  typedef uword (wrapper_fn_##type) (type * a, uword maxcount);               \
                                                                              \
  __test_funct_fn uword clib_count_equal_##type##_wrapper (type *a,           \
							   uword maxcount)    \
  {                                                                           \
    return clib_count_equal_##type (a, maxcount);                             \
  }                                                                           \
                                                                              \
  static wrapper_fn_##type *wfn_##type = &clib_count_equal_##type##_wrapper;  \
  static clib_error_t *test_clib_count_equal_##type (clib_error_t *err)       \
  {                                                                           \
    u32 ps = clib_mem_get_log2_page_size ();                                  \
    void *map;                                                                \
                                                                              \
    u16 lengths[] = {                                                         \
      1, 2, 3, 5, 7, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257                 \
    };                                                                        \
    type *data;                                                               \
                                                                              \
    map = clib_mem_vm_map (0, 2ULL << ps, ps, "test");                        \
    if (map == CLIB_MEM_VM_MAP_FAILED)                                        \
      return clib_error_return (err, "clib_mem_vm_map failed");               \
                                                                              \
    data = ((type *) (map + (1ULL << ps)));                                   \
    data[-1] = 0xfe;                                                          \
                                                                              \
    mprotect (data, 1ULL < ps, PROT_NONE);                                    \
                                                                              \
    for (u8 d = 0; d < 255; d++)                                              \
      {                                                                       \
	for (int i = 1; i <= (1 << ps) / sizeof (data[0]); i++)               \
	  data[-i] = d;                                                       \
	for (int i = 0; i < ARRAY_LEN (lengths); i++)                         \
	  {                                                                   \
	    uword rv, len = lengths[i];                                       \
                                                                              \
	    if ((rv = wfn_##type (data - len, len)) != len)                   \
	      {                                                               \
		err = clib_error_return (                                     \
		  err, "testcase 1 failed for len %u data %u(rv %u)", len, d, \
		  rv);                                                        \
		goto done;                                                    \
	      }                                                               \
                                                                              \
	    data[-1] = d + 1;                                                 \
	    if (len > 1 && ((rv = wfn_##type (data - len, len)) != len - 1))  \
	      {                                                               \
		err = clib_error_return (                                     \
		  err, "testcase 2 failed for len %u data %u (rv %u)", len,   \
		  d, rv);                                                     \
		goto done;                                                    \
	      }                                                               \
	    data[-1] = d;                                                     \
                                                                              \
	    data[-2] = d + 1;                                                 \
	    if (len > 2 && ((rv = wfn_##type (data - len, len)) != len - 2))  \
	      {                                                               \
		err = clib_error_return (                                     \
		  err, "testcase 3 failed for len %u data %u (rv %u)", len,   \
		  d, rv);                                                     \
		goto done;                                                    \
	      }                                                               \
	    data[-2] = d;                                                     \
	  }                                                                   \
      }                                                                       \
                                                                              \
  done:                                                                       \
    clib_mem_vm_unmap (map);                                                  \
    return err;                                                               \
  }

foreach_clib_count_equal (u8);
foreach_clib_count_equal (u16);
foreach_clib_count_equal (u32);
foreach_clib_count_equal (u64);

REGISTER_TEST (clib_count_equal_u8) = {
  .name = "clib_count_equal_u8",
  .fn = test_clib_count_equal_u8,
};

REGISTER_TEST (clib_count_equal_u16) = {
  .name = "clib_count_equal_u16",
  .fn = test_clib_count_equal_u16,
};

REGISTER_TEST (clib_count_equal_u32) = {
  .name = "clib_count_equal_u32",
  .fn = test_clib_count_equal_u32,
};

REGISTER_TEST (clib_count_equal_u64) = {
  .name = "clib_count_equal_u64",
  .fn = test_clib_count_equal_u64,
};
