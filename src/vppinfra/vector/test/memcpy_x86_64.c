/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifdef __x86_64__

#include <vppinfra/format.h>
#include <vppinfra/vector/test/test.h>
#include <vppinfra/vector/mask_compare.h>

static __clib_noinline void
wrapper (u8 *dst, u8 *src, uword n)
{
  clib_memcpy_x86_64 (dst, src, n);
}

#define MAX_LEN 1024

static clib_error_t *
test_clib_memcpy_x86_64 (clib_error_t *err)
{
  u8 src[MAX_LEN + 128];
  u8 dst[MAX_LEN + 128];

  for (int i = 0; i < ARRAY_LEN (src); i++)
    src[i] = i & 0x7f;

  for (u16 n = 1; n <= MAX_LEN; n++)
    {
      for (int off = 0; off < 64; off += 7)
	{
	  u8 *d = dst + 64 + off;
	  u8 *s = src + 64;

	  for (int i = 0; i < 128 + n + off; i++)
	    dst[i] = 0xfe;

	  wrapper (d, s, n);

	  for (int i = 0; i < n; i++)
	    if (d[i] != s[i])
	      return clib_error_return (err,
					"memcpy error at position %d "
					"(n = %u, off = %u, expected 0x%02x "
					"found 0x%02x)",
					i, n, off, s[i], d[i]);
	  for (int i = -64; i < 0; i++)
	    if (d[i] != 0xfe)
	      return clib_error_return (err,
					"buffer underrun at position %d "
					"(n = %u, off = %u, expected 0xfe "
					"found 0x%02x)",
					i, n, off, d[i]);
	  for (int i = n; i < n + 64; i++)
	    if (d[i] != 0xfe)
	      return clib_error_return (err,
					"buffer overrun at position %d "
					"(n = %u, off = %u, expected 0xfe "
					"found 0x%02x)",
					i, n, off, d[i]);
	}
    }
  return err;
}

REGISTER_TEST (clib_memcpy_x86_64) = {
  .name = "clib_memcpy_x86_64",
  .fn = test_clib_memcpy_x86_64,
};
#endif
