/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/crc32.h>

#ifndef CLIB_MARCH_VARIANT
char *crc32c_test_string =
  "The quick brown fox jumped over the lazy dog and stumbled.";
uint32_t crc32c_test_values_data[] = {
  0x00000000, 0x96bf4dcc, 0x65479df4, 0x60a63889, 0xda99c852, 0x3337e4e2,
  0x4651af18, 0x83b586a1, 0x2235e3b5, 0x7f896b6f, 0x1f17a8f3, 0x60dc68bc,
  0x6f95458b, 0x24c5aa40, 0xe40de8f0, 0x3e344ed8, 0x798903f4, 0x73ea05e3,
  0xcfc61ead, 0xe6ed33a9, 0xfaa20d87, 0x5ce246c4, 0x4022138c, 0x111b090a,
  0x1a6b673c, 0x298d6a78, 0x5d3485d5, 0xc6c24fec, 0x91600ac3, 0x877506df,
  0xd9702ff7, 0xb7de5f4b, 0xf8f8e606, 0x905bdc1c, 0xb69298ce, 0x3b748c05,
  0x1577ee4e, 0xc19389c7, 0x842bc1c7, 0x0db915db, 0x437d7c44, 0xa61f7901,
  0x54919807, 0xeb4b5a35, 0xb0f5e17e, 0xfded9015, 0xb6ff2e82, 0xaec598e4,
  0x8258fee0, 0xc30f7e3a, 0x390ac90e, 0x1a4376fc, 0xfa5ea3c2, 0xfca2d721,
  0x52d74c9f, 0xe06c4bcd, 0x28728122, 0x67f288d5, 0
};
uint32_t *crc32c_test_values = crc32c_test_values_data;

#else
extern char *crc32c_test_string;
extern uint32_t *crc32c_test_values;
#endif

static clib_error_t *
test_clib_crc32c (clib_error_t *err)
{
  int max_len = strlen (crc32c_test_string);
  int i;
  for (i = 0; i < max_len; i++)
    {
      u32 expected_crc32c = crc32c_test_values[i];
      u32 calculated_crc32 = clib_crc32c ((u8 *) crc32c_test_string, i);
      if (expected_crc32c != calculated_crc32)
	{
	  return clib_error_return (
	    err,
	    "Bad CRC32C for test case %d: expected 0x%08x, calculated: 0x%08x",
	    i, expected_crc32c, calculated_crc32);
	}
    }
  return err;
}

REGISTER_TEST (clib_crc32c) = {
  .name = "clib_crc32c",
  .fn = test_clib_crc32c,
};
