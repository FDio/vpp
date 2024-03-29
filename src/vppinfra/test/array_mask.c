/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector/array_mask.h>

__test_funct_fn void
clib_array_mask_u32_wrapper (u32 *src, u32 mask, u32 n_elts)
{
  clib_array_mask_u32 (src, mask, n_elts);
}

typedef struct
{
  u32 mask;
  u32 expected[256];
} array_mask_test_t;

static array_mask_test_t tests[] = {
  /* mask values 0x1, output array of alternating 0 1 0 1 .. */
  { .mask = 1,
    .expected = { 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1 } },
  /* mask values 0xFFFFFFFF, output array of 0, 1, 2, .., 255 */
  { .mask = ~0U,
    .expected = { 0,   1,   2,	 3,   4,   5,	6,   7,	  8,   9,   10,	 11,
		  12,  13,  14,	 15,  16,  17,	18,  19,  20,  21,  22,	 23,
		  24,  25,  26,	 27,  28,  29,	30,  31,  32,  33,  34,	 35,
		  36,  37,  38,	 39,  40,  41,	42,  43,  44,  45,  46,	 47,
		  48,  49,  50,	 51,  52,  53,	54,  55,  56,  57,  58,	 59,
		  60,  61,  62,	 63,  64,  65,	66,  67,  68,  69,  70,	 71,
		  72,  73,  74,	 75,  76,  77,	78,  79,  80,  81,  82,	 83,
		  84,  85,  86,	 87,  88,  89,	90,  91,  92,  93,  94,	 95,
		  96,  97,  98,	 99,  100, 101, 102, 103, 104, 105, 106, 107,
		  108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		  120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
		  132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
		  144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
		  156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
		  168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
		  180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
		  192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203,
		  204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
		  216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227,
		  228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
		  240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
		  252, 253, 254, 255 } },
  /* mask values 0xF, output array of 0, .., 15, 0, .., 15, 0, .., 15 */
  { .mask = 15,
    .expected = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } },
  /* mask values 0x1, output array of 1, 0, 1, 0,.. */
  { .mask = 1, .expected = { 1, 0, 1, 0, 1, 0, 1, 0, 1, 0 } },
};

static clib_error_t *
test_clib_array_mask_u32 (clib_error_t *err)
{
  u32 i, j, len;
  for (i = 0; i < ARRAY_LEN (tests) - 1; i++)
    {
      u32 src[256];
      for (j = 0; j < ARRAY_LEN (src); j++)
	src[j] = j;

      array_mask_test_t *t = tests + i;
      clib_array_mask_u32_wrapper (src, t->mask, ARRAY_LEN (src));
      for (j = 0; j < ARRAY_LEN (src); j++)
	{
	  if (src[j] != t->expected[j])
	    return clib_error_return (err,
				      "testcase %u failed at "
				      "(src[%u] = 0x%x, expected 0x%x)",
				      i, j, src[j], t->expected[j]);
	}
    }

  for (i = 0; i < ARRAY_LEN (tests) - 1; i++)
    {
      for (len = 1; len <= 256; len++)
	{
	  u32 src[len];
	  for (j = 0; j < ARRAY_LEN (src); j++)
	    src[j] = j;

	  array_mask_test_t *t = tests + i;
	  clib_array_mask_u32_wrapper (src, t->mask, ARRAY_LEN (src));
	  for (j = 0; j < ARRAY_LEN (src); j++)
	    {
	      if (src[j] != t->expected[j])
		return clib_error_return (err,
					  "testcase %u failed at "
					  "(src[%u] = 0x%x, expected 0x%x)",
					  i, j, src[j], t->expected[j]);
	    }
	}
    }

  u32 src[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  array_mask_test_t *t = tests + i;

  clib_array_mask_u32_wrapper (src, t->mask, ARRAY_LEN (src));
  for (j = 0; j < ARRAY_LEN (src); j++)
    {
      if (src[j] != t->expected[j])
	return clib_error_return (err,
				  "testcase %u failed at "
				  "(src[%u] = 0x%x, expected 0x%x)",
				  i, j, src[j], t->expected[j]);
    }

  return err;
}

REGISTER_TEST (clib_array_mask_u32) = {
  .name = "clib_array_mask_u32",
  .fn = test_clib_array_mask_u32,
};
