/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <svm/svm_fifo.h>
#include <vlib/vlib.h>
#include <svm/fifo_segment.h>

#define SFIFO_TEST_I(_cond, _comment, _args...)			\
({								\
  int _evald = (_cond);						\
  if (!(_evald)) {						\
    fformat(stderr, "FAIL:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  } else {							\
    fformat(stderr, "PASS:%d: " _comment "\n",			\
	    __LINE__, ##_args);					\
  }								\
  _evald;							\
})

#define SFIFO_TEST(_cond, _comment, _args...)			\
{								\
    if (!SFIFO_TEST_I(_cond, _comment, ##_args)) {		\
	return 1;                                               \
    }								\
}

typedef struct
{
  u32 offset;
  u32 len;
} test_pattern_t;

/* *INDENT-OFF* */
test_pattern_t test_pattern[] = {
  {380, 8}, {768, 8}, {1156, 8}, {1544, 8}, {1932, 8}, {2320, 8}, {2708, 8},
  {2992, 8}, {372, 8}, {760, 8}, {1148, 8}, {1536, 8}, {1924, 8}, {2312, 8},
  {2700, 8}, {2984, 8}, {364, 8}, {752, 8}, {1140, 8}, {1528, 8}, {1916, 8},
  {2304, 8}, {2692, 8}, {2976, 8}, {356, 8}, {744, 8}, {1132, 8}, {1520, 8},
  {1908, 8}, {2296, 8}, {2684, 8}, {2968, 8}, {348, 8}, {736, 8}, {1124, 8},
  {1512, 8}, {1900, 8}, {2288, 8}, {2676, 8}, {2960, 8}, {340, 8}, {728, 8},
  {1116, 8}, {1504, 8}, {1892, 8}, {2280, 8}, {2668, 8}, {2952, 8}, {332, 8},
  {720, 8}, {1108, 8}, {1496, 8}, {1884, 8}, {2272, 8}, {2660, 8}, {2944, 8},
  {324, 8}, {712, 8}, {1100, 8}, {1488, 8}, {1876, 8}, {2264, 8}, {2652, 8},
  {2936, 8}, {316, 8}, {704, 8}, {1092, 8}, {1480, 8}, {1868, 8}, {2256, 8},
  {2644, 8}, {2928, 8}, {308, 8}, {696, 8}, {1084, 8}, {1472, 8}, {1860, 8},
  {2248, 8}, {2636, 8}, {2920, 8}, {300, 8}, {688, 8}, {1076, 8}, {1464, 8},
  {1852, 8}, {2240, 8}, {2628, 8}, {2912, 8}, {292, 8}, {680, 8}, {1068, 8},
  {1456, 8}, {1844, 8}, {2232, 8}, {2620, 8}, {2904, 8}, {284, 8}, {672, 8},
  {1060, 8}, {1448, 8}, {1836, 8}, {2224, 8}, {2612, 8}, {2896, 8}, {276, 8},
  {664, 8}, {1052, 8}, {1440, 8}, {1828, 8},  {2216, 8}, {2604, 8}, {2888, 8},
  {268, 8}, {656, 8}, {1044, 8}, {1432, 8}, {1820, 8}, {2208, 8}, {2596, 8},
  {2880, 8}, {260, 8}, {648, 8}, {1036, 8}, {1424, 8}, {1812, 8}, {2200, 8},
  {2588, 8}, {2872, 8}, {252, 8}, {640, 8}, {1028, 8}, {1416, 8}, {1804, 8},
  {2192, 8}, {2580, 8}, {2864, 8}, {244, 8}, {632, 8}, {1020, 8}, {1408, 8},
  {1796, 8}, {2184, 8}, {2572, 8}, {2856, 8}, {236, 8}, {624, 8}, {1012, 8},
  {1400, 8}, {1788, 8}, {2176, 8}, {2564, 8}, {2848, 8}, {228, 8}, {616, 8},
  {1004, 8}, {1392, 8}, {1780, 8}, {2168, 8}, {2556, 8}, {2840, 8}, {220, 8},
  {608, 8}, {996, 8}, {1384, 8}, {1772, 8}, {2160, 8}, {2548, 8}, {2832, 8},
  {212, 8}, {600, 8}, {988, 8}, {1376, 8}, {1764, 8}, {2152, 8}, {2540, 8},
  {2824, 8}, {204, 8}, {592, 8}, {980, 8}, {1368, 8}, {1756, 8}, {2144, 8},
  {2532, 8}, {2816, 8}, {196, 8}, {584, 8}, {972, 8}, {1360, 8}, {1748, 8},
  {2136, 8}, {2524, 8}, {2808, 8}, {188, 8}, {576, 8}, {964, 8}, {1352, 8},
  {1740, 8}, {2128, 8}, {2516, 8}, {2800, 8}, {180, 8}, {568, 8}, {956, 8},
  {1344, 8}, {1732, 8}, {2120, 8}, {2508, 8}, {2792, 8}, {172, 8}, {560, 8},
  {948, 8}, {1336, 8}, {1724, 8}, {2112, 8}, {2500, 8}, {2784, 8}, {164, 8},
  {552, 8}, {940, 8}, {1328, 8}, {1716, 8}, {2104, 8}, {2492, 8}, {2776, 8},
  {156, 8}, {544, 8}, {932, 8}, {1320, 8}, {1708, 8}, {2096, 8}, {2484, 8},
  {2768, 8}, {148, 8}, {536, 8}, {924, 8}, {1312, 8}, {1700, 8}, {2088, 8},
  {2476, 8}, {2760, 8}, {140, 8}, {528, 8}, {916, 8}, {1304, 8}, {1692, 8},
  {2080, 8}, {2468, 8}, {2752, 8}, {132, 8}, {520, 8}, {908, 8}, {1296, 8},
  {1684, 8}, {2072, 8}, {2460, 8}, {2744, 8}, {124, 8}, {512, 8}, {900, 8},
  {1288, 8}, {1676, 8}, {2064, 8}, {2452, 8}, {2736, 8}, {116, 8}, {504, 8},
  {892, 8}, {1280, 8}, {1668, 8}, {2056, 8}, {2444, 8}, {2728, 8}, {108, 8},
  {496, 8}, {884, 8}, {1272, 8}, {1660, 8}, {2048, 8}, {2436, 8}, {2720, 8},
  {100, 8}, {488, 8}, {876, 8}, {1264, 8}, {1652, 8}, {2040, 8}, {2428, 8},
  {2716, 4}, {92, 8}, {480, 8}, {868, 8}, {1256, 8}, {1644, 8}, {2032, 8},
  {2420, 8}, {84, 8}, {472, 8}, {860, 8}, {1248, 8}, {1636, 8}, {2024, 8},
  {2412, 8}, {76, 8}, {464, 8}, {852, 8}, {1240, 8}, {1628, 8}, {2016, 8},
  {2404, 8}, {68, 8}, {456, 8}, {844, 8}, {1232, 8}, {1620, 8}, {2008, 8},
  {2396, 8}, {60, 8}, {448, 8}, {836, 8}, {1224, 8}, {1612, 8}, {2000, 8},
  {2388, 8}, {52, 8}, {440, 8}, {828, 8}, {1216, 8}, {1604, 8}, {1992, 8},
  {2380, 8}, {44, 8}, {432, 8}, {820, 8}, {1208, 8}, {1596, 8}, {1984, 8},
  {2372, 8}, {36, 8}, {424, 8}, {812, 8}, {1200, 8}, {1588, 8}, {1976, 8},
  {2364, 8}, {28, 8}, {416, 8}, {804, 8}, {1192, 8}, {1580, 8}, {1968, 8},
  {2356, 8}, {20, 8}, {408, 8}, {796, 8}, {1184, 8}, {1572, 8}, {1960, 8},
  {2348, 8}, {12, 8}, {400, 8}, {788, 8}, {1176, 8}, {1564, 8}, {1952, 8},
  {2340, 8}, {4, 8}, {392, 8}, {780, 8}, {1168, 8}, {1556, 8}, {1944, 8},
  {2332, 8},
  /* missing from original data set */
  {388, 4}, {776, 4}, {1164, 4}, {1552, 4}, {1940, 4}, {2328, 4},
};
/* *INDENT-ON* */

int
pattern_cmp (const void *arg1, const void *arg2)
{
  test_pattern_t *a1 = (test_pattern_t *) arg1;
  test_pattern_t *a2 = (test_pattern_t *) arg2;

  if (a1->offset < a2->offset)
    return -1;
  else if (a1->offset > a2->offset)
    return 1;
  return 0;
}

static u8
fifo_validate_pattern (vlib_main_t * vm, test_pattern_t * pattern,
		       u32 pattern_length)
{
  test_pattern_t *tp = pattern;
  int i;

  /* Go through the pattern and make 100% sure it's sane */
  for (i = 0; i < pattern_length - 1; i++)
    {
      if (tp->offset + tp->len != (tp + 1)->offset)
	{
	  vlib_cli_output (vm, "[%d] missing {%d, %d}", i,
			   (tp->offset + tp->len),
			   (tp + 1)->offset - (tp->offset + tp->len));
	  return 0;
	}
      tp++;
    }
  return 1;
}

static test_pattern_t *
fifo_get_validate_pattern (vlib_main_t * vm, test_pattern_t * test_data,
			   u32 test_data_len)
{
  test_pattern_t *validate_pattern = 0;

  /* Validate, and try segments in order... */
  vec_validate (validate_pattern, test_data_len - 1);
  memcpy (validate_pattern, test_data,
	  test_data_len * sizeof (test_pattern_t));
  qsort ((u8 *) validate_pattern, test_data_len, sizeof (test_pattern_t),
	 pattern_cmp);

  if (fifo_validate_pattern (vm, validate_pattern, test_data_len) == 0)
    return 0;

  return validate_pattern;
}

static svm_fifo_t *
fifo_prepare (u32 fifo_size)
{
  svm_fifo_t *f;
  f = svm_fifo_create (fifo_size);

  /* Paint fifo data vector with -1's */
  clib_memset (f->head_chunk->data, 0xFF, fifo_size);

  return f;
}

static int
compare_data (u8 * data1, u8 * data2, u32 start, u32 len, u32 * index)
{
  int i;

  for (i = start; i < start + len; i++)
    {
      if (data1[i] != data2[i])
	{
	  *index = i;
	  return 1;
	}
    }
  return 0;
}

int
sfifo_test_fifo1 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 1 << 20;
  u32 *test_data = 0;
  u32 offset;
  int i, rv, verbose = 0;
  u32 data_word, test_data_len, j;
  ooo_segment_t *ooo_seg;
  u8 *data, *s, *data_buf = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
    }

  test_data_len = fifo_size / sizeof (u32);
  vec_validate (test_data, test_data_len - 1);

  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i;

  f = fifo_prepare (fifo_size);

  /*
   * Enqueue an initial (un-dequeued) chunk
   */
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) test_data);
  SFIFO_TEST ((rv == sizeof (u32)), "enqueued %d", rv);
  SFIFO_TEST ((f->tail == 4), "fifo tail %u", f->tail);

  /*
   * Create 3 chunks in the future. The offsets are relative
   * to the current fifo tail
   */
  for (i = 0; i < 3; i++)
    {
      offset = (2 * i + 1) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 1));
      if (i == 0)
	{
	  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), data);
	  rv = rv > 0 ? 0 : rv;
	}
      else
	rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i + 1, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  if (verbose)
    vlib_cli_output (vm, "fifo after odd segs: %U", format_svm_fifo, f, 1);

  SFIFO_TEST ((f->tail == 8), "fifo tail %u", f->tail);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 2),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  /*
   * Try adding a completely overlapped segment
   */
  offset = 3 * sizeof (u32) - f->tail;
  data = (u8 *) (test_data + 3);
  rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
  if (rv)
    {
      clib_warning ("enqueue returned %d", rv);
      goto err;
    }

  if (verbose)
    vlib_cli_output (vm, "fifo after overlap seg: %U", format_svm_fifo, f, 1);

  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 2),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  /*
   * Make sure format functions are not buggy
   */
  s = format (0, "%U", format_svm_fifo, f, 2);
  vec_free (s);

  /*
   * Paint some of missing data backwards
   */
  for (i = 3; i > 1; i--)
    {
      offset = (2 * i + 0) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 0));
      rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  if (verbose)
    vlib_cli_output (vm, "fifo before missing link: %U", format_svm_fifo, f,
		     1);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 12),
	      "first ooo seg position %u", ooo_seg->start);
  SFIFO_TEST ((ooo_seg->length == 16),
	      "first ooo seg length %u", ooo_seg->length);

  /*
   * Enqueue the missing u32
   */
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) (test_data + 2));
  if (verbose)
    vlib_cli_output (vm, "fifo after missing link: %U", format_svm_fifo, f,
		     1);
  SFIFO_TEST ((rv == 20), "bytes to be enqueued %u", rv);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  /*
   * Collect results
   */
  for (i = 0; i < 7; i++)
    {
      rv = svm_fifo_dequeue_nowait (f, sizeof (u32), (u8 *) & data_word);
      if (rv != sizeof (u32))
	{
	  clib_warning ("bytes dequeues %u", rv);
	  goto err;
	}
      if (data_word != test_data[i])
	{
	  clib_warning ("recovered [%d] %d not %d", i, data_word,
			test_data[i]);
	  goto err;
	}
    }

  /*
   * Test segment overlaps: last ooo segment overlaps all
   */
  svm_fifo_free (f);
  f = fifo_prepare (fifo_size);

  for (i = 0; i < 4; i++)
    {
      offset = (2 * i + 1) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 1));
      rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i + 1, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  rv = svm_fifo_enqueue_with_offset (f, 8 - f->tail, 21, data);
  SFIFO_TEST ((rv == 0), "ooo enqueued %u", rv);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  /* add missing data to be able to dequeue something */
  rv = svm_fifo_enqueue_nowait (f, 4, data);
  SFIFO_TEST ((rv == 32), "enqueued %u", rv);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  vec_validate (data_buf, vec_len (test_data));
  svm_fifo_peek (f, 0, 4, data_buf);
  if (compare_data (data_buf, data, 0, 4, &j))
    SFIFO_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j], data[j]);
  svm_fifo_peek (f, 8, 21, data_buf);
  if (compare_data (data_buf, data, 0, 21, &j))
    SFIFO_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j], data[j]);
  vec_reset_length (data_buf);

  /*
   * Test segment overlaps: enqueue and overlap ooo segments
   */
  svm_fifo_free (f);
  f = fifo_prepare (fifo_size);

  for (i = 0; i < 4; i++)
    {
      offset = (2 * i + 1) * sizeof (u32) - f->tail;
      data = (u8 *) (test_data + (2 * i + 1));
      rv = svm_fifo_enqueue_with_offset (f, offset, sizeof (u32), data);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", 2 * i + 1, offset,
			 offset + sizeof (u32));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto err;
	}
    }

  if (verbose)
    vlib_cli_output (vm, "fifo after enqueue: %U", format_svm_fifo, f, 1);

  rv = svm_fifo_enqueue_nowait (f, 29, data);
  if (verbose)
    vlib_cli_output (vm, "fifo after enqueueing 29: %U", format_svm_fifo, f,
		     1);
  SFIFO_TEST ((rv == 32), "ooo enqueued %u", rv);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  vec_validate (data_buf, vec_len (data));
  svm_fifo_peek (f, 0, vec_len (data), data_buf);
  if (compare_data (data_buf, data, 0, vec_len (data), &j))
    {
      SFIFO_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j], data[j]);
    }

  /* Try to peek beyond the data */
  rv = svm_fifo_peek (f, svm_fifo_max_dequeue (f), vec_len (data), data_buf);
  SFIFO_TEST ((rv == 0), "peeked %u expected 0", rv);

  vec_free (data_buf);
  svm_fifo_free (f);
  vec_free (test_data);

  return 0;

err:
  svm_fifo_free (f);
  vec_free (test_data);
  return -1;
}

static int
sfifo_test_fifo2 (vlib_main_t * vm)
{
  svm_fifo_t *f;
  u32 fifo_size = (1 << 20) + 1;
  int i, rv, test_data_len;
  u64 data64;
  test_pattern_t *tp, *vp, *test_data;
  ooo_segment_t *ooo_seg;

  test_data = test_pattern;
  test_data_len = ARRAY_LEN (test_pattern);

  vp = fifo_get_validate_pattern (vm, test_data, test_data_len);

  /* Create a fifo */
  f = fifo_prepare (fifo_size);

  /*
   * Try with sorted data
   */
  for (i = 0; i < test_data_len; i++)
    {
      tp = vp + i;
      data64 = tp->offset;
      svm_fifo_enqueue_with_offset (f, tp->offset - f->tail, tp->len,
				    (u8 *) & data64);
    }

  /* Expected result: one big fat chunk at offset 4 */
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 4),
	      "first ooo seg position %u", ooo_seg->start);
  SFIFO_TEST ((ooo_seg->length == 2996),
	      "first ooo seg length %u", ooo_seg->length);

  data64 = 0;
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) & data64);
  SFIFO_TEST ((rv == 3000), "bytes to be enqueued %u", rv);

  svm_fifo_free (f);
  vec_free (vp);

  /*
   * Now try it again w/ unsorted data...
   */

  f = fifo_prepare (fifo_size);

  for (i = 0; i < test_data_len; i++)
    {
      tp = &test_data[i];
      data64 = tp->offset;
      rv = svm_fifo_enqueue_with_offset (f, tp->offset - f->tail, tp->len,
					 (u8 *) & data64);
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	}
    }

  /* Expecting the same result: one big fat chunk at offset 4 */
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 4),
	      "first ooo seg position %u", ooo_seg->start);
  SFIFO_TEST ((ooo_seg->length == 2996),
	      "first ooo seg length %u", ooo_seg->length);

  data64 = 0;
  rv = svm_fifo_enqueue_nowait (f, sizeof (u32), (u8 *) & data64);

  SFIFO_TEST ((rv == 3000), "bytes to be enqueued %u", rv);

  svm_fifo_free (f);

  return 0;
}

static int
sfifo_test_fifo3 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = (4 << 10) + 1;
  u32 fifo_initial_offset = 0;
  u32 total_size = 2 << 10;
  int overlap = 0, verbose = 0, randomize = 1, drop = 0, in_seq_all = 0;
  u8 *data_pattern = 0, *data_buf = 0;
  test_pattern_t *tp, *generate = 0;
  u32 nsegs = 2, seg_size, length_so_far;
  u32 current_offset, offset_increment, len_this_chunk;
  u32 seed = 0xdeaddabe, j;
  int i, rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fifo-size %d", &fifo_size))
	;
      else if (unformat (input, "total-size %d", &total_size))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "overlap"))
	overlap = 1;
      else if (unformat (input, "initial-offset %d", &fifo_initial_offset))
	;
      else if (unformat (input, "seed %d", &seed))
	;
      else if (unformat (input, "nsegs %d", &nsegs))
	;
      else if (unformat (input, "no-randomize"))
	randomize = 0;
      else if (unformat (input, "in-seq-all"))
	in_seq_all = 1;
      else if (unformat (input, "drop"))
	drop = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

  if (total_size > fifo_size)
    {
      clib_warning ("total_size %d greater than fifo size %d", total_size,
		    fifo_size);
      return -1;
    }
  if (overlap && randomize == 0)
    {
      clib_warning ("Can't enqueue in-order with overlap");
      return -1;
    }

  /*
   * Generate data
   */
  vec_validate (data_pattern, total_size - 1);
  for (i = 0; i < vec_len (data_pattern); i++)
    data_pattern[i] = i & 0xff;

  /*
   * Generate segments
   */
  seg_size = total_size / nsegs;
  length_so_far = 0;
  current_offset = randomize;
  while (length_so_far < total_size)
    {
      vec_add2 (generate, tp, 1);
      len_this_chunk = clib_min (seg_size, total_size - length_so_far);
      tp->offset = current_offset;
      tp->len = len_this_chunk;

      if (overlap && (len_this_chunk == seg_size))
	do
	  {
	    offset_increment = len_this_chunk
	      % (1 + (random_u32 (&seed) % len_this_chunk));
	  }
	while (offset_increment == 0);
      else
	offset_increment = len_this_chunk;

      current_offset += offset_increment;
      length_so_far = tp->offset + tp->len;
    }

  /*
   * Validate segment list. Only valid for non-overlap cases.
   */
  if (overlap == 0)
    fifo_validate_pattern (vm, generate, vec_len (generate));

  if (verbose)
    {
      vlib_cli_output (vm, "raw data pattern:");
      for (i = 0; i < vec_len (generate); i++)
	{
	  vlib_cli_output (vm, "[%d] offset %u len %u", i,
			   generate[i].offset, generate[i].len);
	}
    }

  /* Randomize data pattern */
  if (randomize)
    {
      for (i = 0; i < vec_len (generate) / 2; i++)
	{
	  u32 src_index, dst_index;
	  test_pattern_t _tmp, *tmp = &_tmp;

	  src_index = random_u32 (&seed) % vec_len (generate);
	  dst_index = random_u32 (&seed) % vec_len (generate);

	  tmp[0] = generate[dst_index];
	  generate[dst_index] = generate[src_index];
	  generate[src_index] = tmp[0];
	}
      if (verbose)
	{
	  vlib_cli_output (vm, "randomized data pattern:");
	  for (i = 0; i < vec_len (generate); i++)
	    {
	      vlib_cli_output (vm, "[%d] offset %u len %u", i,
			       generate[i].offset, generate[i].len);
	    }
	}
    }

  /*
   * Create a fifo and add segments
   */
  f = fifo_prepare (fifo_size);

  /* manually set head and tail pointers to validate modular arithmetic */
  fifo_initial_offset = fifo_initial_offset % fifo_size;
  svm_fifo_init_pointers (f, fifo_initial_offset, fifo_initial_offset);

  for (i = !randomize; i < vec_len (generate); i++)
    {
      tp = generate + i;
      svm_fifo_enqueue_with_offset (f,
				    fifo_initial_offset + tp->offset -
				    f->tail, tp->len,
				    (u8 *) data_pattern + tp->offset);
    }

  /* Add the first segment in order for non random data */
  if (!randomize)
    svm_fifo_enqueue_nowait (f, generate[0].len, (u8 *) data_pattern);

  /*
   * Expected result: one big fat chunk at offset 1 if randomize == 1
   */

  if (verbose)
    vlib_cli_output (vm, "fifo before missing link: %U",
		     format_svm_fifo, f, 1 /* verbose */ );

  /*
   * Add the missing byte if segments were randomized
   */
  if (randomize)
    {
      u32 bytes_to_enq = 1;
      if (in_seq_all)
	bytes_to_enq = total_size;
      rv = svm_fifo_enqueue_nowait (f, bytes_to_enq, data_pattern + 0);

      if (verbose)
	vlib_cli_output (vm, "in-order enqueue returned %d", rv);

      SFIFO_TEST ((rv == total_size), "enqueued %u expected %u", rv,
		  total_size);

    }

  SFIFO_TEST ((svm_fifo_has_ooo_data (f) == 0), "number of ooo segments %u",
	      svm_fifo_number_ooo_segments (f));

  /*
   * Test if peeked data is the same as original data
   */
  vec_validate (data_buf, vec_len (data_pattern));
  svm_fifo_peek (f, 0, vec_len (data_pattern), data_buf);
  if (compare_data (data_buf, data_pattern, 0, vec_len (data_pattern), &j))
    {
      SFIFO_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j],
		  data_pattern[j]);
    }
  vec_reset_length (data_buf);

  /*
   * Dequeue or drop all data
   */
  if (drop)
    {
      svm_fifo_dequeue_drop (f, vec_len (data_pattern));
    }
  else
    {
      svm_fifo_dequeue_nowait (f, vec_len (data_pattern), data_buf);
      if (compare_data
	  (data_buf, data_pattern, 0, vec_len (data_pattern), &j))
	{
	  SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		      data_pattern[j]);
	}
    }

  SFIFO_TEST ((svm_fifo_max_dequeue (f) == 0), "fifo has %d bytes",
	      svm_fifo_max_dequeue (f));

  svm_fifo_free (f);
  vec_free (data_pattern);
  vec_free (data_buf);

  return 0;
}

static int
sfifo_test_fifo4 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 6 << 10;
  u32 fifo_initial_offset = 1000000000;
  u32 test_n_bytes = 5000, j;
  u8 *test_data = 0, *data_buf = 0;
  int i, rv, verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

  /*
   * Create a fifo and add segments
   */
  f = fifo_prepare (fifo_size);

  /* Set head and tail pointers */
  fifo_initial_offset = fifo_initial_offset % fifo_size;
  svm_fifo_init_pointers (f, fifo_initial_offset, fifo_initial_offset);

  vec_validate (test_data, test_n_bytes - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i;

  for (i = test_n_bytes - 1; i > 0; i--)
    {
      rv = svm_fifo_enqueue_with_offset (f, fifo_initial_offset + i - f->tail,
					 sizeof (u8), &test_data[i]);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", i, i, i + sizeof (u8));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  svm_fifo_free (f);
	  vec_free (test_data);
	  return -1;
	}
    }

  svm_fifo_enqueue_nowait (f, sizeof (u8), &test_data[0]);

  vec_validate (data_buf, vec_len (test_data));

  svm_fifo_dequeue_nowait (f, vec_len (test_data), data_buf);
  rv = compare_data (data_buf, test_data, 0, vec_len (test_data), &j);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", j, data_buf[j],
		     test_data[j]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  svm_fifo_free (f);
  vec_free (test_data);
  return 0;
}

static u32
fifo_pos (svm_fifo_t * f, u32 pos)
{
  return pos;
}

/* Avoids exposing svm_fifo.c internal function */
static ooo_segment_t *
ooo_seg_next (svm_fifo_t * f, ooo_segment_t * s)
{
  if (pool_is_free_index (f->ooo_segments, s->next))
    return 0;
  return pool_elt_at_index (f->ooo_segments, s->next);
}

static int
sfifo_test_fifo5 (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t *f;
  u32 fifo_size = 401, j = 0, offset = 200;
  int i, rv, verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  ooo_segment_t *ooo_seg;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  clib_error_t *e = clib_error_return (0, "unknown input `%U'",
					       format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

  f = fifo_prepare (fifo_size);
  svm_fifo_init_pointers (f, offset, offset);

  vec_validate (test_data, 399);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  /*
   * Start with [100, 200] and [300, 400]
   */
  svm_fifo_enqueue_with_offset (f, 100, 100, &test_data[100]);
  svm_fifo_enqueue_with_offset (f, 300, 100, &test_data[300]);

  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 2),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  SFIFO_TEST ((f->ooos_newest == 1), "newest %u", f->ooos_newest);
  if (verbose)
    vlib_cli_output (vm, "fifo after [100, 200] and [300, 400] : %U",
		     format_svm_fifo, f, 2 /* verbose */ );

  /*
   * Add [225, 275]
   */

  rv = svm_fifo_enqueue_with_offset (f, 225, 50, &test_data[225]);
  if (verbose)
    vlib_cli_output (vm, "fifo after [225, 275] : %U",
		     format_svm_fifo, f, 2 /* verbose */ );
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 3),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == fifo_pos (f, 100 + offset)),
	      "first seg start %u expected %u", ooo_seg->start,
	      fifo_pos (f, 100 + offset));
  SFIFO_TEST ((ooo_seg->length == 100), "first seg length %u expected %u",
	      ooo_seg->length, 100);
  ooo_seg = ooo_seg_next (f, ooo_seg);
  SFIFO_TEST ((ooo_seg->start == fifo_pos (f, 225 + offset)),
	      "second seg start %u expected %u",
	      ooo_seg->start, fifo_pos (f, 225 + offset));
  SFIFO_TEST ((ooo_seg->length == 50), "second seg length %u expected %u",
	      ooo_seg->length, 50);
  ooo_seg = ooo_seg_next (f, ooo_seg);
  SFIFO_TEST ((ooo_seg->start == fifo_pos (f, 300 + offset)),
	      "third seg start %u expected %u",
	      ooo_seg->start, fifo_pos (f, 300 + offset));
  SFIFO_TEST ((ooo_seg->length == 100), "third seg length %u expected %u",
	      ooo_seg->length, 100);
  SFIFO_TEST ((f->ooos_newest == 2), "newest %u", f->ooos_newest);
  /*
   * Add [190, 310]
   */
  rv = svm_fifo_enqueue_with_offset (f, 190, 120, &test_data[190]);
  if (verbose)
    vlib_cli_output (vm, "fifo after [190, 310] : %U",
		     format_svm_fifo, f, 1 /* verbose */ );
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == fifo_pos (f, offset + 100)),
	      "first seg start %u expected %u",
	      ooo_seg->start, fifo_pos (f, offset + 100));
  SFIFO_TEST ((ooo_seg->length == 300), "first seg length %u expected %u",
	      ooo_seg->length, 300);

  /*
   * Add [0, 150]
   */
  rv = svm_fifo_enqueue_nowait (f, 150, test_data);

  if (verbose)
    vlib_cli_output (vm, "fifo after [0 150] : %U", format_svm_fifo, f,
		     2 /* verbose */ );

  SFIFO_TEST ((rv == 400), "managed to enqueue %u expected %u", rv, 400);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));

  vec_validate (data_buf, 399);
  svm_fifo_peek (f, 0, 400, data_buf);
  if (compare_data (data_buf, test_data, 0, 400, &j))
    {
      SFIFO_TEST (0, "[%d] peeked %u expected %u", j, data_buf[j],
		  test_data[j]);
    }

  /*
   * Add [100 200] and overlap it with [50 250]
   */
  svm_fifo_free (f);
  f = fifo_prepare (fifo_size);

  svm_fifo_enqueue_with_offset (f, 100, 100, &test_data[100]);
  svm_fifo_enqueue_with_offset (f, 50, 200, &test_data[50]);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 50), "first seg start %u expected %u",
	      ooo_seg->start, 50);
  SFIFO_TEST ((ooo_seg->length == 200), "first seg length %u expected %u",
	      ooo_seg->length, 200);

  svm_fifo_free (f);
  vec_free (test_data);
  return 0;
}

/*
 * Test ooo head/tail u32 wrapping
 */
static int
sfifo_test_fifo6 (vlib_main_t * vm, unformat_input_t * input)
{
  u32 fifo_size = 101, n_test_bytes = 100;
  int i, j, rv, __clib_unused verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  ooo_segment_t *ooo_seg;
  svm_fifo_t *f;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  f = fifo_prepare (fifo_size);
  vec_validate (test_data, n_test_bytes - 1);
  vec_validate (data_buf, n_test_bytes - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  /*
   * Test ooo segment distance to/from tail with u32 wrap
   */

  /*
   * |0|---[start]--(len5)-->|0|--(len6)-->[end]---|0|
   */
  rv = ooo_segment_distance_to_tail (f, ~0 - 5, 5);
  SFIFO_TEST (rv == 11, "distance to tail should be %u is %u", 11, rv);

  rv = ooo_segment_distance_from_tail (f, ~0 - 5, 5);
  SFIFO_TEST (rv == f->size - 11, "distance from tail should be %u is %u",
	      f->size - 11, rv);

  /*
   * |0|---[end]--(len5)-->|0|--(len6)-->[start]---|0|
   */
  rv = ooo_segment_distance_from_tail (f, 5, ~0 - 5);
  SFIFO_TEST (rv == 11, "distance from tail should be %u is %u", 11, rv);

  rv = ooo_segment_distance_to_tail (f, 5, ~0 - 5);
  SFIFO_TEST (rv == f->size - 11, "distance to tail should be %u is %u",
	      f->size - 11, rv);

  /*
   * Add ooo with tail and ooo segment start u32 wrap
   */
  svm_fifo_init_pointers (f, ~0, ~0);
  svm_fifo_enqueue_with_offset (f, 10, 10, &test_data[10]);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  rv = ooo_segment_offset_prod (f, ooo_seg);
  SFIFO_TEST (rv == 10, "offset should be %u is %u", 10, rv);

  svm_fifo_enqueue_nowait (f, 10, test_data);
  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  SFIFO_TEST (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX,
	      "there should be no ooo seg");

  svm_fifo_peek (f, 5, 10, &data_buf[5]);
  if (compare_data (data_buf, test_data, 5, 10, (u32 *) & j))
    SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		test_data[j]);

  svm_fifo_dequeue_nowait (f, 20, data_buf);
  if (compare_data (data_buf, test_data, 0, 20, (u32 *) & j))
    SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		test_data[j]);

  /*
   * Force collect with tail u32 wrap and without ooo segment start u32 wrap
   */
  svm_fifo_init_pointers (f, ~0 - 10, ~0 - 10);
  svm_fifo_enqueue_with_offset (f, 5, 15, &test_data[5]);
  svm_fifo_enqueue_nowait (f, 12, test_data);

  SFIFO_TEST ((svm_fifo_number_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_number_ooo_segments (f));
  SFIFO_TEST (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX,
	      "there should be no ooo seg");

  svm_fifo_dequeue_nowait (f, 20, data_buf);
  if (compare_data (data_buf, test_data, 0, 20, (u32 *) & j))
    SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		test_data[j]);

  /*
   * Cleanup
   */
  vec_free (test_data);
  vec_free (data_buf);
  svm_fifo_free (f);
  return 0;
}

/*
 * Multiple ooo enqueues and dequeues that force fifo tail/head wrap
 */
static int
sfifo_test_fifo7 (vlib_main_t * vm, unformat_input_t * input)
{
  u32 fifo_size = 101, n_iterations = 100;
  int i, j, rv, __clib_unused verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  u64 n_test_bytes = 100;
  svm_fifo_t *f;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  /*
   * Prepare data structures
   */
  f = fifo_prepare (fifo_size);
  svm_fifo_init_pointers (f, ~0, ~0);

  vec_validate (test_data, n_test_bytes - 1);
  vec_validate (data_buf, n_test_bytes - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  /*
   * Run n iterations of test
   */
  for (i = 0; i < n_iterations; i++)
    {
      for (j = n_test_bytes - 1; j > 0; j -= 2)
	{
	  svm_fifo_enqueue_with_offset (f, j, 1, &test_data[j]);
	  rv = svm_fifo_number_ooo_segments (f);
	  if (rv != (n_test_bytes - j) / 2 + 1)
	    SFIFO_TEST (0, "number of ooo segments expected %u is %u",
			(n_test_bytes - j) / 2 + 1, rv);
	}

      svm_fifo_enqueue_with_offset (f, 1, n_test_bytes - 1, &test_data[1]);
      rv = svm_fifo_number_ooo_segments (f);
      if (rv != 1)
	SFIFO_TEST (0, "number of ooo segments %u", rv);

      svm_fifo_enqueue_nowait (f, 1, test_data);
      rv = svm_fifo_number_ooo_segments (f);
      if (rv != 0)
	SFIFO_TEST (0, "number of ooo segments %u", rv);

      svm_fifo_dequeue_nowait (f, n_test_bytes, data_buf);
      if (compare_data (data_buf, test_data, 0, n_test_bytes, (u32 *) & j))
	SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		    test_data[j]);
      svm_fifo_init_pointers (f, ~0 - i, ~0 - i);
    }
  SFIFO_TEST (1, "passed multiple ooo enqueue/dequeue");

  /*
   * Cleanup
   */
  vec_free (test_data);
  vec_free (data_buf);
  svm_fifo_free (f);
  return 0;
}

/*
 * Enqueue more than 4GB
 */
static int
sfifo_test_fifo_large (vlib_main_t * vm, unformat_input_t * input)
{
  u32 n_iterations = 100, n_bytes_per_iter, half;
  int i, j, rv, __clib_unused verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  u64 n_test_bytes = 100;
  svm_fifo_t *f;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }


  n_test_bytes = 5ULL << 30;
  n_iterations = 1 << 10;
  n_bytes_per_iter = n_test_bytes / n_iterations;

  f = fifo_prepare (n_bytes_per_iter + 1);
  svm_fifo_init_pointers (f, ~0, ~0);

  vec_validate (test_data, n_bytes_per_iter - 1);
  vec_validate (data_buf, n_bytes_per_iter - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  half = n_bytes_per_iter / 2;
  for (i = 0; i < n_iterations; i++)
    {
      svm_fifo_enqueue_with_offset (f, half, half, &test_data[half]);
      svm_fifo_enqueue_nowait (f, half, test_data);
      rv = svm_fifo_number_ooo_segments (f);
      if (rv != 0)
	SFIFO_TEST (0, "number of ooo segments %u", rv);
      svm_fifo_dequeue_nowait (f, n_bytes_per_iter, data_buf);
      if (compare_data (data_buf, test_data, 0, n_bytes_per_iter,
			(u32 *) & j))
	SFIFO_TEST (0, "[%d][%d] dequeued %u expected %u", i, j, data_buf[j],
		    test_data[j]);
    }
  SFIFO_TEST (1, "passed large transfer");

  return 0;
}

static int
sfifo_test_fifo_grow (vlib_main_t * vm, unformat_input_t * input)
{
  int verbose = 0, fifo_size = 201, start_offset = 100, i, j, rv;
  int test_n_bytes, deq_bytes, enq_bytes, n_deqs, n_enqs;
  svm_fifo_chunk_t *c, *next, *prev;
  u8 *test_data = 0, *data_buf = 0;
  svm_fifo_t *f;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }

  f = fifo_prepare (fifo_size);
  svm_fifo_init_pointers (f, start_offset, start_offset);

  /*
   * Add with fifo not wrapped
   */
  c = clib_mem_alloc (sizeof (svm_fifo_chunk_t) + 100);
  c->length = 100;
  c->start_byte = ~0;
  c->next = 0;

  svm_fifo_add_chunk (f, c);

  SFIFO_TEST (f->size == fifo_size + 100, "size expected %u is %u",
	      fifo_size + 100, f->size);
  SFIFO_TEST (c->start_byte == fifo_size, "start byte expected %u is %u",
	      fifo_size, c->start_byte);

  /*
   *  Add with fifo wrapped
   */

  svm_fifo_init_pointers (f, f->nitems - 100, f->nitems + 100);
  c = clib_mem_alloc (sizeof (svm_fifo_chunk_t) + 100);
  c->length = 100;
  c->start_byte = ~0;
  c->next = 0;

  svm_fifo_add_chunk (f, c);

  SFIFO_TEST (f->end_chunk != c, "tail chunk should not be updated");
  SFIFO_TEST (f->size == fifo_size + 100, "size expected %u is %u",
	      fifo_size + 100, f->size);
  SFIFO_TEST (c->start_byte == fifo_size + 100, "start byte expected %u is "
	      " %u", fifo_size + 100, c->start_byte);

  /*
   * Unwrap fifo
   */
  vec_validate (data_buf, 200);
  svm_fifo_dequeue_nowait (f, 201, data_buf);

  SFIFO_TEST (f->end_chunk == c, "tail chunk should be updated");
  SFIFO_TEST (f->size == fifo_size + 200, "size expected %u is %u",
	      fifo_size + 200, f->size);
  SFIFO_TEST (c->start_byte == fifo_size + 100, "start byte expected %u is "
	      "%u", fifo_size + 100, c->start_byte);

  /*
   * Add N chunks
   */
  svm_fifo_init_pointers (f, f->nitems - 100, f->nitems + 100);

  prev = 0;
  for (i = 0; i < 5; i++)
    {
      c = clib_mem_alloc (sizeof (svm_fifo_chunk_t) + 100);
      c->length = 100;
      c->start_byte = ~0;
      c->next = prev;
      prev = c;
    }

  svm_fifo_add_chunk (f, c);
  SFIFO_TEST (f->size == fifo_size + 200, "size expected %u is %u",
	      fifo_size + 200, f->size);

  prev = 0;
  for (i = 0; i < 5; i++)
    {
      c = clib_mem_alloc (sizeof (svm_fifo_chunk_t) + 100);
      c->length = 100;
      c->start_byte = ~0;
      c->next = prev;
      prev = c;
    }

  svm_fifo_add_chunk (f, c);
  SFIFO_TEST (f->size == fifo_size + 200, "size expected %u is %u",
	      fifo_size + 200, f->size);

  svm_fifo_dequeue_nowait (f, 201, data_buf);

  SFIFO_TEST (f->size == fifo_size + 200 + 10 * 100, "size expected %u is %u",
	      fifo_size + 200 + 10 * 100, f->size);
  /*
   * Enqueue/dequeue tests
   */

  test_n_bytes = f->nitems;
  vec_validate (test_data, test_n_bytes - 1);
  vec_validate (data_buf, vec_len (test_data));
  n_deqs = n_enqs = 6;
  deq_bytes = enq_bytes = vec_len (test_data) / n_deqs;

  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i;

  /*
   * Enqueue/deq boundary conditions
   */
  svm_fifo_init_pointers (f, 201, 201);
  SFIFO_TEST (f->tail_chunk->start_byte == 201, "start byte expected %u is "
	      "%u", 201, f->tail_chunk->start_byte);

  svm_fifo_enqueue_nowait (f, 200, test_data);
  SFIFO_TEST (f->tail_chunk->start_byte == 401, "start byte expected %u is "
	      "%u", 401, f->tail_chunk->start_byte);

  svm_fifo_dequeue_nowait (f, 200, data_buf);
  SFIFO_TEST (f->head_chunk->start_byte == 401, "start byte expected %u is "
	      "%u", 401, f->head_chunk->start_byte);

  /*
   * Simple enqueue/deq and data validation (1)
   */
  svm_fifo_init_pointers (f, f->nitems / 2, f->nitems / 2);
  for (i = 0; i < test_n_bytes; i++)
    {
      rv = svm_fifo_enqueue_nowait (f, sizeof (u8), &test_data[i]);
      if (rv < 0)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto cleanup;
	}
    }

  SFIFO_TEST (svm_fifo_max_dequeue (f) == test_n_bytes, "max deq expected %u "
	      "is %u", test_n_bytes, svm_fifo_max_dequeue (f));

  for (i = 0; i < test_n_bytes; i++)
    svm_fifo_dequeue_nowait (f, 1, &data_buf[i]);

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & j);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", j, data_buf[j],
		     test_data[j]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  /*
   * Simple enqueue/deq and data validation (2)
   */
  for (i = 0; i <= n_enqs; i++)
    {
      rv = svm_fifo_enqueue_nowait (f, enq_bytes, test_data + i * enq_bytes);
      if (rv < 0)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto cleanup;
	}
    }

  SFIFO_TEST (svm_fifo_max_dequeue (f) == test_n_bytes, "max deq expected %u "
	      "is %u", test_n_bytes, svm_fifo_max_dequeue (f));

  for (i = 0; i <= n_deqs; i++)
    svm_fifo_dequeue_nowait (f, deq_bytes, data_buf + i * deq_bytes);

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & j);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", j, data_buf[j],
		     test_data[j]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  /*
   * OOO enqueues/dequeues and data validation (1)
   */
  for (i = test_n_bytes - 1; i > 0; i--)
    {
      rv = svm_fifo_enqueue_with_offset (f, i, sizeof (u8), &test_data[i]);
      if (verbose)
	vlib_cli_output (vm, "add [%d] [%d, %d]", i, i, i + sizeof (u8));
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto cleanup;
	}
    }

  SFIFO_TEST (svm_fifo_max_dequeue (f) == 0, "max deq expected %u is %u",
	      0, svm_fifo_max_dequeue (f));

  svm_fifo_enqueue_nowait (f, sizeof (u8), &test_data[0]);

  memset (data_buf, 0, vec_len (data_buf));
  for (i = 0; i <= n_deqs; i++)
    svm_fifo_dequeue_nowait (f, deq_bytes, data_buf + i * deq_bytes);

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & j);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", j, data_buf[j],
		     test_data[j]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  /*
   * OOO enqueues/dequeues and data validation (2)
   */

  for (i = n_enqs; i > 0; i--)
    {
      u32 enq_now = clib_min (enq_bytes, vec_len (test_data) - i * enq_bytes);
      rv = svm_fifo_enqueue_with_offset (f, i * enq_bytes, enq_now,
					 test_data + i * enq_bytes);
      if (verbose)
	vlib_cli_output (vm, "add [%d, %d]", i * enq_bytes,
			 i * enq_bytes + enq_now);
      if (rv)
	{
	  clib_warning ("enqueue returned %d", rv);
	  goto cleanup;
	}
    }

  svm_fifo_enqueue_nowait (f, enq_bytes, &test_data[0]);

  memset (data_buf, 0, vec_len (data_buf));
  for (i = 0; i <= n_deqs; i++)
    svm_fifo_dequeue_nowait (f, deq_bytes, data_buf + i * deq_bytes);

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & j);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", j, data_buf[j],
		     test_data[j]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  /*
   * Cleanup
   */

cleanup:

  c = f->start_chunk->next;
  while (c && c != f->start_chunk)
    {
      next = c->next;
      clib_mem_free (c);
      c = next;
    }

  svm_fifo_free (f);

  vec_free (data_buf);
  return 0;
}

/* *INDENT-OFF* */
svm_fifo_trace_elem_t fifo_trace[] = {};
/* *INDENT-ON* */

static int
sfifo_test_fifo_replay (vlib_main_t * vm, unformat_input_t * input)
{
  svm_fifo_t f;
  int verbose = 0;
  u8 no_read = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "no-read"))
	no_read = 1;
      else
	{
	  clib_error_t *e = clib_error_return
	    (0, "unknown input `%U'", format_unformat_error, input);
	  clib_error_report (e);
	  return -1;
	}
    }

#if SVMF_FIFO_TRACE
  f.trace = fifo_trace;
#endif

  str = svm_fifo_replay (str, &f, no_read, verbose);
  vlib_cli_output (vm, "%v", str);
  return 0;
}

static fifo_segment_main_t segment_main;

static int
sfifo_test_fifo_segment_hello_world (int verbose)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &segment_main;
  u8 *test_data, *retrieved_data = 0;
  fifo_segment_t *fs;
  svm_fifo_t *f;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = "fifo-test1";
  a->segment_size = 256 << 10;

  rv = fifo_segment_create (sm, a);

  SFIFO_TEST (!rv, "svm_fifo_segment_create returned %d", rv);

  fs = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  f = fifo_segment_alloc_fifo (fs, 4096, FIFO_SEGMENT_RX_FIFO);

  SFIFO_TEST (f != 0, "svm_fifo_segment_alloc_fifo");

  test_data = format (0, "Hello world%c", 0);
  vec_validate (retrieved_data, vec_len (test_data) - 1);

  while (svm_fifo_max_enqueue (f) >= vec_len (test_data))
    svm_fifo_enqueue_nowait (f, vec_len (test_data), test_data);

  while (svm_fifo_max_dequeue (f) >= vec_len (test_data))
    svm_fifo_dequeue_nowait (f, vec_len (retrieved_data), retrieved_data);

  while (svm_fifo_max_enqueue (f) >= vec_len (test_data))
    svm_fifo_enqueue_nowait (f, vec_len (test_data), test_data);

  while (svm_fifo_max_dequeue (f) >= vec_len (test_data))
    svm_fifo_dequeue_nowait (f, vec_len (retrieved_data), retrieved_data);

  SFIFO_TEST (!memcmp (retrieved_data, test_data, vec_len (test_data)),
	      "data should be identical");

  vec_free (test_data);
  vec_free (retrieved_data);
  vec_free (a->new_segment_indices);
  fifo_segment_free_fifo (fs, f);
  fifo_segment_delete (sm, fs);
  return 0;
}

static int
sfifo_test_fifo_segment_fifo_grow (int verbose)
{
  fifo_segment_main_t *sm = &segment_main;
  fifo_segment_create_args_t _a, *a = &_a;
  int rv, fifo_size = 4096, n_chunks;
  fifo_segment_t *fs;
  svm_fifo_t *f;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = "fifo-test1";
  a->segment_size = 256 << 10;

  rv = fifo_segment_create (sm, a);

  SFIFO_TEST (!rv, "svm_fifo_segment_create returned %d", rv);

  /*
   * Alloc and grow fifo
   */
  fs = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  f = fifo_segment_alloc_fifo (fs, fifo_size, FIFO_SEGMENT_RX_FIFO);

  SFIFO_TEST (f != 0, "svm_fifo_segment_alloc_fifo");

  fifo_segment_grow_fifo (fs, f, fifo_size);
  SFIFO_TEST (f->size == 2 * fifo_size, "fifo size should be %u is %u",
	      2 * fifo_size, f->size);

  fifo_segment_grow_fifo (fs, f, 16 * fifo_size);
  SFIFO_TEST (f->size == 18 * fifo_size, "fifo size should be %u is %u",
	      18 * fifo_size, f->size);

  /*
   * Free and test free list size
   */
  fifo_segment_free_fifo (fs, f);

  n_chunks = fifo_segment_num_free_chunks (fs, fifo_size);
  SFIFO_TEST (n_chunks == 1, "free 2^10B chunks should be %u is %u", 1,
	      n_chunks);
  n_chunks = fifo_segment_num_free_chunks (fs, 16 * fifo_size);
  SFIFO_TEST (n_chunks == 1, "free 2^14B chunks should be %u is %u", 1,
	      n_chunks);
  n_chunks = fifo_segment_num_free_chunks (fs, ~0);
  SFIFO_TEST (n_chunks == 2, "free chunks should be %u is %u", 2, n_chunks);

  /*
   * Realloc fifo
   */
  f = fifo_segment_alloc_fifo (fs, fifo_size, FIFO_SEGMENT_RX_FIFO);

  fifo_segment_grow_fifo (fs, f, fifo_size);
  n_chunks = fifo_segment_num_free_chunks (fs, fifo_size);
  SFIFO_TEST (n_chunks == 0, "free 2^10B chunks should be %u is %u", 0,
	      n_chunks);

  fifo_segment_grow_fifo (fs, f, 16 * fifo_size);
  SFIFO_TEST (n_chunks == 0, "free 2^14B chunks should be %u is %u", 0,
	      n_chunks);
  n_chunks = fifo_segment_num_free_chunks (fs, ~0);
  SFIFO_TEST (n_chunks == 0, "free chunks should be %u is %u", 0, n_chunks);

  /*
   * Free again
   */
  fifo_segment_free_fifo (fs, f);
  n_chunks = fifo_segment_num_free_chunks (fs, ~0);
  SFIFO_TEST (n_chunks == 2, "free chunks should be %u is %u", 2, n_chunks);

  /*
   * Cleanup
   */
  fifo_segment_delete (sm, fs);
  vec_free (a->new_segment_indices);
  return 0;
}

static int
sfifo_test_fifo_segment_slave (int verbose)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &segment_main;
  u8 *test_data, *retrieved_data = 0;
  fifo_segment_t *sp;
  fifo_segment_header_t *fsh;
  ssvm_shared_header_t *sh;
  svm_fifo_t *f;
  u32 *result;
  int rv, i;

  sleep (2);

  sm->timeout_in_seconds = 5;
  clib_memset (a, 0, sizeof (*a));
  a->segment_name = "fifo-test1";

  rv = fifo_segment_attach (sm, a);

  SFIFO_TEST (!rv, "svm_fifo_segment_attach returned %d", rv);

  sp = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  vec_free (a->new_segment_indices);
  sh = sp->ssvm.sh;
  fsh = (fifo_segment_header_t *) sh->opaque[0];

  /* might wanna wait.. */
  f = fsh->fifos;

  /* Lazy bastards united */
  test_data = format (0, "Hello world%c", 0);
  vec_validate (retrieved_data, vec_len (test_data) - 1);

  for (i = 0; i < 1000; i++)
    {
      svm_fifo_dequeue_nowait (f, vec_len (retrieved_data), retrieved_data);
      if (memcmp (retrieved_data, test_data, vec_len (retrieved_data)))
	{
	  result = (u32 *) f->head_chunk->data;
	  *result = 1;
	  _exit (0);
	}
    }

  result = (u32 *) f->head_chunk->data;
  *result = 0;

  vec_free (test_data);
  vec_free (retrieved_data);
  _exit (0);
}

static int
sfifo_test_fifo_segment_master_slave (int verbose)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &segment_main;
  fifo_segment_t *sp;
  svm_fifo_t *f;
  u8 *test_data;
  u32 *result;
  int rv, i;
  pid_t pid;

  pid = fork ();
  if (pid < 0)
    SFIFO_TEST (0, "fork failed");

  if (!pid)
    sfifo_test_fifo_segment_slave (verbose);

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = "fifo-test1";
  a->segment_size = 256 << 10;

  rv = fifo_segment_create (sm, a);

  SFIFO_TEST (!rv, "svm_fifo_segment_create returned %d", rv);

  sp = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  f = fifo_segment_alloc_fifo (sp, 4096, FIFO_SEGMENT_RX_FIFO);

  SFIFO_TEST (f != 0, "svm_fifo_segment_alloc_fifo alloc");

  test_data = format (0, "Hello world%c", 0);

  usleep (200e3);

  for (i = 0; i < 1000; i++)
    svm_fifo_enqueue_nowait (f, vec_len (test_data), test_data);

  /* Wait for slave */
  i = 0;
  while (svm_fifo_max_dequeue (f) && i++ < 1e10)
    ;

  usleep (1e3);

  result = (u32 *) f->head_chunk->data;
  SFIFO_TEST (*result == 0, "slave reported no error");

  vec_free (a->new_segment_indices);
  vec_free (test_data);
  fifo_segment_free_fifo (sp, f);
  fifo_segment_delete (sm, sp);
  return 0;
}

static int
sfifo_test_fifo_segment_mempig (int verbose)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &segment_main;
  fifo_segment_t *sp;
  svm_fifo_t *f;
  svm_fifo_t **flist = 0;
  int rv;
  int i;

  clib_memset (a, 0, sizeof (*a));

  a->segment_name = "fifo-test1";
  a->segment_size = 256 << 10;

  rv = fifo_segment_create (sm, a);

  SFIFO_TEST (!rv, "svm_fifo_segment_create returned %d", rv);

  sp = fifo_segment_get_segment (sm, a->new_segment_indices[0]);

  for (i = 0; i < 1000; i++)
    {
      f = fifo_segment_alloc_fifo (sp, 4096, FIFO_SEGMENT_RX_FIFO);
      if (f == 0)
	break;
      vec_add1 (flist, f);
    }

  SFIFO_TEST (vec_len (flist), "created %d fifos", vec_len (flist));

  for (i = 0; i < vec_len (flist); i++)
    {
      f = flist[i];
      fifo_segment_free_fifo (sp, f);
    }

  _vec_len (flist) = 0;

  for (i = 0; i < 1000; i++)
    {
      f = fifo_segment_alloc_fifo (sp, 4096, FIFO_SEGMENT_RX_FIFO);
      if (f == 0)
	break;
      vec_add1 (flist, f);
    }

  SFIFO_TEST (vec_len (flist), "second try created %d fifos",
	      vec_len (flist));
  for (i = 0; i < vec_len (flist); i++)
    {
      f = flist[i];
      fifo_segment_free_fifo (sp, f);
    }

  fifo_segment_delete (sm, sp);
  return 0;
}

static int
sfifo_test_fifo_segment (vlib_main_t * vm, unformat_input_t * input)
{
  int rv, verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "masterslave"))
	{
	  if ((rv = sfifo_test_fifo_segment_master_slave (verbose)))
	    return -1;
	}
      else if (unformat (input, "basic"))
	{
	  if ((rv = sfifo_test_fifo_segment_hello_world (verbose)))
	    return -1;
	}
      else if (unformat (input, "mempig"))
	{
	  if ((rv = sfifo_test_fifo_segment_mempig (verbose)))
	    return -1;
	}
      else if (unformat (input, "grow fifo"))
	{
	  if ((rv = sfifo_test_fifo_segment_fifo_grow (verbose)))
	    return -1;
	}
      else if (unformat (input, "all"))
	{
	  if ((rv = sfifo_test_fifo_segment_hello_world (verbose)))
	    return -1;
	  if ((rv = sfifo_test_fifo_segment_mempig (verbose)))
	    return -1;
	  if ((rv = sfifo_test_fifo_segment_fifo_grow (verbose)))
	    return -1;
	  /* Pretty slow so avoid running it always
	     if ((rv = sfifo_test_fifo_segment_master_slave (verbose)))
	     return -1;
	   */
	}
      else
	{
	  vlib_cli_output (vm, "parse error: '%U'", format_unformat_error,
			   input);
	  return -1;
	}
    }
  return 0;
}

static clib_error_t *
svm_fifo_test (vlib_main_t * vm, unformat_input_t * input,
	       vlib_cli_command_t * cmd_arg)
{
  int res = 0;
  char *str;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fifo1"))
	res = sfifo_test_fifo1 (vm, input);
      else if (unformat (input, "fifo2"))
	res = sfifo_test_fifo2 (vm);
      else if (unformat (input, "fifo3"))
	res = sfifo_test_fifo3 (vm, input);
      else if (unformat (input, "fifo4"))
	res = sfifo_test_fifo4 (vm, input);
      else if (unformat (input, "fifo5"))
	res = sfifo_test_fifo5 (vm, input);
      else if (unformat (input, "fifo6"))
	res = sfifo_test_fifo6 (vm, input);
      else if (unformat (input, "fifo7"))
	res = sfifo_test_fifo7 (vm, input);
      else if (unformat (input, "large"))
	res = sfifo_test_fifo_large (vm, input);
      else if (unformat (input, "replay"))
	res = sfifo_test_fifo_replay (vm, input);
      else if (unformat (input, "grow"))
	res = sfifo_test_fifo_grow (vm, input);
      else if (unformat (input, "segment"))
	res = sfifo_test_fifo_segment (vm, input);
      else if (unformat (input, "all"))
	{
	  if ((res = sfifo_test_fifo1 (vm, input)))
	    goto done;

	  if ((res = sfifo_test_fifo2 (vm)))
	    goto done;

	  /*
	   * Run a number of fifo3 configs
	   */
	  str = "nsegs 10 overlap seed 123";
	  unformat_init_cstring (input, str);
	  if ((res = sfifo_test_fifo3 (vm, input)))
	    goto done;
	  unformat_free (input);

	  str = "nsegs 10 overlap seed 123 in-seq-all";
	  unformat_init_cstring (input, str);
	  if ((res = sfifo_test_fifo3 (vm, input)))
	    goto done;
	  unformat_free (input);

	  str = "nsegs 10 overlap seed 123 initial-offset 3917";
	  unformat_init_cstring (input, str);
	  if ((res = sfifo_test_fifo3 (vm, input)))
	    goto done;
	  unformat_free (input);

	  str = "nsegs 10 overlap seed 123 initial-offset 3917 drop";
	  unformat_init_cstring (input, str);
	  if ((res = sfifo_test_fifo3 (vm, input)))
	    goto done;
	  unformat_free (input);

	  str = "nsegs 10 seed 123 initial-offset 3917 drop no-randomize";
	  unformat_init_cstring (input, str);
	  if ((res = sfifo_test_fifo3 (vm, input)))
	    goto done;
	  unformat_free (input);

	  if ((res = sfifo_test_fifo4 (vm, input)))
	    goto done;

	  if ((res = sfifo_test_fifo5 (vm, input)))
	    goto done;

	  if ((res = sfifo_test_fifo6 (vm, input)))
	    goto done;

	  if ((res = sfifo_test_fifo7 (vm, input)))
	    goto done;

	  if ((res = sfifo_test_fifo_grow (vm, input)))
	    goto done;

	  str = "all";
	  unformat_init_cstring (input, str);
	  if ((res = sfifo_test_fifo_segment (vm, input)))
	    goto done;
	}
      else
	{
	  vlib_cli_output (vm, "unknown input `%U'", format_unformat_error,
			   input);
	  res = -1;
	  goto done;
	}

    }

done:
  if (res)
    return clib_error_return (0, "svm fifo unit test failed");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (svm_fifo_test_command, static) =
{
  .path = "test svm fifo",
  .short_help = "internal svm fifo unit tests",
  .function = svm_fifo_test,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
