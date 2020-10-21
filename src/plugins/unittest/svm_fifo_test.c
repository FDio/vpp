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
#include <svm/svm_common.h>
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

static fifo_segment_t *
fifo_segment_prepare (fifo_segment_main_t * sm, char *seg_name, u32 seg_size)
{
  fifo_segment_create_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = seg_name;
  a->segment_size = seg_size ? seg_size : 32 << 20;

  if (fifo_segment_create (sm, a))
    return 0;

  return fifo_segment_get_segment (sm, a->new_segment_indices[0]);
}

static void
ft_fifo_segment_free (fifo_segment_main_t * sm, fifo_segment_t * fs)
{
  fifo_segment_delete (sm, fs);
}

static svm_fifo_t *
fifo_segment_alloc_fifo (fifo_segment_t * fs, u32 data_bytes,
			 fifo_segment_ftype_t ftype)
{
  return fifo_segment_alloc_fifo_w_slice (fs, 0, data_bytes, ftype);
}

static svm_fifo_t *
fifo_prepare (fifo_segment_t * fs, u32 fifo_size)
{
  svm_fifo_t *f;
  svm_fifo_chunk_t *c;

  f = fifo_segment_alloc_fifo (fs, fifo_size, FIFO_SEGMENT_RX_FIFO);

  /* Paint 1st fifo chunk with -1's */
  c = svm_fifo_head_chunk (f);
  clib_memset (c->data, 0xFF, c->length);

  svm_fifo_init_ooo_lookup (f, 1 /* deq ooo */ );
  return f;
}

static void
ft_fifo_free (fifo_segment_t * fs, svm_fifo_t * f)
{
  fifo_segment_free_fifo (fs, f);
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
  u32 fifo_size = 1 << 20, *test_data = 0, offset, data_word, test_data_len;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u8 *data, *s, *data_buf = 0;
  int i, rv, verbose = 0;
  ooo_segment_t *ooo_seg;
  fifo_segment_t *fs;
  svm_fifo_t *f;
  u32 j;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
    }

  test_data_len = fifo_size / sizeof (u32);
  vec_validate (test_data, test_data_len - 1);

  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i;

  fs = fifo_segment_prepare (fsm, "fifo-test1", 0);
  f = fifo_prepare (fs, fifo_size);

  /*
   * Enqueue an initial (un-dequeued) chunk
   */
  rv = svm_fifo_enqueue (f, sizeof (u32), (u8 *) test_data);
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
	  rv = svm_fifo_enqueue (f, sizeof (u32), data);
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
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 2),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));

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

  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 2),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));

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
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 12),
	      "first ooo seg position %u", ooo_seg->start);
  SFIFO_TEST ((ooo_seg->length == 16),
	      "first ooo seg length %u", ooo_seg->length);

  /*
   * Enqueue the missing u32
   */
  rv = svm_fifo_enqueue (f, sizeof (u32), (u8 *) (test_data + 2));
  if (verbose)
    vlib_cli_output (vm, "fifo after missing link: %U", format_svm_fifo, f,
		     1);
  SFIFO_TEST ((rv == 20), "bytes to be enqueued %u", rv);
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));

  /*
   * Collect results
   */
  for (i = 0; i < 7; i++)
    {
      rv = svm_fifo_dequeue (f, sizeof (u32), (u8 *) & data_word);
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
  ft_fifo_free (fs, f);
  f = fifo_prepare (fs, fifo_size);

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
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));

  /* add missing data to be able to dequeue something */
  rv = svm_fifo_enqueue (f, 4, data);
  SFIFO_TEST ((rv == 32), "enqueued %u", rv);
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));

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
  ft_fifo_free (fs, f);
  f = fifo_prepare (fs, fifo_size);

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

  rv = svm_fifo_enqueue (f, 29, data);
  if (verbose)
    vlib_cli_output (vm, "fifo after enqueueing 29: %U", format_svm_fifo, f,
		     1);
  SFIFO_TEST ((rv == 32), "ooo enqueued %u", rv);
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));

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
  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (test_data);

  return 0;

err:
  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (test_data);

  return -1;
}

static int
sfifo_test_fifo2 (vlib_main_t * vm)
{
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  test_pattern_t *tp, *vp, *test_data;
  u32 fifo_size = (1 << 20) + 1;
  int i, rv, test_data_len;
  ooo_segment_t *ooo_seg;
  fifo_segment_t *fs;
  svm_fifo_t *f;
  u64 data64;

  test_data = test_pattern;
  test_data_len = ARRAY_LEN (test_pattern);

  vp = fifo_get_validate_pattern (vm, test_data, test_data_len);

  /* Create a fifo */
  fs = fifo_segment_prepare (fsm, "fifo-test2", 0);
  f = fifo_prepare (fs, fifo_size);

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
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 4),
	      "first ooo seg position %u", ooo_seg->start);
  SFIFO_TEST ((ooo_seg->length == 2996),
	      "first ooo seg length %u", ooo_seg->length);

  data64 = 0;
  rv = svm_fifo_enqueue (f, sizeof (u32), (u8 *) & data64);
  SFIFO_TEST ((rv == 3000), "bytes to be enqueued %u", rv);

  ft_fifo_free (fs, f);
  vec_free (vp);

  /*
   * Now try it again w/ unsorted data...
   */

  f = fifo_prepare (fs, fifo_size);

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
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 4),
	      "first ooo seg position %u", ooo_seg->start);
  SFIFO_TEST ((ooo_seg->length == 2996),
	      "first ooo seg length %u", ooo_seg->length);

  data64 = 0;
  rv = svm_fifo_enqueue (f, sizeof (u32), (u8 *) & data64);

  SFIFO_TEST ((rv == 3000), "bytes to be enqueued %u", rv);

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);

  return 0;
}

static int
sfifo_test_fifo3 (vlib_main_t * vm, unformat_input_t * input)
{
  u32 nsegs = 2, seg_size, length_so_far, current_offset, offset_increment;
  int overlap = 0, verbose = 0, randomize = 1, drop = 0, in_seq_all = 0;
  u32 len_this_chunk, seed = 0xdeaddabe, j, total_size = 2 << 10;
  u32 fifo_size = (4 << 10) + 1, fifo_initial_offset = 0;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u8 *data_pattern = 0, *data_buf = 0;
  test_pattern_t *tp, *generate = 0;
  fifo_segment_t *fs;
  svm_fifo_t *f;
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
  fs = fifo_segment_prepare (fsm, "fifo-test3", 0);
  f = fifo_prepare (fs, fifo_size);

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
    svm_fifo_enqueue (f, generate[0].len, (u8 *) data_pattern);

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
      rv = svm_fifo_enqueue (f, bytes_to_enq, data_pattern + 0);

      if (verbose)
	vlib_cli_output (vm, "in-order enqueue returned %d", rv);

      SFIFO_TEST ((rv == total_size), "enqueued %u expected %u", rv,
		  total_size);

    }

  SFIFO_TEST ((svm_fifo_has_ooo_data (f) == 0), "number of ooo segments %u",
	      svm_fifo_n_ooo_segments (f));

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

  /*
   * Dequeue or drop all data
   */
  if (drop)
    {
      svm_fifo_dequeue_drop (f, vec_len (data_pattern));
    }
  else
    {
      memset (data_buf, 0, vec_len (data_pattern));
      svm_fifo_dequeue (f, vec_len (data_pattern), data_buf);
      if (compare_data
	  (data_buf, data_pattern, 0, vec_len (data_pattern), &j))
	{
	  SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		      data_pattern[j]);
	}
    }

  SFIFO_TEST ((svm_fifo_max_dequeue (f) == 0), "fifo has %d bytes",
	      svm_fifo_max_dequeue (f));

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (data_pattern);
  vec_free (data_buf);

  return 0;
}

static int
sfifo_test_fifo4 (vlib_main_t * vm, unformat_input_t * input)
{
  u32 fifo_size = 6 << 10, fifo_initial_offset = 1e9, test_n_bytes = 5000, j;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u8 *test_data = 0, *data_buf = 0;
  int i, rv, verbose = 0;
  fifo_segment_t *fs;
  svm_fifo_t *f;

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
  fs = fifo_segment_prepare (fsm, "fifo-test4", 0);
  f = fifo_prepare (fs, fifo_size);

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
	SFIFO_TEST (0, "enqueue returned %d", rv);
    }

  svm_fifo_enqueue (f, sizeof (u8), &test_data[0]);

  vec_validate (data_buf, vec_len (test_data));

  svm_fifo_dequeue (f, vec_len (test_data), data_buf);
  rv = compare_data (data_buf, test_data, 0, vec_len (test_data), &j);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", j, data_buf[j],
		     test_data[j]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
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
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u32 fifo_size = 401, j = 0, offset = 200;
  u8 *test_data = 0, *data_buf = 0;
  int i, rv, verbose = 0;
  ooo_segment_t *ooo_seg;
  fifo_segment_t *fs;
  svm_fifo_t *f;

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

  fs = fifo_segment_prepare (fsm, "fifo-test5", 0);
  f = fifo_prepare (fs, fifo_size);
  svm_fifo_init_pointers (f, offset, offset);

  vec_validate (test_data, 399);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  /*
   * Start with [100, 200] and [300, 400]
   */
  svm_fifo_enqueue_with_offset (f, 100, 100, &test_data[100]);
  svm_fifo_enqueue_with_offset (f, 300, 100, &test_data[300]);

  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 2),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
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
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 3),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
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
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == fifo_pos (f, offset + 100)),
	      "first seg start %u expected %u",
	      ooo_seg->start, fifo_pos (f, offset + 100));
  SFIFO_TEST ((ooo_seg->length == 300), "first seg length %u expected %u",
	      ooo_seg->length, 300);

  /*
   * Add [0, 150]
   */
  rv = svm_fifo_enqueue (f, 150, test_data);

  if (verbose)
    vlib_cli_output (vm, "fifo after [0 150] : %U", format_svm_fifo, f,
		     2 /* verbose */ );

  SFIFO_TEST ((rv == 400), "managed to enqueue %u expected %u", rv, 400);
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));

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
  ft_fifo_free (fs, f);
  f = fifo_prepare (fs, fifo_size);

  svm_fifo_enqueue_with_offset (f, 100, 100, &test_data[100]);
  svm_fifo_enqueue_with_offset (f, 50, 200, &test_data[50]);
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  SFIFO_TEST ((ooo_seg->start == 50), "first seg start %u expected %u",
	      ooo_seg->start, 50);
  SFIFO_TEST ((ooo_seg->length == 200), "first seg length %u expected %u",
	      ooo_seg->length, 200);

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (test_data);
  return 0;
}

/*
 * Test ooo head/tail u32 wrapping
 */
static int
sfifo_test_fifo6 (vlib_main_t * vm, unformat_input_t * input)
{
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u32 fifo_size = 101, n_test_bytes = 100;
  int i, j, rv, __clib_unused verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  ooo_segment_t *ooo_seg;
  fifo_segment_t *fs;
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

  fs = fifo_segment_prepare (fsm, "fifo-test6", 0);
  f = fifo_prepare (fs, fifo_size);

  vec_validate (test_data, n_test_bytes - 1);
  vec_validate (data_buf, n_test_bytes - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  /*
   * Add ooo with tail and ooo segment start u32 wrap
   */
  svm_fifo_init_pointers (f, ~0 % fifo_size, ~0 % fifo_size);
  svm_fifo_enqueue_with_offset (f, 10, 10, &test_data[10]);
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 1),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  ooo_seg = svm_fifo_first_ooo_segment (f);
  rv = ooo_segment_offset_prod (f, ooo_seg);
  SFIFO_TEST (rv == 10, "offset should be %u is %u", 10, rv);

  svm_fifo_enqueue (f, 10, test_data);
  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  SFIFO_TEST (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX,
	      "there should be no ooo seg");

  svm_fifo_peek (f, 5, 10, &data_buf[5]);
  if (compare_data (data_buf, test_data, 5, 10, (u32 *) & j))
    SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		test_data[j]);

  svm_fifo_dequeue (f, 20, data_buf);
  if (compare_data (data_buf, test_data, 0, 20, (u32 *) & j))
    SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		test_data[j]);

  /*
   * Force collect with tail u32 wrap and without ooo segment start u32 wrap
   */
  svm_fifo_init_pointers (f, (~0 - 10) % fifo_size, (~0 - 10) % fifo_size);
  svm_fifo_enqueue_with_offset (f, 5, 15, &test_data[5]);
  svm_fifo_enqueue (f, 12, test_data);

  SFIFO_TEST ((svm_fifo_n_ooo_segments (f) == 0),
	      "number of ooo segments %u", svm_fifo_n_ooo_segments (f));
  SFIFO_TEST (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX,
	      "there should be no ooo seg");

  svm_fifo_dequeue (f, 20, data_buf);
  if (compare_data (data_buf, test_data, 0, 20, (u32 *) & j))
    SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		test_data[j]);

  /*
   * Cleanup
   */
  vec_free (test_data);
  vec_free (data_buf);
  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  return 0;
}

/*
 * Multiple ooo enqueues and dequeues that force fifo tail/head wrap
 */
static int
sfifo_test_fifo7 (vlib_main_t * vm, unformat_input_t * input)
{
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u32 fifo_size = 101, n_iterations = 100;
  int i, j, rv, __clib_unused verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  u64 n_test_bytes = 100;
  fifo_segment_t *fs;
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
  fs = fifo_segment_prepare (fsm, "fifo-test7", 0);
  f = fifo_prepare (fs, fifo_size);
  svm_fifo_init_pointers (f, ~0 % fifo_size, ~0 % fifo_size);

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
	  rv = svm_fifo_n_ooo_segments (f);
	  if (rv != (n_test_bytes - j) / 2 + 1)
	    SFIFO_TEST (0, "number of ooo segments expected %u is %u",
			(n_test_bytes - j) / 2 + 1, rv);
	}

      svm_fifo_enqueue_with_offset (f, 1, n_test_bytes - 1, &test_data[1]);
      rv = svm_fifo_n_ooo_segments (f);
      if (rv != 1)
	SFIFO_TEST (0, "number of ooo segments %u", rv);

      svm_fifo_enqueue (f, 1, test_data);
      rv = svm_fifo_n_ooo_segments (f);
      if (rv != 0)
	SFIFO_TEST (0, "number of ooo segments %u", rv);

      svm_fifo_dequeue (f, n_test_bytes, data_buf);
      if (compare_data (data_buf, test_data, 0, n_test_bytes, (u32 *) & j))
	SFIFO_TEST (0, "[%d] dequeued %u expected %u", j, data_buf[j],
		    test_data[j]);
      svm_fifo_init_pointers (f, (~0 - i) % f->size, (~0 - i) % f->size);
    }
  SFIFO_TEST (1, "passed multiple ooo enqueue/dequeue");

  /*
   * Cleanup
   */
  vec_free (test_data);
  vec_free (data_buf);
  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  return 0;
}

/*
 * Enqueue more than 4GB
 */
static int
sfifo_test_fifo_large (vlib_main_t * vm, unformat_input_t * input)
{
  u32 n_iterations = 100, n_bytes_per_iter, half, fifo_size;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  int i, j, rv, __clib_unused verbose = 0;
  u8 *test_data = 0, *data_buf = 0;
  u64 n_test_bytes = 100;
  fifo_segment_t *fs;
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
  fifo_size = n_bytes_per_iter + 1;

  fs = fifo_segment_prepare (fsm, "fifo-large", 0);
  f = fifo_prepare (fs, fifo_size);
  svm_fifo_init_pointers (f, ~0 % fifo_size, ~0 % fifo_size);

  vec_validate (test_data, n_bytes_per_iter - 1);
  vec_validate (data_buf, n_bytes_per_iter - 1);
  for (i = 0; i < vec_len (test_data); i++)
    test_data[i] = i % 0xff;

  half = n_bytes_per_iter / 2;
  for (i = 0; i < n_iterations; i++)
    {
      svm_fifo_enqueue_with_offset (f, half, half, &test_data[half]);
      svm_fifo_enqueue (f, half, test_data);
      rv = svm_fifo_n_ooo_segments (f);
      if (rv != 0)
	SFIFO_TEST (0, "number of ooo segments %u", rv);
      svm_fifo_dequeue (f, n_bytes_per_iter, data_buf);
      if (compare_data (data_buf, test_data, 0, n_bytes_per_iter,
			(u32 *) & j))
	SFIFO_TEST (0, "[%d][%d] dequeued %u expected %u", i, j, data_buf[j],
		    test_data[j]);
    }
  SFIFO_TEST (1, "passed large transfer");

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);

  return 0;
}

static void
validate_test_and_buf_vecs (u8 ** test_data, u8 ** data_buf, u32 len)
{
  int i, cur_len;

  cur_len = vec_len (*test_data);
  vec_validate (*test_data, len - 1);
  vec_validate (*data_buf, len - 1);

  for (i = cur_len; i < vec_len (*test_data); i++)
    (*test_data)[i] = i;
}

static int
enqueue_ooo (svm_fifo_t * f, u8 * test_data, u32 len, u32 iterations)
{
  u32 offset, enq_now, ooo_chunk;
  int i, rv;

  ooo_chunk = len / iterations;
  for (i = iterations; i > 0; i--)
    {
      offset = i * ooo_chunk;
      enq_now = clib_min (ooo_chunk, len - offset);
      if (!enq_now)
	continue;
      rv = svm_fifo_enqueue_with_offset (f, offset, enq_now,
					 test_data + offset);
      if (rv)
	return rv;
    }

  return 0;
}

static int
enqueue_ooo_packets (svm_fifo_t * f, u32 len, u32 enq_chunk, u8 * test_data)
{
  u32 offset, enq_now;
  int i, rv;

  for (i = 1; i <= len / enq_chunk; i++)
    {
      offset = i * enq_chunk;
      enq_now = clib_min (enq_chunk, len - offset);
      if (!enq_now)
	continue;
      rv = svm_fifo_enqueue_with_offset (f, offset, enq_now,
					 test_data + offset);
      if (rv)
	return rv;

      if (svm_fifo_size (f) < len - 4096)
	svm_fifo_set_size (f, svm_fifo_size (f) + enq_now);
      else
	svm_fifo_set_size (f, len);
    }

  return 0;
}

static int
enqueue_packets_inc (svm_fifo_t * f, u32 len, u32 enq_chunk, u8 * test_data)
{
  u32 enq_now, offset;
  int i, rv;

  for (i = 0; i <= len / enq_chunk; i++)
    {
      offset = i * enq_chunk;
      enq_now = clib_min (enq_chunk, len - offset);
      rv = svm_fifo_enqueue (f, enq_now, test_data + offset);
      if (rv != enq_now)
	return -1;
      if (svm_fifo_size (f) < len - 4096)
	svm_fifo_set_size (f, svm_fifo_size (f) + enq_now);
      else
	svm_fifo_set_size (f, len);
    }
  return 0;
}

static int
dequeue_ooo (svm_fifo_t * f, u8 * data_buf, u32 len, u32 iterations)
{
  u32 offset, ooo_chunk, deq_now;
  int i, rv;

  ooo_chunk = len / iterations;
  for (i = iterations; i >= 0; i--)
    {
      offset = i * ooo_chunk;
      deq_now = clib_min (ooo_chunk, len - offset);
      if (deq_now == 0)
	continue;
      rv = svm_fifo_peek (f, offset, deq_now, data_buf + offset);
      if (rv != deq_now)
	return rv;
    }
  return 0;
}

static int
dequeue_ooo_inc (svm_fifo_t * f, u8 * data_buf, u32 len, u32 iterations)
{
  u32 offset, ooo_chunk, deq_now;
  int i, rv;

  ooo_chunk = len / iterations;
  for (i = 0; i <= iterations; i++)
    {
      offset = i * ooo_chunk;
      deq_now = clib_min (ooo_chunk, len - offset);
      if (deq_now == 0)
	continue;
      rv = svm_fifo_peek (f, offset, deq_now, data_buf + offset);
      if (rv != deq_now)
	return rv;
    }
  return 0;
}

static int
dequeue_packets (svm_fifo_t * f, u32 len, u32 deq_chunk, u8 * data_buf)
{
  u32 offset, deq_now;
  int i, rv;

  for (i = 0; i <= len / deq_chunk; i++)
    {
      offset = i * deq_chunk;
      deq_now = clib_min (deq_chunk, len - offset);
      if (deq_now == 0)
	continue;
      rv = svm_fifo_dequeue (f, deq_now, data_buf + offset);
      if (rv != deq_now)
	return rv;
    }
  return 0;
}

static int
sfifo_test_fifo_grow (vlib_main_t * vm, unformat_input_t * input)
{
  int __clib_unused verbose = 0, fifo_size = 4096, fifo_inc = 4096, rv, i;
  u32 enq_chunk, offset, deq_now, last_start_byte;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u8 *test_data = 0, *data_buf = 0;
  svm_fifo_chunk_t *c;
  fifo_segment_t *fs;
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

  fs = fifo_segment_prepare (fsm, "fifo-grow", 0);
  f = fifo_prepare (fs, fifo_size);

  /*
   * Grow size and alloc chunks by enqueueing in order
   */
  fifo_size += fifo_inc;
  svm_fifo_set_size (f, fifo_size);
  last_start_byte = 4096;
  validate_test_and_buf_vecs (&test_data, &data_buf, fifo_size);

  rv = svm_fifo_enqueue (f, fifo_size, test_data);

  SFIFO_TEST (rv == fifo_size, "enqueue should work");
  SFIFO_TEST (svm_fifo_size (f) == fifo_size, "size expected %u is %u",
	      fifo_size, svm_fifo_size (f));
  SFIFO_TEST (svm_fifo_max_dequeue (f) == fifo_size, "max deq should be %u",
	      fifo_size);
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 2, "should have 2 chunks has %u", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  c = f->head_chunk;
  SFIFO_TEST (c->start_byte == 0, "head start byte should be %u", 0);
  SFIFO_TEST (c->length == 4096, "head chunk length should be %u", 4096);
  SFIFO_TEST (f->tail_chunk == 0, "no tail chunk");
  SFIFO_TEST (f->ooo_enq == 0, "should have no ooo enq chunk");
  SFIFO_TEST (f->ooo_deq == 0, "should have no ooo deq chunk");
  c = f->end_chunk;
  SFIFO_TEST (c->start_byte == last_start_byte, "end chunk start byte should"
	      " be %u", last_start_byte);
  SFIFO_TEST (c->length == 4096, "end chunk length should be %u", 4096);

  /*
   * Dequeue and validate data
   */

  rv = svm_fifo_dequeue (f, fifo_size, data_buf);
  SFIFO_TEST (rv == fifo_size, "should dequeue all data");
  last_start_byte += 4096;	/* size of last segment */

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & i);

  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);
  SFIFO_TEST (f->head_chunk == 0, "head chunk should be 0");
  SFIFO_TEST (f->tail_chunk == 0, "tail chunk should be 0");
  SFIFO_TEST (f->ooo_deq == 0, "should have no ooo deq chunk");
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  /*
   * Allocate one new chunk by enqueueing out of order all but first chunk
   *
   */

  enq_chunk = vec_len (test_data) / 10;
  rv = enqueue_ooo (f, test_data, vec_len (test_data), 10);
  SFIFO_TEST (!rv, "enqueue ooo should work");

  SFIFO_TEST (svm_fifo_size (f) == fifo_size, "size expected %u is %u",
	      fifo_size, svm_fifo_size (f));
  SFIFO_TEST (svm_fifo_max_dequeue (f) == 0, "max deq should be %u", 0);
  /* Fifo has 2 chunks because the we didn't allow the first chunk to be
   * freed when all the data was dequeued. Could be optimized in the future */
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 2, "should have %u chunks has %u", 2, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  SFIFO_TEST (f->head_chunk == 0, "should have no head chunk");
  /* When new fifo chunks are allocated, tail is initialized */
  SFIFO_TEST (f->tail_chunk != 0, "should have no tail chunk");
  SFIFO_TEST (f->ooo_enq != 0, "should have an ooo enq chunk");

  c = f->end_chunk;
  SFIFO_TEST (c->start_byte == last_start_byte,
	      "end chunk should start at %u", last_start_byte);
  SFIFO_TEST (c->length == 8192, "end chunk length should be %u", 8192);
  SFIFO_TEST (f->ooo_enq == c, "ooo enq chunk should be end chunk");

  /*
   * Enqueue the first chunk
   */
  rv = svm_fifo_enqueue (f, enq_chunk, test_data);
  SFIFO_TEST (rv == fifo_size, "enq should succeed %u", rv);
  rv = svm_fifo_max_dequeue (f);
  SFIFO_TEST (rv == fifo_size, "max deq should be %u is %u", fifo_size, rv);
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 2, "should have %u chunks has %u", 2, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  SFIFO_TEST (f->head_chunk == 0, "should have no head chunk");
  /* Fifo is full so tail and ooo_enq should be 0 */
  SFIFO_TEST (f->tail_chunk == 0, "should have no tail chunk");
  SFIFO_TEST (f->ooo_enq == 0, "should have no ooo enq chunk");

  /*
   * Peek and validate data
   */

  memset (data_buf, 0, vec_len (data_buf));

  rv = dequeue_ooo_inc (f, data_buf, fifo_size, 10);
  SFIFO_TEST (!rv, "ooo deq should work %d", rv);

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & i);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);
  SFIFO_TEST ((rv == 0), "peeked compared to original returned %d", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  /* Peeked all the data in a full fifo so ooo_deq ends up 0 */
  SFIFO_TEST (f->ooo_deq == 0, "should have no ooo deq chunk");

  /*
   * Peek in reverse order and validate data
   *
   * RB tree should be exercised
   */

  memset (data_buf, 0, vec_len (data_buf));
  for (i = 10; i >= 0; i--)
    {
      offset = i * enq_chunk;
      deq_now = clib_min (enq_chunk, vec_len (test_data) - offset);
      rv = svm_fifo_peek (f, offset, deq_now, data_buf + offset);
      if (rv != deq_now)
	SFIFO_TEST (0, "failed to peek");
    }

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & i);

  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);
  SFIFO_TEST ((rv == 0), "peeked compared to original returned %d", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  /* Last chunk peeked is the first, so ooo_deq should be non zero */
  SFIFO_TEST (f->ooo_deq != 0, "should have ooo deq chunk");

  /*
   * Dequeue drop all bytes
   */
  rv = svm_fifo_dequeue_drop (f, fifo_size);
  SFIFO_TEST ((rv == fifo_size), "all bytes should be dropped %u", rv);
  last_start_byte += 8192;

  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  SFIFO_TEST (f->head_chunk == 0, "should have no head chunk");
  SFIFO_TEST (f->tail_chunk == 0, "should have no tail chunk");

  /* We don't remove the last chunk even when the fifo goes empty */
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 1, "should have %u chunks has %u", 1, rv);

  /*
   * Increase size such that it can't be the sum of multiple chunk lengths
   *
   * A chunk of 16kB should be allocated
   */
  fifo_size += 2 * fifo_inc - 100;
  svm_fifo_set_size (f, fifo_size);
  validate_test_and_buf_vecs (&test_data, &data_buf, fifo_size + fifo_inc);
  enq_chunk = vec_len (test_data) / 10;
  memset (data_buf, 0, vec_len (data_buf));

  /*
   * Enqueue data ooo
   */
  rv = enqueue_ooo (f, test_data, fifo_size, 10);
  SFIFO_TEST (!rv, "enqueue ooo should work");

  SFIFO_TEST (svm_fifo_size (f) == fifo_size, "size expected %u is %u",
	      fifo_size, svm_fifo_size (f));
  SFIFO_TEST (svm_fifo_max_dequeue (f) == 0, "max deq should be %u", 0);
  /* Fifo has 2 chunks because the we didn't allow the first chunk to be
   * freed when all the data was dequeued. Could be optimized in the future */
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 2, "should have %u chunks has %u", 2, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  SFIFO_TEST (f->head_chunk == 0, "should have no head chunk");
  /* When new fifo chunks are allocated, tail is initialized */
  SFIFO_TEST (f->tail_chunk != 0, "should have no tail chunk");
  SFIFO_TEST (f->ooo_enq != 0, "should have an ooo enq chunk");

  c = f->end_chunk;
  SFIFO_TEST (c->start_byte == last_start_byte,
	      "end chunk should start at %u", last_start_byte);
  SFIFO_TEST (c->length == 16384, "end chunk length should be %u", 16384);
  SFIFO_TEST (f->ooo_enq == c, "ooo enq chunk should be end chunk");

  /*
   * Enqueue the first chunk
   */
  rv = svm_fifo_enqueue (f, enq_chunk, test_data);
  SFIFO_TEST (rv == fifo_size, "enq should succeed %u", rv);
  rv = svm_fifo_max_dequeue (f);
  SFIFO_TEST (rv == fifo_size, "max deq should be %u is %u", fifo_size, rv);
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 2, "should have %u chunks has %u", 2, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  /*
   * Dequeue just a part of data. Because we're tracking ooo data, we can't
   * call dequeue. Therefore, first peek and then dequeue drop
   */
  rv = svm_fifo_peek (f, 0, fifo_inc, data_buf);
  SFIFO_TEST (rv == fifo_inc, "should dequeue all data");
  rv = svm_fifo_dequeue_drop (f, fifo_inc);
  SFIFO_TEST (rv == fifo_inc, "should dequeue all data");
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 1, "should have %u chunks has %u", 1, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  /*
   * Enqueue ooo as much data as it was dequeued
   */
  rv = enqueue_ooo (f, test_data + fifo_size, fifo_inc, 2);
  SFIFO_TEST (!rv, "ooo enqueue should work %d", rv);

  rv = svm_fifo_enqueue (f, fifo_inc / 2, test_data + fifo_size);
  SFIFO_TEST (rv == fifo_inc, "enqueue should work %d", rv);

  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 2, "should have %u chunks has %u", 2, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  last_start_byte += 16384;
  c = f->end_chunk;
  SFIFO_TEST (c->start_byte == last_start_byte,
	      "end chunk should start at %u", last_start_byte);
  SFIFO_TEST (c->length == 4096, "end chunk length should be %u", 4096);

  /*
   * Dequeue all. Don't call dequeue see above
   */
  rv = svm_fifo_peek (f, 0, fifo_size, data_buf + fifo_inc);
  SFIFO_TEST (rv == fifo_size, "should dequeue all data");
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & i);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);

  rv = svm_fifo_dequeue_drop (f, fifo_size);
  SFIFO_TEST (rv == fifo_size, "should dequeue all data");

  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  /* fifo does not end on chunk boundary because of the - 100 */
  SFIFO_TEST (f->head_chunk != 0, "should have head chunk");
  SFIFO_TEST (f->tail_chunk != 0, "should have tail chunk");

  /*
   * Enqueue and dequeue byte-by-byte ooo
   */

  memset (data_buf, 0, vec_len (data_buf));

  rv = enqueue_ooo (f, test_data, fifo_size, fifo_size);
  SFIFO_TEST (!rv, "ooo enqueue should work %d", rv);

  rv = svm_fifo_enqueue (f, 1, test_data);
  SFIFO_TEST (rv == fifo_size, "enqueue should work %d", rv);

  rv = dequeue_ooo (f, data_buf, fifo_size, fifo_size);
  SFIFO_TEST (!rv, "ooo deq should work %d", rv);

  rv = compare_data (data_buf, test_data, 0, fifo_size, (u32 *) & i);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  last_start_byte += 4096;
  c = f->end_chunk;
  SFIFO_TEST (c->start_byte == last_start_byte,
	      "end chunk should start at %u", last_start_byte);
  SFIFO_TEST (c->length == 16384, "end chunk length should be %u", 16384);

  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 2, "should have %u chunks has %u", 2, rv);

  /*
   * Dequeue drop all bytes
   */
  rv = svm_fifo_dequeue_drop (f, fifo_size);
  SFIFO_TEST ((rv == fifo_size), "all bytes should be dropped %u", rv);

  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  SFIFO_TEST (f->head_chunk != 0, "should have head chunk");
  SFIFO_TEST (f->tail_chunk != 0, "should have tail chunk");

  /* We don't remove the last chunk even when the fifo goes empty */
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 1, "should have %u chunks has %u", 1, rv);
  SFIFO_TEST (f->ooo_enq == 0, "should have no ooo enq chunk");
  SFIFO_TEST (f->ooo_deq == 0, "should have no ooo deq chunk");

  /*
   * Grow fifo to 4MB and force only 4kB chunk allocations
   */
  fifo_size = 4 << 20;
  svm_fifo_set_size (f, fifo_inc);
  validate_test_and_buf_vecs (&test_data, &data_buf, fifo_size);
  enq_chunk = 1500;
  memset (data_buf, 0, vec_len (data_buf));

  rv = enqueue_packets_inc (f, fifo_size, enq_chunk, test_data);
  SFIFO_TEST (!rv, "incremental packet enqueue should work");

  SFIFO_TEST (svm_fifo_max_dequeue (f) == fifo_size, "max deq should be %u",
	      fifo_size);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == (fifo_size / 4096) + 1, "should have %u chunks has %u",
	      (fifo_size / 4096) + 1, rv);


  /*
   * Dequeue all
   */

  /* Because we're tracking ooo data, we can't call dequeue. Therefore,
   * first peek and then dequeue drop */
  rv = svm_fifo_peek (f, 0, fifo_size, data_buf);
  SFIFO_TEST (rv == fifo_size, "should dequeue all data");

  rv = compare_data (data_buf, test_data, 0, vec_len (test_data),
		     (u32 *) & i);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  SFIFO_TEST ((rv == 0), "dequeued compared to original returned %d", rv);


  rv = svm_fifo_dequeue_drop (f, fifo_size);
  SFIFO_TEST ((rv == fifo_size), "all bytes should be dropped %u", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  SFIFO_TEST (f->ooo_deq == 0, "should have no ooo deq chunk");
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 1, "should have %u chunks has %u", 1, rv);

  /*
   * Cleanup
   */

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (test_data);
  vec_free (data_buf);
  return 0;
}

static int
sfifo_test_fifo_shrink (vlib_main_t * vm, unformat_input_t * input)
{
  int __clib_unused verbose = 0, fifo_size = 4096, deq_chunk;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u8 *test_data = 0, *data_buf = 0;
  fifo_segment_t *fs;
  svm_fifo_t *f;
  u32 enq_chunk;
  int i, rv;

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
   * Init fifo and enqueue data such that multiple 4096 chunks are allocated
   */
  fs = fifo_segment_prepare (fsm, "fifo-shrink", 0);
  f = fifo_prepare (fs, fifo_size);

  fifo_size = 4 << 20;
  svm_fifo_set_size (f, 4096);
  validate_test_and_buf_vecs (&test_data, &data_buf, fifo_size);
  enq_chunk = 1500;
  rv = enqueue_packets_inc (f, fifo_size, enq_chunk, test_data);
  SFIFO_TEST (!rv, "incremental packet enqueue should work");

  rv = svm_fifo_max_enqueue (f);
  SFIFO_TEST (rv == 0, "enqueue space %u", rv);
  SFIFO_TEST (svm_fifo_max_dequeue (f) == fifo_size, "max deq should be %u",
	      fifo_size);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == (fifo_size / 4096), "should have %u chunks has %u",
	      (fifo_size / 4096), rv);

  /*
   * Dequeue enough to collect one chunk
   */
  deq_chunk = 4096;
  rv = svm_fifo_dequeue (f, deq_chunk, data_buf);
  SFIFO_TEST (rv == deq_chunk, "should dequeue all data");

  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == (fifo_size / 4096) - 1, "should have %u chunks has %u",
	      (fifo_size / 4096) - 1, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  rv = svm_fifo_max_enqueue (f);
  SFIFO_TEST (rv == deq_chunk, "enqueue space %u", rv);

  /*
   * Dequeue ooo byte-by-byte remaining data
   */
  rv = dequeue_ooo (f, data_buf + deq_chunk, fifo_size - deq_chunk,
		    fifo_size - deq_chunk);
  SFIFO_TEST (!rv, "ooo deq should work %d", rv);

  rv = compare_data (data_buf, test_data, 0, fifo_size, (u32 *) & i);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);

  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == (fifo_size / 4096) - 1, "should have %u chunks has %u",
	      (fifo_size / 4096) - 1, rv);

  /*
   * Drop all data
   */
  rv = svm_fifo_dequeue_drop (f, fifo_size - deq_chunk);
  SFIFO_TEST (rv == fifo_size - deq_chunk, "should drop all data");
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == 1, "should have %u chunks has %u", 1, rv);
  rv = svm_fifo_max_enqueue (f);
  SFIFO_TEST (rv == fifo_size, "enqueue space %u", rv);


  /*
   * Reset size and enqueue ooo all data
   */
  svm_fifo_set_size (f, 4096);
  enq_chunk = deq_chunk = 1500;
  rv = enqueue_ooo_packets (f, vec_len (test_data), 1500, test_data);
  SFIFO_TEST (!rv, "enqueue ooo should work");
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  /* 1 additional chunk left from previous test */
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == (fifo_size / 4096) + 1, "should have %u chunks has %u",
	      (fifo_size / 4096) + 1, rv);

  /*
   * Add missing first chunk
   */
  rv = svm_fifo_enqueue (f, enq_chunk, test_data);
  SFIFO_TEST (rv == fifo_size, "enq should succeed %u", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");
  rv = svm_fifo_max_dequeue (f);
  SFIFO_TEST (rv == fifo_size, "max deq should be %u is %u", fifo_size, rv);
  rv = svm_fifo_n_chunks (f);
  SFIFO_TEST (rv == (fifo_size / 4096) + 1, "should have %u chunks has %u",
	      (fifo_size / 4096) + 1, rv);

  /*
   * Dequeue as packets
   */
  memset (data_buf, 0, vec_len (data_buf));
  rv = dequeue_packets (f, fifo_size, deq_chunk, data_buf);
  SFIFO_TEST (!rv, "deq pkts should work %d", rv);

  rv = compare_data (data_buf, test_data, 0, fifo_size, (u32 *) & i);
  if (rv)
    vlib_cli_output (vm, "[%d] dequeued %u expected %u", i, data_buf[i],
		     test_data[i]);

  /*
   * Enqueue and dequeue set of packets
   */
  svm_fifo_set_size (f, 4096);
  for (i = 0; i < 1000; i++)
    {
      rv = svm_fifo_enqueue (f, enq_chunk, test_data);
      if (rv != enq_chunk)
	SFIFO_TEST (0, "enq fail");
      rv = svm_fifo_dequeue (f, deq_chunk, data_buf);
      if (rv != deq_chunk)
	SFIFO_TEST (0, "deq fail");
    }

  /*
   * Cleanup
   */

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (test_data);
  vec_free (data_buf);

  return 0;
}

static int
sfifo_test_fifo_indirect (vlib_main_t * vm, unformat_input_t * input)
{
  int __clib_unused verbose = 0, fifo_size = 4096, deq_chunk;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u8 *test_data = 0, *data_buf = 0;
  svm_fifo_chunk_t *c;
  fifo_segment_t *fs;
  svm_fifo_t *f;
  int rv;

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
   * Init fifo and enqueue data such that multiple 4096 chunks are allocated
   */
  fs = fifo_segment_prepare (fsm, "fifo-indirect", 0);
  f = fifo_prepare (fs, fifo_size);

  fifo_size = 4 << 20;
  svm_fifo_set_size (f, fifo_size);
  validate_test_and_buf_vecs (&test_data, &data_buf, fifo_size);

  c = f->start_chunk;
  SFIFO_TEST (c->next == 0, "no next");

  svm_fifo_fill_chunk_list (f);
  SFIFO_TEST (c->next != 0, "new chunk should've been allocated");
  SFIFO_TEST (c->next->length == 4 << 20, "new chunk should be 4MB");

  rv = svm_fifo_max_write_chunk (f);
  SFIFO_TEST (rv == 4096, "max write chunk %u", rv);

  /*
   * Enqueue enough to fill first chunk
   */
  svm_fifo_enqueue_nocopy (f, 4096);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  c = svm_fifo_tail_chunk (f);
  SFIFO_TEST (c == f->end_chunk, "tail is end chunk");

  /* Initialize head chunk */
  rv = svm_fifo_max_read_chunk (f);
  SFIFO_TEST (rv == 4096, "max read chunk %u", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  /*
   * Move head over last segment
   */
  rv = svm_fifo_dequeue (f, 4096, data_buf);
  SFIFO_TEST (rv == 4096, "dequeue should work");

  c = svm_fifo_head_chunk (f);
  SFIFO_TEST (c == f->end_chunk, "head chunk should be last");

  rv = svm_fifo_max_read_chunk (f);
  SFIFO_TEST (rv == 0, "max read chunk %u", rv);

  rv = svm_fifo_max_write_chunk (f);
  SFIFO_TEST (rv == 4 << 20, "max write chunk %u", rv);

  /*
   * Cleanup
   */

  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (test_data);
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

static int
sfifo_test_fifo_make_rcv_wnd_zero (vlib_main_t * vm, unformat_input_t * input)
{
  int __clib_unused verbose = 0, fifo_size = 4096, deq_chunk;
  fifo_segment_main_t _fsm = { 0 }, *fsm = &_fsm;
  u8 *test_data = 0, *data_buf = 0;
  fifo_segment_t *fs;
  svm_fifo_t *f;
  int rv;

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
   * Init fifo and enqueue data such that multiple 4096 chunks are allocated
   */
  fs = fifo_segment_prepare (fsm, "fifo-rcv-wnd-zero", 0);
  f = fifo_prepare (fs, fifo_size);

  /* Enqueue 3000 into 4KB chunk, so there'll be 1096 free space */
  svm_fifo_set_size (f, 4096);
  validate_test_and_buf_vecs (&test_data, &data_buf, fifo_size);
  rv = svm_fifo_enqueue (f, 3000, test_data);
  SFIFO_TEST (rv == 3000, "enqueued %u", rv);
  rv = svm_fifo_max_enqueue (f);
  SFIFO_TEST (rv == 1096, "svm_fifo_max_enqueue %u", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  /* Shrink fifo size to the in-use size */
  svm_fifo_set_size (f, 3000);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  /* In TCP, this should result in rcv-wnd = 0 */
  rv = svm_fifo_max_enqueue (f);
  SFIFO_TEST (rv == 0, "svm_fifo_max_enqueue %u", rv);
  rv = svm_fifo_max_enqueue_prod (f);
  SFIFO_TEST (rv == 0, "svm_fifo_max_enqueue_prod %u", rv);

  /* Dequeue and ... */
  rv = svm_fifo_dequeue (f, 3000, data_buf);
  SFIFO_TEST (rv == 3000, "dequeued %u", rv);

  /* Clean up */
  ft_fifo_free (fs, f);
  ft_fifo_segment_free (fsm, fs);
  vec_free (test_data);
  vec_free (data_buf);

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
    svm_fifo_enqueue (f, vec_len (test_data), test_data);

  while (svm_fifo_max_dequeue (f) >= vec_len (test_data))
    svm_fifo_dequeue (f, vec_len (retrieved_data), retrieved_data);

  while (svm_fifo_max_enqueue (f) >= vec_len (test_data))
    svm_fifo_enqueue (f, vec_len (test_data), test_data);

  while (svm_fifo_max_dequeue (f) >= vec_len (test_data))
    svm_fifo_dequeue (f, vec_len (retrieved_data), retrieved_data);

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
  int rv, fifo_size = 4096, n_chunks, n_batch;
  fifo_segment_main_t *sm = &segment_main;
  fifo_segment_create_args_t _a, *a = &_a;
  u8 *test_data = 0, *data_buf = 0;
  u32 n_free_chunk_bytes, new_size;
  fifo_segment_t *fs;
  svm_fifo_t *f, *tf;

  clib_memset (a, 0, sizeof (*a));
  a->segment_name = "fifo-test1";
  /* size chosen to be able to force multi chunk allocation lower */
  a->segment_size = 256 << 10;

  /* fifo allocation allocates chunks in batch */
  n_batch = FIFO_SEGMENT_ALLOC_BATCH_SIZE;

  rv = fifo_segment_create (sm, a);

  SFIFO_TEST (!rv, "svm_fifo_segment_create returned %d", rv);

  /*
   * Alloc fifo
   */
  fs = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  fs->h->pct_first_alloc = 100;
  f = fifo_segment_alloc_fifo (fs, fifo_size, FIFO_SEGMENT_RX_FIFO);

  SFIFO_TEST (f != 0, "svm_fifo_segment_alloc_fifo");

  n_chunks = fifo_segment_num_free_chunks (fs, fifo_size);
  SFIFO_TEST (n_chunks == n_batch - 1, "free 2^10B chunks "
	      "should be %u is %u", n_batch - 1, n_chunks);
  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (rv == (n_batch - 1) * fifo_size, "free chunk bytes %u "
	      "expected %u", rv, (n_batch - 1) * fifo_size);

  /*
   * Grow fifo by preallocated fifo_size chunk
   */
  svm_fifo_set_size (f, 2 * fifo_size);
  validate_test_and_buf_vecs (&test_data, &data_buf, 2 * fifo_size);

  rv = svm_fifo_enqueue (f, vec_len (test_data), test_data);
  SFIFO_TEST (rv == vec_len (test_data), "enq should succeed %u", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  n_chunks = fifo_segment_num_free_chunks (fs, fifo_size);
  SFIFO_TEST (n_chunks == n_batch - 2, "free 2^10B chunks "
	      "should be %u is %u", n_batch - 2, n_chunks);
  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (rv == (n_batch - 2) * fifo_size, "free chunk bytes %u "
	      "expected %u", rv, (n_batch - 2) * fifo_size);

  /* Grow by a size not preallocated but first make sure there's space */
  rv = fifo_segment_free_bytes (fs);
  SFIFO_TEST (rv > 16 * fifo_size, "free bytes %u more than %u", rv,
	      16 * fifo_size);

  /* Force fifo growth */
  svm_fifo_set_size (f, svm_fifo_size (f) + 16 * fifo_size);
  validate_test_and_buf_vecs (&test_data, &data_buf, svm_fifo_size (f));
  rv = svm_fifo_enqueue (f, vec_len (test_data), test_data);

  SFIFO_TEST (svm_fifo_size (f) == 18 * fifo_size, "fifo size should be %u "
	      "is %u", 18 * fifo_size, svm_fifo_size (f));

  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (rv == (n_batch - 2) * fifo_size, "free chunk bytes %u "
	      "expected %u", rv, (n_batch - 2) * fifo_size);

  /*
   * Free and test free list size
   */
  fifo_segment_free_fifo (fs, f);

  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (rv == (16 + n_batch) * fifo_size, "free chunk bytes expected %u"
	      " is %u", (16 + n_batch) * fifo_size, rv);
  n_chunks = fifo_segment_num_free_chunks (fs, fifo_size);
  SFIFO_TEST (n_chunks == n_batch, "free 2^10B chunks "
	      "should be %u is %u", n_batch, n_chunks);
  n_chunks = fifo_segment_num_free_chunks (fs, 16 * fifo_size);
  SFIFO_TEST (n_chunks == 1, "free 2^14B chunks should be %u is %u", 1,
	      n_chunks);
  n_chunks = fifo_segment_num_free_chunks (fs, ~0);
  SFIFO_TEST (n_chunks == 1 + n_batch, "free chunks should be %u is %u",
	      1 + n_batch, n_chunks);

  /*
   * Realloc fifo
   */
  f = fifo_segment_alloc_fifo (fs, fifo_size, FIFO_SEGMENT_RX_FIFO);

  /* Force chunk allocation */
  svm_fifo_set_size (f, svm_fifo_size (f) + fifo_size);
  rv = svm_fifo_enqueue (f, svm_fifo_size (f), test_data);

  SFIFO_TEST (rv == svm_fifo_size (f), "enq should succeed %u", rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  n_chunks = fifo_segment_num_free_chunks (fs, fifo_size);
  SFIFO_TEST (n_chunks == n_batch - 2, "free 2^10B chunks should be %u is %u",
	      n_batch - 2, n_chunks);

  /* Grow and alloc 16 * fifo_size chunk */
  svm_fifo_set_size (f, svm_fifo_size (f) + 16 * fifo_size);
  rv = svm_fifo_enqueue (f, svm_fifo_size (f), test_data);

  n_chunks = fifo_segment_num_free_chunks (fs, 16 * fifo_size);
  SFIFO_TEST (n_chunks == 0, "free 2^14B chunks should be %u is %u", 0,
	      n_chunks);
  n_chunks = fifo_segment_num_free_chunks (fs, ~0);
  SFIFO_TEST (n_chunks == n_batch - 2, "free chunks should be %u is %u",
	      n_batch - 2, n_chunks);

  /*
   * Free again
   */
  fifo_segment_free_fifo (fs, f);
  n_chunks = fifo_segment_num_free_chunks (fs, ~0);
  SFIFO_TEST (n_chunks == 1 + n_batch, "free chunks should be %u is %u",
	      1 + n_batch, n_chunks);

  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (rv == (16 + n_batch) * fifo_size, "free chunk bytes expected %u"
	      " is %u", (16 + n_batch) * fifo_size, rv);

  n_free_chunk_bytes = rv;

  /*
   * Allocate non power of 2 fifo/chunk and check that free chunk bytes
   * is correctly updated
   */

  f = fifo_segment_alloc_fifo (fs, 16 * fifo_size - 1, FIFO_SEGMENT_RX_FIFO);
  rv = fifo_segment_fl_chunk_bytes (fs);

  SFIFO_TEST (n_free_chunk_bytes - 16 * fifo_size == rv, "free chunk bytes "
	      "expected %u is %u", n_free_chunk_bytes - 16 * fifo_size, rv);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  fifo_segment_free_fifo (fs, f);
  rv = fifo_segment_fl_chunk_bytes (fs);

  SFIFO_TEST (n_free_chunk_bytes == rv, "free chunk bytes expected %u is %u",
	      n_free_chunk_bytes, rv);

  /*
   * Force multi chunk fifo allocation
   */

  /* Check that we can force multi chunk allocation. Note that fifo size
   * rounded up to power of 2, i.e., 17 becomes 32 */
  rv = fifo_segment_free_bytes (fs);
  SFIFO_TEST (rv < 32 * fifo_size, "free bytes %u less than %u", rv,
	      32 * fifo_size);

  f = fifo_segment_alloc_fifo (fs, 17 * fifo_size, FIFO_SEGMENT_RX_FIFO);
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  rv = fifo_segment_fl_chunk_bytes (fs);

  /* Make sure that the non-power of two chunk freed above is correctly
   * accounted for in the chunk free bytes reduction due to chunk allocation
   * for the fifo, i.e., it's rounded up by 1 */
  SFIFO_TEST (n_free_chunk_bytes - 17 * fifo_size == rv, "free chunk bytes "
	      "expected %u is %u", n_free_chunk_bytes - 17 * fifo_size, rv);

  fifo_segment_free_fifo (fs, f);

  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (n_free_chunk_bytes == rv, "free chunk bytes expected %u is %u",
	      n_free_chunk_bytes, rv);

  /*
   * Allocate fifo that has all chunks. Because we have a chunk size limit of
   * segment_size / 2, allocate 2 fifos.
   */
  tf = fifo_segment_alloc_fifo (fs, n_free_chunk_bytes / 2,
				FIFO_SEGMENT_RX_FIFO);
  SFIFO_TEST (tf != 0, "allocation should work");
  SFIFO_TEST (svm_fifo_is_sane (tf), "fifo should be sane");

  f = fifo_segment_alloc_fifo (fs, n_free_chunk_bytes / 2,
			       FIFO_SEGMENT_RX_FIFO);
  SFIFO_TEST (f != 0, "allocation should work");
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  fifo_segment_free_fifo (fs, tf);
  fifo_segment_free_fifo (fs, f);

  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (n_free_chunk_bytes == rv, "free chunk bytes expected %u is %u",
	      n_free_chunk_bytes, rv);

  /*
   * Try to allocate more than space available
   */

  f = fifo_segment_alloc_fifo (fs, n_free_chunk_bytes + fifo_size,
			       FIFO_SEGMENT_RX_FIFO);
  SFIFO_TEST (f == 0, "allocation should fail");

  /*
   * Allocate fifo and try to grow beyond available space
   */
  f = fifo_segment_alloc_fifo (fs, fifo_segment_free_bytes (fs),
			       FIFO_SEGMENT_RX_FIFO);

  /* Try to force fifo growth */
  new_size = svm_fifo_size (f) + n_free_chunk_bytes + 1;
  svm_fifo_set_size (f, new_size);
  validate_test_and_buf_vecs (&test_data, &data_buf, new_size);
  rv = svm_fifo_enqueue (f, new_size, test_data);

  SFIFO_TEST (rv != new_size, "grow should fail size %u wrote %d",
	      new_size, rv);

  fifo_segment_free_fifo (fs, f);

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
  fifo_segment_t *fs;
  svm_fifo_t *f;
  u32 *result;
  int rv, i;

  sleep (2);

  sm->timeout_in_seconds = 5;
  clib_memset (a, 0, sizeof (*a));
  a->segment_name = "fifo-test1";

  rv = fifo_segment_attach (sm, a);

  SFIFO_TEST (!rv, "svm_fifo_segment_attach returned %d", rv);

  fs = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  vec_free (a->new_segment_indices);

  /* might wanna wait.. */
  f = fifo_segment_get_slice_fifo_list (fs, 0);

  /* Lazy bastards united */
  test_data = format (0, "Hello world%c", 0);
  vec_validate (retrieved_data, vec_len (test_data) - 1);

  for (i = 0; i < 1000; i++)
    {
      svm_fifo_dequeue (f, vec_len (retrieved_data), retrieved_data);
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
    svm_fifo_enqueue (f, vec_len (test_data), test_data);

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
sfifo_test_fifo_segment_prealloc (int verbose)
{
  fifo_segment_create_args_t _a, *a = &_a;
  fifo_segment_main_t *sm = &segment_main;
  u32 max_pairs, pairs_req, free_space, pair_mem;
  svm_fifo_t *f, *tf, *old;
  fifo_segment_t *fs;
  int rv, alloc;

  clib_memset (a, 0, sizeof (*a));

  a->segment_name = "fifo-test-prealloc";
  a->segment_size = 256 << 10;
  a->segment_type = SSVM_SEGMENT_MEMFD;

  rv = fifo_segment_create (sm, a);
  SFIFO_TEST (!rv, "svm_fifo_segment_create returned %d", rv);
  fs = fifo_segment_get_segment (sm, a->new_segment_indices[0]);
  fs->h->pct_first_alloc = 100;

  /*
   * Prealloc chunks and headers
   */
  free_space = fifo_segment_free_bytes (fs);
  SFIFO_TEST (free_space <= 256 << 10, "free space expected %u is %u",
	      256 << 10, free_space);
  rv = fifo_segment_prealloc_fifo_chunks (fs, 0, 4096, 50);
  SFIFO_TEST (rv == 0, "chunk prealloc should work");
  rv = fifo_segment_num_free_chunks (fs, 4096);
  SFIFO_TEST (rv == 50, "prealloc chunks expected %u is %u", 50, rv);
  rv = fifo_segment_free_bytes (fs);
  free_space -= (sizeof (svm_fifo_chunk_t) + 4096) * 50;
  SFIFO_TEST (rv == free_space, "free space expected %u is %u", free_space,
	      rv);
  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (rv == 4096 * 50, "chunk free space expected %u is %u",
	      4096 * 50, rv);

  rv = fifo_segment_prealloc_fifo_hdrs (fs, 0, 50);
  SFIFO_TEST (rv == 0, "fifo hdr prealloc should work");
  rv = fifo_segment_num_free_fifos (fs);
  SFIFO_TEST (rv == 50, "prealloc fifo hdrs expected %u is %u", 50, rv);
  rv = fifo_segment_free_bytes (fs);
  free_space -= sizeof (svm_fifo_t) * 50;
  SFIFO_TEST (rv == free_space, "free space expected %u is %u", free_space,
	      rv);

  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_free_bytes (fs);
  SFIFO_TEST (clib_abs (rv - (int) free_space) < 512,
	      "free space expected %u is %u", free_space, rv);

  /* Use all free chunk memory */
  f = fifo_segment_alloc_fifo (fs, 100 << 10, FIFO_SEGMENT_RX_FIFO);
  SFIFO_TEST (f != 0, "fifo allocated");
  SFIFO_TEST (svm_fifo_is_sane (f), "fifo should be sane");

  tf = fifo_segment_alloc_fifo (fs, 100 << 10, FIFO_SEGMENT_RX_FIFO);
  SFIFO_TEST (tf != 0, "fifo allocated");
  SFIFO_TEST (svm_fifo_is_sane (tf), "fifo should be sane");

  rv = fifo_segment_num_free_chunks (fs, 4096);
  SFIFO_TEST (rv == 0, "prealloc chunks expected %u is %u", 0, rv);
  rv = fifo_segment_fl_chunk_bytes (fs);
  SFIFO_TEST (rv == 0, "chunk free space expected %u is %u", 0, rv);


  /*
   * Multiple preallocs that consume the remaining space
   */
  fifo_segment_update_free_bytes (fs);
  free_space = fifo_segment_free_bytes (fs);
  pair_mem = 2 * (4096 + sizeof (*f) + sizeof (svm_fifo_chunk_t));
  max_pairs = pairs_req = (free_space / pair_mem) - 1;
  fifo_segment_preallocate_fifo_pairs (fs, 4096, 4096, &pairs_req);
  SFIFO_TEST (pairs_req == 0, "prealloc pairs should work req %u", max_pairs);
  rv = fifo_segment_num_free_chunks (fs, 4096);
  SFIFO_TEST (rv == max_pairs * 2, "prealloc chunks expected %u is %u",
	      max_pairs * 2, rv);

  fifo_segment_update_free_bytes (fs);
  rv = fifo_segment_free_bytes (fs);
  SFIFO_TEST (rv < 2 * pair_mem, "free bytes %u less than %u", rv,
	      2 * pair_mem);

  /* Preallocate as many more chunks as possible. Heap is almost full
   * so we may not use all the free space*/
  alloc = 0;
  while (!fifo_segment_prealloc_fifo_chunks (fs, 0, 4096, 1))
    alloc++;
  SFIFO_TEST (alloc, "chunk prealloc should work %u", alloc);
  rv = fifo_segment_num_free_chunks (fs, 4096);
  SFIFO_TEST (rv == max_pairs * 2 + alloc, "prealloc chunks expected %u "
	      "is %u", max_pairs * 2 + alloc, rv);

  rv = fifo_segment_free_bytes (fs);
  SFIFO_TEST (rv < pair_mem, "free bytes expected less than %u is %u",
	      pair_mem, rv);

  /*
   * Test negative prealloc cases
   */
  pairs_req = 1;
  fifo_segment_preallocate_fifo_pairs (fs, 4096, 4096, &pairs_req);
  SFIFO_TEST (pairs_req == 1, "prealloc pairs should not work");

  old = f;
  f = fifo_segment_alloc_fifo (fs, 200 << 10, FIFO_SEGMENT_RX_FIFO);
  SFIFO_TEST (f == 0, "fifo alloc should fail");

  rv = fifo_segment_prealloc_fifo_chunks (fs, 0, 4096, 50);
  SFIFO_TEST (rv == -1, "chunk prealloc should fail");

  rv = fifo_segment_prealloc_fifo_hdrs (fs, 0, 50);
  SFIFO_TEST (rv == -1, "fifo hdr prealloc should fail");

  /*
   * Cleanup
   */
  fifo_segment_free_fifo (fs, old);
  fifo_segment_free_fifo (fs, tf);
  close (fs->ssvm.fd);
  fifo_segment_delete (sm, fs);
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
      else if (unformat (input, "prealloc"))
	{
	  if ((rv = sfifo_test_fifo_segment_prealloc (verbose)))
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
	  if ((rv = sfifo_test_fifo_segment_prealloc (verbose)))
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

  clib_warning ("high mem %lu", HIGH_SEGMENT_BASEVA);
  fifo_segment_main_init (&segment_main, HIGH_SEGMENT_BASEVA, 5);
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
      else if (unformat (input, "shrink"))
	res = sfifo_test_fifo_shrink (vm, input);
      else if (unformat (input, "indirect"))
	res = sfifo_test_fifo_indirect (vm, input);
      else if (unformat (input, "zero"))
	res = sfifo_test_fifo_make_rcv_wnd_zero (vm, input);
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

	  if ((res = sfifo_test_fifo_shrink (vm, input)))
	    goto done;

	  if ((res = sfifo_test_fifo_indirect (vm, input)))
	    goto done;

	  if ((res = sfifo_test_fifo_make_rcv_wnd_zero (vm, input)))
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
