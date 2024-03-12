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

#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>

#define TEST_I(_cond, _comment, _args...)                                     \
  ({                                                                          \
    int _evald = (0 == (_cond));                                              \
    if (_evald)                                                               \
      {                                                                       \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);       \
      }                                                                       \
    _evald;                                                                   \
  })

#define TEST(_cond, _comment, _args...)                                       \
  {                                                                           \
    if (TEST_I (_cond, _comment, ##_args))                                    \
      {                                                                       \
	goto err;                                                             \
      }                                                                       \
  }

typedef struct
{
  i16 current_data;
  u16 current_length;
  u8 ref_count;
} chained_buffer_template_t;

static int
build_chain (vlib_main_t *vm, const chained_buffer_template_t *tmpl, u32 n,
	     clib_random_buffer_t *randbuf, u8 **rand, vlib_buffer_t **b_,
	     u32 *bi_)
{
  vlib_buffer_t *bufs[2 * VLIB_BUFFER_LINEARIZE_MAX], **b = bufs;
  u32 bis[2 * VLIB_BUFFER_LINEARIZE_MAX + 1], *bi = bis;
  u32 n_alloc;

  if (rand)
    vec_reset_length (*rand);

  ASSERT (n <= ARRAY_LEN (bufs));
  n_alloc = vlib_buffer_alloc (vm, bi, n);
  if (n_alloc != n)
    {
      vlib_buffer_free (vm, bi, n_alloc);
      return 0;
    }

  vlib_get_buffers (vm, bis, bufs, n);

  while (n > 0)
    {
      b[0]->next_buffer = bi[1];
      b[0]->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b[0]->current_data = tmpl->current_data;
      b[0]->current_length = tmpl->current_length;
      b[0]->ref_count = 0xff == tmpl->ref_count ? 1 : tmpl->ref_count;

      if (rand)
	{
	  const u16 len = b[0]->current_length;
	  if (len)
	    {
	      vec_add (*rand, clib_random_buffer_get_data (randbuf, len), len);
	      void *dst = vlib_buffer_get_current (b[0]);
	      const void *src =
		vec_elt_at_index (*rand, vec_len (*rand) - len);
	      clib_memcpy_fast (dst, src, len);
	    }
	}

      b++;
      bi++;
      tmpl++;
      n--;
    }

  b[-1]->flags &= ~VLIB_BUFFER_NEXT_PRESENT;

  *b_ = bufs[0];
  *bi_ = bis[0];
  return 1;
}

static int
check_chain (vlib_main_t *vm, vlib_buffer_t *b, const u8 *rand)
{
  int len_chain = vlib_buffer_length_in_chain (vm, b);
  int len;

  /* check for data corruption */
  if (clib_memcmp (vlib_buffer_get_current (b), vec_elt_at_index (rand, 0),
		   b->current_length))
    return 0;
  len = b->current_length;
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      if (clib_memcmp (vlib_buffer_get_current (b),
		       vec_elt_at_index (rand, len), b->current_length))
	return 0;
      len += b->current_length;
    }

  /* check for data truncation */
  if (len != vec_len (rand))
    return 0;

  /* check total length update is correct */
  if (len != len_chain)
    return 0;

  return 1;
}

static int
test_chain (vlib_main_t *vm, const chained_buffer_template_t *tmpl,
	    const u32 n, const int clone_off, clib_random_buffer_t *randbuf,
	    u8 **rand)
{
  vlib_buffer_t *b;
  u32 bi[2];
  int ret = 0;

  if (!build_chain (vm, tmpl, n, randbuf, rand, &b, bi))
    goto err0;

  if (clone_off)
    {
      if (2 != vlib_buffer_clone (vm, bi[0], bi, 2, clone_off))
	goto err1;
      b = vlib_get_buffer (vm, bi[0]);
    }

  if (!(ret = vlib_buffer_chain_linearize (vm, b)))
    goto err2;

  if (!check_chain (vm, b, *rand))
    {
      ret = 0;
      goto err2;
    }

err2:
  if (clone_off)
    vlib_buffer_free_one (vm, bi[1]);
err1:
  vlib_buffer_free_one (vm, bi[0]);
err0:
  return ret;
}

static int
linearize_test (vlib_main_t *vm)
{
  chained_buffer_template_t tmpl[VLIB_BUFFER_LINEARIZE_MAX];
  clib_random_buffer_t randbuf;
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  u8 *rand = 0;
  int ret = 0;
  int i;

  clib_random_buffer_init (&randbuf, 0);

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  for (i = 0; i < 2; i++)
    {
      tmpl[i].current_data = -14;
      tmpl[i].current_length = 14 + data_size;
    }
  TEST (2 == test_chain (vm, tmpl, 2, 0, &randbuf, &rand),
	"linearize chain with negative current data");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  tmpl[0].current_data = 12;
  tmpl[0].current_length = data_size - 12;
  tmpl[1].current_data = 0;
  tmpl[1].current_length = 0;
  TEST (1 == test_chain (vm, tmpl, 2, 0, &randbuf, &rand),
	"linearize chain with empty next");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  tmpl[0].current_data = 0;
  tmpl[0].current_length = data_size - 17;
  tmpl[1].current_data = -5;
  tmpl[1].current_length = 3;
  tmpl[2].current_data = 17;
  tmpl[2].current_length = 9;
  tmpl[3].current_data = 3;
  tmpl[3].current_length = 5;
  TEST (1 == test_chain (vm, tmpl, 4, 0, &randbuf, &rand),
	"linearize chain into a single buffer");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  tmpl[0].current_data = 0;
  tmpl[0].current_length = data_size - 2;
  tmpl[1].current_data = -VLIB_BUFFER_PRE_DATA_SIZE;
  tmpl[1].current_length = 20;
  tmpl[2].current_data = data_size - 10;
  tmpl[2].current_length = 10;
  tmpl[3].current_data = 0;
  tmpl[3].current_length = data_size;
  TEST (2 == test_chain (vm, tmpl, 4, data_size - 1, &randbuf, &rand),
	"linearize cloned chain");

  clib_memset (tmpl, 0xff, sizeof (tmpl));
  for (i = 0; i < 100; i++)
    {
      u8 *r = clib_random_buffer_get_data (&randbuf, 1);
      int n = clib_max (r[0] % ARRAY_LEN (tmpl), 1);
      int j;
      for (j = 0; j < n; j++)
	{
	  r = clib_random_buffer_get_data (&randbuf, 3);
	  i16 current_data = (i16) r[0] - VLIB_BUFFER_PRE_DATA_SIZE;
	  u16 current_length = *(u16 *) (r + 1) % (data_size - current_data);
	  tmpl[j].current_data = current_data;
	  tmpl[j].current_length = current_length;
	}
      r = clib_random_buffer_get_data (&randbuf, 1);
      TEST (
	test_chain (vm, tmpl, n, r[0] > 250 ? r[0] % 128 : 0, &randbuf, &rand),
	"linearize random chain %d", i);
    }

  ret = 1;
err:
  clib_random_buffer_free (&randbuf);
  vec_free (rand);
  return ret;
}

static clib_error_t *
test_linearize_fn (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{

  if (!linearize_test (vm))
    {
      return clib_error_return (0, "linearize test failed");
    }

  return 0;
}

VLIB_CLI_COMMAND (test_linearize_command, static) =
{
  .path = "test chained-buffer-linearization",
  .short_help = "test chained-buffer-linearization",
  .function = test_linearize_fn,
};

static clib_error_t *
test_linearize_speed_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  /* typical 9000-bytes TCP jumbo frames */
  const chained_buffer_template_t tmpl[5] = { { 14, 2034, 1 },
					      { 0, 2048, 1 },
					      { 0, 2048, 1 },
					      { 0, 2048, 1 },
					      { 0, 808, 1 } };
  int i, j;

  for (i = 0; i < 10; i++)
    {
      u64 tot = 0;
      for (j = 0; j < 100000; j++)
	{
	  vlib_buffer_t *b;
	  u32 bi;

	  if (!build_chain (vm, tmpl, 5, 0, 0, &b, &bi))
	    return clib_error_create ("build_chain() failed");

	  CLIB_COMPILER_BARRIER ();
	  u64 start = clib_cpu_time_now ();
	  CLIB_COMPILER_BARRIER ();

	  vlib_buffer_chain_linearize (vm, b);

	  CLIB_COMPILER_BARRIER ();
	  tot += clib_cpu_time_now () - start;
	  CLIB_COMPILER_BARRIER ();

	  vlib_buffer_free_one (vm, bi);
	}
      vlib_cli_output (vm, "%.03f ticks/call", (f64) tot / j);
    }

  return 0;
}

VLIB_CLI_COMMAND (test_linearize_speed_command, static) = {
  .path = "test chained-buffer-linearization speed",
  .short_help = "test chained-buffer-linearization speed",
  .function = test_linearize_speed_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
