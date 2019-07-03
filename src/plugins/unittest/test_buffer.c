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

#define TEST_I(_cond, _comment, _args...)			\
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

#define TEST(_cond, _comment, _args...)			\
{								\
    if (!TEST_I(_cond, _comment, ##_args)) {		\
	return 1;                                               \
    }								\
}

/* test function for a specific case where current_data is negative, verify
 * that there is no crash */
static int
linearize_negative_current_data (vlib_main_t * vm)
{
  u32 bi[32];
  TEST (ARRAY_LEN (bi) == vlib_buffer_alloc (vm, bi, ARRAY_LEN (bi)),
	"buff alloc");
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  u32 i;
  for (i = 0; i < ARRAY_LEN (bi) - 1; ++i)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[i]);
      b->next_buffer = bi[i + 1];
      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b->current_data = -14;
      b->current_length = 14 + data_size;
    }

  (void) vlib_buffer_chain_linearize (vm, vlib_get_buffer (vm, bi[0]));

  return 0;
}

static clib_error_t *
test_linearize_fn (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{

  if (linearize_negative_current_data (vm))
    {
      return clib_error_return (0, "linearize_negative_current_data failed");
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_linearize_command, static) =
{
  .path = "test chained-buffer-linearization",
  .short_help = "test chained-buffer-linearization",
  .function = test_linearize_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
