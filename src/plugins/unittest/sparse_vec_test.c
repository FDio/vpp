/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vppinfra/sparse_vec.h>

static clib_error_t *
test_sparse_vec_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  /* A sparse vector ... */
  int *spv = 0;
  int i, c0, c1;
  u32 i0, i1;

  /* set one member */
  sparse_vec_validate (spv, 42)[0] = 0x4242;
  /* count how many times we can find it */
  c0 = 0;
  for (i = 0; i <= 0xffff; i++)
    {
      c0 += (sparse_vec_index (spv, i) != 0);
    }

  if (c0 != 1)
    vlib_cli_output (vm, "sparse_vec_index failed: c0 is %d != 1", c0);

  c0 = 0;
  c1 = 0;
  for (i = 0; i <= 0xffff; i++)
    {
      sparse_vec_index2 (spv, i, 0xffff ^ i, &i0, &i1);
      c0 += (i0 != 0);
      c1 += (i1 != 0);
    }

  if (c0 != 1)
    vlib_cli_output (vm, "sparse_vec_index2 failed: c0 is %d != 1", c0);
  if (c1 != 1)
    vlib_cli_output (vm, "sparse_vec_index2 failed: c1 is %d != 1", c1);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_sparse_vec_command, static) =
{
  .path = "test sparse_vec",
  .short_help = "test sparse_vec",
  .function = test_sparse_vec_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
