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

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_sa.h>

static clib_error_t *
test_ipsec_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u64 seq_num;
  u32 sa_id;

  sa_id = ~0;
  seq_num = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sa %d", &sa_id))
	;
      else if (unformat (input, "seq 0x%llx", &seq_num))
	;
      else
	break;
    }

  if (~0 != sa_id)
    {
      ipsec_main_t *im = &ipsec_main;
      ipsec_sa_t *sa;
      u32 sa_index;

      sa_index = ipsec_get_sa_index_by_sa_id (sa_id);
      sa = pool_elt_at_index (im->sad, sa_index);

      sa->seq = seq_num & 0xffffffff;
      sa->seq_hi = seq_num >> 32;
    }
  else
    {
      return clib_error_return (0, "unknown SA `%U'",
				format_unformat_error, input);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_ipsec_command, static) =
{
  .path = "test ipsec",
  .short_help = "test ipsec sa <ID> seq-num <VALUE>",
  .function = test_ipsec_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
