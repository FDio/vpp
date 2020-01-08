/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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


#include <vnet/match/match_engine.h>

typedef struct match_engine_reg_t_
{
  const char *meg_name;
  u32 meg_prio;
  match_engine_vft_t meg_vft;
} match_engine_reg_t;

static match_engine_reg_t *match_engines[MATCH_N_SEMANTICS][MATCH_N_TYPES];

static int
match_engine_reg_cmp (void *a1, void *a2)
{
  match_engine_reg_t *meg1 = a1, *meg2 = a2;

  return (meg1->meg_prio - meg2->meg_prio);
}

void
match_engine_register (const char *name,
		       match_type_t type,
		       match_semantic_t sem,
		       u32 prio, const match_engine_vft_t * vft)
{
  match_engine_reg_t meg = {
    .meg_name = strdup (name),
    .meg_prio = prio,
    .meg_vft = *vft,
  };
  vec_add1 (match_engines[sem][type], meg);
  vec_sort_with_function (match_engines[sem][type], match_engine_reg_cmp);
}

const match_engine_vft_t *
match_engine_get (match_semantic_t sem, match_type_t type)
{
  return (&match_engines[sem][type][0].meg_vft);
}

static clib_error_t *
match_engine_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const match_engine_reg_t *meg;
  match_semantic_t sem;
  match_type_t type;

  for (sem = 0; sem < ARRAY_LEN (match_engines); sem++)
    {
      for (type = 0; type < ARRAY_LEN (match_engines[0]); type++)
	{
	  vlib_cli_output (vm, " %U - %U",
			   format_match_semantic, sem,
			   format_match_type, type);
	  vec_foreach (meg, match_engines[sem][type])
	  {
	    vlib_cli_output (vm, "  %d: %s", meg->meg_prio, meg->meg_name);
	  }
	}
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(match_engine_show_cmd) =
{
    .path = "show match engines",
    .short_help = "show match engines",
    .function = match_engine_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
