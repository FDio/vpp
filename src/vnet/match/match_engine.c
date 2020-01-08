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

/**
 * Maintain ranked engine configs per-semantic, per-type and per-list length
 * (by powers of 2)
 */
#define MATCH_ENGINE_LEN_LOG2S 24
static match_engine_reg_t
  * match_engines[MATCH_N_SEMANTICS][MATCH_N_TYPES][MATCH_ENGINE_LEN_LOG2S];
static match_engine_reg_t
  * match_engine_defaults[MATCH_N_SEMANTICS][MATCH_N_TYPES]
  [MATCH_ENGINE_LEN_LOG2S];

#define FOR_EACH_MATCH_LEN_LOG2(_len) \
  for (_len = 0; _len < MATCH_ENGINE_LEN_LOG2S; _len++)

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
		       const match_engine_vft_t * vft,
		       const match_engine_priority_t * priorities)
{
  const match_engine_priority_t *p;
  match_engine_reg_t meg;
  u32 i, len;

  i = 0;

  vec_foreach (p, priorities)
  {
    meg.meg_name = strdup (name);
    meg.meg_prio = p->prio;
    meg.meg_vft = *vft;

    len = max_pow2 (p->len);

    while (len >= (1 << i) && i < MATCH_ENGINE_LEN_LOG2S)
      {
	vec_add1 (match_engine_defaults[sem][type][i], meg);
	vec_sort_with_function (match_engine_defaults[sem][type][i],
				match_engine_reg_cmp);
	i++;
      }
  }

  while (i < MATCH_ENGINE_LEN_LOG2S)
    {
      vec_add1 (match_engine_defaults[sem][type][i], meg);
      vec_sort_with_function (match_engine_defaults[sem][type][i],
			      match_engine_reg_cmp);
      i++;
    }

  clib_memcpy (match_engines, match_engine_defaults,
	       sizeof (match_engine_defaults));
}

const match_engine_vft_t *
match_engine_get (match_semantic_t sem, match_type_t type, u32 set_size)
{
  u32 log2, len2 = max_pow2 (set_size);

  log2 = count_trailing_zeros (len2);

  return (&match_engines[sem][type][log2][0].meg_vft);
}

static clib_error_t *
match_engine_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const match_engine_reg_t *meg;
  match_semantic_t sem;
  match_type_t type;
  u8 log2;

  FOR_EACH_MATCH_SEMANTIC (sem)
  {
    FOR_EACH_MATCH_TYPE (type)
    {
      vlib_cli_output (vm, " %U - %U",
		       format_match_semantic, sem, format_match_type, type);
      FOR_EACH_MATCH_LEN_LOG2 (log2)
      {
	vlib_cli_output (vm, "  %d:", (1 << log2));
	vec_foreach (meg, match_engines[sem][type][log2])
	{
	  vlib_cli_output (vm, "   %d: %s", meg->meg_prio, meg->meg_name);
	}
      }
    }
  }

  return (NULL);
}

static clib_error_t *
match_engine_restore_defaults (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  clib_memcpy (match_engines,
	       match_engine_defaults, sizeof (match_engine_defaults));

  return (NULL);
}

static clib_error_t *
match_engine_set (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  match_semantic_t msem, msem_begin, msem_end;
  match_type_t mtype, mtype_begin, mtype_end;
  u32 priority, len, len_begin, len_end;
  u8 *engine;

  len_begin = 0;
  len_end = MATCH_ENGINE_LEN_LOG2S;
  mtype_begin = 0;
  mtype_end = MATCH_N_TYPES;
  msem_begin = 0;
  msem_end = MATCH_N_SEMANTICS;
  priority = ~0;

  const char *valid_chars = "a-zA-Z0-9_";

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "priority %d", &priority))
	;
      else if (unformat (input, "%U", unformat_match_type, &mtype_begin))
	mtype_end = mtype_begin + 1;
      else if (unformat (input, "%U", unformat_match_semantic, &msem_begin))
	msem_end = msem_begin + 1;
      else if (unformat (input, "%d", &len_begin))
	len_end = len_begin + 1;
      else if (unformat (input, "%U", unformat_token, valid_chars, &engine))
	;
      else
	return clib_error_return (0, "error");
    }

  if (~0 == priority)
    return clib_error_return (0, "specify priority");

  for (msem = msem_begin; msem < msem_end; msem++)
    {
      for (mtype = mtype_begin; mtype < mtype_end; mtype++)
	{
	  for (len = len_begin; len < len_end; len++)
	    {
	      match_engine_reg_t *meg;

	      vec_foreach (meg, match_engines[msem][mtype][len])
	      {
		if (0 == strcmp (meg->meg_name, (char *) engine))
		  {
		    meg->meg_prio = priority;
		    break;
		  }
	      }
	      vec_sort_with_function (match_engines[msem][mtype][len],
				      match_engine_reg_cmp);
	    }
	}
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(match_engine_restore_defaults_cmd) =
{
    .path = "show match engines",
    .short_help = "show match engines",
    .function = match_engine_show,
};
VLIB_CLI_COMMAND(match_engine_show_cmd) =
{
    .path = "match engine restore defaults",
    .short_help = "match engine restore defaults",
    .function = match_engine_restore_defaults,
};
VLIB_CLI_COMMAND(match_engine_set_cmd) =
{
    .path = "match engine set",
    .short_help = "match engine set",
    .function = match_engine_set,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
