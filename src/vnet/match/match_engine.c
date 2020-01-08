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
typedef struct match_engines_t_
{
  match_engine_reg_t
    * me_engines[MATCH_N_SEMANTICS][MATCH_N_TYPES][MATCH_ENGINE_LEN_LOG2S];
} match_engines_t;

static match_engine_vft_t match_engine_noop;
static match_engines_t match_engines;
static match_engines_t match_engine_defaults;

#define FOR_EACH_MATCH_LEN_LOG2(_len) \
  for (_len = 0; _len < MATCH_ENGINE_LEN_LOG2S; _len++)

static int
match_engine_reg_cmp (void *a1, void *a2)
{
  match_engine_reg_t *meg1 = a1, *meg2 = a2;

  if (meg1->meg_prio == meg2->meg_prio)
    return 1;
  return (meg1->meg_prio - meg2->meg_prio);
}

static void
match_engine_copy (const match_engines_t * src, match_engines_t * dst)
{
  match_semantic_t sem;
  match_type_t type;
  u8 log2;

  FOR_EACH_MATCH_SEMANTIC (sem)
    FOR_EACH_MATCH_TYPE (type) FOR_EACH_MATCH_LEN_LOG2 (log2)
  {
    vec_free (dst->me_engines[sem][type][log2]);
    dst->me_engines[sem][type][log2] =
      vec_dup (src->me_engines[sem][type][log2]);
  }
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
	vec_add1 (match_engine_defaults.me_engines[sem][type][i], meg);
	vec_sort_with_function (match_engine_defaults.me_engines[sem][type]
				[i], match_engine_reg_cmp);
	i++;
      }
  }

  while (i < MATCH_ENGINE_LEN_LOG2S)
    {
      vec_add1 (match_engine_defaults.me_engines[sem][type][i], meg);
      vec_sort_with_function (match_engine_defaults.me_engines[sem][type][i],
			      match_engine_reg_cmp);
      i++;
    }

  match_engine_copy (&match_engine_defaults, &match_engines);
}

const match_engine_vft_t *
match_engine_get (match_semantic_t sem, match_type_t type, u32 set_size)
{
  u32 log2;

  if (0 == set_size)
    return (&match_engine_noop);

  log2 = count_trailing_zeros (max_pow2 (set_size));

  return (&match_engines.me_engines[sem][type][log2][0].meg_vft);
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
	vec_foreach (meg, match_engines.me_engines[sem][type][log2])
	{
	  vlib_cli_output (vm, "   %d: %s", meg->meg_prio, meg->meg_name);
	}
      }
    }
  }

  return (NULL);
}

void
match_engine_restore_defaults (void)
{
  match_engine_copy (&match_engine_defaults, &match_engines);
}

static clib_error_t *
match_engine_restore_defaults_cli (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  match_engine_restore_defaults ();

  return (NULL);
}

void
match_engine_set_priority (const char *engine,
			   match_semantic_t msem,
			   match_type_t mtype, u32 len, u32 priority)
{
  match_engine_reg_t *meg;

  vec_foreach (meg, match_engines.me_engines[msem][mtype][len])
  {
    if (NULL == engine || 0 == strcmp (engine, meg->meg_name))
      {
	meg->meg_prio = priority;
	break;
      }
  }
  vec_sort_with_function (match_engines.me_engines[msem][mtype][len],
			  match_engine_reg_cmp);
}

static clib_error_t *
match_engine_set (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
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

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "priority %d", &priority))
	;
      else if (unformat (line_input, "%U", unformat_match_type, &mtype_begin))
	mtype_end = mtype_begin + 1;
      else
	if (unformat (line_input, "%U", unformat_match_semantic, &msem_begin))
	msem_end = msem_begin + 1;
      else if (unformat (line_input, "%d", &len_begin))
	len_end = len_begin + 1;
      else
	if (unformat (line_input, "%U", unformat_token, valid_chars, &engine))
	;
      else
	return clib_error_return (0, "error");
    }

  if (~0 == priority)
    return clib_error_return (0, "specify priority");

  for (msem = msem_begin; msem < msem_end; msem++)
    for (mtype = mtype_begin; mtype < mtype_end; mtype++)
      for (len = len_begin; len < len_end; len++)
	match_engine_set_priority ((char *) engine, msem, mtype, len,
				   priority);

  unformat_free (line_input);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(match_engine_show_cmd) =
{
  .path = "show match engines",
  .short_help = "show match engines",
  .function = match_engine_show,
};
VLIB_CLI_COMMAND(match_engine_restore_defaults_cmd) =
{
  .path = "match engine restore defaults",
  .short_help = "match engine restore defaults",
  .function = match_engine_restore_defaults_cli,
};
VLIB_CLI_COMMAND(match_engine_set_cmd) =
{
  .path = "match engine set",
  .short_help = "match engine set",
  .function = match_engine_set,
};
/* *INDENT-ON* */

static bool
match_noop_match (vlib_main_t * vm,
		  vlib_buffer_t * buf,
		  i16 l2_offset,
		  i16 l3_offset,
		  const struct match_set_app_t_ *app,
		  f64 now, match_result_t * result)
{
  *result = MATCH_RESULT_MISS;
  return (false);
}

static void
match_noop_apply (match_set_t * mt,
		  match_semantic_t semantic,
		  match_set_tag_flags_t flags, match_set_app_t * msa)
{
  msa->msa_match = match_noop_match;
  msa->msa_index = 0;
}

static void
match_noop_update (match_set_t * mt,
		   index_t msei, const match_set_app_t * msa)
{
}

static void
match_noop_unapply (match_set_t * mt, const match_set_app_t * msa)
{
}

static u8 *
format_match_noop (u8 * s, va_list * l)
{
  return (format (s, "noop"));
}

static match_engine_vft_t match_engine_noop = {
  .mev_apply = match_noop_apply,
  .mev_unapply = match_noop_unapply,
  .mev_list_actions = {
		       [MATCH_ENGINE_LIST_ADD] = match_noop_update,
		       [MATCH_ENGINE_LIST_REPLACE] = match_noop_update,
		       [MATCH_ENGINE_LIST_DELETE] = match_noop_update,
		       },
  .mev_format = format_match_noop,
};

static clib_error_t *
match_engine_init (vlib_main_t * vm)
{

  return (NULL);
}

VLIB_INIT_FUNCTION (match_engine_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
