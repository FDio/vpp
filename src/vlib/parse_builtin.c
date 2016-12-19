/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vlib/parse.h>

always_inline void *
parse_last_match_value (vlib_parse_main_t * pm)
{
  vlib_parse_item_t *i;
  i = pool_elt_at_index (pm->parse_items,
			 vec_elt (pm->match_items,
				  vec_len (pm->match_items) - 1));
  return i->value.as_pointer;
}

vlib_parse_match_t
eof_match (vlib_parse_main_t * pm, vlib_parse_type_t * type,
	   vlib_lex_token_t * t, vlib_parse_value_t * valuep)
{
  return t->token ==
    VLIB_LEX_eof ? VLIB_PARSE_MATCH_DONE : VLIB_PARSE_MATCH_FAIL;
}

PARSE_TYPE_INIT (eof, eof_match, 0 /* cleanup value */ ,
		 0 /* format value */ );

vlib_parse_match_t
rule_eof_match (vlib_parse_main_t * pm, vlib_parse_type_t * type,
		vlib_lex_token_t * t, vlib_parse_value_t * valuep)
{
  vlib_parse_match_function_t *fp = parse_last_match_value (pm);
  pm->current_token_index--;
  return fp ? fp (pm, type, t, valuep) : VLIB_PARSE_MATCH_RULE;
}

PARSE_TYPE_INIT (rule_eof, rule_eof_match, 0, 0);

vlib_parse_match_t
word_match (vlib_parse_main_t * pm, vlib_parse_type_t * type,
	    vlib_lex_token_t * t, vlib_parse_value_t * valuep)
{
  u8 *tv, *iv;
  int i;

  if (t->token != VLIB_LEX_word)
    return VLIB_PARSE_MATCH_FAIL;

  tv = t->value.as_pointer;
  iv = parse_last_match_value (pm);

  for (i = 0; tv[i]; i++)
    {
      if (tv[i] != iv[i])
	return VLIB_PARSE_MATCH_FAIL;
    }

  return iv[i] == 0 ? VLIB_PARSE_MATCH_FULL : VLIB_PARSE_MATCH_PARTIAL;
}

PARSE_TYPE_INIT (word, word_match, 0 /* clnup value */ ,
		 0 /* format value */ );

vlib_parse_match_t
number_match (vlib_parse_main_t * pm, vlib_parse_type_t * type,
	      vlib_lex_token_t * t, vlib_parse_value_t * valuep)
{
  if (t->token == VLIB_LEX_number)
    {
      valuep->value.as_uword = t->value.as_uword;
      return VLIB_PARSE_MATCH_VALUE;
    }
  return VLIB_PARSE_MATCH_FAIL;
}

static u8 *
format_value_number (u8 * s, va_list * args)
{
  vlib_parse_value_t *v = va_arg (*args, vlib_parse_value_t *);
  uword a = v->value.as_uword;

  if (BITS (uword) == 64)
    s = format (s, "%lld(0x%llx)", a, a);
  else
    s = format (s, "%ld(0x%lx)", a, a);
  return s;
}

PARSE_TYPE_INIT (number, number_match, 0 /* cln value */ ,
		 format_value_number /* fmt value */ );


#define foreach_vanilla_lex_match_function      \
    _(plus)                                     \
    _(minus)                                    \
    _(star)                                     \
    _(slash)                                    \
    _(lpar)                                     \
    _(rpar)

#define LEX_MATCH_DEBUG 0

#define _(name)                                                 \
vlib_parse_match_t name##_match (vlib_parse_main_t *pm,         \
                                 vlib_parse_type_t *type,       \
                                 vlib_lex_token_t *t,           \
                                 vlib_parse_value_t *valuep)    \
{                                                               \
  if (LEX_MATCH_DEBUG > 0)                                      \
    clib_warning ("against %U returns %s",                      \
                  format_vlib_lex_token, pm->lex_main, t,       \
                  (t->token == VLIB_LEX_##name)                 \
                  ? "VLIB_PARSE_MATCH_FULL" :                   \
                  "VLIB_PARSE_MATCH_FAIL");                     \
  if (t->token == VLIB_LEX_##name)                              \
    return VLIB_PARSE_MATCH_FULL;                               \
  return VLIB_PARSE_MATCH_FAIL;                                 \
}                                                               \
                                                                \
PARSE_TYPE_INIT (name, name##_match, 0 /* cln value */,         \
                 0 /* fmt val */);

foreach_vanilla_lex_match_function
#undef _
/* So we're linked in. */
static clib_error_t *
parse_builtin_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (parse_builtin_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
