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
#include <vlib/unix/unix.h>

static u8 *
format_value_v4_address (u8 * s, va_list * args)
{
  vlib_parse_value_t *v = va_arg (*args, vlib_parse_value_t *);
  u32 a = v->value.as_uword;

  s = format (s, "%d.%d.%d.%d",
	      (a >> 24) & 0xFF,
	      (a >> 16) & 0xFF, (a >> 8) & 0xFF, (a >> 0) & 0xFF);

  return s;
}

static vlib_parse_match_t
v4_address_match (vlib_parse_main_t * pm, vlib_parse_type_t * type,
		  vlib_lex_token_t * t, vlib_parse_value_t * valuep)
{
  u32 digit;
  u32 value = 0;
  int i;

  if (vec_len (pm->tokens) - (t - pm->tokens) < 7)
    return VLIB_PARSE_MATCH_FAIL;

  /* NUMBER DOT NUMBER DOT NUMBER DOT NUMBER */

  for (i = 0; i < 7; i++)
    {
      if ((i & 1) == 0)
	{
	  if (t[i].token != VLIB_LEX_number)
	    return VLIB_PARSE_MATCH_FAIL;
	  if (t[i].value.as_uword > 0xff)
	    return VLIB_PARSE_MATCH_FAIL;
	  digit = t[i].value.as_uword;
	  value = (value << 8) | digit;
	}
      else
	{
	  if (t[i].token != VLIB_LEX_dot)
	    return VLIB_PARSE_MATCH_FAIL;
	}
    }
  /* note: caller advances by 1 */
  pm->current_token_index += 6;
  valuep->value.as_uword = value;
  return VLIB_PARSE_MATCH_VALUE;
}

PARSE_TYPE_INIT (v4_address, v4_address_match, 0, format_value_v4_address)
     static u8 *format_value_v4_address_and_mask (u8 * s, va_list * args)
{
  vlib_parse_value_t *v = va_arg (*args, vlib_parse_value_t *);
  u32 *a = v->value.as_pointer;

  s = format (s, "%d.%d.%d.%d",
	      (a[0] >> 24) & 0xFF,
	      (a[0] >> 16) & 0xFF, (a[0] >> 8) & 0xFF, (a[0] >> 0) & 0xFF);
  s = format (s, "/%d", a[1]);

  return s;
}

static vlib_parse_match_t
v4_address_and_mask_match (vlib_parse_main_t * pm, vlib_parse_type_t * type,
			   vlib_lex_token_t * t, vlib_parse_value_t * valuep)
{
  u32 digit;
  u32 address = 0;
  u32 *rv = 0;
  int i;

  if (vec_len (pm->tokens) - (t - pm->tokens) < 9)
    return VLIB_PARSE_MATCH_FAIL;

  /* NUMBER DOT NUMBER DOT NUMBER DOT NUMBER */

  for (i = 0; i < 7; i++)
    {
      if ((i & 1) == 0)
	{
	  if (t[i].token != VLIB_LEX_number)
	    return VLIB_PARSE_MATCH_FAIL;
	  if (t[i].value.as_uword > 0xff)
	    return VLIB_PARSE_MATCH_FAIL;
	  digit = t[i].value.as_uword;
	  address = (address << 8) | digit;
	}
      else
	{
	  if (t[i].token != VLIB_LEX_dot)
	    return VLIB_PARSE_MATCH_FAIL;
	}
    }

  if (t[7].token != VLIB_LEX_slash || t[8].token != VLIB_LEX_number)
    return VLIB_PARSE_MATCH_FAIL;

  vec_add1 (rv, address);
  vec_add1 (rv, t[8].value.as_uword);

  /* note: caller advances by 1 */
  pm->current_token_index += 8;
  valuep->value.as_pointer = rv;
  return VLIB_PARSE_MATCH_VALUE;
}

void
v4_address_and_mask_cleanup (vlib_parse_value_t * valuep)
{
  u32 *trash = valuep->value.as_pointer;
  vec_free (trash);
}

PARSE_TYPE_INIT (v4_address_and_mask, v4_address_and_mask_match,
		 v4_address_and_mask_cleanup,
		 format_value_v4_address_and_mask)
     vlib_lex_main_t vlib_lex_main;



     vlib_parse_match_t eval_factor0 (vlib_parse_main_t * pm,
				      vlib_parse_item_t * item,
				      vlib_parse_value_t * value)
{
  clib_warning ("%U", format_vlib_parse_value, pm);
  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_factor1 (vlib_parse_main_t * pm,
	      vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  clib_warning ("%U", format_vlib_parse_value, pm);
  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_factor2 (vlib_parse_main_t * pm,
	      vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  word a;
  int index = vec_len (pm->parse_value) - 1;

  a = pm->parse_value[index].value.as_word;

  pm->parse_value[index].value.as_word = -a;
  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_term0 (vlib_parse_main_t * pm,
	    vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  clib_warning ("%U", format_vlib_parse_value, pm);
  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_term1 (vlib_parse_main_t * pm,
	    vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  uword a, b;
  int index = vec_len (pm->parse_value) - 2;

  a = pm->parse_value[index].value.as_uword;
  b = pm->parse_value[index + 1].value.as_uword;

  pm->parse_value[index].value.as_uword = a * b;
  _vec_len (pm->parse_value) -= 1;
  clib_warning ("%U", format_vlib_parse_value, pm);

  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_term2 (vlib_parse_main_t * pm,
	    vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  uword a, b;
  int index = vec_len (pm->parse_value) - 2;

  a = pm->parse_value[index].value.as_uword;
  b = pm->parse_value[index + 1].value.as_uword;

  pm->parse_value[index].value.as_uword = a / b;
  _vec_len (pm->parse_value) -= 1;
  clib_warning ("%U", format_vlib_parse_value, pm);

  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_exp0 (vlib_parse_main_t * pm,
	   vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_exp1 (vlib_parse_main_t * pm,
	   vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  uword a, b;
  int index = vec_len (pm->parse_value) - 2;

  a = pm->parse_value[index].value.as_uword;
  b = pm->parse_value[index + 1].value.as_uword;

  pm->parse_value[index].value.as_uword = a + b;
  _vec_len (pm->parse_value) -= 1;
  clib_warning ("%U", format_vlib_parse_value, pm);

  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_exp2 (vlib_parse_main_t * pm,
	   vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  uword a, b;
  int index = vec_len (pm->parse_value) - 2;

  a = pm->parse_value[index].value.as_uword;
  b = pm->parse_value[index + 1].value.as_uword;

  pm->parse_value[index].value.as_uword = a - b;
  _vec_len (pm->parse_value) -= 1;
  clib_warning ("%U", format_vlib_parse_value, pm);

  return VLIB_PARSE_MATCH_RULE;
}

vlib_parse_match_t
eval_result (vlib_parse_main_t * pm,
	     vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  clib_warning ("%U", format_vlib_parse_value, pm);
  return VLIB_PARSE_MATCH_DONE;
}

vlib_parse_match_t
noop_match_rule (vlib_parse_main_t * pm,
		 vlib_parse_item_t * item, vlib_parse_value_t * value)
{
  clib_warning ("%U", format_vlib_parse_value, pm);
  return VLIB_PARSE_MATCH_RULE;
}

#if 0
PARSE_INIT (t1, "moo", eval0);
PARSE_INIT (t2, "moo cow mumble", eval1);
PARSE_INIT (t3, "moo cow", eval2);
PARSE_INIT (t4, "moo cow mumble grunch", eval3);
#endif

#if 0
PARSE_INIT (r1, "eval <exp>", eval_result);

PARSE_INIT (r2, "<exp> = <term><exp2>", eval_exp0);
PARSE_INIT (r3, "<exp2> = <plus> <exp>", eval_exp1);
PARSE_INIT (r4, "<exp2> = <minus> <exp>", eval_exp2);
PARSE_INIT (r5, "<exp2> = ", noop_match_rule);
PARSE_TYPE_INIT (exp, rule_match, 0, 0);
PARSE_TYPE_INIT (exp2, rule_match, 0, 0);

PARSE_INIT (r6, "<term> = <factor><term2>", eval_term0);
PARSE_INIT (r7, "<term2> = <star> <term>", eval_term1);
PARSE_INIT (r8, "<term2> = <slash> <term>", eval_term2);
PARSE_INIT (r9, "<term2> = ", noop_match_rule);
PARSE_TYPE_INIT (term, rule_match, 0, 0);
PARSE_TYPE_INIT (term2, rule_match, 0, 0);

PARSE_INIT (r11, "<factor> = <lpar> <exp> <rpar>", eval_factor1);
PARSE_INIT (r10, "<factor> = <number>", eval_factor0);
PARSE_INIT (r12, "<factor> = <minus> <factor>", eval_factor2);

PARSE_TYPE_INIT (factor, rule_match, 0, 0);
#endif

PARSE_INIT (r1, "eval <exp>", eval_result);

#if 1
PARSE_INIT (r2, "<exp> = <term><exp2>", eval_exp0);
PARSE_INIT (r3, "<exp2> = <plus> <exp>", eval_exp1);
PARSE_INIT (r4, "<exp2> = <minus> <exp>", eval_exp2);
PARSE_INIT (r5, "<exp2> = ", noop_match_rule);
PARSE_TYPE_INIT (exp, rule_match, 0, 0);
PARSE_TYPE_INIT (exp2, rule_match, 0, 0);

PARSE_INIT (r6, "<term> = <factor><term2>", eval_term0);
PARSE_INIT (r7, "<term2> = <star> <term>", eval_term1);
PARSE_INIT (r8, "<term2> = <slash> <term>", eval_term2);
PARSE_INIT (r9, "<term2> = ", noop_match_rule);
PARSE_TYPE_INIT (term, rule_match, 0, 0);
PARSE_TYPE_INIT (term2, rule_match, 0, 0);

PARSE_INIT (r11, "<factor> = <lpar> <exp> <rpar>", eval_factor1);
PARSE_INIT (r10, "<factor> = <number>", eval_factor0);
PARSE_INIT (r12, "<factor> = <minus> <factor>", eval_factor2);

PARSE_TYPE_INIT (factor, rule_match, 0, 0);
#endif

#if 0
PARSE_TYPE_INIT (exp, rule_match, 0, 0);
PARSE_INIT (r6, "<exp> = a b", eval_term0);
PARSE_INIT (r7, "<exp> = c d", eval_term1);
PARSE_INIT (r9, "<exp> = ", noop_match_rule);
#endif

#if 0
#define foreach_rule_evaluator                  \
_(0)                                            \
_(1)                                            \
_(2)						\
_(3)

#define _(n)                                            \
vlib_parse_match_t eval##n (vlib_parse_main_t *pm,      \
                            vlib_parse_item_t *item,    \
                            vlib_parse_value_t *value)  \
{                                                       \
  clib_warning ("%U", format_vlib_parse_value, pm);     \
  return VLIB_PARSE_MATCH_DONE;                         \
}
foreach_rule_evaluator
#undef _
PARSE_INIT (r1, "eval <moo>", eval_result);

PARSE_INIT (r2, "<moo> = cow", eval0);
PARSE_INIT (r4, "<moo> = ", eval1);
PARSE_TYPE_INIT (moo, rule_match, 0, 0);
#endif


clib_error_t *
test_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, parse_init)))
    return error;

  return 0;
}

VLIB_INIT_FUNCTION (test_init);

clib_error_t *
vlib_stdlex_init (vlib_main_t * vm)
{
  vlib_lex_main_t *lm = &vlib_lex_main;
  u16 top_index;
  u16 slash_index, slash_star_index, slash_slash_index, slash_star_star_index;
  u16 slash_token;
  u16 word_index;
  u16 zero_index, octal_index, decimal_index, hex_index, binary_index;

  top_index = vlib_lex_add_table ("top");

#define foreach_top_level_single_character_token        \
  _('(', lpar)                                          \
  _(')', rpar)                                          \
  _(';', semi)                                          \
  _('[', lbrack)                                        \
  _(']', rbrack)                                        \
  _('{', lcurly)                                        \
  _('}', rcurly)                                        \
  _('+', plus)                                          \
  _('-', minus)                                         \
  _('*', star)                                          \
  _('%', percent)                                       \
  _('@', atsign)                                        \
  _(',', comma)                                         \
  _('.', dot)                                           \
  _('?', qmark)

#define _(c,t) \
  vlib_lex_set_action_range(top_index,c,c,VLIB_LEX_RETURN,vlib_lex_add_token(lm, #t), top_index);
  foreach_top_level_single_character_token;
#undef _

  /* Numbers */
  zero_index = vlib_lex_add_table ("zero");
  octal_index = vlib_lex_add_table ("octal");
  decimal_index = vlib_lex_add_table ("decimal");
  hex_index = vlib_lex_add_table ("hex");
  binary_index = vlib_lex_add_table ("binary");

  /* Support 0x 0b 0t and 0123 [octal] */
  vlib_lex_set_action_range (top_index, '0', '0', VLIB_LEX_START_NUMBER, 10,
			     zero_index);
  vlib_lex_set_action_range (top_index, '1', '9', VLIB_LEX_START_NUMBER, 10,
			     decimal_index);

  vlib_lex_set_action_range (zero_index, 0, 0x7F, VLIB_LEX_RETURN_AND_RESCAN,
			     VLIB_LEX_number, top_index);

  vlib_lex_set_action_range (zero_index, 'x', 'x', VLIB_LEX_IGNORE, ~0,
			     hex_index);
  vlib_lex_set_action_range (zero_index, 'b', 'b', VLIB_LEX_IGNORE, ~0,
			     binary_index);
  vlib_lex_set_action_range (zero_index, 't', 't', VLIB_LEX_IGNORE, ~0,
			     decimal_index);
  vlib_lex_set_action_range (zero_index, '0', '7', VLIB_LEX_START_NUMBER, 8,
			     octal_index);

  /* Octal */
  vlib_lex_set_action_range (octal_index, 0, 0x7f, VLIB_LEX_RETURN_AND_RESCAN,
			     VLIB_LEX_number, top_index);
  vlib_lex_set_action_range (octal_index, '0', '7', VLIB_LEX_ADD_TO_NUMBER, 8,
			     octal_index);

  /* Decimal */
  vlib_lex_set_action_range (decimal_index, 0, 0x7f,
			     VLIB_LEX_RETURN_AND_RESCAN, VLIB_LEX_number,
			     top_index);
  vlib_lex_set_action_range (decimal_index, '0', '9', VLIB_LEX_ADD_TO_NUMBER,
			     10, decimal_index);

  /* Hex */
  vlib_lex_set_action_range (hex_index, 0, 0x7f, VLIB_LEX_RETURN_AND_RESCAN,
			     VLIB_LEX_number, top_index);
  vlib_lex_set_action_range (hex_index, '0', '9', VLIB_LEX_ADD_TO_NUMBER, 16,
			     hex_index);
  vlib_lex_set_action_range (hex_index, 'a', 'f', VLIB_LEX_ADD_TO_NUMBER, 16,
			     hex_index);
  vlib_lex_set_action_range (hex_index, 'A', 'F', VLIB_LEX_ADD_TO_NUMBER, 16,
			     hex_index);

  /* Binary */
  vlib_lex_set_action_range (binary_index, 0, 0x7f,
			     VLIB_LEX_RETURN_AND_RESCAN, VLIB_LEX_number,
			     top_index);
  vlib_lex_set_action_range (binary_index, '0', '1', VLIB_LEX_ADD_TO_NUMBER,
			     2, binary_index);

  /* c/c++ comment syntax is the worst... */

  slash_index = vlib_lex_add_table ("slash");
  slash_star_index = vlib_lex_add_table ("slash_star");
  slash_star_star_index = vlib_lex_add_table ("slash_star_star");
  slash_slash_index = vlib_lex_add_table ("slash_slash");
  slash_token = vlib_lex_add_token (lm, "slash");

  /* Top level: see a slash, ignore, go to slash table */
  vlib_lex_set_action_range (top_index, '/', '/', VLIB_LEX_IGNORE, ~0,
			     slash_index);

  /* default for slash table: return SLASH, go to top table */
  vlib_lex_set_action_range (slash_index, 1, 0x7F, VLIB_LEX_RETURN_AND_RESCAN,
			     slash_token, top_index);
  /* see slash-slash, go to s-s table */
  vlib_lex_set_action_range (slash_index, '/', '/', VLIB_LEX_IGNORE, ~0,
			     slash_slash_index);
  /* see slash-star, go to s-* table */
  vlib_lex_set_action_range (slash_index, '*', '*', VLIB_LEX_IGNORE, ~0,
			     slash_star_index);

  /* EOL in s-s table, ignore, go to top table */
  vlib_lex_set_action_range (slash_slash_index, '\n', '\n', VLIB_LEX_IGNORE,
			     ~0, top_index);

  /* slash-star blah blah star */
  vlib_lex_set_action_range (slash_star_index, '*', '*', VLIB_LEX_IGNORE, ~0,
			     slash_star_star_index);

  /* slash star blah blah star slash */
  vlib_lex_set_action_range (slash_star_star_index, '/', '/', VLIB_LEX_IGNORE,
			     ~0, top_index);

  /* LT, =, GT */
  vlib_lex_set_action_range (top_index, '<', '<', VLIB_LEX_RETURN,
			     VLIB_LEX_lt, top_index);
  vlib_lex_set_action_range (top_index, '=', '=', VLIB_LEX_RETURN,
			     VLIB_LEX_equals, top_index);
  vlib_lex_set_action_range (top_index, '>', '>', VLIB_LEX_RETURN,
			     VLIB_LEX_gt, top_index);

  /* words, key and otherwise */
  word_index = vlib_lex_add_table ("word");

  vlib_lex_set_action_range (top_index, 'a', 'z', VLIB_LEX_ADD_TO_TOKEN, ~0,
			     word_index);
  vlib_lex_set_action_range (top_index, 'A', 'Z', VLIB_LEX_ADD_TO_TOKEN, ~0,
			     word_index);

  vlib_lex_set_action_range (word_index, 0, 0x7f, VLIB_LEX_KEYWORD_CHECK, ~0,
			     top_index);

  vlib_lex_set_action_range (word_index, 'a', 'z', VLIB_LEX_ADD_TO_TOKEN, ~0,
			     word_index);
  vlib_lex_set_action_range (word_index, 'A', 'Z', VLIB_LEX_ADD_TO_TOKEN, ~0,
			     word_index);
  vlib_lex_set_action_range (word_index, '_', '_', VLIB_LEX_ADD_TO_TOKEN, ~0,
			     word_index);
  vlib_lex_set_action_range (word_index, '0', '9', VLIB_LEX_ADD_TO_TOKEN, ~0,
			     word_index);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
