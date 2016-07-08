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
#include <vlib/vlib.h>
#include <vlib/lex.h>

vlib_lex_main_t vlib_lex_main;

#define LEX_DEBUG 0

u8 *
format_vlib_lex_token (u8 * s, va_list * args)
{
  vlib_lex_main_t *lm = va_arg (*args, vlib_lex_main_t *);
  vlib_lex_token_t *t = va_arg (*args, vlib_lex_token_t *);

  if (t->token == VLIB_LEX_word)
    s = format (s, "%s", t->value.as_pointer);
  else
    s = format (s, "%s", lm->lex_token_names[t->token]);
  return s;
}

void
vlib_lex_get_token (vlib_lex_main_t * lm, vlib_lex_token_t * rv)
{
  u8 c;
  vlib_lex_table_t *t;
  vlib_lex_table_entry_t *e;
  uword tv;

  if (PREDICT_FALSE (lm->pushback_sp >= 0))
    {
      rv[0] = lm->pushback_vector[lm->pushback_sp--];
      return;
    }

  rv->value.as_uword = ~0;

  while (1)
    {
      if (PREDICT_FALSE (lm->current_index >= vec_len (lm->input_vector)))
	{
	  rv->token = VLIB_LEX_eof;
	  return;
	}

      t = vec_elt_at_index (lm->lex_tables, lm->current_table_index);
      c = (lm->input_vector[lm->current_index++]) & 0x7f;
      e = &t->entries[c];
      lm->current_table_index = e->next_table_index;

      switch (e->action)
	{
	case VLIB_LEX_IGNORE:
	  continue;

	case VLIB_LEX_START_NUMBER:
	  lm->current_token_value = 0;
	  /* fallthru */

	case VLIB_LEX_ADD_TO_NUMBER:
	  lm->current_number_base = e->token;
	  lm->current_token_value *= lm->current_number_base;
	  tv = c - '0';
	  if (tv >= lm->current_number_base)
	    {
	      tv = 10 + c - 'A';
	      if (tv >= lm->current_number_base)
		tv = 10 + c - 'a';
	    }
	  lm->current_token_value += tv;
	  continue;

	case VLIB_LEX_ADD_TO_TOKEN:
	  vec_add1 (lm->token_buffer, c);
	  continue;

	case VLIB_LEX_KEYWORD_CHECK:
	  {
	    uword *p;

	    vec_add1 (lm->token_buffer, 0);

	    /* It's either a keyword or just a word. */
	    p = hash_get_mem (lm->lex_keywords, lm->token_buffer);
	    if (p)
	      {
		rv->token = p[0];
		if (LEX_DEBUG > 0)
		  clib_warning ("keyword '%s' token %s",
				lm->token_buffer,
				lm->lex_token_names[rv->token]);
	      }
	    else
	      {
		/* it's a WORD */
		rv->token = VLIB_LEX_word;
		rv->value.as_pointer = vec_dup (lm->token_buffer);
		if (LEX_DEBUG > 0)
		  clib_warning ("%s, value '%s'",
				lm->lex_token_names[VLIB_LEX_word],
				rv->value.as_pointer);
	      }
	    _vec_len (lm->token_buffer) = 0;

	    /* Rescan the character which terminated the keyword/word. */
	    lm->current_index--;
	    return;
	  }

	case VLIB_LEX_RETURN_AND_RESCAN:
	  ASSERT (lm->current_index);
	  lm->current_index--;
	  /* note flow-through */

	case VLIB_LEX_RETURN:
	  rv->token = e->token;
	  rv->value.as_uword = lm->current_token_value;
	  lm->current_token_value = ~0;
	  if (LEX_DEBUG > 0)
	    {
	      clib_warning
		("table %s char '%c'(0x%02x) next table %s return %s",
		 t->name, c, c, lm->lex_tables[e->next_table_index].name,
		 lm->lex_token_names[e->token]);
	      if (rv->token == VLIB_LEX_number)
		clib_warning ("  numeric value 0x%x (%d)", rv->value,
			      rv->value);
	    }
	  return;
	}
    }
}

u16
vlib_lex_add_token (vlib_lex_main_t * lm, char *token_name)
{
  uword *p;
  u16 rv;

  p = hash_get_mem (lm->lex_tokens_by_name, token_name);

  if (p)
    return p[0];

  rv = vec_len (lm->lex_token_names);
  hash_set_mem (lm->lex_tokens_by_name, token_name, rv);
  vec_add1 (lm->lex_token_names, token_name);

  return rv;
}

static u16
add_keyword (vlib_lex_main_t * lm, char *keyword, char *token_name)
{
  uword *p;
  u16 token;

  p = hash_get_mem (lm->lex_keywords, keyword);

  ASSERT (p == 0);

  token = vlib_lex_add_token (lm, token_name);

  hash_set_mem (lm->lex_keywords, keyword, token);
  return token;
}

u16
vlib_lex_find_or_add_keyword (vlib_lex_main_t * lm, char *keyword,
			      char *token_name)
{
  uword *p = hash_get_mem (lm->lex_keywords, keyword);
  return p ? p[0] : add_keyword (lm, keyword, token_name);
}

void
vlib_lex_set_action_range (u32 table_index, u8 lo, u8 hi, u16 action,
			   u16 token, u32 next_table_index)
{
  int i;
  vlib_lex_main_t *lm = &vlib_lex_main;
  vlib_lex_table_t *t = pool_elt_at_index (lm->lex_tables, table_index);

  for (i = lo; i <= hi; i++)
    {
      ASSERT (i < ARRAY_LEN (t->entries));
      t->entries[i].action = action;
      t->entries[i].token = token;
      t->entries[i].next_table_index = next_table_index;
    }
}

u16
vlib_lex_add_table (char *name)
{
  vlib_lex_main_t *lm = &vlib_lex_main;
  vlib_lex_table_t *t;
  uword *p;

  p = hash_get_mem (lm->lex_tables_by_name, name);

  ASSERT (p == 0);

  pool_get_aligned (lm->lex_tables, t, CLIB_CACHE_LINE_BYTES);

  t->name = name;

  hash_set_mem (lm->lex_tables_by_name, name, t - lm->lex_tables);

  vlib_lex_set_action_range (t - lm->lex_tables, 1, 0x7F, VLIB_LEX_IGNORE, ~0,
			     t - lm->lex_tables);

  vlib_lex_set_action_range (t - lm->lex_tables, 0, 0, VLIB_LEX_RETURN,
			     VLIB_LEX_eof, t - lm->lex_tables);

  return t - lm->lex_tables;
}

void
vlib_lex_reset (vlib_lex_main_t * lm, u8 * input_vector)
{
  if (lm->pushback_vector)
    _vec_len (lm->pushback_vector) = 0;
  lm->pushback_sp = -1;

  lm->input_vector = input_vector;
  lm->current_index = 0;
}

static clib_error_t *
lex_onetime_init (vlib_main_t * vm)
{
  vlib_lex_main_t *lm = &vlib_lex_main;

  lm->lex_tables_by_name = hash_create_string (0, sizeof (uword));
  lm->lex_tokens_by_name = hash_create_string (0, sizeof (uword));
  lm->lex_keywords = hash_create_string (0, sizeof (uword));
  lm->pushback_sp = -1;

#define _(f) { u16 tmp = vlib_lex_add_token (lm, #f); ASSERT (tmp == VLIB_LEX_##f); }
  foreach_vlib_lex_global_token;
#undef _

  vec_validate (lm->token_buffer, 127);
  _vec_len (lm->token_buffer) = 0;

  return 0;
}

VLIB_INIT_FUNCTION (lex_onetime_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
