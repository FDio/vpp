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
#ifndef included_vlib_lex_h
#define included_vlib_lex_h

#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/error.h>
#include <vppinfra/pool.h>

#define foreach_vlib_lex_global_token           \
  _ (invalid)                                   \
  _ (eof)                                       \
  _ (word)                                      \
  _ (number)                                    \
  _ (lt)                                        \
  _ (gt)                                        \
  _ (dot)                                       \
  _ (slash)                                     \
  _ (qmark)                                     \
  _ (equals)                                    \
  _ (plus)                                      \
  _ (minus)                                     \
  _ (star)                                      \
  _ (lpar)                                      \
  _ (rpar)

typedef enum
{
#define _(f) VLIB_LEX_##f,
  foreach_vlib_lex_global_token
#undef _
} vlib_lex_global_token_t;

typedef enum
{
  VLIB_LEX_IGNORE,
  VLIB_LEX_ADD_TO_TOKEN,
  VLIB_LEX_RETURN,
  VLIB_LEX_RETURN_AND_RESCAN,
  VLIB_LEX_KEYWORD_CHECK,
  VLIB_LEX_START_NUMBER,
  VLIB_LEX_ADD_TO_NUMBER,
} vlib_lex_action_t;

typedef struct
{
  u16 action;
  u16 next_table_index;
  u16 token;
} vlib_lex_table_entry_t;

typedef struct
{
  char *name;
  vlib_lex_table_entry_t entries[128];
} vlib_lex_table_t;

typedef struct
{
  u32 token;

  union
  {
    uword as_uword;
    void *as_pointer;
    char *as_string;
  } value;
} vlib_lex_token_t;

typedef struct
{
  vlib_lex_table_t *lex_tables;
  uword *lex_tables_by_name;

  /* Vector of token strings. */
  char **lex_token_names;

  /* Hash mapping c string name to token index. */
  uword *lex_tokens_by_name;

  /* Hash mapping c string keyword name to token index. */
  uword *lex_keywords;

  vlib_lex_token_t *pushback_vector;

  i32 pushback_sp;

  u32 current_table_index;

  uword current_token_value;

  uword current_number_base;

  /* Input string we are lex-ing. */
  u8 *input_vector;

  /* Current index into input vector. */
  u32 current_index;

  /* Re-used vector for forming token strings and hashing them. */
  u8 *token_buffer;
} vlib_lex_main_t;

vlib_lex_main_t vlib_lex_main;

always_inline void
vlib_lex_cleanup_token (vlib_lex_token_t * t)
{
  if (t->token == VLIB_LEX_word)
    {
      u8 *tv = t->value.as_pointer;
      vec_free (tv);
    }
}

u16 vlib_lex_add_table (char *name);
void vlib_lex_get_token (vlib_lex_main_t * lm, vlib_lex_token_t * result);
u16 vlib_lex_add_token (vlib_lex_main_t * lm, char *token_name);
void vlib_lex_set_action_range (u32 table_index, u8 lo, u8 hi, u16 action,
				u16 token, u32 next_table_index);
void vlib_lex_reset (vlib_lex_main_t * lm, u8 * input_vector);
format_function_t format_vlib_lex_token;

#endif /* included_vlib_lex_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
