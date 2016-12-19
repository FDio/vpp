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

#define PARSE_DEBUG 0

u16 word_type_index, number_type_index, eof_type_index, rule_eof_type_index,
  plus_type_index, minus_type_index, star_type_index, slash_type_index,
  lpar_type_index, rpar_type_index;

u8 *
format_vlib_parse_value (u8 * s, va_list * args)
{
  vlib_parse_main_t *pm = va_arg (*args, vlib_parse_main_t *);
  vlib_parse_type_t *type;
  vlib_parse_value_t *v;
  u16 type_index;

  s = format (s, "%d items:\n", vec_len (pm->parse_value));
  vec_foreach (v, pm->parse_value)
  {
    type_index = v->type;
    type = pool_elt_at_index (pm->parse_types, type_index);
    if (type->format_value)
      s = format (s, "[%d]: %U\n", v - pm->parse_value,
		  type->format_value, v);
    else
      s = format (s, "[%d]: (nofun)\n", v - pm->parse_value);
  }
  return s;
}

static u8 *
format_vlib_parse_match (u8 * s, va_list * args)
{
  vlib_parse_match_t m = va_arg (*args, vlib_parse_match_t);
  char *t = 0;
  switch (m)
    {
#define _(a) case VLIB_PARSE_##a: t = #a; break;
      foreach_parse_match_type
#undef _
    default:
      t = 0;
      break;
    }

  if (t)
    return format (s, "%s", t);
  else
    return format (s, "unknown 0x%x", m);
}

static u8 *
format_vlib_parse_item (u8 * s, va_list * args)
{
  vlib_parse_main_t *pm = va_arg (*args, vlib_parse_main_t *);
  vlib_parse_item_t *item = va_arg (*args, vlib_parse_item_t *);
  vlib_parse_type_t *type = pool_elt_at_index (pm->parse_types, item->type);

  if (item->type == word_type_index)
    s = format (s, "%s", item->value.as_pointer);
  else
    s = format (s, "<%s>", type->name);
  return s;
}

static u8 *
format_vlib_parse_graph (u8 * s, va_list * args)
{
  vlib_parse_main_t *pm = va_arg (*args, vlib_parse_main_t *);
  vlib_parse_graph_t *node = va_arg (*args, vlib_parse_graph_t *);
  vlib_parse_item_t *item;
  vlib_parse_type_t *type;

  /* $$$ hash table */
  /* *INDENT-OFF* */
  pool_foreach (type, pm->parse_types,
                ({
                  if (type->rule_index == node - pm->parse_graph)
                    s = format (s, "\n<%s>\n", type->name);
                }));
/* *INDENT-ON* */

  if (pm->root_index == (node - pm->parse_graph))
    s = format (s, "\n<root>\n");

  item = pool_elt_at_index (pm->parse_items, node->item);

  s = format (s, "[%d] %U ", node - pm->parse_graph,
	      format_vlib_parse_item, pm, item);

  if (node->peer == (u32) ~ 0)
    s = format (s, "peer nil  ");
  else
    s = format (s, "peer %4u ", node->peer);

  if (node->deeper == (u32) ~ 0)
    s = format (s, "deeper nil  ");
  else
    s = format (s, "deeper %4u ", node->deeper);

  return s;
}

void
dump_parse_graph (void)
{
  vlib_parse_main_t *pm = &vlib_parse_main;
  vlib_parse_graph_t *node;

  /* *INDENT-OFF* */
  pool_foreach (node, pm->parse_graph, ({
    fformat(stdout, "%U\n", format_vlib_parse_graph, pm, node);
  }));
/* *INDENT-ON* */
}

always_inline void
parse_cleanup_value (vlib_parse_main_t * pm, vlib_parse_value_t * pv)
{
  vlib_parse_type_t *type = pool_elt_at_index (pm->parse_types, pv->type);
  if (type->value_cleanup_function)
    type->value_cleanup_function (pv);
}

static void
parse_reset (vlib_parse_main_t * pm, u8 * input)
{
  vlib_lex_token_t *t;
  vlib_parse_value_t *pv;

  vlib_lex_reset (pm->lex_main, input);

  vec_foreach (t, pm->tokens) vlib_lex_cleanup_token (t);

  vec_foreach (pv, pm->parse_value) parse_cleanup_value (pm, pv);

  _vec_len (pm->parse_value) = 0;
  _vec_len (pm->tokens) = 0;
  pm->current_token_index = 0;
}

static void
parse_help (vlib_parse_main_t * pm, u32 index)
{
  vlib_parse_graph_t *node;
  vlib_parse_item_t *item;
  vlib_parse_type_t *type;
  vlib_main_t *vm = pm->vlib_main;
  u8 *help_input;
  int i;

  help_input = vec_dup (pm->lex_main->input_vector);

  for (i = vec_len (help_input) - 1; i >= 0; i--)
    if (help_input[i] == '?')
      {
	help_input[i] = 0;
	_vec_len (help_input) = i;
	break;
      }

  for (i = vec_len (help_input) - 1; i >= 0; i--)
    {
      if (help_input[i] != ' ' && help_input[i] != '\t')
	break;
      help_input[i] = 0;
      break;
    }
  _vec_len (help_input) = i + 1;

  while (index != (u32) ~ 0)
    {
      node = pool_elt_at_index (pm->parse_graph, index);
      item = pool_elt_at_index (pm->parse_items, node->item);
      type = pool_elt_at_index (pm->parse_types, item->type);

      if (item->type == eof_type_index && vec_len (pm->match_items) == 0)
	/* do nothing */ ;
      else if (item->type == word_type_index)
	vlib_cli_output (vm, "%s %s\n", help_input, item->value.as_pointer);
      else
	vlib_cli_output (vm, "%s <%s>\n", help_input, type->name);
      index = node->peer;
    }
  vec_free (help_input);
}

static vlib_parse_match_t
parse_eval_internal (vlib_parse_main_t * pm, u32 index)
{
  vlib_parse_graph_t *node;
  vlib_parse_item_t *item;
  vlib_parse_type_t *type;
  vlib_parse_value_t value, *pv;
  vlib_parse_match_t rv;
  u32 *partial_matches = 0;
  vlib_lex_token_t *t;
  u32 save_token_index = (u32) ~ 0, save_match_items = 0;
  int had_value = 0;

  if (pm->current_token_index >= vec_len (pm->tokens))
    return VLIB_PARSE_MATCH_FAIL;

  /* current token */
  t = vec_elt_at_index (pm->tokens, pm->current_token_index);

  /* Help ? */
  if (PREDICT_FALSE (t->token == VLIB_LEX_qmark))
    {
      parse_help (pm, index);
      _vec_len (pm->match_items) = 0;
      return VLIB_PARSE_MATCH_DONE;
    }

  /* Across all peers at this level of the parse graph */
  while (index != (u32) ~ 0)
    {
      node = pool_elt_at_index (pm->parse_graph, index);
      item = pool_elt_at_index (pm->parse_items, node->item);
      type = pool_elt_at_index (pm->parse_types, item->type);

      /*
       * Save the token index. We may have to back up several
       * trie plies. Type-specific match functions can consume
       * multiple tokens, and they may not be optimally careful
       */
      save_token_index = pm->current_token_index;
      save_match_items = vec_len (pm->match_items);
      vec_add1 (pm->match_items, node->item);

      if (PARSE_DEBUG > 1)
	clib_warning ("Try to match token %U against node %d",
		      format_vlib_lex_token, pm->lex_main, t, index);

      /* Call the type-specific match function */
      rv = type->match_function (pm, type, t, &value);

      if (PARSE_DEBUG > 1)
	clib_warning ("returned %U", format_vlib_parse_match, rv);

      switch (rv)
	{
	case VLIB_PARSE_MATCH_VALUE:
	  /*
	   * Matched, and returned a value to append to the
	   * set of args passed to the action function
	   */
	  value.type = item->type;
	  vec_add1 (pm->parse_value, value);
	  had_value = 1;
	  /* fallthrough */

	case VLIB_PARSE_MATCH_FULL:
	unambiguous_partial_match:
	  /* Consume the matched token */
	  pm->current_token_index++;

	  /* continue matching along this path */
	  rv = parse_eval_internal (pm, node->deeper);

	  /* this is not the right path */
	  if (rv == VLIB_PARSE_MATCH_FAIL)
	    {
	      if (had_value)
		{
		  /* Delete the value */
		  value = pm->parse_value[vec_len (pm->parse_value) - 1];
		  parse_cleanup_value (pm, &value);
		  _vec_len (pm->parse_value) -= 1;
		}
	      /* Continue with the next sibling */
	      pm->current_token_index = save_token_index;
	      _vec_len (pm->match_items) = save_match_items;
	      index = node->peer;
	      break;
	    }
	  return rv;

	case VLIB_PARSE_MATCH_PARTIAL:
	  /* Partial (substring) match, remember it but keep going */
	  vec_add1 (partial_matches, node - pm->parse_graph);
	  index = node->peer;
	  break;

	case VLIB_PARSE_MATCH_FAIL:
	  /* Continue with the next sibling */
	  index = node->peer;
	  _vec_len (pm->match_items) = save_match_items;
	  break;

	case VLIB_PARSE_MATCH_DONE:
	  /* Parse complete, invoke the action function */
	  if (PARSE_DEBUG > 0)
	    clib_warning ("parse_value: %U", format_vlib_parse_value, pm);

	  {
	    vlib_parse_eval_function_t *f = item->value.as_pointer;
	    if (f)
	      rv = f (pm, item, pm->parse_value);
	  }

	  vec_foreach (pv, pm->parse_value) parse_cleanup_value (pm, pv);
	  _vec_len (pm->parse_value) = 0;
	  _vec_len (pm->match_items) = 0;
	  return rv;

	case VLIB_PARSE_MATCH_AMBIGUOUS:
	case VLIB_PARSE_MATCH_EVAL_FAIL:
	case VLIB_PARSE_MATCH_RULE:
	  _vec_len (pm->match_items) = save_match_items;
	  return rv;
	}
    }

  /*
   * Out of siblings. If we have exactly one partial match
   * we win
   */
  if (vec_len (partial_matches) == 1)
    {
      index = partial_matches[0];
      node = pool_elt_at_index (pm->parse_graph, index);
      vec_free (partial_matches);
      goto unambiguous_partial_match;
    }

  /* Ordinary loser */
  rv = VLIB_PARSE_MATCH_FAIL;

  /* Ambiguous loser */
  if (vec_len (partial_matches) > 1)
    {
      vec_free (partial_matches);
      rv = VLIB_PARSE_MATCH_AMBIGUOUS;
    }

  _vec_len (pm->match_items) = save_match_items;
  return rv;
}

vlib_parse_match_t
rule_match (vlib_parse_main_t * pm, vlib_parse_type_t * type,
	    vlib_lex_token_t * t, vlib_parse_value_t * valuep)
{
  vlib_parse_match_t rv;
  static int recursion_level;

  if (PARSE_DEBUG > 1)
    clib_warning ("[%d]: try to match type %s graph index %d",
		  recursion_level, type->name, type->rule_index);
  recursion_level++;
  rv = parse_eval_internal (pm, type->rule_index);
  recursion_level--;

  /* Break the recusive unwind here... */
  if (rv == VLIB_PARSE_MATCH_RULE)
    {
      if (PARSE_DEBUG > 1)
	clib_warning ("[%d]: type %s matched", recursion_level, type->name);

      return VLIB_PARSE_MATCH_FULL;
    }
  else
    {
      if (PARSE_DEBUG > 1)
	clib_warning ("[%d]: type %s returns %U", recursion_level, type->name,
		      format_vlib_parse_match, rv);
    }
  return rv;
}

static int
parse_eval (vlib_parse_main_t * pm, u8 * input)
{
  vlib_lex_token_t *t;

  parse_reset (pm, input);

  /* Tokenize the entire input vector */
  do
    {
      vec_add2 (pm->tokens, t, 1);
      vlib_lex_get_token (pm->lex_main, t);
    }
  while (t->token != VLIB_LEX_eof);

  /* Feed it to the parser */
  return parse_eval_internal (pm, pm->root_index);
}

/* Temporary vlib stub */
vlib_parse_match_t
vlib_parse_eval (u8 * input)
{
  return parse_eval (&vlib_parse_main, input);
}

u16
parse_type_find_or_create (vlib_parse_main_t * pm, vlib_parse_type_t * t)
{
  uword *p;
  vlib_parse_type_t *n;
  u8 *name_copy;

  p = hash_get_mem (pm->parse_type_by_name_hash, t->name);
  if (p)
    return p[0];

  pool_get (pm->parse_types, n);
  *n = *t;
  n->rule_index = (u32) ~ 0;

  name_copy = format (0, "%s%c", n->name, 0);

  hash_set_mem (pm->parse_type_by_name_hash, name_copy, n - pm->parse_types);
  return n - pm->parse_types;
}

u16
parse_type_find_by_name (vlib_parse_main_t * pm, char *name)
{
  uword *p;

  p = hash_get_mem (pm->parse_type_by_name_hash, name);
  if (p)
    return p[0];

  return (u16) ~ 0;
}

u32
parse_item_find_or_create (vlib_parse_main_t * pm, vlib_parse_item_t * item)
{
  uword *p;
  vlib_parse_item_t *i;

  /* Exact match the entire item */
  p = mhash_get (&pm->parse_item_hash, item);
  if (p)
    return p[0];

  pool_get (pm->parse_items, i);
  *i = *item;

  mhash_set (&pm->parse_item_hash, i, i - pm->parse_items, 0);
  return i - pm->parse_items;
}

static void
parse_type_and_graph_init (vlib_parse_main_t * pm)
{
  u32 eof_index;
  vlib_parse_type_t type;
  vlib_parse_item_t item;

  memset (&type, 0, sizeof (type));

#define foreach_token_type                      \
  _ (eof)                                       \
  _ (rule_eof)                                  \
  _ (word)                                      \
  _ (number)                                    \
  _ (plus)                                      \
  _ (minus)                                     \
  _ (star)                                      \
  _ (slash)                                     \
  _ (lpar)                                      \
  _ (rpar)

#define _(a) a##_type_index = parse_type_find_by_name (pm, #a);
  foreach_token_type
#undef _
    memset (&item, 0, sizeof (item));
  item.type = eof_type_index;

  eof_index = parse_item_find_or_create (pm, &item);
  pm->root_index = (u32) ~ 0;

#if 0
  pool_get (pm->parse_graph, g);
  memset (g, 0xff, sizeof (*g));
  g->item = eof_index;
  pm->root_index = 0;
#endif
}



static void
tokenize (vlib_parse_main_t * pm, parse_registration_t * pr)
{
  vlib_lex_token_t *t;
  pm->register_input = format (pm->register_input,
			       "%s%c", pr->initializer, 0);

  parse_reset (pm, pm->register_input);

  do
    {
      vec_add2 (pm->tokens, t, 1);
      vlib_lex_get_token (pm->lex_main, t);
    }
  while (t->token != VLIB_LEX_eof);
  _vec_len (pm->register_input) = 0;
}

static int
is_typed_rule (vlib_parse_main_t * pm)
{
  vlib_lex_token_t *t = vec_elt_at_index (pm->tokens, 0);

  /* <mytype> = blah blah blah */
  if (vec_len (pm->tokens) >= 4
      && t[0].token == VLIB_LEX_lt
      && t[1].token == VLIB_LEX_word
      && t[2].token == VLIB_LEX_gt && t[3].token == VLIB_LEX_equals)
    return 1;
  return 0;
}

static int
token_matches_graph_node (vlib_parse_main_t * pm,
			  vlib_lex_token_t * t,
			  vlib_parse_graph_t * node,
			  vlib_parse_item_t * item,
			  vlib_parse_type_t * type, u32 * token_increment)
{
  /* EOFs don't match */
  if (t->token == VLIB_LEX_eof)
    return 0;

  /* New chain element is a word */
  if (t->token == VLIB_LEX_word)
    {
      /* but the item in hand is not a word */
      if (item->type != word_type_index)
	return 0;

      /* Or it's not this particular word */
      if (strcmp (t->value.as_pointer, item->value.as_pointer))
	return 0;
      *token_increment = 1;
      return 1;
    }
  /* New chain element is a type-name: < TYPE-NAME > */
  if (t->token == VLIB_LEX_lt)
    {
      u16 token_type_index;

      /* < TYPE > */
      if (t[1].token != VLIB_LEX_word || t[2].token != VLIB_LEX_gt)
	{
	  clib_warning (0, "broken type name in '%s'", pm->register_input);
	  return 0;
	}

      token_type_index = parse_type_find_by_name (pm, t[1].value.as_pointer);
      if (token_type_index == (u16) ~ 0)
	{
	  clib_warning (0, "unknown type '%s'", t[1].value.as_pointer);
	  return 0;
	}

      /* Its a known type but does not match. */
      if (item->type != token_type_index)
	return 0;

      *token_increment = 3;
      return 1;
    }
  clib_warning ("BUG: t->token = %d", t->token);
  return 0;
}

u32
generate_subgraph_from_tokens (vlib_parse_main_t * pm,
			       vlib_lex_token_t * t,
			       u32 * new_subgraph_depth,
			       parse_registration_t * pr, int not_a_rule)
{
  vlib_parse_graph_t *g, *last_g;
  vlib_parse_item_t new_item;
  u32 rv = (u32) ~ 0, new_item_index, last_index = (u32) ~ 0;
  u16 token_type_index;
  u32 depth = 0;

  while (t < pm->tokens + vec_len (pm->tokens))
    {
      memset (&new_item, 0, sizeof (new_item));

      if (t->token == VLIB_LEX_word)
	{
	  new_item.type = word_type_index;
	  new_item.value.as_pointer = vec_dup ((u8 *) t->value.as_pointer);
	  new_item_index = parse_item_find_or_create (pm, &new_item);
	  t++;
	}
      else if (t->token == VLIB_LEX_lt)
	{
	  if (t[1].token != VLIB_LEX_word || t[2].token != VLIB_LEX_gt)
	    {
	      clib_warning ("broken type name in '%s'", pm->register_input);
	      goto screwed;
	    }
	  token_type_index = parse_type_find_by_name (pm,
						      t[1].value.as_pointer);
	  if (token_type_index == (u16) ~ 0)
	    {
	      clib_warning ("unknown type 2 '%s'", t[1].value.as_pointer);
	      goto screwed;
	    }

	  new_item.type = token_type_index;
	  new_item.value.as_pointer = 0;
	  new_item_index = parse_item_find_or_create (pm, &new_item);
	  t += 3;		/* skip < <type-name> and > */
	}
      else if (t->token == VLIB_LEX_eof)
	{
	screwed:
	  new_item.type = not_a_rule ? eof_type_index : rule_eof_type_index;
	  new_item.value.as_pointer = pr->eof_match;
	  new_item_index = parse_item_find_or_create (pm, &new_item);
	  t++;
	}
      else
	{
	  clib_warning ("unexpected token %U index %d in '%s'",
			format_vlib_lex_token, pm->lex_main, t,
			t - pm->tokens, pm->register_input);
	  goto screwed;
	}

      pool_get (pm->parse_graph, g);
      memset (g, 0xff, sizeof (*g));
      g->item = new_item_index;
      depth++;

      if (rv == (u32) ~ 0)
	{
	  rv = g - pm->parse_graph;
	  last_index = rv;
	}
      else
	{
	  last_g = pool_elt_at_index (pm->parse_graph, last_index);
	  last_index = last_g->deeper = g - pm->parse_graph;
	}
    }
  *new_subgraph_depth = depth;
  return rv;
}

static u32
measure_depth (vlib_parse_main_t * pm, u32 index)
{
  vlib_parse_graph_t *node;
  vlib_parse_item_t *item;
  u32 max = 0;
  u32 depth;

  if (index == (u32) ~ 0)
    return 0;

  node = pool_elt_at_index (pm->parse_graph, index);
  item = pool_elt_at_index (pm->parse_items, node->item);

  if (item->type == eof_type_index)
    return 1;

  while (index != (u32) ~ 0)
    {
      node = pool_elt_at_index (pm->parse_graph, index);
      depth = measure_depth (pm, node->deeper);
      if (max < depth)
	max = depth;
      index = node->peer;
    }

  return max + 1;
}

static void
add_subgraph_to_graph (vlib_parse_main_t * pm,
		       u32 last_matching_index,
		       u32 graph_root_index,
		       u32 new_subgraph_index, u32 new_subgraph_depth)
{
  vlib_parse_graph_t *parent_node;
  int new_subgraph_longest = 1;
  u32 current_peer_index;
  u32 current_depth;
  vlib_parse_graph_t *current_peer = 0;
  vlib_parse_graph_t *new_subgraph_node =
    pool_elt_at_index (pm->parse_graph, new_subgraph_index);

  /*
   * Case 1: top-level peer. Splice into the top-level
   * peer chain according to rule depth
   */
  if (last_matching_index == (u32) ~ 0)
    {
      u32 index = graph_root_index;
      while (1)
	{
	  current_peer = pool_elt_at_index (pm->parse_graph, index);
	  current_depth = measure_depth (pm, index);
	  if (current_depth < new_subgraph_depth
	      || current_peer->peer == (u32) ~ 0)
	    break;
	  index = current_peer->peer;
	}
      new_subgraph_node->peer = current_peer->peer;
      current_peer->peer = new_subgraph_index;
      return;
    }

  parent_node = pool_elt_at_index (pm->parse_graph, last_matching_index);
  current_peer_index = parent_node->deeper;

  while (current_peer_index != (u32) ~ 0)
    {
      current_peer = pool_elt_at_index (pm->parse_graph, current_peer_index);
      current_depth = measure_depth (pm, current_peer_index);
      if (current_depth < new_subgraph_depth)
	break;
      new_subgraph_longest = 0;
      current_peer_index = current_peer->peer;
    }

  ASSERT (current_peer);

  if (new_subgraph_longest)
    {
      new_subgraph_node->peer = parent_node->deeper;
      parent_node->deeper = new_subgraph_index;
    }
  else
    {
      new_subgraph_node->peer = current_peer->peer;
      current_peer->peer = new_subgraph_index;
    }
}

static clib_error_t *
parse_register_one (vlib_parse_main_t * pm, parse_registration_t * pr)
{
  u32 graph_root_index;
  u16 subgraph_type_index = (u16) ~ 0;
  vlib_parse_type_t *subgraph_type = 0;
  vlib_lex_token_t *t;
  vlib_parse_graph_t *node;
  u32 node_index, last_index, token_increment, new_subgraph_index;
  u32 new_subgraph_depth, last_matching_index;
  vlib_parse_item_t *item;
  vlib_parse_type_t *type;

  int use_main_graph = 1;

  tokenize (pm, pr);

  /* A typed rule? */
  if (is_typed_rule (pm))
    {
      /* Get the type and its current subgraph root, if any */
      t = vec_elt_at_index (pm->tokens, 1);
      subgraph_type_index = parse_type_find_by_name (pm, t->value.as_pointer);
      if (subgraph_type_index == (u16) ~ 0)
	return clib_error_return (0, "undeclared type '%s'",
				  t->value.as_pointer);
      subgraph_type =
	pool_elt_at_index (pm->parse_types, subgraph_type_index);
      graph_root_index = subgraph_type->rule_index;
      /* Skip "mytype> = */
      t += 3;
      use_main_graph = 0;
    }
  else
    {
      /* top-level graph */
      graph_root_index = pm->root_index;
      t = vec_elt_at_index (pm->tokens, 0);
    }

  last_matching_index = (u32) ~ 0;
  last_index = node_index = graph_root_index;

  /* Find the first token which isn't already being parsed */
  while (t < pm->tokens + vec_len (pm->tokens) && node_index != (u32) ~ 0)
    {
      node = pool_elt_at_index (pm->parse_graph, node_index);
      item = pool_elt_at_index (pm->parse_items, node->item);
      type = pool_elt_at_index (pm->parse_types, item->type);
      last_index = node_index;

      if (token_matches_graph_node
	  (pm, t, node, item, type, &token_increment))
	{
	  t += token_increment;
	  last_matching_index = node_index;
	  node_index = node->deeper;
	}
      else
	node_index = node->peer;
    }

  new_subgraph_index =
    generate_subgraph_from_tokens (pm, t, &new_subgraph_depth, pr,
				   use_main_graph);

  /* trivial cases: first graph node or first type rule */
  if (graph_root_index == (u32) ~ 0)
    {
      if (use_main_graph)
	pm->root_index = new_subgraph_index;
      else
	subgraph_type->rule_index = new_subgraph_index;
      return 0;
    }

  add_subgraph_to_graph (pm, last_matching_index, graph_root_index,
			 new_subgraph_index, new_subgraph_depth);
  return 0;
}

static clib_error_t *
parse_register (vlib_main_t * vm,
		parse_registration_t * lo,
		parse_registration_t * hi, vlib_parse_main_t * pm)
{
  parse_registration_t *pr;

  for (pr = lo; pr < hi; pr = vlib_elf_section_data_next (pr, 0))
    vec_add1 (pm->parse_registrations, pr);

  return 0;
}

static clib_error_t *
parse_register_one_type (vlib_parse_main_t * pm, vlib_parse_type_t * rp)
{
  (void) parse_type_find_or_create (pm, (vlib_parse_type_t *) rp);
  return 0;
}

static clib_error_t *
parse_type_register (vlib_main_t * vm,
		     vlib_parse_type_t * lo,
		     vlib_parse_type_t * hi, vlib_parse_main_t * pm)
{
  clib_error_t *error = 0;
  vlib_parse_type_t *ptr;

  for (ptr = lo; ptr < hi; ptr = vlib_elf_section_data_next (ptr, 0))
    {
      error = parse_register_one_type (pm, ptr);
      if (error)
	goto done;
    }

done:
  return error;
}

clib_error_t *vlib_stdlex_init (vlib_main_t * vm) __attribute__ ((weak));
clib_error_t *
vlib_stdlex_init (vlib_main_t * vm)
{
  (void) vlib_lex_add_table ("ignore_everything");
  return 0;
}

static int
compute_rule_length (parse_registration_t * r)
{
  int length, i;
  vlib_parse_main_t *pm = &vlib_parse_main;

  if (r->rule_length)
    return r->rule_length;

  length = 0;

  tokenize (pm, r);
  length = vec_len (pm->tokens);

  /* Account for "<foo> = " in "<foo> = bar" etc. */
  if (is_typed_rule (pm))
    length -= 2;

  for (i = 0; i < vec_len (pm->tokens); i++)
    {
      switch (pm->tokens[i].token)
	{
	case VLIB_LEX_lt:
	case VLIB_LEX_gt:
	  length -= 1;

	default:
	  break;
	}
    }

  ASSERT (length > 0);
  r->rule_length = length;
  return length;
}

static int
rule_length_compare (parse_registration_t * r1, parse_registration_t * r2)
{
  compute_rule_length (r1);
  compute_rule_length (r2);
  /* Descending sort */
  return r2->rule_length - r1->rule_length;
}


static clib_error_t *
parse_init (vlib_main_t * vm)
{
  vlib_parse_main_t *pm = &vlib_parse_main;
  vlib_lex_main_t *lm = &vlib_lex_main;
  vlib_elf_section_bounds_t *b, *bounds;
  clib_error_t *error = 0;
  parse_registration_t *rule;
  int i;

  if ((error = vlib_call_init_function (vm, lex_onetime_init)))
    return error;

  if ((error = vlib_stdlex_init (vm)))
    return error;

  if ((error = vlib_call_init_function (vm, parse_builtin_init)))
    return error;

  pm->vlib_main = vm;
  pm->lex_main = lm;

  mhash_init (&pm->parse_item_hash, sizeof (u32), sizeof (vlib_parse_item_t));
  pm->parse_type_by_name_hash = hash_create_string (0, sizeof (u32));

  vec_validate (pm->parse_value, 16);
  vec_validate (pm->tokens, 16);
  vec_validate (pm->register_input, 32);
  vec_validate (pm->match_items, 16);

  _vec_len (pm->parse_value) = 0;
  _vec_len (pm->tokens) = 0;
  _vec_len (pm->register_input) = 0;
  _vec_len (pm->match_items) = 0;

  bounds = vlib_get_elf_section_bounds (vm, "parse_type_registrations");
  vec_foreach (b, bounds)
  {
    error = parse_type_register (vm, b->lo, b->hi, pm);
    if (error)
      break;
  }
  vec_free (bounds);

  parse_type_and_graph_init (pm);

  bounds = vlib_get_elf_section_bounds (vm, "parse_registrations");
  vec_foreach (b, bounds)
  {
    error = parse_register (vm, b->lo, b->hi, pm);
    if (error)
      break;
  }
  vec_free (bounds);

  vec_sort_with_function (pm->parse_registrations, rule_length_compare);

  for (i = 0; i < vec_len (pm->parse_registrations); i++)
    {
      rule = pm->parse_registrations[i];
      parse_register_one (pm, rule);
    }

  return error;
}

VLIB_INIT_FUNCTION (parse_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
