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
#ifndef included_vlib_parse_h
#define included_vlib_parse_h

#include <vlib/vlib.h>
#include <vlib/lex.h>
#include <vppinfra/mhash.h>

typedef struct
{
  /* Word aligned value. */
  union
  {
    u8 as_u8[32 - 1 * sizeof (u16)];
    void *as_pointer;
    uword as_uword;
    word as_word;
    u64 as_u64;
  } value;

  /* 16 bit type at end so that 30 bytes of value are aligned. */
  u16 type;
} __attribute ((packed))
  vlib_parse_value_t;

/* Instance of a type. */
     typedef struct
     {
       u32
	 type;

       u32
	 origin;

       u32
	 help_index;

       union
       {
	 void *
	   as_pointer;
	 uword
	   as_uword;
       } value;
     } vlib_parse_item_t;

     typedef struct
     {
       /* Index of item for this node. */
       u32
	 item;

       /* Graph index of peer (sibling) node (linked list of peers). */
       u32
	 peer;

       /* Graph index of deeper (child) node (linked list of children). */
       u32
	 deeper;
     } vlib_parse_graph_t;

#define foreach_parse_match_type                \
  _(MATCH_DONE)					\
  _(MATCH_RULE)					\
  _(MATCH_FAIL)					\
  _(MATCH_FULL)					\
  _(MATCH_VALUE)				\
  _(MATCH_PARTIAL)				\
  _(MATCH_AMBIGUOUS)				\
  _(MATCH_EVAL_FAIL)

     typedef enum
     {
#define _(a) VLIB_PARSE_##a,
       foreach_parse_match_type
#undef _
     } vlib_parse_match_t;

     struct vlib_parse_type;
     struct vlib_parse_main;

     typedef
     vlib_parse_match_t (vlib_parse_match_function_t)
  (struct vlib_parse_main *,
   struct vlib_parse_type *, vlib_lex_token_t *, vlib_parse_value_t *);
     typedef void (vlib_parse_value_cleanup_function_t) (vlib_parse_value_t
							 *);

     typedef struct vlib_parse_type
     {
       /* Type name. */
       char *
	 name;

       vlib_parse_match_function_t *
	 match_function;

       vlib_parse_value_cleanup_function_t *
	 value_cleanup_function;

       format_function_t *
	 format_value;

       u32
	 rule_index;
     } vlib_parse_type_t;

     typedef struct
     {
       char *
	 initializer;
       void *
	 eof_match;
       int
	 rule_length;
     } parse_registration_t;

     typedef struct vlib_parse_main
     {
       /* (type, origin, help, value) tuples */
       vlib_parse_item_t *
	 parse_items;
       mhash_t
	 parse_item_hash;

       /* (item, peer, deeper) tuples */
       vlib_parse_graph_t *
	 parse_graph;
       u32
	 root_index;

       u8 *
	 register_input;

       /* parser types */
       vlib_parse_type_t *
	 parse_types;
       uword *
	 parse_type_by_name_hash;

       /* Vector of MATCH_VALUEs */
       vlib_parse_value_t *
	 parse_value;
       u32 *
	 match_items;

       /* Parse registrations */
       parse_registration_t **
	 parse_registrations;

       /* Token vector */
       vlib_lex_token_t *
	 tokens;
       u32
	 current_token_index;

       vlib_lex_main_t *
	 lex_main;
       vlib_main_t *
	 vlib_main;
     } vlib_parse_main_t;

     vlib_parse_main_t
       vlib_parse_main;

     typedef
     vlib_parse_match_t (vlib_parse_eval_function_t)
  (vlib_parse_main_t *, vlib_parse_item_t *, vlib_parse_value_t *);

vlib_parse_match_t
vlib_parse_eval (u8 * input);

     format_function_t format_vlib_parse_value;

/* FIXME need these to be global? */
     vlib_parse_match_function_t rule_match, eof_match, word_match,
       number_match;

#define _PARSE_REGISTRATION_DATA(x) \
VLIB_ELF_SECTION_DATA(x##_registration,parse_registration_t,parse_registrations)

#define PARSE_INIT(x, s, e)                     \
static _PARSE_REGISTRATION_DATA(x) = {          \
    .initializer = s,                           \
    .eof_match = e,                             \
};

#define _PARSE_TYPE_REGISTRATION_DATA(x) \
VLIB_ELF_SECTION_DATA(x##_type_registration,vlib_parse_type_t, \
parse_type_registrations)

#define PARSE_TYPE_INIT(n, m, c, f)             \
static _PARSE_TYPE_REGISTRATION_DATA(n) = {     \
    .name = #n,                                 \
    .match_function = m,			\
    .value_cleanup_function = c,		\
    .format_value = f,				\
};

#endif /* included_vlib_parse_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
