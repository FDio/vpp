/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2010-2020 Cisco and/or its affiliates.
 */

/* macros.h - definitions for a simple macro expander */

#ifndef included_macros_h
#define included_macros_h

#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/format.h>

#ifdef CLIB_UNIX
#include <stdlib.h>
#include <unistd.h>
#endif

typedef struct
{
  uword *the_builtin_eval_hash;
  uword *the_value_table_hash;
} clib_macro_main_t;

int clib_macro_unset (clib_macro_main_t * mm, char *name);
int clib_macro_set_value (clib_macro_main_t * mm, char *name, char *value);
void clib_macro_add_builtin (clib_macro_main_t * mm, char *name,
			     void *eval_fn);
i8 *clib_macro_get_value (clib_macro_main_t * mm, char *name);
i8 *clib_macro_eval (clib_macro_main_t * mm, i8 * s, i32 complain,
		     u16 level, u16 max_level);
i8 *clib_macro_eval_dollar (clib_macro_main_t * mm, i8 * s, i32 complain);
void clib_macro_init (clib_macro_main_t * mm);
void clib_macro_free (clib_macro_main_t * mm);

format_function_t format_clib_macro_main;

#endif /* included_macros_h */
