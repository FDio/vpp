/*
 * macros.c - a simple macro expander
 *
 *  Copyright (c) 2010-2020 Cisco and/or its affiliates.
 *
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

#include <vppinfra/macros.h>

static inline int
macro_isalnum (i8 c)
{
  if ((c >= 'A' && c <= 'Z')
      || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '_'))
    return 1;
  return 0;
}

static i8 *
builtin_eval (clib_macro_main_t * mm, i8 * varname, i32 complain)
{
  uword *p;
  i8 *(*fp) (clib_macro_main_t *, i32);

  p = hash_get_mem (mm->the_builtin_eval_hash, varname);
  if (p == 0)
    return 0;
  fp = (void *) (p[0]);
  return (*fp) (mm, complain);
}

__clib_export int
clib_macro_unset (clib_macro_main_t * mm, char *name)
{
  hash_pair_t *p;
  u8 *key, *value;

  p = hash_get_pair (mm->the_value_table_hash, name);

  if (p == 0)
    return 1;

  key = (u8 *) (p->key);
  value = (u8 *) (p->value[0]);
  hash_unset_mem (mm->the_value_table_hash, name);

  vec_free (value);
  vec_free (key);
  return 0;
}

__clib_export int
clib_macro_set_value (clib_macro_main_t * mm, char *name, char *value)
{
  u8 *key_copy, *value_copy;
  int rv;

  rv = clib_macro_unset (mm, name);

  key_copy = format (0, "%s%c", name, 0);
  value_copy = format (0, "%s%c", value, 0);

  hash_set_mem (mm->the_value_table_hash, key_copy, value_copy);
  return rv;
}

i8 *
clib_macro_get_value (clib_macro_main_t * mm, char *name)
{
  uword *p;

  p = hash_get_mem (mm->the_value_table_hash, name);
  if (p)
    return (i8 *) (p[0]);
  else
    return 0;
}

/*
 * eval: takes a string, returns a vector.
 * looks up $foobar in the variable table.
 */
__clib_export i8 *
clib_macro_eval (clib_macro_main_t * mm, i8 * s, i32 complain, u16 level,
		 u16 max_level)
{
  i8 *rv = 0;
  i8 *varname, *varvalue;
  i8 *ts;

  if (level >= max_level)
    {
      if (complain)
	clib_warning ("circular definition, level %d", level);
      return (i8 *) format (0, " CIRCULAR ");
    }

  while (*s)
    {
      switch (*s)
	{
	case '\\':
	  s++;
	  /* fallthrough */

	default:
	  vec_add1 (rv, *s);
	  s++;
	  break;

	case '$':
	  s++;
	  varname = 0;
	  /*
	   * Make vector with variable name in it.
	   */
	  while (*s && (macro_isalnum (*s) || (*s == '_') || (*s == '(')))
	    {

	      /* handle $(foo) */
	      if (*s == '(')
		{
		  s++;		/* skip '(' */
		  while (*s && *s != ')')
		    {
		      vec_add1 (varname, *s);
		      s++;
		    }
		  if (*s)
		    s++;	/* skip ')' */
		  break;
		}
	      vec_add1 (varname, *s);
	      s++;
	    }
	  /* null terminate */
	  vec_add1 (varname, 0);
	  /* Look for a builtin, e.g. $my_hostname */
	  if (!(varvalue = builtin_eval (mm, varname, complain)))
	    {
	      /* Look in value table */
	      if (!varvalue)
		{
		  i8 *tmp = clib_macro_get_value (mm, (char *) varname);
		  if (tmp)
		    varvalue = (i8 *) format (0, "%s%c", tmp, 0);
		}
#ifdef CLIB_UNIX
	      /* Look in environment. */
	      if (!varvalue)
		{
		  char *tmp = getenv ((char *) varname);
		  if (tmp)
		    varvalue = (i8 *) format (0, "%s%c", tmp, 0);
		}
#endif /* CLIB_UNIX */
	    }
	  if (varvalue)
	    {
	      /* recursively evaluate */
	      ts = clib_macro_eval (mm, varvalue, complain, level + 1,
				    max_level);
	      vec_free (varvalue);
	      /* add results to answer */
	      vec_append (rv, ts);
	      /* Remove NULL termination or the results are sad */
	      _vec_len (rv) = vec_len (rv) - 1;
	      vec_free (ts);
	    }
	  else
	    {
	      if (complain)
		clib_warning ("Undefined Variable Reference: %s\n", varname);
	      vec_append (rv, format (0, "UNSET "));
	      _vec_len (rv) = vec_len (rv) - 1;

	    }
	  vec_free (varname);
	}
    }
  vec_add1 (rv, 0);
  return (rv);
}

/*
 * eval: takes a string, returns a vector.
 * looks up $foobar in the variable table.
 */
i8 *
clib_macro_eval_dollar (clib_macro_main_t * mm, i8 * s, i32 complain)
{
  i8 *s2;
  i8 *rv;

  s2 = (i8 *) format (0, "$(%s)%c", s, 0);
  rv = clib_macro_eval (mm, s2, complain, 0 /* level */ , 8 /* max_level */ );
  vec_free (s2);
  return (rv);
}

__clib_export void
clib_macro_add_builtin (clib_macro_main_t * mm, char *name, void *eval_fn)
{
  hash_set_mem (mm->the_builtin_eval_hash, name, (uword) eval_fn);
}

#ifdef CLIB_UNIX
static i8 *
eval_hostname (clib_macro_main_t * mm, i32 complain)
{
  char tmp[128];
  if (gethostname (tmp, sizeof (tmp)))
    return ((i8 *) format (0, "gethostname-error%c", 0));
  return ((i8 *) format (0, "%s%c", tmp, 0));
}
#endif

__clib_export void
clib_macro_init (clib_macro_main_t * mm)
{
  if (mm->the_builtin_eval_hash != 0)
    {
      clib_warning ("mm %p already initialized", mm);
      return;
    }

  mm->the_builtin_eval_hash = hash_create_string (0, sizeof (uword));
  mm->the_value_table_hash = hash_create_string (0, sizeof (uword));

#ifdef CLIB_UNIX
  hash_set_mem (mm->the_builtin_eval_hash, "hostname", (uword) eval_hostname);
#endif
}

__clib_export void
clib_macro_free (clib_macro_main_t * mm)
{
  hash_pair_t *p;
  u8 **strings_to_free = 0;
  int i;

  hash_free (mm->the_builtin_eval_hash);

  /* *INDENT-OFF* */
  hash_foreach_pair (p, mm->the_value_table_hash,
  ({
    vec_add1 (strings_to_free, (u8 *) (p->key));
    vec_add1 (strings_to_free, (u8 *) (p->value[0]));
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (strings_to_free); i++)
    vec_free (strings_to_free[i]);
  vec_free (strings_to_free);
  hash_free (mm->the_value_table_hash);
}

typedef struct
{
  u8 *name;
  u8 *value;
} name_sort_t;

static int
name_compare (void *a1, void *a2)
{
  name_sort_t *ns1 = a1;
  name_sort_t *ns2 = a2;

  return strcmp ((char *) ns1->name, (char *) ns2->name);
}


__clib_export u8 *
format_clib_macro_main (u8 * s, va_list * args)
{
  clib_macro_main_t *mm = va_arg (*args, clib_macro_main_t *);
  int evaluate = va_arg (*args, int);
  hash_pair_t *p;
  name_sort_t *nses = 0, *ns;
  int i;

  /* *INDENT-OFF* */
  hash_foreach_pair (p, mm->the_value_table_hash,
  ({
    vec_add2 (nses, ns, 1);
    ns->name = (u8 *)(p->key);
    ns->value = (u8 *)(p->value[0]);
  }));
  /* *INDENT-ON* */

  if (vec_len (nses) == 0)
    return s;

  vec_sort_with_function (nses, name_compare);

  for (i = 0; i < vec_len (nses); i++)
    {
      s = format (s, "%-20s", nses[i].name);
      if (evaluate == 0)
	s = format (s, "%s\n", nses[i].value);
      else
	{
	  u8 *rv = (u8 *) clib_macro_eval_dollar (mm, (i8 *) nses[i].name,
						  0 /* no complain */ );
	  s = format (s, "%s\n", rv);
	  vec_free (rv);
	}
    }
  return s;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
