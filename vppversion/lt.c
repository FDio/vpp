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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>

#define foreach_libtool_mode _ (compile) _ (link) _ (install)

typedef enum {
#define _(m) MODE_##m,
  foreach_libtool_mode
#undef _
} lt_mode_t;

typedef enum {
  LITERAL,
  OUTPUT_EXE,
  OUTPUT_LO,
  OUTPUT_LA,
  LT_LIB,
  NON_LT_LIB,
  IGNORE,
} lt_edit_type_t;

typedef struct {
  lt_edit_type_t type;
  u8 * data;
} lt_edit_t;

typedef struct {
  u8 * path;
} lt_lib_path_t;

typedef struct {
  lt_mode_t mode;
  int link_static;
  int silent;
  lt_edit_type_t output_edit_type;
  u8 * output_file;
  lt_edit_t * edits;
  lt_lib_path_t * lib_path;
  uword * rpath_hash;
  u8 * tag;
} lt_main_t;

static lt_lib_path_t *
search_lib_path (lt_main_t * lm, char * fmt, ...)
{
  va_list va;
  static u8 * file_name, * path_name;
  lt_lib_path_t * p = 0;

  if (file_name)
    _vec_len (file_name) = 0;

  va_start (va, fmt);
  file_name = va_format (file_name, fmt, &va);
  va_end (va);

  path_name = 0;
  vec_foreach (p, lm->lib_path)
    {
      struct stat st;

      if (path_name)
	_vec_len (path_name) = 0;

      path_name = format (path_name, "%s/%v%c", p->path, file_name, 0);
      if (stat ((char *) path_name, &st) >= 0)
	return p;
    }
  return 0;
}

static u8 * format_libtool_mode (u8 * s, va_list * args)
{
  int m = va_arg (*args, int);
  char * t;
  switch (m)
    {
#define _(f) case MODE_##f: t = #f; break;
      foreach_libtool_mode;
#undef _
    default:
      t = 0;
    }
  if (t)
    vec_add (s, t, strlen (t));
  else
    s = format (s, "unknown 0x%x", m);
  return s;
}

static uword unformat_libtool_mode (unformat_input_t * input, va_list * args)
{
  int * result = va_arg (*args, int *);
#define _(m) if (unformat (input, #m)) { *result = MODE_##m; return 1; }
  foreach_libtool_mode;
#undef _
  return 0;
}

static uword unformat_basename (unformat_input_t * input, va_list * args)
{
  u8 ** result = va_arg (*args, u8 **);
  u8 * suffix = va_arg (*args, u8 *);
  u8 * current_suffix = suffix;
  uword c;

  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      switch (c)
	{
	case 0:
	case ' ':
	case '\t':
	case '\n':
	case '\r':
	  goto fail;
	}

      vec_add1 (*result, c);
      if (c == *current_suffix)
	current_suffix++;
      else
	current_suffix = suffix;

      if (*current_suffix == 0)
	{
	  _vec_len (*result) -= current_suffix - suffix;
	  return 1;
	}
    }
 fail:
  vec_free (*result);
  return 0;
}

static void edit (lt_main_t * lm, lt_edit_type_t type, char * fmt, ...)
{
  va_list va;
  lt_edit_t * e;
  u8 * s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  vec_add2 (lm->edits, e, 1);
  e->type = type;
  e->data = s;
}

static u8 * format_argv (u8 * s, va_list * args)
{
  u8 ** a = va_arg (*args, u8 **);
  uword i;
  for (i = 0; i < vec_len (a) - 1; i++)
    {
      if (i > 0)
	vec_add1 (s, ' ');
      vec_add (s, a[i], vec_len (a[i]) - 1);
    }
  return s;
}

static u8 * format_dirname (u8 * s, va_list * args)
{
  u8 * f = va_arg (*args, u8 *);
  u8 * t;

  for (t = vec_end (f) - 1; t >= f; t--)
    {
      if (t[0] == '/')
	break;
    }
  if (t[0] == '/')
    vec_add (s, f, t - f);
  else
    vec_add1 (s, '.');
  return s;
}

static u8 * format_basename (u8 * s, va_list * args)
{
  u8 * f = va_arg (*args, u8 *);
  u8 * t;

  for (t = vec_end (f) - 1; t >= f; t--)
    {
      if (t[0] == '/')
	break;
    }
  if (t[0] == '/')
    vec_add (s, t + 1, vec_end (f) - (t + 1));
  else
    vec_add (s, f, vec_len (f));
  return s;
}

static void my_system (char * fmt, ...)
{
  va_list va;
  u8 * s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (s, 0);		/* null terminate */
  if (system ((char *) s) != 0)
    clib_error ("%s", s);
  vec_free (s);
}

static u8 * my_cmd (char * fmt, ...)
{
  va_list va;
  u8 * s;
  FILE * result;
  int c;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (s, 0);		/* null terminate */
  result = popen ((char *) s, "r");
  if (! result)
    clib_error ("%s", s);
  _vec_len (s) = 0;
  while ((c = fgetc (result)) != EOF)
    vec_add1 (s, c);
  pclose (result);
  return s;
}

static void make_file_with_contents (lt_main_t * lm, u8 * contents, char * fmt, ...)
{
  va_list va;
  u8 * s;
  FILE * f;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  vec_add1 (s, 0);		/* null terminate */
  f = fopen ((char *) s, "w");

  if (! f)
    clib_error ("fopen %s", s);

  if (1 != fwrite (contents, vec_len (contents), 1, f))
    clib_error ("fwrite");

  fclose (f);
}

static u8 ** add_argv (u8 ** argv, char * fmt, ...)
{
  va_list va;
  u8 * s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (s, 0);		/* null terminate */
  vec_add1 (argv, s);
  return argv;
}

#define GEN_ARGV_PIC (1 << 0)
#define GEN_ARGV_PUNT (1 << 1)

static u8 ** gen_argv (lt_main_t * lm, uword flags)
{
  u8 ** r = 0;
  uword * path_used_bitmap = 0;
  lt_edit_t * e;
  int is_punt;

  is_punt = (flags & GEN_ARGV_PUNT) != 0;
  if (is_punt)
    {
      /* No supported so punt back to shell based libtool. */
      r = add_argv (r, "/bin/sh");
      r = add_argv (r, "./libtool");
      r = add_argv (r, "--mode=%U", format_libtool_mode, lm->mode);
    }

  if (lm->mode == MODE_compile)
    ASSERT (lm->output_edit_type != OUTPUT_LA);

  vec_foreach (e, lm->edits)
    {
      switch (e->type)
	{
	case LITERAL:
	  r = add_argv (r, "%v", e->data);
	  break;

	case OUTPUT_EXE:
	  if (! is_punt)
	    my_system ("mkdir -p %U/.libs", format_dirname, e->data);
	  r = add_argv (r, "-o");
	  r = add_argv (r, "%s%v", is_punt ? "" : ".libs/", e->data);
	  break;

	case OUTPUT_LO:
	  if (flags & GEN_ARGV_PIC)
	    {
	      r = add_argv (r, "-fPIC");
	      r = add_argv (r, "-DPIC");
	    }
	  r = add_argv (r, "-o");

	  if (is_punt)
	    r = add_argv (r, "-o %v.lo", e->data);

	  else if (flags & GEN_ARGV_PIC)
	    {
	      my_system ("mkdir -p %U/.libs", format_dirname, e->data);
	      r = add_argv (r, "%U/.libs/%U.o",
			    format_dirname, e->data,
			    format_basename, e->data);
	    }
	  else
	    {
	      my_system ("mkdir -p %U", format_dirname, e->data);
	      r = add_argv (r, "%v.o", e->data);
	    }
	  break;

	case OUTPUT_LA:
	  if (is_punt)
	    r = add_argv (r, "-o %v.la", e->data);
	  else
	    abort ();
	  break;

	case LT_LIB:
	  if (is_punt)
	    r = add_argv (r, "%v.la", e->data);

	  else if (lm->mode == MODE_link)
	    {
	      u8 * pwd = get_current_dir_name ();
	      u8 * libdir = my_cmd (". %s/%v.la && echo -n ${libdir}", pwd, e->data);

	      if (! hash_get_mem (lm->rpath_hash, libdir))
		{
		  r = add_argv (r, "-Wl,-rpath");
		  r = add_argv (r, "-Wl,%v", libdir);
		  hash_set_mem (lm->rpath_hash, libdir, 0);
		}

	      r = add_argv (r, "%U/.libs/%U.so",
			    format_dirname, e->data,
			    format_basename, e->data);
	    }
	  else
	    r = add_argv (r, "%v.la", e->data);
	  break;

	case NON_LT_LIB:
	  if (lm->mode == MODE_link && ! is_punt)
	    {
	      lt_lib_path_t * p = search_lib_path (lm, "lib%v.so", e->data);
	      if (p)
		{
		  path_used_bitmap = clib_bitmap_ori (path_used_bitmap, p - lm->lib_path);
		  r = add_argv (r, "%s/lib%v.so", p->path, e->data);
		}
	      else
		r = add_argv (r, "-l%v", e->data);
	    }

	  else
	    r = add_argv (r, "-l%v", e->data);
	  break;

	default:
	  ASSERT (0);
	}
    }

  {
    uword i;
    clib_bitmap_foreach (i, path_used_bitmap, ({
      lt_lib_path_t * p = vec_elt_at_index (lm->lib_path, i);
      r = add_argv (r, "-Wl,-rpath");
      r = add_argv (r, "-Wl,%s", p->path);
    }));
    clib_bitmap_free (path_used_bitmap);
  }

  vec_add1 (r, 0);

  return r;
}

static void do_command (lt_main_t * lm, u8 ** argv)
{
  u8 * cmd = format (0, "%U%c", format_argv, argv, 0);

  if (! lm->silent)
    fformat (stderr, "lt: %s\n", cmd);

  if (system ((char *) cmd))
    exit (1);

  vec_free (cmd);
}

static int lt_main (unformat_input_t * input)
{
  lt_main_t _lm = {0}, * lm = &_lm;
  clib_error_t * error = 0;
  u8 * s;

  lm->rpath_hash = hash_create_vec (0, sizeof (u8), sizeof (uword));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      s = 0;

      if (s)
	_vec_len (s) = 0;

      if (unformat (input, "-o %s", &s))
	{
	  u8 * dot = vec_end (s) - 4;
	  int is_la = 0, is_lo = 0;

	  is_lo = vec_len (s) >= 4 && ! strcmp ((char *) dot, ".lo");
	  is_la = vec_len (s) >= 4 && ! strcmp ((char *) dot, ".la");
	  if (is_lo || is_la)
	    {
	      dot[0] = 0;
	      lm->output_edit_type = is_lo ? OUTPUT_LO : OUTPUT_LA;
	    }
	  else
	    lm->output_edit_type = OUTPUT_EXE;
	  edit (lm, lm->output_edit_type, "%s", s);
	  lm->output_file = format (0, "%s", s);
	}

      else if (unformat (input, "-L%s", &s))
	{
	  lt_lib_path_t * p;
	  vec_add2 (lm->lib_path, p, 1);
	  p->path = s;
	  edit (lm, LITERAL, "-L%s", s);
	}

      else if (unformat (input, "%U", unformat_basename, &s, ".la"))
	edit (lm, LT_LIB, "%v", s);

      else if (unformat (input, "-l%s", &s))
	edit (lm, NON_LT_LIB, "%s", s);

      else if (unformat (input, "--mode=%U", unformat_libtool_mode, &lm->mode))
	;

      else if (unformat (input, "--tag=%s", &lm->tag))
	;

      else if (unformat (input, "-static"))
	{
	  lm->link_static = 1;
	  edit (lm, LITERAL, "%s", "-static");
	}

      else if (unformat (input, "%s", &s))
	edit (lm, LITERAL, "%s", s);

      else
	{
	  error = clib_error_create ("parse error `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  {
    u8 ** argv;
    
    if (! (lm->mode == MODE_compile
	   || (lm->mode == MODE_link && lm->output_edit_type == OUTPUT_EXE && ! lm->link_static)))
      {
	argv = gen_argv (lm, GEN_ARGV_PUNT);
	do_command (lm, argv);
      }
    else if (lm->mode == MODE_compile)
      {
	argv = gen_argv (lm, GEN_ARGV_PIC);
	do_command (lm, argv);
	argv = gen_argv (lm, 0);
	do_command (lm, argv);
      }
    else
      {
	argv = gen_argv (lm, 0);
	do_command (lm, argv);
      }

    if (lm->mode == MODE_compile)
      {
	u8 * s = 0;
	u8 * f = lm->output_file;

	/* Need this or .lo files are rejected. */
	s = format (s, "# Generated by libtool (Eliot lt 0.0)\n");

	s = format (s, "pic_object='.libs/%U.o'\n", format_basename, f);
	s = format (s, "non_pic_object='%U.o'\n", format_basename, f);
	make_file_with_contents (lm, s, "%v.lo", f);
	vec_free (s);
      }
    else if (lm->mode == MODE_link)
      {
	u8 * s = 0;
	u8 * f = lm->output_file;
	s = format (s, "%s",
		    "# Generated by libtool (Eliot lt) 2.4\n"
		    "# %%%MAGIC variable%%%\n"
                    "generated_by_libtool_version=2.4\n");
	make_file_with_contents (lm, s, "%v", f);
	vec_free (s);
      }

    {
      int status;
      while (1)
	{
	  if (waitpid (-1, &status, 0) < 0 && errno == ECHILD)
	    break;
	}
      exit (0);
    }
  }

 done:
  if (s)
    vec_free (s);
  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  return 0;
}

int main (int argc, char * argv[])
{
  unformat_input_t i;

  unformat_init_command_line (&i, argv);
  exit (lt_main (&i));
  return 0;
}
