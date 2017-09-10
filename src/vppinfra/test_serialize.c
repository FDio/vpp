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
/*
  Copyright (c) 2005 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <vppinfra/serialize.h>
#include <vppinfra/os.h>

#define foreach_my_vector_type			\
  _ (u8, a8)					\
  _ (u16, a16)					\
  _ (u32, a32)

typedef struct
{
#define _(t,f) t f;
  foreach_my_vector_type
#undef _
} my_vector_type_t;

static void
serialize_my_vector_type_single (serialize_main_t * m, va_list * va)
{
  my_vector_type_t *v = va_arg (*va, my_vector_type_t *);
  u32 n = va_arg (*va, u32);
  u32 i;

  for (i = 0; i < n; i++)
    {
#define _(t,f) serialize_integer (m, v[i].f, sizeof (v[i].f));
      foreach_my_vector_type;
    }
#undef _
}

static void
unserialize_my_vector_type_single (serialize_main_t * m, va_list * va)
{
  my_vector_type_t *v = va_arg (*va, my_vector_type_t *);
  u32 n = va_arg (*va, u32);
  u32 i;

  for (i = 0; i < n; i++)
    {
#define _(t,f) { u32 tmp; unserialize_integer (m, &tmp, sizeof (v[i].f)); v[i].f = tmp; }
      foreach_my_vector_type;
#undef _
    }
}

static void
serialize_my_vector_type_multiple (serialize_main_t * m, va_list * va)
{
  my_vector_type_t *v = va_arg (*va, my_vector_type_t *);
  u32 n = va_arg (*va, u32);

#define _(t,f)					\
  serialize_multiple				\
    (m,						\
     &v[0].f,					\
     STRUCT_SIZE_OF (my_vector_type_t, f),	\
     STRUCT_STRIDE_OF (my_vector_type_t, f),	\
     n);

  foreach_my_vector_type;

#undef _
}

static void
unserialize_my_vector_type_multiple (serialize_main_t * m, va_list * va)
{
  my_vector_type_t *v = va_arg (*va, my_vector_type_t *);
  u32 n = va_arg (*va, u32);

#define _(t,f)					\
  unserialize_multiple				\
    (m,						\
     &v[0].f,					\
     STRUCT_SIZE_OF (my_vector_type_t, f),	\
     STRUCT_STRIDE_OF (my_vector_type_t, f),	\
     n);

  foreach_my_vector_type;

#undef _
}

typedef struct
{
  u32 n_iter;
  u32 seed;
  u32 verbose;
  u32 multiple;
  u32 max_len;

  my_vector_type_t **test_vectors;

  char *dump_file;

  serialize_main_t serialize_main;
  serialize_main_t unserialize_main;
} test_serialize_main_t;

int
test_serialize_main (unformat_input_t * input)
{
  clib_error_t *error = 0;
  test_serialize_main_t _tm, *tm = &_tm;
  serialize_main_t *sm = &tm->serialize_main;
  serialize_main_t *um = &tm->unserialize_main;
  uword i;

  memset (tm, 0, sizeof (tm[0]));
  tm->n_iter = 100;
  tm->seed = 1;
  tm->max_len = 128;
  tm->verbose = 0;
  tm->multiple = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iter %d", &tm->n_iter))
	;
      else if (unformat (input, "seed %d", &tm->seed))
	;
      else if (unformat (input, "file %s", &tm->dump_file))
	;
      else if (unformat (input, "max-len %d", &tm->max_len))
	;
      else if (unformat (input, "multiple %=", &tm->multiple, 1))
	;
      else if (unformat (input, "single %=", &tm->multiple, 0))
	;
      else if (unformat (input, "verbose %=", &tm->verbose, 1))
	;
      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (tm->seed == 0)
    tm->seed = random_default_seed ();

  clib_warning ("iter %d seed %d max-len %d", tm->n_iter, tm->seed,
		tm->max_len);

#ifdef CLIB_UNIX
  if (tm->dump_file)
    serialize_open_clib_file (sm, tm->dump_file);
  else
#endif
    serialize_open_vector (sm, 0);

  vec_resize (tm->test_vectors, tm->n_iter);
  for (i = 0; i < tm->n_iter; i++)
    {
      uword l = 1 + (random_u32 (&tm->seed) % tm->max_len);
      my_vector_type_t *mv;

      vec_resize (tm->test_vectors[i], l);
      vec_foreach (mv, tm->test_vectors[i])
      {
#define _(t,f) mv->f = random_u32 (&tm->seed) & pow2_mask (31);
	foreach_my_vector_type;
#undef _
      }

      vec_serialize (sm, tm->test_vectors[i],
		     tm->multiple ? serialize_my_vector_type_multiple :
		     serialize_my_vector_type_single);
    }

  if (tm->verbose)
    clib_warning ("overflow vector max bytes %d",
		  vec_max_len (sm->stream.overflow_buffer));

  serialize_close (sm);

#ifdef CLIB_UNIX
  if (tm->dump_file)
    {
      if ((error = unserialize_open_clib_file (um, tm->dump_file)))
	goto done;
    }
  else
#endif
    {
      u8 *v = serialize_close_vector (sm);
      unserialize_open_data (um, v, vec_len (v));
    }

  for (i = 0; i < tm->n_iter; i++)
    {
      my_vector_type_t *mv0;
      my_vector_type_t *mv1;

      vec_unserialize (um, &mv0,
		       tm->multiple ? unserialize_my_vector_type_multiple :
		       unserialize_my_vector_type_single);
      mv1 = tm->test_vectors[i];

      if (vec_len (mv0) != vec_len (mv1))
	os_panic ();
      if (memcmp (mv0, mv1, vec_len (mv0) * sizeof (mv0[0])))
	os_panic ();

      vec_free (mv0);
    }

done:
  if (error)
    clib_error_report (error);
  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int r;

  unformat_init_command_line (&i, argv);
  r = test_serialize_main (&i);
  unformat_free (&i);
  return r;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
