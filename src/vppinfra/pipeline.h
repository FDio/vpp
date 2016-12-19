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
 * pipeline.h: software pipeline infrastructure
 *
 * Copyright (c) 2010 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_clib_pipeline_h
#define included_clib_pipeline_h

#define clib_pipeline_stage(F,TYPE,ARG,I,BODY)		\
  always_inline void F##_inline (void * _, u32 I)	\
  { TYPE ARG = _; { BODY; } }				\
  never_inline  void F##_no_inline (TYPE ARG, u32 I)	\
  { F##_inline (ARG, I); }

#define clib_pipeline_stage_static(F,TYPE,ARG,I,BODY)		\
  static_always_inline void F##_inline (void * _, u32 I)	\
  { TYPE ARG = _; { BODY; } }					\
  never_inline  void F##_no_inline (TYPE ARG, u32 I)		\
  { F##_inline (ARG, I); }

#define clib_pipeline_stage_no_inline(F,TYPE,ARG,I,BODY)	\
  never_inline void F##_no_inline (void * _, u32 I)		\
  { TYPE ARG = _; { BODY; } }					\
  never_inline  void F##_inline (TYPE ARG, u32 I)		\
  { F##_no_inline (ARG, I); }

#define _clib_pipeline_var(v) _clib_pipeline_##v

#define clib_pipeline_stage_execute(F,A,I,S) \
  F##_##S (A, _clib_pipeline_var(i) - (I))

#define clib_pipeline_main_stage(F,A,I) \
  clib_pipeline_stage_execute (F, A, I, inline)
#define clib_pipeline_init_stage(F,A,I) \
  if (_clib_pipeline_var(i) >= (I)) clib_pipeline_stage_execute (F, A, I, no_inline)
#define clib_pipeline_exit_stage(F,A,I)					\
  if (_clib_pipeline_var(i) >= (I) && _clib_pipeline_var(i) - (I) < _clib_pipeline_var(n_vectors)) \
    clib_pipeline_stage_execute (F, A, I, no_inline)

#define clib_pipeline_init_loop				\
  for (_clib_pipeline_var(i) = 0;			\
       _clib_pipeline_var(i) <				\
	 clib_min (_clib_pipeline_var(n_stages) - 1,	\
		   _clib_pipeline_var(n_vectors));	\
       _clib_pipeline_var(i)++)

#define clib_pipeline_main_loop					\
  for (; _clib_pipeline_var(i) < _clib_pipeline_var(n_vectors);	\
       _clib_pipeline_var(i)++)

#define clib_pipeline_exit_loop						\
  for (; _clib_pipeline_var(i) < (_clib_pipeline_var(n_vectors)		\
				  + _clib_pipeline_var(n_stages) - 1);	\
       _clib_pipeline_var(i)++)

#define clib_pipeline_run_2_stage(N,ARG,STAGE0,STAGE1)	\
do {							\
  uword _clib_pipeline_var(n_vectors) = (N);		\
  uword _clib_pipeline_var(n_stages) = 2;		\
  uword _clib_pipeline_var(i);				\
							\
  clib_pipeline_init_loop				\
    {							\
      clib_pipeline_init_stage (STAGE0, ARG, 0);	\
    }							\
							\
  clib_pipeline_main_loop				\
    {							\
      clib_pipeline_main_stage (STAGE0, ARG, 0);	\
      clib_pipeline_main_stage (STAGE1, ARG, 1);	\
    }							\
							\
  clib_pipeline_exit_loop				\
    {							\
      clib_pipeline_exit_stage (STAGE1, ARG, 1);	\
    }							\
} while (0)

#define clib_pipeline_run_3_stage(N,ARG,STAGE0,STAGE1,STAGE2)	\
do {								\
  uword _clib_pipeline_var(n_vectors) = (N);			\
  uword _clib_pipeline_var(n_stages) = 3;			\
  uword _clib_pipeline_var(i);					\
								\
  clib_pipeline_init_loop					\
    {								\
      clib_pipeline_init_stage (STAGE0, ARG, 0);		\
      clib_pipeline_init_stage (STAGE1, ARG, 1);		\
    }								\
								\
  clib_pipeline_main_loop					\
    {								\
      clib_pipeline_main_stage (STAGE0, ARG, 0);		\
      clib_pipeline_main_stage (STAGE1, ARG, 1);		\
      clib_pipeline_main_stage (STAGE2, ARG, 2);		\
    }								\
								\
  clib_pipeline_exit_loop					\
    {								\
      clib_pipeline_exit_stage (STAGE1, ARG, 1);		\
      clib_pipeline_exit_stage (STAGE2, ARG, 2);		\
    }								\
} while (0)

#define clib_pipeline_run_4_stage(N,ARG,STAGE0,STAGE1,STAGE2,STAGE3)	\
do {									\
  uword _clib_pipeline_var(n_vectors) = (N);				\
  uword _clib_pipeline_var(n_stages) = 4;				\
  uword _clib_pipeline_var(i);						\
									\
  clib_pipeline_init_loop						\
    {									\
      clib_pipeline_init_stage (STAGE0, ARG, 0);			\
      clib_pipeline_init_stage (STAGE1, ARG, 1);			\
      clib_pipeline_init_stage (STAGE2, ARG, 2);			\
    }									\
									\
  clib_pipeline_main_loop						\
    {									\
      clib_pipeline_main_stage (STAGE0, ARG, 0);			\
      clib_pipeline_main_stage (STAGE1, ARG, 1);			\
      clib_pipeline_main_stage (STAGE2, ARG, 2);			\
      clib_pipeline_main_stage (STAGE3, ARG, 3);			\
    }									\
									\
  clib_pipeline_exit_loop						\
    {									\
      clib_pipeline_exit_stage (STAGE1, ARG, 1);			\
      clib_pipeline_exit_stage (STAGE2, ARG, 2);			\
      clib_pipeline_exit_stage (STAGE3, ARG, 3);			\
    }									\
} while (0)

#endif /* included_clib_pipeline_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
