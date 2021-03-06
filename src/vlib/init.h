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
 * init.h: mechanism for functions to be called at init/exit.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
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

#ifndef included_vlib_init_h
#define included_vlib_init_h

#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>

/* Init/exit functions: called at start/end of main routine.  Init
   functions are typically used to register and setup packet
   processing nodes.  */

typedef clib_error_t *(vlib_init_function_t) (struct vlib_main_t * vm);

typedef struct _vlib_init_function_list_elt
{
  struct _vlib_init_function_list_elt *next_init_function;
  vlib_init_function_t *f;
  char *name;
  char **runs_before;
  char **runs_after;
  char **init_order;
} _vlib_init_function_list_elt_t;

/* Configuration functions: called with configuration input just before
   main polling loop starts. */
typedef clib_error_t *(vlib_config_function_t) (struct vlib_main_t * vm,
						unformat_input_t * input);

typedef struct vlib_config_function_runtime_t
{
  /* Function to call.  Set to null once function has already been called. */
  vlib_config_function_t *function;

  /* Input for function. */
  unformat_input_t input;

  /* next config function registration */
  struct vlib_config_function_runtime_t *next_registration;

  /* To be invoked as soon as the clib heap is available */
  u8 is_early;

  /* Name used to distinguish input on command line. */
  char name[32];
} vlib_config_function_runtime_t;

#define VLIB_REMOVE_FROM_LINKED_LIST(first,p,next)              \
{                                                               \
  ASSERT (first);                                               \
  if (first == p)                                               \
      first = (p)->next;                                        \
  else                                                          \
    {                                                           \
      __typeof__ (p) current = first;                           \
      while (current->next)                                     \
	{                                                       \
	  if (current->next == p)                               \
	    {                                                   \
	      current->next = current->next->next;              \
	      break;                                            \
	    }                                                   \
	  current = current->next;                              \
	}                                                       \
      ASSERT (current);                                         \
    }                                                           \
}

#define _VLIB_INIT_FUNCTION_SYMBOL(x, type)	\
  _vlib_##type##_function_##x

#define VLIB_INIT_FUNCTION_SYMBOL(x)		\
  _VLIB_INIT_FUNCTION_SYMBOL(x, init)
#define VLIB_MAIN_LOOP_ENTER_FUNCTION_SYMBOL(x)		\
  _VLIB_INIT_FUNCTION_SYMBOL(x, main_loop_enter)
#define VLIB_MAIN_LOOP_EXIT_FUNCTION_SYMBOL(x)	\
  _VLIB_INIT_FUNCTION_SYMBOL(x, main_loop_exit)
#define VLIB_CONFIG_FUNCTION_SYMBOL(x)		\
  _VLIB_INIT_FUNCTION_SYMBOL(x, config)

/* Declaration is global (e.g. not static) so that init functions can
   be called from other modules to resolve init function depend. */

#ifndef CLIB_MARCH_VARIANT
#define VLIB_DECLARE_INIT_FUNCTION(x, tag)                                    \
  vlib_init_function_t *_VLIB_INIT_FUNCTION_SYMBOL (x, tag) = x;              \
  static void __vlib_add_##tag##_function_##x (void)                          \
    __attribute__ ((__constructor__));                                        \
  static _vlib_init_function_list_elt_t _vlib_init_function_##tag##_##x;      \
  static void __vlib_add_##tag##_function_##x (void)                          \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    _vlib_init_function_##tag##_##x.next_init_function =                      \
      vgm->tag##_function_registrations;                                      \
    vgm->tag##_function_registrations = &_vlib_init_function_##tag##_##x;     \
    _vlib_init_function_##tag##_##x.f = &x;                                   \
    _vlib_init_function_##tag##_##x.name = #x;                                \
  }                                                                           \
  static void __vlib_rm_##tag##_function_##x (void)                           \
    __attribute__ ((__destructor__));                                         \
  static void __vlib_rm_##tag##_function_##x (void)                           \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    _vlib_init_function_list_elt_t *this, *prev;                              \
    this = vgm->tag##_function_registrations;                                 \
    if (this == 0)                                                            \
      return;                                                                 \
    if (this->f == &x)                                                        \
      {                                                                       \
	vgm->tag##_function_registrations = this->next_init_function;         \
	return;                                                               \
      }                                                                       \
    prev = this;                                                              \
    this = this->next_init_function;                                          \
    while (this)                                                              \
      {                                                                       \
	if (this->f == &x)                                                    \
	  {                                                                   \
	    prev->next_init_function = this->next_init_function;              \
	    return;                                                           \
	  }                                                                   \
	prev = this;                                                          \
	this = this->next_init_function;                                      \
      }                                                                       \
  }                                                                           \
  static _vlib_init_function_list_elt_t _vlib_init_function_##tag##_##x
#else
/* create unused pointer to silence compiler warnings and get whole
   function optimized out */
#define VLIB_DECLARE_INIT_FUNCTION(x, tag)                      \
static __clib_unused void * __clib_unused_##tag##_##x = x
#endif

#define VLIB_INIT_FUNCTION(x) VLIB_DECLARE_INIT_FUNCTION(x,init)
#define VLIB_WORKER_INIT_FUNCTION(x) VLIB_DECLARE_INIT_FUNCTION(x,worker_init)

#define VLIB_MAIN_LOOP_ENTER_FUNCTION(x) \
  VLIB_DECLARE_INIT_FUNCTION(x,main_loop_enter)
#define VLIB_MAIN_LOOP_EXIT_FUNCTION(x) \
VLIB_DECLARE_INIT_FUNCTION(x,main_loop_exit)

#ifndef CLIB_MARCH_VARIANT
#define VLIB_CONFIG_FUNCTION(x, n, ...)                                       \
  __VA_ARGS__ vlib_config_function_runtime_t VLIB_CONFIG_FUNCTION_SYMBOL (x); \
  static void __vlib_add_config_function_##x (void)                           \
    __attribute__ ((__constructor__));                                        \
  static void __vlib_add_config_function_##x (void)                           \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    VLIB_CONFIG_FUNCTION_SYMBOL (x).next_registration =                       \
      vgm->config_function_registrations;                                     \
    vgm->config_function_registrations = &VLIB_CONFIG_FUNCTION_SYMBOL (x);    \
  }                                                                           \
  static void __vlib_rm_config_function_##x (void)                            \
    __attribute__ ((__destructor__));                                         \
  static void __vlib_rm_config_function_##x (void)                            \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    vlib_config_function_runtime_t *p = &VLIB_CONFIG_FUNCTION_SYMBOL (x);     \
    VLIB_REMOVE_FROM_LINKED_LIST (vgm->config_function_registrations, p,      \
				  next_registration);                         \
  }                                                                           \
  vlib_config_function_runtime_t VLIB_CONFIG_FUNCTION_SYMBOL (x) = {          \
    .name = n,                                                                \
    .function = x,                                                            \
    .is_early = 0,                                                            \
  }
#else
/* create unused pointer to silence compiler warnings and get whole
   function optimized out */
#define VLIB_CONFIG_FUNCTION(x,n,...)                           \
  static __clib_unused vlib_config_function_runtime_t           \
    VLIB_CONFIG_FUNCTION_SYMBOL (__clib_unused_##x)             \
  = {                                                           \
    .name = n,                                                  \
    .function = x,                                              \
    .is_early = 0,						\
  }
#endif

#ifndef CLIB_MARCH_VARIANT
#define VLIB_EARLY_CONFIG_FUNCTION(x, n, ...)                                 \
  __VA_ARGS__ vlib_config_function_runtime_t VLIB_CONFIG_FUNCTION_SYMBOL (x); \
  static void __vlib_add_config_function_##x (void)                           \
    __attribute__ ((__constructor__));                                        \
  static void __vlib_add_config_function_##x (void)                           \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    VLIB_CONFIG_FUNCTION_SYMBOL (x).next_registration =                       \
      vgm->config_function_registrations;                                     \
    vgm->config_function_registrations = &VLIB_CONFIG_FUNCTION_SYMBOL (x);    \
  }                                                                           \
  static void __vlib_rm_config_function_##x (void)                            \
    __attribute__ ((__destructor__));                                         \
  static void __vlib_rm_config_function_##x (void)                            \
  {                                                                           \
    vlib_global_main_t *vgm = vlib_get_global_main ();                        \
    vlib_config_function_runtime_t *p = &VLIB_CONFIG_FUNCTION_SYMBOL (x);     \
    VLIB_REMOVE_FROM_LINKED_LIST (vgm->config_function_registrations, p,      \
				  next_registration);                         \
  }                                                                           \
  vlib_config_function_runtime_t VLIB_CONFIG_FUNCTION_SYMBOL (x) = {          \
    .name = n,                                                                \
    .function = x,                                                            \
    .is_early = 1,                                                            \
  }
#else
/* create unused pointer to silence compiler warnings and get whole
   function optimized out */
#define VLIB_EARLY_CONFIG_FUNCTION(x,n,...)                     \
  static __clib_unused vlib_config_function_runtime_t           \
    VLIB_CONFIG_FUNCTION_SYMBOL (__clib_unused_##x)             \
  = {                                                           \
    .name = n,                                                  \
    .function = x,                                              \
    .is_early = 1,						\
  }
#endif

/* Call given init function: used for init function dependencies. */
#define vlib_call_init_function(vm, x)                                        \
  ({                                                                          \
    vlib_global_main_t *vgm = &vlib_global_main;                              \
    extern vlib_init_function_t *VLIB_INIT_FUNCTION_SYMBOL (x);               \
    vlib_init_function_t *_f = VLIB_INIT_FUNCTION_SYMBOL (x);                 \
    clib_error_t *_error = 0;                                                 \
    if (!hash_get (vgm->init_functions_called, _f))                           \
      {                                                                       \
	hash_set1 (vgm->init_functions_called, _f);                           \
	_error = _f (vm);                                                     \
      }                                                                       \
    _error;                                                                   \
  })

/* Don't call given init function: used to suppress parts of the netstack */
#define vlib_mark_init_function_complete(vm, x)                               \
  ({                                                                          \
    vlib_global_main_t *vgm = &vlib_global_main;                              \
    extern vlib_init_function_t *VLIB_INIT_FUNCTION_SYMBOL (x);               \
    vlib_init_function_t *_f = VLIB_INIT_FUNCTION_SYMBOL (x);                 \
    hash_set1 (vgm->init_functions_called, _f);                               \
  })

#define vlib_call_post_graph_init_function(vm, x)                             \
  ({                                                                          \
    vlib_global_main_t *vgm = &vlib_global_main;                              \
    extern vlib_init_function_t *VLIB_POST_GRAPH_INIT_FUNCTION_SYMBOL (x);    \
    vlib_init_function_t *_f = VLIB_POST_GRAPH_INIT_FUNCTION_SYMBOL (x);      \
    clib_error_t *_error = 0;                                                 \
    if (!hash_get (vgm->init_functions_called, _f))                           \
      {                                                                       \
	hash_set1 (vgm->init_functions_called, _f);                           \
	_error = _f (vm);                                                     \
      }                                                                       \
    _error;                                                                   \
  })

#define vlib_call_config_function(vm, x)                                      \
  ({                                                                          \
    vlib_global_main_t *vgm = &vlib_global_main;                              \
    vlib_config_function_runtime_t *_r;                                       \
    clib_error_t *_error = 0;                                                 \
    extern vlib_config_function_runtime_t VLIB_CONFIG_FUNCTION_SYMBOL (x);    \
                                                                              \
    _r = &VLIB_CONFIG_FUNCTION_SYMBOL (x);                                    \
    if (!hash_get (vgm->init_functions_called, _r->function))                 \
      {                                                                       \
	hash_set1 (vgm->init_functions_called, _r->function);                 \
	_error = _r->function (vm, &_r->input);                               \
      }                                                                       \
    _error;                                                                   \
  })

#define vlib_call_main_loop_enter_function(vm, x)                             \
  ({                                                                          \
    vlib_global_main_t *vgm = &vlib_global_main;                              \
    extern vlib_init_function_t *VLIB_MAIN_LOOP_ENTER_FUNCTION_SYMBOL (x);    \
    vlib_init_function_t *_f = VLIB_MAIN_LOOP_ENTER_FUNCTION_SYMBOL (x);      \
    clib_error_t *_error = 0;                                                 \
    if (!hash_get (vgm->init_functions_called, _f))                           \
      {                                                                       \
	hash_set1 (vgm->init_functions_called, _f);                           \
	_error = _f (vm);                                                     \
      }                                                                       \
    _error;                                                                   \
  })

/* External functions. */
clib_error_t *vlib_call_all_init_functions (struct vlib_main_t *vm);
clib_error_t *vlib_call_all_config_functions (struct vlib_main_t *vm,
					      unformat_input_t * input,
					      int is_early);
clib_error_t *vlib_call_all_main_loop_enter_functions (struct vlib_main_t
						       *vm);
clib_error_t *vlib_call_all_main_loop_exit_functions (struct vlib_main_t *vm);
clib_error_t *
vlib_call_init_exit_functions (struct vlib_main_t *vm,
			       _vlib_init_function_list_elt_t **headp,
			       int call_once, int is_global);
clib_error_t *
vlib_call_init_exit_functions_no_sort (struct vlib_main_t *vm,
				       _vlib_init_function_list_elt_t **headp,
				       int call_once, int is_global);
clib_error_t *vlib_sort_init_exit_functions (_vlib_init_function_list_elt_t
					     **);
#define foreach_vlib_module_reference		\
  _ (node_cli)					\
  _ (trace_cli)

/* Dummy function to get node_cli.c linked in. */
#define _(x) void vlib_##x##_reference (void);
foreach_vlib_module_reference
#undef _
#define VLIB_INITS(...)  (char*[]) { __VA_ARGS__, 0}
#endif /* included_vlib_init_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
