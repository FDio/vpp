/*
 *------------------------------------------------------------------
 * api.h
 *
 * Copyright (c) 2009-2015 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef included_api_h
#define included_api_h

#include <stddef.h>
#include <vppinfra/error.h>
#include <svm/svm.h>
#include <vlib/vlib.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api_common.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct
 {
   u8 endian; u8 wrapped;
   u32 nitems;
}) vl_api_trace_file_header_t;
/* *INDENT-ON* */

int vl_msg_api_trace_save (api_main_t * am,
			   vl_api_trace_which_t which, FILE * fp);

#define VLIB_API_INIT_FUNCTION(x) VLIB_DECLARE_INIT_FUNCTION(x,api_init)

/* Call given init function: used for init function dependencies. */
#define vlib_call_api_init_function(vm, x)                              \
  ({                                                                    \
    extern vlib_init_function_t * _VLIB_INIT_FUNCTION_SYMBOL (x,api_init); \
    vlib_init_function_t * _f = _VLIB_INIT_FUNCTION_SYMBOL (x,api_init); \
    clib_error_t * _error = 0;                                          \
    if (! hash_get (vm->init_functions_called, _f))                     \
      {                                                                 \
	hash_set1 (vm->init_functions_called, _f);                      \
	_error = _f (vm);                                               \
      }                                                                 \
    _error;                                                             \
  })


#define _VL_MSG_API_FUNCTION_SYMBOL(x, type)	\
  _vl_msg_api_##type##_function_##x

#define VL_MSG_API_FUNCTION_SYMBOL(x)		\
  _VL_MSG_API_FUNCTION_SYMBOL(x, reaper)

#define VLIB_DECLARE_REAPER_FUNCTION(x, tag)                            \
vl_msg_api_init_function_t * _VL_MSG_API_FUNCTION_SYMBOL (x, tag) = x;  \
static void __vl_msg_api_add_##tag##_function_##x (void)                \
    __attribute__((__constructor__)) ;                                  \
                                                                        \
static void __vl_msg_api_add_##tag##_function_##x (void)                \
{                                                                       \
 api_main_t * am = &api_main;                                           \
 static _vl_msg_api_function_list_elt_t _vl_msg_api_function;           \
 _vl_msg_api_function.next_init_function                                \
    = am->tag##_function_registrations;                                 \
  am->tag##_function_registrations = &_vl_msg_api_function;             \
 _vl_msg_api_function.f = &x;                                           \
}

#define VL_MSG_API_REAPER_FUNCTION(x) VLIB_DECLARE_REAPER_FUNCTION(x,reaper)

/* Call reaper function with client index */
#define vl_msg_api_call_reaper_function(ci)                             \
  ({                                                                    \
    extern vlib_init_function_t * VLIB_INIT_FUNCTION_SYMBOL (reaper);   \
    vlib_init_function_t * _f = VLIB_INIT_FUNCTION_SYMBOL (reaper);     \
    clib_error_t * _error = 0;                                          \
    _error = _f (ci);                                                   \
  })

static inline u32
vl_msg_api_get_msg_length_inline (void *msg_arg)
{
  u8 *msg = (u8 *) msg_arg;

  msgbuf_t *header = (msgbuf_t *) (msg - offsetof (msgbuf_t, data));

  return clib_net_to_host_u32 (header->data_len);
}

int vl_msg_api_rx_trace_enabled (api_main_t * am);
int vl_msg_api_tx_trace_enabled (api_main_t * am);
void vl_msg_api_trace (api_main_t * am, vl_api_trace_t * tp, void *msg);
int vl_msg_api_trace_onoff (api_main_t * am, vl_api_trace_which_t which,
			    int onoff);
int vl_msg_api_trace_free (api_main_t * am, vl_api_trace_which_t which);
int vl_msg_api_trace_configure (api_main_t * am, vl_api_trace_which_t which,
				u32 nitems);
void vl_msg_api_handler_with_vm_node (api_main_t * am,
				      void *the_msg, vlib_main_t * vm,
				      vlib_node_runtime_t * node);
vl_api_trace_t *vl_msg_api_trace_get (api_main_t * am,
				      vl_api_trace_which_t which);
void vl_msg_api_add_msg_name_crc (api_main_t * am, const char *string,
				  u32 id);
void vl_msg_api_add_version (api_main_t * am, const char *string,
			     u32 major, u32 minor, u32 patch);
/* node_serialize.c prototypes */
u8 *vlib_node_serialize (vlib_node_main_t * nm, u8 * vector,
			 u32 max_threads, int include_nexts,
			 int include_stats);
vlib_node_t **vlib_node_unserialize (u8 * vector);
u32 vl_msg_api_get_msg_length (void *msg_arg);

#endif /* included_api_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
