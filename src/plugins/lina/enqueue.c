/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vppinfra/socket.h>
#include <vlib/vlib.h>

#include <lina/shared.h>
#include <lina/lina.h>

#define foreach_lina_enqueue_error \
  _(NO_FREE_SLOTS, "no free slots")

typedef enum
{
#define _(f,s) LINA_TX_ERROR_##f,
  foreach_lina_enqueue_error
#undef _
    LINA_ENQUEUE_N_ERROR,
} lina_enqueue_error_t;

static char *lina_enqueue_error_strings[] = {
#define _(n,s) s,
  foreach_lina_enqueue_error
#undef _
};


static u8 *
format_lina_enqueue_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}


VLIB_NODE_FN (lina_enqueue_node) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
{
  clib_warning ("%u packets received", frame->n_vectors);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lina_enqueue_node) = {
  .name = "lina-enqueue",
  .vector_size = sizeof (u32),
  .format_trace = format_lina_enqueue_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = LINA_ENQUEUE_N_ERROR,
  .error_strings = lina_enqueue_error_strings,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
