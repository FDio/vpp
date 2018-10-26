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

#define foreach_lina_dequeue_error \
  _(NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f,s) LINA_TX_ERROR_##f,
  foreach_lina_dequeue_error
#undef _
    LINA_DEQUEUE_N_ERROR,
} lina_dequeue_error_t;

static char *lina_dequeue_error_strings[] = {
#define _(n,s) s,
  foreach_lina_dequeue_error
#undef _
};


static u8 *
format_lina_dequeue_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}


VLIB_NODE_FN (lina_dequeue_node) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * frame)
{
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lina_dequeue_node) = {
  .name = "lina-dequeue",
  .vector_size = sizeof (u32),
  .format_trace = format_lina_dequeue_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = LINA_DEQUEUE_N_ERROR,
  .error_strings = lina_dequeue_error_strings,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
