
/*
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
 */

#include <vnet/vnet.h>
#include <vppinfra/xxhash.h>
#include <vlib/threads.h>
#include <vnet/handoff.h>
#include <vnet/feature/feature.h>

typedef struct
{
  uword *workers_bitmap;
  u32 *workers;
} per_inteface_handoff_data_t;

typedef struct
{
  u32 cached_next_index;
  u32 num_workers;
  u32 first_worker_index;

  per_inteface_handoff_data_t *if_data;

  /* Worker handoff index */
  u32 frame_queue_index;

    u64 (*hash_fn) (ethernet_header_t *);
} handoff_main_t;

extern handoff_main_t handoff_main;

#ifndef CLIB_MARCH_VARIANT
handoff_main_t handoff_main;
#endif /* CLIB_MARCH_VARIANT */

typedef struct
{
  u32 sw_if_index;
  u32 next_worker_index;
  u32 buffer_index;
} worker_handoff_trace_t;

#define foreach_worker_handoff_error			\
  _(CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym,str) WORKER_HANDOFF_ERROR_##sym,
  foreach_worker_handoff_error
#undef _
    WORKER_HANDOFF_N_ERROR,
} worker_handoff_error_t;

static char *worker_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_worker_handoff_error
#undef _
};

/* packet trace format function */
static u8 *
format_worker_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  worker_handoff_trace_t *t = va_arg (*args, worker_handoff_trace_t *);

  s =
    format (s, "worker-handoff: sw_if_index %d, next_worker %d, buffer 0x%x",
	    t->sw_if_index, t->next_worker_index, t->buffer_index);
  return s;
}

VLIB_NODE_FN (worker_handoff_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  handoff_main_t *hm = &handoff_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      u32 sw_if_index0;
      u32 hash;
      u64 hash_key;
      per_inteface_handoff_data_t *ihd0;
      u32 index0;


      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      ASSERT (hm->if_data);
      ihd0 = vec_elt_at_index (hm->if_data, sw_if_index0);

      /*
       * Force unknown traffic onto worker 0,
       * and into ethernet-input. $$$$ add more hashes.
       */

      /* Compute ingress LB hash */
      hash_key = hm->hash_fn ((ethernet_header_t *)
			      vlib_buffer_get_current (b[0]));
      hash = (u32) clib_xxhash (hash_key);

      /* if input node did not specify next index, then packet
         should go to ethernet-input */

      if (PREDICT_TRUE (is_pow2 (vec_len (ihd0->workers))))
	index0 = hash & (vec_len (ihd0->workers) - 1);
      else
	index0 = hash % vec_len (ihd0->workers);

      ti[0] = hm->first_worker_index + ihd0->workers[index0];

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  worker_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_worker_index = ti[0];
	  t->buffer_index = vlib_get_buffer_index (vm, b[0]);
	}

      /* next */
      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, hm->frame_queue_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 WORKER_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (worker_handoff_node) = {
  .name = "worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_worker_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(worker_handoff_error_strings),
  .error_strings = worker_handoff_error_strings,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
int
interface_handoff_enable_disable (vlib_main_t * vm, u32 sw_if_index,
				  uword * bitmap, int enable_disable)
{
  handoff_main_t *hm = &handoff_main;
  vnet_sw_interface_t *sw;
  vnet_main_t *vnm = vnet_get_main ();
  per_inteface_handoff_data_t *d;
  int i, rv = 0;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (clib_bitmap_last_set (bitmap) >= hm->num_workers)
    return VNET_API_ERROR_INVALID_WORKER;

  if (hm->frame_queue_index == ~0)
    {
      vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
      hm->frame_queue_index = vlib_frame_queue_main_init (n->index, 0);
    }

  vec_validate (hm->if_data, sw_if_index);
  d = vec_elt_at_index (hm->if_data, sw_if_index);

  vec_free (d->workers);
  vec_free (d->workers_bitmap);

  if (enable_disable)
    {
      d->workers_bitmap = bitmap;
      /* *INDENT-OFF* */
      clib_bitmap_foreach (i, bitmap,
	({
	  vec_add1(d->workers, i);
	}));
      /* *INDENT-ON* */
    }

  vnet_feature_enable_disable ("device-input", "worker-handoff",
			       sw_if_index, enable_disable, 0, 0);
  return rv;
}

static clib_error_t *
set_interface_handoff_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  handoff_main_t *hm = &handoff_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
  uword *bitmap = 0;
  u32 sym = ~0;

  int rv = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "workers %U", unformat_bitmap_list, &bitmap))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else if (unformat (input, "symmetrical"))
	sym = 1;
      else if (unformat (input, "asymmetrical"))
	sym = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  if (bitmap == 0)
    return clib_error_return (0, "Please specify list of workers...");

  rv =
    interface_handoff_enable_disable (vm, sw_if_index, bitmap,
				      enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface");
      break;

    case VNET_API_ERROR_INVALID_WORKER:
      return clib_error_return (0, "Invalid worker(s)");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "unknown return value %d", rv);
    }

  if (sym == 1)
    hm->hash_fn = eth_get_sym_key;
  else if (sym == 0)
    hm->hash_fn = eth_get_key;

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_handoff_command, static) = {
  .path = "set interface handoff",
  .short_help =
  "set interface handoff <interface-name> workers <workers-list> [symmetrical|asymmetrical]",
  .function = set_interface_handoff_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
handoff_init (vlib_main_t * vm)
{
  handoff_main_t *hm = &handoff_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error;
  uword *p;

  if ((error = vlib_call_init_function (vm, threads_init)))
    return error;

  vlib_thread_registration_t *tr;
  /* Only the standard vnet worker threads are supported */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  hm->num_workers = tr->count;
	  hm->first_worker_index = tr->first_index;
	}
    }

  hm->hash_fn = eth_get_key;
  hm->frame_queue_index = ~0;

  return 0;
}

VLIB_INIT_FUNCTION (handoff_init);

#endif /* CLIB_MARCH_VARIANT */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
