
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

typedef struct {
  u32 sw_if_index;
  u32 next_worker_index;
} handoff_trace_t;

/* packet trace format function */
static u8 * format_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  handoff_trace_t * t = va_arg (*args, handoff_trace_t *);

  s = format (s, "handoff: sw_if_index %d, next worker index %d",
              t->sw_if_index, t->next_worker_index);
  return s;
}

vlib_node_registration_t handoff_node;

static uword
worker_handoff_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame)
{
  vlib_thread_main_t * tm = vlib_get_thread_main();
  u32 n_left_from, * from;
  static vlib_frame_queue_elt_t ** handoff_queue_elt_by_worker_index;
  static vlib_frame_queue_t ** congested_handoff_queue_by_worker_index = 0;
  vlib_frame_queue_elt_t * hf = 0;
  int i;
  u32 n_left_to_next_worker = 0, * to_next_worker = 0;
  u32 next_worker_index = 0;
  u32 current_worker_index = ~0;
  static int num_workers_set;
  static u32 num_workers;
  static u32 first_worker_index;

  if (PREDICT_FALSE(num_workers_set == 0))
    {
      uword * p;
      vlib_thread_registration_t * tr;
      /* Only the standard vnet worker threads are supported */
      p = hash_get_mem (tm->thread_registrations_by_name, "workers");
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
        {
          num_workers = tr->count;
          first_worker_index = tr->first_index;
        }
      num_workers_set = 1;
    }

  if (PREDICT_FALSE(handoff_queue_elt_by_worker_index == 0))
    {
      vec_validate (handoff_queue_elt_by_worker_index, tm->n_vlib_mains - 1);

      vec_validate_init_empty (congested_handoff_queue_by_worker_index,
                               first_worker_index + num_workers - 1,
                               (vlib_frame_queue_t *)(~0));
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      u32 sw_if_index0;
      u32 hash;
      u64 hash_key;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

      next_worker_index = first_worker_index;

      /*
       * Force unknown traffic onto worker 0,
       * and into ethernet-input. $$$$ add more hashes.
       */

      /* Compute ingress LB hash */
      hash_key = eth_get_key ((ethernet_header_t *) b0->data);
      hash = (u32) clib_xxhash (hash_key);

      if (PREDICT_FALSE (b0->flags & BUFFER_HANDOFF_NEXT_VALID == 0))
        vnet_buffer(b0)->io_handoff.next_index = HANDOFF_DISPATCH_NEXT_ETHERNET_INPUT;

      if (PREDICT_TRUE (is_pow2 (num_workers)))
	next_worker_index += hash & (num_workers - 1);
      else
	next_worker_index += hash % num_workers;

      if (next_worker_index != current_worker_index)
	{
	  if (hf)
	    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

	  hf = dpdk_get_handoff_queue_elt(next_worker_index,
					  handoff_queue_elt_by_worker_index);

	  n_left_to_next_worker = VLIB_FRAME_SIZE - hf->n_vectors;
	  to_next_worker = &hf->buffer_index[hf->n_vectors];
	  current_worker_index = next_worker_index;
	}

      /* enqueue to correct worker thread */
      to_next_worker[0] = bi0;
      to_next_worker++;
      n_left_to_next_worker--;

      if (n_left_to_next_worker == 0)
	{
	  hf->n_vectors = VLIB_FRAME_SIZE;
	  vlib_put_handoff_queue_elt(hf);
	  current_worker_index = ~0;
	  handoff_queue_elt_by_worker_index[next_worker_index] = 0;
	  hf = 0;
	}

      if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
			&& (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  handoff_trace_t *t =
	     vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_worker_index = next_worker_index;
	}

    }

  if (hf)
    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

  /* Ship frames to the worker nodes */
  for (i = 0; i < vec_len (handoff_queue_elt_by_worker_index); i++)
    {
      if (handoff_queue_elt_by_worker_index[i])
        {
          hf = handoff_queue_elt_by_worker_index[i];
          /*
           * It works better to let the handoff node
           * rate-adapt, always ship the handoff queue element.
           */
          if (1 || hf->n_vectors == hf->last_n_vectors)
            {
              vlib_put_handoff_queue_elt(hf);
              handoff_queue_elt_by_worker_index[i] = 0;
            }
          else
            hf->last_n_vectors = hf->n_vectors;
        }
      congested_handoff_queue_by_worker_index[i] = (vlib_frame_queue_t *)(~0);
    }
  hf = 0;
  current_worker_index = ~0;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (handoff_node) = {
  .function = worker_handoff_node_fn,
  .name = "worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 1,
  .next_nodes = {
        [0] = "error-drop",
  },
};

int interface_handoff_enable_disable (vlib_main_t * vm, u32 sw_if_index,
                                      int enable_disable)
{
  vnet_sw_interface_t * sw;
  vnet_main_t * vnm = vnet_get_main();
  int rv;
  u32 node_index = enable_disable ? handoff_node.index : ~0;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface (vnm, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  rv = vnet_hw_interface_rx_redirect_to_node (vnm, sw_if_index, node_index);
  return rv;
}

static clib_error_t *
set_interface_handoff_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       vnet_get_main(), &sw_if_index))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = interface_handoff_enable_disable (vm, sw_if_index, enable_disable);

  switch(rv) {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0, "Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "unknown return value %d", rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (set_interface_handoff_command, static) = {
    .path = "set interface handoff",
    .short_help =
    "set interface handoff <interface-name>",
    .function = set_interface_handoff_command_fn,
};

typedef struct {
  u32 cached_next_index;

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} handoff_dispatch_main_t;

typedef struct {
  u32 buffer_index;
  u32 next_index;
  u32 sw_if_index;
} handoff_dispatch_trace_t;

/* packet trace format function */
static u8 * format_handoff_dispatch_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  handoff_dispatch_trace_t * t = va_arg (*args, handoff_dispatch_trace_t *);

  s = format (s, "HANDOFF_DISPATCH: sw_if_index %d next_index %d buffer 0x%x",
      t->sw_if_index,
      t->next_index,
      t->buffer_index);
  return s;
}

handoff_dispatch_main_t handoff_dispatch_main;

vlib_node_registration_t handoff_dispatch_node;

#define foreach_handoff_dispatch_error \
_(EXAMPLE, "example packets")

typedef enum {
#define _(sym,str) HANDOFF_DISPATCH_ERROR_##sym,
  foreach_handoff_dispatch_error
#undef _
  HANDOFF_DISPATCH_N_ERROR,
} handoff_dispatch_error_t;

static char * handoff_dispatch_error_strings[] = {
#define _(sym,string) string,
  foreach_handoff_dispatch_error
#undef _
};

static uword
handoff_dispatch_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  handoff_dispatch_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	  }

          /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          next0 = vnet_buffer(b0)->io_handoff.next_index;
          next1 = vnet_buffer(b1)->io_handoff.next_index;

          if (PREDICT_FALSE(vm->trace_main.trace_active_hint))
            {
            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
              {
                vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0);
                handoff_dispatch_trace_t *t =
                  vlib_add_trace (vm, node, b0, sizeof (*t));
                sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                t->buffer_index = bi0;
              }
            if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
              {
                vlib_trace_buffer (vm, node, next1, b1, /* follow_chain */ 0);
                handoff_dispatch_trace_t *t =
                  vlib_add_trace (vm, node, b1, sizeof (*t));
                sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
                t->sw_if_index = sw_if_index1;
                t->next_index = next1;
                t->buffer_index = bi1;
              }
            }

          /* verify speculative enqueues, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0;
	  vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;

          /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          next0 = vnet_buffer(b0)->io_handoff.next_index;

          if (PREDICT_FALSE(vm->trace_main.trace_active_hint))
            {
            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
              {
                vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0);
                handoff_dispatch_trace_t *t =
                  vlib_add_trace (vm, node, b0, sizeof (*t));
                sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                t->buffer_index = bi0;
              }
            }

          /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (handoff_dispatch_node) = {
  .function = handoff_dispatch_node_fn,
  .name = "handoff-dispatch",
  .vector_size = sizeof (u32),
  .format_trace = format_handoff_dispatch_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_IS_HANDOFF,

  .n_errors = ARRAY_LEN(handoff_dispatch_error_strings),
  .error_strings = handoff_dispatch_error_strings,

  .n_next_nodes = HANDOFF_DISPATCH_N_NEXT,

  .next_nodes = {
        [HANDOFF_DISPATCH_NEXT_DROP] = "error-drop",
        [HANDOFF_DISPATCH_NEXT_ETHERNET_INPUT] = "ethernet-input",
        [HANDOFF_DISPATCH_NEXT_IP4_INPUT] = "ip4-input",
        [HANDOFF_DISPATCH_NEXT_IP6_INPUT] = "ip6-input",
        [HANDOFF_DISPATCH_NEXT_MPLS_INPUT] = "mpls-gre-input",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (handoff_dispatch_node, handoff_dispatch_node_fn)

clib_error_t *handoff_dispatch_init (vlib_main_t *vm)
{
  handoff_dispatch_main_t * mp = &handoff_dispatch_main;

  mp->vlib_main = vm;
  mp->vnet_main = &vnet_main;

  return 0;
}

VLIB_INIT_FUNCTION (handoff_dispatch_init);
