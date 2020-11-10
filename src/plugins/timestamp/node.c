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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <timestamp/timestamp.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u64 stamp;
} timestamp_trace_t;

extern vlib_node_registration_t timestamp_ingress_node;
extern vlib_node_registration_t timestamp_egress_node;

/* packet trace format function */
static u8 *
format_timestamp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  timestamp_trace_t *t = va_arg (*args, timestamp_trace_t *);

  s = format (s, "TIMESTAMP: sw_if_index %d, next_index %d, sec %Lx", 
                            t->sw_if_index, t->next_index, t->stamp);
  return s;
}

#define foreach_timestamp_error \
_(INGRESS_STAMPED, "Timestamp ingress packets processed") \
_(EGRESS_STAMPED, "Timestamp egress packets processed")

typedef enum
{
#define _(sym,str) TIMESTAMP_ERROR_##sym,
  foreach_timestamp_error
#undef _
    TIMESTAMP_N_ERROR,
} timestamp_error_t;

static char *timestamp_error_strings[] = {
#define _(sym,string) string,
  foreach_timestamp_error
#undef _
};

typedef enum
{
  TIMESTAMP_NEXT_DROP,
  TIMESTAMP_NEXT_ETHERNET_INPUT,
  TIMESTAMP_N_NEXT,
} timestamp_next_t;
typedef union
{
  u64 as_u64;
  u32 as_u32[2];
} time_u64_t;
/*
 * Simple dual/single loop version, default version which will compile
 * everywhere.
 *
 * Node costs 30 clocks/pkt at a vector size of 51
 */
static uword
timestamp_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame, u8 egress)
{
  u32 n_left_from, *from, *to_next;
  timestamp_next_t next_index;
  u32 pkts_stamped = 0;
  vnet_main_t * vnm = vnet_get_main();
  vnet_interface_main_t * im = & vnm -> interface_main;
  u8 arc = im -> output_feature_arc_index;
  vnet_feature_config_main_t * fcm;

  if (egress)
    fcm = vnet_feature_get_config_main(arc);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
     // Single loop
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;
      u64 stamp;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      // Stamp
      stamp = unix_time_now_nsec();

      /* Pass the timestamp, thanks to the vnet_buffer->opaque2 unused metadata field */
      /* Set next0 to e.g. interface-tx */
      timestamp_meta_t *time_meta = (void *)  &vnet_buffer2 (b0)->unused[0];
      if (egress)
      {
        vnet_get_config_data(&fcm->config_main, &b0->current_config_index, &next0,/* # bytes of config data */0);
        // Save egress timestamp
        time_meta->timestamp_egress = stamp;
        // If we have all 3, then ioam data must be inserted
        if(time_meta->ptr_to_ioam_transit_delay && time_meta->timestamp_ingress && time_meta->timestamp_egress)
        {
          time_u64_t transit_delay;
          transit_delay.as_u64 = time_meta->timestamp_egress - time_meta->timestamp_ingress;
          // overflow
          if (transit_delay.as_u32[1])
          {
            transit_delay.as_u32[0] = 0x80000000; // overflow as per IETF
          }
          *time_meta->ptr_to_ioam_transit_delay = clib_host_to_net_u32(transit_delay.as_u32[0]);
          // Clear
          time_meta->ptr_to_ioam_transit_delay = NULL;
        }
      }
      else
      {
        next0 = TIMESTAMP_NEXT_ETHERNET_INPUT;
        time_meta->timestamp_ingress = stamp;
      }
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
            && (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        timestamp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
        t->next_index = next0;
        if(egress)
        {
          t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
          t->stamp = time_meta->timestamp_egress;
        }
        else
        {
          t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
          t->stamp = time_meta->timestamp_ingress;
        }
      }

      pkts_stamped += 1;

      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                      to_next, n_left_to_next,
                                      bi0, next0);
	  }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  if (egress)
  {
    vlib_node_increment_counter (vm, node->node_index, TIMESTAMP_ERROR_EGRESS_STAMPED, pkts_stamped);
  }
  else
  {
    vlib_node_increment_counter (vm, node->node_index, TIMESTAMP_ERROR_INGRESS_STAMPED, pkts_stamped);
  }
  return frame->n_vectors;
}
static uword
timestamp_ingress_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return timestamp_node_inline (vm, node, frame, 0); /* ingress */
}
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (timestamp_ingress_node) =
{
  .function = timestamp_ingress_node_fn,
  .name = "timestamp-ingress",
  .vector_size = sizeof (u32),
  .format_trace = format_timestamp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(timestamp_error_strings),
  .error_strings = timestamp_error_strings,

  .n_next_nodes = TIMESTAMP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [TIMESTAMP_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [TIMESTAMP_NEXT_DROP] = "error-drop", /* not used */
  },
};
static uword
timestamp_egress_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return timestamp_node_inline (vm, node, frame, 1); /* egress */
}
VLIB_REGISTER_NODE (timestamp_egress_node) =
{
  .function = timestamp_egress_node_fn,
  .name = "timestamp-egress",
  .vector_size = sizeof (u32),
  .format_trace = format_timestamp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(timestamp_error_strings),
  .error_strings = timestamp_error_strings,

  .n_next_nodes = TIMESTAMP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [TIMESTAMP_NEXT_DROP] = "error-drop", 
    [TIMESTAMP_NEXT_ETHERNET_INPUT] = "ethernet-input", /* not used */
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
