/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vppinfra/error.h>
#include <mactime/mactime.h>

typedef struct
{
  u32 next_index;
  u32 device_index;
  u8 src_mac[6];
  u8 device_name[64];
} mactime_trace_t;

vlib_node_registration_t mactime_node;
vlib_node_registration_t mactime_tx_node;

#define foreach_mactime_error                   \
_(DROP, "Dropped packets")                      \
_(OK, "Permitted packets")

typedef enum
{
#define _(sym,str) MACTIME_ERROR_##sym,
  foreach_mactime_error
#undef _
    MACTIME_N_ERROR,
} mactime_error_t;

static char *mactime_error_strings[] = {
#define _(sym,string) string,
  foreach_mactime_error
#undef _
};

typedef enum
{
  MACTIME_NEXT_DROP,
  MACTIME_NEXT_ETHERNET_INPUT,
  MACTIME_N_NEXT,
} mactime_next_t;

/* packet trace format function */
static u8 *
format_mactime_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mactime_trace_t *t = va_arg (*args, mactime_trace_t *);

  s = format (s, "MACTIME: src mac %U device %s result %s\n",
	      format_mac_address, t->src_mac,
	      (t->device_index != ~0) ? t->device_name : (u8 *) "unknown",
	      t->next_index == MACTIME_NEXT_DROP ? "drop" : "pass");
  return s;
}

static uword
mactime_node_inline (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame,
		     int is_tx)
{
  u32 n_left_from, *from, *to_next;
  mactime_next_t next_index;
  mactime_main_t *mm = &mactime_main;
  mactime_device_t *dp;
  clib_bihash_kv_8_8_t kv;
  clib_bihash_8_8_t *lut = &mm->lookup_table;
  u32 packets_ok = 0, packets_dropped = 0;
  f64 now;
  u32 thread_index = vm->thread_index;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  u8 arc = im->output_feature_arc_index;
  vnet_feature_config_main_t *fcm;

  if (is_tx)
    fcm = vnet_feature_get_config_main (arc);

  now = clib_timebase_now (&mm->timebase);

  if (PREDICT_FALSE ((now - mm->sunday_midnight) > 86400.0 * 7.0))
    mm->sunday_midnight = clib_timebase_find_sunday_midnight (now);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 device_index0;
	  u32 len0;
	  ethernet_header_t *en0;
	  int i;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Set next0 to e.g. interface-tx */
	  if (is_tx)
	    vnet_get_config_data (&fcm->config_main,
				  &b0->current_config_index, &next0,
				  /* # bytes of config data */ 0);
	  else
	    next0 = MACTIME_NEXT_ETHERNET_INPUT;

	  vlib_buffer_advance (b0, -(word) vnet_buffer (b0)->l2_hdr_offset);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  en0 = vlib_buffer_get_current (b0);
	  kv.key = 0;
	  if (is_tx)
	    _clib_memcpy (&kv.key, en0->dst_address, 6);
	  else
	    _clib_memcpy (&kv.key, en0->src_address, 6);

	  /* Lookup the src/dst mac address */
	  if (clib_bihash_search_8_8 (lut, &kv, &kv) < 0)
	    {
	      /* Create a table entry... */
	      mactime_send_create_entry_message
		(is_tx ? en0->dst_address : en0->src_address);

	      /* and let this packet pass */
	      device_index0 = ~0;
	      dp = 0;
	      packets_ok++;
	      goto trace0;
	    }
	  else
	    device_index0 = kv.value;

	  dp = pool_elt_at_index (mm->devices, device_index0);

	  /* Static drop / allow? */
	  if (PREDICT_FALSE
	      (dp->flags &
	       (MACTIME_DEVICE_FLAG_STATIC_DROP
		| MACTIME_DEVICE_FLAG_STATIC_ALLOW)))
	    {
	      if (dp->flags & MACTIME_DEVICE_FLAG_STATIC_DROP)
		{
		  next0 = MACTIME_NEXT_DROP;
		  vlib_increment_combined_counter
		    (&mm->drop_counters, thread_index, dp - mm->devices, 1,
		     len0);
		  packets_dropped++;
		}
	      else		/* note next0 set to allow */
		{
		  vlib_increment_combined_counter
		    (&mm->allow_counters, thread_index, dp - mm->devices, 1,
		     len0);
		  packets_ok++;
		}
	      goto trace0;
	    }

	  /* Known device, see if traffic allowed at the moment */
	  for (i = 0; i < vec_len (dp->ranges); i++)
	    {
	      clib_timebase_range_t *r = dp->ranges + i;
	      f64 start0, end0;

	      start0 = r->start + mm->sunday_midnight;
	      end0 = r->end + mm->sunday_midnight;
	      /* Packet within time range */
	      if (now >= start0 && now <= end0)
		{
		  /* And it's a drop range, drop it */
		  if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_DROP)
		    {
		      vlib_increment_combined_counter
			(&mm->drop_counters, thread_index,
			 dp - mm->devices, 1, len0);
		      packets_dropped++;
		      next0 = MACTIME_NEXT_DROP;
		    }
		  else		/* it's an allow range, allow it */
		    {
		      vlib_increment_combined_counter
			(&mm->allow_counters, thread_index,
			 dp - mm->devices, 1, len0);
		      packets_ok++;
		    }
		  goto trace0;
		}
	    }
	  /*
	   * Didn't hit a range, so *drop* if allow configured, or
	   * *allow* if drop configured.
	   */
	  if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
	    {
	      next0 = MACTIME_NEXT_DROP;
	      vlib_increment_combined_counter
		(&mm->drop_counters, thread_index, dp - mm->devices, 1, len0);
	      packets_dropped++;
	    }
	  else
	    {
	      vlib_increment_combined_counter
		(&mm->allow_counters, thread_index, dp - mm->devices, 1,
		 len0);
	      packets_ok++;
	    }

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      mactime_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      _clib_memcpy (t->src_mac, en0->src_address,
			    sizeof (t->src_mac));

	      t->next_index = next0;
	      t->device_index = device_index0;

	      if (dp)
		{
		  _clib_memcpy (t->device_name, dp->device_name,
				ARRAY_LEN (t->device_name));
		  t->device_name[ARRAY_LEN (t->device_name) - 1] = 0;
		}
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       MACTIME_ERROR_DROP, packets_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       MACTIME_ERROR_OK, packets_ok);
  return frame->n_vectors;
}

static uword
mactime_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return mactime_node_inline (vm, node, frame, 0 /* is_tx */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mactime_node) =
{
  .function = mactime_node_fn,
  .name = "mactime",
  .vector_size = sizeof (u32),
  .format_trace = format_mactime_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(mactime_error_strings),
  .error_strings = mactime_error_strings,

  .n_next_nodes = MACTIME_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes =
  {
    [MACTIME_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [MACTIME_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

static uword
mactime_tx_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return mactime_node_inline (vm, node, frame, 1 /* is_tx */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mactime_tx_node) =
{
  .function = mactime_tx_node_fn,
  .name = "mactime-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_mactime_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(mactime_error_strings),
  .error_strings = mactime_error_strings,

  .n_next_nodes = MACTIME_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes =
  {
    [MACTIME_NEXT_DROP] = "error-drop",
    [MACTIME_NEXT_ETHERNET_INPUT] = "ethernet-input", /* notused */
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
