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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <ioam/export/ioam_export.h>

typedef struct
{
  u32 next_index;
  u32 flow_label;
} export_trace_t;

/* packet trace format function */
static u8 *
format_export_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  export_trace_t *t = va_arg (*args, export_trace_t *);

  s = format (s, "EXPORT: flow_label %d, next index %d",
	      t->flow_label, t->next_index);
  return s;
}

vlib_node_registration_t export_node;

#define foreach_export_error \
_(RECORDED, "Packets recorded for export")

typedef enum
{
#define _(sym,str) EXPORT_ERROR_##sym,
  foreach_export_error
#undef _
    EXPORT_N_ERROR,
} export_error_t;

static char *export_error_strings[] = {
#define _(sym,string) string,
  foreach_export_error
#undef _
};

typedef enum
{
  EXPORT_NEXT_POP_HBYH,
  EXPORT_N_NEXT,
} export_next_t;

always_inline void
copy3cachelines (void *dst, const void *src, size_t n)
{
#if 0
  if (PREDICT_FALSE (n < DEFAULT_EXPORT_SIZE))
    {
      /* Copy only the first 1/2 cache lines whatever is available */
      if (n >= 64)
	clib_mov64 ((u8 *) dst, (const u8 *) src);
      if (n >= 128)
	clib_mov64 ((u8 *) dst + 64, (const u8 *) src + 64);
      return;
    }
  clib_mov64 ((u8 *) dst, (const u8 *) src);
  clib_mov64 ((u8 *) dst + 64, (const u8 *) src + 64);
  clib_mov64 ((u8 *) dst + 128, (const u8 *) src + 128);
#endif
#if 1

  u64 *copy_dst, *copy_src;
  int i;
  copy_dst = (u64 *) dst;
  copy_src = (u64 *) src;
  if (PREDICT_FALSE (n < DEFAULT_EXPORT_SIZE))
    {
      for (i = 0; i < n / 64; i++)
	{
	  copy_dst[0] = copy_src[0];
	  copy_dst[1] = copy_src[1];
	  copy_dst[2] = copy_src[2];
	  copy_dst[3] = copy_src[3];
	  copy_dst[4] = copy_src[4];
	  copy_dst[5] = copy_src[5];
	  copy_dst[6] = copy_src[6];
	  copy_dst[7] = copy_src[7];
	  copy_dst += 8;
	  copy_src += 8;
	}
      return;
    }
  for (i = 0; i < 3; i++)
    {
      copy_dst[0] = copy_src[0];
      copy_dst[1] = copy_src[1];
      copy_dst[2] = copy_src[2];
      copy_dst[3] = copy_src[3];
      copy_dst[4] = copy_src[4];
      copy_dst[5] = copy_src[5];
      copy_dst[6] = copy_src[6];
      copy_dst[7] = copy_src[7];
      copy_dst += 8;
      copy_src += 8;
    }
#endif
}

static uword
ip6_export_node_fn (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ioam_export_main_t *em = &ioam_export_main;
  u32 n_left_from, *from, *to_next;
  export_next_t next_index;
  u32 pkts_recorded = 0;
  ioam_export_buffer_t *my_buf = 0;
  vlib_buffer_t *eb0 = 0;
  u32 ebi0 = 0;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (__sync_lock_test_and_set (em->lockp[vm->cpu_index], 1))
    ;
  my_buf = ioam_export_get_my_buffer (vm->cpu_index);
  my_buf->touched_at = vlib_time_now (vm);
  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = EXPORT_NEXT_POP_HBYH;
	  u32 next1 = EXPORT_NEXT_POP_HBYH;
	  u32 bi0, bi1;
	  ip6_header_t *ip60, *ip61;
	  vlib_buffer_t *p0, *p1;
	  u32 ip_len0, ip_len1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    /* IPv6 + HbyH header + Trace option */
	    /* 40   +           2 + [4 hdr] + [16]* no_of_nodes */
	    /* 3 cache lines can get v6 hdr + trace option with upto 9 node trace */
	    CLIB_PREFETCH (p2->data, 3 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 3 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  /* speculatively enqueue p0 and p1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, bi0);
	  p1 = vlib_get_buffer (vm, bi1);

	  ip60 = vlib_buffer_get_current (p0);
	  ip61 = vlib_buffer_get_current (p1);

	  ip_len0 =
	    clib_net_to_host_u16 (ip60->payload_length) +
	    sizeof (ip6_header_t);
	  ip_len1 =
	    clib_net_to_host_u16 (ip61->payload_length) +
	    sizeof (ip6_header_t);

	  ebi0 = my_buf->buffer_index;
	  eb0 = vlib_get_buffer (vm, ebi0);
	  if (PREDICT_FALSE (eb0 == 0))
	    goto NO_BUFFER1;

	  ip_len0 =
	    ip_len0 > DEFAULT_EXPORT_SIZE ? DEFAULT_EXPORT_SIZE : ip_len0;
	  ip_len1 =
	    ip_len1 > DEFAULT_EXPORT_SIZE ? DEFAULT_EXPORT_SIZE : ip_len1;

	  copy3cachelines (eb0->data + eb0->current_length, ip60, ip_len0);
	  eb0->current_length += DEFAULT_EXPORT_SIZE;
	  /* To maintain uniform size per export, each
	   * record is default size, ip6 hdr can be
	   * used to parse the record correctly
	   */
	  my_buf->records_in_this_buffer++;
	  /* if number of buf exceeds max that fits in a MTU sized buffer
	   * ship it to the queue and pick new one
	   */
	  if (my_buf->records_in_this_buffer >= DEFAULT_EXPORT_RECORDS)
	    {
	      ioam_export_send_buffer (vm, my_buf);
	      ioam_export_init_buffer (vm, my_buf);
	    }

	  ebi0 = my_buf->buffer_index;
	  eb0 = vlib_get_buffer (vm, ebi0);
	  if (PREDICT_FALSE (eb0 == 0))
	    goto NO_BUFFER1;

	  copy3cachelines (eb0->data + eb0->current_length, ip61, ip_len1);
	  eb0->current_length += DEFAULT_EXPORT_SIZE;
	  my_buf->records_in_this_buffer++;
	  if (my_buf->records_in_this_buffer >= DEFAULT_EXPORT_RECORDS)
	    {
	      ioam_export_send_buffer (vm, my_buf);
	      ioam_export_init_buffer (vm, my_buf);
	    }

	  pkts_recorded += 2;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (p0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  export_trace_t *t =
		    vlib_add_trace (vm, node, p0, sizeof (*t));
		  t->flow_label =
		    clib_net_to_host_u32 (ip60->
					  ip_version_traffic_class_and_flow_label);
		  t->next_index = next0;
		}
	      if (p1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  export_trace_t *t =
		    vlib_add_trace (vm, node, p1, sizeof (*t));
		  t->flow_label =
		    clib_net_to_host_u32 (ip61->
					  ip_version_traffic_class_and_flow_label);
		  t->next_index = next1;
		}
	    }
	NO_BUFFER1:
	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *p0;
	  u32 next0 = EXPORT_NEXT_POP_HBYH;
	  ip6_header_t *ip60;
	  u32 ip_len0;

	  /* speculatively enqueue p0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip60 = vlib_buffer_get_current (p0);
	  ip_len0 =
	    clib_net_to_host_u16 (ip60->payload_length) +
	    sizeof (ip6_header_t);

	  ebi0 = my_buf->buffer_index;
	  eb0 = vlib_get_buffer (vm, ebi0);
	  if (PREDICT_FALSE (eb0 == 0))
	    goto NO_BUFFER;

	  ip_len0 =
	    ip_len0 > DEFAULT_EXPORT_SIZE ? DEFAULT_EXPORT_SIZE : ip_len0;
	  copy3cachelines (eb0->data + eb0->current_length, ip60, ip_len0);
	  eb0->current_length += DEFAULT_EXPORT_SIZE;
	  /* To maintain uniform size per export, each
	   * record is default size, ip6 hdr can be
	   * used to parse the record correctly
	   */
	  my_buf->records_in_this_buffer++;
	  /* if number of buf exceeds max that fits in a MTU sized buffer
	   * ship it to the queue and pick new one
	   */
	  if (my_buf->records_in_this_buffer >= DEFAULT_EXPORT_RECORDS)
	    {
	      ioam_export_send_buffer (vm, my_buf);
	      ioam_export_init_buffer (vm, my_buf);
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (p0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      export_trace_t *t = vlib_add_trace (vm, node, p0, sizeof (*t));
	      t->flow_label =
		clib_net_to_host_u32 (ip60->
				      ip_version_traffic_class_and_flow_label);
	      t->next_index = next0;
	    }

	  pkts_recorded += 1;
	NO_BUFFER:
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, export_node.index,
			       EXPORT_ERROR_RECORDED, pkts_recorded);
  *em->lockp[vm->cpu_index] = 0;
  return frame->n_vectors;
}

/*
 * Node for IP6 export
 */
VLIB_REGISTER_NODE (export_node) =
{
  .function = ip6_export_node_fn,
  .name = "ip6-export",
  .vector_size = sizeof (u32),
  .format_trace = format_export_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (export_error_strings),
  .error_strings = export_error_strings,
  .n_next_nodes = EXPORT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [EXPORT_NEXT_POP_HBYH] = "ip6-pop-hop-by-hop"
  },
};
