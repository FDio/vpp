/*
 * node.c - ipfix probe graph node
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/ip/ip4_packet.h>
#include <vnet/feature/feature.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>

#include <flowhandoff/flowhandoff.h>

#define TSCMARKS 0
#if TSCMARKS > 0
#include "/home/damarion/cisco/vpp-sandbox/include/tscmarks.h"
#define TM(x) if (vm->thread_index == 1) tsc_mark(x)
#define TP(x) if (vm->thread_index == 1) tsc_print(3,x)
#else
#define TM(x)
#define TP(x)
#endif

/* No counters at the moment */
#define foreach_flowhandoff_error			\
  _(HIT, "hit")						\
  _(ADD, "add")						\
  _(LOCAL, "enqueued local")				\
  _(REMOTE, "enqueued remote")				\
  _(CON_DROP, "congestion drop")

typedef enum
{
#define _(sym,str) FLOWPROBE_ERROR_##sym,
  foreach_flowhandoff_error
#undef _
    FLOWHANDOFF_N_ERROR,
} flowhandoff_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *flowhandoff_error_strings[] = {
#define _(sym,string) string,
  foreach_flowhandoff_error
#undef _
};
#endif

typedef enum
{
  FLOWHANDOFF_NEXT_DROP,
  FLOWHANDOFF_NEXT_IP4_LOOKUP,
  FLOWHANDOFF_N_NEXT,
} flowhandoff_next_t;

#define FLOWHANDOFF_NEXT_NODES {				\
    [FLOWHANDOFF_NEXT_DROP] = "error-drop",			\
    [FLOWHANDOFF_NEXT_IP4_LOOKUP] = "ip4-lookup",		\
}


typedef struct
{
  union
  {
    clib_bihash_kv_16_8_t kv;
    u8x16 as_u8x16;
  } __clib_packed;
  u64 hash;
} __clib_packed fh_hash_entry_t;

STATIC_ASSERT_SIZEOF (fh_hash_entry_t, 32);
STATIC_ASSERT_OFFSET_OF (fh_hash_entry_t, as_u8x16, 0);
STATIC_ASSERT_OFFSET_OF (fh_hash_entry_t, kv.key, 0);

static_always_inline void
calc_key (ip4_header_t * ip, fh_hash_entry_t * e)
{
  tcp_header_t *t = (tcp_header_t *) (ip + 1);
  u64 sa, da, sp, dp, pr;

  sa = ip->src_address.as_u32;
  da = ip->dst_address.as_u32;
  sp = t->src_port;
  dp = t->dst_port;
  pr = ip->protocol;

  e->kv.key[0] = sa << 32 | da;
  e->kv.key[1] = sp << 32 | dp << 16 | pr;
}

static_always_inline void
reverse_key (clib_bihash_kv_16_8_t * k, clib_bihash_kv_16_8_t * r)
{
  u64 sa, da, sp, dp, pr;
  da = k->key[0] & 0xffffffff;
  sa = k->key[0] >> 32;
  pr = k->key[1] & 0xff;
  dp = (k->key[1] >> 16) & 0xffff;
  sp = (k->key[1] >> 32) & 0xffff;
  r->key[0] = da << 32 | sa;
  r->key[1] = dp << 32 | sp << 16 | pr;
}

static uword
flowhandoff_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame,
		     int is_ip4)
{
  flowhandoff_main_t *fm = &flowhandoff_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u32 n_left = frame->n_vectors;
  u32 *from;
  fh_hash_entry_t entries[VLIB_FRAME_SIZE], *e;
  clib_bihash_kv_16_8_t rkv;

  TM ("vlib_get_buffers");

  from = vlib_frame_vector_args (frame);

  vlib_get_buffers (vm, from, bufs, n_left);

  b = bufs;
  next = nexts;
  e = entries;

  TM ("calc key and hash");
  while (n_left > 3)
    {
      if (PREDICT_TRUE (n_left >= 12))
	{
	  vlib_buffer_t **pb = b + 8;
	  CLIB_PREFETCH (pb[0]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (pb[1]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (pb[2]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (pb[3]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      calc_key (vlib_buffer_get_current (b[0]), e + 0);
      e[0].hash = clib_bihash_hash_16_8 (&e[0].kv);
      calc_key (vlib_buffer_get_current (b[1]), e + 1);
      e[1].hash = clib_bihash_hash_16_8 (&e[1].kv);
      calc_key (vlib_buffer_get_current (b[2]), e + 2);
      e[2].hash = clib_bihash_hash_16_8 (&e[2].kv);
      calc_key (vlib_buffer_get_current (b[3]), e + 3);
      e[3].hash = clib_bihash_hash_16_8 (&e[3].kv);

      /* next */
      b += 4;
      e += 4;
      next += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      calc_key (vlib_buffer_get_current (b[0]), e + 0);
      e[0].hash = clib_bihash_hash_16_8 (&e[0].kv);

      /* next */
      b += 1;
      e += 1;
      next += 1;
      n_left -= 1;
    }

  u16 hit_count = 0;
  u16 n_added = 0;
  n_left = frame->n_vectors;
  e = entries;
  u32 *bi = from;

  TM ("search and add");

  while (n_left)
    {
      if (PREDICT_TRUE (n_left >= 16))
	clib_bihash_prefetch_bucket_16_8 (&fm->table4, e[15].hash);

      if (PREDICT_TRUE (n_left >= 8))
	clib_bihash_prefetch_data_16_8 (&fm->table4, e[7].hash);

      if (clib_bihash_search_inline_with_hash_16_8 (&fm->table4,
						    e[0].hash, &e[0].kv))
	{
	  /* we don't add more than 16 entries per vector */
	  if (n_added < 16)
	    {
	      e[0].kv.value = vm->thread_index;
	      reverse_key (&e[0].kv, &rkv);
	      rkv.value = vm->thread_index;
	      clib_bihash_add_del_16_8 (&fm->table4, &e[0].kv, 1);
	      clib_bihash_add_del_16_8 (&fm->table4, &rkv, 1);
	      n_added++;
	    }
	  to_local[n_local] = bi[0];
	  n_local++;
	}
      else
	{

	  if (e[0].kv.value == vm->thread_index)
	    {
	      /* known flow which belongs to this thread */
	      to_local[n_local] = bi[0];
	      n_local++;
	    }
	  else
	    {
	      /* known flow which belongs to remote thread */
	      to_remote[n_remote] = bi[0];
	      thread_indices[n_remote] = e[0].kv.value;
	      n_remote++;
	    }
	  hit_count++;
	}
      n_left -= 1;
      e += 1;
      bi++;
    }


  TM ("enqueue local");
  /* unqueue local to ip4-lookup */
  clib_memset_u16 (nexts, FLOWHANDOFF_NEXT_IP4_LOOKUP, n_local);
  vlib_buffer_enqueue_to_next (vm, node, to_local, nexts, n_local);

  TM ("enqueue remote");
  /* handover buffers to remote node */
  u32 n_remote_enq;
  n_remote_enq = vlib_buffer_enqueue_to_thread (vm, fm->frame_queue_index,
						to_remote, thread_indices,
						n_remote, 1);

  TM ("counters");
  vlib_node_increment_counter (vm, node->node_index, FLOWPROBE_ERROR_HIT,
			       hit_count);
  vlib_node_increment_counter (vm, node->node_index, FLOWPROBE_ERROR_ADD,
			       n_added);
  vlib_node_increment_counter (vm, node->node_index, FLOWPROBE_ERROR_LOCAL,
			       n_local);
  vlib_node_increment_counter (vm, node->node_index, FLOWPROBE_ERROR_REMOTE,
			       n_remote_enq);
  vlib_node_increment_counter (vm, node->node_index, FLOWPROBE_ERROR_CON_DROP,
			       n_remote - n_remote_enq);
  TM (0);
  TP (frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (flowhandoff_ip4_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return flowhandoff_node_fn (vm, node, frame, 1);
}


#ifndef CLIB_MARCH_VARIANT
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowhandoff_ip4_node) = {
  .name = "flowhandoff4-input",
  .vector_size = sizeof (u32),
//  .format_trace = format_flowhandoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowhandoff_error_strings),
  .error_strings = flowhandoff_error_strings,
  .n_next_nodes = FLOWHANDOFF_N_NEXT,
  .next_nodes = FLOWHANDOFF_NEXT_NODES,
};
/* *INDENT-ON* */
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
