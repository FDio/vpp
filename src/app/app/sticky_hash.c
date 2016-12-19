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
#include <vnet/l2/l2_classify.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/error.h>

typedef struct
{
  u32 fwd_entry_index;
  u32 rev_entry_index;
  /* Not strictly needed, for show command */
  u32 fib_index;
} sticky_hash_session_t;

typedef struct
{
  u32 cached_next_index;

  /* next index added to l2_classify */
  u32 fwd_miss_next_index;

  /* session pool */
  sticky_hash_session_t *sessions;

  /* Forward and reverse data session setup buffers */
  u8 fdata[3 * sizeof (u32x4)];
  u8 rdata[3 * sizeof (u32x4)];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vnet_classify_main_t *vnet_classify_main;
  l2_input_classify_main_t *l2_input_classify_main;
}
sticky_hash_main_t;

typedef struct
{
  /* $$$$ fill in with per-pkt trace data */
  u32 next_index;
  u32 sw_if_index;
} sticky_hash_miss_trace_t;

/* packet trace format function */
static u8 *
format_sticky_hash_miss_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sticky_hash_miss_trace_t *t = va_arg (*args, sticky_hash_miss_trace_t *);

  s = format (s, "STICKY_HASH_MISS: sw_if_index %d", t->sw_if_index);
  return s;
}

typedef CLIB_PACKED (struct
		     {
		     ethernet_header_t eh; ip4_header_t ip;
		     }) classify_data_or_mask_t;

sticky_hash_main_t sticky_hash_main;

vlib_node_registration_t sticky_hash_miss_node;

#define foreach_sticky_hash_miss_error \
_(MISSES, "forward flow classify misses")

typedef enum
{
#define _(sym,str) STICKY_HASH_MISS_ERROR_##sym,
  foreach_sticky_hash_miss_error
#undef _
    STICKY_HASH_MISS_N_ERROR,
} sticky_hash_miss_error_t;

static char *sticky_hash_miss_error_strings[] = {
#define _(sym,string) string,
  foreach_sticky_hash_miss_error
#undef _
};

/*
 * To drop a pkt and increment one of the previous counters:
 *
 * set b0->error = error_node->errors[STICKY_HASH_MISS_ERROR_EXAMPLE];
 * set next0 to a disposition index bound to "error-drop".
 *
 * To manually increment the specific counter STICKY_HASH_MISS_ERROR_EXAMPLE:
 *
 *  vlib_node_t *n = vlib_get_node (vm, sticky_hash_miss.index);
 *  u32 node_counter_base_index = n->error_heap_index;
 *  vlib_error_main_t * em = &vm->error_main;
 *  em->counters[node_counter_base_index + STICKY_HASH_MISS_ERROR_EXAMPLE] += 1;
 *
 */

typedef enum
{
  STICKY_HASH_MISS_NEXT_IP4_INPUT,
  STICKY_HASH_MISS_N_NEXT,
} sticky_hash_miss_next_t;

static uword
sticky_hash_miss_node_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  sticky_hash_miss_next_t next_index;
  sticky_hash_main_t *mp = &sticky_hash_main;
  vlib_node_t *n = vlib_get_node (vm, sticky_hash_miss_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  vnet_classify_main_t *cm = mp->vnet_classify_main;
  ip4_main_t *im = &ip4_main;

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
	  u32 sw_if_index0;
	  u32 fib_index0, ft_index0, rt_index0;
	  vnet_classify_table_3_t *ft0, *rt0;
	  vnet_classify_entry_3_t *fe0, *re0;
	  classify_data_or_mask_t *h0;
	  u8 was_found0;
	  ip4_fib_t *fib0;
	  sticky_hash_session_t *s;
	  u32 tmp;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  next0 = mp->cached_next_index;

	  h0 = vlib_buffer_get_current (b0);

	  /* Add forward and reverse entries for this flow */
	  clib_memcpy (mp->fdata, h0, sizeof (mp->fdata));
	  clib_memcpy (mp->rdata, h0, sizeof (mp->rdata));

	  h0 = (classify_data_or_mask_t *) (mp->rdata);

	  /* swap src + dst addresses to form reverse data */
	  tmp = h0->ip.src_address.as_u32;
	  h0->ip.src_address.as_u32 = h0->ip.dst_address.as_u32;
	  h0->ip.dst_address.as_u32 = tmp;

	  /* dig up fwd + rev tables */
	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index0);
	  fib0 = vec_elt_at_index (im->fibs, fib_index0);

	  ft_index0 = fib0->fwd_classify_table_index;
	  rt_index0 = fib0->rev_classify_table_index;

	  ft0 = (vnet_classify_table_3_t *)
	    pool_elt_at_index (cm->tables, ft_index0);
	  rt0 = (vnet_classify_table_3_t *)
	    pool_elt_at_index (cm->tables, rt_index0);

	  fe0 =
	    vnet_classify_find_or_add_entry_3 (ft0, mp->fdata, &was_found0);
	  fe0->next_index = L2_INPUT_CLASSIFY_NEXT_IP4_INPUT;
	  fe0->advance = sizeof (ethernet_header_t);

	  re0 = vnet_classify_find_or_add_entry_3 (rt0, mp->rdata, 0);
	  re0->next_index = L2_INPUT_CLASSIFY_NEXT_IP4_INPUT;	/* $$$ FIXME */
	  re0->advance = sizeof (ethernet_header_t);

	  /* Note: we could get a whole vector of misses for the same sess */
	  if (was_found0 == 0)
	    {
	      pool_get (mp->sessions, s);

	      fe0->opaque_index = s - mp->sessions;
	      re0->opaque_index = s - mp->sessions;

	      s->fwd_entry_index = fe0 - ft0->entries;
	      s->rev_entry_index = re0 - rt0->entries;
	      s->fib_index = fib_index0;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      sticky_hash_miss_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }

	  em->counters[node_counter_base_index +
		       STICKY_HASH_MISS_ERROR_MISSES] += 1;

	  vlib_buffer_advance (b0, sizeof (ethernet_header_t));

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (sticky_hash_miss_node) = {
  .function = sticky_hash_miss_node_fn,
  .name = "sticky-hash-miss",
  .vector_size = sizeof (u32),
  .format_trace = format_sticky_hash_miss_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(sticky_hash_miss_error_strings),
  .error_strings = sticky_hash_miss_error_strings,

  .n_next_nodes = STICKY_HASH_MISS_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [STICKY_HASH_MISS_NEXT_IP4_INPUT] = "ip4-input",
  },
};
/* *INDENT-ON* */

clib_error_t *
sticky_hash_miss_init (vlib_main_t * vm)
{
  sticky_hash_main_t *mp = &sticky_hash_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();
  mp->vnet_classify_main = &vnet_classify_main;
  mp->l2_input_classify_main = &l2_input_classify_main;

  return 0;
}

VLIB_INIT_FUNCTION (sticky_hash_miss_init);

static int ip4_sticky_hash_enable_disable
  (sticky_hash_main_t * mp,
   u32 fwd_sw_if_index, u8 * fwd_mask,
   u32 rev_sw_if_index, u8 * rev_mask, u32 nbuckets, int enable_disable)
{
  ip4_main_t *im = &ip4_main;
  u32 fib_index;
  ip4_fib_t *fib;
  vnet_classify_main_t *cm = mp->vnet_classify_main;
  l2_input_classify_main_t *l2cm = mp->l2_input_classify_main;
  vnet_classify_table_3_t *ft, *rt;

  fib_index = vec_elt (im->fib_index_by_sw_if_index, fwd_sw_if_index);
  fib = vec_elt_at_index (im->fibs, fib_index);

  if (fib->fwd_classify_table_index == ~0)
    {
      /* Set up forward table */
      ft = (vnet_classify_table_3_t *)
	vnet_classify_new_table (cm, fwd_mask, nbuckets,
				 0 /* skip */ , 3 /* match */ );
      fib->fwd_classify_table_index
	= ft - (vnet_classify_table_3_t *) cm->tables;
      mp->fwd_miss_next_index =
	vlib_node_add_next (mp->vlib_main, l2_input_classify_node.index,
			    sticky_hash_miss_node.index);
      ft->miss_next_index = mp->fwd_miss_next_index;

      /* Set up reverse table */
      rt = (vnet_classify_table_3_t *)
	vnet_classify_new_table (cm, rev_mask, nbuckets,
				 0 /* skip */ , 3 /* match */ );
      fib->rev_classify_table_index
	= rt - (vnet_classify_table_3_t *) cm->tables;
    }

  vec_validate
    (l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP4],
     fwd_sw_if_index);

  vec_validate
    (l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP6],
     fwd_sw_if_index);

  vec_validate
    (l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_OTHER],
     fwd_sw_if_index);

  l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP4]
    [fwd_sw_if_index] = fib->fwd_classify_table_index;

  l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP6]
    [fwd_sw_if_index] = ~0;

  l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_OTHER]
    [fwd_sw_if_index] = ~0;


  vec_validate
    (l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP4],
     rev_sw_if_index);

  vec_validate
    (l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP6],
     rev_sw_if_index);

  vec_validate
    (l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_OTHER],
     rev_sw_if_index);


  l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP4]
    [rev_sw_if_index] = fib->rev_classify_table_index;

  l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_IP6]
    [rev_sw_if_index] = ~0;

  l2cm->classify_table_index_by_sw_if_index[L2_INPUT_CLASSIFY_TABLE_OTHER]
    [rev_sw_if_index] = ~0;

  vnet_l2_input_classify_enable_disable (fwd_sw_if_index, enable_disable);
  vnet_l2_input_classify_enable_disable (rev_sw_if_index, enable_disable);
  return 0;
}

static clib_error_t *
ip4_sticky_hash_init_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  u32 fwd_sw_if_index = ~0, rev_sw_if_index = ~0;
  int enable_disable = 1;
  u32 nbuckets = 2;
  int rv;
  sticky_hash_main_t *mp = &sticky_hash_main;
  classify_data_or_mask_t fwd_mask, rev_mask;
  u8 *fm = 0, *rm = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "fwd %U", unformat_vnet_sw_interface, mp->vnet_main,
	   &fwd_sw_if_index))
	;
      if (unformat
	  (input, "rev %U", unformat_vnet_sw_interface, mp->vnet_main,
	   &rev_sw_if_index))
	;
      else if (unformat (input, "nbuckets %d", &nbuckets))
	;
      else if (unformat (input, "disable"))
	enable_disable = 0;

      else
	break;
    }

  nbuckets = 1 << max_log2 (nbuckets);

  if (fwd_sw_if_index == ~0)
    return clib_error_return (0, "fwd interface not set");

  if (rev_sw_if_index == ~0)
    return clib_error_return (0, "rev interface not set");

  if (!is_pow2 (nbuckets))
    return clib_error_return (0, "nbuckets %d not a power of 2", nbuckets);

  ASSERT (sizeof (fwd_mask) <= 3 * sizeof (u32x4));

  /* Mask on src/dst address, depending on direction */
  memset (&fwd_mask, 0, sizeof (fwd_mask));
  memset (&fwd_mask.ip.src_address, 0xff, 4);

  memset (&rev_mask, 0, sizeof (rev_mask));
  memset (&rev_mask.ip.dst_address, 0xff, 4);

  vec_validate (fm, 3 * sizeof (u32x4) - 1);
  vec_validate (rm, 3 * sizeof (u32x4) - 1);

  clib_memcpy (fm, &fwd_mask, sizeof (fwd_mask));
  clib_memcpy (rm, &rev_mask, sizeof (rev_mask));

  rv = ip4_sticky_hash_enable_disable (mp, fwd_sw_if_index, fm,
				       rev_sw_if_index, rm,
				       nbuckets, enable_disable);

  vec_free (fm);
  vec_free (rm);
  switch (rv)
    {
    case 0:
      return 0;

    default:
      return clib_error_return (0,
				"ip4_sticky_hash_enable_disable returned %d",
				rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (sticky_hash_init_command, static) = {
  .path = "ip sticky classify",
  .short_help = "ip sticky classify fwd <intfc> rev <intfc> "
  "[nbuckets <nn>][disable]",
  .function = ip4_sticky_hash_init_command_fn,
};
/* *INDENT-ON* */


u8 *
format_sticky_hash_session (u8 * s, va_list * args)
{
  sticky_hash_main_t *mp = va_arg (*args, sticky_hash_main_t *);
  sticky_hash_session_t *session = va_arg (*args, sticky_hash_session_t *);
  vnet_classify_table_3_t *t;
  vnet_classify_entry_3_t *e;
  ip4_main_t *im = &ip4_main;
  vnet_classify_main_t *cm = mp->vnet_classify_main;
  ip4_fib_t *fib;
  classify_data_or_mask_t *match;

  fib = vec_elt_at_index (im->fibs, session->fib_index);

  t = (vnet_classify_table_3_t *)
    pool_elt_at_index (cm->tables, fib->fwd_classify_table_index);
  e = pool_elt_at_index (t->entries, session->fwd_entry_index);
  match = (classify_data_or_mask_t *) (e->key);

  s = format
    (s,
     "[%6d] fwd src %U next index %d session %d fib %d\n"
     "         hits %lld last-heard %.6f\n",
     e - t->entries,
     format_ip4_address, &match->ip.src_address,
     e->next_index, e->opaque_index, fib->table_id, e->hits, e->last_heard);

  if (e->opaque_index != session - mp->sessions)
    s = format (s, "WARNING: forward session index mismatch!\n");

  t = (vnet_classify_table_3_t *)
    pool_elt_at_index (cm->tables, fib->rev_classify_table_index);
  e = pool_elt_at_index (t->entries, session->rev_entry_index);
  match = (classify_data_or_mask_t *) (e->key);

  s = format
    (s,
     "[%6d] rev dst %U next index %d session %d\n"
     "         hits %lld last-heard %.6f\n",
     e - t->entries,
     format_ip4_address, &match->ip.dst_address,
     e->next_index, e->opaque_index, e->hits, e->last_heard);

  if (e->opaque_index != session - mp->sessions)
    s = format (s, "WARNING: reverse session index mismatch!\n");
  s = format (s, "---------\n");

  return s;
}

static clib_error_t *
show_ip4_sticky_hash_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  sticky_hash_main_t *mp = &sticky_hash_main;
  sticky_hash_session_t *s;
  int verbose = 0;
  int dump_classifier_tables = 0;
  ip4_fib_t *fib;
  ip4_main_t *im4 = &ip4_main;
  vnet_classify_main_t *cm = mp->vnet_classify_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "dump-tables")
	       || unformat (input, "dump-classifier-tables"))
	dump_classifier_tables = 1;
      else
	break;
    }

  if (pool_elts (mp->sessions) == 0)
    vlib_cli_output (vm, "No ip sticky hash sessions");


  vlib_cli_output (vm, "%d active sessions\n", pool_elts (mp->sessions));

  vec_foreach (fib, im4->fibs)
  {
    if (fib->fwd_classify_table_index != ~0)
      vlib_cli_output (vm, "fib %d fwd table: \n%U",
		       fib->table_id,
		       format_classify_table,
		       cm,
		       pool_elt_at_index
		       (cm->tables, fib->fwd_classify_table_index),
		       dump_classifier_tables);
    if (fib->rev_classify_table_index != ~0)
      vlib_cli_output (vm, "fib %d rev table: \n%U",
		       fib->table_id,
		       format_classify_table,
		       cm,
		       pool_elt_at_index
		       (cm->tables, fib->rev_classify_table_index),
		       dump_classifier_tables);
  }

  if (verbose)
    {
      /* *INDENT-OFF* */
      pool_foreach (s, mp->sessions,
      ({
        vlib_cli_output (vm, "%U", format_sticky_hash_session, mp, s);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_sticky_hash_command, static) = {
  .path = "show sticky classify",
  .short_help = "Display sticky classifier tables",
  .function = show_ip4_sticky_hash_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
