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
#include <vpp/oam/oam.h>

oam_main_t oam_main;

static vlib_node_registration_t oam_node;

static void
init_oam_packet_template (oam_main_t * om, oam_target_t * t)
{
  oam_template_t *h;
  int i;
  ip_csum_t sum;
  u16 csum;

  vec_validate (t->template, 0);

  h = t->template;
  clib_memset (h, 0, sizeof (*h));

  h->ip4.src_address.as_u32 = t->src_address.as_u32;
  h->ip4.dst_address.as_u32 = t->dst_address.as_u32;
  h->ip4.ip_version_and_header_length = 0x45;
  h->ip4.length = clib_host_to_net_u16 (sizeof (*h));
  h->ip4.ttl = 64;		/* as in linux */
  h->ip4.protocol = IP_PROTOCOL_ICMP;
  h->ip4.checksum = ip4_header_checksum (&h->ip4);

  /*
   * Template has seq = 0. Each time we send one of these puppies,
   * change the sequence number and fix the execrated checksum
   */
  h->icmp.type = ICMP4_echo_request;
  h->id = clib_host_to_net_u16 (t->id);

  for (i = 0; i < ARRAY_LEN (h->data); i++)
    h->data[i] = 'A' + i;

  sum = ip_incremental_checksum (0, &h->icmp,
				 sizeof (h->icmp) + sizeof (h->id) +
				 sizeof (h->seq) + sizeof (h->data));
  csum = ~ip_csum_fold (sum);
  h->icmp.checksum = csum;
}

int
vpe_oam_add_del_target (ip4_address_t * src_address,
			ip4_address_t * dst_address, u32 fib_id, int is_add)
{
  u64 key;
  uword *p;
  oam_main_t *om = &oam_main;
  oam_target_t *t;
  ip4_main_t *im = &ip4_main;
  u32 fib_index;

  /* Make sure the FIB actually exists */
  p = hash_get (im->fib_index_by_table_id, fib_id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_FIB;

  fib_index = p[0];

  key = ((u64) fib_index << 32) | (dst_address->as_u32);
  p = hash_get (om->target_by_address_and_fib_id, key);

  if (is_add)
    {
      if (p)
	return VNET_API_ERROR_INVALID_REGISTRATION;	/* already there... */

      pool_get (om->targets, t);
      clib_memset (t, 0, sizeof (*t));
      t->src_address.as_u32 = src_address->as_u32;
      t->dst_address.as_u32 = dst_address->as_u32;
      t->fib_id = fib_id;
      t->fib_index = fib_index;
      t->state = OAM_STATE_DEAD;
      t->last_heard_time = vlib_time_now (om->vlib_main);
      t->last_heard_seq = (u16) ~ om->misses_allowed;
      t->id = (u16) random_u32 (&om->random_seed);
      t->seq = 1;
      init_oam_packet_template (om, t);
      hash_set (om->target_by_address_and_fib_id, key, t - om->targets);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;	/* no such oam target */
      t = pool_elt_at_index (om->targets, p[0]);
      vec_free (t->template);
      hash_unset (om->target_by_address_and_fib_id, key);
      pool_put (om->targets, t);
    }
  return 0;
}

static clib_error_t *
oam_add_del_target_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  int is_add = -1;
  ip4_address_t src_address;
  int src_set = 0;
  ip4_address_t dst_address;
  int dst_set = 0;
  u32 fib_id = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "src %U", unformat_ip4_address, &src_address))
	src_set = 1;
      else if (unformat (input, "dst %U", unformat_ip4_address, &dst_address))
	dst_set = 1;
      else if (unformat (input, "fib %d", &fib_id))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (is_add == -1)
    return clib_error_return (0, "missing add / del qualifier");
  if (src_set == 0)
    return clib_error_return (0, "src address not set");
  if (dst_set == 0)
    return clib_error_return (0, "dst address not set");

  (void) vpe_oam_add_del_target (&src_address, &dst_address, fib_id, is_add);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (oam_add_del_target_command, static) = {
  .path = "oam",
  .short_help = "oam [add|del] target <ip4-address> fib <fib-id>",
  .function = oam_add_del_target_command_fn,
};
/* *INDENT-ON* */

static uword
oam_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f_arg)
{
  oam_main_t *om = &oam_main;
  uword *event_data = 0;
  oam_target_t *t;
  oam_template_t *h0;
  u32 bi0;
  u16 new_seq;
  ip_csum_t sum0;
  vlib_frame_t *f;
  u32 *to_next, *from;
  u32 ip4_lookup_node_index;
  vlib_node_t *ip4_lookup_node;
  vlib_buffer_t *b0;
  static u32 *buffers;
  oam_template_copy_t *copy_src, *copy_dst;
  void send_oam_event (oam_target_t * t);
  u32 nalloc;

  /* Enqueue pkts to ip4-lookup */
  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  ip4_lookup_node_index = ip4_lookup_node->index;

  while (1)
    {
      /* Only timeout events at the moment */
      vlib_process_wait_for_event_or_clock (vm, om->interval);
      vec_reset_length (event_data);

      if (pool_elts (om->targets) == 0)
	continue;

      if (vec_len (buffers) < pool_elts (om->targets))
	vec_validate (buffers, pool_elts (om->targets) - 1);

      nalloc = vlib_buffer_alloc (vm, buffers, pool_elts (om->targets));
      if (nalloc < pool_elts (om->targets))
	{
	  vlib_buffer_free (vm, buffers, nalloc);
	  continue;
	}

      f = vlib_get_frame_to_node (vm, ip4_lookup_node_index);
      f->n_vectors = 0;
      to_next = vlib_frame_vector_args (f);
      from = buffers;

      /* *INDENT-OFF* */
      pool_foreach (t, om->targets,
      ({
        /* State transition announcement... */
        if ((t->seq - t->last_heard_seq) >= om->misses_allowed)
          {
            if (t->state == OAM_STATE_ALIVE)
              {
                if (CLIB_DEBUG > 0)
                  clib_warning ("oam target %U now DEAD",
                                format_ip4_address, &t->dst_address);
                t->state = OAM_STATE_DEAD;
                send_oam_event (t);
              }
          }
        else
          {
            if (t->state == OAM_STATE_DEAD)
              {
                if (CLIB_DEBUG > 0)
                  clib_warning ("oam target %U now ALIVE",
                                format_ip4_address, &t->dst_address);
                t->state = OAM_STATE_ALIVE;
                send_oam_event (t);
              }
          }

        /* Send a new icmp */
        t->seq++;
        new_seq = clib_host_to_net_u16 (t->seq);

        bi0 = from[0];
        from++;

        b0 = vlib_get_buffer (vm, bi0);
        vnet_buffer (b0)->sw_if_index[VLIB_RX] = 0;
        vnet_buffer (b0)->sw_if_index [VLIB_TX] = t->fib_index;

        /* Marginally faster than memcpy, probably */
        copy_dst = (oam_template_copy_t *) b0->data;
        copy_src = (oam_template_copy_t *) t->template;

        copy_dst->v8[0] = copy_src->v8[0];
        copy_dst->v8[1] = copy_src->v8[1];
        copy_dst->v8[2] = copy_src->v8[2];
        copy_dst->v8[3] = copy_src->v8[3];
        copy_dst->v4 = copy_src->v4;

        b0->current_data = 0;
        b0->current_length = sizeof (*t->template);
        h0 = vlib_buffer_get_current (b0);

        sum0 = h0->icmp.checksum;
        sum0 = ip_csum_update(sum0, 0 /* old seq */,
                              new_seq, oam_template_t, seq);
        h0->seq = new_seq;
        h0->icmp.checksum = ip_csum_fold (sum0);

        to_next[0] = bi0;
        to_next++;
        f->n_vectors++;
        if (f->n_vectors == VLIB_FRAME_SIZE)
          {
            clib_warning ("Too many OAM clients...");
            goto out;
          }
      }));
      /* *INDENT-ON* */

    out:
      vlib_put_frame_to_node (vm, ip4_lookup_node_index, f);
    }
  return 0;			/* not so much */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (oam_process_node,static) = {
  .function = oam_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "vpe-oam-process",
};
/* *INDENT-ON* */

static clib_error_t *
oam_config (vlib_main_t * vm, unformat_input_t * input)
{
  oam_main_t *om = &oam_main;
  f64 interval;
  u32 misses_allowed;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "interval %f", &interval))
	om->interval = interval;
      else if (unformat (input, "misses-allowed %d", &misses_allowed))
	om->interval = misses_allowed;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (oam_config, "oam");

static clib_error_t *
oam_init (vlib_main_t * vm)
{
  oam_main_t *om = &oam_main;

  om->vlib_main = vm;
  om->vnet_main = vnet_get_main ();
  om->interval = 2.04;
  om->misses_allowed = 3;
  om->random_seed = (u32) (vlib_time_now (vm) * 1e6);
  om->target_by_address_and_fib_id = hash_create (0, sizeof (uword));
  om->icmp_id = random_u32 (&om->random_seed);

  ip4_icmp_register_type (vm, ICMP4_echo_reply, oam_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (oam_init);

static u8 *
format_oam_target (u8 * s, va_list * args)
{
  oam_target_t *t = va_arg (*args, oam_target_t *);
  int verbose = va_arg (*args, int);

  if (t == 0)
    return format (s, "%=6s%=14s%=14s%=12s%=10s",
		   "Fib", "Src", "Dst", "Last Heard", "State");

  s = format (s, "%=6d%=14U%=14U%=12.2f%=10s",
	      t->fib_id,
	      format_ip4_address, &t->src_address,
	      format_ip4_address, &t->dst_address,
	      t->last_heard_time,
	      (t->state == OAM_STATE_ALIVE) ? "alive" : "dead");
  if (verbose)
    s = format (s, "   seq %d last_heard_seq %d", t->seq, t->last_heard_seq);

  return s;
}

static clib_error_t *
show_oam_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  oam_main_t *om = &oam_main;
  oam_target_t *t;
  int verbose = 0;

  if (unformat (input, "verbose") || unformat (input, "v"))
    verbose = 1;

  /* print header */
  vlib_cli_output (vm, "%U", format_oam_target, 0, verbose);

  /* *INDENT-OFF* */
  pool_foreach (t, om->targets,
  ({
    vlib_cli_output (vm, "%U", format_oam_target, t, verbose);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_oam_command, static) = {
  .path = "show oam",
  .short_help = "show oam",
  .function = show_oam_command_fn,
};
/* *INDENT-ON* */

typedef struct
{
  u32 target_pool_index;
  ip4_address_t address;
} oam_trace_t;

/* packet trace format function */
static u8 *
format_swap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  oam_trace_t *t = va_arg (*args, oam_trace_t *);

  s = format (s, "OAM: rx from address %U, target index %d",
	      format_ip4_address, &t->address, t->target_pool_index);
  return s;
}


#define foreach_oam_error                               \
_(PROCESSED, "vpe icmp4 oam replies processed")         \
_(DROPPED, "icmp4 replies dropped (no registration)")

typedef enum
{
#define _(sym,str) OAM_ERROR_##sym,
  foreach_oam_error
#undef _
    OAM_N_ERROR,
} oam_error_t;

static char *oam_error_strings[] = {
#define _(sym,string) string,
  foreach_oam_error
#undef _
};

/*
 * To drop a pkt and increment one of the previous counters:
 *
 * set b0->error = error_node->errors[OAM_ERROR_EXAMPLE];
 * set next0 to a disposition index bound to "error-drop".
 *
 * To manually increment the specific counter OAM_ERROR_EXAMPLE:
 *
 *  vlib_node_t *n = vlib_get_node (vm, oam.index);
 *  u32 node_counter_base_index = n->error_heap_index;
 *  vlib_error_main_t * em = &vm->error_main;
 *  em->counters[node_counter_base_index + OAM_ERROR_EXAMPLE] += 1;
 *
 */

typedef enum
{
  OAM_NEXT_DROP,
  OAM_NEXT_PUNT,
  OAM_N_NEXT,
} oam_next_t;

static uword
oam_node_fn (vlib_main_t * vm,
	     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  oam_next_t next_index;
  oam_main_t *om = &oam_main;
  u32 next0 = OAM_NEXT_DROP;	/* all pkts go to the hopper... */
  u32 next1 = OAM_NEXT_DROP;
  uword *u0, *u1;
  oam_template_t *oam0, *oam1;
  u32 fib_index0, fib_index1;
  u64 key0, key1;
  oam_target_t *t0, *t1;
  ip4_main_t *im = &ip4_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 sw_if_index0, sw_if_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
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

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  oam0 = vlib_buffer_get_current (b0);
	  oam1 = vlib_buffer_get_current (b1);
	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index0);
	  fib_index1 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index1);

	  key0 = ((u64) fib_index0 << 32) | oam0->ip4.src_address.as_u32;
	  u0 = hash_get (om->target_by_address_and_fib_id, key0);
	  if (u0)
	    {
	      t0 = pool_elt_at_index (om->targets, u0[0]);
	      t0->last_heard_time = vlib_time_now (vm);
	      t0->last_heard_seq = clib_net_to_host_u16 (oam0->seq);
	      b0->error = node->errors[OAM_ERROR_PROCESSED];
	    }
	  else
	    b0->error = node->errors[OAM_ERROR_DROPPED];

	  key1 = ((u64) fib_index1 << 32) | oam1->ip4.src_address.as_u32;
	  u1 = hash_get (om->target_by_address_and_fib_id, key1);
	  if (u1)
	    {
	      t1 = pool_elt_at_index (om->targets, u1[0]);
	      t1->last_heard_time = vlib_time_now (vm);
	      t1->last_heard_seq = clib_net_to_host_u16 (oam1->seq);
	      b1->error = node->errors[OAM_ERROR_PROCESSED];
	    }
	  else
	    b1->error = node->errors[OAM_ERROR_DROPPED];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  oam_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->target_pool_index = u0 ? u0[0] : (u32) ~ 0;
		  t->address.as_u32 = oam0->ip4.src_address.as_u32;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  oam_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->target_pool_index = u1 ? u1[0] : (u32) ~ 0;
		  t->address.as_u32 = oam1->ip4.src_address.as_u32;

		}
	    }

	  if (vm->os_punt_frame)
	    next0 = next1 = OAM_NEXT_PUNT;

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sw_if_index0;
	  vlib_buffer_t *b0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  oam0 = vlib_buffer_get_current (b0);
	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index0);

	  key0 = ((u64) fib_index0 << 32) | oam0->ip4.src_address.as_u32;
	  u0 = hash_get (om->target_by_address_and_fib_id, key0);
	  if (u0)
	    {
	      t0 = pool_elt_at_index (om->targets, u0[0]);
	      t0->last_heard_time = vlib_time_now (vm);
	      t0->last_heard_seq = clib_net_to_host_u16 (oam0->seq);
	      b0->error = node->errors[OAM_ERROR_PROCESSED];
	    }
	  else
	    b0->error = node->errors[OAM_ERROR_DROPPED];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      oam_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->target_pool_index = u0 ? u0[0] : (u32) ~ 0;
	      t->address.as_u32 = oam0->ip4.src_address.as_u32;
	    }

	  if (vm->os_punt_frame)
	    next0 = OAM_NEXT_PUNT;

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
VLIB_REGISTER_NODE (oam_node,static) = {
  .function = oam_node_fn,
  .name = "vpe-icmp4-oam",
  .vector_size = sizeof (u32),
  .format_trace = format_swap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(oam_error_strings),
  .error_strings = oam_error_strings,

  .n_next_nodes = OAM_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [OAM_NEXT_DROP] = "error-drop",
    [OAM_NEXT_PUNT] = "error-punt",
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
