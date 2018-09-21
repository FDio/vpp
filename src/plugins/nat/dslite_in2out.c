/*
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
#include <nat/dslite.h>
#include <nat/nat_inlines.h>

vlib_node_registration_t dslite_in2out_node;
vlib_node_registration_t dslite_in2out_slowpath_node;

typedef enum
{
  DSLITE_IN2OUT_NEXT_IP4_LOOKUP,
  DSLITE_IN2OUT_NEXT_IP6_ICMP,
  DSLITE_IN2OUT_NEXT_DROP,
  DSLITE_IN2OUT_NEXT_SLOWPATH,
  DSLITE_IN2OUT_N_NEXT,
} dslite_in2out_next_t;

static char *dslite_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_dslite_error
#undef _
};

static u32
slow_path (dslite_main_t * dm, dslite_session_key_t * in2out_key,
	   dslite_session_t ** sp, u32 next, u8 * error, u32 thread_index)
{
  dslite_b4_t *b4;
  clib_bihash_kv_16_8_t b4_kv, b4_value;
  clib_bihash_kv_24_8_t in2out_kv;
  clib_bihash_kv_8_8_t out2in_kv;
  dlist_elt_t *head_elt, *oldest_elt, *elt;
  u32 oldest_index;
  dslite_session_t *s;
  snat_session_key_t out2in_key;

  out2in_key.protocol = in2out_key->proto;
  out2in_key.fib_index = 0;

  b4_kv.key[0] = in2out_key->softwire_id.as_u64[0];
  b4_kv.key[1] = in2out_key->softwire_id.as_u64[1];

  if (clib_bihash_search_16_8
      (&dm->per_thread_data[thread_index].b4_hash, &b4_kv, &b4_value))
    {
      pool_get (dm->per_thread_data[thread_index].b4s, b4);
      memset (b4, 0, sizeof (*b4));
      b4->addr.as_u64[0] = in2out_key->softwire_id.as_u64[0];
      b4->addr.as_u64[1] = in2out_key->softwire_id.as_u64[1];

      pool_get (dm->per_thread_data[thread_index].list_pool, head_elt);
      b4->sessions_per_b4_list_head_index =
	head_elt - dm->per_thread_data[thread_index].list_pool;
      clib_dlist_init (dm->per_thread_data[thread_index].list_pool,
		       b4->sessions_per_b4_list_head_index);

      b4_kv.value = b4 - dm->per_thread_data[thread_index].b4s;
      clib_bihash_add_del_16_8 (&dm->per_thread_data[thread_index].b4_hash,
				&b4_kv, 1);
    }
  else
    {
      b4 =
	pool_elt_at_index (dm->per_thread_data[thread_index].b4s,
			   b4_value.value);
    }

  //TODO configurable quota
  if (b4->nsessions >= 1000)
    {
      oldest_index =
	clib_dlist_remove_head (dm->per_thread_data[thread_index].list_pool,
				b4->sessions_per_b4_list_head_index);
      ASSERT (oldest_index != ~0);
      clib_dlist_addtail (dm->per_thread_data[thread_index].list_pool,
			  b4->sessions_per_b4_list_head_index, oldest_index);
      oldest_elt =
	pool_elt_at_index (dm->per_thread_data[thread_index].list_pool,
			   oldest_index);
      s =
	pool_elt_at_index (dm->per_thread_data[thread_index].sessions,
			   oldest_elt->value);

      in2out_kv.key[0] = s->in2out.as_u64[0];
      in2out_kv.key[1] = s->in2out.as_u64[1];
      in2out_kv.key[2] = s->in2out.as_u64[2];
      clib_bihash_add_del_24_8 (&dm->per_thread_data[thread_index].in2out,
				&in2out_kv, 0);
      out2in_kv.key = s->out2in.as_u64;
      clib_bihash_add_del_8_8 (&dm->per_thread_data[thread_index].out2in,
			       &out2in_kv, 0);
      snat_free_outside_address_and_port (dm->addr_pool, thread_index,
					  &s->out2in);

      if (snat_alloc_outside_address_and_port
	  (dm->addr_pool, 0, thread_index, &out2in_key,
	   dm->port_per_thread, thread_index))
	ASSERT (0);
    }
  else
    {
      if (snat_alloc_outside_address_and_port
	  (dm->addr_pool, 0, thread_index, &out2in_key,
	   dm->port_per_thread, thread_index))
	{
	  *error = DSLITE_ERROR_OUT_OF_PORTS;
	  return DSLITE_IN2OUT_NEXT_DROP;
	}
      pool_get (dm->per_thread_data[thread_index].sessions, s);
      memset (s, 0, sizeof (*s));
      b4->nsessions++;

      pool_get (dm->per_thread_data[thread_index].list_pool, elt);
      clib_dlist_init (dm->per_thread_data[thread_index].list_pool,
		       elt - dm->per_thread_data[thread_index].list_pool);
      elt->value = s - dm->per_thread_data[thread_index].sessions;
      s->per_b4_index = elt - dm->per_thread_data[thread_index].list_pool;
      s->per_b4_list_head_index = b4->sessions_per_b4_list_head_index;
      clib_dlist_addtail (dm->per_thread_data[thread_index].list_pool,
			  s->per_b4_list_head_index,
			  elt - dm->per_thread_data[thread_index].list_pool);
    }

  s->in2out = *in2out_key;
  s->out2in = out2in_key;
  *sp = s;
  in2out_kv.key[0] = s->in2out.as_u64[0];
  in2out_kv.key[1] = s->in2out.as_u64[1];
  in2out_kv.key[2] = s->in2out.as_u64[2];
  in2out_kv.value = s - dm->per_thread_data[thread_index].sessions;
  clib_bihash_add_del_24_8 (&dm->per_thread_data[thread_index].in2out,
			    &in2out_kv, 1);
  out2in_kv.key = s->out2in.as_u64;
  out2in_kv.value = s - dm->per_thread_data[thread_index].sessions;
  clib_bihash_add_del_8_8 (&dm->per_thread_data[thread_index].out2in,
			   &out2in_kv, 1);

  return next;
}

static inline u32
dslite_icmp_in2out (dslite_main_t * dm, ip6_header_t * ip6,
		    ip4_header_t * ip4, dslite_session_t ** sp, u32 next,
		    u8 * error, u32 thread_index)
{
  dslite_session_t *s = 0;
  icmp46_header_t *icmp = ip4_next_header (ip4);
  clib_bihash_kv_24_8_t kv, value;
  dslite_session_key_t key;
  u32 n = next;
  icmp_echo_header_t *echo;
  u32 new_addr, old_addr;
  u16 old_id, new_id;
  ip_csum_t sum;

  if (icmp_is_error_message (icmp))
    {
      n = DSLITE_IN2OUT_NEXT_DROP;
      *error = DSLITE_ERROR_BAD_ICMP_TYPE;
      goto done;
    }

  echo = (icmp_echo_header_t *) (icmp + 1);

  key.addr = ip4->src_address;
  key.port = echo->identifier;
  key.proto = SNAT_PROTOCOL_ICMP;
  key.softwire_id.as_u64[0] = ip6->src_address.as_u64[0];
  key.softwire_id.as_u64[1] = ip6->src_address.as_u64[1];
  key.pad = 0;
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  kv.key[2] = key.as_u64[2];

  if (clib_bihash_search_24_8
      (&dm->per_thread_data[thread_index].in2out, &kv, &value))
    {
      n = slow_path (dm, &key, &s, next, error, thread_index);
      if (PREDICT_FALSE (next == DSLITE_IN2OUT_NEXT_DROP))
	goto done;
    }
  else
    {
      s =
	pool_elt_at_index (dm->per_thread_data[thread_index].sessions,
			   value.value);
    }

  old_addr = ip4->src_address.as_u32;
  ip4->src_address = s->out2in.addr;
  new_addr = ip4->src_address.as_u32;
  sum = ip4->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address);
  ip4->checksum = ip_csum_fold (sum);

  old_id = echo->identifier;
  echo->identifier = new_id = s->out2in.port;
  sum = icmp->checksum;
  sum = ip_csum_update (sum, old_id, new_id, icmp_echo_header_t, identifier);
  icmp->checksum = ip_csum_fold (sum);

done:
  *sp = s;
  return n;
}

static inline uword
dslite_in2out_node_fn_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame, u8 is_slow_path)
{
  u32 n_left_from, *from, *to_next;
  dslite_in2out_next_t next_index;
  u32 node_index;
  vlib_node_runtime_t *error_node;
  u32 thread_index = vm->thread_index;
  f64 now = vlib_time_now (vm);
  dslite_main_t *dm = &dslite_main;

  node_index =
    is_slow_path ? dslite_in2out_slowpath_node.
    index : dslite_in2out_node.index;

  error_node = vlib_node_get_runtime (vm, node_index);

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
	  u32 next0 = DSLITE_IN2OUT_NEXT_IP4_LOOKUP;
	  ip4_header_t *ip40;
	  ip6_header_t *ip60;
	  u8 error0 = DSLITE_ERROR_IN2OUT;
	  u32 proto0;
	  dslite_session_t *s0 = 0;
	  clib_bihash_kv_24_8_t kv0, value0;
	  dslite_session_key_t key0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  ip_csum_t sum0;
	  u32 new_addr0, old_addr0;
	  u16 old_port0, new_port0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip60 = vlib_buffer_get_current (b0);

	  if (PREDICT_FALSE (ip60->protocol != IP_PROTOCOL_IP_IN_IP))
	    {
	      if (ip60->protocol == IP_PROTOCOL_ICMP6)
		{
		  next0 = DSLITE_IN2OUT_NEXT_IP6_ICMP;
		  goto trace0;
		}
	      error0 = DSLITE_ERROR_BAD_IP6_PROTOCOL;
	      next0 = DSLITE_IN2OUT_NEXT_DROP;
	      goto trace0;
	    }

	  ip40 = vlib_buffer_get_current (b0) + sizeof (ip6_header_t);
	  proto0 = ip_proto_to_snat_proto (ip40->protocol);

	  if (PREDICT_FALSE (proto0 == ~0))
	    {
	      error0 = DSLITE_ERROR_UNSUPPORTED_PROTOCOL;
	      next0 = DSLITE_IN2OUT_NEXT_DROP;
	      goto trace0;
	    }

	  udp0 = ip4_next_header (ip40);
	  tcp0 = (tcp_header_t *) udp0;

	  if (is_slow_path)
	    {
	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 =
		    dslite_icmp_in2out (dm, ip60, ip40, &s0, next0, &error0,
					thread_index);
		  if (PREDICT_FALSE (next0 == DSLITE_IN2OUT_NEXT_DROP))
		    goto trace0;

		  goto accounting0;
		}
	    }
	  else
	    {
	      if (PREDICT_FALSE (proto0 == SNAT_PROTOCOL_ICMP))
		{
		  next0 = DSLITE_IN2OUT_NEXT_SLOWPATH;
		  goto trace0;
		}
	    }

	  key0.addr = ip40->src_address;
	  key0.port = udp0->src_port;
	  key0.proto = proto0;
	  key0.softwire_id.as_u64[0] = ip60->src_address.as_u64[0];
	  key0.softwire_id.as_u64[1] = ip60->src_address.as_u64[1];
	  key0.pad = 0;
	  kv0.key[0] = key0.as_u64[0];
	  kv0.key[1] = key0.as_u64[1];
	  kv0.key[2] = key0.as_u64[2];

	  if (clib_bihash_search_24_8
	      (&dm->per_thread_data[thread_index].in2out, &kv0, &value0))
	    {
	      if (is_slow_path)
		{
		  next0 =
		    slow_path (dm, &key0, &s0, next0, &error0, thread_index);
		  if (PREDICT_FALSE (next0 == DSLITE_IN2OUT_NEXT_DROP))
		    goto trace0;
		}
	      else
		{
		  next0 = DSLITE_IN2OUT_NEXT_SLOWPATH;
		  goto trace0;
		}
	    }
	  else
	    {
	      s0 =
		pool_elt_at_index (dm->per_thread_data[thread_index].sessions,
				   value0.value);
	    }

	  old_addr0 = ip40->src_address.as_u32;
	  ip40->src_address = s0->out2in.addr;
	  new_addr0 = ip40->src_address.as_u32;
	  sum0 = ip40->checksum;
	  sum0 =
	    ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
			    src_address);
	  ip40->checksum = ip_csum_fold (sum0);
	  if (PREDICT_TRUE (proto0 == SNAT_PROTOCOL_TCP))
	    {
	      old_port0 = tcp0->src_port;
	      tcp0->src_port = s0->out2in.port;
	      new_port0 = tcp0->src_port;

	      sum0 = tcp0->checksum;
	      sum0 =
		ip_csum_update (sum0, old_addr0, new_addr0, ip4_header_t,
				dst_address);
	      sum0 =
		ip_csum_update (sum0, old_port0, new_port0, ip4_header_t,
				length);
	      mss_clamping (&snat_main, tcp0, &sum0);
	      tcp0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      old_port0 = udp0->src_port;
	      udp0->src_port = s0->out2in.port;
	      udp0->checksum = 0;
	    }

	accounting0:
	  /* Accounting */
	  s0->last_heard = now;
	  s0->total_pkts++;
	  s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);
	  /* Per-B4 LRU list maintenance */
	  clib_dlist_remove (dm->per_thread_data[thread_index].list_pool,
			     s0->per_b4_index);
	  clib_dlist_addtail (dm->per_thread_data[thread_index].list_pool,
			      s0->per_b4_list_head_index, s0->per_b4_index);

	  ip40->tos =
	    (clib_net_to_host_u32
	     (ip60->ip_version_traffic_class_and_flow_label) & 0x0ff00000) >>
	    20;
	  vlib_buffer_advance (b0, sizeof (ip6_header_t));

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      dslite_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->session_index = ~0;
	      if (s0)
		t->session_index =
		  s0 - dm->per_thread_data[thread_index].sessions;
	    }

	  b0->error = error_node->errors[error0];

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
dslite_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  return dslite_in2out_node_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dslite_in2out_node) = {
  .function = dslite_in2out_node_fn,
  .name = "dslite-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_dslite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dslite_in2out_error_strings),
  .error_strings = dslite_in2out_error_strings,
  .n_next_nodes = DSLITE_IN2OUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [DSLITE_IN2OUT_NEXT_DROP] = "error-drop",
    [DSLITE_IN2OUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [DSLITE_IN2OUT_NEXT_IP6_ICMP] = "ip6-icmp-input",
    [DSLITE_IN2OUT_NEXT_SLOWPATH] = "dslite-in2out-slowpath",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (dslite_in2out_node, dslite_in2out_node_fn);

static uword
dslite_in2out_slowpath_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return dslite_in2out_node_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dslite_in2out_slowpath_node) = {
  .function = dslite_in2out_slowpath_node_fn,
  .name = "dslite-in2out-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_dslite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dslite_in2out_error_strings),
  .error_strings = dslite_in2out_error_strings,
  .n_next_nodes = DSLITE_IN2OUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [DSLITE_IN2OUT_NEXT_DROP] = "error-drop",
    [DSLITE_IN2OUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [DSLITE_IN2OUT_NEXT_IP6_ICMP] = "ip6-lookup",
    [DSLITE_IN2OUT_NEXT_SLOWPATH] = "dslite-in2out-slowpath",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (dslite_in2out_slowpath_node,
			      dslite_in2out_slowpath_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
