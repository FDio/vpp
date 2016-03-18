;;; tunnel-decap-skel.el - tunnel decapsulation skeleton

(require 'skeleton)

(define-skeleton skel-tunnel-decap
"Insert a tunnel decap implementation"
nil
'(setq encap_stack (skeleton-read "encap_stack (e.g ip4_udp_lisp): "))
'(setq ENCAP_STACK (upcase encap_stack))
'(setq encap-stack (replace-regexp-in-string "_" "-" encap_stack))
'(setq ENCAP-STACK (upcase encap-stack))
"
#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/" encap-stack "/" encap_stack ".h>

typedef struct {
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  " encap_stack "_header_t h;
} " encap_stack "_rx_trace_t;

static u8 * format_" encap_stack "_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  " encap_stack "_rx_trace_t * t = va_arg (*args, " encap_stack "_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, \"" ENCAP-STACK ": tunnel %d next %d error %d\", 
                  t->tunnel_index, t->next_index, t->error);
    }
  else
    {
      s = format (s, \"" ENCAP-STACK ": no tunnel next %d error %d\\n\", 
                  t->next_index, t->error);
    }
  s = format (s, \"\\n  %U\", format_" encap_stack "_header_with_length, &t->h, 
              (u32) sizeof (t->h) /* max size */);
  return s;
}

static uword
" encap_stack "_input (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  " encap_stack "_main_t * ngm = &" encap_stack "_main;
  u32 last_tunnel_index = ~0;
  " encap_stack "_tunnel_key_t last_key;
  u32 pkts_decapsulated = 0;

  memset (&last_key, 0xff, sizeof (last_key));

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0 /* $$$ dual loop when the single loop works */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  nsh_unicast_header_t * h0, * h1;
          u32 label0, label1;
	  u32 next0, next1;
	  uword * p0, * p1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          h0 = vlib_buffer_get_current (b0);
          h1 = vlib_buffer_get_current (b1);
          
          next0 = next1 = " ENCAP_STACK "_INPUT_NEXT_IP4_INPUT;

          label0 = clib_net_to_host_u32 (h0->label_exp_s_ttl);
          label1 = clib_net_to_host_u32 (h1->label_exp_s_ttl);

	  /* 
	   * Translate label contents into a fib index.
	   * This is a decent sanity check, and guarantees
	   * a sane FIB for the downstream lookup
	   */
          label0 = vnet_nsh_uc_get_label (label0);
          label1 = vnet_nsh_uc_get_label (label1);

          /* If 2xlabels match, and match the 1-wide cache, use it */
          if (label0 == label1 && rt->last_label == label0)
            {
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = rt->last_fib_index;
              vnet_buffer(b1)->sw_if_index[VLIB_TX] = rt->last_fib_index;
            }
          else
            {
              p0 = hash_get (rt->mm->fib_index_by_nsh_label, label0);
              if (PREDICT_FALSE (p0 == 0))
                {
                  next0 = " ENCAP_STACK "_INPUT_NEXT_DROP;
                  b0->error = node->errors[NSH_ERROR_BAD_LABEL];
                }
              else
                vnet_buffer(b0)->sw_if_index[VLIB_TX] = p0[0];
              
              p1 = hash_get (rt->mm->fib_index_by_nsh_label, label1);
              if (PREDICT_FALSE (p1 == 0))
                {
                  next1 = " ENCAP_STACK "_INPUT_NEXT_DROP;
                  b1->error = node->errors[NSH_ERROR_BAD_LABEL];
                }
              else
                {
                  vnet_buffer(b1)->sw_if_index[VLIB_TX] = p1[0];
                  rt->last_fib_index = p1[0];
                  rt->last_label = label1;
                }
            }

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              nsh_rx_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b0, sizeof (*tr));
              tr->label_exp_s_ttl = label0;
            }
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              nsh_rx_trace_t *tr = vlib_add_trace (vm, node, 
                                                   b1, sizeof (*tr));
              tr->label_exp_s_ttl = label1;
            }

          vlib_buffer_advance (b0, sizeof (*h0));
          vlib_buffer_advance (b1, sizeof (*h1));

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
#endif 
    
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0;
          " encap_stack "_header_t * iuX0;
	  uword * p0;
          u32 tunnel_index0;
          " encap_stack "_tunnel_t * t0;
          " encap_stack "_tunnel_key_t key0;
          u32 error0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* 
           * udp leaves current_data pointing at the tunnel header
           * $$$$ FIXME
           */
          vlib_buffer_advance 
            (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));

          iuX0 = vlib_buffer_get_current (b0);

          /* pop (ip, udp, lisp-gpe) */
          vlib_buffer_advance (b0, sizeof (*iuX0));

          tunnel_index0 = ~0;
          error0 = 0;
          next0 = " ENCAP_STACK "_INPUT_NEXT_DROP;

          key0.src = iuX0->ip4.src_address.as_u32;
          key0.iid = iuX0->lisp.iid;

          /* $$$ validate key comparison */
          if (PREDICT_FALSE ((key0.as_u64[0] != last_key.as_u64[0])))
            {
              p0 = hash_get_mem (ngm->" encap_stack "_tunnel_by_key, &key0);

              if (p0 == 0)
                {
                  error0 = " ENCAP_STACK "_ERROR_NO_SUCH_TUNNEL;
                  goto trace0;
                }

              last_key.as_u64[0] = key0.as_u64[0];
              tunnel_index0 = last_tunnel_index = p0[0];
            }
          else
            tunnel_index0 = last_tunnel_index;

          t0 = pool_elt_at_index (ngm->tunnels, tunnel_index0);

          next0 = t0->decap_next_index;

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          vnet_update_l2_len (b0);

          /* 
           * ip[46] lookup in the configured FIB
           * " encap-stack ", here's the encap tunnel sw_if_index
           */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->decap_fib_index;
          pkts_decapsulated ++;

        trace0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              " encap_stack "_rx_trace_t *tr 
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->h = iuX0->lisp;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, " encap_stack "_input_node.index,
                               " ENCAP_STACK "_ERROR_DECAPSULATED, 
                               pkts_decapsulated);
  return from_frame->n_vectors;
}

static char * " encap_stack "_error_strings[] = {
#define " encap_stack "_error(n,s) s,
#include <vnet/" encap-stack "/" encap_stack "_error.def>
#undef " encap_stack "_error
#undef _
};

VLIB_REGISTER_NODE (" encap_stack "_input_node) = {
  .function = \"" encap_stack "_input\",
  .name = \"" encap-stack "-input\",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = " ENCAP_STACK "_N_ERROR,
  .error_strings = " encap_stack "_error_strings,

  .n_next_nodes = " ENCAP_STACK "_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [" ENCAP_STACK "_INPUT_NEXT_##s] = n,
    foreach_" encap_stack "_input_next
#undef _
  },

  .format_buffer = format_" encap_stack "_header_with_length,
  .format_trace = format_" encap_stack "_rx_trace,
  // $$$$ .unformat_buffer = unformat_" encap_stack "_header,
};

")
