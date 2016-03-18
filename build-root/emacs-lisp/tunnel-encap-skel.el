;;; tunnel-encap-skel.el - tunnel interface output skeleton

(require 'skeleton)

(define-skeleton skel-tunnel-encap
"Insert a tunnel encap implementation"
nil
'(setq encap_stack (skeleton-read "encap_stack (e.g ip4_udp_lisp): "))
'(setq ENCAP_STACK (upcase encap_stack))
'(setq encap-stack (replace-regexp-in-string "_" "-" encap_stack))
'(setq ENCAP-STACK (upcase encap-stack))
"
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/" encap-stack "/" encap_stack ".h>

/* Statistics (not really errors) */
#define foreach_" encap_stack "_encap_error    \\
_(ENCAPSULATED, \"good packets encapsulated\")

static char * " encap_stack "_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_" encap_stack "_encap_error
#undef _
};

typedef enum {
#define _(sym,str) " ENCAP_STACK "_ENCAP_ERROR_##sym,
    foreach_" encap_stack "_encap_error
#undef _
    " ENCAP_STACK "_ENCAP_N_ERROR,
} " encap_stack "_encap_error_t;

typedef enum {
    " ENCAP_STACK "_ENCAP_NEXT_IP4_LOOKUP,
    " ENCAP_STACK "_ENCAP_NEXT_DROP,
    " ENCAP_STACK "_ENCAP_N_NEXT,
} " encap_stack "_encap_next_t;

typedef struct {
  u32 tunnel_index;
} " encap_stack "_encap_trace_t;

u8 * format_" encap_stack "_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  " encap_stack "_encap_trace_t * t 
      = va_arg (*args, " encap_stack "_encap_trace_t *);

  s = format (s, \"" ENCAP-STACK ": tunnel %d\", t->tunnel_index);
  return s;
}

/* $$$$ FIXME adjust to match the rewrite string */
#define foreach_fixed_header_offset             \\
_(0) _(1) _(2) _(3) _(FIXME)

static uword
" encap_stack "_encap (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  " encap_stack "_main_t * ngm = &" encap_stack "_main;
  vnet_main_t * vnm = ngm->vnet_main;
  u32 pkts_encapsulated = 0;
  u16 old_l0 = 0, old_l1 = 0;

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
          
          next0 = next1 = " ENCAP_STACK "_ENCAP_NEXT_IP4_LOOKUP;

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
	  u32 next0 = " ENCAP_STACK "_ENCAP_NEXT_IP4_LOOKUP;
          vnet_hw_interface_t * hi0;
          ip4_header_t * ip0;
          udp_header_t * udp0;
          u64 * copy_src0, * copy_dst0;
          u32 * copy_src_last0, * copy_dst_last0;
          " encap_stack "_tunnel_t * t0;
          u16 new_l0;
          ip_csum_t sum0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* 1-wide cache? */
          hi0 = vnet_get_sup_hw_interface 
            (vnm, vnet_buffer(b0)->sw_if_index[VLIB_TX]);

          t0 = pool_elt_at_index (ngm->tunnels, hi0->dev_instance);

          ASSERT(vec_len(t0->rewrite) >= 24);

          /* Apply the rewrite string. $$$$ vnet_rewrite? */
          vlib_buffer_advance (b0, -(word)_vec_len(t0->rewrite));

          ip0 = vlib_buffer_get_current(b0);
          /* Copy the fixed header */
          copy_dst0 = (u64 *) ip0;
          copy_src0 = (u64 *) t0->rewrite;

          ASSERT (sizeof (ip4_udp_" encap_stack "_header_t) == FIXME);

          /* Copy first N octets 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
          foreach_fixed_header_offset;
#undef _
#if 0 /* needed if encap not a multiple of 8 bytes */
          /* Last 4 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u32 *)(&copy_dst0[FIXME]);
          copy_src_last0 = (u32 *)(&copy_src0[FIXME]);
          copy_dst_last0[0] = copy_src_last0[0];

#endif
          /* fix the <bleep>ing outer-IP checksum */
          sum0 = ip0->checksum;
          /* old_l0 always 0, see the rewrite setup */
          new_l0 = 
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
          
          sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
                                 length /* changed member */);
          ip0->checksum = ip_csum_fold (sum0);
          ip0->length = new_l0;
          
          /* Fix UDP length */
          udp0 = (udp_header_t *)(ip0+1);
          new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
                                         - sizeof (*ip0));
          
          udp0->length = new_l0;

          /* Reset to look up tunnel partner in the configured FIB */
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_fib_index;
          pkts_encapsulated ++;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              " encap_stack "_encap_trace_t *tr = 
                vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->tunnel_index = t0 - ngm->tunnels;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, 
                               " ENCAP_STACK "_ENCAP_ERROR_ENCAPSULATED, 
                               pkts_encapsulated);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (" encap_stack "_encap_node) = {
  .function = " encap_stack "_encap,
  .name = \"" encap-stack "-encap\",
  .vector_size = sizeof (u32),
  .format_trace = format_" encap_stack "_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(" encap_stack "_encap_error_strings),
  .error_strings = " encap_stack "_encap_error_strings,

  .n_next_nodes = " ENCAP_STACK "_ENCAP_N_NEXT,

  .next_nodes = {
        [" ENCAP_STACK "_ENCAP_NEXT_IP4_LOOKUP] = \"ip4-lookup\",
        [" ENCAP_STACK "_ENCAP_NEXT_DROP] = \"error-drop\",
  },
};
")
