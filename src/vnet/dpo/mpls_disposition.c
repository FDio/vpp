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

#include <vnet/ip/ip4_input.h>
#include <vnet/ip/ip6_input.h>
#include <vnet/dpo/mpls_disposition.h>
#include <vnet/mpls/mpls.h>

#ifndef CLIB_MARCH_VARIANT
/*
 * pool of all MPLS Label DPOs
 */
mpls_disp_dpo_t *mpls_disp_dpo_pool;

static mpls_disp_dpo_t *
mpls_disp_dpo_alloc (void)
{
    mpls_disp_dpo_t *mdd;

    pool_get_aligned(mpls_disp_dpo_pool, mdd, CLIB_CACHE_LINE_BYTES);
    clib_memset(mdd, 0, sizeof(*mdd));

    dpo_reset(&mdd->mdd_dpo);

    return (mdd);
}

static index_t
mpls_disp_dpo_get_index (mpls_disp_dpo_t *mdd)
{
    return (mdd - mpls_disp_dpo_pool);
}

void
mpls_disp_dpo_create (dpo_proto_t payload_proto,
                      fib_rpf_id_t rpf_id,
                      fib_mpls_lsp_mode_t mode,
                      const dpo_id_t *parent,
                      dpo_id_t *dpo)
{
    mpls_disp_dpo_t *mdd;
    dpo_type_t dtype;

    mdd = mpls_disp_dpo_alloc();

    mdd->mdd_payload_proto = payload_proto;
    mdd->mdd_rpf_id = rpf_id;
    mdd->mdd_mode = mode;
    dtype = (FIB_MPLS_LSP_MODE_PIPE == mode ?
             DPO_MPLS_DISPOSITION_PIPE :
             DPO_MPLS_DISPOSITION_UNIFORM);

    /*
     * stack this disposition object on the parent given
     */
    dpo_stack(dtype,
              mdd->mdd_payload_proto,
              &mdd->mdd_dpo,
              parent);

    /*
     * set up the return DPO to refer to this object
     */
    dpo_set(dpo,
            dtype,
            payload_proto,
            mpls_disp_dpo_get_index(mdd));
}

u8*
format_mpls_disp_dpo (u8 *s, va_list *args)
{
    index_t index = va_arg(*args, index_t);
    u32 indent = va_arg(*args, u32);
    mpls_disp_dpo_t *mdd;

    mdd = mpls_disp_dpo_get(index);

    s = format(s, "mpls-disposition:[%d]:[", index);

    if (0 != mdd->mdd_rpf_id)
        s = format(s, "rpf-id:%d ", mdd->mdd_rpf_id);

    s = format(s, "%U, %U]",
               format_dpo_proto, mdd->mdd_payload_proto,
               format_fib_mpls_lsp_mode, mdd->mdd_mode);

    s = format(s, "\n%U", format_white_space, indent);
    s = format(s, "%U", format_dpo_id, &mdd->mdd_dpo, indent+2);

    return (s);
}

static void
mpls_disp_dpo_lock (dpo_id_t *dpo)
{
    mpls_disp_dpo_t *mdd;

    mdd = mpls_disp_dpo_get(dpo->dpoi_index);

    mdd->mdd_locks++;
}

static void
mpls_disp_dpo_unlock (dpo_id_t *dpo)
{
    mpls_disp_dpo_t *mdd;

    mdd = mpls_disp_dpo_get(dpo->dpoi_index);

    mdd->mdd_locks--;

    if (0 == mdd->mdd_locks)
    {
	dpo_reset(&mdd->mdd_dpo);
	pool_put(mpls_disp_dpo_pool, mdd);
    }
}
#endif /* CLIB_MARCH_VARIANT */

/**
 * @brief A struct to hold tracing information for the MPLS label disposition
 * node.
 */
typedef struct mpls_label_disposition_trace_t_
{
    dpo_proto_t mddt_payload_proto;
    fib_rpf_id_t mddt_rpf_id;
    fib_mpls_lsp_mode_t mddt_mode;
} mpls_label_disposition_trace_t;

extern vlib_node_registration_t ip4_mpls_label_disposition_pipe_node;
extern vlib_node_registration_t ip6_mpls_label_disposition_pipe_node;
extern vlib_node_registration_t ip4_mpls_label_disposition_uniform_node;
extern vlib_node_registration_t ip6_mpls_label_disposition_uniform_node;

always_inline uword
mpls_label_disposition_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			       vlib_frame_t *frame,
			       ip_address_family_t payload_af,
			       fib_mpls_lsp_mode_t mode)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_node_runtime_t *error_node;
  u32 n_left, *from;

  if (AF_IP4 == payload_af)
    {
        if (FIB_MPLS_LSP_MODE_PIPE == mode)
            error_node =
                vlib_node_get_runtime(vm, ip4_mpls_label_disposition_pipe_node.index);
        else
            error_node =
                vlib_node_get_runtime(vm, ip4_mpls_label_disposition_uniform_node.index);
    }
    else
    {
        if (FIB_MPLS_LSP_MODE_PIPE == mode)
            error_node =
                vlib_node_get_runtime(vm, ip6_mpls_label_disposition_pipe_node.index);
        else
            error_node =
                vlib_node_get_runtime(vm, ip6_mpls_label_disposition_uniform_node.index);
    }
    from = vlib_frame_vector_args (frame);
    n_left = frame->n_vectors;

    vlib_get_buffers (vm, from, bufs, n_left);
    b = bufs;
    next = nexts;

    while (n_left >= 2)
      {
	mpls_disp_dpo_t *mdd0, *mdd1;
	u32 mddi0, mddi1;

	/* Prefetch next iteration. */
	if (n_left >= 4)
	  {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[3], LOAD);
	    vlib_prefetch_buffer_data (b[2], LOAD);
	    vlib_prefetch_buffer_data (b[3], LOAD);
	  }

	/* dst lookup was done by ip4 lookup */
	mddi0 = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
	mddi1 = vnet_buffer (b[1])->ip.adj_index[VLIB_TX];
	mdd0 = mpls_disp_dpo_get (mddi0);
	mdd1 = mpls_disp_dpo_get (mddi1);

	next[0] = mdd0->mdd_dpo.dpoi_next_node;
	next[1] = mdd1->mdd_dpo.dpoi_next_node;

	if (AF_IP4 == payload_af)
	  {
	    ip4_header_t *ip0, *ip1;

	    ip0 = vlib_buffer_get_current (b[0]);
	    ip1 = vlib_buffer_get_current (b[1]);

	    /*
	     * IPv4 input checks on the exposed IP header
	     * including checksum
	     */
	    ip4_input_check_x2 (vm, error_node, b, next,
				IP_INPUT_FLAGS_VERIFY_CHECKSUM);

	    if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
	      {
		/*
		 * Copy the TTL from the MPLS packet into the
		 * exposed IP. recalc the chksum
		 */
		ip0->ttl = vnet_buffer (b[0])->mpls.ttl;
		ip1->ttl = vnet_buffer (b[1])->mpls.ttl;
		ip0->tos = mpls_exp_to_ip_dscp (vnet_buffer (b[0])->mpls.exp);
		ip1->tos = mpls_exp_to_ip_dscp (vnet_buffer (b[1])->mpls.exp);

		ip0->checksum = ip4_header_checksum (ip0);
		ip1->checksum = ip4_header_checksum (ip1);
	      }
	  }
	else
	  {
	    ip6_header_t *ip0, *ip1;

	    ip0 = vlib_buffer_get_current (b[0]);
	    ip1 = vlib_buffer_get_current (b[1]);

	    /*
	     * IPv6 input checks on the exposed IP header
	     */
	    ip6_input_check_x2 (vm, error_node, b, next);

	    if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
	      {
		/*
		 * Copy the TTL from the MPLS packet into the
		 * exposed IP
		 */
		ip0->hop_limit = vnet_buffer (b[0])->mpls.ttl;
		ip1->hop_limit = vnet_buffer (b[1])->mpls.ttl;

		ip6_set_traffic_class_network_order (
		  ip0, mpls_exp_to_ip_dscp (vnet_buffer (b[0])->mpls.exp));
		ip6_set_traffic_class_network_order (
		  ip1, mpls_exp_to_ip_dscp (vnet_buffer (b[1])->mpls.exp));
	      }
	  }

	vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = mdd0->mdd_dpo.dpoi_index;
	vnet_buffer (b[1])->ip.adj_index[VLIB_TX] = mdd1->mdd_dpo.dpoi_index;
	vnet_buffer (b[0])->ip.rpf_id = mdd0->mdd_rpf_id;
	vnet_buffer (b[1])->ip.rpf_id = mdd1->mdd_rpf_id;

	if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	  {
	    mpls_label_disposition_trace_t *tr =
	      vlib_add_trace (vm, node, b[0], sizeof (*tr));
	    tr->mddt_payload_proto = mdd0->mdd_payload_proto;
	    tr->mddt_rpf_id = mdd0->mdd_rpf_id;
	    tr->mddt_mode = mdd0->mdd_mode;
	  }
	if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	  {
	    mpls_label_disposition_trace_t *tr =
	      vlib_add_trace (vm, node, b[1], sizeof (*tr));
	    tr->mddt_payload_proto = mdd1->mdd_payload_proto;
	    tr->mddt_rpf_id = mdd1->mdd_rpf_id;
	    tr->mddt_mode = mdd1->mdd_mode;
	  }

	next += 2;
	b += 2;
	n_left -= 2;
      }

    while (n_left > 0)
      {
	mpls_disp_dpo_t *mdd0;
	u32 mddi0;

	/* dst lookup was done by ip4 lookup */
	mddi0 = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
	mdd0 = mpls_disp_dpo_get (mddi0);
	next[0] = mdd0->mdd_dpo.dpoi_next_node;

	if (AF_IP4 == payload_af)
	  {
	    ip4_header_t *ip0;

	    ip0 = vlib_buffer_get_current (b[0]);

	    /*
	     * IPv4 input checks on the exposed IP header
	     * including checksum
	     */
	    ip4_input_check_x1 (vm, error_node, b, next,
				IP_INPUT_FLAGS_VERIFY_CHECKSUM);

	    if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
	      {
		/*
		 * Copy the TTL from the MPLS packet into the
		 * exposed IP. recalc the chksum
		 */
		ip0->ttl = vnet_buffer (b[0])->mpls.ttl;
		ip0->tos = mpls_exp_to_ip_dscp (vnet_buffer (b[0])->mpls.exp);
		ip0->checksum = ip4_header_checksum (ip0);
	      }
	  }
	else
	  {
	    ip6_header_t *ip0;

	    ip0 = vlib_buffer_get_current (b[0]);

	    /*
	     * IPv6 input checks on the exposed IP header
	     */
	    ip6_input_check_x1 (vm, error_node, b, next);

	    if (FIB_MPLS_LSP_MODE_UNIFORM == mode)
	      {
		/*
		 * Copy the TTL from the MPLS packet into the
		 * exposed IP
		 */
		ip0->hop_limit = vnet_buffer (b[0])->mpls.ttl;

		ip6_set_traffic_class_network_order (
		  ip0, mpls_exp_to_ip_dscp (vnet_buffer (b[0])->mpls.exp));
	      }
	  }

	vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = mdd0->mdd_dpo.dpoi_index;
	vnet_buffer (b[0])->ip.rpf_id = mdd0->mdd_rpf_id;

	if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	  {
	    mpls_label_disposition_trace_t *tr =
	      vlib_add_trace (vm, node, b[0], sizeof (*tr));
	    tr->mddt_payload_proto = mdd0->mdd_payload_proto;
	    tr->mddt_rpf_id = mdd0->mdd_rpf_id;
	    tr->mddt_mode = mdd0->mdd_mode;
	  }

	next += 1;
	b += 1;
	n_left -= 1;
      }

    vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

    return frame->n_vectors;
}

static u8 *
format_mpls_label_disposition_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    CLIB_UNUSED(mpls_label_disposition_trace_t * t);

    t = va_arg(*args, mpls_label_disposition_trace_t *);

    s = format(s, "rpf-id:%d %U, %U",
               t->mddt_rpf_id,
               format_dpo_proto, t->mddt_payload_proto,
               format_fib_mpls_lsp_mode, t->mddt_mode);

    return (s);
}

VLIB_NODE_FN (ip4_mpls_label_disposition_pipe_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  return (mpls_label_disposition_inline (vm, node, frame, AF_IP4,
					 FIB_MPLS_LSP_MODE_PIPE));
}

VLIB_REGISTER_NODE (ip4_mpls_label_disposition_pipe_node) = {
  .name = "ip4-mpls-label-disposition-pipe",
  .vector_size = sizeof (u32),

  .format_trace = format_mpls_label_disposition_trace,
  .sibling_of = "ip4-input",
  .n_errors = IP4_N_ERROR,
  .error_counters = ip4_error_counters,
};

VLIB_NODE_FN (ip6_mpls_label_disposition_pipe_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  return (mpls_label_disposition_inline (vm, node, frame, AF_IP6,
					 FIB_MPLS_LSP_MODE_PIPE));
}

VLIB_REGISTER_NODE (ip6_mpls_label_disposition_pipe_node) = {
  .name = "ip6-mpls-label-disposition-pipe",
  .vector_size = sizeof (u32),

  .format_trace = format_mpls_label_disposition_trace,
  .sibling_of = "ip6-input",
  .n_errors = IP6_N_ERROR,
  .error_counters = ip6_error_counters,
};

VLIB_NODE_FN (ip4_mpls_label_disposition_uniform_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  return (mpls_label_disposition_inline (vm, node, frame, AF_IP4,
					 FIB_MPLS_LSP_MODE_UNIFORM));
}

VLIB_REGISTER_NODE (ip4_mpls_label_disposition_uniform_node) = {
  .name = "ip4-mpls-label-disposition-uniform",
  .vector_size = sizeof (u32),

  .format_trace = format_mpls_label_disposition_trace,
  .sibling_of = "ip4-input",
  .n_errors = IP4_N_ERROR,
  .error_counters = ip4_error_counters,
};

VLIB_NODE_FN (ip6_mpls_label_disposition_uniform_node) (vlib_main_t * vm,
                                    vlib_node_runtime_t * node,
                                    vlib_frame_t * frame)
{
  return (mpls_label_disposition_inline (vm, node, frame, AF_IP6,
					 FIB_MPLS_LSP_MODE_UNIFORM));
}

VLIB_REGISTER_NODE (ip6_mpls_label_disposition_uniform_node) = {
  .name = "ip6-mpls-label-disposition-uniform",
  .vector_size = sizeof (u32),

  .format_trace = format_mpls_label_disposition_trace,
  .sibling_of = "ip6-input",
  .n_errors = IP6_N_ERROR,
  .error_counters = ip6_error_counters,
};

#ifndef CLIB_MARCH_VARIANT
static void
mpls_disp_dpo_mem_show (void)
{
    fib_show_memory_usage("MPLS label",
			  pool_elts(mpls_disp_dpo_pool),
			  pool_len(mpls_disp_dpo_pool),
			  sizeof(mpls_disp_dpo_t));
}

const static dpo_vft_t mdd_vft = {
    .dv_lock = mpls_disp_dpo_lock,
    .dv_unlock = mpls_disp_dpo_unlock,
    .dv_format = format_mpls_disp_dpo,
    .dv_mem_show = mpls_disp_dpo_mem_show,
};

const static char* const mpls_label_disp_pipe_ip4_nodes[] =
{
    "ip4-mpls-label-disposition-pipe",
    NULL,
};
const static char* const mpls_label_disp_pipe_ip6_nodes[] =
{
    "ip6-mpls-label-disposition-pipe",
    NULL,
};
const static char* const * const mpls_label_disp_pipe_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_disp_pipe_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_disp_pipe_ip6_nodes,
};

const static char* const mpls_label_disp_uniform_ip4_nodes[] =
{
    "ip4-mpls-label-disposition-uniform",
    NULL,
};
const static char* const mpls_label_disp_uniform_ip6_nodes[] =
{
    "ip6-mpls-label-disposition-uniform",
    NULL,
};
const static char* const * const mpls_label_disp_uniform_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mpls_label_disp_uniform_ip4_nodes,
    [DPO_PROTO_IP6]  = mpls_label_disp_uniform_ip6_nodes,
};


void
mpls_disp_dpo_module_init(void)
{
    dpo_register(DPO_MPLS_DISPOSITION_PIPE, &mdd_vft,
                 mpls_label_disp_pipe_nodes);
    dpo_register(DPO_MPLS_DISPOSITION_UNIFORM, &mdd_vft,
                 mpls_label_disp_uniform_nodes);
}
#endif /* CLIB_MARCH_VARIANT */
