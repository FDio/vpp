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
/**
 * @brief
 * The data-path object representing dropping the packet
 */

#include <vnet/dpo/ip_null_dpo.h>
#include <vnet/ip/ip.h>

/**
 * @brief A representation of the IP_NULL DPO
 */
typedef struct ip_null_dpo_t_
{
    /**
     * @brief The action to take on a packet
     */
    ip_null_dpo_action_t ind_action;
    /**
     * @brief The next VLIB node
     */
    u32 ind_next_index;
    /**
     * rate limits
     */
} ip_null_dpo_t;

/**
 * @brief the IP_NULL dpos are shared by all routes, hence they are global.
 * As the neame implies this is only for IP, hence 2.
 */
static ip_null_dpo_t ip_null_dpos[2 * IP_NULL_DPO_ACTION_NUM] = {
    [0] = {
	/* proto ip4, no action */
	.ind_action = IP_NULL_ACTION_NONE,
    },
    [1] = {
	/* proto ip4, action send unreach */
	.ind_action = IP_NULL_ACTION_SEND_ICMP_UNREACH,
    },
    [2] = {
	/* proto ip4, action send unreach */
	.ind_action = IP_NULL_ACTION_SEND_ICMP_PROHIBIT,
    },
    [3] = {
	/* proto ip6, no action */
	.ind_action = IP_NULL_ACTION_NONE,
    },
    [4] = {
	/* proto ip6, action send unreach */
	.ind_action = IP_NULL_ACTION_SEND_ICMP_UNREACH,
    },
    [5] = {
	/* proto ip6, action send unreach */
	.ind_action = IP_NULL_ACTION_SEND_ICMP_PROHIBIT,
    },
};

/**
 * @brief Action strings
 */
const char *ip_null_action_strings[] = IP_NULL_ACTIONS;

void
ip_null_dpo_add_and_lock (dpo_proto_t proto,
			  ip_null_dpo_action_t action,
			  dpo_id_t *dpo)
{
    int i;

    ASSERT((proto == DPO_PROTO_IP4) ||
	   (proto == DPO_PROTO_IP6));
    ASSERT(action < IP_NULL_DPO_ACTION_NUM);

    i = (proto == DPO_PROTO_IP4 ? 0 : 1);

    dpo_set(dpo, DPO_IP_NULL, proto, (i*IP_NULL_DPO_ACTION_NUM) + action);
}

always_inline const ip_null_dpo_t*
ip_null_dpo_get (index_t indi)
{
    return (&ip_null_dpos[indi]);
}

ip_null_dpo_action_t
ip_null_dpo_get_action (index_t indi)
{
    return (ip_null_dpos[indi].ind_action);
}

static void
ip_null_dpo_lock (dpo_id_t *dpo)
{
    /*
     * not maintaining a lock count on the ip_null, they are const global and
     * never die.
     */
}
static void
ip_null_dpo_unlock (dpo_id_t *dpo)
{
}

static u8*
format_ip_null_dpo (u8 *s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    const ip_null_dpo_t *ind;
    dpo_proto_t proto;

    ind = ip_null_dpo_get(index);
    proto = (index < IP_NULL_DPO_ACTION_NUM ? DPO_PROTO_IP4 : DPO_PROTO_IP6);

    return (format(s, "%U-null action:%s",
		   format_dpo_proto, proto,
		   ip_null_action_strings[ind->ind_action]));
}

const static dpo_vft_t ip_null_vft = {
    .dv_lock   = ip_null_dpo_lock,
    .dv_unlock = ip_null_dpo_unlock,
    .dv_format = format_ip_null_dpo,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a ip_null
 *        object.
 *
 * this means that these graph nodes are ones from which a ip_null is the
 * parent object in the DPO-graph.
 */
const static char* const ip4_null_nodes[] =
{
    "ip4-null",
    NULL,
};
const static char* const ip6_null_nodes[] =
{
    "ip6-null",
    NULL,
};

const static char* const * const ip_null_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4] = ip4_null_nodes,
    [DPO_PROTO_IP6] = ip6_null_nodes,
};

typedef struct ip_null_dpo_trace_t_
{
    index_t ind_index;
} ip_null_dpo_trace_t;

/**
 * @brief Exit nodes from a IP_NULL
 */
typedef enum ip_null_next_t_
{
    IP_NULL_NEXT_DROP,
    IP_NULL_NEXT_ICMP,
    IP_NULL_NEXT_NUM,
} ip_null_next_t;

always_inline uword
ip_null_dpo_switch (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    u8 is_ip4)
{
    u32 n_left_from, next_index, *from, *to_next;
    static f64 time_last_seed_change = -1e100;
    static u32 hash_seeds[3];
    static uword hash_bitmap[256 / BITS (uword)];
    f64 time_now;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    time_now = vlib_time_now (vm);
    if (time_now - time_last_seed_change > 1e-1)
    {
	uword i;
	u32 * r = clib_random_buffer_get_data (&vm->random_buffer,
					       sizeof (hash_seeds));
	for (i = 0; i < ARRAY_LEN (hash_seeds); i++)
	    hash_seeds[i] = r[i];

	/* Mark all hash keys as been not-seen before. */
	for (i = 0; i < ARRAY_LEN (hash_bitmap); i++)
	    hash_bitmap[i] = 0;

	time_last_seed_change = time_now;
    }

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
	u32 n_left_to_next;

	vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	while (n_left_from > 0 && n_left_to_next > 0)
	{
	    u32 a0, b0, c0, m0, drop0;
	    vlib_buffer_t *p0;
	    u32 bi0, indi0, next0;
	    const ip_null_dpo_t *ind0;
	    uword bm0;

	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    p0 = vlib_get_buffer (vm, bi0);

	    /* lookup dst + src mac */
	    indi0 =  vnet_buffer (p0)->ip.adj_index;
	    ind0 = ip_null_dpo_get(indi0);
	    next0 = IP_NULL_NEXT_DROP;

	    /*
	     * rate limit - don't DoS the sender.
	     */
	    a0 = hash_seeds[0];
	    b0 = hash_seeds[1];
	    c0 = hash_seeds[2];

	    if (is_ip4)
	    {
		ip4_header_t *ip0 = vlib_buffer_get_current (p0);

		a0 ^= ip0->dst_address.data_u32;
		b0 ^= ip0->src_address.data_u32;

		hash_v3_finalize32 (a0, b0, c0);
	    }
	    else
	    {
		ip6_header_t *ip0 = vlib_buffer_get_current (p0);

		a0 ^= ip0->dst_address.as_u32[0];
		b0 ^= ip0->src_address.as_u32[0];
		c0 ^= ip0->src_address.as_u32[1];

		hash_v3_mix32 (a0, b0, c0);

		a0 ^= ip0->dst_address.as_u32[1];
		b0 ^= ip0->src_address.as_u32[2];
		c0 ^= ip0->src_address.as_u32[3];

		hash_v3_finalize32 (a0, b0, c0);
	    }

	    c0 &= BITS (hash_bitmap) - 1;
	    c0 = c0 / BITS (uword);
	    m0 = (uword) 1 << (c0 % BITS (uword));

	    bm0 = hash_bitmap[c0];
	    drop0 = (bm0 & m0) != 0;

	    /* Mark it as seen. */
	    hash_bitmap[c0] = bm0 | m0;

	    if (PREDICT_FALSE(!drop0))
	    {
		if (is_ip4)
		{
		    /*
		     * There's a trade-off here. This conditinal statement
		     * versus a graph node per-condition. Given the number
		     * expect number of packets to reach a null route is 0
		     * we favour the run-time cost over the graph complexity
		     */
		    if (IP_NULL_ACTION_SEND_ICMP_UNREACH == ind0->ind_action)
		    {
			next0 = IP_NULL_NEXT_ICMP;
			icmp4_error_set_vnet_buffer(
			    p0,
			    ICMP4_destination_unreachable,
			    ICMP4_destination_unreachable_destination_unreachable_host,
			    0);
		    }
		    else if (IP_NULL_ACTION_SEND_ICMP_PROHIBIT == ind0->ind_action)
		    {
			next0 = IP_NULL_NEXT_ICMP;
			icmp4_error_set_vnet_buffer(
			    p0,
			    ICMP4_destination_unreachable,
			    ICMP4_destination_unreachable_host_administratively_prohibited,
			    0);
		    }
		}
		else
		{
		    if (IP_NULL_ACTION_SEND_ICMP_UNREACH == ind0->ind_action)
		    {
			next0 = IP_NULL_NEXT_ICMP;
			icmp6_error_set_vnet_buffer(
			    p0,
			    ICMP6_destination_unreachable,
			    ICMP6_destination_unreachable_no_route_to_destination,
			    0);
		    }
		    else if (IP_NULL_ACTION_SEND_ICMP_PROHIBIT == ind0->ind_action)
		    {
			next0 = IP_NULL_NEXT_ICMP;
			icmp6_error_set_vnet_buffer(
			    p0,
			    ICMP6_destination_unreachable,
			    ICMP6_destination_unreachable_destination_administratively_prohibited,
			    0);
		    }
		}
	    }

	    if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
		ip_null_dpo_trace_t *tr = vlib_add_trace (vm, node, p0,
							  sizeof (*tr));
		tr->ind_index = indi0;
	    }
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					     n_left_to_next, bi0, next0);
	}

	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

static u8 *
format_ip_null_dpo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_null_dpo_trace_t *t = va_arg (*args, ip_null_dpo_trace_t *);

  s = format (s, "%U", format_ip_null_dpo, t->ind_index, 0);
  return s;
}

static uword
ip4_null_dpo_switch (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
    return (ip_null_dpo_switch(vm, node, frame, 1));
}

/**
 * @brief
 */
VLIB_REGISTER_NODE (ip4_null_dpo_node) = {
  .function = ip4_null_dpo_switch,
  .name = "ip4-null",
  .vector_size = sizeof (u32),

  .format_trace = format_ip_null_dpo_trace,
  .n_next_nodes = IP_NULL_NEXT_NUM,
  .next_nodes = {
      [IP_NULL_NEXT_DROP] = "ip4-drop",
      [IP_NULL_NEXT_ICMP] = "ip4-icmp-error",
  },
};

static uword
ip6_null_dpo_switch (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
    return (ip_null_dpo_switch(vm, node, frame, 0));
}

/**
 * @brief
 */
VLIB_REGISTER_NODE (ip6_null_dpo_node) = {
  .function = ip6_null_dpo_switch,
  .name = "ip6-null",
  .vector_size = sizeof (u32),

  .format_trace = format_ip_null_dpo_trace,
  .n_next_nodes = IP_NULL_NEXT_NUM,
  .next_nodes = {
      [IP_NULL_NEXT_DROP] = "ip6-drop",
      [IP_NULL_NEXT_ICMP] = "ip6-icmp-error",
  },
};

void
ip_null_dpo_module_init (void)
{
    dpo_register(DPO_IP_NULL, &ip_null_vft, ip_null_nodes);
}
