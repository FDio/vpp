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
 * A Data-Path Object is an object that represents actions that are
 * applied to packets are they are switched through VPP.
 *
 * The DPO is a base class that is specialised by other objects to provide
 * concrete actions
 *
 * The VLIB graph nodes are graph of types, the DPO graph is a graph of instances.
 */

#include <vnet/dpo/dpo.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/format.h>
#include <vnet/adj/adj.h>

#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/mpls_label_dpo.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/dpo/punt_dpo.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/dpo/ip_null_dpo.h>
#include <vnet/dpo/replicate_dpo.h>
#include <vnet/dpo/interface_rx_dpo.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/dpo/mpls_disposition.h>
#include <vnet/dpo/dvr_dpo.h>
#include <vnet/dpo/l3_proxy_dpo.h>
#include <vnet/dpo/ip6_ll_dpo.h>
#include <vnet/dpo/pw_cw.h>

/**
 * Array of char* names for the DPO types and protos
 */
static const char* dpo_type_names[] = DPO_TYPES;
static const char* dpo_proto_names[] = DPO_PROTOS;

/**
 * @brief Vector of virtual function tables for the DPO types
 *
 * This is a vector so we can dynamically register new DPO types in plugins.
 */
static dpo_vft_t *dpo_vfts;

/**
 * @brief vector of graph node names associated with each DPO type and protocol.
 *
 *   dpo_nodes[child_type][child_proto][node_X] = node_name;
 * i.e.
 *   dpo_node[DPO_LOAD_BALANCE][DPO_PROTO_IP4][0] = "ip4-lookup"
 *   dpo_node[DPO_LOAD_BALANCE][DPO_PROTO_IP4][1] = "ip4-load-balance"
 *
 * This is a vector so we can dynamically register new DPO types in plugins.
 */
static const char* const * const ** dpo_nodes;

/**
 * @brief Vector of edge indicies from parent DPO nodes to child
 *
 * dpo_edges[child_type][child_proto][parent_type][parent_proto] = edge_index
 *
 * This array is derived at init time from the dpo_nodes above. Note that
 * the third dimension in dpo_nodes is lost, hence, the edge index from each
 * node MUST be the same.
 * Including both the child and parent protocol is required to support the
 * case where it changes as the graph is traversed, most notably when an
 * MPLS label is popped.
 *
 * Note that this array is child type specific, not child instance specific.
 */
static u32 ****dpo_edges;

/**
 * @brief The DPO type value that can be assigned to the next dynamic
 *        type registration.
 */
static dpo_type_t dpo_dynamic = DPO_LAST;

dpo_proto_t
vnet_link_to_dpo_proto (vnet_link_t linkt)
{
    switch (linkt)
    {
    case VNET_LINK_IP6:
        return (DPO_PROTO_IP6);
    case VNET_LINK_IP4:
        return (DPO_PROTO_IP4);
    case VNET_LINK_MPLS:
        return (DPO_PROTO_MPLS);
    case VNET_LINK_ETHERNET:
        return (DPO_PROTO_ETHERNET);
    case VNET_LINK_NSH:
        return (DPO_PROTO_NSH);
    case VNET_LINK_ARP:
	break;
    }
    ASSERT(0);
    return (0);
}

vnet_link_t
dpo_proto_to_link (dpo_proto_t dp)
{
    switch (dp)
    {
    case DPO_PROTO_IP6:
        return (VNET_LINK_IP6);
    case DPO_PROTO_IP4:
        return (VNET_LINK_IP4);
    case DPO_PROTO_MPLS:
    case DPO_PROTO_BIER:
        return (VNET_LINK_MPLS);
    case DPO_PROTO_ETHERNET:
        return (VNET_LINK_ETHERNET);
    case DPO_PROTO_NSH:
        return (VNET_LINK_NSH);
    }
    return (~0);
}

u8 *
format_dpo_type (u8 * s, va_list * args)
{
    dpo_type_t type = va_arg (*args, int);

    s = format(s, "%s", dpo_type_names[type]);

    return (s);
}

u8 *
format_dpo_id (u8 * s, va_list * args)
{
    dpo_id_t *dpo = va_arg (*args, dpo_id_t*);
    u32 indent = va_arg (*args, u32);

    s = format(s, "[@%d]: ", dpo->dpoi_next_node);

    if (NULL != dpo_vfts[dpo->dpoi_type].dv_format)
    {
        s = format(s, "%U",
                   dpo_vfts[dpo->dpoi_type].dv_format,
                   dpo->dpoi_index,
                   indent);
    }
    else
    {
        switch (dpo->dpoi_type)
        {
        case DPO_FIRST:
            s = format(s, "unset");
            break;
        default:
            s = format(s, "unknown");
            break;
        }
    }
    return (s);
}

u8 *
format_dpo_proto (u8 * s, va_list * args)
{
    dpo_proto_t proto = va_arg (*args, int);

    return (format(s, "%s", dpo_proto_names[proto]));
}

void
dpo_set (dpo_id_t *dpo,
	 dpo_type_t type,
	 dpo_proto_t proto,
	 index_t index)
{
    dpo_id_t tmp = *dpo;

    dpo->dpoi_type = type;
    dpo->dpoi_proto = proto,
    dpo->dpoi_index = index;

    if (DPO_ADJACENCY == type)
    {
	/*
	 * set the adj subtype
	 */
	ip_adjacency_t *adj;

	adj = adj_get(index);

	switch (adj->lookup_next_index)
	{
	case IP_LOOKUP_NEXT_ARP:
	    dpo->dpoi_type = DPO_ADJACENCY_INCOMPLETE;
	    break;
	case IP_LOOKUP_NEXT_MIDCHAIN:
	    dpo->dpoi_type = DPO_ADJACENCY_MIDCHAIN;
	    break;
	case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
	    dpo->dpoi_type = DPO_ADJACENCY_MCAST_MIDCHAIN;
	    break;
	case IP_LOOKUP_NEXT_MCAST:
	    dpo->dpoi_type = DPO_ADJACENCY_MCAST;
            break;
	case IP_LOOKUP_NEXT_GLEAN:
	    dpo->dpoi_type = DPO_ADJACENCY_GLEAN;
	    break;
	default:
	    break;
	}
    }
    dpo_lock(dpo);
    dpo_unlock(&tmp);
}

void
dpo_reset (dpo_id_t *dpo)
{
    dpo_id_t tmp = DPO_INVALID;

    /*
     * use the atomic copy operation.
     */
    dpo_copy(dpo, &tmp);
}

/**
 * \brief
 * Compare two Data-path objects
 *
 * like memcmp, return 0 is matching, !0 otherwise.
 */
int
dpo_cmp (const dpo_id_t *dpo1,
	 const dpo_id_t *dpo2)
{
    int res;

    res = dpo1->dpoi_type - dpo2->dpoi_type;

    if (0 != res) return (res);

    return (dpo1->dpoi_index - dpo2->dpoi_index);
}

void
dpo_copy (dpo_id_t *dst,
	  const dpo_id_t *src)
{
    dpo_id_t tmp = {
        .as_u64 = dst->as_u64
    };

    /*
     * the destination is written in a single u64 write - hence atomically w.r.t
     * any packets inflight.
     */
    dst->as_u64 = src->as_u64;

    dpo_lock(dst);
    dpo_unlock(&tmp);
}

int
dpo_is_adj (const dpo_id_t *dpo)
{
    return ((dpo->dpoi_type == DPO_ADJACENCY) ||
	    (dpo->dpoi_type == DPO_ADJACENCY_INCOMPLETE) ||
            (dpo->dpoi_type == DPO_ADJACENCY_GLEAN) ||
            (dpo->dpoi_type == DPO_ADJACENCY_MCAST) ||
            (dpo->dpoi_type == DPO_ADJACENCY_MCAST_MIDCHAIN) ||
	    (dpo->dpoi_type == DPO_ADJACENCY_MIDCHAIN) ||
	    (dpo->dpoi_type == DPO_ADJACENCY_GLEAN));
}

static u32 *
dpo_default_get_next_node (const dpo_id_t *dpo)
{
    u32 *node_indices = NULL;
    const char *node_name;
    u32 ii = 0;

    node_name = dpo_nodes[dpo->dpoi_type][dpo->dpoi_proto][ii];
    while (NULL != node_name)
    {
        vlib_node_t *node;

        node = vlib_get_node_by_name(vlib_get_main(), (u8*) node_name);
        ASSERT(NULL != node);
        vec_add1(node_indices, node->index);

        ++ii;
        node_name = dpo_nodes[dpo->dpoi_type][dpo->dpoi_proto][ii];
    }

    return (node_indices);
}

/**
 * A default variant of the make interpose function that just returns
 * the original
 */
static void
dpo_default_mk_interpose (const dpo_id_t *original,
                          const dpo_id_t *parent,
                          dpo_id_t *clone)
{
    dpo_copy(clone, original);
}

void
dpo_register (dpo_type_t type,
	      const dpo_vft_t *vft,
              const char * const * const * nodes)
{
    vec_validate(dpo_vfts, type);
    dpo_vfts[type] = *vft;
    if (NULL == dpo_vfts[type].dv_get_next_node)
    {
        dpo_vfts[type].dv_get_next_node = dpo_default_get_next_node;
    }
    if (NULL == dpo_vfts[type].dv_mk_interpose)
    {
        dpo_vfts[type].dv_mk_interpose = dpo_default_mk_interpose;
    }

    vec_validate(dpo_nodes, type);
    dpo_nodes[type] = nodes;
}

dpo_type_t
dpo_register_new_type (const dpo_vft_t *vft,
                       const char * const * const * nodes)
{
    dpo_type_t type = dpo_dynamic++;

    dpo_register(type, vft, nodes);

    return (type);
}

void
dpo_mk_interpose (const dpo_id_t *original,
                  const dpo_id_t *parent,
                  dpo_id_t *clone)
{
    if (!dpo_id_is_valid(original))
	return;

    dpo_vfts[original->dpoi_type].dv_mk_interpose(original, parent, clone);
}

void
dpo_lock (dpo_id_t *dpo)
{
    if (!dpo_id_is_valid(dpo))
	return;

    dpo_vfts[dpo->dpoi_type].dv_lock(dpo);
}

void
dpo_unlock (dpo_id_t *dpo)
{
    if (!dpo_id_is_valid(dpo))
	return;

    dpo_vfts[dpo->dpoi_type].dv_unlock(dpo);
}

u32
dpo_get_urpf(const dpo_id_t *dpo)
{
    if (dpo_id_is_valid(dpo) &&
        (NULL != dpo_vfts[dpo->dpoi_type].dv_get_urpf))
    {
        return (dpo_vfts[dpo->dpoi_type].dv_get_urpf(dpo));
    }

    return (~0);
}

static u32
dpo_get_next_node (dpo_type_t child_type,
                   dpo_proto_t child_proto,
                   const dpo_id_t *parent_dpo)
{
    dpo_proto_t parent_proto;
    dpo_type_t parent_type;

    parent_type = parent_dpo->dpoi_type;
    parent_proto = parent_dpo->dpoi_proto;

    vec_validate(dpo_edges, child_type);
    vec_validate(dpo_edges[child_type], child_proto);
    vec_validate(dpo_edges[child_type][child_proto], parent_type);
    vec_validate_init_empty(
        dpo_edges[child_type][child_proto][parent_type],
        parent_proto, ~0);

    /*
     * if the edge index has not yet been created for this node to node transition
     */
    if (~0 == dpo_edges[child_type][child_proto][parent_type][parent_proto])
    {
        vlib_node_t *child_node;
        u32 *parent_indices;
        vlib_main_t *vm;
        u32 edge, *pi, cc;

        vm = vlib_get_main();

        ASSERT(NULL != dpo_vfts[parent_type].dv_get_next_node);
        ASSERT(NULL != dpo_nodes[child_type]);
        ASSERT(NULL != dpo_nodes[child_type][child_proto]);

        cc = 0;
        parent_indices = dpo_vfts[parent_type].dv_get_next_node(parent_dpo);

        vlib_worker_thread_barrier_sync(vm);

        /*
         * create a graph arc from each of the child's registered node types,
         * to each of the parent's.
         */
        while (NULL != dpo_nodes[child_type][child_proto][cc])
        {
            child_node =
                vlib_get_node_by_name(vm,
                                      (u8*) dpo_nodes[child_type][child_proto][cc]);

            vec_foreach(pi, parent_indices)
            {
                edge = vlib_node_add_next(vm, child_node->index, *pi);

                if (~0 == dpo_edges[child_type][child_proto][parent_type][parent_proto])
                {
                    dpo_edges[child_type][child_proto][parent_type][parent_proto] = edge;
                }
                else
                {
                    ASSERT(dpo_edges[child_type][child_proto][parent_type][parent_proto] == edge);
                }
            }
            cc++;
        }

        vlib_worker_thread_barrier_release(vm);
        vec_free(parent_indices);
    }

    return (dpo_edges[child_type][child_proto][parent_type][parent_proto]);
}

/**
 * @brief return already stacked up next node index for a given
 * child_type/child_proto and parent_type/patent_proto.
 * The VLIB graph arc used is taken from the parent and child types
 * passed.
 */
u32
dpo_get_next_node_by_type_and_proto (dpo_type_t   child_type,
                                     dpo_proto_t  child_proto,
                                     dpo_type_t   parent_type,
                                     dpo_proto_t  parent_proto)
{
   return (dpo_edges[child_type][child_proto][parent_type][parent_proto]);
}

/**
 * @brief Stack one DPO object on another, and thus establish a child parent
 * relationship. The VLIB graph arc used is taken from the parent and child types
 * passed.
 */
static void
dpo_stack_i (u32 edge,
             dpo_id_t *dpo,
             const dpo_id_t *parent)
{
    /*
     * in order to get an atomic update of the parent we create a temporary,
     * from a copy of the child, and add the next_node. then we copy to the parent
     */
    dpo_id_t tmp = DPO_INVALID;
    dpo_copy(&tmp, parent);

    /*
     * get the edge index for the parent to child VLIB graph transition
     */
    tmp.dpoi_next_node = edge;

    /*
     * this update is atomic.
     */
    dpo_copy(dpo, &tmp);

    dpo_reset(&tmp);
}

/**
 * @brief Stack one DPO object on another, and thus establish a child-parent
 * relationship. The VLIB graph arc used is taken from the parent and child types
 * passed.
 */
void
dpo_stack (dpo_type_t child_type,
           dpo_proto_t child_proto,
           dpo_id_t *dpo,
           const dpo_id_t *parent)
{
    dpo_stack_i(dpo_get_next_node(child_type, child_proto, parent), dpo, parent);
}

/**
 * @brief Stack one DPO object on another, and thus establish a child parent
 * relationship. A new VLIB graph arc is created from the child node passed
 * to the nodes registered by the parent. The VLIB infra will ensure this arc
 * is added only once.
 */
void
dpo_stack_from_node (u32 child_node_index,
                     dpo_id_t *dpo,
                     const dpo_id_t *parent)
{
    dpo_type_t parent_type;
    u32 *parent_indices;
    vlib_main_t *vm;
    u32 edge, *pi;

    edge = 0;
    parent_type = parent->dpoi_type;
    vm = vlib_get_main();

    ASSERT(NULL != dpo_vfts[parent_type].dv_get_next_node);
    parent_indices = dpo_vfts[parent_type].dv_get_next_node(parent);
    ASSERT(parent_indices);

    /*
     * This loop is purposefully written with the worker thread lock in the
     * inner loop because;
     *  1) the likelihood that the edge does not exist is smaller
     *  2) the likelihood there is more than one node is even smaller
     * so we are optimising for not need to take the lock
     */
    vec_foreach(pi, parent_indices)
    {
        edge = vlib_node_get_next(vm, child_node_index, *pi);

        if (~0 == edge)
        {
            vlib_worker_thread_barrier_sync(vm);

            edge = vlib_node_add_next(vm, child_node_index, *pi);

            vlib_worker_thread_barrier_release(vm);
        }
    }
    dpo_stack_i(edge, dpo, parent);

    /* should free this local vector to avoid memory leak */
    vec_free(parent_indices);
}

static clib_error_t *
dpo_module_init (vlib_main_t * vm)
{
    drop_dpo_module_init();
    punt_dpo_module_init();
    receive_dpo_module_init();
    load_balance_module_init();
    mpls_label_dpo_module_init();
    classify_dpo_module_init();
    lookup_dpo_module_init();
    ip_null_dpo_module_init();
    ip6_ll_dpo_module_init();
    replicate_module_init();
    interface_rx_dpo_module_init();
    interface_tx_dpo_module_init();
    mpls_disp_dpo_module_init();
    dvr_dpo_module_init();
    l3_proxy_dpo_module_init();
    pw_cw_dpo_module_init();

    return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION(dpo_module_init) =
{
    .runs_before = VLIB_INITS ("ip_main_init"),
};
/* *INDENT-ON* */

static clib_error_t *
dpo_memory_show (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
    dpo_vft_t *vft;

    vlib_cli_output (vm, "DPO memory");
    vlib_cli_output (vm, "%=30s %=5s %=8s/%=9s   totals",
		     "Name","Size", "in-use", "allocated");

    vec_foreach(vft, dpo_vfts)
    {
	if (NULL != vft->dv_mem_show)
	    vft->dv_mem_show();
    }

    return (NULL);
}

/* *INDENT-OFF* */
/*?
 * The '<em>sh dpo memory </em>' command displays the memory usage for each
 * data-plane object type.
 *
 * @cliexpar
 * @cliexstart{show dpo memory}
 * DPO memory
 *             Name               Size  in-use /allocated   totals
 *         load-balance            64     12   /    12      768/768
 *           Adjacency            256      1   /    1       256/256
 *            Receive              24      5   /    5       120/120
 *            Lookup               12      0   /    0       0/0
 *           Classify              12      0   /    0       0/0
 *          MPLS label             24      0   /    0       0/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_fib_memory, static) = {
    .path = "show dpo memory",
    .function = dpo_memory_show,
    .short_help = "show dpo memory",
};
/* *INDENT-ON* */
