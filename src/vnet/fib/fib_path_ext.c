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

#include <vnet/mpls/mpls.h>
#include <vnet/dpo/mpls_label_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>

#include <vnet/fib/fib_path_ext.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_path.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_internal.h>

const char *fib_path_ext_adj_flags_names[] = FIB_PATH_EXT_ADJ_ATTR_NAMES;

u8 *
format_fib_path_ext (u8 * s, va_list * args)
{
    fib_path_ext_t *path_ext;
    u32 ii;

    path_ext = va_arg (*args, fib_path_ext_t *);

    s = format(s, "path:%d ", path_ext->fpe_path_index);

    switch (path_ext->fpe_type)
    {
    case FIB_PATH_EXT_MPLS:
        s = format(s, "labels:",
                   path_ext->fpe_path_index);
        for (ii = 0; ii < vec_len(path_ext->fpe_path.frp_label_stack); ii++)
        {
            s = format(s, "%U ",
                       format_mpls_unicast_label,
                       path_ext->fpe_path.frp_label_stack[ii]);
        }
        break;
    case FIB_PATH_EXT_ADJ: {
        fib_path_ext_adj_attr_t attr;

        s = format(s, "adj-flags:");
        if (path_ext->fpe_adj_flags)
        {
            FOR_EACH_PATH_EXT_ADJ_ATTR(attr)
            {
                s = format(s, "%s", fib_path_ext_adj_flags_names[attr]);
            }
        }
        else
        {
            s = format(s, "None");
        }
        break;
    }
    }
    return (s);
}

int
fib_path_ext_cmp (fib_path_ext_t *path_ext,
		  const fib_route_path_t *rpath)
{
    return (fib_route_path_cmp(&path_ext->fpe_path, rpath));
}

static fib_path_list_walk_rc_t
fib_path_ext_match (fib_node_index_t pl_index,
		    fib_node_index_t path_index,
		    void *ctx)
{
    fib_path_ext_t *path_ext = ctx;

    if (!fib_path_cmp_w_route_path(path_index,
				   &path_ext->fpe_path))
    {
	path_ext->fpe_path_index = path_index;
	return (FIB_PATH_LIST_WALK_STOP);
    }
    return (FIB_PATH_LIST_WALK_CONTINUE);
}

void
fib_path_ext_resolve (fib_path_ext_t *path_ext,
		      fib_node_index_t path_list_index)
{
    /*
     * Find the path on the path list that this is an extension for
     */
    path_ext->fpe_path_index = FIB_NODE_INDEX_INVALID;
    fib_path_list_walk(path_list_index,
		       fib_path_ext_match,
		       path_ext);
}

static void
fib_path_ext_init (fib_path_ext_t *path_ext,
		   fib_node_index_t path_list_index,
                   fib_path_ext_type_t ext_type,
		   const fib_route_path_t *rpath)
{
    path_ext->fpe_path = *rpath;
    path_ext->fpe_path_index = FIB_NODE_INDEX_INVALID;
    path_ext->fpe_adj_flags = FIB_PATH_EXT_ADJ_FLAG_NONE;
    path_ext->fpe_type = ext_type;

    fib_path_ext_resolve(path_ext, path_list_index);
}

/**
 * @brief Return true if the label stack is implicit null
 */
static int
fib_path_ext_is_imp_null (fib_path_ext_t *path_ext)
{
    return ((1 == vec_len(path_ext->fpe_label_stack)) &&
	    (MPLS_IETF_IMPLICIT_NULL_LABEL == path_ext->fpe_label_stack[0]));
}

load_balance_path_t *
fib_path_ext_stack (fib_path_ext_t *path_ext,
                    fib_forward_chain_type_t child_fct,
                    fib_forward_chain_type_t imp_null_fct,
		    load_balance_path_t *nhs)
{
    fib_forward_chain_type_t parent_fct;
    load_balance_path_t *nh;

    if (!fib_path_is_resolved(path_ext->fpe_path_index))
	return (nhs);

    /*
     * Since we are stacking this path-extension, it must have a valid out
     * label. From the chain type request by the child, determine what
     * chain type we will request from the parent.
     */
    switch (child_fct)
    {
    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
    {
	/*
	 * The EOS chain is a tricky since, when the path has an imp NULL one cannot know
         * the adjacency to link to without knowing what the packets payload protocol
	 * will be once the label is popped.
	 */
	if (fib_path_ext_is_imp_null(path_ext))
	{
            parent_fct = imp_null_fct;
        }
        else
        {
            /*
             * we have a label to stack. packets will thus be labelled when
             * they encounter the child, ergo, non-eos.
             */
	    parent_fct = FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS;
        }
	break;
    }
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
	if (fib_path_ext_is_imp_null(path_ext))
	{
            /*
             * implicit-null label for the eos or IP chain, need to pick up
             * the IP adj
             */
	    parent_fct = child_fct;
	}
        else
        {
            /*
             * we have a label to stack. packets will thus be labelled when
             * they encounter the child, ergo, non-eos.
             */
	    parent_fct = FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS;
        }
	break;
    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
        parent_fct = child_fct;
	break;
    case FIB_FORW_CHAIN_TYPE_ETHERNET:
        parent_fct = FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS;
	break;
    default:
        return (nhs);
	break;
    }

    dpo_id_t via_dpo = DPO_INVALID;

    /*
     * The next object in the graph after the imposition of the label
     * will be the DPO contributed by the path through which the packets
     * are to be sent. We stack the MPLS Label DPO on this path DPO
     */
    fib_path_contribute_forwarding(path_ext->fpe_path_index,
				   parent_fct,
				   &via_dpo);

    if (dpo_is_drop(&via_dpo) ||
	load_balance_is_drop(&via_dpo))
    {
	/*
	 * don't stack a path extension on a drop. doing so will create
	 * a LB bucket entry on drop, and we will lose a percentage of traffic.
	 */
    }
    else
    {
	vec_add2(nhs, nh, 1);
	nh->path_weight = fib_path_get_weight(path_ext->fpe_path_index);
	nh->path_index = path_ext->fpe_path_index;
	dpo_copy(&nh->path_dpo, &via_dpo);

	/*
	 * The label is stackable for this chain type
	 * construct the mpls header that will be imposed in the data-path
	 */
	if (!fib_path_ext_is_imp_null(path_ext))
	{
            /*
             * we use the parent protocol for the label so that
             * we pickup the correct MPLS imposition nodes to do
             * ip[46] processing.
             */
            dpo_proto_t chain_proto;
            mpls_eos_bit_t eos;
            index_t mldi;

            eos = (child_fct == FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS ?
                   MPLS_NON_EOS :
                   MPLS_EOS);
            chain_proto = fib_forw_chain_type_to_dpo_proto(child_fct);

            mldi = mpls_label_dpo_create(path_ext->fpe_label_stack,
                                         eos, 255, 0,
                                         chain_proto,
                                         &nh->path_dpo);

	    dpo_set(&nh->path_dpo,
		    DPO_MPLS_LABEL,
                    chain_proto,
                    mldi);
	}
    }
    dpo_reset(&via_dpo);

    return (nhs);
}

fib_path_ext_t *
fib_path_ext_list_find (const fib_path_ext_list_t *list,
                        fib_path_ext_type_t ext_type,
                        const fib_route_path_t *rpath)
{
    fib_path_ext_t *path_ext;

    vec_foreach(path_ext, list->fpel_exts)
    {
        if ((path_ext->fpe_type == ext_type) &&
            !fib_path_ext_cmp(path_ext, rpath) )
        {
            return (path_ext);
        }
    }
    return (NULL);
}

fib_path_ext_t *
fib_path_ext_list_find_by_path_index (const fib_path_ext_list_t *list,
                                      fib_node_index_t path_index)
{
    fib_path_ext_t *path_ext;

    vec_foreach(path_ext, list->fpel_exts)
    {
        if (path_ext->fpe_path_index == path_index)
        {
            return (path_ext);
        }
    }
    return (NULL);
}


fib_path_ext_t *
fib_path_ext_list_push_back (fib_path_ext_list_t *list,
                             fib_node_index_t path_list_index,
                             fib_path_ext_type_t ext_type,
                             const fib_route_path_t *rpath)
{
    fib_path_ext_t *path_ext;

    path_ext = fib_path_ext_list_find(list, ext_type, rpath);

    if (NULL == path_ext)
    {
        vec_add2(list->fpel_exts, path_ext, 1);
        fib_path_ext_init(path_ext, path_list_index, ext_type, rpath);
    }

    return (path_ext);
}

/*
 * insert, sorted, a path extension to the entry's list.
 * It's not strictly necessary to sort the path extensions, since each
 * extension has the path index to which it resolves. However, by being
 * sorted the load-balance produced has a deterministic order, not an order
 * based on the sequence of extension additions. this is a considerable benefit.
 */
fib_path_ext_t *
fib_path_ext_list_insert (fib_path_ext_list_t *list,
                          fib_node_index_t path_list_index,
                          fib_path_ext_type_t ext_type,
                          const fib_route_path_t *rpath)
{
    fib_path_ext_t new_path_ext, *path_ext;
    int i = 0;

    if (0 == fib_path_ext_list_length(list))
    {
        return (fib_path_ext_list_push_back(list, path_list_index,
                                            ext_type, rpath));
    }

    fib_path_ext_init(&new_path_ext, path_list_index, ext_type, rpath);

    vec_foreach(path_ext, list->fpel_exts)
    {
        int res = fib_path_ext_cmp(path_ext, rpath);

        if (0 == res)
        {
            /*
             * don't add duplicate extensions. modify instead
             */
            vec_free(path_ext->fpe_label_stack);
            *path_ext = new_path_ext;
            goto done;
        }
        else if (res < 0)
        {
            i++;
        }
        else
        {
            break;
        }
    }
    vec_insert_elts(list->fpel_exts, &new_path_ext, 1, i);
done:
    return (&(list->fpel_exts[i]));
}

void
fib_path_ext_list_resolve (fib_path_ext_list_t *list,
                           fib_node_index_t path_list_index)
{
    fib_path_ext_t *path_ext;

    vec_foreach(path_ext, list->fpel_exts)
    {
        fib_path_ext_resolve(path_ext, path_list_index);
    };
}

void
fib_path_ext_list_remove (fib_path_ext_list_t *list,
                          fib_path_ext_type_t ext_type,
                          const fib_route_path_t *rpath)
{
    fib_path_ext_t *path_ext;

    path_ext = fib_path_ext_list_find(list, ext_type, rpath);

    if (NULL != path_ext)
    {
        /*
         * delete the element moving the remaining elements down 1 position.
         * this preserves the sorted order.
         */
        vec_free(path_ext->fpe_label_stack);
        vec_delete(list->fpel_exts, 1, (path_ext - list->fpel_exts));
    }
}

void
fib_path_ext_list_flush (fib_path_ext_list_t *list)
{
    fib_path_ext_t *path_ext;

    vec_foreach(path_ext, list->fpel_exts)
    {
        vec_free(path_ext->fpe_label_stack);
    };
    vec_free(list->fpel_exts);
    list->fpel_exts = NULL;
}

u8*
format_fib_path_ext_list (u8 * s, va_list * args)
{
    fib_path_ext_list_t *list;
    fib_path_ext_t *path_ext;

    list = va_arg (*args, fib_path_ext_list_t *);

    if (fib_path_ext_list_length(list))
    {
        s = format(s, "    Extensions:");
        vec_foreach(path_ext, list->fpel_exts)
        {
            s = format(s, "\n     %U", format_fib_path_ext, path_ext);
        };
    }

    return (s);
}

int
fib_path_ext_list_length (const fib_path_ext_list_t *list)
{
    return (vec_len(list->fpel_exts));
}
