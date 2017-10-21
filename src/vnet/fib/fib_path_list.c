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

#include <vppinfra/mhash.h>
#include <vnet/ip/ip.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_internal.h>
#include <vnet/fib/fib_node_list.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/fib/fib_urpf_list.h>

/**
 * The magic number of child entries that make a path-list popular.
 * There's a trade-off here between convergnece and forwarding speed.
 * Popular path-lists generate load-balance maps for the entires that
 * use them. If the map is present there is a switch path cost to indirect
 * through the map - this indirection provides the fast convergence - so
 * without the map convergence is slower.
 */
#define FIB_PATH_LIST_POPULAR 64

/**
 * FIB path-list
 * A representation of the list/set of path trough which a prefix is reachable
 */
typedef struct fib_path_list_t_ {
    /**
     * A path-list is a node in the FIB graph.
     */
    fib_node_t fpl_node;

    /**
     * Flags on the path-list
     */
    fib_path_list_flags_t fpl_flags;

    /**
     * Vector of paths indicies for all configured paths.
     * For shareable path-lists this list MUST not change.
     */
    fib_node_index_t *fpl_paths;

    /**
     * the RPF list calculated for this path list
     */
    fib_node_index_t fpl_urpf;

    /**
     * Hash table of paths. valid only with INDEXED flag
     */
    uword *fpl_db;
} fib_path_list_t;

/*
 * Array of strings/names for the FIB sources
 */
static const char *fib_path_list_attr_names[] = FIB_PATH_LIST_ATTRIBUTES;

/*
 * The memory pool from which we allocate all the path-lists
 */
static fib_path_list_t * fib_path_list_pool;

/*
 * The data-base of shared path-lists
 */
static uword *fib_path_list_db;

/*
 * Debug macro
 */
#ifdef FIB_DEBUG
#define FIB_PATH_LIST_DBG(_pl, _fmt, _args...)		  \
{   		            				  \
    u8 *_tmp = 0;					  \
    _tmp = fib_path_list_format(			  \
	fib_path_list_get_index(_pl), _tmp);		  \
    clib_warning("pl:[%d:%p:%p:%s]:" _fmt,		  \
		 fib_path_list_get_index(_pl),		  \
		 _pl, _pl->fpl_paths, _tmp,		  \
		 ##_args);				  \
    vec_free(_tmp);					  \
}
#else
#define FIB_PATH_LIST_DBG(_pl, _fmt, _args...)
#endif

static fib_path_list_t *
fib_path_list_get (fib_node_index_t index)
{
    return (pool_elt_at_index(fib_path_list_pool, index));
}

static fib_node_t *
fib_path_list_get_node (fib_node_index_t index)
{
    return ((fib_node_t*)fib_path_list_get(index));
}

static fib_path_list_t*
fib_path_list_from_fib_node (fib_node_t *node)
{
#if CLIB_DEBUG > 0
    ASSERT(FIB_NODE_TYPE_PATH_LIST == node->fn_type);
#endif
    return ((fib_path_list_t*)node);
}

static fib_node_index_t
fib_path_list_get_index (fib_path_list_t *path_list)
{
    return (path_list - fib_path_list_pool);
}

static u8 *
format_fib_path_list (u8 * s, va_list * args)
{
    fib_path_list_attribute_t attr;
    fib_node_index_t *path_index;
    fib_path_list_t *path_list;

    path_list = va_arg (*args, fib_path_list_t *);
    
    s = format (s, "    index:%u", fib_path_list_get_index(path_list));
    s = format (s, " locks:%u", path_list->fpl_node.fn_locks);

    if (FIB_PATH_LIST_FLAG_NONE != path_list->fpl_flags)
    {
	s = format (s, " flags:");
	FOR_EACH_PATH_LIST_ATTRIBUTE(attr)
        {
	    if ((1<<attr) & path_list->fpl_flags)
            {
		s = format (s, "%s,", fib_path_list_attr_names[attr]);
	    }
	}
    }
    s = format (s, " %U\n", format_fib_urpf_list, path_list->fpl_urpf);

    vec_foreach (path_index, path_list->fpl_paths)
    {
	s = fib_path_format(*path_index, s);
	s = format(s, "\n");
    }

    return (s);
}

u8 *
fib_path_list_format (fib_node_index_t path_list_index,
		      u8 * s)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    return (format(s, "%U", format_fib_path_list, path_list));
}

static uword
fib_path_list_hash (fib_path_list_t *path_list)
{
    uword old_path_list_hash, new_path_list_hash, path_hash;
    fib_node_index_t *path_index;

    ASSERT(path_list);

    new_path_list_hash = old_path_list_hash = vec_len(path_list->fpl_paths);

    vec_foreach (path_index, path_list->fpl_paths)
    {
	path_hash = fib_path_hash(*path_index);
#if uword_bits == 64
	hash_mix64(path_hash, old_path_list_hash, new_path_list_hash);
#else
	hash_mix32(path_hash, old_path_list_hash, new_path_list_hash);
#endif
    }

    return (new_path_list_hash);
}

always_inline uword
fib_path_list_db_hash_key_from_index (uword index)
{
    return 1 + 2*index;
}

always_inline uword
fib_path_list_db_hash_key_is_index (uword key)
{
    return key & 1;
}

always_inline uword
fib_path_list_db_hash_key_2_index (uword key)
{
    ASSERT (fib_path_list_db_hash_key_is_index (key));
    return key / 2;
}

static fib_path_list_t*
fib_path_list_db_get_from_hash_key (uword key)
{
    fib_path_list_t *path_list;

    if (fib_path_list_db_hash_key_is_index (key))
    {
	fib_node_index_t path_list_index;

	path_list_index = fib_path_list_db_hash_key_2_index(key);
	path_list = fib_path_list_get(path_list_index);
    }
    else
    {       
	path_list = uword_to_pointer (key, fib_path_list_t *);
    }

    return (path_list);
}

static uword
fib_path_list_db_hash_key_sum (hash_t * h,
			       uword key)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_db_get_from_hash_key(key);

    return (fib_path_list_hash(path_list));
}

static uword
fib_path_list_db_hash_key_equal (hash_t * h,
				 uword key1,
				 uword key2)
{
    fib_path_list_t *path_list1, *path_list2;

    path_list1 = fib_path_list_db_get_from_hash_key(key1);
    path_list2 = fib_path_list_db_get_from_hash_key(key2);

    return (fib_path_list_hash(path_list1) ==
	    fib_path_list_hash(path_list2));
}

static fib_node_index_t
fib_path_list_db_find (fib_path_list_t *path_list)
{
    uword *p;

    p = hash_get(fib_path_list_db, path_list);

    if (NULL != p)
    {
	return p[0];
    }

    return (FIB_NODE_INDEX_INVALID);
}

static void
fib_path_list_db_insert (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    ASSERT(FIB_NODE_INDEX_INVALID == fib_path_list_db_find(path_list));

    hash_set (fib_path_list_db,
	      fib_path_list_db_hash_key_from_index(path_list_index),
	      path_list_index);

    FIB_PATH_LIST_DBG(path_list, "DB-inserted");
}

static void
fib_path_list_db_remove (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    ASSERT(FIB_NODE_INDEX_INVALID != fib_path_list_db_find(path_list));

    hash_unset(fib_path_list_db,
	       fib_path_list_db_hash_key_from_index(path_list_index));

    FIB_PATH_LIST_DBG(path_list, "DB-removed");
}

static void
fib_path_list_destroy (fib_path_list_t *path_list)
{
    fib_node_index_t *path_index;

    FIB_PATH_LIST_DBG(path_list, "destroy");

    vec_foreach (path_index, path_list->fpl_paths)
    {
	fib_path_destroy(*path_index);
    }

    vec_free(path_list->fpl_paths);
    fib_urpf_list_unlock(path_list->fpl_urpf);

    fib_node_deinit(&path_list->fpl_node);
    pool_put(fib_path_list_pool, path_list);
}

static void
fib_path_list_last_lock_gone (fib_node_t *node)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_from_fib_node(node);

    FIB_PATH_LIST_DBG(path_list, "last-lock");

    if (path_list->fpl_flags & FIB_PATH_LIST_FLAG_SHARED)
    {
	fib_path_list_db_remove(fib_path_list_get_index(path_list));
    }
    fib_path_list_destroy(path_list);
}

/*
 * fib_path_mk_lb
 *
 * update the multipath adj this path-list will contribute to its
 * children's forwarding.
 */
static void
fib_path_list_mk_lb (fib_path_list_t *path_list,
		     fib_forward_chain_type_t fct,
		     dpo_id_t *dpo)
{
    load_balance_path_t *nhs;
    fib_node_index_t *path_index;

    nhs  = NULL;

    if (!dpo_id_is_valid(dpo))
    {
        /*
         * first time create
         */
        dpo_set(dpo,
                DPO_LOAD_BALANCE,
                fib_forw_chain_type_to_dpo_proto(fct),
                load_balance_create(0,
				    fib_forw_chain_type_to_dpo_proto(fct),
				    0 /* FIXME FLOW HASH */));
    }

    /*
     * We gather the DPOs from resolved paths.
     */
    vec_foreach (path_index, path_list->fpl_paths)
    {
	nhs = fib_path_append_nh_for_multipath_hash(*path_index,
                                                    fct,
                                                    nhs);
    }

    /*
     * Path-list load-balances, which if used, would be shared and hence
     * never need a load-balance map.
     */
    load_balance_multipath_update(dpo, nhs, LOAD_BALANCE_FLAG_NONE);

    FIB_PATH_LIST_DBG(path_list, "mk lb: %d", dpo->dpoi_index);

    vec_free(nhs);
}

/**
 * @brief [re]build the path list's uRPF list
 */
static void
fib_path_list_mk_urpf (fib_path_list_t *path_list)
{
    fib_node_index_t *path_index;

    /*
     * ditch the old one. by iterating through all paths we are going
     * to re-find all the adjs that were in the old one anyway. If we
     * keep the old one, then the |sort|uniq requires more work.
     * All users of the RPF list have their own lock, so we can release
     * immediately.
     */
    fib_urpf_list_unlock(path_list->fpl_urpf);
    path_list->fpl_urpf = fib_urpf_list_alloc_and_lock();

    vec_foreach (path_index, path_list->fpl_paths)
    {
	fib_path_contribute_urpf(*path_index, path_list->fpl_urpf);
    }

    fib_urpf_list_bake(path_list->fpl_urpf);
}

/**
 * @brief Contribute (add) this path list's uRPF list. This allows the child
 * to construct an aggregate list.
 */
void
fib_path_list_contribute_urpf (fib_node_index_t path_list_index,
			       index_t urpf)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    fib_urpf_list_combine(urpf, path_list->fpl_urpf);
}

/**
 * @brief Return the the child the RPF list pre-built for this path list
 */
index_t
fib_path_list_get_urpf (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    return (path_list->fpl_urpf);
}

/*
 * fib_path_list_back_walk
 *
 * Called from one of this path-list's paths to progate
 * a back walk
 */
void
fib_path_list_back_walk (fib_node_index_t path_list_index,
			 fib_node_back_walk_ctx_t *ctx)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    fib_path_list_mk_urpf(path_list);

    /*
     * propagate the backwalk further
     */
    if (path_list->fpl_flags & FIB_PATH_LIST_FLAG_POPULAR)
    {
        /*
         * many children. schedule a async walk
         */
        fib_walk_async(FIB_NODE_TYPE_PATH_LIST,
                       path_list_index,
                       FIB_WALK_PRIORITY_LOW,
                       ctx);
    }
    else
    {
        /*
         * only a few children. continue the walk synchronously
         */
	fib_walk_sync(FIB_NODE_TYPE_PATH_LIST, path_list_index, ctx);
    }
}

/*
 * fib_path_list_back_walk_notify
 *
 * A back walk has reach this path-list.
 */
static fib_node_back_walk_rc_t
fib_path_list_back_walk_notify (fib_node_t *node,
				fib_node_back_walk_ctx_t *ctx)
{
    /*
     * the path-list is not a direct child of any other node type
     * paths, which do not change thier to-list-mapping, save the
     * list they are a member of, and invoke the BW function directly.
     */
    ASSERT(0);

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * Display the path-list memory usage
 */
static void
fib_path_list_memory_show (void)
{
    fib_show_memory_usage("Path-list",
			  pool_elts(fib_path_list_pool),
			  pool_len(fib_path_list_pool),
			  sizeof(fib_path_list_t));
    fib_urpf_list_show_mem();
}

/*
 * The FIB path-list's graph node virtual function table
 */
static const fib_node_vft_t fib_path_list_vft = {
    .fnv_get = fib_path_list_get_node,
    .fnv_last_lock = fib_path_list_last_lock_gone,
    .fnv_back_walk = fib_path_list_back_walk_notify,
    .fnv_mem_show = fib_path_list_memory_show,
};

static inline fib_path_list_t *
fib_path_list_alloc (fib_node_index_t *path_list_index)
{
    fib_path_list_t *path_list;

    pool_get(fib_path_list_pool, path_list);
    memset(path_list, 0, sizeof(*path_list));

    fib_node_init(&path_list->fpl_node,
		  FIB_NODE_TYPE_PATH_LIST);
    path_list->fpl_urpf = INDEX_INVALID;
    path_list->fpl_paths = NULL;

    *path_list_index = fib_path_list_get_index(path_list);

    FIB_PATH_LIST_DBG(path_list, "alloc");

    return (path_list);
}

static fib_path_list_t *
fib_path_list_resolve (fib_path_list_t *path_list)
{
    fib_node_index_t *path_index, *paths, path_list_index;

    ASSERT(!(path_list->fpl_flags & FIB_PATH_LIST_FLAG_RESOLVED));

    /*
     * resolving a path-list is a recursive action. this means more path
     * lists can be created during this call, and hence this path-list
     * can be realloc'd. so we work with copies.
     * this function is called only once per-path list, so its no great overhead.
     */
    path_list_index = fib_path_list_get_index(path_list);
    paths = vec_dup(path_list->fpl_paths);

    vec_foreach (path_index, paths)
    {
	fib_path_resolve(*path_index);
    }

    vec_free(paths);
    path_list = fib_path_list_get(path_list_index);

    FIB_PATH_LIST_DBG(path_list, "resovled");

    if (!(path_list->fpl_flags & FIB_PATH_LIST_FLAG_NO_URPF))
    {
        fib_path_list_mk_urpf(path_list);
    }
    return (path_list);
}

u32
fib_path_list_get_n_paths (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    if (FIB_NODE_INDEX_INVALID == path_list_index)
    {
        return (0);
    }

    path_list = fib_path_list_get(path_list_index);

    return (vec_len(path_list->fpl_paths));
}


u32
fib_path_list_get_resolving_interface (fib_node_index_t path_list_index)
{
    fib_node_index_t *path_index;
    fib_path_list_t *path_list;
    u32 sw_if_index;

    path_list = fib_path_list_get(path_list_index);

    sw_if_index = ~0;
    vec_foreach (path_index, path_list->fpl_paths)
    {
	sw_if_index = fib_path_get_resolving_interface(*path_index);
	if (~0 != sw_if_index)
	{
	    return (sw_if_index);
	}
    }

    return (sw_if_index);
}

dpo_proto_t
fib_path_list_get_proto (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    /*
     * we don't support a mix of path protocols, so we can return the proto
     * of the first
     */
    return (fib_path_get_proto(path_list->fpl_paths[0]));
}

int
fib_path_list_is_looped (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    return (path_list->fpl_flags & FIB_PATH_LIST_FLAG_LOOPED);
}

int
fib_path_list_is_popular (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    return (path_list->fpl_flags & FIB_PATH_LIST_FLAG_POPULAR);
}

static fib_path_list_flags_t
fib_path_list_flags_fixup (fib_path_list_flags_t flags)
{
    /*
     * we do no share drop nor exclusive path-lists
     */
    if (flags & FIB_PATH_LIST_FLAG_DROP ||
	flags & FIB_PATH_LIST_FLAG_EXCLUSIVE)
    {
	flags &= ~FIB_PATH_LIST_FLAG_SHARED;
    }

    return (flags);
}

fib_node_index_t
fib_path_list_create (fib_path_list_flags_t flags,
		      const fib_route_path_t *rpaths)
{
    fib_node_index_t path_list_index, old_path_list_index;
    fib_path_list_t *path_list;
    int i;

    flags = fib_path_list_flags_fixup(flags);
    path_list = fib_path_list_alloc(&path_list_index);
    path_list->fpl_flags = flags;

    if (NULL != rpaths)
    {
        vec_foreach_index(i, rpaths)
        {
            vec_add1(path_list->fpl_paths,
                     fib_path_create(path_list_index,
                                     &rpaths[i]));
        }
        /*
         * we sort the paths since the key for the path-list is
         * the description of the paths it contains. The paths need to
         * be sorted else this description will differ.
         */
        if (vec_len(path_list->fpl_paths) > 1)
        {
            vec_sort_with_function(path_list->fpl_paths,
                                   fib_path_cmp_for_sort);
        }
    }

    /*
     * If a shared path list is requested, consult the DB for a match
     */
    if (flags & FIB_PATH_LIST_FLAG_SHARED)
    {
	/*
	 * check for a matching path-list in the DB.
	 * If we find one then we can return the existing one and destroy the
	 * new one just created.
	 */
	old_path_list_index = fib_path_list_db_find(path_list);
	if (FIB_NODE_INDEX_INVALID != old_path_list_index)
	{
	    fib_path_list_destroy(path_list);
	
	    path_list_index = old_path_list_index;
	}
	else
	{
	    /*
	     * if there was not a matching path-list, then this
	     * new one will need inserting into the DB and resolving.
	     */
	    fib_path_list_db_insert(path_list_index);
	    path_list = fib_path_list_resolve(path_list);
	}
    }
    else
    {
	/*
	 * no shared path list requested. resolve and use the one
	 * just created.
	 */
	path_list = fib_path_list_resolve(path_list);
    }

    return (path_list_index);
}

static fib_path_cfg_flags_t 
fib_path_list_flags_2_path_flags (fib_path_list_flags_t plf)
{
    fib_path_cfg_flags_t pf = FIB_PATH_CFG_FLAG_NONE;

    if (plf & FIB_PATH_LIST_FLAG_DROP)
    {
	pf |= FIB_PATH_CFG_FLAG_DROP;
    }
    if (plf & FIB_PATH_LIST_FLAG_EXCLUSIVE)
    {
	pf |= FIB_PATH_CFG_FLAG_EXCLUSIVE;
    }
    if (plf & FIB_PATH_LIST_FLAG_LOCAL)
    {
        pf |= FIB_PATH_CFG_FLAG_LOCAL;
    }

    return (pf);
}

fib_node_index_t
fib_path_list_create_special (dpo_proto_t nh_proto,
			      fib_path_list_flags_t flags,
			      const dpo_id_t *dpo)
{
    fib_node_index_t path_index, path_list_index;
    fib_path_list_t *path_list;

    path_list = fib_path_list_alloc(&path_list_index);
    path_list->fpl_flags = flags;

    path_index =
	fib_path_create_special(path_list_index,
                                nh_proto,
				fib_path_list_flags_2_path_flags(flags),
				dpo);
    vec_add1(path_list->fpl_paths, path_index);

    /*
     * we don't share path-lists. we can do PIC on them so why bother.
     */
    path_list = fib_path_list_resolve(path_list);

    return (path_list_index);
}

/*
 * return the index info the path-lists's vector of paths, of the matching path.
 * ~0 if not found
 */
u32
fib_path_list_find_rpath (fib_node_index_t path_list_index,
                          const fib_route_path_t *rpath)
{
    fib_path_list_t *path_list;
    u32 ii;

    path_list = fib_path_list_get(path_list_index);

    vec_foreach_index (ii, path_list->fpl_paths)
    {
        if (!fib_path_cmp_w_route_path(path_list->fpl_paths[ii], rpath))
        {
            return (ii);
        }
    }
    return (~0);
}


/*
 * fib_path_list_copy_and_path_add
 *
 * Create a copy of a path-list and append one more path to it.
 * The path-list returned could either have been newly created, or
 * can be a shared path-list from the data-base.
 */
fib_node_index_t
fib_path_list_path_add (fib_node_index_t path_list_index,
                        const fib_route_path_t *rpaths)
{
    fib_node_index_t new_path_index, *orig_path_index;
    fib_path_list_t *path_list;

    /*
     * alloc the new list before we retrieve the old one, lest
     * the alloc result in a realloc
     */
    path_list = fib_path_list_get(path_list_index);

    ASSERT(1 == vec_len(rpaths));
    ASSERT(!(path_list->fpl_flags & FIB_PATH_LIST_FLAG_SHARED));

    FIB_PATH_LIST_DBG(orig_path_list, "path-add");

    new_path_index = fib_path_create(path_list_index,
                                     rpaths);

    vec_foreach (orig_path_index, path_list->fpl_paths)
    {
        /*
         * don't add duplicate paths
         */
	if (0 == fib_path_cmp(new_path_index, *orig_path_index))
        {
            fib_path_destroy(new_path_index);
            return (*orig_path_index);
        }
    }

    /*
     * Add the new path - no sort, no sharing, no key..
     */
    vec_add1(path_list->fpl_paths, new_path_index);

    FIB_PATH_LIST_DBG(path_list, "path-added");

    /*
     * no shared path list requested. resolve and use the one
     * just created.
     */
    fib_path_resolve(new_path_index);

    return (new_path_index);
}

fib_node_index_t
fib_path_list_copy_and_path_add (fib_node_index_t orig_path_list_index,
                                 fib_path_list_flags_t flags,
                                 const fib_route_path_t *rpaths)
{
    fib_node_index_t path_index, new_path_index, *orig_path_index;
    fib_path_list_t *path_list, *orig_path_list;
    fib_node_index_t exist_path_list_index;
    fib_node_index_t path_list_index;
    fib_node_index_t pi;

    ASSERT(1 == vec_len(rpaths));

    /*
     * alloc the new list before we retrieve the old one, lest
     * the alloc result in a realloc
     */
    path_list = fib_path_list_alloc(&path_list_index);

    orig_path_list = fib_path_list_get(orig_path_list_index);

    FIB_PATH_LIST_DBG(orig_path_list, "copy-add");

    flags = fib_path_list_flags_fixup(flags);
    path_list->fpl_flags = flags;

    vec_validate(path_list->fpl_paths, vec_len(orig_path_list->fpl_paths));
    pi = 0;

    new_path_index = fib_path_create(path_list_index,
                                     rpaths);

    vec_foreach (orig_path_index, orig_path_list->fpl_paths)
    {
        /*
         * don't add duplicate paths
         * In the unlikely event the path is a duplicate, then we'll
         * find a matching path-list later and this one will be toast.
         */
	if (0 != fib_path_cmp(new_path_index, *orig_path_index))
        {
            path_index = fib_path_copy(*orig_path_index, path_list_index);
            path_list->fpl_paths[pi++] = path_index;
        }
        else
        {
            _vec_len(path_list->fpl_paths) = vec_len(orig_path_list->fpl_paths);
        }
    }

    path_list->fpl_paths[pi] = new_path_index;

    /*
     * we sort the paths since the key for the path-list is
     * the description of the paths it contains. The paths need to
     * be sorted else this description will differ.
     */
    vec_sort_with_function(path_list->fpl_paths, fib_path_cmp_for_sort);

    FIB_PATH_LIST_DBG(path_list, "path-added");

    /*
     * check for a matching path-list in the DB.
     * If we find one then we can return the existing one and destroy the
     * new one just created.
     */
    if (path_list->fpl_flags & FIB_PATH_LIST_FLAG_SHARED)
    {
        exist_path_list_index = fib_path_list_db_find(path_list);
        if (FIB_NODE_INDEX_INVALID != exist_path_list_index)
        {
            fib_path_list_destroy(path_list);
	
            path_list_index = exist_path_list_index;
        }
        else
        {
            /*
             * if there was not a matching path-list, then this
             * new one will need inserting into the DB and resolving.
             */
            fib_path_list_db_insert(path_list_index);

            path_list = fib_path_list_resolve(path_list);
        }
    }
    else
    {
        /*
         * no shared path list requested. resolve and use the one
         * just created.
         */
        path_list = fib_path_list_resolve(path_list);
    }

    return (path_list_index);
}

/*
 * fib_path_list_path_remove
 */
fib_node_index_t
fib_path_list_path_remove (fib_node_index_t path_list_index,
                           const fib_route_path_t *rpaths)
{
    fib_node_index_t match_path_index, tmp_path_index;
    fib_path_list_t *path_list;
    fib_node_index_t pi;

    path_list = fib_path_list_get(path_list_index);

    ASSERT(1 == vec_len(rpaths));
    ASSERT(!(path_list->fpl_flags & FIB_PATH_LIST_FLAG_SHARED));

    FIB_PATH_LIST_DBG(orig_path_list, "path-remove");

    /*
     * create a representation of the path to be removed, so it
     * can be used as a comparison object during the copy.
     */
    tmp_path_index = fib_path_create(path_list_index,
				     rpaths);
    match_path_index = FIB_NODE_INDEX_INVALID;

    vec_foreach_index (pi, path_list->fpl_paths)
    {
	if (0 == fib_path_cmp(tmp_path_index,
                              path_list->fpl_paths[pi]))
        {
            /*
             * match - remove it
             */
            match_path_index = path_list->fpl_paths[pi];
            fib_path_destroy(match_path_index);
            vec_del1(path_list->fpl_paths, pi);
	}
    }

    /*
     * done with the temporary now
     */
    fib_path_destroy(tmp_path_index);

    return (match_path_index);
}

/*
 * fib_path_list_copy_and_path_remove
 *
 * Copy the path-list excluding the path passed.
 * If the path is the last one, then the index reurned will be invalid.
 * i.e. the path-list is toast.
 */
fib_node_index_t
fib_path_list_copy_and_path_remove (fib_node_index_t orig_path_list_index,
				    fib_path_list_flags_t flags,
				    const fib_route_path_t *rpaths)
{
    fib_node_index_t path_index, *orig_path_index, path_list_index, tmp_path_index;
    fib_path_list_t *path_list,  *orig_path_list;
    fib_node_index_t pi;

    ASSERT(1 == vec_len(rpaths));

    path_list = fib_path_list_alloc(&path_list_index);

    flags = fib_path_list_flags_fixup(flags);
    orig_path_list = fib_path_list_get(orig_path_list_index);

    FIB_PATH_LIST_DBG(orig_path_list, "copy-remove");

    path_list->fpl_flags = flags;
    /*
     * allocate as many paths as we might need in one go, rather than
     * using vec_add to do a few at a time.
     */
    if (vec_len(orig_path_list->fpl_paths) > 1)
    {
	vec_validate(path_list->fpl_paths, vec_len(orig_path_list->fpl_paths) - 2);
    }
    pi = 0;

    /*
     * create a representation of the path to be removed, so it
     * can be used as a comparison object during the copy.
     */
    tmp_path_index = fib_path_create(path_list_index,
				     rpaths);

    vec_foreach (orig_path_index, orig_path_list->fpl_paths)
    {
	if (0 != fib_path_cmp(tmp_path_index, *orig_path_index)) {
	    path_index = fib_path_copy(*orig_path_index, path_list_index);
	    if (pi < vec_len(path_list->fpl_paths))
	    {
		path_list->fpl_paths[pi++] = path_index;
	    }
	    else
	    {
		/*
		 * this is the unlikely case that the path being
		 * removed does not match one in the path-list, so
		 * we end up with as many paths as we started with.
		 * the paths vector was sized above with the expectation
		 * that we would have 1 less.
		 */
		vec_add1(path_list->fpl_paths, path_index);
	    }
	}
    }

    /*
     * done with the temporary now
     */
    fib_path_destroy(tmp_path_index);

    /*
     * if there are no paths, then the new path-list is aborted
     */
    if (0 == vec_len(path_list->fpl_paths)) {
	FIB_PATH_LIST_DBG(path_list, "last-path-removed");

	fib_path_list_destroy(path_list);

	path_list_index = FIB_NODE_INDEX_INVALID;
    } else {
	/*
	 * we sort the paths since the key for the path-list is
	 * the description of the paths it contains. The paths need to
	 * be sorted else this description will differ.
	 */
	vec_sort_with_function(path_list->fpl_paths, fib_path_cmp_for_sort);
    
	/*
	 * If a shared path list is requested, consult the DB for a match
	 */
	if (path_list->fpl_flags & FIB_PATH_LIST_FLAG_SHARED)
	{
	    fib_node_index_t exist_path_list_index;

            /*
	     * check for a matching path-list in the DB.
	     * If we find one then we can return the existing one and destroy the
	     * new one just created.
	     */
	    exist_path_list_index = fib_path_list_db_find(path_list);
	    if (FIB_NODE_INDEX_INVALID != exist_path_list_index)
	    {
		fib_path_list_destroy(path_list);
	
		path_list_index = exist_path_list_index;
	    }
	    else
	    {
		/*
		 * if there was not a matching path-list, then this
		 * new one will need inserting into the DB and resolving.
		 */
		fib_path_list_db_insert(path_list_index);

		path_list = fib_path_list_resolve(path_list);
	    }
	}
	else
	{
	    /*
	     * no shared path list requested. resolve and use the one
	     * just created.
	     */
	    path_list = fib_path_list_resolve(path_list);
	}
    }

    return (path_list_index);
}

/*
 * fib_path_list_contribute_forwarding
 *
 * Return the index of a load-balance that user of this path-list should
 * use for forwarding
 */
void
fib_path_list_contribute_forwarding (fib_node_index_t path_list_index,
				     fib_forward_chain_type_t fct,
				     dpo_id_t *dpo)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    fib_path_list_mk_lb(path_list, fct, dpo);
}

/*
 * fib_path_list_get_adj
 *
 * Return the index of a adjacency for the first path that user of this
 * path-list should use for forwarding
 */
adj_index_t
fib_path_list_get_adj (fib_node_index_t path_list_index,
		       fib_forward_chain_type_t type)
{
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);
    return (fib_path_get_adj(path_list->fpl_paths[0]));
}

int
fib_path_list_recursive_loop_detect (fib_node_index_t path_list_index,
				     fib_node_index_t **entry_indicies)
{
    fib_node_index_t *path_index;
    int is_looped, list_looped;
    fib_path_list_t *path_list;

    list_looped = 0;
    path_list = fib_path_list_get(path_list_index);

    vec_foreach (path_index, path_list->fpl_paths)
    {
	fib_node_index_t *copy, **copy_ptr;

	/*
	 * we need a copy of the nodes visited so that when we add entries
	 * we explore on the nth path and a looped is detected, those entries
	 * are not again searched for n+1 path and so finding a loop that does
	 * not exist.
	 */
	copy = vec_dup(*entry_indicies);
	copy_ptr = &copy;

	is_looped  = fib_path_recursive_loop_detect(*path_index, copy_ptr);
	list_looped += is_looped;
    }

    FIB_PATH_LIST_DBG(path_list, "loop-detect: eval:%d", eval);

    if (list_looped)
    {
	path_list->fpl_flags |= FIB_PATH_LIST_FLAG_LOOPED;
    }
    else
    {
	path_list->fpl_flags &= ~FIB_PATH_LIST_FLAG_LOOPED;
    }

    return (list_looped);
}

u32
fib_path_list_child_add (fib_node_index_t path_list_index,
			 fib_node_type_t child_type,
			 fib_node_index_t child_index)
{
    u32 sibling;

    sibling = fib_node_child_add(FIB_NODE_TYPE_PATH_LIST,
                                 path_list_index,
                                 child_type,
                                 child_index);

    if (FIB_PATH_LIST_POPULAR == fib_node_get_n_children(FIB_NODE_TYPE_PATH_LIST,
                                                         path_list_index))
    {
        /*
         * Set the popular flag on the path-list once we pass the magic
         * threshold. then walk children to update.
         * We don't undo this action. The rational being that the number
         * of entries using this prefix is large enough such that it is a
         * non-trival amount of effort to converge them. If we get into the
         * situation where we are adding and removing entries such that we
         * flip-flop over the threshold, then this non-trivial work is added
         * to each of those routes adds/deletes - not a situation we want.
         */
        fib_node_back_walk_ctx_t ctx = {
            .fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
        };
        fib_path_list_t *path_list;

        path_list = fib_path_list_get(path_list_index);
        path_list->fpl_flags |= FIB_PATH_LIST_FLAG_POPULAR;

	fib_walk_sync(FIB_NODE_TYPE_PATH_LIST, path_list_index, &ctx);
    }

    return (sibling);
}

void
fib_path_list_child_remove (fib_node_index_t path_list_index,
			    u32 si)
{
    fib_node_child_remove(FIB_NODE_TYPE_PATH_LIST,
                          path_list_index,
                          si);
}

void
fib_path_list_lock(fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    if (FIB_NODE_INDEX_INVALID != path_list_index)
    {
	path_list = fib_path_list_get(path_list_index);

	fib_node_lock(&path_list->fpl_node);
	FIB_PATH_LIST_DBG(path_list, "lock");
    }
}

void
fib_path_list_unlock (fib_node_index_t path_list_index)
{
    fib_path_list_t *path_list;

    if (FIB_NODE_INDEX_INVALID != path_list_index)
    {
	path_list = fib_path_list_get(path_list_index);
	FIB_PATH_LIST_DBG(path_list, "unlock");
    
	fib_node_unlock(&path_list->fpl_node);
    }
}

u32
fib_path_list_pool_size (void)
{
    return (pool_elts(fib_path_list_pool));    
}

u32
fib_path_list_db_size (void)
{
    return (hash_elts(fib_path_list_db));
}

void
fib_path_list_walk (fib_node_index_t path_list_index,
		    fib_path_list_walk_fn_t func,
		    void *ctx)
{
    fib_node_index_t *path_index;
    fib_path_list_t *path_list;

    path_list = fib_path_list_get(path_list_index);

    vec_foreach(path_index, path_list->fpl_paths)
    {
	if (FIB_PATH_LIST_WALK_STOP == func(path_list_index,
                                            *path_index,
                                            ctx))
	    break;
    }
}


void
fib_path_list_module_init (void)
{
    fib_node_register_type (FIB_NODE_TYPE_PATH_LIST, &fib_path_list_vft);

    fib_path_list_db = hash_create2 (/* elts */ 0,
    				     /* user */ 0,
    				     /* value_bytes */ sizeof (fib_node_index_t),
    				     fib_path_list_db_hash_key_sum,
    				     fib_path_list_db_hash_key_equal,
    				     /* format pair/arg */
    				     0, 0);
}

static clib_error_t *
show_fib_path_list_command (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
    fib_path_list_t *path_list;
    fib_node_index_t pli;

    if (unformat (input, "%d", &pli))
    {
	/*
	 * show one in detail
	 */
	if (!pool_is_free_index(fib_path_list_pool, pli))
	{
	    path_list = fib_path_list_get(pli);
	    u8 *s = fib_path_list_format(pli, NULL);
	    s = format(s, "children:");
	    s = fib_node_children_format(path_list->fpl_node.fn_children, s);
	    vlib_cli_output (vm, "%s", s);
	    vec_free(s);
	}
	else
	{
	    vlib_cli_output (vm, "path list %d invalid", pli);
	}
    }
    else
    {
	/*
	 * show all
	 */
	vlib_cli_output (vm, "FIB Path Lists");
	pool_foreach(path_list, fib_path_list_pool,
	({
	    vlib_cli_output (vm, "%U", format_fib_path_list, path_list);
	}));
    }
    return (NULL);
}

VLIB_CLI_COMMAND (show_fib_path_list, static) = {
  .path = "show fib path-lists",
  .function = show_fib_path_list_command,
  .short_help = "show fib path-lists",
};
