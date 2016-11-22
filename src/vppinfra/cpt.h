
#ifndef __CPT_H__
#define __CPT_H__

#include <vlib/vlib.h>

#define CPL 128

typedef struct cpt_node_128_t_
{
    u16 cptn_mask_len;

    u32 cptn_nodes[2];
    u32 cptn_cover;
    u32 cptn_value;
    u32 cptn_key_len;
    u128 cptn_key;
    u128 cptn_key_mask;
    u128 cptn_mask;
    u128 cptn_range;
} cpt_node_128_t;

typedef struct cpt_t_
{
    /**
     * €brief A pool for nodes
     */
    cpt_node_128_t *cpt_nodes;

    /**
     * The top/head node - always present
     */
    u32 cpt_top;
} cpt_128_t;

/**
 * Steal the top bit of an index to identify result of node
 */
#define CPT_INDEX_INVALID ~0

extern void cpt_init(cpt_128_t *cpt);

extern void cpt_insert(cpt_128_t *cpt, const u8 *prefix, u32 len, u32 value);

extern u8* format_cpt(u8 * s, va_list * args);

always_inline cpt_node_128_t*
cpt_node_get (const cpt_128_t *cpt,
              u32 ni)
{
    return (pool_elt_at_index(cpt->cpt_nodes, ni));
}

always_inline int
cpt_node_exact_match (const cpt_node_128_t *cptn, const u128 *p)
{
    return ((*(p) & cptn->cptn_mask) == cptn->cptn_range);
}

extern u32 cpt_search_exact(const cpt_128_t *cpt,
                            const u8 *prefix,
                            u32 len);

always_inline u32
cpt_search (const cpt_128_t *cpt,
            const u8 *prefix)
{
    const cpt_node_128_t *cn, *cover;
    u128 result, *p;
    u32 index;

    cn = NULL;
    p = (u128*)prefix;

    index = cpt->cpt_top;
    cover = NULL;

    while (index != CPT_INDEX_INVALID)
    {
        cn = cpt_node_get(cpt, index);

        if ((cn->cptn_key_mask & *p) != cn->cptn_key)
        {
            /*
             * the prefix (key) stored in this node does not match the prefix
             * we are looking for - we've gone too far down the tree. Return
             * the value from the last node visited since that is the LPM.
             */
            return (cover->cptn_value);
        }

        /*
         * is the search key and the stored key equal over the bit range
         * represented by the node.
         */
        result = cpt_node_exact_match(cn, p);

        index = cn->cptn_nodes[result];
        cover = cn;
    }

    return (cn->cptn_value);
}


#endif
