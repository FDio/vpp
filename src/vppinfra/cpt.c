
#include <vppinfra/cpt.h>

#define MIN(x,y) (((x)<(y))?(x):(y))
#define MAX(x,y) (((x)>(y))?(x):(y))

static void
cpt_node_update (cpt_node_128_t *cptn,
                 u32 mask_len)
{
    u32 ii;

    cptn->cptn_mask_len = mask_len;
    cptn->cptn_mask = 0;

    for (ii = 0; ii < mask_len; ii++)
        cptn->cptn_mask |= ((u128)1) << (127 - ii);

    cptn->cptn_range = cptn->cptn_key & cptn->cptn_mask;
}


static cpt_node_128_t *
cpt_node_alloc (cpt_128_t *cpt,
                u32 mask_len,
                const u128 *p,
                u32 len,
                u32 value)
{
    cpt_node_128_t *cptn;
    u32 ii;

    pool_get(cpt->cpt_nodes, cptn);

    cptn->cptn_mask_len = mask_len;
    cptn->cptn_key = *p;
    cptn->cptn_key_len = len;
    for (ii = 0; ii < len; ii++)
        cptn->cptn_key_mask |= ((u128)1) << (127 - ii);

    cptn->cptn_value = value;
    cptn->cptn_nodes[0] = CPT_INDEX_INVALID;
    cptn->cptn_nodes[1] = CPT_INDEX_INVALID;

    cpt_node_update(cptn, mask_len);

    return (cptn);
}

static u32
cpt_node_get_index (cpt_128_t *cpt,
                    cpt_node_128_t *cptn)
{
    return (cptn - cpt->cpt_nodes);
}


void
cpt_init (cpt_128_t *cpt)
{
    cpt_node_128_t *top;
    u128 p = 0;

    cpt->cpt_nodes = NULL;
    cpt->cpt_top = ~0;

    top = cpt_node_alloc(cpt, 0, &p, 0, CPT_INDEX_INVALID);

    top->cptn_cover = CPT_INDEX_INVALID;
    top->cptn_value = CPT_INDEX_INVALID;

    cpt->cpt_top = cpt_node_get_index(cpt, top);
}

static u8*
format_cpt_node (u8 * s, va_list * args)
{
    cpt_128_t *cpt = va_arg (*args, cpt_128_t *);
    u32 index = va_arg (*args, u32);
    u32 indent = va_arg (*args, u32);

    cpt_node_128_t *cptn;

    cptn = cpt_node_get(cpt, index);

    s = format(s, "ml:%d value:%d key:[%llx][%llx]/%d\n",
               cptn->cptn_mask_len,
               cptn->cptn_value,
               ((u64*)&cptn->cptn_key)[0],
               ((u64*)&cptn->cptn_key)[1],
               cptn->cptn_key_len);

    if (CPT_INDEX_INVALID != cptn->cptn_nodes[0])
    {
        s = format(s, "%U0: %U",
                   format_white_space, indent,
                   format_cpt_node, cpt, cptn->cptn_nodes[0], indent+1);
    }
    if (CPT_INDEX_INVALID != cptn->cptn_nodes[1])
    {
        s = format(s, "%U1: %U",
                   format_white_space, indent,
                   format_cpt_node, cpt, cptn->cptn_nodes[1], indent+1);
    }

    return (s);
}

u8*
format_cpt (u8 * s, va_list * args)
{
    cpt_128_t *cpt = va_arg (*args, cpt_128_t *);

    s = format(s, "Compressed Patricia Tree:\n");

    s = format(s, "%U", format_cpt_node, cpt, cpt->cpt_top, 1);

    return (s);
}

static void
cpt_node_wedge (cpt_128_t *cpt,
                cpt_node_128_t *old,
                const u128 *p,
                u32 len,
                u32 value)
{
    /*
     * Wedge (insert) a new node for p inbetween the node passed and
     * its cover.
     * We are allocating new nodes so we need to handle possible reallos
     */
    cpt_node_128_t *cover, *new;
    u32 ni;

    ni = cpt_node_get_index(cpt, old);
    cover = cpt_node_get(cpt, old->cptn_cover);

    /*
     * the cover chooses between the two nodes based on the shorter mask len
     */
    cpt_node_update(cover, MIN(len, old->cptn_key_len));

    /*
     * the mask in the new node is equal to the prefix it represents
     */
    new = cpt_node_alloc(cpt, len, p, len, value);

    /*
     * the cover has its mask reduced to the number of bits in common
     * with the shorter mask prefix + 1.
     * If the new nad old node both match the cover's mask, then the
     * old is covered by the new, else, the old and new are a hit and miss resp
     */
    old = cpt_node_get(cpt, ni);
    cover = cpt_node_get(cpt, old->cptn_cover);

    /*
     * If the old and the new node both match on the cover, then the
     * new is inserted inbetween the two
     */
    if (cpt_node_exact_match(cover, &old->cptn_key) &&
        cpt_node_exact_match(cover, &new->cptn_key))
    {
        cpt_node_update(new, old->cptn_key_len);
        new->cptn_cover = cpt_node_get_index(cpt, cover);
        old->cptn_cover = cpt_node_get_index(cpt, new);

        cover->cptn_nodes[1] = cpt_node_get_index(cpt, new);

        if (cpt_node_exact_match(new, &old->cptn_key))
        {
            new->cptn_nodes[1] = cpt_node_get_index(cpt, old);
        }
        else
        {
            new->cptn_nodes[0] = cpt_node_get_index(cpt, old);
        }
    }
    else
    {
        new->cptn_cover = cpt_node_get_index(cpt, cover);
        old->cptn_cover = cpt_node_get_index(cpt, cover);

        /*
         * set which is the hit and which the miss
         */
        if (cpt_node_exact_match(cover, &new->cptn_key))
        {
            cover->cptn_nodes[1] = cpt_node_get_index(cpt, new);
            cover->cptn_nodes[0] = cpt_node_get_index(cpt, old);
        }
        else
        {
            cover->cptn_nodes[1] = cpt_node_get_index(cpt, old);
            cover->cptn_nodes[0] = cpt_node_get_index(cpt, new);
        }
    }
}

static u32
cpt_node_n_bits_common (cpt_node_128_t *n1,
                        cpt_node_128_t *n2)
{
    u128 mask;
    u32 n_bits;

    n_bits = 0;
    mask = ((u128)1) << 127;

    while ((n1->cptn_key & mask) == (n2->cptn_key & mask))
        mask |= ((u128)1) << (127 - ++n_bits);

    return (n_bits);
}

static void
cpt_node_set_descendents (cpt_128_t *cpt,
                          cpt_node_128_t *cover,
                          cpt_node_128_t *d1,
                          cpt_node_128_t *d2)
{
    cpt_node_update(cover, MIN(d1->cptn_mask_len,
                               d2->cptn_mask_len));
    /*
     * set which is the hit and which the miss
     */
    if (cpt_node_exact_match(cover, &d1->cptn_key))
    {
        cover->cptn_nodes[1] = cpt_node_get_index(cpt, d1);
        cover->cptn_nodes[0] = cpt_node_get_index(cpt, d2);
    }
    else
    {
        cover->cptn_nodes[1] = cpt_node_get_index(cpt, d2);
        cover->cptn_nodes[0] = cpt_node_get_index(cpt, d1);
    }
}

static void
cpt_node_fork (cpt_128_t *cpt,
               u32 ni,
               const u128 *p,
               u32 len,
               u32 value)
{
    cpt_node_128_t *cover, *forked, *d1, *d2, *d3;
    u32 ni2, n_bits1, n_bits2;

    d1 = cpt_node_alloc(cpt, len, p, len, value);
    ni2 = cpt_node_get_index(cpt, d1);

    forked = cpt_node_alloc(cpt, len, p, len, CPT_INDEX_INVALID);
    forked->cptn_cover = ni;

    cover = cpt_node_get(cpt, ni);
    d1 = cpt_node_get(cpt, ni2);
    d2 = cpt_node_get(cpt, cover->cptn_nodes[0]);
    d3 = cpt_node_get(cpt, cover->cptn_nodes[1]);

    /*
     * going from
     *    cover
     *     / \
     *    d2 d3
     *
     * The the correct arragement of:
     *     cover
     *      / \ 
     *     dx  forked
     *           / \ 
     *          dy  dz
     *
     * The nodes with the most bits in common are dy and dz
     */
    n_bits1 = cpt_node_n_bits_common(d1, d2);
    n_bits2 = cpt_node_n_bits_common(d1, d3);

    if (n_bits1 > n_bits2)
    {
        cpt_node_set_descendents(cpt, forked, d1, d2);
        cpt_node_set_descendents(cpt, cover, forked, d3);
    }
    else
    {
        cpt_node_set_descendents(cpt, forked, d1, d3);
        cpt_node_set_descendents(cpt, cover, forked, d2);
    }
}

static void
cpt_node_insert (cpt_128_t *cpt,
                 u32 ni,
                 const u128 *p,
                 u32 len,
                 u32 value)
{
    cpt_node_128_t *cptn;
    u128 result;

    cptn = cpt_node_get(cpt, ni);

    if (len == cptn->cptn_key_len)
    {
        /*
         * adding a prefix of the same length as the node.
         * check for an exact match.
         */
        if (cpt_node_exact_match(cptn, p))
        {
            /*
             * this is an exact match. treat as modify.
             */
            cptn->cptn_value = value;
        }
        else
        {
            /*
             * the covering entry has a descendant in this slot
             * with a mask length matching the entry to insert
             * but it is not this prefix, i.e. the cover is X::/32
             * which has descendants X:0:0:1::/64 and X::/64 and we are
             * adding X:0:0:2::/64.
             * We need to create a new node to represent the common
             * /63.
             */
            cpt_node_fork(cpt, cptn->cptn_cover, p, len, value);
        }
    }
    else if (len < cptn->cptn_key_len)
    {
        /*
         * adding a prefix of a length in the middle of
         * a represented rnge
         */
        cpt_node_wedge(cpt, cptn, p, len, value);
    }
    else
    {
        /*
         * Adding a new prefix with a length greater than the node
         * represents. recurse down the tree.
         */
        u32 index;

        result = ((*(p) & cptn->cptn_mask) == cptn->cptn_range);
        index = cptn->cptn_nodes[result];

        if (index == CPT_INDEX_INVALID)
        {
            /*
             * end of the tree - insert here - handle reallocs.
             */
            cpt_node_128_t *new;
            u32 ni;

            ni = cpt_node_get_index(cpt, cptn);

            new = cpt_node_alloc(cpt, len, p, len, value);
            new->cptn_cover = ni;

            cptn = cpt_node_get(cpt, ni);
            cpt_node_update(cptn, len);

            if (cpt_node_exact_match(cptn, &new->cptn_key))
            {
                cptn->cptn_nodes[1] = cpt_node_get_index(cpt, new);
            }
            else
            {
                cptn->cptn_nodes[0] = cpt_node_get_index(cpt, new);
            }
        }
        else
        {
            cpt_node_insert(cpt, index, (const u128*)p, len, value);
        }
    }
}

void
cpt_insert (cpt_128_t *cpt,
            const u8 *prefix,
            u32 len,
            u32 value)
{
    cpt_node_insert(cpt, cpt->cpt_top, (const u128*)prefix, len, value);
}

u32
cpt_search_exact (const cpt_128_t *cpt,
                  const u8 *prefix,
                  u32 len)
{
    const cpt_node_128_t *cn;
    u128 result, *p;
    u32 index;

    p = (u128*)prefix;

    index = cpt->cpt_top;

    while (index != CPT_INDEX_INVALID)
    {
        cn = cpt_node_get(cpt, index);

        if ((cn->cptn_key_mask & *p) != cn->cptn_key)
        {
            /*
             * the prefix (key) stored in this node does not match the prefix
             * we are looking for - we've gone too far down the tree. Return
             * the value from the last node visited since that is the best LPM.
             */
            return (CPT_INDEX_INVALID);
        }
        else if (((cn->cptn_key_mask & *p) == cn->cptn_key) &&
                 (cn->cptn_key_len ==len))
        {
            return (cn->cptn_value);
        }

        /*
         * is the search key and the stored key equal over the bit range
         * represented by the node.
         */
        result = cpt_node_exact_match(cn, p);

        index = cn->cptn_nodes[result];
    }

    return (CPT_INDEX_INVALID);
}
