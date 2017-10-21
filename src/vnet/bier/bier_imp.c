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
/**
 * bier_imposition : The BIER imposition object
 *
 * A BIER imposition object is present in the IP mcast output list
 * and represents the imposition of a BIER bitmask. After BIER header
 * imposition the packet is forward within the appropriate/specifid
 * BIER table
 */

#include <vnet/bier/bier_imp.h>
#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_hdr_inlines.h>
#include <vnet/fib/fib_node.h>
#include <vnet/mpls/mpls_types.h>

/**
 * The memory pool of all imp objects
 */
bier_imp_t *bier_imp_pool;

/**
 * When constructing the BIER imp ID from an index and BSL, shift
 * the BSL this far
 */
#define BIER_IMP_ID_HLEN_SHIFT 24

static void
bier_imp_lock_i (bier_imp_t *bi)
{
    bi->bi_locks++;
}

void
bier_imp_lock (index_t bii)
{
    bier_imp_lock_i(bier_imp_get(bii));
}

static index_t
bier_imp_get_index(bier_imp_t *bi)
{
    return (bi - bier_imp_pool);
}

index_t
bier_imp_add_or_lock (const bier_table_id_t *bti,
                      bier_bp_t sender,
                      const bier_bit_string_t *bs)
{
    bier_imp_t *bi = NULL;
    fib_protocol_t fproto;
    index_t btii;

    pool_get_aligned(bier_imp_pool, bi, CLIB_CACHE_LINE_BYTES);

    bi->bi_tbl = *bti;
    btii = bier_table_add_or_lock(bti, MPLS_LABEL_INVALID);

    /*
     * init the BIER header we will paint on in the data plane
     */
    bier_hdr_init(&bi->bi_hdr,
                  BIER_HDR_VERSION_1,
                  BIER_HDR_PROTO_INVALID, // filled in later
                  bti->bti_hdr_len,
                  0, // entropy
                  sender);
    bier_hdr_hton(&bi->bi_hdr);
    clib_memcpy(&bi->bi_bits, bs->bbs_buckets, bs->bbs_len);

    bier_imp_lock_i(bi);

    /*
     * get and stack on the forwarding info from the table
     */
    FOR_EACH_FIB_IP_PROTOCOL(fproto)
    {
        /*
         * initialise to invalid first, lest we pick up garbage
         * from the pool alloc
         */
        dpo_id_t dpo = DPO_INVALID;
        bi->bi_dpo[fproto] = dpo;

        bier_table_contribute_forwarding(btii, &dpo);
        dpo_stack(DPO_BIER_IMP, fib_proto_to_dpo(fproto),
                  &bi->bi_dpo[fproto],
                  &dpo);
        dpo_reset(&dpo);
    }

    return (bier_imp_get_index(bi));
}

void
bier_imp_unlock (index_t bii)
{
    fib_protocol_t fproto;
    bier_imp_t *bi;

    if (INDEX_INVALID == bii)
    {
        return;
    }

    bi = bier_imp_get(bii);

    bi->bi_locks--;

    if (0 == bi->bi_locks)
    {
        bier_table_unlock(&bi->bi_tbl);

        FOR_EACH_FIB_IP_PROTOCOL(fproto)
        {
            dpo_reset(&bi->bi_dpo[fproto]);
        }
        pool_put(bier_imp_pool, bi);
    }
}

u8*
format_bier_imp (u8* s, va_list *args)
{
    index_t bii = va_arg (*args, index_t);
    u32 indent = va_arg(*args, u32);
    bier_show_flags_t flags = va_arg(*args, bier_show_flags_t);
    bier_imp_t *bi;

    bi = bier_imp_get(bii);

    s = format(s, "bier-imp:[%d]: tbl:[%U] hdr:[%U]",
               bier_imp_get_index(bi),
               format_bier_table_id, &bi->bi_tbl,
               format_bier_hdr, &bi->bi_hdr);

    if (BIER_SHOW_DETAIL & flags)
    {
        bier_bit_string_t bbs;
        bier_hdr_t copy;

        copy = bi->bi_hdr;
        bier_hdr_ntoh(&copy);
        bier_bit_string_init(&bbs,
                             bier_hdr_get_len_id(&copy),
                             bi->bi_bits.bits);

        s = format(s, "\n%U%U",
                   format_white_space, indent,
                   format_bier_bit_string, &bbs);
        s = format(s, "\n%U%U",
                   format_white_space, indent,
                   format_dpo_id, &bi->bi_dpo, indent+2);
    }

    return (s);
}

void
bier_imp_contribute_forwarding (index_t bii,
                                dpo_proto_t proto,
                                dpo_id_t *dpo)
{
    dpo_set(dpo, DPO_BIER_IMP, proto, bii);
}

const static char* const bier_imp_ip4_nodes[] =
{
    "bier-imp-ip4",
    NULL,
};
const static char* const bier_imp_ip6_nodes[] =
{
    "bier-imp-ip6",
    NULL,
};

const static char* const * const bier_imp_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = bier_imp_ip4_nodes,
    [DPO_PROTO_IP6]  = bier_imp_ip6_nodes,
};

static void
bier_imp_dpo_lock (dpo_id_t *dpo)
{
    bier_imp_lock(dpo->dpoi_index);
}

static void
bier_imp_dpo_unlock (dpo_id_t *dpo)
{
    bier_imp_unlock(dpo->dpoi_index);
}

static void
bier_imp_dpo_mem_show (void)
{
    fib_show_memory_usage("BIER imposition",
                          pool_elts(bier_imp_pool),
                          pool_len(bier_imp_pool),
                          sizeof(bier_imp_t));
}

static u8*
format_bier_imp_dpo (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);

    s = format(s, "%U", format_bier_imp, index, indent, BIER_SHOW_DETAIL);

    return (s);
}

const static dpo_vft_t bier_imp_vft = {
    .dv_lock = bier_imp_dpo_lock,
    .dv_unlock = bier_imp_dpo_unlock,
    .dv_format = format_bier_imp_dpo,
    .dv_mem_show = bier_imp_dpo_mem_show,
};

clib_error_t *
bier_imp_db_module_init (vlib_main_t *vm)
{
    dpo_register(DPO_BIER_IMP, &bier_imp_vft, bier_imp_nodes);

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_imp_db_module_init);

static clib_error_t *
show_bier_imp (vlib_main_t * vm,
               unformat_input_t * input,
               vlib_cli_command_t * cmd)
{
    bier_imp_t *bi;
    index_t bii;

    bii = INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%d", &bii))
            ;
        else
        {
            break;
        }
    }

    if (INDEX_INVALID == bii)
    {
        pool_foreach(bi, bier_imp_pool,
        ({
            vlib_cli_output(vm, "%U", format_bier_imp,
                            bier_imp_get_index(bi),
                            1,
                            BIER_SHOW_BRIEF);
        }));
    }
    else
    {
        vlib_cli_output(vm, "%U", format_bier_imp, bii, 1,
                        BIER_SHOW_DETAIL);
    }
    return (NULL);
}

VLIB_CLI_COMMAND (show_bier_imp_node, static) = {
    .path = "show bier imp",
    .short_help = "show bier imp [index]",
    .function = show_bier_imp,
};
