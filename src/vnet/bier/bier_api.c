/*
 *------------------------------------------------------------------
 * bier_api.c - vnet BIER api
 *
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/api_errno.h>
#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_imp.h>
#include <vnet/bier/bier_disp_table.h>
#include <vnet/bier/bier_disp_entry.h>
#include <vnet/bier/bier_bit_string.h>
#include <vnet/bier/bier_hdr_inlines.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_api.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_bier_api_msg                            \
    _(BIER_TABLE_ADD_DEL, bier_table_add_del)           \
    _(BIER_TABLE_DUMP, bier_table_dump)                 \
    _(BIER_ROUTE_ADD_DEL, bier_route_add_del)           \
    _(BIER_ROUTE_DUMP, bier_route_dump)                 \
    _(BIER_IMP_ADD, bier_imp_add)                       \
    _(BIER_IMP_DEL, bier_imp_del)                       \
    _(BIER_IMP_DUMP, bier_imp_dump)                     \
    _(BIER_DISP_TABLE_ADD_DEL, bier_disp_table_add_del) \
    _(BIER_DISP_TABLE_DUMP, bier_disp_table_dump)       \
    _(BIER_DISP_ENTRY_ADD_DEL, bier_disp_entry_add_del) \
    _(BIER_DISP_ENTRY_DUMP, bier_disp_entry_dump)

static void
vl_api_bier_table_add_del_t_handler (vl_api_bier_table_add_del_t * mp)
{
    vl_api_bier_table_add_del_reply_t *rmp;
    vnet_main_t *vnm;
    int rv;

    vnm = vnet_get_main ();
    vnm->api_errno = 0;

    bier_table_id_t bti = {
        .bti_set = mp->bt_tbl_id.bt_set,
        .bti_sub_domain = mp->bt_tbl_id.bt_sub_domain,
        .bti_hdr_len = mp->bt_tbl_id.bt_hdr_len_id,
        .bti_type = BIER_TABLE_MPLS_SPF,
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };

    if (mp->bt_is_add)
    {
        bier_table_add_or_lock(&bti, ntohl(mp->bt_label));
    }
    else
    {
        bier_table_unlock(&bti);
    }

    rv = vnm->api_errno;

    REPLY_MACRO (VL_API_BIER_TABLE_ADD_DEL_REPLY);
}

static void
send_bier_table_details (unix_shared_memory_queue_t * q,
                         u32 context,
                         const bier_table_t *bt)
{
    vl_api_bier_table_details_t *mp;

    mp = vl_msg_api_alloc(sizeof(*mp));
    if (!mp)
        return;
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_BIER_TABLE_DETAILS);
    mp->context = context;

    mp->bt_label = bt->bt_ll;
    mp->bt_tbl_id.bt_set = bt->bt_id.bti_set;
    mp->bt_tbl_id.bt_sub_domain = bt->bt_id.bti_sub_domain;
    mp->bt_tbl_id.bt_hdr_len_id = bt->bt_id.bti_hdr_len;

    vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_bier_table_dump_t_handler (vl_api_bier_table_dump_t * mp)
{
    unix_shared_memory_queue_t *q;
    bier_table_t *bt;

    q = vl_api_client_index_to_input_queue (mp->client_index);
    if (q == 0)
        return;

    pool_foreach(bt, bier_table_pool,
    ({
        /*
         * skip the ecmp tables.
         */
        if (bier_table_is_main(bt))
        {
            send_bier_table_details(q, mp->context, bt);
        }
    }));
}

static void
vl_api_bier_route_add_del_t_handler (vl_api_bier_route_add_del_t * mp)
{
    vl_api_bier_route_add_del_reply_t *rmp;
    fib_route_path_t *brpaths, *brpath;
    vnet_main_t *vnm;
    bier_bp_t bp;
    int rv = 0;
    u8 ii, jj;

    vnm = vnet_get_main ();
    vnm->api_errno = 0;

    bp = ntohs(mp->br_bp);
    brpaths = NULL;

    if (0 == bp || bp > 0xffff)
    {
        rv = -1;
        goto done;
    }

    bier_table_id_t bti = {
        .bti_set = mp->br_tbl_id.bt_set,
        .bti_sub_domain = mp->br_tbl_id.bt_sub_domain,
        .bti_hdr_len = mp->br_tbl_id.bt_hdr_len_id,
        .bti_type = BIER_TABLE_MPLS_SPF,
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };

    vec_validate(brpaths, mp->br_n_paths - 1);

    vec_foreach_index(ii, brpaths)
    {
        brpath = &brpaths[ii];
        memset(brpath, 0, sizeof(*brpath));
        brpath->frp_flags = FIB_ROUTE_PATH_BIER_FMASK;

        vec_validate(brpath->frp_label_stack,
                     mp->br_paths[ii].n_labels - 1);
        for (jj = 0; jj < mp->br_paths[ii].n_labels; jj++)
        {
            brpath->frp_label_stack[jj] =
                ntohl(mp->br_paths[ii].label_stack[jj]);
        }

        if (0 == mp->br_paths[ii].afi)
        {
            clib_memcpy (&brpath->frp_addr.ip4,
                         mp->br_paths[ii].next_hop,
                         sizeof (brpath->frp_addr.ip4));
        }
        else
        {
            clib_memcpy (&brpath->frp_addr.ip6,
                         mp->br_paths[ii].next_hop,
                         sizeof (brpath->frp_addr.ip6));
        }
        if (ip46_address_is_zero(&brpath->frp_addr))
        {
            index_t bdti;

            bdti = bier_disp_table_find(ntohl(mp->br_paths[ii].table_id));

            if (INDEX_INVALID != bdti)
                brpath->frp_fib_index = bdti;
            else
            {
                rv = VNET_API_ERROR_NO_SUCH_FIB;
                goto done;
            }
        }
    }

    if (mp->br_is_add)
    {
        bier_table_route_add(&bti, ntohs(mp->br_bp), brpaths);
    }
    else
    {
        bier_table_route_remove(&bti, ntohs(mp->br_bp), brpaths);
    }

done:
    vec_free(brpaths);
    rv = (rv == 0) ? vnm->api_errno : rv;

    REPLY_MACRO (VL_API_BIER_ROUTE_ADD_DEL_REPLY);
}

typedef struct bier_route_details_walk_t_
{
    unix_shared_memory_queue_t * q;
    u32 context;
} bier_route_details_walk_t;

static void
send_bier_route_details (const bier_table_t *bt,
                         const bier_entry_t *be,
                         void *args)
{
    fib_route_path_encode_t *api_rpaths = NULL, *api_rpath;
    bier_route_details_walk_t *ctx = args;
    vl_api_bier_route_details_t *mp;
    vl_api_fib_path3_t *fp;
    u32 n_paths, m_size;

    n_paths = fib_path_list_get_n_paths(be->be_path_list);
    m_size = sizeof(*mp) + (n_paths * sizeof(vl_api_fib_path3_t));
    mp = vl_msg_api_alloc(m_size);
    if (!mp)
        return;

    memset(mp, 0, m_size);
    mp->_vl_msg_id = ntohs(VL_API_BIER_ROUTE_DETAILS);
    mp->context = ctx->context;

    mp->br_tbl_id.bt_set = bt->bt_id.bti_set;
    mp->br_tbl_id.bt_sub_domain = bt->bt_id.bti_sub_domain;
    mp->br_tbl_id.bt_hdr_len_id = bt->bt_id.bti_hdr_len;
    mp->br_bp = htons(be->be_bp);
    mp->br_n_paths = htonl(n_paths);

    fib_path_list_walk(be->be_path_list, fib_path_encode, &api_rpaths);

    fp = mp->br_paths;
    vec_foreach (api_rpath, api_rpaths)
    {
        fp->weight = api_rpath->rpath.frp_weight;
        fp->preference = api_rpath->rpath.frp_preference;
        fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
        fp->n_labels = 0;
        copy_fib_next_hop (api_rpath, fp);
        fp++;
    }

    vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);
}

static void
vl_api_bier_route_dump_t_handler (vl_api_bier_route_dump_t * mp)
{
    unix_shared_memory_queue_t *q;

    q = vl_api_client_index_to_input_queue (mp->client_index);
    if (q == 0)
        return;

    bier_table_id_t bti = {
        .bti_set = mp->br_tbl_id.bt_set,
        .bti_sub_domain = mp->br_tbl_id.bt_sub_domain,
        .bti_hdr_len = mp->br_tbl_id.bt_hdr_len_id,
        .bti_type = BIER_TABLE_MPLS_SPF,
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };
    bier_route_details_walk_t ctx = {
        .q = q,
        .context = mp->context,
    };
    bier_table_walk(&bti, send_bier_route_details, &ctx);
}

static void
vl_api_bier_imp_add_t_handler (vl_api_bier_imp_add_t * mp)
{
    vl_api_bier_imp_add_reply_t *rmp;
    vnet_main_t *vnm;
    index_t bii;
    int rv = 0;

    vnm = vnet_get_main ();
    vnm->api_errno = 0;

    bier_table_id_t bti = {
        .bti_set = mp->bi_tbl_id.bt_set,
        .bti_sub_domain = mp->bi_tbl_id.bt_sub_domain,
        .bti_hdr_len = mp->bi_tbl_id.bt_hdr_len_id,
        .bti_type = BIER_TABLE_MPLS_SPF,
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };
    bier_bit_string_t bs = {
        .bbs_len = mp->bi_n_bytes,
        .bbs_buckets = mp->bi_bytes,
    };

    bii = bier_imp_add_or_lock(&bti, ntohs(mp->bi_src), &bs);

    /* *INDENT-OFF* */
    REPLY_MACRO2 (VL_API_BIER_IMP_ADD_REPLY,
    ({
        rmp->bi_index = bii;
    }));
    /* *INDENT-OM* */
}

static void
vl_api_bier_imp_del_t_handler (vl_api_bier_imp_del_t * mp)
{
    vl_api_bier_imp_del_reply_t *rmp;
    vnet_main_t *vnm;
    int rv = 0;

    vnm = vnet_get_main ();
    vnm->api_errno = 0;

    bier_imp_unlock(ntohl(mp->bi_index));

    REPLY_MACRO(VL_API_BIER_IMP_DEL_REPLY);
}

static void
send_bier_imp_details (unix_shared_memory_queue_t * q,
                       u32 context,
                       const bier_imp_t *bi)
{
    vl_api_bier_imp_details_t *mp;
    bier_hdr_t copy;
    u8 n_bytes;

    copy = bi->bi_hdr;
    bier_hdr_ntoh(&copy);

    n_bytes = bier_hdr_len_id_to_num_bytes(
                  bier_hdr_get_len_id(&copy));
    mp = vl_msg_api_alloc(sizeof(*mp) + n_bytes);
    if (!mp)
        return;
    memset(mp, 0, sizeof(*mp)+n_bytes);
    mp->_vl_msg_id = ntohs(VL_API_BIER_IMP_DETAILS);
    mp->context = context;

    mp->bi_tbl_id.bt_set = bi->bi_tbl.bti_set;
    mp->bi_tbl_id.bt_sub_domain = bi->bi_tbl.bti_sub_domain;
    mp->bi_tbl_id.bt_hdr_len_id = bi->bi_tbl.bti_hdr_len;


    mp->bi_src = htons(bier_hdr_get_src_id(&copy));
    mp->bi_n_bytes = n_bytes;
    memcpy(mp->bi_bytes, bi->bi_bits.bits, n_bytes);

    vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_bier_imp_dump_t_handler (vl_api_bier_imp_dump_t * mp)
{
    unix_shared_memory_queue_t *q;
    bier_imp_t *bi;

    q = vl_api_client_index_to_input_queue (mp->client_index);
    if (q == 0)
        return;

    pool_foreach(bi, bier_imp_pool,
    ({
        send_bier_imp_details(q, mp->context, bi);
    }));
}

static void
vl_api_bier_disp_table_add_del_t_handler (vl_api_bier_disp_table_add_del_t * mp)
{
    vl_api_bier_disp_table_add_del_reply_t *rmp;
    vnet_main_t *vnm;
    u32 table_id;
    int rv;

    vnm = vnet_get_main ();
    vnm->api_errno = 0;
    table_id = ntohl(mp->bdt_tbl_id);

    if (mp->bdt_is_add)
    {
        bier_disp_table_add_or_lock(table_id);
    }
    else
    {
        bier_disp_table_unlock_w_table_id(table_id);
    }

    rv = vnm->api_errno;

    REPLY_MACRO (VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY);
}

static void
send_bier_disp_table_details (unix_shared_memory_queue_t * q,
                              u32 context,
                              const bier_disp_table_t *bdt)
{
    vl_api_bier_disp_table_details_t *mp;

    mp = vl_msg_api_alloc(sizeof(*mp));
    if (!mp)
        return;
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(VL_API_BIER_DISP_TABLE_DETAILS);
    mp->context = context;

    mp->bdt_tbl_id = htonl(bdt->bdt_table_id);

    vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_bier_disp_table_dump_t_handler (vl_api_bier_disp_table_dump_t * mp)
{
    unix_shared_memory_queue_t *q;
    bier_disp_table_t *bdt;

    q = vl_api_client_index_to_input_queue (mp->client_index);
    if (q == 0)
        return;

    pool_foreach(bdt, bier_disp_table_pool,
    ({
        send_bier_disp_table_details(q, mp->context, bdt);
    }));
}

static void
vl_api_bier_disp_entry_add_del_t_handler (vl_api_bier_disp_entry_add_del_t * mp)
{
    vl_api_bier_disp_entry_add_del_reply_t *rmp;
    fib_route_path_t *brps = NULL, *brp;
    vnet_main_t *vnm;
    bier_bp_t bp;
    u32 table_id;
    int rv = 0;
    u32 ii;

    vnm = vnet_get_main ();
    vnm->api_errno = 0;
    table_id = ntohl(mp->bde_tbl_id);
    bp = ntohs(mp->bde_bp);

    if (0 == bp || bp > 0xffff)
    {
        rv = -1;
        goto done;
    }

    vec_validate(brps, mp->bde_n_paths - 1);
    vec_foreach_index(ii, brps)
    {
        brp = &brps[ii];
        brp->frp_fib_index = ntohl(mp->bde_paths[ii].table_id);
        brp->frp_sw_if_index = ntohl(mp->bde_paths[ii].sw_if_index);

        if (~0 != ntohl(mp->bde_paths[ii].rpf_id))
        {
            brp->frp_flags = FIB_ROUTE_PATH_RPF_ID;
            brp->frp_rpf_id = ntohl(mp->bde_paths[ii].rpf_id);
        }

        if (0 == mp->bde_paths[ii].afi)
        {
            clib_memcpy (&brp->frp_addr.ip4,
                         mp->bde_paths[ii].next_hop,
                         sizeof (brp->frp_addr.ip4));
        }
        else
        {
            clib_memcpy (&brp->frp_addr.ip6,
                         mp->bde_paths[ii].next_hop,
                         sizeof (brp->frp_addr.ip6));
        }
        if (ip46_address_is_zero(&brp->frp_addr))
        {
            index_t fti;

            switch (mp->bde_payload_proto)
            {
            case BIER_HDR_PROTO_INVALID:
            case BIER_HDR_PROTO_MPLS_DOWN_STREAM:
            case BIER_HDR_PROTO_MPLS_UP_STREAM:
            case BIER_HDR_PROTO_ETHERNET:
            case BIER_HDR_PROTO_VXLAN:
            case BIER_HDR_PROTO_CTRL:
            case BIER_HDR_PROTO_OAM:
                rv = VNET_API_ERROR_UNSUPPORTED;
                goto done;
                break;
            case BIER_HDR_PROTO_IPV4:
            case BIER_HDR_PROTO_IPV6:
            {
                fib_protocol_t fproto;

                fproto = (mp->bde_payload_proto == BIER_HDR_PROTO_IPV4 ?
                          FIB_PROTOCOL_IP4 :
                          FIB_PROTOCOL_IP6);

                if (brp->frp_flags & FIB_ROUTE_PATH_RPF_ID)
                {
                    fti = mfib_table_find (fproto,
                                           ntohl (mp->bde_paths[ii].table_id));
                }
                else
                {
                    fti = fib_table_find (fproto,
                                          ntohl (mp->bde_paths[ii].table_id));
                }

                if (INDEX_INVALID != fti)
                {
                    brp->frp_fib_index = fti;
                }
                else
                {
                    rv = VNET_API_ERROR_NO_SUCH_FIB;
                    goto done;
                }
                break;
            }
            }
        }
    }

    if (mp->bde_is_add)
    {
        bier_disp_table_entry_path_add(table_id, bp,
                                       mp->bde_payload_proto,
                                       brps);
    }
    else
    {
        bier_disp_table_entry_path_remove(table_id, bp,
                                          mp->bde_payload_proto,
                                          brps);
    }

done:
    vec_free(brps);
    rv = (rv == 0) ? vnm->api_errno : rv;

    REPLY_MACRO (VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY);
}

typedef struct bier_disp_entry_details_walk_t_
{
    unix_shared_memory_queue_t * q;
    u32 context;
} bier_disp_entry_details_walk_t;

static void
send_bier_disp_entry_details (const bier_disp_table_t *bdt,
                              const bier_disp_entry_t *bde,
                              u16 bp,
                              void *args)
{
    fib_route_path_encode_t *api_rpaths = NULL, *api_rpath;
    bier_disp_entry_details_walk_t *ctx = args;
    vl_api_bier_disp_entry_details_t *mp;
    bier_hdr_proto_id_t pproto;
    vl_api_fib_path3_t *fp;
    u32 n_paths, m_size;

    FOR_EACH_BIER_HDR_PROTO(pproto)
    {
        fib_node_index_t pl = bde->bde_pl[pproto];
        if (INDEX_INVALID != pl)
        {
            n_paths = fib_path_list_get_n_paths(pl);
            m_size = sizeof(*mp) + (n_paths * sizeof(vl_api_fib_path3_t));
            mp = vl_msg_api_alloc(m_size);
            if (!mp)
                return;

            memset(mp, 0, m_size);
            mp->_vl_msg_id = ntohs(VL_API_BIER_DISP_ENTRY_DETAILS);
            mp->context = ctx->context;

            mp->bde_tbl_id = htonl(bdt->bdt_table_id);
            mp->bde_n_paths = htonl(n_paths);
            mp->bde_payload_proto = pproto;
            mp->bde_bp = htons(bp);

            fib_path_list_walk(pl, fib_path_encode, &api_rpaths);

            fp = mp->bde_paths;
            vec_foreach (api_rpath, api_rpaths)
            {
                fp->weight = api_rpath->rpath.frp_weight;
                fp->preference = api_rpath->rpath.frp_preference;
                fp->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
                fp->n_labels = 0;
                copy_fib_next_hop (api_rpath, fp);
                fp++;
            }

            vl_msg_api_send_shmem (ctx->q, (u8 *) & mp);
        }
    }
}

static void
vl_api_bier_disp_entry_dump_t_handler (vl_api_bier_disp_entry_dump_t * mp)
{
    unix_shared_memory_queue_t *q;

    q = vl_api_client_index_to_input_queue (mp->client_index);
    if (q == 0)
        return;

    bier_disp_entry_details_walk_t ctx = {
        .q = q,
        .context = mp->context,
    };
    bier_disp_table_walk(ntohl(mp->bde_tbl_id),
                         send_bier_disp_entry_details,
                         &ctx);
}

#define vl_msg_name_crc_list
#include <vnet/bier/bier.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
    foreach_vl_msg_name_crc_bier;
#undef _
}

static clib_error_t *
bier_api_hookup (vlib_main_t * vm)
{
    api_main_t *am = &api_main;

#define _(N,n)                                          \
    vl_msg_api_set_handlers(VL_API_##N, #n,             \
                            vl_api_##n##_t_handler,     \
                            vl_noop_handler,            \
                            vl_api_##n##_t_endian,      \
                            vl_api_##n##_t_print,       \
                            sizeof(vl_api_##n##_t), 1);
    foreach_bier_api_msg;
#undef _

    /*
     * Set up the (msg_name, crc, message-id) table
     */
    setup_message_id_table (am);

    return 0;
}

VLIB_API_INIT_FUNCTION (bier_api_hookup);
