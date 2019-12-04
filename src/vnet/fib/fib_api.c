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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/bier/bier_disp_table.h>
#include <vpp/api/types.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/ip/ip_format_fns.h>

#include <vnet/fib/fib.api_enum.h>
#include <vnet/fib/fib.api_types.h>

static u16 fib_base_msg_id;
#define REPLY_MSG_ID_BASE fib_base_msg_id
#include <vlibapi/api_helper_macros.h>

int
fib_api_table_id_decode (fib_protocol_t fproto,
                         u32 table_id,
                         u32 *fib_index)
{
    *fib_index = fib_table_find(fproto, table_id);

    if (INDEX_INVALID == *fib_index)
    {
        return VNET_API_ERROR_NO_SUCH_FIB;
    }

    return (0);
}

int
fib_api_mtable_id_decode (fib_protocol_t fproto,
                          u32 table_id,
                          u32 *fib_index)
{
    *fib_index = mfib_table_find(fproto, table_id);

    if (~0 == *fib_index)
    {
        return VNET_API_ERROR_NO_SUCH_FIB;
    }

    return (0);
}

static void
fib_api_next_hop_decode (const vl_api_fib_path_t *in,
                         ip46_address_t *out)
{
    if (in->proto == FIB_API_PATH_NH_PROTO_IP4)
        clib_memcpy (&out->ip4, &in->nh.address.ip4, sizeof (out->ip4));
    else if (in->proto == FIB_API_PATH_NH_PROTO_IP6)
        clib_memcpy (&out->ip6, &in->nh.address.ip6, sizeof (out->ip6));
}

static vl_api_fib_path_nh_proto_t
fib_api_path_dpo_proto_to_nh (dpo_proto_t dproto)
{
    switch (dproto)
    {
    case DPO_PROTO_IP4:
        return (FIB_API_PATH_NH_PROTO_IP4);
    case DPO_PROTO_IP6:
        return (FIB_API_PATH_NH_PROTO_IP6);
    case DPO_PROTO_MPLS:
        return (FIB_API_PATH_NH_PROTO_MPLS);
    case DPO_PROTO_BIER:
        return (FIB_API_PATH_NH_PROTO_BIER);
    case DPO_PROTO_ETHERNET:
        return (FIB_API_PATH_NH_PROTO_ETHERNET);
    case DPO_PROTO_NSH:
        ASSERT(0);
        break;
    }
    return (FIB_API_PATH_NH_PROTO_IP4);
}


static void
fib_api_next_hop_encode (const fib_route_path_t *rpath,
                         vl_api_fib_path_t *fp)
{
    fp->proto = fib_api_path_dpo_proto_to_nh(rpath->frp_proto);

    if (rpath->frp_proto == DPO_PROTO_IP4)
        clib_memcpy (&fp->nh.address.ip4,
                &rpath->frp_addr.ip4,
                sizeof (rpath->frp_addr.ip4));
    else if (rpath->frp_proto == DPO_PROTO_IP6)
        clib_memcpy (&fp->nh.address.ip6,
                &rpath->frp_addr.ip6,
                sizeof (rpath->frp_addr.ip6));
}

static int
fib_api_path_nh_proto_to_dpo (vl_api_fib_path_nh_proto_t pp,
                              dpo_proto_t *dproto)
{
    switch (pp)
    {
    case FIB_API_PATH_NH_PROTO_IP4:
        *dproto = DPO_PROTO_IP4;
        break;
    case FIB_API_PATH_NH_PROTO_IP6:
        *dproto = DPO_PROTO_IP6;
        break;
    case FIB_API_PATH_NH_PROTO_MPLS:
        *dproto = DPO_PROTO_MPLS;
        break;
    case FIB_API_PATH_NH_PROTO_BIER:
        *dproto = DPO_PROTO_BIER;
        break;
    case FIB_API_PATH_NH_PROTO_ETHERNET:
        *dproto = DPO_PROTO_ETHERNET;
        break;
    default:
        return (-1);
    }
    return (0);
}

int
fib_api_path_decode (vl_api_fib_path_t *in,
                     fib_route_path_t *out)
{
    vnet_classify_main_t *cm = &vnet_classify_main;
    int rv = 0, n_labels;
    vnet_main_t *vnm;
    u8 ii;

    vnm = vnet_get_main ();
    clib_memset(&out->frp_dpo, 0, sizeof(out->frp_dpo));

    /* enums are u32 */
    in->flags = ntohl (in->flags);
    in->type = ntohl (in->type);
    in->proto = ntohl (in->proto);

    /*
     * attributes that apply to all path types
     */
    out->frp_flags = 0;
    out->frp_weight = in->weight;
    if (0 == out->frp_weight)
    {
        out->frp_weight = 1;
    }
    out->frp_preference = in->preference;

    rv = fib_api_path_nh_proto_to_dpo(in->proto, &out->frp_proto);

    if (0 != rv)
        return (rv);

    /*
     * convert the flags and the AFI to determine the path type
     */
    if (in->flags & FIB_API_PATH_FLAG_RESOLVE_VIA_HOST)
        out->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_HOST;
    if (in->flags & FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED)
        out->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED;
    if (in->flags & FIB_API_PATH_FLAG_POP_PW_CW)
        out->frp_flags |= FIB_ROUTE_PATH_POP_PW_CW;

    switch (in->type)
    {
    case FIB_API_PATH_TYPE_DVR:
        out->frp_sw_if_index = ntohl(in->sw_if_index);
        out->frp_flags |= FIB_ROUTE_PATH_DVR;
        break;
    case FIB_API_PATH_TYPE_INTERFACE_RX:
        out->frp_sw_if_index = ntohl(in->sw_if_index);
        out->frp_flags |= FIB_ROUTE_PATH_INTF_RX;
        break;
    case FIB_API_PATH_TYPE_DROP:
        out->frp_flags |= FIB_ROUTE_PATH_DROP;
        break;
    case FIB_API_PATH_TYPE_LOCAL:
        out->frp_flags |= FIB_ROUTE_PATH_LOCAL;
        out->frp_sw_if_index = ntohl(in->sw_if_index);
        break;
    case FIB_API_PATH_TYPE_ICMP_UNREACH:
        out->frp_flags |= FIB_ROUTE_PATH_ICMP_UNREACH;
        break;
    case FIB_API_PATH_TYPE_ICMP_PROHIBIT:
        out->frp_flags |= FIB_ROUTE_PATH_ICMP_PROHIBIT;
        break;
    case FIB_API_PATH_TYPE_CLASSIFY:
        out->frp_flags |= FIB_ROUTE_PATH_CLASSIFY;

        if (pool_is_free_index (cm->tables, ntohl (in->nh.classify_table_index)))
        {
            return VNET_API_ERROR_NO_SUCH_TABLE;
        }
        out->frp_classify_table_id = ntohl (in->nh.classify_table_index);
        break;
    case FIB_API_PATH_TYPE_UDP_ENCAP:
        out->frp_flags |= FIB_ROUTE_PATH_UDP_ENCAP;
        out->frp_udp_encap_id = ntohl(in->nh.obj_id);
        break;
    case FIB_API_PATH_TYPE_BIER_IMP:
        out->frp_flags |= FIB_ROUTE_PATH_BIER_IMP;
        out->frp_bier_imp = ntohl (in->nh.obj_id);
        break;

    case FIB_API_PATH_TYPE_SOURCE_LOOKUP:
        out->frp_flags |= FIB_ROUTE_PATH_SOURCE_LOOKUP;
        /* fall through */
    case FIB_API_PATH_TYPE_NORMAL:
        switch (out->frp_proto)
        {
        case DPO_PROTO_IP4:
        case DPO_PROTO_IP6:
            fib_api_next_hop_decode(in, &out->frp_addr);
            out->frp_sw_if_index = ntohl(in->sw_if_index);
            out->frp_rpf_id = ntohl(in->rpf_id);

            if (0 == out->frp_rpf_id)
            {
                /* allow 0 to be an unset value on the API */
                out->frp_rpf_id = ~0;
            }

            if (~0 != out->frp_rpf_id)
            {
                out->frp_flags |= FIB_ROUTE_PATH_RPF_ID;
            }

            if (~0 == out->frp_sw_if_index)
            {
                /* recursive or deag, validate the next-hop FIB */
                if (~0 != out->frp_rpf_id)
                {
                    rv = fib_api_mtable_id_decode(
                        dpo_proto_to_fib(out->frp_proto),
                        ntohl(in->table_id),
                        &out->frp_fib_index);
                }
                else
                {
                    rv = fib_api_table_id_decode(
                        dpo_proto_to_fib(out->frp_proto),
                        ntohl(in->table_id),
                        &out->frp_fib_index);
                }
                if (0 != rv)
                {
                    return (rv);
                }
            }
            else
            {
                if (pool_is_free_index (vnm->interface_main.sw_interfaces,
                                        out->frp_sw_if_index))
                {
                    return VNET_API_ERROR_NO_MATCHING_INTERFACE;
                }
            }

            if (ip46_address_is_zero(&out->frp_addr))
            {
                if (~0 == out->frp_sw_if_index &&
                    ~0 != out->frp_fib_index)
                {
                    out->frp_flags |= FIB_ROUTE_PATH_DEAG;
                }
            }

            break;
        case DPO_PROTO_MPLS:
            out->frp_local_label = ntohl (in->nh.via_label);
            out->frp_eos = MPLS_NON_EOS;
            out->frp_sw_if_index = ~0;
            break;
        case DPO_PROTO_BIER:
            out->frp_sw_if_index = ntohl(in->sw_if_index);
            out->frp_rpf_id = ntohl(in->rpf_id);

            if (!(out->frp_flags & FIB_ROUTE_PATH_BIER_IMP))
            {
                fib_api_next_hop_decode(in, &out->frp_addr);

                if (ip46_address_is_zero(&out->frp_addr))
                {
                    index_t bdti;

                    bdti = bier_disp_table_find(ntohl(in->table_id));

                    if (INDEX_INVALID != bdti)
                    {
                        out->frp_fib_index = bdti;
                    }
                    else
                    {
                        return (VNET_API_ERROR_NO_SUCH_FIB);
                    }
                }
            }
            break;
        case DPO_PROTO_ETHERNET:
            out->frp_sw_if_index = ntohl(in->sw_if_index);
            break;
        case DPO_PROTO_NSH:
            break;
        }
    }

    n_labels = in->n_labels;
    if (n_labels != 0)
    {
        vec_validate (out->frp_label_stack, n_labels - 1);
        for (ii = 0; ii < n_labels; ii++)
        {
            out->frp_label_stack[ii].fml_value =
                ntohl(in->label_stack[ii].label);
            out->frp_label_stack[ii].fml_ttl =
                in->label_stack[ii].ttl;
            out->frp_label_stack[ii].fml_exp =
                in->label_stack[ii].exp;
            out->frp_label_stack[ii].fml_mode =
                (in->label_stack[ii].is_uniform ?
                 FIB_MPLS_LSP_MODE_UNIFORM :
                 FIB_MPLS_LSP_MODE_PIPE);
        }
    }

    return (0);
}

void
fib_api_path_encode (const fib_route_path_t * rpath,
                     vl_api_fib_path_t *out)
{
    memset (out, 0, sizeof (*out));

    out->weight = rpath->frp_weight;
    out->preference = rpath->frp_preference;
    out->sw_if_index = htonl (rpath->frp_sw_if_index);
    out->proto = fib_api_path_dpo_proto_to_nh(rpath->frp_proto);
    out->rpf_id = rpath->frp_rpf_id;
    fib_api_next_hop_encode (rpath, out);

    if (0 != rpath->frp_fib_index)
    {
        if ((DPO_PROTO_IP6 == rpath->frp_proto) ||
            (DPO_PROTO_IP4 == rpath->frp_proto))
        {
            if (rpath->frp_flags & FIB_ROUTE_PATH_RPF_ID)
            {
                out->table_id = htonl (mfib_table_get_table_id(
                                           rpath->frp_fib_index,
                                           dpo_proto_to_fib(rpath->frp_proto)));
            }
            else
            {
                out->table_id = htonl (fib_table_get_table_id(
                                           rpath->frp_fib_index,
                                           dpo_proto_to_fib(rpath->frp_proto)));
            }
        }
    }

    if (rpath->frp_flags & FIB_ROUTE_PATH_DVR)
    {
        out->type = FIB_API_PATH_TYPE_DVR;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_ICMP_UNREACH)
    {
        out->type = FIB_API_PATH_TYPE_ICMP_UNREACH;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_ICMP_PROHIBIT)
    {
        out->type = FIB_API_PATH_TYPE_ICMP_PROHIBIT;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_LOCAL)
    {
        out->type = FIB_API_PATH_TYPE_LOCAL;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_DROP)
    {
        out->type = FIB_API_PATH_TYPE_DROP;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_UDP_ENCAP)
    {
        out->type = FIB_API_PATH_TYPE_UDP_ENCAP;
        out->nh.obj_id = rpath->frp_udp_encap_id;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_BIER_IMP)
    {
        out->type = FIB_API_PATH_TYPE_BIER_IMP;
        out->nh.obj_id = rpath->frp_bier_imp;
    }
    else if (rpath->frp_flags & FIB_ROUTE_PATH_INTF_RX)
    {
        out->type = FIB_API_PATH_TYPE_INTERFACE_RX;
    }
    else
    {
        out->type = FIB_API_PATH_TYPE_NORMAL;
    }
    if (rpath->frp_flags & FIB_ROUTE_PATH_RESOLVE_VIA_HOST)
    {
        out->flags |= FIB_API_PATH_FLAG_RESOLVE_VIA_HOST;
    }
    if (rpath->frp_flags & FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED)
    {
        out->flags |= FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED;
    }

    out->flags = htonl (out->flags);
    out->type = htonl (out->type);
    out->proto = htonl (out->proto);

    if (rpath->frp_label_stack)
    {
        int ii;

        for (ii = 0; ii < vec_len(rpath->frp_label_stack); ii++)
        {
            out->label_stack[ii].label =
                htonl(rpath->frp_label_stack[ii].fml_value);
            out->label_stack[ii].ttl =
                rpath->frp_label_stack[ii].fml_ttl;
            out->label_stack[ii].exp =
                rpath->frp_label_stack[ii].fml_exp;
        }
        out->n_labels = ii;
    }
}

int
fib_api_route_add_del (u8 is_add,
                       u8 is_multipath,
                       u32 fib_index,
                       const fib_prefix_t * prefix,
                       fib_source_t src,
                       fib_entry_flag_t entry_flags,
                       fib_route_path_t *rpaths)
{
    if (is_multipath)
    {
        if (vec_len(rpaths) == 0)
            return (VNET_API_ERROR_NO_PATHS_IN_ROUTE);

        /* Iterative path add/remove */
        if (is_add)
            fib_table_entry_path_add2 (fib_index,
                                       prefix,
                                       src,
                                       entry_flags,
                                       rpaths);
        else
            fib_table_entry_path_remove2 (fib_index,
                                          prefix,
                                          src,
                                          rpaths);
    }
    else
    {
        if (is_add)
        {
            if (vec_len(rpaths) == 0)
                return (VNET_API_ERROR_NO_PATHS_IN_ROUTE);

            /* path replacement */
            fib_table_entry_update (fib_index,
                                    prefix,
                                    src,
                                    entry_flags,
                                    rpaths);
        }
        else
            /* entry delete */
            fib_table_entry_delete (fib_index,
                                    prefix,
                                    src);
    }

    return (0);
}

u8*
format_vl_api_fib_path (u8 * s, va_list * args)
{
    const vl_api_fib_path_t *path = va_arg (*args, vl_api_fib_path_t*);

    s = format (s, "sw_if_index %d", ntohl (path->sw_if_index));
    switch (clib_net_to_host_u32(path->proto))
    {
    case FIB_API_PATH_NH_PROTO_IP4:
        s = format (s, " %U", format_vl_api_address_union,
                    &path->nh.address, ADDRESS_IP4);
        break;
    case FIB_API_PATH_NH_PROTO_IP6:
        s = format (s, " %U", format_vl_api_address_union,
                    &path->nh.address, ADDRESS_IP6);
        break;
    default:
        break;
    }
    s = format (s, " weight %d", path->weight);
    s = format (s, " preference %d", path->preference);
    s = format (s, " type %d", ntohl(path->type));
    s = format (s, " proto %d", ntohl(path->proto));
    s = format (s, " flags %d", ntohl(path->flags));
    s = format (s, " n_labels %d", ntohl(path->n_labels));
    s = format (s, " table-id %d", ntohl(path->table_id));
    s = format (s, " rpf-id %d", ntohl(path->rpf_id));

    return (s);
}

int
fib_proto_from_api_address_family (vl_api_address_family_t af, fib_protocol_t * out)
{
    switch (af)
    {
    case ADDRESS_IP4:
        *out = (FIB_PROTOCOL_IP4);
        return (0);
    case ADDRESS_IP6:
        *out = (FIB_PROTOCOL_IP6);
        return (0);
    }

    return (VNET_API_ERROR_INVALID_ADDRESS_FAMILY);
}

vl_api_address_family_t
fib_proto_to_api_address_family (fib_protocol_t fproto)
{
    switch (fproto)
    {
    case FIB_PROTOCOL_IP4:
        return (ADDRESS_IP4);
    case FIB_PROTOCOL_IP6:
        return (ADDRESS_IP6);
    default:
        break;
    }

    ASSERT(0);
    return (ADDRESS_IP4);
}

void
vl_api_fib_source_add_t_handler (vl_api_fib_source_add_t * mp)
{
    vl_api_fib_source_add_reply_t *rmp;
    fib_source_t src;
    int rv = 0;
    u8 *name;

    name = format (0, "%s", mp->src.name);
    vec_add1 (name, 0);

    src = fib_source_allocate((const char *)name,
                              mp->src.priority,
                              FIB_SOURCE_BH_API);

    vec_free(name);

    REPLY_MACRO2 (VL_API_FIB_SOURCE_ADD_REPLY,
    ({
        rmp->id = src;
    }));
}

typedef struct fib_source_dump_ctx_t_
{
    vl_api_registration_t * reg;
    u32 context;
} fib_source_dump_ctx_t;

static walk_rc_t
send_fib_source (fib_source_t id,
                 const char *name,
                 fib_source_priority_t prio,
                 fib_source_behaviour_t bh,
                 void *data)
{
    vl_api_fib_source_details_t *mp;
    fib_source_dump_ctx_t *ctx;

    ctx = data;
    mp = vl_msg_api_alloc_zero (sizeof (*mp));
    if (!mp)
        return WALK_STOP;

    mp->_vl_msg_id = ntohs (VL_API_FIB_SOURCE_DETAILS + REPLY_MSG_ID_BASE);
    mp->context = ctx->context;

    mp->src.priority = prio;
    mp->src.id = id;
    clib_memcpy(mp->src.name, name,
                clib_min(strlen(name), ARRAY_LEN(mp->src.name)));

    vl_api_send_msg (ctx->reg, (u8 *) mp);

    return (WALK_CONTINUE);
}

void
vl_api_fib_source_dump_t_handler (vl_api_fib_source_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    fib_source_dump_ctx_t ctx = {
        .reg = reg,
        .context = mp->context,
    };

    fib_source_walk(send_fib_source, &ctx);
}


#include <vnet/fib/fib.api.c>

static clib_error_t *
fib_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  fib_base_msg_id = setup_message_id_table ();

  return (NULL);
}

VLIB_API_INIT_FUNCTION (fib_api_hookup);
