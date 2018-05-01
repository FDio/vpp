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
        memcpy (&out->ip4, &in->nh.address.ip4, sizeof (out->ip4));
    else if (in->proto == FIB_API_PATH_NH_PROTO_IP6)
        memcpy (&out->ip6, &in->nh.address.ip6, sizeof (out->ip6));
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
        memcpy (&fp->nh.address.ip4,
                &rpath->frp_addr.ip4,
                sizeof (rpath->frp_addr.ip4));
    else if (rpath->frp_proto == DPO_PROTO_IP6)
        memcpy (&fp->nh.address.ip6,
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
    out->frp_preference = in->preference;
    rv = fib_api_path_nh_proto_to_dpo(in->proto, &out->frp_proto);

    if (0 != rv)
        return (rv);

    /*
     * convert the flags and the AFI to dtermine the path type
     */
    if (in->flags & FIB_API_PATH_FLAG_RESOLVE_VIA_HOST)
        out->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_HOST;
    if (in->flags & FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED)
        out->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED;

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
            if (~0 == out->rpf_id || 0 == out->rpf_id)
            {
                out->table_id = htonl (fib_table_get_table_id(
                                           rpath->frp_fib_index,
                                           dpo_proto_to_fib(rpath->frp_proto)));
            }
            else
            {
                out->table_id = htonl (mfib_table_get_table_id(
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
}

void
fib_api_route_add_del (u8 is_add,
                       u8 is_multipath,
                       u32 fib_index,
                       const fib_prefix_t * prefix,
                       fib_entry_flag_t entry_flags,
                       fib_route_path_t *rpaths)
{
  if (is_multipath)
    {
      /* Iterative path add/remove */
      if (is_add)
	fib_table_entry_path_add2 (fib_index,
				   prefix,
				   FIB_SOURCE_API,
                                   entry_flags,
                                   rpaths);
      else
	fib_table_entry_path_remove2 (fib_index,
				      prefix,
                                      FIB_SOURCE_API,
                                      rpaths);
    }
  else
    {
      if (is_add)
        /* path replacement */
	fib_table_entry_update (fib_index,
                                prefix,
                                FIB_SOURCE_API,
                                entry_flags,
                                rpaths);
      else
        /* entry delete */
	fib_table_entry_delete (fib_index,
                                prefix,
                                FIB_SOURCE_API);
    }
}

u8*
format_vl_api_fib_path(u8 * s, va_list * args)
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

fib_protocol_t
fib_proto_from_api_address_family (int af)
{
    switch (clib_net_to_host_u32 (af))
    {
    case ADDRESS_IP4:
        return (FIB_PROTOCOL_IP4);
    case ADDRESS_IP6:
        return (FIB_PROTOCOL_IP6);
    }

    ASSERT(0);
    return (FIB_PROTOCOL_IP4);
}

int
fib_proto_to_api_address_family (fib_protocol_t fproto)
{
    switch (fproto)
    {
    case FIB_PROTOCOL_IP4:
        return (clib_net_to_host_u32 (ADDRESS_IP4));
    case FIB_PROTOCOL_IP6:
        return (clib_net_to_host_u32 (ADDRESS_IP6));
    default:
        break;
    }

    ASSERT(0);
    return (clib_net_to_host_u32 (ADDRESS_IP4));
}
