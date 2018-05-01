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
    if (in->dpo_proto == DPO_PROTO_IP4)
        memcpy (&out->ip4, in->next_hop, sizeof (out->ip4));
    else if (in->dpo_proto == DPO_PROTO_IP6)
        memcpy (&out->ip6, in->next_hop, sizeof (out->ip6));
}

static void
fib_api_next_hop_encode (const fib_route_path_t *rpath,
                         vl_api_fib_path_t *fp)
{
    fp->dpo_proto = rpath->frp_proto;

    if (rpath->frp_proto == DPO_PROTO_IP4)
        memcpy (fp->next_hop,
                &rpath->frp_addr.ip4,
                sizeof (rpath->frp_addr.ip4));
    else if (rpath->frp_proto == DPO_PROTO_IP6)
        memcpy (fp->next_hop,
                &rpath->frp_addr.ip6,
                sizeof (rpath->frp_addr.ip6));
}

int
fib_api_path_decode (const vl_api_fib_path_t *in,
                     fib_route_path_t *out)
{
    vnet_classify_main_t *cm = &vnet_classify_main;
    int rv = 0, n_labels;
    vnet_main_t *vnm;
    u8 ii;

    vnm = vnet_get_main ();
    memset(&out->frp_dpo, 0, sizeof(out->frp_dpo));

    /*
     * attributes that apply to all path types
     */
    out->frp_flags = 0;
    out->frp_weight = in->weight;
    out->frp_preference = in->preference;

    /*
     * convert the flags and the AFI to dtermine the path type
     */
    if (in->is_dvr)
        out->frp_flags |= FIB_ROUTE_PATH_DVR;
    if (in->is_resolve_host)
        out->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_HOST;
    if (in->is_resolve_attached)
        out->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED;
    if (in->is_interface_rx)
        out->frp_flags |= FIB_ROUTE_PATH_INTF_RX;
    if (in->is_source_lookup)
        out->frp_flags |= FIB_ROUTE_PATH_SOURCE_LOOKUP;
    out->frp_proto = in->dpo_proto;

    if (in->is_drop)
    {
        out->frp_flags |= FIB_ROUTE_PATH_DROP;        
    }
    else if (in->is_local)
    {
        out->frp_flags |= FIB_ROUTE_PATH_LOCAL;        
    }
    else if (in->is_unreach)
    {
        out->frp_flags |= FIB_ROUTE_PATH_ICMP_UNREACH;
    }
    else if (in->is_prohibit)
    {
        out->frp_flags |= FIB_ROUTE_PATH_ICMP_PROHIBIT;
    }
    else if (in->is_classify)
    {
        out->frp_flags |= FIB_ROUTE_PATH_CLASSIFY;
        
        if (pool_is_free_index (cm->tables, ntohl (in->classify_table_index)))
        {
            return VNET_API_ERROR_NO_SUCH_TABLE;
        }
        out->frp_classify_table_id = ntohl (in->classify_table_index);
    }
    else if (in->is_udp_encap)
    {
        out->frp_flags |= FIB_ROUTE_PATH_UDP_ENCAP;
        out->frp_udp_encap_id = ntohl(in->next_hop_id);
    }
    else
    {
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
            out->frp_local_label = ntohl (in->via_label);
            out->frp_eos = MPLS_NON_EOS;
            break;
        case DPO_PROTO_BIER:
            fib_api_next_hop_decode(in, &out->frp_addr);

            if (~0 != in->next_hop_id)
            {
                out->frp_bier_imp = ntohl (in->next_hop_id);
                out->frp_flags = FIB_ROUTE_PATH_BIER_IMP;
            }
            else if (ip46_address_is_zero(&out->frp_addr))
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
            break;
        case DPO_PROTO_ETHERNET:
        case DPO_PROTO_NSH:
            break;
        }
    }

    n_labels = in->n_labels;
    if (n_labels == 0)
        ;
    else
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
fib_api_prefix_encode (const fib_prefix_t *pfx,
                       vl_api_fib_prefix_t *out)
{
    out->address_length = pfx->fp_len;
    out->is_ip6 = (FIB_PROTOCOL_IP6 == pfx->fp_proto ? 1 : 0);

    if (FIB_PROTOCOL_IP6 == pfx->fp_proto)
    {
        memcpy (out->address,
                &pfx->fp_addr.ip6,
                sizeof (pfx->fp_addr.ip6));
    }
    else
    {
        memcpy (out->address,
                &pfx->fp_addr.ip4,
                sizeof (pfx->fp_addr.ip4));
    }
}

void
fib_api_prefix_decode (const vl_api_fib_prefix_t *in,
                       fib_prefix_t *out)
{
    out->fp_len = in->address_length;
    out->fp_proto = (in->is_ip6 ?
                     FIB_PROTOCOL_IP6 :
                     FIB_PROTOCOL_IP4);

    if (FIB_PROTOCOL_IP6 == out->fp_proto)
    {
        memcpy (&out->fp_addr.ip6,
                in->address,
                sizeof (out->fp_addr.ip6));
    }
    else
    {
        memcpy (&out->fp_addr.ip4,
                in->address,
                sizeof (out->fp_addr.ip4));
    }
}

void
fib_api_path_encode (const fib_route_path_t * rpath,
                     vl_api_fib_path_t *out)
{
    memset (out, 0, sizeof (*out));

    out->weight = rpath->frp_weight;
    out->preference = rpath->frp_preference;
    out->sw_if_index = htonl (rpath->frp_sw_if_index);
    out->dpo_proto = rpath->frp_proto;
    fib_api_next_hop_encode (rpath, out);

    if (~0 == rpath->frp_sw_if_index &&
        !ip46_address_is_zero(&rpath->frp_addr))
    {
        if ((DPO_PROTO_IP6 == rpath->frp_proto) ||
            (DPO_PROTO_IP4 == rpath->frp_proto))
        {
            fib_table_t *fib;

            fib = fib_table_get (rpath->frp_fib_index,
                                 dpo_proto_to_fib(rpath->frp_proto));

            out->table_id = htonl (fib->ft_table_id);
        }
    }

    if (rpath->frp_flags & FIB_ROUTE_PATH_DVR)
    {
        out->is_dvr = 1;
    }
    if (rpath->frp_flags & FIB_ROUTE_PATH_ICMP_UNREACH)
    {
        out->is_unreach = 1;
    }
    if (rpath->frp_flags & FIB_ROUTE_PATH_ICMP_PROHIBIT)
    {
        out->is_prohibit = 1;
    }
    if (rpath->frp_flags & FIB_ROUTE_PATH_LOCAL)
    {
        out->is_local = 1;
    }
    if (rpath->frp_flags & FIB_ROUTE_PATH_DROP)
    {
        out->is_drop = 1;
    }
    if (rpath->frp_flags & FIB_ROUTE_PATH_UDP_ENCAP)
    {
        out->is_udp_encap = 1;
        out->next_hop_id = rpath->frp_udp_encap_id;
    }
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
