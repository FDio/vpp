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
fib_path_api_parse (const vl_api_fib_path3_t *in,
                    fib_route_path_t *out)
{
    fib_route_path_flags_t path_flags;
    mpls_label_t next_hop_via_label;
    int rv = 0, n_labels;
    u8 ii;

    path_flags = FIB_ROUTE_PATH_FLAG_NONE;
    next_hop_via_label = ntohl (in->via_label);
    memset(out, 0, sizeof(*out));
    out->frp_sw_if_index = ~0;

    out->frp_proto = in->afi;
    // .frp_addr = (NULL == next_hop ? zero_addr : *next_hop),
    out->frp_sw_if_index = ntohl(in->sw_if_index);
    out->frp_fib_index = ntohl(in->table_id);
    out->frp_weight = in->weight;
    out->frp_preference = in->preference;

    /*
     * the special INVALID label meams we are not recursing via a
     * label. Exp-null value is never a valid via-label so that
     * also means it's not a via-label and means clients that set
     * it to 0 by default get the expected behaviour
     */
    if ((MPLS_LABEL_INVALID != next_hop_via_label) &&
        (0 != next_hop_via_label))
    {
        out->frp_proto = DPO_PROTO_MPLS;
        out->frp_local_label = next_hop_via_label;
        out->frp_eos = MPLS_NON_EOS;
    }

    n_labels = in->n_labels;
    if (n_labels == 0)
        ;
    else if (1 == n_labels)
        vec_add1 (out->frp_label_stack, ntohl (in->label_stack[0]));
    else
    {
        vec_validate (out->frp_label_stack, n_labels - 1);
        for (ii = 0; ii < n_labels; ii++)
            out->frp_label_stack[ii] = ntohl (in->label_stack[ii]);
    }

    if (in->is_dvr)
        path_flags |= FIB_ROUTE_PATH_DVR;
    if (in->is_resolve_host)
        path_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_HOST;
    if (in->is_resolve_attached)
        path_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED;
    /* if (in->is_interface_rx) */
    /*     path_flags |= FIB_ROUTE_PATH_INTF_RX; */
    /* if (in->is_rpf_id) */
    /*     path_flags |= FIB_ROUTE_PATH_RPF_ID; */
    if (in->is_source_lookup)
        path_flags |= FIB_ROUTE_PATH_SOURCE_LOOKUP;

    if (in->is_udp_encap)
    {
        path_flags |= FIB_ROUTE_PATH_UDP_ENCAP;
        out->frp_udp_encap_id = ntohl(in->next_hop_id);
    }
    else
    {
        if (DPO_PROTO_IP4 == in->afi)
        {
            clib_memcpy (&out->frp_addr.ip4,
                         in->next_hop,
                         sizeof (out->frp_addr.ip4));
        }
        else if (DPO_PROTO_IP6 == in->afi)
        {
            clib_memcpy (&out->frp_addr.ip6,
                         in->next_hop,
                         sizeof (out->frp_addr.ip6));
        }

        if (ip46_address_is_zero(&out->frp_addr))
        {
            if (DPO_PROTO_BIER == in->afi)
            {
                index_t bdti;

                bdti = bier_disp_table_find(ntohl(in->table_id));

                if (INDEX_INVALID != bdti)
                {
                    out->frp_fib_index = bdti;
                    out->frp_proto = DPO_PROTO_BIER;
                }
                else
                {
                    rv = VNET_API_ERROR_NO_SUCH_FIB;
                }
            }
            else if (out->frp_sw_if_index == ~0 &&
                     out->frp_fib_index != ~0)
            {
                path_flags |= FIB_ROUTE_PATH_DEAG;
            }
        }
    }

    out->frp_flags = path_flags;

    return (rv);
}

void
fib_prefix_to_api (const fib_prefix_t *pfx,
                   u8 address[16],
                   u8 *length,
                   u8 *is_ip6)
{
    *length = pfx->fp_len;
    *is_ip6 = (FIB_PROTOCOL_IP6 == pfx->fp_proto ? 1 : 0);

    if (FIB_PROTOCOL_IP6 == pfx->fp_proto)
    {
        memcpy (address, &pfx->fp_addr.ip6, sizeof (pfx->fp_addr.ip6));
    }
    else
    {
        memcpy (address, &pfx->fp_addr.ip4, sizeof (pfx->fp_addr.ip4));
    }
}
