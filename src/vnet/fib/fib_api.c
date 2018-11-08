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
#include <vnet/bier/bier_disp_table.h>
#include <vnet/dpo/ip_null_dpo.h>

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
fib_path_api_parse (const vl_api_fib_path_t *in,
                    fib_route_path_t *out)
{
    fib_route_path_flags_t path_flags;
    mpls_label_t next_hop_via_label;
    int rv = 0, n_labels;
    u8 ii;

    path_flags = FIB_ROUTE_PATH_FLAG_NONE;
    next_hop_via_label = ntohl (in->via_label);
    clib_memset(out, 0, sizeof(*out));
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

static void
fib_api_path_copy_next_hop (const fib_route_path_encode_t * api_rpath, void *fp_arg)
{
  int is_ip4;
  vl_api_fib_path_t *fp = (vl_api_fib_path_t *) fp_arg;

  if (api_rpath->rpath.frp_proto == DPO_PROTO_IP4)
    fp->afi = IP46_TYPE_IP4;
  else if (api_rpath->rpath.frp_proto == DPO_PROTO_IP6)
    fp->afi = IP46_TYPE_IP6;
  else
    {
      is_ip4 = ip46_address_is_ip4 (&api_rpath->rpath.frp_addr);
      if (is_ip4)
	fp->afi = IP46_TYPE_IP4;
      else
	fp->afi = IP46_TYPE_IP6;
    }
  if (fp->afi == IP46_TYPE_IP4)
    memcpy (fp->next_hop, &api_rpath->rpath.frp_addr.ip4,
	    sizeof (api_rpath->rpath.frp_addr.ip4));
  else
    memcpy (fp->next_hop, &api_rpath->rpath.frp_addr.ip6,
	    sizeof (api_rpath->rpath.frp_addr.ip6));
}

void
fib_api_path_encode (const fib_route_path_encode_t * api_rpath,
                     vl_api_fib_path_t *out)
{
    clib_memset (out, 0, sizeof (*out));
    switch (api_rpath->dpo.dpoi_type)
    {
    case DPO_RECEIVE:
        out->is_local = true;
        break;
    case DPO_DROP:
        out->is_drop = true;
        break;
    case DPO_IP_NULL:
        switch (ip_null_dpo_get_action(api_rpath->dpo.dpoi_index))
        {
        case IP_NULL_ACTION_NONE:
            out->is_drop = true;
            break;
        case IP_NULL_ACTION_SEND_ICMP_UNREACH:
            out->is_unreach = true;
            break;
        case IP_NULL_ACTION_SEND_ICMP_PROHIBIT:
            out->is_prohibit = true;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    out->weight = api_rpath->rpath.frp_weight;
    out->preference = api_rpath->rpath.frp_preference;
    out->sw_if_index = htonl (api_rpath->rpath.frp_sw_if_index);
    out->afi = api_rpath->rpath.frp_proto;
    fib_api_path_copy_next_hop (api_rpath, out);

    if (0 != api_rpath->rpath.frp_fib_index)
    {
        if ((DPO_PROTO_IP6 == api_rpath->rpath.frp_proto) ||
            (DPO_PROTO_IP4 == api_rpath->rpath.frp_proto))
        {
            fib_table_t *fib;

            fib = fib_table_get (api_rpath->rpath.frp_fib_index,
                                 dpo_proto_to_fib(api_rpath->rpath.frp_proto));

            out->table_id = htonl (fib->ft_table_id);
        }
    }

    if (api_rpath->rpath.frp_flags & FIB_ROUTE_PATH_DVR)
    {
        out->is_dvr = 1;
    }
    if (api_rpath->rpath.frp_flags & FIB_ROUTE_PATH_UDP_ENCAP)
    {
        out->is_udp_encap = 1;
        out->next_hop_id = api_rpath->rpath.frp_udp_encap_id;
    }
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
