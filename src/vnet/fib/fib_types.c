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

#include <vnet/ip/ip.h>

#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_internal.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_types.h>
#include <vnet/mpls/mpls.h>

/*
 * arrays of protocol and link names
 */
static const char* fib_protocol_names[] = FIB_PROTOCOLS;
static const char* vnet_link_names[] = VNET_LINKS;
static const char* fib_forw_chain_names[] = FIB_FORW_CHAINS;
static const char* fib_mpls_lsp_mode_names[] = FIB_MPLS_LSP_MODES;

u8 *
format_fib_protocol (u8 * s, va_list * ap)
{
    fib_protocol_t proto = va_arg(*ap, int); // fib_protocol_t promotion

    return (format (s, "%s", fib_protocol_names[proto]));
}

u8 *
format_vnet_link (u8 * s, va_list * ap)
{
    vnet_link_t link = va_arg(*ap, int); // vnet_link_t promotion

    return (format (s, "%s", vnet_link_names[link]));
}

u8 *
format_fib_forw_chain_type (u8 * s, va_list * args)
{
    fib_forward_chain_type_t fct = va_arg(*args, int);

    return (format (s, "%s", fib_forw_chain_names[fct]));
}

u8 *
format_fib_mpls_lsp_mode(u8 *s, va_list *ap)
{
    fib_mpls_lsp_mode_t mode = va_arg(*ap, int);

    return (format (s, "%s", fib_mpls_lsp_mode_names[mode])); 
}

u8 *
format_fib_mpls_label (u8 *s, va_list *ap)
{
    fib_mpls_label_t *label = va_arg(*ap, fib_mpls_label_t *);

    s = format(s, "%U %U ttl:%d exp:%d",
               format_mpls_unicast_label,
               label->fml_value,
               format_fib_mpls_lsp_mode,
               label->fml_mode,
               label->fml_ttl,
               label->fml_exp);

    return (s);
}

void
fib_prefix_from_ip46_addr (const ip46_address_t *addr,
			   fib_prefix_t *pfx)
{
    ASSERT(!ip46_address_is_zero(addr));

    pfx->fp_proto = ((ip46_address_is_ip4(addr) ?
		      FIB_PROTOCOL_IP4 :
		      FIB_PROTOCOL_IP6));
    pfx->fp_len = ((ip46_address_is_ip4(addr) ?
		    32 : 128));
    pfx->fp_addr = *addr;
    pfx->___fp___pad = 0;
}

u8 *
format_fib_route_path_flags (u8 *s, va_list *ap)
{
    fib_route_path_flags_t flags = va_arg (*ap, fib_route_path_flags_t);

    if (flags & FIB_ROUTE_PATH_RESOLVE_VIA_HOST)
        s = format (s, "via-host");
    if (flags & FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED)
        s = format (s, "via-attached,");
    if (flags & FIB_ROUTE_PATH_LOCAL)
        s = format (s, "local,");
    if (flags & FIB_ROUTE_PATH_ATTACHED)
        s = format (s, "attached,");
    if (flags & FIB_ROUTE_PATH_DROP)
         s = format (s, "drop,");
   if (flags & FIB_ROUTE_PATH_EXCLUSIVE)
        s = format (s, "exclusive,");
    if (flags & FIB_ROUTE_PATH_INTF_RX)
        s = format (s, "intf-rx,");
    if (flags & FIB_ROUTE_PATH_RPF_ID)
        s = format (s, "rpf-id,");
    if (flags & FIB_ROUTE_PATH_SOURCE_LOOKUP)
        s = format (s, "src-lkup,");
    if (flags & FIB_ROUTE_PATH_UDP_ENCAP)
        s = format (s, "udp-encap,");
    if (flags & FIB_ROUTE_PATH_BIER_FMASK)
        s = format (s, "bier-fmask,");
    if (flags & FIB_ROUTE_PATH_BIER_TABLE)
        s = format (s, "bier-table,");
    if (flags & FIB_ROUTE_PATH_BIER_IMP)
        s = format (s, "bier-imp,");
    if (flags & FIB_ROUTE_PATH_DEAG)
        s = format (s, "deag,");
    if (flags & FIB_ROUTE_PATH_DVR)
        s = format (s, "dvr,");
    if (flags & FIB_ROUTE_PATH_ICMP_UNREACH)
        s = format (s, "imcp-unreach,");
    if (flags & FIB_ROUTE_PATH_ICMP_PROHIBIT)
        s = format (s, "icmp-prohibit,");
    if (flags & FIB_ROUTE_PATH_CLASSIFY)
        s = format (s, "classify,");
    if (flags & FIB_ROUTE_PATH_POP_PW_CW)
        s = format (s, "pop-pw-cw,");

    return (s);
}

u8 *
format_fib_route_path (u8 *s, va_list *ap)
{
    fib_route_path_t *rpath = va_arg (*ap, fib_route_path_t*);

    s = format (s, "%U %U, %U, [%U]",
                format_dpo_proto, rpath->frp_proto,
                format_ip46_address, &rpath->frp_addr, IP46_TYPE_ANY,
                format_vnet_sw_if_index_name, vnet_get_main (),
                rpath->frp_sw_if_index,
                format_fib_route_path_flags, rpath->frp_flags);

    return (s);
}

void
fib_prefix_from_mpls_label (mpls_label_t label,
                            mpls_eos_bit_t eos,
			    fib_prefix_t *pfx)
{
    pfx->fp_proto = FIB_PROTOCOL_MPLS;
    pfx->fp_len = 21;
    pfx->fp_label = label;
    pfx->fp_eos = eos;
    pfx->___fp___pad = 0;
}

void
fib_prefix_copy (fib_prefix_t *dst,
                 const fib_prefix_t *src)
{
    clib_memcpy(dst, src, sizeof(*dst));
}

int
fib_prefix_cmp (const fib_prefix_t *p1,
		const fib_prefix_t *p2)
{
    int res;

    res = (p1->fp_proto - p2->fp_proto);

    if (0 == res)
    {
	switch (p1->fp_proto)
	{
	case FIB_PROTOCOL_IP4:
	case FIB_PROTOCOL_IP6:
	    res = (p1->fp_len - p2->fp_len);

	    if (0 == res)
	    {
		res = ip46_address_cmp(&p1->fp_addr, &p2->fp_addr);
	    }
	    break;
	case FIB_PROTOCOL_MPLS:
	    res = (p1->fp_label - p2->fp_label);

	    if (0 == res)
	    {
		res = (p1->fp_eos - p2->fp_eos);
	    }
	    break;
	}
    }

    return (res);
}

int
fib_prefix_is_cover (const fib_prefix_t *p1,
		     const fib_prefix_t *p2)
{
    switch (p1->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_destination_matches_route(&ip4_main,
					      &p1->fp_addr.ip4,
					      &p2->fp_addr.ip4,
					      p1->fp_len));
    case FIB_PROTOCOL_IP6:
	return (ip6_destination_matches_route(&ip6_main,
					      &p1->fp_addr.ip6,
					      &p2->fp_addr.ip6,
					      p1->fp_len));
    case FIB_PROTOCOL_MPLS:
	break;
    }
    return (0);
}

u8
fib_prefix_get_host_length (fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (32);
    case FIB_PROTOCOL_IP6:
	return (128);
    case FIB_PROTOCOL_MPLS:
	return (21);
    }
    return (0);
}

int
fib_prefix_is_host (const fib_prefix_t *prefix)
{
    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (prefix->fp_len == 32);
    case FIB_PROTOCOL_IP6:
	return (prefix->fp_len == 128);
    case FIB_PROTOCOL_MPLS:
	return (!0);
    }
    return (0);
}

void
fib_prefix_normalize (const fib_prefix_t *p,
                      fib_prefix_t *out)
{
    fib_prefix_copy (out, p);

    switch (p->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	ip4_address_normalize(&out->fp_addr.ip4, out->fp_len);
        break;
    case FIB_PROTOCOL_IP6:
	ip6_address_normalize(&out->fp_addr.ip6, out->fp_len);
        break;
    case FIB_PROTOCOL_MPLS:
	break;
    }
}

u8 *
format_fib_prefix (u8 * s, va_list * args)
{
    fib_prefix_t *fp = va_arg (*args, fib_prefix_t *);

    /*
     * protocol specific so it prints ::/0 correctly.
     */
    switch (fp->fp_proto)
    {
    case FIB_PROTOCOL_IP6:
    {
	ip6_address_t p6 = fp->fp_addr.ip6;

	ip6_address_mask(&p6, &(ip6_main.fib_masks[fp->fp_len]));
	s = format (s, "%U", format_ip6_address, &p6);
	break;
    }
    case FIB_PROTOCOL_IP4:
    {
	ip4_address_t p4 = fp->fp_addr.ip4;
	p4.as_u32 &= ip4_main.fib_masks[fp->fp_len];

	s = format (s, "%U", format_ip4_address, &p4);
	break;
    }
    case FIB_PROTOCOL_MPLS:
	s = format (s, "%U:%U",
		    format_mpls_unicast_label, fp->fp_label,
		    format_mpls_eos_bit, fp->fp_eos);
	break;
    }
    s = format (s, "/%d", fp->fp_len);

    return (s);
}

int
fib_route_path_cmp (const fib_route_path_t *rpath1,
		    const fib_route_path_t *rpath2)
{
    int res;

    res = ip46_address_cmp(&rpath1->frp_addr,
			   &rpath2->frp_addr);

    if (0 != res) return (res);

    res = (rpath1->frp_sw_if_index - rpath2->frp_sw_if_index);

    if (0 != res) return (res);

    if (ip46_address_is_zero(&rpath1->frp_addr))
    {
	res = rpath1->frp_fib_index - rpath2->frp_fib_index;
    }

    return (res);
}

dpo_proto_t
fib_proto_to_dpo (fib_protocol_t fib_proto)
{
    switch (fib_proto)
    {
    case FIB_PROTOCOL_IP6:
        return (DPO_PROTO_IP6);
    case FIB_PROTOCOL_IP4:
        return (DPO_PROTO_IP4);
    case FIB_PROTOCOL_MPLS:
        return (DPO_PROTO_MPLS);
    }
    ASSERT(0);
    return (0);
}

fib_protocol_t
dpo_proto_to_fib (dpo_proto_t dpo_proto)
{
    switch (dpo_proto)
    {
    case DPO_PROTO_IP6:
        return (FIB_PROTOCOL_IP6);
    case DPO_PROTO_IP4:
        return (FIB_PROTOCOL_IP4);
    case DPO_PROTO_MPLS:
        return (FIB_PROTOCOL_MPLS);
    default:
	break;
    }
    ASSERT(0);
    return (0);
}

vnet_link_t
fib_proto_to_link (fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (VNET_LINK_IP4);
    case FIB_PROTOCOL_IP6:
	return (VNET_LINK_IP6);
    case FIB_PROTOCOL_MPLS:
	return (VNET_LINK_MPLS);
    }
    ASSERT(0);
    return (0);
}

ip46_type_t
fib_proto_to_ip46 (fib_protocol_t fproto)
{
    switch (fproto)
    {
    case FIB_PROTOCOL_IP4:
	return (IP46_TYPE_IP4);
    case FIB_PROTOCOL_IP6:
	return (IP46_TYPE_IP6);
    case FIB_PROTOCOL_MPLS:
	return (IP46_TYPE_ANY);
    }
    ASSERT(0);
    return (IP46_TYPE_ANY);
}

fib_protocol_t
fib_proto_from_ip46 (ip46_type_t iproto)
{
    switch (iproto)
    {
    case IP46_TYPE_IP4:
        return FIB_PROTOCOL_IP4;
    case IP46_TYPE_IP6:
        return FIB_PROTOCOL_IP6;
    case IP46_TYPE_ANY:
        ASSERT(0);
        return FIB_PROTOCOL_IP4;
    }

    ASSERT(0);
    return FIB_PROTOCOL_IP4;
}

fib_forward_chain_type_t
fib_forw_chain_type_from_dpo_proto (dpo_proto_t proto)
{
    switch (proto)
    {
    case DPO_PROTO_IP4:
	return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
    case DPO_PROTO_IP6:
	return (FIB_FORW_CHAIN_TYPE_UNICAST_IP6);
    case DPO_PROTO_MPLS:
	return (FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS);
    case DPO_PROTO_ETHERNET:
	return (FIB_FORW_CHAIN_TYPE_ETHERNET);
    case DPO_PROTO_NSH:
        return (FIB_FORW_CHAIN_TYPE_NSH);
    case DPO_PROTO_BIER:
	return (FIB_FORW_CHAIN_TYPE_BIER);
    }
    ASSERT(0);
    return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
}

fib_forward_chain_type_t
fib_forw_chain_type_from_fib_proto (fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
    case FIB_PROTOCOL_IP6:
	return (FIB_FORW_CHAIN_TYPE_UNICAST_IP6);
    case FIB_PROTOCOL_MPLS:
	return (FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS);
    }
    ASSERT(0);
    return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
}

vnet_link_t
fib_forw_chain_type_to_link_type (fib_forward_chain_type_t fct)
{
    switch (fct)
    {
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
	return (VNET_LINK_IP4);
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
	return (VNET_LINK_IP6);
    case FIB_FORW_CHAIN_TYPE_ETHERNET:
	return (VNET_LINK_ETHERNET);
    case FIB_FORW_CHAIN_TYPE_NSH:
        return (VNET_LINK_NSH);
    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
    case FIB_FORW_CHAIN_TYPE_BIER:
	/*
	 * insufficient information to to convert
	 */
	ASSERT(0);
	break;
    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
	return (VNET_LINK_MPLS);
    }
    return (VNET_LINK_IP4);
}

fib_forward_chain_type_t
fib_forw_chain_type_from_link_type (vnet_link_t link_type)
{
    switch (link_type)
    {
    case VNET_LINK_IP4:
        return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
    case VNET_LINK_IP6:
        return (FIB_FORW_CHAIN_TYPE_UNICAST_IP6);
    case VNET_LINK_MPLS:
        return (FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS);
    case VNET_LINK_ETHERNET:
        return (FIB_FORW_CHAIN_TYPE_ETHERNET);
    case VNET_LINK_NSH:
        return (FIB_FORW_CHAIN_TYPE_NSH);
    case VNET_LINK_ARP:
        break;
    }

    ASSERT(0);
    return (FIB_FORW_CHAIN_TYPE_UNICAST_IP4);
}

dpo_proto_t
fib_forw_chain_type_to_dpo_proto (fib_forward_chain_type_t fct)
{
    switch (fct)
    {
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
	return (DPO_PROTO_IP4);
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
	return (DPO_PROTO_IP6);
    case FIB_FORW_CHAIN_TYPE_ETHERNET:
	return (DPO_PROTO_ETHERNET);
    case FIB_FORW_CHAIN_TYPE_NSH:
        return (DPO_PROTO_NSH);
    case FIB_FORW_CHAIN_TYPE_BIER:
	return (DPO_PROTO_BIER);
    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
	return (DPO_PROTO_MPLS);
    }
    return (DPO_PROTO_IP4);
}

uword
unformat_fib_route_path (unformat_input_t * input, va_list * args)
{
    fib_route_path_t *rpath = va_arg (*args, fib_route_path_t *);
    dpo_proto_t *payload_proto = va_arg (*args, void*);
    u32 weight, preference, udp_encap_id, fi;
    mpls_label_t out_label;
    vnet_main_t *vnm;

    vnm = vnet_get_main ();
    clib_memset(rpath, 0, sizeof(*rpath));
    rpath->frp_weight = 1;
    rpath->frp_sw_if_index = ~0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "%U %U",
                      unformat_ip4_address,
                      &rpath->frp_addr.ip4,
                      unformat_vnet_sw_interface, vnm,
                      &rpath->frp_sw_if_index))
        {
            rpath->frp_proto = DPO_PROTO_IP4;
        }
        else if (unformat (input, "%U %U",
                           unformat_ip6_address,
                           &rpath->frp_addr.ip6,
                           unformat_vnet_sw_interface, vnm,
                           &rpath->frp_sw_if_index))
        {
            rpath->frp_proto = DPO_PROTO_IP6;
        }
        else if (unformat (input, "weight %u", &weight))
        {
            rpath->frp_weight = weight;
        }
        else if (unformat (input, "preference %u", &preference))
        {
            rpath->frp_preference = preference;
        }
        else if (unformat (input, "%U next-hop-table %d",
                           unformat_ip4_address,
                           &rpath->frp_addr.ip4,
                           &rpath->frp_fib_index))
        {
            rpath->frp_sw_if_index = ~0;
            rpath->frp_proto = DPO_PROTO_IP4;

            /*
             * the user enter table-ids, convert to index
             */
            fi = fib_table_find (FIB_PROTOCOL_IP4, rpath->frp_fib_index);
            if (~0 == fi)
                return 0;
            rpath->frp_fib_index = fi;
        }
        else if (unformat (input, "%U next-hop-table %d",
                           unformat_ip6_address,
                           &rpath->frp_addr.ip6,
                           &rpath->frp_fib_index))
        {
            rpath->frp_sw_if_index = ~0;
            rpath->frp_proto = DPO_PROTO_IP6;
            fi = fib_table_find (FIB_PROTOCOL_IP6, rpath->frp_fib_index);
            if (~0 == fi)
                return 0;
            rpath->frp_fib_index = fi;
        }
        else if (unformat (input, "%U",
                           unformat_ip4_address,
                           &rpath->frp_addr.ip4))
        {
            /*
             * the recursive next-hops are by default in the default table
             */
            rpath->frp_fib_index = 0;
            rpath->frp_sw_if_index = ~0;
            rpath->frp_proto = DPO_PROTO_IP4;
        }
        else if (unformat (input, "%U",
                           unformat_ip6_address,
                           &rpath->frp_addr.ip6))
        {
            rpath->frp_fib_index = 0;
            rpath->frp_sw_if_index = ~0;
            rpath->frp_proto = DPO_PROTO_IP6;
        }
        else if (unformat (input, "udp-encap %d", &udp_encap_id))
        {
            rpath->frp_udp_encap_id = udp_encap_id;
            rpath->frp_flags |= FIB_ROUTE_PATH_UDP_ENCAP;
            rpath->frp_proto = *payload_proto;
        }
        else if (unformat (input, "lookup in table %d", &rpath->frp_fib_index))
        {
            rpath->frp_proto = *payload_proto;
            rpath->frp_sw_if_index = ~0;
            rpath->frp_flags |= FIB_ROUTE_PATH_DEAG;
        }
        else if (unformat (input, "resolve-via-host"))
        {
            rpath->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_HOST;
        }
        else if (unformat (input, "resolve-via-attached"))
        {
            rpath->frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED;
        }
        else if (unformat (input, "pop-pw-cw"))
        {
            rpath->frp_flags |= FIB_ROUTE_PATH_POP_PW_CW;
        }
        else if (unformat (input,
                           "ip4-lookup-in-table %d",
                           &rpath->frp_fib_index))
        {
            rpath->frp_proto = DPO_PROTO_IP4;
            *payload_proto = DPO_PROTO_IP4;
            fi = fib_table_find (FIB_PROTOCOL_IP4, rpath->frp_fib_index);
            if (~0 == fi)
                return 0;
            rpath->frp_fib_index = fi;
        }
        else if (unformat (input,
                           "ip6-lookup-in-table %d",
                           &rpath->frp_fib_index))
        {
            rpath->frp_proto = DPO_PROTO_IP6;
            *payload_proto = DPO_PROTO_IP6;
            fi = fib_table_find (FIB_PROTOCOL_IP6, rpath->frp_fib_index);
            if (~0 == fi)
                return 0;
            rpath->frp_fib_index = fi;
        }
        else if (unformat (input,
                           "mpls-lookup-in-table %d",
                           &rpath->frp_fib_index))
        {
            rpath->frp_proto = DPO_PROTO_MPLS;
            *payload_proto = DPO_PROTO_MPLS;
            fi = fib_table_find (FIB_PROTOCOL_MPLS, rpath->frp_fib_index);
            if (~0 == fi)
                return 0;
            rpath->frp_fib_index = fi;
        }
        else if (unformat (input, "src-lookup"))
        {
            rpath->frp_flags |= FIB_ROUTE_PATH_SOURCE_LOOKUP;
        }
        else if (unformat (input,
                           "l2-input-on %U",
                           unformat_vnet_sw_interface, vnm,
                           &rpath->frp_sw_if_index))
        {
            rpath->frp_proto = DPO_PROTO_ETHERNET;
            *payload_proto = DPO_PROTO_ETHERNET;
            rpath->frp_flags |= FIB_ROUTE_PATH_INTF_RX;
        }
        else if (unformat (input, "via-label %U",
                           unformat_mpls_unicast_label,
                           &rpath->frp_local_label))
        {
            rpath->frp_eos = MPLS_NON_EOS;
            rpath->frp_proto = DPO_PROTO_MPLS;
            rpath->frp_sw_if_index = ~0;
        }
        else if (unformat (input, "rx-ip4 %U",
                           unformat_vnet_sw_interface, vnm,
                           &rpath->frp_sw_if_index))
        {
            rpath->frp_proto = DPO_PROTO_IP4;
            rpath->frp_flags = FIB_ROUTE_PATH_INTF_RX;
        }
      else if (unformat (input, "local"))
	{
	  clib_memset (&rpath->frp_addr, 0, sizeof (rpath->frp_addr));
	  rpath->frp_sw_if_index = ~0;
	  rpath->frp_weight = 1;
	  rpath->frp_flags |= FIB_ROUTE_PATH_LOCAL;
        }
      else if (unformat (input, "%U",
			 unformat_mfib_itf_flags, &rpath->frp_mitf_flags))
	;
      else if (unformat (input, "out-labels"))
        {
            while (unformat (input, "%U",
                             unformat_mpls_unicast_label, &out_label))
            {
                fib_mpls_label_t fml = {
                    .fml_value = out_label,
                };
                vec_add1(rpath->frp_label_stack, fml);
            }
        }
        else if (unformat (input, "%U",
                           unformat_vnet_sw_interface, vnm,
                           &rpath->frp_sw_if_index))
        {
            rpath->frp_proto = *payload_proto;
        }
        else if (unformat (input, "via"))
        {
            /* new path, back up and return */
            unformat_put_input (input);
            unformat_put_input (input);
            unformat_put_input (input);
            unformat_put_input (input);
            break;
        }
        else
        {
            return (0);
        }
    }

    return (1);
}
