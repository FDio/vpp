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
#include <vnet/mpls/mpls.h>

/*
 * arrays of protocol and link names
 */
static const char* fib_protocol_names[] = FIB_PROTOCOLS;
static const char* vnet_link_names[] = VNET_LINKS;
static const char* fib_forw_chain_names[] = FIB_FORW_CHAINS;

u8 *
format_fib_protocol (u8 * s, va_list ap)
{
    fib_protocol_t proto = va_arg(ap, int); // fib_protocol_t promotion

    return (format (s, "%s", fib_protocol_names[proto]));
}

u8 *
format_vnet_link (u8 * s, va_list ap)
{
    vnet_link_t link = va_arg(ap, int); // vnet_link_t promotion

    return (format (s, "%s", vnet_link_names[link]));
}

u8 *
format_fib_forw_chain_type (u8 * s, va_list * args)
{
    fib_forward_chain_type_t fct = va_arg(*args, int);

    return (format (s, "%s", fib_forw_chain_names[fct]));
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
    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
	return (DPO_PROTO_MPLS);
    }
    return (DPO_PROTO_IP4);
}
