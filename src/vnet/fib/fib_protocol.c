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

#include <vnet/fib/fib_protocol.h>

/*
 * arrays of protocol and link names
 */
static const char* fib_protocol_names[] = FIB_PROTOCOLS;

u8 *
format_fib_protocol (u8 * s, va_list * ap)
{
    fib_protocol_t proto = va_arg(*ap, int); // fib_protocol_t promotion

    return (format (s, "%s", fib_protocol_names[proto]));
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

fib_protocol_t
fib_ip_proto (bool is_ip6)
{
    return ((is_ip6) ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
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
