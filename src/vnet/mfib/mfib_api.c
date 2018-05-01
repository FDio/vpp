/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vnet/mfib/mfib_api.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ip/ip_types.h>

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

void
mfib_api_prefix_encode (const mfib_prefix_t *in,
                        vl_api_mfib_prefix_t *out)
{
    out->af = (FIB_PROTOCOL_IP6 == in->fp_proto ?
               ADDRESS_IP6 :
               ADDRESS_IP4);
    out->grp_address_length = in->fp_len;

    ip_api_address_union_encode(&in->fp_grp_addr, out->af, &out->grp_address);
    ip_api_address_union_encode(&in->fp_src_addr, out->af, &out->src_address);
}

void
mfib_api_prefix_decode (const vl_api_mfib_prefix_t *in,
                        mfib_prefix_t *out)
{
    out->fp_proto = (ADDRESS_IP6 == in->af ?
                     FIB_PROTOCOL_IP6 :
                     FIB_PROTOCOL_IP4);
    out->fp_len = in->grp_address_length;

    ip_api_address_union_decode(&in->grp_address, in->af, &out->fp_grp_addr);
    ip_api_address_union_decode(&in->src_address, in->af, &out->fp_grp_addr);
}

static vl_api_mfib_itf_flags_t
mfib_api_path_itf_flags_encode (mfib_itf_flags_t flags)
{
    vl_api_mfib_itf_flags_t out = MFIB_API_ITF_FLAG_NONE;

    switch (flags)
    {
    case MFIB_ITF_FLAG_NONE:
        out = MFIB_API_ITF_FLAG_NONE;
        break;
    case MFIB_ITF_FLAG_NEGATE_SIGNAL:
        out = MFIB_API_ITF_FLAG_NEGATE_SIGNAL;
        break;
    case MFIB_ITF_FLAG_ACCEPT:
        out = MFIB_API_ITF_FLAG_ACCEPT;
        break;
    case MFIB_ITF_FLAG_FORWARD:
        out = MFIB_API_ITF_FLAG_FORWARD;
        break;
    case MFIB_ITF_FLAG_SIGNAL_PRESENT:
        out = MFIB_API_ITF_FLAG_SIGNAL_PRESENT;
        break;
    case MFIB_ITF_FLAG_DONT_PRESERVE:
        out = MFIB_API_ITF_FLAG_DONT_PRESERVE;
        break;
    }
    return (ntohl(out));
}

void
mfib_api_path_encode (const fib_route_path_t *in,
                      vl_api_mfib_path_t *out)
{
    out->itf_flags = mfib_api_path_itf_flags_encode(in->frp_mitf_flags);

    fib_api_path_encode(in, &out->path);
}

static int
mfib_api_path_itf_flags_decode (vl_api_mfib_itf_flags_t in,
                                mfib_itf_flags_t *out)
{
    in = ntohl(in);

    switch (in)
    {
    case MFIB_API_ITF_FLAG_NONE:
        *out = MFIB_ITF_FLAG_NONE;
        return (0);
    case MFIB_API_ITF_FLAG_NEGATE_SIGNAL:
        *out = MFIB_ITF_FLAG_NEGATE_SIGNAL;
        return (0);
    case MFIB_API_ITF_FLAG_ACCEPT:
        *out = MFIB_ITF_FLAG_ACCEPT;
        return (0);
    case MFIB_API_ITF_FLAG_FORWARD:
        *out = MFIB_ITF_FLAG_FORWARD;
        return (0);
    case MFIB_API_ITF_FLAG_SIGNAL_PRESENT:
        *out = MFIB_ITF_FLAG_SIGNAL_PRESENT;
        return (0);
    case MFIB_API_ITF_FLAG_DONT_PRESERVE:
        *out = MFIB_ITF_FLAG_DONT_PRESERVE;
        return (0);
    }
    return (-1);
}

int
mfib_api_path_decode (const vl_api_mfib_path_t *in,
                      fib_route_path_t *out)
{
    mfib_api_path_itf_flags_decode(in->itf_flags, &out->frp_mitf_flags);

    return (fib_api_path_decode(&in->path, out));
}

int
mfib_api_table_id_decode (fib_protocol_t fproto,
                          u32 table_id,
                          u32 *fib_index)
{
    *fib_index = mfib_table_find(fproto, table_id);

    if (INDEX_INVALID == *fib_index)
    {
        return VNET_API_ERROR_NO_SUCH_FIB;
    }

    return (0);
}
