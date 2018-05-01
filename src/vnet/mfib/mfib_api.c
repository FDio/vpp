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
    out->is_ip6 = (FIB_PROTOCOL_IP6 == in->fp_proto);
    out->grp_address_length = in->fp_len;
    if (out->is_ip6)
    {
        memcpy (out->grp_address,
                &in->fp_grp_addr.ip6,
                sizeof (in->fp_grp_addr.ip6));
        memcpy (out->src_address,
                &in->fp_src_addr.ip6,
                sizeof (in->fp_src_addr.ip6));
    }
    else
    {
        memcpy (out->grp_address,
                &in->fp_grp_addr.ip4,
                sizeof (in->fp_grp_addr.ip4));
        memcpy (out->src_address,
                &in->fp_src_addr.ip4,
                sizeof (in->fp_src_addr.ip4));
    }
}

void
mfib_api_prefix_decode (const vl_api_mfib_prefix_t *in,
                        mfib_prefix_t *out)
{
    out->fp_proto = (in->is_ip6 ?
                     FIB_PROTOCOL_IP6 :
                     FIB_PROTOCOL_IP4);
    out->fp_len = in->grp_address_length;
    if (in->is_ip6)
    {
        memcpy (&out->fp_grp_addr.ip6,
                in->grp_address,
                sizeof (out->fp_grp_addr.ip6));
        memcpy (&out->fp_src_addr.ip6,
                in->src_address,
                sizeof (out->fp_src_addr.ip6));
    }
    else
    {
        memcpy (&out->fp_grp_addr.ip4,
                in->grp_address,
                sizeof (out->fp_grp_addr.ip4));
        memcpy (&out->fp_src_addr.ip4,
                in->src_address,
                sizeof (out->fp_src_addr.ip4));
    }    
}

void
mfib_api_path_encode (const mfib_route_path_t *in,
                      vl_api_mfib_path_t *out)
{
    out->itf_flags = ntohl(in->itf_flags);

    fib_api_path_encode(&in->rpath, &out->path);
}

int
mfib_api_path_decode (const vl_api_mfib_path_t *in,
                      mfib_route_path_t *out)
{
    out->itf_flags = ntohl(in->itf_flags);

    return (fib_api_path_decode(&in->path, &out->rpath));
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
