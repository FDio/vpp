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

#include <vnet/mfib/mfib_api.h>

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
mfib_api_prefix_encode (const mfib_prefix_t *pfx,
                        struct _vl_api_mfib_prefix *out)
{
    out->is_ip6 = (FIB_PROTOCOL_IP6 == pfx->fp_proto);
    out->grp_address_length = pfx->fp_len;
    memcpy (out->grp_address,
            &pfx->fp_grp_addr.ip6,
            sizeof (pfx->fp_grp_addr.ip6));
    memcpy (out->src_address,
            &pfx->fp_src_addr.ip6,
            sizeof (pfx->fp_src_addr.ip6));
}

/* void */
/* mfib_api_prefix_decode (const struct _vl_api_mfib_prefix *in, */
/*                         mfib_prefix_t *out) */
/* { */
/* } */
