/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/**
 * @brief FIB Source Address selection
 *
 * Use the FIB for source address selection on an interface
 */

#include <vnet/fib/fib_sas.h>
#include <vnet/adj/adj_glean.h>
#include <vnet/ip/ip6_link.h>


bool
fib_sas_get (u32 sw_if_index,
             ip_address_family_t af,
             const ip46_address_t *dst,
             ip46_address_t *src)
{
    switch (af)
    {
    case AF_IP4:
        if (dst)
            return (fib_sas4_get(sw_if_index, &dst->ip4, &src->ip4));
        else
            return (fib_sas4_get(sw_if_index, NULL, &src->ip4));
    case AF_IP6:
        if (dst)
            return (fib_sas6_get(sw_if_index, &dst->ip6, &src->ip6));
        else
            return (fib_sas6_get(sw_if_index, NULL, &src->ip6));
    }
    return (false);
}

bool
fib_sas4_get (u32 sw_if_index,
              const ip4_address_t *dst,
              ip4_address_t *src)
{
    ip46_address_t d_tmp, *d_tmpp = NULL;
    const ip46_address_t *s_tmp;
    vnet_sw_interface_t *swif;

    if (dst)
    {
        d_tmpp = &d_tmp;
        d_tmp.ip4 = *dst;
    }

    /*
     * If the interface is unnumbered then use the IP interface
     */
    swif = vnet_get_sw_interface (vnet_get_main(), sw_if_index);

    if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)
        sw_if_index = swif->unnumbered_sw_if_index;

    /*
     * get the source address from the glean adjacency
     */
    s_tmp = adj_glean_get_src (FIB_PROTOCOL_IP4, sw_if_index, d_tmpp);

    if (NULL != s_tmp)
    {
        src->as_u32 = s_tmp->ip4.as_u32;
        return (true);
    }

    return (false);
}

bool
fib_sas6_get (u32 sw_if_index,
              const ip6_address_t *dst,
              ip6_address_t *src)
{
    ip46_address_t d_tmp, *d_tmpp = NULL;
    const ip46_address_t *s_tmp;

    if (dst)
    {
        d_tmpp = &d_tmp;
        d_tmp.ip6 = *dst;
    }

    /*
     * if the dst is v6 and link local, use the source link local
     */
    if (ip6_address_is_link_local_unicast (dst))
    {
        ip6_address_copy (src, ip6_get_link_local_address (sw_if_index));
        return (true);
    }

    /*
     * get the source address from the glean adjacency
     */
    s_tmp = adj_glean_get_src (FIB_PROTOCOL_IP6, sw_if_index, d_tmpp);

    if (NULL != s_tmp)
    {
        ip6_address_copy(src, &s_tmp->ip6);
        return (true);
    }

    return (false);
}
