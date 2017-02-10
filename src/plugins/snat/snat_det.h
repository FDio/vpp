/*
 * snat_det.h - deterministic nat definitions
 *
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_snat_det_h__
#define __included_snat_det_h__

#include <vnet/ip/ip.h>

always_inline int
is_addr_in_net (ip4_address_t * addr, ip4_address_t * net, u8 plen)
{
  if (net->as_u32 == (addr->as_u32 & ip4_main.fib_masks[plen]))
    return 1;
  return 0;
}

always_inline snat_det_map_t *
snat_det_map_by_user (snat_main_t * sm, ip4_address_t * user_addr)
{
  snat_det_map_t * dm;

  pool_foreach (dm, sm->det_maps,
  ({
    if (is_addr_in_net(user_addr, &dm->in_addr, dm->in_plen))
      return dm;
  }));
  return 0;
}

always_inline snat_det_map_t *
snat_det_map_by_out (snat_main_t * sm, ip4_address_t * out_addr)
{
  snat_det_map_t * dm;

  pool_foreach (dm, sm->det_maps,
  ({
    if (is_addr_in_net(out_addr, &dm->out_addr, dm->out_plen))
      return dm;
  }));
  return 0;
}

always_inline void
snat_det_forward (snat_det_map_t * dm, ip4_address_t * in_addr,
                  ip4_address_t * out_addr, u16 * lo_port)
{
  u32 in_offset, out_offset;

  in_offset = clib_net_to_host_u32(in_addr->as_u32) -
    clib_net_to_host_u32(dm->in_addr.as_u32);
  out_offset = in_offset / dm->sharing_ratio;
  out_addr->as_u32 = clib_host_to_net_u32(
    clib_net_to_host_u32(dm->out_addr.as_u32) + out_offset);
  *lo_port = 1024 + dm->ports_per_host * (in_offset % dm->sharing_ratio);
}

always_inline void
snat_det_reverse (snat_det_map_t * dm, ip4_address_t * out_addr, u16 out_port,
                  ip4_address_t * in_addr)
{
  u32 in_offset1, in_offset2, out_offset;

  out_offset = clib_net_to_host_u32(out_addr->as_u32) -
    clib_net_to_host_u32(dm->out_addr.as_u32);
  in_offset1 = out_offset * dm->sharing_ratio;
  in_offset2 = (out_port - 1024) / dm->ports_per_host;
  in_addr->as_u32 = clib_host_to_net_u32(
    clib_net_to_host_u32(dm->in_addr.as_u32) + in_offset1 + in_offset2);
}

always_inline u32
snat_det_user_ses_offset (ip4_address_t * addr, u8 plen)
{
  return (clib_net_to_host_u32(addr->as_u32) & pow2_mask(32 - plen)) *
     SNAT_DET_SES_PER_USER;
}

always_inline u16
snat_det_get_in_port_by_out (snat_det_map_t * dm, ip4_address_t * in_addr,
                             u64 out_key)
{
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);
  for (i = 0; i < SNAT_DET_SES_PER_USER; i++)
     {
       if (!dm->sessions[i + user_offset].in_port)
         return 0;
       if (dm->sessions[i + user_offset].out.as_u64 == out_key)
         return dm->sessions[i + user_offset].in_port;
     }

  return 0;
}

always_inline int
snat_det_find_ses_by_in_port_or_create (snat_det_map_t * dm,
                                        ip4_address_t * in_addr, u16 in_port,
                                        snat_det_out_key_t * out)
{
  u32 user_offset;
  u16 i;

  user_offset = snat_det_user_ses_offset (in_addr, dm->in_plen);
  for (i = 0; i < SNAT_DET_SES_PER_USER; i++)
    {
      if (!dm->sessions[i + user_offset].in_port)
        {
          dm->sessions[i + user_offset].in_port = in_port;
          dm->sessions[i + user_offset].out.as_u64 = out->as_u64;
          vlib_increment_simple_counter(&dm->ses_num, os_get_cpu_number(), 0, 1);
          return 0;
        }
      if (dm->sessions[i + user_offset].in_port == in_port)
        return 0;
    }

  return 1;
}

#endif /* __included_snat_det_h__ */
