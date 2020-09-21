/*
 *------------------------------------------------------------------
 *
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
 *------------------------------------------------------------------
 */

#include <lisp/lisp-cp/lisp_types_api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

int
unformat_lisp_eid_api (gid_address_t * dst, u32 vni, const vl_api_eid_t * eid)
{
  switch (eid->type)
    {
    case EID_TYPE_API_PREFIX:			/* ip prefix */
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      ip_address_decode2 (&eid->address.prefix.address, &dst->ippref.addr);
      gid_address_ippref_len (dst) = eid->address.prefix.len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case EID_TYPE_API_MAC:			/* l2 mac */
      gid_address_type (dst) = GID_ADDR_MAC;
      mac_address_decode (eid->address.mac, (mac_address_t *) gid_address_mac (dst));
      break;
    default:
      /* unknown type */
      return VNET_API_ERROR_INVALID_VALUE;
    }

  gid_address_vni (dst) = clib_net_to_host_u32 (vni);

  return 0;
}

void
lisp_fid_put_api (vl_api_eid_t * eid, const fid_address_t * fid)
{
  switch (fid_addr_type (fid))
    {
    case FID_ADDR_IP_PREF:
      ip_prefix_encode2 (&fid_addr_ippref (fid), &eid->address.prefix);
      eid->type = EID_TYPE_API_PREFIX;
      break;

    case FID_ADDR_MAC:
      mac_address_encode ((mac_address_t *) fid_addr_mac (fid), eid->address.mac);
      eid->type = EID_TYPE_API_MAC;
      break;

    default:
      clib_warning ("Unknown FID type %d!", fid_addr_type (fid));
      break;
    }
}

void
lisp_gid_put_api (vl_api_eid_t * eid, const gid_address_t * gid)
{
  switch (gid_address_type (gid))
    {
    case GID_ADDR_IP_PREFIX:
      ip_prefix_encode2 (&gid_address_ippref (gid), &eid->address.prefix);
      eid->type = EID_TYPE_API_PREFIX;
      break;

    case GID_ADDR_MAC:
      mac_address_encode ((mac_address_t *) gid_address_mac (gid), eid->address.mac);
      eid->type = EID_TYPE_API_MAC;
      break;

    default:
      clib_warning ("Unknown GID type %d!", gid_address_type (gid));
      break;
    }
}
