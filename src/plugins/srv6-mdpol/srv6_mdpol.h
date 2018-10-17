/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_srv6_mdpol_h__
#define __included_srv6_mdpol_h__

#include <vnet/vnet.h>

#define SRH_TLV_TYPE_OPAQUE 6

typedef struct
{
  /* Type */
  u8 type;

  /* Length of the variable length data in octets */
  u8 length;

  /* Opaque data */
  u8 value[14];
} __attribute__ ((packed)) ip6_srh_tlv_opaque_t;

#endif /* __included_srv6_mdpol_h__ */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
