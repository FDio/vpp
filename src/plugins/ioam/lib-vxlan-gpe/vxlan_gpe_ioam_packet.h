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
#ifndef __included_vxlan_gpe_ioam_packet_h__
#define __included_vxlan_gpe_ioam_packet_h__

#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/ip.h>



#define VXLAN_GPE_OPTION_TYPE_IOAM_TRACE   59
#define VXLAN_GPE_OPTION_TYPE_IOAM_PROOF_OF_TRANSIT 60

/**
 * @brief VXLAN GPE Extension (iOAM) Header definition
 */
typedef struct
{
  u8 type;
  u8 length;
  /** Reserved */
  u8 reserved;
  /** see vxlan_gpe_protocol_t */
  u8 protocol;
} vxlan_gpe_ioam_hdr_t;

/*
 * @brief VxLAN GPE iOAM Option definition
 */
typedef struct
{
  /* Option Type */
  u8 type;
  /* Length in octets of the option data field */
  u8 length;
} vxlan_gpe_ioam_option_t;


#endif


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
