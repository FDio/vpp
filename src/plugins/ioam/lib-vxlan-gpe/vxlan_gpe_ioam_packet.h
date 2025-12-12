/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __included_vxlan_gpe_ioam_packet_h__
#define __included_vxlan_gpe_ioam_packet_h__

#include <plugins/vxlan-gpe/vxlan_gpe.h>
#include <plugins/vxlan-gpe/vxlan_gpe_packet.h>
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
