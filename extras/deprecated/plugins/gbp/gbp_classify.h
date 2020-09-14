/*
 * gbp.h : Group Based Policy
 *
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

#ifndef __GBP_CLASSIFY_H__
#define __GBP_CLASSIFY_H__

#include <plugins/gbp/gbp.h>
#include <vnet/ethernet/arp_packet.h>

typedef enum gbp_src_classify_type_t_
{
  GBP_SRC_CLASSIFY_NULL,
  GBP_SRC_CLASSIFY_PORT,
  GBP_SRC_CLASSIFY_LPM,
  GBP_SRC_CLASSIFY_LPM_ANON,
  GBP_SRC_N_CLASSIFY
#define GBP_SRC_N_CLASSIFY GBP_SRC_N_CLASSIFY
} gbp_src_classify_type_t;

/**
 * Grouping of global data for the GBP source EPG classification feature
 */
typedef struct gbp_src_classify_main_t_
{
  /**
   * Next nodes for L2 output features
   */
  u32 l2_input_feat_next[GBP_SRC_N_CLASSIFY][32];
} gbp_src_classify_main_t;

extern gbp_src_classify_main_t gbp_src_classify_main;

enum gbp_classify_get_ip_way
{
  GBP_CLASSIFY_GET_IP_SRC = 0,
  GBP_CLASSIFY_GET_IP_DST = 1
};

static_always_inline dpo_proto_t
gbp_classify_get_ip_address (const ethernet_header_t * eh0,
			     const ip4_address_t ** ip4,
			     const ip6_address_t ** ip6,
			     const enum gbp_classify_get_ip_way way)
{
  u16 etype = clib_net_to_host_u16 (eh0->type);
  const void *l3h0 = eh0 + 1;

  if (ETHERNET_TYPE_VLAN == etype)
    {
      const ethernet_vlan_header_t *vh0 =
	(ethernet_vlan_header_t *) (eh0 + 1);
      etype = clib_net_to_host_u16 (vh0->type);
      l3h0 = vh0 + 1;
    }

  switch (etype)
    {
    case ETHERNET_TYPE_IP4:
      *ip4 = &(&((const ip4_header_t *) l3h0)->src_address)[way];
      return DPO_PROTO_IP4;
    case ETHERNET_TYPE_IP6:
      *ip6 = &(&((const ip6_header_t *) l3h0)->src_address)[way];
      return DPO_PROTO_IP6;
    case ETHERNET_TYPE_ARP:
      *ip4 = &((ethernet_arp_header_t *) l3h0)->ip4_over_ethernet[way].ip4;
      return DPO_PROTO_IP4;
    }

  return DPO_PROTO_NONE;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
