#pragma once
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>

typedef struct
{
  /* Next nodes for each feature */
  u32 feat_next_node_index[32];

  /* vector of egress sw_if_index per BD */
  u32 *bd_punt_if;

  /* vector of source MAC addresses per tx sw_if_index */
  mac_address_t *bd_punt_src_mac;
} l2_lldp_bd_punt_main_t;

extern l2_lldp_bd_punt_main_t l2_lldp_bd_punt_main;