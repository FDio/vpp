/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * @file
 * @brief L2-GRE over IPSec packet processing.
*/

#ifndef included_ipsec_gre_h
#define included_ipsec_gre_h

#include <vnet/vnet.h>
#include <vnet/gre/packet.h>
#include <vnet/gre/gre.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>

extern vnet_hw_interface_class_t ipsec_gre_hw_interface_class;

/**
 * @brief IPSec-GRE errors.
 *
*/
typedef enum
{
#define ipsec_gre_error(n,s) IPSEC_GRE_ERROR_##n,
#include <vnet/ipsec-gre/error.def>
#undef ipsec_gre_error
  IPSEC_GRE_N_ERROR,
} ipsec_gre_error_t;

/**
 * @brief IPSec-GRE tunnel parameters.
 *
*/
typedef struct
{
  ip4_address_t tunnel_src; /**< tunnel IPv4 src address */
  ip4_address_t tunnel_dst; /**< tunnel IPv4 dst address */
  u32 local_sa;		    /**< local IPSec SA index */
  u32 remote_sa;	    /**< remote IPSec SA index */
  u32 local_sa_id;	    /**< local IPSec SA id */
  u32 remote_sa_id;	    /**< remote IPSec SA id */
  u32 hw_if_index;;	    /**< hardware interface index */
  u32 sw_if_index;;	    /**< software interface index */
} ipsec_gre_tunnel_t;

/**
 * @brief IPSec-GRE state.
 *
*/
typedef struct
{
  ipsec_gre_tunnel_t *tunnels; /**< pool of tunnel instances */

  uword *tunnel_by_key;	 /**< hash mapping src/dst addr pair to tunnel */

  u32 *free_ipsec_gre_tunnel_hw_if_indices;  /**< free vlib hw_if_indices */

  u32 *tunnel_index_by_sw_if_index;  /**< mapping from sw_if_index to tunnel
                                          index */

  vlib_main_t *vlib_main;  /**< convenience */
  vnet_main_t *vnet_main;  /**< convenience */
} ipsec_gre_main_t;

ipsec_gre_main_t ipsec_gre_main;

extern vlib_node_registration_t ipsec_gre_input_node;
extern vnet_device_class_t ipsec_gre_device_class;

/* manually added to the interface output node in ipsec_gre.c */
#define IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT 1

/**
 * @brief IPSec-GRE tunnel add/del arguments.
 *
*/
typedef struct
{
  u8 is_add; /**< 1 - add, 0 - delete */

  ip4_address_t src; /**< tunnel IPv4 src address */
  ip4_address_t dst; /**< tunnel IPv4 dst address */
  u32 lsa;	     /**< local IPSec SA id */
  u32 rsa;	     /**< remote IPSec SA id */
} vnet_ipsec_gre_add_del_tunnel_args_t;

int vnet_ipsec_gre_add_del_tunnel
  (vnet_ipsec_gre_add_del_tunnel_args_t * a, u32 * sw_if_indexp);

#endif /* included_ipsec_gre_h */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
