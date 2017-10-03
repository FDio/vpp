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
 * @brief LISP sub-interfaces.
 *
 */

#ifndef __LISP_GPE_SUB_INTERFACE_H__
#define __LISP_GPE_SUB_INTERFACE_H__

#include <vnet/lisp-gpe/lisp_gpe.h>

/**
 * A Key for lookup in the L£ sub-interface DB
 */
typedef struct lisp_gpe_sub_interface_key_t_
{
    /**
     * The local-RLOC. This is the interface's 'source' address.
     */
  ip_address_t local_rloc;

    /**
     * The VNI. In network byte order!
     */
  u32 vni;
} lisp_gpe_sub_interface_key_t;

/**
 * @brief A LISP L3 sub-interface
 *
 * A LISP sub-interface is a multi-access interface, whose local address is a
 * single local-RLOC. Adjacencies that form on this sub-interface, represent
 * remote RLOCs.
 * This is analogous to an ethernet interface.
 * As with all interface types it can only be present in one VRF, hence a
 * LISP sub-interface is per-local-rloc and per-VNI.
 */
typedef struct lisp_gpe_sub_interface_t_
{
  /**
   * The interface's key inthe DB; rloc & vni;
   * The key is allocated from the heap so it can be used in the hash-table.
   * if it's part of the object, then it is subjet to realloc, which no-worky.
   */
  lisp_gpe_sub_interface_key_t *key;

  /**
   * The Table-ID in the overlay that this interface is bound to.
   */
  u32 eid_table_id;

  /**
   * A reference counting lock on the number of users of this interface.
   * When this count drops to 0 the interface is deleted.
   */
  u32 locks;

  /**
   * The SW if index assigned to this sub-interface
   */
  u32 sw_if_index;

  /**
   * The SW IF index assigned to the main interface of which this is a sub.
   */
  u32 main_sw_if_index;
} lisp_gpe_sub_interface_t;

extern index_t lisp_gpe_sub_interface_find_or_create_and_lock (const
							       ip_address_t *
							       lrloc,
							       u32
							       eid_table_id,
							       u32 vni);

extern u8 *format_lisp_gpe_sub_interface (u8 * s, va_list * ap);

extern void lisp_gpe_sub_interface_unlock (index_t itf);

extern const lisp_gpe_sub_interface_t *lisp_gpe_sub_interface_get (index_t
								   itf);

/**
 * A DB of all L3 sub-interfaces. The key is:{VNI,l-RLOC}
 */
extern uword *lisp_gpe_sub_interfaces_sw_if_index;

/**
 * @brief
 *  Get a VNET L3 interface matching the local-RLOC and VNI
 *  Called from the data-plane
 */
always_inline u32
lisp_gpe_sub_interface_find_ip6 (const ip6_address_t * addr, u32 vni)
{
  lisp_gpe_sub_interface_key_t key;
  const uword *p;

  key.local_rloc.ip.v6.as_u64[0] = addr->as_u64[0];
  key.local_rloc.ip.v6.as_u64[1] = addr->as_u64[1];
  key.local_rloc.version = IP6;
  key.vni = vni;

  p = hash_get_mem (&lisp_gpe_sub_interfaces_sw_if_index, &key);

  if (NULL != p)
    return p[0];

  return (INDEX_INVALID);
}

/**
 * @brief
 *  Get a VNET L3 interface matching the local-RLOC and VNI
 *  Called from the data-plane
 */
always_inline index_t
lisp_gpe_sub_interface_find_ip4 (const ip4_address_t * addr, u32 vni)
{
  lisp_gpe_sub_interface_key_t key;
  const uword *p;

  key.local_rloc.ip.v4.as_u32 = addr->as_u32;
  key.local_rloc.version = IP4;
  key.vni = vni;

  p = hash_get_mem (&lisp_gpe_sub_interfaces_sw_if_index, &key);

  if (NULL != p)
    return p[0];

  return (INDEX_INVALID);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
