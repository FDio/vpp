/*
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

#ifndef PLUGINS_IPFIXCOLLECTOR_PLUGIN_IPFIXCOLLECTOR_IPFIXCOLLECTOR_H_
#define PLUGINS_IPFIXCOLLECTOR_PLUGIN_IPFIXCOLLECTOR_IPFIXCOLLECTOR_H_

#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#define IPFIX_COLLECTOR_CLIENT_NAME_MAX 64

#define IPFIX_COLLECTOR_ERR_INVALID_PARAM -1
#define IPFIX_COLLECTOR_ERR_REG_EXISTS -2

/** @brief Structure other nodes to use for registering with IP-FIX collector.
*/
typedef struct
{
  /** String containing name of the client interested in getting
      ip-fix packets. */
  u8 *client_name;

  /** Node index where packets have to be redirected. */
  u32 client_node;

  /** Setid of IPFix for which client is intereseted in getting packets. */
  u16 ipfix_setid;

  /** Add(0) or del(1) operation. */
  u16 del;
} ipfix_client_add_del_t;

/** @brief IP-FIX collector internal client structure to store SetID to
     client node ID.
*/
typedef struct
{
  /** String containing name of the client interested in getting
        ip-fix packets. */
  u8 *client_name;

  /** Node index where packets have to be redirected. */
  u32 client_node;

  /** ipfix-collector next index where packets have to be redirected. */
  u32 client_next_node;

  /** Setid of IPFix for which client is intereseted in getting packets. */
  u16 set_id;
} ipfix_client;

/** @brief IP-FIX collector main structure to SetID to client node ID mapping.
    @note cache aligned.
*/
typedef struct
{
  /** Hash table to map IP-FIX setid to a client registration pool. SetId is
      key to hash map. */
  uword *client_reg_table;

  /** Pool of Client node information for the IP-FIX SetID. */
  ipfix_client *client_reg_pool;

  /** Pointer to VLib main for the node - ipfix-collector. */
  vlib_main_t *vlib_main;

  /** Pointer to vnet main for convenience. */
  vnet_main_t *vnet_main;
} ipfix_collector_main_t;

extern vlib_node_registration_t ipfix_collector_node;

extern ipfix_collector_main_t ipfix_collector_main;

/**
 * @brief IP-FIX SetID registration function.
 *
 * This function can be used by other VPP graph nodes to receive IP-FIX packets
 * with a particular setid.
 *
 * @param vlib_main_t Vlib main of the graph node which is interseted in
 *                    getting IP-Fix packet.
 * @param ipfix_client_add_del_t Structure describing the client node which
 *                               is interested in getting the IP-Fix packets for
 *                               a SetID.
 *
 * @returns 0 on success.
 * @returns Error codes(<0) otherwise.
 */
int
ipfix_collector_reg_setid (vlib_main_t * vm, ipfix_client_add_del_t * info);

always_inline ipfix_client *
ipfix_collector_get_client (u16 set_id)
{
  ipfix_collector_main_t *cm = &ipfix_collector_main;
  uword *p;

  p = hash_get (cm->client_reg_table, set_id);
  return (p ? pool_elt_at_index (cm->client_reg_pool, (*p)) : NULL);
}

#endif /* PLUGINS_IPFIXCOLLECTOR_PLUGIN_IPFIXCOLLECTOR_IPFIXCOLLECTOR_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
