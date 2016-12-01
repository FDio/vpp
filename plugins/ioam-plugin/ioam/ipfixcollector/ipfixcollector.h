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

#ifndef PLUGINS_IPFIXCOLLECTOR_PLUGIN_IPFIXCOLLECTOR_IPFIXCOLLECTOR_H_
#define PLUGINS_IPFIXCOLLECTOR_PLUGIN_IPFIXCOLLECTOR_IPFIXCOLLECTOR_H_

#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#define IPFIX_COLLECTOR_CLIENT_NAME_MAX 64

#define IPFIX_COLLECTOR_ERR_INVALID_PARAM -1
#define IPFIX_COLLECTOR_ERR_REG_EXISTS -2

/*
 * @client_name - string containing name of the client interested in
 *                getting ip-fix packets
 * @ client_node - Node index where packets have to be redirected.
 * @ ipfix_setid - setid of IPFix for which client is intereseted in getting packets
 * @ del - Add or del operation
 */
typedef struct {
  u8 *client_name;
  u32 client_node;
  u16 ipfix_setid;
  u16 del;
} ipfix_client_add_del_t;

typedef struct {
  u8 *client_name;
  u32 client_node;
  u32 client_next_node;
  u16 set_id;
} ipfix_client;

typedef struct {
  /* Hash table to map IP-FIX setid to a client */
  uword *client_reg_table;

  /* Client node information */
  ipfix_client *client_reg_pool;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ipfix_collector_main_t;

extern vlib_node_registration_t ipfix_collector_node;

extern ipfix_collector_main_t ipfix_collector_main;

int
ipfix_collector_reg_setid(vlib_main_t *vm, ipfix_client_add_del_t *info);

always_inline ipfix_client *
ipfix_collector_get_client (u16 set_id)
{
  ipfix_collector_main_t *cm = &ipfix_collector_main;
  uword *p;

  p = hash_get (cm->client_reg_table, set_id);
  return (p ? pool_elt_at_index(cm->client_reg_pool, (*p)) : NULL);
}

#endif /* PLUGINS_IPFIXCOLLECTOR_PLUGIN_IPFIXCOLLECTOR_IPFIXCOLLECTOR_H_ */
