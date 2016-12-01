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

#include <vnet/ip/ip.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/udp.h>
#include <ioam/ipfixcollector/ipfixcollector.h>

ipfix_collector_main_t ipfix_collector_main;

/*
 * ipfix_collector_reg_setid
 * This function can be used by other VPP graph nodes to receive IP-FIX packets
 * with a particular setid.
 */
int
ipfix_collector_reg_setid (vlib_main_t * vm, ipfix_client_add_del_t * info)
{
  ipfix_collector_main_t *cm = &ipfix_collector_main;
  uword *p = NULL;
  int i;
  ipfix_client *client = 0;

  if ((!info) || (!info->client_name))
    return IPFIX_COLLECTOR_ERR_INVALID_PARAM;

  p = hash_get (cm->client_reg_table, info->ipfix_setid);
  client = p ? pool_elt_at_index (cm->client_reg_pool, (*p)) : NULL;

  if (info->del)
    {
      if (!client)
	return 0;		//There is no registered handler, so send success

      hash_unset (cm->client_reg_table, info->ipfix_setid);
      vec_free(client->client_name);
      pool_put (cm->client_reg_pool, client);
      return 0;
    }

  if (client)
    return IPFIX_COLLECTOR_ERR_REG_EXISTS;

  pool_get (cm->client_reg_pool, client);
  i = client - cm->client_reg_pool;
  client->client_name = vec_dup(info->client_name);
  client->client_node = info->client_node;
  client->client_next_node = vlib_node_add_next (vm,
						 ipfix_collector_node.index,
						 client->client_node);
  client->set_id = info->ipfix_setid;

  hash_set (cm->client_reg_table, info->ipfix_setid, i);
  return 0;
}

/**
 * @brief plugin-api required function
 * @param vm vlib_main_t * vlib main data structure pointer
 * @param h vlib_plugin_handoff_t * handoff structure
 * @param from_early_init int notused
 *
 * <em>Notes:</em>
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */
clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
		      int from_early_init)
{
  ipfix_collector_main_t *cm = &ipfix_collector_main;
  clib_error_t *error = 0;
  cm->vlib_main = vm;
  cm->vnet_main = h->vnet_main;

  return error;
}

static clib_error_t *
ipfix_collector_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;
  ipfix_collector_main_t *cm = &ipfix_collector_main;

  cm->client_reg_pool = NULL;
  cm->client_reg_table = hash_create (0, sizeof (uword));

  udp_register_dst_port (vm,
			 UDP_DST_PORT_ipfix,
			 ipfix_collector_node.index, 1 /* is_ip4 */ );
  return error;
}

VLIB_INIT_FUNCTION (ipfix_collector_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
