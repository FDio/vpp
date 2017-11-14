/*
 * proxy_node.c: common dhcp v4 and v6 proxy node processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

/**
 * @brief Shard 4/6 instance of DHCP main
 */
dhcp_proxy_main_t dhcp_proxy_main;

static void
dhcp_proxy_rx_table_lock (fib_protocol_t proto,
                          u32 fib_index)
{
    if (FIB_PROTOCOL_IP4 == proto)
        fib_table_lock(fib_index, proto, FIB_SOURCE_DHCP);
    else
        mfib_table_lock(fib_index, proto, MFIB_SOURCE_DHCP);
}

static void
dhcp_proxy_rx_table_unlock (fib_protocol_t proto,
                            u32 fib_index)
{
    if (FIB_PROTOCOL_IP4 == proto)
        fib_table_unlock(fib_index, proto, FIB_SOURCE_DHCP);
    else
        mfib_table_unlock(fib_index, proto, MFIB_SOURCE_DHCP);
}

 u32
dhcp_proxy_rx_table_get_table_id (fib_protocol_t proto,
                                  u32 fib_index)
{
    if (FIB_PROTOCOL_IP4 == proto)
      {
        fib_table_t *fib;

        fib = fib_table_get(fib_index, proto);

        return (fib->ft_table_id);
      }
    else
      {
        mfib_table_t *mfib;

        mfib = mfib_table_get(fib_index, proto);

        return (mfib->mft_table_id);
      }
}

void
dhcp_proxy_walk (fib_protocol_t proto,
                 dhcp_proxy_walk_fn_t fn,
                 void *ctx)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_proxy_t * server;
  u32 server_index, i;

  vec_foreach_index (i, dpm->dhcp_server_index_by_rx_fib_index[proto])
  {
      server_index = dpm->dhcp_server_index_by_rx_fib_index[proto][i];
      if (~0 == server_index)
          continue;

      server = pool_elt_at_index (dpm->dhcp_servers[proto], server_index);

      if (!fn(server, ctx))
          break;
    }
}

void
dhcp_vss_walk (fib_protocol_t proto,
               dhcp_vss_walk_fn_t fn,
               void *ctx)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  mfib_table_t *mfib;
  dhcp_vss_t * vss;
  u32 vss_index, i;
  fib_table_t *fib;

  vec_foreach_index (i, dpm->vss_index_by_rx_fib_index[proto])
  {
      vss_index = dpm->vss_index_by_rx_fib_index[proto][i];
      if (~0 == vss_index)
          continue;

      vss = pool_elt_at_index (dpm->vss[proto], vss_index);

      if (FIB_PROTOCOL_IP4 == proto)
        {
          fib = fib_table_get(i, proto);

          if (!fn(vss, fib->ft_table_id, ctx))
              break;
        }
      else
        {
          mfib = mfib_table_get(i, proto);

          if (!fn(vss, mfib->mft_table_id, ctx))
              break;
        }
    }
}

static u32
dhcp_proxy_server_find (dhcp_proxy_t *proxy,
                        fib_protocol_t proto,
                        ip46_address_t *addr,
                        u32 server_table_id)
{
    dhcp_server_t *server;
    u32 ii, fib_index;

    vec_foreach_index(ii, proxy->dhcp_servers)
    {
        server = &proxy->dhcp_servers[ii];
        fib_index = fib_table_find(proto, server_table_id);

        if (ip46_address_is_equal(&server->dhcp_server,
                                  addr) &&
            (server->server_fib_index == fib_index))
        {
            return (ii);
        }
    }
    return (~0);
}

int
dhcp_proxy_server_del (fib_protocol_t proto,
                       u32 rx_fib_index,
                       ip46_address_t *addr,
                       u32 server_table_id)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_proxy_t *proxy = 0;

  proxy = dhcp_get_proxy(dpm, rx_fib_index, proto);

  if (NULL != proxy)
  {
      dhcp_server_t *server;
      u32 index;

      index = dhcp_proxy_server_find(proxy, proto, addr, server_table_id);

      if (~0 != index)
      {
          server = &proxy->dhcp_servers[index];
          fib_table_unlock (server->server_fib_index, proto, FIB_SOURCE_DHCP);

          vec_del1(proxy->dhcp_servers, index);

          if (0 == vec_len(proxy->dhcp_servers))
          {
              /* no servers left, delete the proxy config */
              dpm->dhcp_server_index_by_rx_fib_index[proto][rx_fib_index] = ~0;
              vec_free(proxy->dhcp_servers);
              pool_put (dpm->dhcp_servers[proto], proxy);
              return (1);
          }
      }
  }

  /* the proxy still exists */
  return (0);
}

int
dhcp_proxy_server_add (fib_protocol_t proto,
                       ip46_address_t *addr,
                       ip46_address_t *src_address,
                       u32 rx_fib_index,
                       u32 server_table_id)
{
  dhcp_proxy_main_t * dpm = &dhcp_proxy_main;
  dhcp_proxy_t * proxy = 0;
  int new = 0;

  proxy = dhcp_get_proxy(dpm, rx_fib_index, proto);

  if (NULL == proxy)
  {
      vec_validate_init_empty(dpm->dhcp_server_index_by_rx_fib_index[proto],
                              rx_fib_index,
                              ~0);

      pool_get (dpm->dhcp_servers[proto], proxy);
      memset (proxy, 0, sizeof (*proxy));
      new = 1;

      dpm->dhcp_server_index_by_rx_fib_index[proto][rx_fib_index] =
          proxy - dpm->dhcp_servers[proto];

      proxy->dhcp_src_address = *src_address;
      proxy->rx_fib_index = rx_fib_index;
  }
  else
  {
      if (~0 != dhcp_proxy_server_find(proxy, proto, addr, server_table_id))
      {
          return (new);
      }
  }

  dhcp_server_t server = {
      .dhcp_server = *addr,
      .server_fib_index = fib_table_find_or_create_and_lock(proto,
                                                            server_table_id,
                                                            FIB_SOURCE_DHCP),
  };

  vec_add1(proxy->dhcp_servers, server);

  return (new);
}

typedef struct dhcp4_proxy_dump_walk_ctx_t_
{
    fib_protocol_t proto;
    void *opaque;
    u32 context;
} dhcp_proxy_dump_walk_cxt_t;

static int
dhcp_proxy_dump_walk (dhcp_proxy_t *proxy,
                      void *arg)
{
  dhcp_proxy_dump_walk_cxt_t *ctx = arg;

  dhcp_send_details(ctx->proto,
                    ctx->opaque,
                    ctx->context,
                    proxy);

  return (1);
}

void
dhcp_proxy_dump (fib_protocol_t proto,
                 void *opaque,
                 u32 context)
{
    dhcp_proxy_dump_walk_cxt_t ctx =  {
        .proto = proto,
        .opaque = opaque,
        .context = context,
    };
    dhcp_proxy_walk(proto, dhcp_proxy_dump_walk, &ctx);
}

int
dhcp_vss_show_walk (dhcp_vss_t *vss,
                    u32 rx_table_id,
                    void *ctx)
{
    vlib_main_t * vm = ctx;

    if (vss->vss_type == VSS_TYPE_VPN_ID)
      {
	u32 oui = ((u32) vss->vpn_id[0] << 16) + ((u32) vss->vpn_id[1] << 8)
	    + ((u32) vss->vpn_id[2]);
	u32 fib_id = ((u32) vss->vpn_id[3] << 24) + ((u32) vss->vpn_id[4] << 16)
	    + ((u32) vss->vpn_id[5] << 8) + ((u32) vss->vpn_id[6]);
	vlib_cli_output (vm, " fib_table: %d  oui: %d vpn_index: %d",
			 rx_table_id, oui, fib_id);
      }
    else if (vss->vss_type == VSS_TYPE_ASCII)
	vlib_cli_output (vm, " fib_table: %d  vpn_id: %s",
			 rx_table_id, vss->vpn_ascii_id);
    else
	vlib_cli_output (vm, " fib_table: %d  default global vpn", rx_table_id);

    return (1);
}

void update_vss (dhcp_vss_t *v,
		 u8 vss_type,
		 u8 *vpn_ascii_id,
		 u32 oui,
		 u32 vpn_index)
{
  v->vss_type = vss_type;
  if (v->vpn_ascii_id)
    {
	if (v->vpn_ascii_id == (u8 *) ~0)
	v->vpn_ascii_id = 0;
      else
	vec_free (v->vpn_ascii_id);
    }

  if (vss_type == VSS_TYPE_ASCII)
      v->vpn_ascii_id = vpn_ascii_id;
  else if (vss_type == VSS_TYPE_VPN_ID)
    {
      v->vpn_id[0] = (oui >> 16) & 0xff;
      v->vpn_id[1] = (oui >> 8) & 0xff;
      v->vpn_id[2] = (oui >> 0) & 0xff;
      v->vpn_id[3] = (vpn_index >> 24) & 0xff;
      v->vpn_id[4] = (vpn_index >> 16) & 0xff;
      v->vpn_id[5] = (vpn_index >> 8) & 0xff;
      v->vpn_id[6] = (vpn_index >> 0) & 0xff;
    }
}

int dhcp_proxy_set_vss (fib_protocol_t proto,
                        u32 tbl_id,
			u8 vss_type,
			u8 *vpn_ascii_id,
                        u32 oui,
                        u32 vpn_index,
                        u8 is_del)
{
  dhcp_proxy_main_t *dm = &dhcp_proxy_main;
  dhcp_vss_t *v = NULL;
  u32  rx_fib_index;
  int rc = 0;
  
  if (proto == FIB_PROTOCOL_IP4)
      rx_fib_index = fib_table_find_or_create_and_lock(proto, tbl_id,
                                                       FIB_SOURCE_DHCP);
  else
      rx_fib_index = mfib_table_find_or_create_and_lock(proto, tbl_id,
                                                        MFIB_SOURCE_DHCP);
  v = dhcp_get_vss_info(dm, rx_fib_index, proto);

  if (NULL != v)
    {
      if (is_del)
        {
          /* release the lock held on the table when the VSS
           * info was created */
          dhcp_proxy_rx_table_unlock (proto, rx_fib_index);

	  vec_free (v->vpn_ascii_id);
          pool_put (dm->vss[proto], v);
          dm->vss_index_by_rx_fib_index[proto][rx_fib_index] = ~0;
        }
      else
        {
	  update_vss (v, vss_type, vpn_ascii_id, oui, vpn_index);
        }
    }
  else
    {
      if (is_del)
        rc = VNET_API_ERROR_NO_SUCH_ENTRY;
      else
        {
          /* create a new entry */
          vec_validate_init_empty(dm->vss_index_by_rx_fib_index[proto],
                                  rx_fib_index, ~0);

          /* hold a lock on the table whilst the VSS info exist */
          pool_get (dm->vss[proto], v);
	  update_vss (v, vss_type, vpn_ascii_id, oui, vpn_index);
          dm->vss_index_by_rx_fib_index[proto][rx_fib_index] =
              v - dm->vss[proto];
          dhcp_proxy_rx_table_lock (proto, rx_fib_index);
        }
    }

  /* Release the lock taken during the create_or_lock at the start */
  dhcp_proxy_rx_table_unlock (proto, rx_fib_index);

  return (rc);
}
