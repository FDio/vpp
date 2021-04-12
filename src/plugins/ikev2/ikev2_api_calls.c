/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vpp/api/vpe_msg_enum.h>
#include <plugins/ikev2/ikev2_api_calls.h>
#include <plugins/ikev2/ikev2.h>
#include <plugins/ikev2/ikev2_priv.h>

/*
 * We create a unique client registration for all the internal calls. 
 * The client index is hardcoded to prevent interfering with other client 
 * indexes. The reference to the regisration is available from the main
 * thread in am->my_registration. 
 * This registration doesn't use shared memory queues. API calls are direct
 * calls and repys are processed synchronously.
 * 
 * We introduced a new type to prevent VPP from sending pings to itself.
 * 
 * Registrating the unique client could be done globally (VPP init).
 */
u32
ikev2_api_register_client ()
{
  api_main_t *am = vlibapi_get_main ();
  u32 client_index;
  vl_api_registration_t *regp =
    clib_mem_alloc (sizeof (vl_api_registration_t));

  clib_memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_INTERNAL;
  client_index = (1 << 30);
  regp->name = (u8 *) "IKEV2_API_CLIENT";
  am->my_registration = regp;
  return client_index;
}

/* Any internal handler should process the API reply to garantee that this  
 * reply is available in the internal client registration. It is also 
 * responsible to free it. This allows the main thread to process theses
 * internal API calls synchronously.
 * 
 * For now, we have to write all the handlers by hand. Is it possible to 
 * automate this process with the .api files?
 */
int
ikev2_api_ipsec_sa_add_and_lock (u32 id, u32 spi, ipsec_protocol_t proto,
				 ipsec_crypto_alg_t crypto_alg,
				 const ipsec_key_t *ck,
				 ipsec_integ_alg_t integ_alg,
				 const ipsec_key_t *ik, ipsec_sa_flags_t flags,
				 u32 salt, u16 src_port, u16 dst_port,
				 const tunnel_t *tun, u32 *sa_out_index)
{
  u32 api_client_index = ikev2_get_api_index ();
  vl_api_ipsec_sad_entry_add_del_v3_t *mp =
    vl_msg_api_alloc (sizeof (vl_api_ipsec_sad_entry_add_del_v3_t));
  int rv;
  
  /* Check that we are in main thread */
  ASSERT(vlib_get_thread_index()==0);

  mp->_vl_msg_id = htons (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3);
  mp->client_index = api_client_index;
  mp->context = 0;
  mp->is_add = 1;
  mp->entry.sad_id = htonl (id);
  mp->entry.spi = htonl (spi);
  mp->entry.protocol = ipsec_proto_encode (proto);
  mp->entry.crypto_algorithm = ipsec_crypto_algo_encode (crypto_alg);
  ipsec_key_encode (ck, &mp->entry.crypto_key);
  mp->entry.integrity_algorithm = ipsec_integ_algo_encode (integ_alg);
  ipsec_key_encode (ik, &mp->entry.integrity_key);
  mp->entry.flags = ipsec_sad_flags_encode (flags);
  mp->entry.salt = salt;
  mp->entry.udp_src_port = src_port;
  mp->entry.udp_dst_port = dst_port;
  tunnel_encode (tun, &mp->entry.tunnel);

  vl_msg_api_handler ((void *) mp);

  vl_api_registration_t *rp =
    vl_api_client_index_to_registration (api_client_index);

  if (!rp)
    {
      ikev2_log_warning ("Internal API client not registered");
      return VNET_API_ERROR_NO_INTERNAL_CLIENT;
    }
  vl_api_ipsec_sad_entry_add_del_v3_reply_t *rpm =
    (vl_api_ipsec_sad_entry_add_del_v3_reply_t *) rp->buf;

  if (!rpm ||
      rpm->_vl_msg_id != ntohs (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY))
    {
      ikev2_log_warning (
	"No API answer received : IPsec plugin might not be loaded");
      return VNET_API_ERROR_API_NOT_LOADED;
    }
  rv = rpm->retval;
  vl_msg_api_free (rpm);
  return rv;
}

int
ikev2_api_ipsec_sa_unlock_id (u32 id)
{
  u32 api_client_index = ikev2_get_api_index ();
  vl_api_ipsec_sad_entry_add_del_v3_t *mp =
    vl_msg_api_alloc (sizeof (vl_api_ipsec_sad_entry_add_del_v3_t));
  int rv;
    
  /* Check that we are in main thread */
  ASSERT(vlib_get_thread_index()==0);

  memset (mp, 0, sizeof (vl_api_ipsec_sad_entry_add_del_v3_t));
  mp->_vl_msg_id = htons (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3);
  mp->client_index = api_client_index;
  mp->context = 0;
  mp->is_add = 0;
  mp->entry.sad_id = htonl (id);
  mp->entry.protocol = clib_host_to_net_u32 (IPSEC_API_PROTO_ESP);

  vl_msg_api_handler ((void *) mp);

  vl_api_registration_t *rp =
    vl_api_client_index_to_registration (api_client_index);

  if (!rp)
    {
      ikev2_log_warning ("Internal API client not registered");
      return VNET_API_ERROR_NO_INTERNAL_CLIENT;
    }
  vl_api_ipsec_sad_entry_add_del_v3_reply_t *rpm =
    (vl_api_ipsec_sad_entry_add_del_v3_reply_t *) rp->buf;

  if (!rpm ||
      rpm->_vl_msg_id != ntohs (VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY))
    {
      ikev2_log_warning (
	"No API answer received : IPsec plugin might not be loaded");
      return VNET_API_ERROR_API_NOT_LOADED;
    }
  rv = rpm->retval;
  vl_msg_api_free (rpm);
  return rv;
}

int
ikev2_api_ipsec_tun_protect_del (u32 sw_if_index, const ip_address_t *nh)
{
  u32 api_client_index = ikev2_get_api_index ();
  vl_api_ipsec_tunnel_protect_del_t *mp =
    vl_msg_api_alloc (sizeof (vl_api_ipsec_tunnel_protect_del_t));
  int rv;

  /* Check that we are in main thread */
  ASSERT(vlib_get_thread_index()==0);

  mp->_vl_msg_id = htons (VL_API_IPSEC_TUNNEL_PROTECT_DEL);
  mp->client_index = api_client_index;
  mp->context = 0;
  mp->sw_if_index = htonl (sw_if_index);
  if (nh)
    ip_address_encode2 (nh, &mp->nh);

  vl_msg_api_handler ((void *) mp);

  vl_api_registration_t *rp =
    vl_api_client_index_to_registration (api_client_index);

  if (!rp)
    {
      ikev2_log_warning ("Internal API client not registered");
      return VNET_API_ERROR_NO_INTERNAL_CLIENT;
    }
  vl_api_ipsec_tunnel_protect_del_reply_t *rpm =
    (vl_api_ipsec_tunnel_protect_del_reply_t *) rp->buf;

  if (!rpm || rpm->_vl_msg_id != ntohs (VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY))
    {
      ikev2_log_warning (
	"No API answer received : IPsec plugin might not be loaded");
      return VNET_API_ERROR_API_NOT_LOADED;
    }
  rv = rpm->retval;
  vl_msg_api_free (rpm);
  return rv;
}

int
ikev2_api_ipsec_tun_protect_update (u32 sw_if_index, const ip_address_t *nh,
				    u32 sa_out, u32 *sas_in)
{
  u32 api_client_index = ikev2_get_api_index ();
  u32 ii;
  vl_api_ipsec_tunnel_protect_update_t *mp =
    vl_msg_api_alloc (sizeof (vl_api_ipsec_tunnel_protect_update_t) +
		      vec_len (sas_in) * sizeof (u32));
  int rv;
    
  /* Check that we are in main thread */
  ASSERT(vlib_get_thread_index()==0);

  mp->_vl_msg_id = htons (VL_API_IPSEC_TUNNEL_PROTECT_UPDATE);
  mp->client_index = api_client_index;
  mp->context = 0;
  mp->tunnel.sw_if_index = htonl (sw_if_index);
  mp->tunnel.sa_out = htonl (sa_out);
  mp->tunnel.n_sa_in = vec_len (sas_in);
  vec_foreach_index (ii, sas_in)
    mp->tunnel.sa_in[ii] = htonl (sas_in[ii]);
  if (nh)
    ip_address_encode2 (nh, &mp->tunnel.nh);

  vl_msg_api_handler ((void *) mp);

  vl_api_registration_t *rp =
    vl_api_client_index_to_registration (api_client_index);

  if (!rp)
    {
      ikev2_log_warning ("Internal API client not registered");
      return VNET_API_ERROR_NO_INTERNAL_CLIENT;
    }
  vl_api_ipsec_tunnel_protect_update_reply_t *rpm =
    (vl_api_ipsec_tunnel_protect_update_reply_t *) rp->buf;

  if (!rpm ||
      rpm->_vl_msg_id != ntohs (VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY))
    {
      ikev2_log_warning (
	"No API answer received : IPsec plugin might not be loaded");
      return VNET_API_ERROR_API_NOT_LOADED;
    }
  rv = rpm->retval;
  vl_msg_api_free (rpm);
  return rv;
}

int
ikev2_api_ipsec_register_udp_port (u16 port)
{
  u32 api_client_index = ikev2_get_api_index ();
  vl_api_ipsec_register_udp_port_t *mp =
    vl_msg_api_alloc (sizeof (vl_api_ipsec_register_udp_port_t));
  int rv;
    
  /* Check that we are in main thread */
  ASSERT(vlib_get_thread_index()==0);

  mp->_vl_msg_id = htons (VL_API_IPSEC_REGISTER_UDP_PORT);
  mp->client_index = api_client_index;
  mp->context = 0;
  mp->port = htons (port);

  vl_msg_api_handler ((void *) mp);

  vl_api_registration_t *rp =
    vl_api_client_index_to_registration (api_client_index);

  if (!rp)
    {
      ikev2_log_warning ("Internal API client not registered");
      return VNET_API_ERROR_NO_INTERNAL_CLIENT;
    }
  vl_api_ipsec_register_udp_port_reply_t *rpm =
    (vl_api_ipsec_register_udp_port_reply_t *) rp->buf;

  if (!rpm || rpm->_vl_msg_id != ntohs (VL_API_IPSEC_REGISTER_UDP_PORT_REPLY))
    {
      ikev2_log_warning (
	"No API answer received : IPsec plugin might not be loaded");
      return VNET_API_ERROR_API_NOT_LOADED;
    }
  rv = rpm->retval;
  vl_msg_api_free (rpm);
  return rv;
}

int
ikev2_api_ipsec_unregister_udp_port (u16 port)
{
  u32 api_client_index = ikev2_get_api_index ();
  vl_api_ipsec_unregister_udp_port_t *mp =
    vl_msg_api_alloc (sizeof (vl_api_ipsec_unregister_udp_port_t));
  int rv;
    
  /* Check that we are in main thread */
  ASSERT(vlib_get_thread_index()==0);

  mp->_vl_msg_id = htons (VL_API_IPSEC_UNREGISTER_UDP_PORT);
  mp->client_index = api_client_index;
  mp->context = 0;
  mp->port = htons (port);

  vl_msg_api_handler ((void *) mp);

  vl_api_registration_t *rp =
    vl_api_client_index_to_registration (api_client_index);

  if (!rp)
    {
      ikev2_log_warning ("Internal API client not registered");
      return VNET_API_ERROR_NO_INTERNAL_CLIENT;
    }
  vl_api_ipsec_unregister_udp_port_reply_t *rpm =
    (vl_api_ipsec_unregister_udp_port_reply_t *) rp->buf;

  if (!rpm ||
      rpm->_vl_msg_id != ntohs (VL_API_IPSEC_UNREGISTER_UDP_PORT_REPLY))
    {
      ikev2_log_warning (
	"No API answer received : IPsec plugin might not be loaded");
      return VNET_API_ERROR_API_NOT_LOADED;
    }
  rv = rpm->retval;
  vl_msg_api_free (rpm);
  return rv;
}