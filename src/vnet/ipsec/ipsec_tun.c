/*
 * ipsec_tun.h : IPSEC tunnel protection
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/esp.h>
#include <vnet/udp/udp.h>

/**
 * Pool of tunnel protection objects
 */
ipsec_protect_t *ipsec_protect_pool;

/**
 * DB of protected tunnels
 */
typedef struct ipsec_protect_db_t_
{
  u32 *tunnels;
  u32 count;
} ipsec_protect_db_t;

static ipsec_protect_db_t ipsec_protect_db;

static void
ipsec_tun_protect_feature_set (ipsec_protect_t * itp, u8 enable)
{
  u32 sai = itp->it_sa[IPSEC_PROTECT_DIR_OUTBOUND];
  vnet_feature_enable_disable ("ip4-output",
			       "esp4-encrypt-tun",
			       itp->it_sw_if_index, enable,
			       &sai, sizeof (sai));
  vnet_feature_enable_disable ("ip6-output",
			       "esp6-encrypt-tun",
			       itp->it_sw_if_index, enable,
			       &sai, sizeof (sai));
}

int
ipsec_tun_protect_update (u32 sw_if_index, u32 sa_in_id, u32 sa_out_id)
{
  u32 sa_in, sa_out, iti;
  ipsec_protect_t *it;
  vlib_main_t *vm;

  vm = vlib_get_main ();
  vec_validate_init_empty (ipsec_protect_db.tunnels, sw_if_index,
			   INDEX_INVALID);
  iti = ipsec_protect_db.tunnels[sw_if_index];

  sa_in = ipsec_get_sa_index_by_sa_id (sa_in_id);
  sa_out = ipsec_get_sa_index_by_sa_id (sa_out_id);

  if (~0 == sa_in || ~0 == sa_out)
    return VNET_API_ERROR_INVALID_VALUE;

  if (INDEX_INVALID == iti)
    {
      vnet_hw_interface_class_t *hw_class;
      vlib_node_t *esp_decrypt_node;
      vnet_hw_interface_t *hi;
      ipsec_main_t *im;
      vnet_main_t *vnm;
      ipsec_sa_t *sa;
      int rv;

      im = &ipsec_main;
      vnm = vnet_get_main ();
      hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
      hw_class = vnet_get_hw_interface_class (vnm, hi->hw_class_index);

      if (NULL == hw_class->tun_desc)
	return (-1);

      pool_get_zero (ipsec_protect_pool, it);

      it->it_sw_if_index = sw_if_index;
      ipsec_protect_db.tunnels[sw_if_index] = it - ipsec_protect_pool;
      ipsec_protect_db.count++;
      it->it_sa[IPSEC_PROTECT_DIR_INBOUND] = sa_in;
      it->it_sa[IPSEC_PROTECT_DIR_OUTBOUND] = sa_out;

      rv = hw_class->tun_desc (sw_if_index, &it->it_tun.src,
			       &it->it_tun.dst, &it->it_decap_node_index);

      if (rv)
	return (-2);

      /*
       * enable the encrypt feature for egress.
       */
      ipsec_tun_protect_feature_set (it, 1);

      /*
       * add to the tunnel DB for ingress
       *  - if the SA is in trasnport mode, then the packates will arrivw
       *    with the IP src,dst of the protected tunnel, in which case we can
       *    simply strip the IP header and hand the payload to the protocol
       *    appropriate input handler
       *  - if the SA is in tunnel mode then there are two IP headers present
       *    one for the crytpo tunnel endpoints (described in the SA) and one
       *    for the tunnel endpoints. The out IP headers in the srriving
       *    packets will have the crypto endpoints. So the DB needs to contain
       *    the crpto endpoint. Once the crypto header is stripped, revealing,
       *    the tunnel-IP we have 2 choices:
       *     1) do a tunnel lookup based on the revealed header
       *     2) skip the tunnel lookup and assume that the packet matches the
       *        one that is protected here.
       *    If we did 1) then we would allow our peer to use the SA for tunnel
       *    X to inject traffic onto tunnel Y, this is not good. If we do 2)
       *    then we don't verify that the peer is indeed using SA for tunnel
       *    X and addressing tunnel X. So we take a compromise, once the SA
       *    matches to tunnel X we veriy that the inner IP matches the value
       *    of the tunnel we are protecting, else it's dropped.
       */
      sa = ipsec_sa_get (sa_in);

      if (ipsec_sa_is_set_IS_TUNNEL (sa))
	{
	  it->it_crypto.src = sa->tunnel_dst_addr;
	  it->it_crypto.dst = sa->tunnel_src_addr;
	  ipsec_sa_set_PROTECT (sa);
	}
      else
	{
	  it->it_crypto.src = it->it_tun.src;
	  it->it_crypto.dst = it->it_tun.dst;
	}

      /*
       * The key is formed from the tunnel's destination
       * as the packet lookup is done from the packet's source
       */
      if (ip46_address_is_ip4 (&it->it_crypto.dst))
	{
	  ipsec4_tunnel_key_t key = {
	    .remote_ip = it->it_crypto.dst.ip4.as_u32,
	    .spi = clib_host_to_net_u32 (sa->spi),
	  };
	  hash_set (im->tun4_protect_by_key, key.as_u64,
		    it - ipsec_protect_pool);
	  esp_decrypt_node =
	    vlib_get_node_by_name (vm, (u8 *) "esp6-decrypt");
	}
      else
	{
	  ipsec6_tunnel_key_t key = {
	    .remote_ip = it->it_crypto.dst.ip6,
	    .spi = clib_host_to_net_u32 (sa->spi),
	  };
	  hash_set_mem_alloc (&im->tun6_protect_by_key, &key,
			      it - ipsec_protect_pool);
	  esp_decrypt_node =
	    vlib_get_node_by_name (vm, (u8 *) "esp4-decrypt");
	}

      /*
       * add the arc from ESP decrypt to the tunnel decap node
       */
      it->it_edge = vlib_node_add_next (vm,
					esp_decrypt_node->index,
					it->it_decap_node_index);

      if (1 == hash_elts (im->tun4_protect_by_key))
	ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec4_tun_input_node.index);
      if (1 == hash_elts (im->tun6_protect_by_key))
	ip6_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec6_tun_input_node.index);
    }
  else
    {
      /* update TODO */
      ASSERT (0);
    }

  return (0);
}

int
ipsec_tun_protect_del (u32 sw_if_index)
{
  ipsec_protect_t *itp;
  ipsec_main_t *im;
  ipsec_sa_t *sa;
  index_t itpi;

  im = &ipsec_main;

  vec_validate_init_empty (ipsec_protect_db.tunnels, sw_if_index,
			   INDEX_INVALID);
  itpi = ipsec_protect_db.tunnels[sw_if_index];

  if (INDEX_INVALID == itpi)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  itp = ipsec_tun_protect_get (itpi);
  sa = ipsec_sa_get (itp->it_sa[IPSEC_PROTECT_DIR_INBOUND]);
  ipsec_sa_unset_PROTECT (sa);

  if (ip46_address_is_ip4 (&itp->it_crypto.dst))
    {
      ipsec4_tunnel_key_t key = {
	.remote_ip = itp->it_crypto.dst.ip4.as_u32,
	.spi = clib_host_to_net_u32 (sa->spi),
      };
      hash_unset (im->tun4_protect_by_key, &key);
    }
  else
    {
      ipsec6_tunnel_key_t key = {
	.remote_ip = itp->it_crypto.dst.ip6,
	.spi = clib_host_to_net_u32 (sa->spi),
      };
      hash_unset_mem_free (&im->tun6_protect_by_key, &key);
    }
  ipsec_tun_protect_feature_set (itp, 0);

  ipsec_protect_db.tunnels[itp->it_sw_if_index] = INDEX_INVALID;

  pool_put (ipsec_protect_pool, itp);

  return (0);
}

void
ipsec_tun_protect_walk (ipsec_tun_protect_walk_cb_t fn, void *ctx)
{
  index_t itpi;

  /* *INDENT-OFF* */
  pool_foreach_index(itpi, ipsec_protect_pool,
  ({
    fn (itpi, ctx);
  }));
  /* *INDENT-ON* */
}

clib_error_t *
ipsec_tunnel_protect_init (vlib_main_t * vm)
{
  ipsec_main_t *im;

  im = &ipsec_main;
  im->tun6_protect_by_key = hash_create_mem (0,
					     sizeof (ipsec6_tunnel_key_t),
					     sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (ipsec_tunnel_protect_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
