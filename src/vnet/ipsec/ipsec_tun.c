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

static int
ipsec_tun_protect_feature_set (ipsec_protect_t * itp, u8 enable)
{
  u32 sai = itp->itp_out_sa;
  int is_ip4, is_l2, rv;

  is_ip4 = ip46_address_is_ip4 (&itp->itp_tun.src);
  is_l2 = itp->itp_flags & IPSEC_PROTECT_L2;

  if (is_ip4)
    {
      if (is_l2)
	rv = vnet_feature_enable_disable ("ethernet-output",
					  "esp4-encrypt-tun",
					  itp->itp_sw_if_index, enable,
					  &sai, sizeof (sai));
      else
	rv = vnet_feature_enable_disable ("ip4-output",
					  "esp4-encrypt-tun",
					  itp->itp_sw_if_index, enable,
					  &sai, sizeof (sai));
    }
  else
    {
      if (is_l2)
	rv = vnet_feature_enable_disable ("ethernet-output",
					  "esp6-encrypt-tun",
					  itp->itp_sw_if_index, enable,
					  &sai, sizeof (sai));
      else
	rv = vnet_feature_enable_disable ("ip6-output",
					  "esp6-encrypt-tun",
					  itp->itp_sw_if_index, enable,
					  &sai, sizeof (sai));
    }

  ASSERT (!rv);
  return (rv);
}

static u32
ipsec_tun_protect_get_decrypt_node (vlib_main_t * vm,
				    const ipsec_protect_t * itp)
{
  vlib_node_t *node;

  if (ip46_address_is_ip4 (&itp->itp_crypto.dst))
    node = vlib_get_node_by_name (vm, (u8 *) "esp4-decrypt-tun");
  else
    node = vlib_get_node_by_name (vm, (u8 *) "esp6-decrypt-tun");

  return (node->index);
}

static void
ipsec_tun_protect_db_add (ipsec_main_t * im, const ipsec_protect_t * itp)
{
  const ipsec_sa_t *sa;
  u32 sai;

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SAI(itp, sai,
  ({
      sa = ipsec_sa_get (sai);

      ipsec_tun_lkup_result_t res = {
        .tun_index = itp - ipsec_protect_pool,
        .sa_index = sai,
      };

      /*
       * The key is formed from the tunnel's destination
       * as the packet lookup is done from the packet's source
       */
      if (ip46_address_is_ip4 (&itp->itp_crypto.dst))
        {
          ipsec4_tunnel_key_t key = {
            .remote_ip = itp->itp_crypto.dst.ip4.as_u32,
            .spi = clib_host_to_net_u32 (sa->spi),
          };
          hash_set (im->tun4_protect_by_key, key.as_u64, res.as_u64);
        }
      else
        {
          ipsec6_tunnel_key_t key = {
            .remote_ip = itp->itp_crypto.dst.ip6,
            .spi = clib_host_to_net_u32 (sa->spi),
          };
          hash_set_mem_alloc (&im->tun6_protect_by_key, &key, res.as_u64);
        }
  }))
  /* *INDENT-ON* */
}

static void
ipsec_tun_protect_db_remove (ipsec_main_t * im, const ipsec_protect_t * itp)
{
  const ipsec_sa_t *sa;

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
      if (ip46_address_is_ip4 (&itp->itp_crypto.dst))
        {
          ipsec4_tunnel_key_t key = {
            .remote_ip = itp->itp_crypto.dst.ip4.as_u32,
            .spi = clib_host_to_net_u32 (sa->spi),
          };
          hash_unset (im->tun4_protect_by_key, &key);
        }
      else
        {
          ipsec6_tunnel_key_t key = {
            .remote_ip = itp->itp_crypto.dst.ip6,
            .spi = clib_host_to_net_u32 (sa->spi),
          };
          hash_unset_mem_free (&im->tun6_protect_by_key, &key);
        }
  }))
  /* *INDENT-ON* */
}

static void
ipsec_tun_protect_config (ipsec_main_t * im,
			  ipsec_protect_t * itp, u32 sa_out, u32 * sas_in)
{
  ipsec_sa_t *sa;
  u32 ii;

  itp->itp_n_sa_in = vec_len (sas_in);
  for (ii = 0; ii < itp->itp_n_sa_in; ii++)
    itp->itp_in_sas[ii] = sas_in[ii];
  itp->itp_out_sa = sa_out;

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
    if (ipsec_sa_is_set_IS_TUNNEL (sa))
      {
        itp->itp_crypto.src = sa->tunnel_dst_addr;
        itp->itp_crypto.dst = sa->tunnel_src_addr;
        ipsec_sa_set_IS_PROTECT (sa);
      }
    else
      {
        itp->itp_crypto.src = itp->itp_tun.src;
        itp->itp_crypto.dst = itp->itp_tun.dst;
      }
  }));
  /* *INDENT-ON* */

  /*
   * add to the DB against each SA
   */
  ipsec_tun_protect_db_add (im, itp);

  /*
   * enable the encrypt feature for egress.
   */
  ipsec_tun_protect_feature_set (itp, 1);

}

static void
ipsec_tun_protect_unconfig (ipsec_main_t * im, ipsec_protect_t * itp)
{
  ipsec_sa_t *sa;

  ipsec_tun_protect_feature_set (itp, 0);

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
    ipsec_sa_unset_IS_PROTECT (sa);
  }));
  /* *INDENT-ON* */

  ipsec_tun_protect_db_remove (im, itp);
}

int
ipsec_tun_protect_update (u32 sw_if_index, u32 sa_out, u32 * sas_in)
{
  u32 itpi, ii;
  ipsec_protect_t *itp;
  ipsec_main_t *im;
  vlib_main_t *vm;
  int rv;

  rv = 0;
  im = &ipsec_main;
  vm = vlib_get_main ();
  vec_validate_init_empty (ipsec_protect_db.tunnels, sw_if_index,
			   INDEX_INVALID);
  itpi = ipsec_protect_db.tunnels[sw_if_index];

  vec_foreach_index (ii, sas_in)
  {
    sas_in[ii] = ipsec_get_sa_index_by_sa_id (sas_in[ii]);
    if (~0 == sas_in[ii])
      {
	rv = VNET_API_ERROR_INVALID_VALUE;
	goto out;
      }
  }

  sa_out = ipsec_get_sa_index_by_sa_id (sa_out);

  if (~0 == sa_out)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  if (INDEX_INVALID == itpi)
    {
      vnet_device_class_t *dev_class;
      vnet_hw_interface_t *hi;
      vnet_main_t *vnm;
      u8 is_l2;

      vnm = vnet_get_main ();
      hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
      dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

      if (NULL == dev_class->tun_desc)
	{
	  rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	  goto out;
	}

      pool_get_zero (ipsec_protect_pool, itp);

      itp->itp_sw_if_index = sw_if_index;
      ipsec_protect_db.tunnels[sw_if_index] = itp - ipsec_protect_pool;
      ipsec_protect_db.count++;

      itp->itp_n_sa_in = vec_len (sas_in);
      for (ii = 0; ii < itp->itp_n_sa_in; ii++)
	itp->itp_in_sas[ii] = sas_in[ii];
      itp->itp_out_sa = sa_out;

      rv = dev_class->tun_desc (sw_if_index,
				&itp->itp_tun.src,
				&itp->itp_tun.dst,
				&is_l2, &itp->itp_decap_node_index);

      if (rv)
	goto out;

      if (is_l2)
	itp->itp_flags |= IPSEC_PROTECT_L2;

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

      ipsec_tun_protect_config (im, itp, sa_out, sas_in);

      /*
       * add the arc from ESP decrypt to the tunnel decap node
       */
      itp->itp_edge = vlib_node_add_next (vm,
					  ipsec_tun_protect_get_decrypt_node
					  (vm, itp),
					  itp->itp_decap_node_index);

      if (1 == hash_elts (im->tun4_protect_by_key))
	ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec4_tun_input_node.index);
      if (1 == hash_elts (im->tun6_protect_by_key))
	ip6_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec6_tun_input_node.index);
    }
  else
    {
      /* update - exchanging SA onlys */
      itp = pool_elt_at_index (ipsec_protect_pool, itpi);

      ipsec_tun_protect_unconfig (im, itp);
      ipsec_tun_protect_config (im, itp, sa_out, sas_in);
    }

  vec_free (sas_in);
out:
  return (rv);
}

int
ipsec_tun_protect_del (u32 sw_if_index)
{
  ipsec_protect_t *itp;
  ipsec_main_t *im;
  index_t itpi;

  im = &ipsec_main;

  vec_validate_init_empty (ipsec_protect_db.tunnels, sw_if_index,
			   INDEX_INVALID);
  itpi = ipsec_protect_db.tunnels[sw_if_index];

  if (INDEX_INVALID == itpi)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  itp = ipsec_tun_protect_get (itpi);
  ipsec_tun_protect_unconfig (im, itp);

  ipsec_protect_db.tunnels[itp->itp_sw_if_index] = INDEX_INVALID;

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
					     sizeof (u64));
  im->tun4_protect_by_key = hash_create (0, sizeof (u64));

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
