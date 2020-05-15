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
ipsec_tun_protect_t *ipsec_protect_pool;

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
ipsec_tun_protect_feature_set (ipsec_tun_protect_t * itp, u8 enable)
{
  u32 sai = itp->itp_out_sa;
  int rv;

  const char *enc_node = (ip46_address_is_ip4 (&itp->itp_tun.src) ?
			  "esp4-encrypt-tun" : "esp6-encrypt-tun");

  if (itp->itp_flags & IPSEC_PROTECT_L2)
    {
      rv = vnet_feature_enable_disable ("ethernet-output",
					enc_node,
					itp->itp_sw_if_index, enable,
					&sai, sizeof (sai));
    }
  else
    {
      rv = vnet_feature_enable_disable ("ip4-output",
					enc_node,
					itp->itp_sw_if_index, enable,
					&sai, sizeof (sai));
      rv = vnet_feature_enable_disable ("ip6-output",
					enc_node,
					itp->itp_sw_if_index, enable,
					&sai, sizeof (sai));
    }
  ASSERT (!rv);
  return (rv);
}

static void
ipsec_tun_protect_db_add (ipsec_main_t * im, const ipsec_tun_protect_t * itp)
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
            .remote_ip = itp->itp_crypto.dst.ip4,
            .spi = clib_host_to_net_u32 (sa->spi),
          };
          hash_set (im->tun4_protect_by_key, key.as_u64, res.as_u64);
          if (1 == hash_elts(im->tun4_protect_by_key))
            udp_register_dst_port (vlib_get_main(),
                                   UDP_DST_PORT_ipsec,
                                   ipsec4_tun_input_node.index, 1);
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
ipsec_tun_protect_db_remove (ipsec_main_t * im,
			     const ipsec_tun_protect_t * itp)
{
  const ipsec_sa_t *sa;

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
      if (ip46_address_is_ip4 (&itp->itp_crypto.dst))
        {
          ipsec4_tunnel_key_t key = {
            .remote_ip = itp->itp_crypto.dst.ip4,
            .spi = clib_host_to_net_u32 (sa->spi),
          };
          hash_unset (im->tun4_protect_by_key, &key);
          if (0 == hash_elts(im->tun4_protect_by_key))
            udp_unregister_dst_port (vlib_get_main(),
                                     UDP_DST_PORT_ipsec,
                                     1);
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
			  ipsec_tun_protect_t * itp, u32 sa_out, u32 * sas_in)
{
  ipsec_sa_t *sa;
  index_t sai;
  u32 ii;

  itp->itp_n_sa_in = vec_len (sas_in);
  for (ii = 0; ii < itp->itp_n_sa_in; ii++)
    itp->itp_in_sas[ii] = sas_in[ii];
  itp->itp_out_sa = sa_out;

  ipsec_sa_lock (itp->itp_out_sa);

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SAI(itp, sai,
  ({
    ipsec_sa_lock(sai);
  }));
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
    if (ipsec_sa_is_set_IS_TUNNEL (sa))
      {
        itp->itp_crypto.src = sa->tunnel_dst_addr;
        itp->itp_crypto.dst = sa->tunnel_src_addr;
        ipsec_sa_set_IS_PROTECT (sa);
        itp->itp_flags |= IPSEC_PROTECT_ENCAPED;
      }
    else
      {
        itp->itp_crypto.src = itp->itp_tun.src;
        itp->itp_crypto.dst = itp->itp_tun.dst;
        itp->itp_flags &= ~IPSEC_PROTECT_ENCAPED;
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
ipsec_tun_protect_unconfig (ipsec_main_t * im, ipsec_tun_protect_t * itp)
{
  ipsec_sa_t *sa;
  index_t sai;

  ipsec_tun_protect_feature_set (itp, 0);

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
    ipsec_sa_unset_IS_PROTECT (sa);
  }));

  ipsec_tun_protect_db_remove (im, itp);

  ipsec_sa_unlock(itp->itp_out_sa);

  FOR_EACH_IPSEC_PROTECT_INPUT_SAI(itp, sai,
  ({
    ipsec_sa_unlock(sai);
  }));
  /* *INDENT-ON* */
}

index_t
ipsec_tun_protect_find (u32 sw_if_index)
{
  if (vec_len (ipsec_protect_db.tunnels) < sw_if_index)
    return (INDEX_INVALID);

  return (ipsec_protect_db.tunnels[sw_if_index]);
}

int
ipsec_tun_protect_update_one (u32 sw_if_index, u32 sa_out, u32 sa_in)
{
  u32 *sas_in = NULL;
  int rv;

  vec_add1 (sas_in, sa_in);
  rv = ipsec_tun_protect_update (sw_if_index, sa_out, sas_in);

  return (rv);
}

int
ipsec_tun_protect_update_out (u32 sw_if_index, u32 sa_out)
{
  u32 itpi, *sas_in, sai, *saip;
  ipsec_tun_protect_t *itp;
  ipsec_main_t *im;
  int rv;

  sas_in = NULL;
  rv = 0;
  im = &ipsec_main;
  vec_validate_init_empty (ipsec_protect_db.tunnels, sw_if_index,
			   INDEX_INVALID);
  itpi = ipsec_protect_db.tunnels[sw_if_index];

  if (INDEX_INVALID == itpi)
    {
      return (VNET_API_ERROR_INVALID_INTERFACE);
    }

  itp = pool_elt_at_index (ipsec_protect_pool, itpi);

  /* *INDENT-0FF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SAI (itp, sai, (
						{
						ipsec_sa_lock (sai);
						vec_add1 (sas_in, sai);
						}
				    ));
  /* *INDENT-ON* */

  sa_out = ipsec_sa_find_and_lock (sa_out);

  if (~0 == sa_out)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  ipsec_tun_protect_unconfig (im, itp);
  ipsec_tun_protect_config (im, itp, sa_out, sas_in);

  ipsec_sa_unlock (sa_out);
  vec_foreach (saip, sas_in) ipsec_sa_unlock (*saip);

out:
  vec_free (sas_in);
  return (rv);
}

int
ipsec_tun_protect_update_in (u32 sw_if_index, u32 sa_in)
{
  u32 itpi, *sas_in, sa_out;
  ipsec_tun_protect_t *itp;
  ipsec_main_t *im;
  int rv;

  sas_in = NULL;
  rv = 0;
  im = &ipsec_main;
  vec_validate_init_empty (ipsec_protect_db.tunnels, sw_if_index,
			   INDEX_INVALID);
  itpi = ipsec_protect_db.tunnels[sw_if_index];

  if (INDEX_INVALID == itpi)
    {
      return (VNET_API_ERROR_INVALID_INTERFACE);
    }

  sa_in = ipsec_sa_find_and_lock (sa_in);

  if (~0 == sa_in)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }
  vec_add1 (sas_in, sa_in);

  itp = pool_elt_at_index (ipsec_protect_pool, itpi);
  sa_out = itp->itp_out_sa;

  ipsec_sa_lock (sa_out);

  ipsec_tun_protect_unconfig (im, itp);
  ipsec_tun_protect_config (im, itp, sa_out, sas_in);

  ipsec_sa_unlock (sa_out);
  ipsec_sa_unlock (sa_in);
out:
  vec_free (sas_in);
  return (rv);
}

int
ipsec_tun_protect_update (u32 sw_if_index, u32 sa_out, u32 * sas_in)
{
  ipsec_tun_protect_t *itp;
  u32 itpi, ii, *saip;
  ipsec_main_t *im;
  int rv;

  rv = 0;
  im = &ipsec_main;
  vec_validate_init_empty (ipsec_protect_db.tunnels, sw_if_index,
			   INDEX_INVALID);
  itpi = ipsec_protect_db.tunnels[sw_if_index];

  vec_foreach_index (ii, sas_in)
  {
    sas_in[ii] = ipsec_sa_find_and_lock (sas_in[ii]);
    if (~0 == sas_in[ii])
      {
	rv = VNET_API_ERROR_INVALID_VALUE;
	goto out;
      }
  }

  sa_out = ipsec_sa_find_and_lock (sa_out);

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

      if (NULL == dev_class->ip_tun_desc)
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

      rv = dev_class->ip_tun_desc (sw_if_index,
				   &itp->itp_tun.src,
				   &itp->itp_tun.dst, &is_l2);

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
       *    for the tunnel endpoints. The outer IP headers in the srriving
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

      if (1 == hash_elts (im->tun4_protect_by_key))
	ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec4_tun_input_node.index);
      if (1 == hash_elts (im->tun6_protect_by_key))
	ip6_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec6_tun_input_node.index);
    }
  else
    {
      /* updating SAs only */
      itp = pool_elt_at_index (ipsec_protect_pool, itpi);

      ipsec_tun_protect_unconfig (im, itp);
      ipsec_tun_protect_config (im, itp, sa_out, sas_in);
    }

  ipsec_sa_unlock (sa_out);
  vec_foreach (saip, sas_in) ipsec_sa_unlock (*saip);
  vec_free (sas_in);

out:
  return (rv);
}

int
ipsec_tun_protect_del (u32 sw_if_index)
{
  ipsec_tun_protect_t *itp;
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

  if (0 == hash_elts (im->tun4_protect_by_key))
    ip4_unregister_protocol (IP_PROTOCOL_IPSEC_ESP);
  if (0 == hash_elts (im->tun6_protect_by_key))
    ip6_unregister_protocol (IP_PROTOCOL_IPSEC_ESP);

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
