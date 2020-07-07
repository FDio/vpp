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
#include <vnet/ipsec/ipsec_itf.h>
#include <vnet/ipsec/esp.h>
#include <vnet/udp/udp.h>
#include <vnet/adj/adj_delegate.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/teib/teib.h>

/**
 * The logger
 */
vlib_log_class_t ipsec_tun_protect_logger;

/**
 * Pool of tunnel protection objects
 */
ipsec_tun_protect_t *ipsec_tun_protect_pool;

/**
 * Adj delegate registered type
 */
static adj_delegate_type_t ipsec_tun_adj_delegate_type;

/**
 * Adj index to TX SA mapping
 */
index_t *ipsec_tun_protect_sa_by_adj_index;

const ip_address_t IP_ADDR_ALL_0 = IP_ADDRESS_V4_ALL_0S;

/**
 * The DB of all added per-nh tunnel protectiond
 */
typedef struct ipsec_tun_protect_itf_db_t_
{
  /** A hash table key'd on IP (4 or 6) address */
  uword *id_hash;
  /** If the interface is P2P then there is only one protect
   * object associated with the auto-adj for each NH proto */
  index_t id_itp;
} ipsec_tun_protect_itf_db_t;

typedef struct ipsec_tun_protect_db_t_
{
  /** Per-interface vector */
  ipsec_tun_protect_itf_db_t *id_itf;
} ipsec_tun_protect_db_t;

static ipsec_tun_protect_db_t itp_db;

const static ipsec_tun_protect_itf_db_t IPSEC_TUN_PROTECT_DEFAULT_DB_ENTRY = {
  .id_itp = INDEX_INVALID,
};

#define ITP_DBG(_itp, _fmt, _args...)                   \
{   		          				\
  vlib_log_debug(ipsec_tun_protect_logger,              \
                 "[%U]: " _fmt,                         \
                 format_ipsec_tun_protect,              \
                 _itp, ##_args);                        \
}

#define ITP_DBG2(_fmt, _args...)                        \
{   		          				\
  vlib_log_debug(ipsec_tun_protect_logger,              \
                 _fmt, ##_args);                        \
}

static u32 ipsec_tun_node_regs[N_AF];

void
ipsec_tun_register_nodes (ip_address_family_t af)
{
  if (0 == ipsec_tun_node_regs[af]++)
    {
      if (AF_IP4 == af)
	{
	  ipsec_register_udp_port (UDP_DST_PORT_ipsec);
	  ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
				 ipsec4_tun_input_node.index);
	}
      else
	ip6_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec6_tun_input_node.index);
    }
}

void
ipsec_tun_unregister_nodes (ip_address_family_t af)
{
  ASSERT (0 != ipsec_tun_node_regs[af]);
  if (0 == --ipsec_tun_node_regs[af])
    {
      if (AF_IP4 == af)
	{
	  ipsec_unregister_udp_port (UDP_DST_PORT_ipsec);
	  ip4_unregister_protocol (IP_PROTOCOL_IPSEC_ESP);
	}
      else
	ip6_unregister_protocol (IP_PROTOCOL_IPSEC_ESP);
    }
}

static inline const ipsec_tun_protect_t *
ipsec_tun_protect_from_const_base (const adj_delegate_t * ad)
{
  if (ad == NULL)
    return (NULL);
  return (pool_elt_at_index (ipsec_tun_protect_pool, ad->ad_index));
}

static u32
ipsec_tun_protect_get_adj_next (vnet_link_t linkt,
				const ipsec_tun_protect_t * itp)
{
  ipsec_main_t *im;
  ipsec_sa_t *sa;
  bool is_ip4;
  u32 next;


  if (itp->itp_flags & IPSEC_PROTECT_ITF)
    is_ip4 = linkt == VNET_LINK_IP4;
  else
    is_ip4 = ip46_address_is_ip4 (&itp->itp_tun.src);

  sa = ipsec_sa_get (itp->itp_out_sa);
  im = &ipsec_main;

  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_NONE &&
      sa->integ_alg == IPSEC_INTEG_ALG_NONE)
    next = (is_ip4 ?
	    im->esp4_no_crypto_tun_node_index :
	    im->esp6_no_crypto_tun_node_index);
  else if (itp->itp_flags & IPSEC_PROTECT_L2)
    next = (is_ip4 ?
	    im->esp4_encrypt_l2_tun_node_index :
	    im->esp6_encrypt_l2_tun_node_index);
  else
    next = (is_ip4 ?
	    im->esp4_encrypt_tun_node_index :
	    im->esp6_encrypt_tun_node_index);

  return (next);
}

static void
ipsec_tun_protect_add_adj (adj_index_t ai, const ipsec_tun_protect_t * itp)
{
  vec_validate_init_empty (ipsec_tun_protect_sa_by_adj_index, ai,
			   INDEX_INVALID);

  if (NULL == itp)
    {
      ipsec_tun_protect_sa_by_adj_index[ai] = INDEX_INVALID;
      adj_nbr_midchain_reset_next_node (ai);
    }
  else
    {
      ipsec_tun_protect_sa_by_adj_index[ai] = itp->itp_out_sa;
      adj_nbr_midchain_update_next_node
	(ai, ipsec_tun_protect_get_adj_next (adj_get_link_type (ai), itp));
    }
}

static index_t
ipsec_tun_protect_find (u32 sw_if_index, const ip_address_t * nh)
{
  ipsec_tun_protect_itf_db_t *idi;
  uword *p;

  if (vec_len (itp_db.id_itf) <= sw_if_index)
    return INDEX_INVALID;

  if (vnet_sw_interface_is_p2p (vnet_get_main (), sw_if_index))
    return (itp_db.id_itf[sw_if_index].id_itp);

  idi = &itp_db.id_itf[sw_if_index];
  p = hash_get_mem (idi->id_hash, nh);

  if (NULL == p)
    {
      return INDEX_INVALID;
    }
  return (p[0]);
}

static void
ipsec_tun_protect_rx_db_add (ipsec_main_t * im,
			     const ipsec_tun_protect_t * itp)
{
  const ipsec_sa_t *sa;
  u32 sai;

  if (ip46_address_is_zero (&itp->itp_crypto.dst))
    return;

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SAI(itp, sai,
  ({
      sa = ipsec_sa_get (sai);

      ipsec_tun_lkup_result_t res = {
        .tun_index = itp - ipsec_tun_protect_pool,
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
          ipsec_tun_register_nodes(AF_IP4);
        }
      else
        {
          ipsec6_tunnel_key_t key = {
            .remote_ip = itp->itp_crypto.dst.ip6,
            .spi = clib_host_to_net_u32 (sa->spi),
          };
          hash_set_mem_alloc (&im->tun6_protect_by_key, &key, res.as_u64);
          ipsec_tun_register_nodes(AF_IP6);
        }
  }))
  /* *INDENT-ON* */
}

static adj_walk_rc_t
ipsec_tun_protect_adj_add (adj_index_t ai, void *arg)
{
  ipsec_tun_protect_t *itp = arg;
  adj_delegate_add (adj_get (ai), ipsec_tun_adj_delegate_type,
		    itp - ipsec_tun_protect_pool);
  ipsec_tun_protect_add_adj (ai, itp);

  if (itp->itp_flags & IPSEC_PROTECT_ITF)
    ipsec_itf_adj_stack (ai, itp->itp_out_sa);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
ipsec_tun_protect_tx_db_add (ipsec_tun_protect_t * itp)
{
  /*
   * add the delegate to the adj
   */
  ipsec_tun_protect_itf_db_t *idi;
  fib_protocol_t nh_proto;
  ip46_address_t nh;

  vec_validate_init_empty (itp_db.id_itf,
			   itp->itp_sw_if_index,
			   IPSEC_TUN_PROTECT_DEFAULT_DB_ENTRY);

  idi = &itp_db.id_itf[itp->itp_sw_if_index];

  if (vnet_sw_interface_is_p2p (vnet_get_main (), itp->itp_sw_if_index))
    {
      if (INDEX_INVALID == idi->id_itp)
	{
	  // ipsec_tun_protect_feature_set (itp, 1);
	}
      idi->id_itp = itp - ipsec_tun_protect_pool;

      FOR_EACH_FIB_IP_PROTOCOL (nh_proto)
	adj_nbr_walk (itp->itp_sw_if_index,
		      nh_proto, ipsec_tun_protect_adj_add, itp);
    }
  else
    {
      if (NULL == idi->id_hash)
	{
	  idi->id_hash =
	    hash_create_mem (0, sizeof (ip_address_t), sizeof (uword));
	  /*
	   * enable the encrypt feature for egress if this is the first addition
	   * on this interface
	   */
	  // ipsec_tun_protect_feature_set (itp, 1);
	}

      hash_set_mem (idi->id_hash, itp->itp_key, itp - ipsec_tun_protect_pool);

      /*
       * walk all the adjs with the same nh on this interface
       * to associate them with this protection
       */
      nh_proto = ip_address_to_46 (itp->itp_key, &nh);

      adj_nbr_walk_nh (itp->itp_sw_if_index,
		       nh_proto, &nh, ipsec_tun_protect_adj_add, itp);

      ipsec_tun_register_nodes (FIB_PROTOCOL_IP6 == nh_proto ?
				AF_IP6 : AF_IP4);
    }
}

static void
ipsec_tun_protect_rx_db_remove (ipsec_main_t * im,
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
        if (hash_get(im->tun4_protect_by_key, key.as_u64))
          {
            hash_unset (im->tun4_protect_by_key, key.as_u64);
            ipsec_tun_unregister_nodes(AF_IP4);
          }
      }
    else
      {
        ipsec6_tunnel_key_t key = {
          .remote_ip = itp->itp_crypto.dst.ip6,
          .spi = clib_host_to_net_u32 (sa->spi),
        };
        if (hash_get_mem(im->tun6_protect_by_key, &key))
          {
            hash_unset_mem_free (&im->tun6_protect_by_key, &key);
            ipsec_tun_unregister_nodes(AF_IP6);
          }
      }
  }));
  /* *INDENT-ON* */
}

static adj_walk_rc_t
ipsec_tun_protect_adj_remove (adj_index_t ai, void *arg)
{
  ipsec_tun_protect_t *itp = arg;

  adj_delegate_remove (ai, ipsec_tun_adj_delegate_type);
  ipsec_tun_protect_add_adj (ai, NULL);

  if (itp->itp_flags & IPSEC_PROTECT_ITF)
    ipsec_itf_adj_unstack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
ipsec_tun_protect_tx_db_remove (ipsec_tun_protect_t * itp)
{
  ipsec_tun_protect_itf_db_t *idi;
  fib_protocol_t nh_proto;
  ip46_address_t nh;

  nh_proto = ip_address_to_46 (itp->itp_key, &nh);
  idi = &itp_db.id_itf[itp->itp_sw_if_index];

  if (vnet_sw_interface_is_p2p (vnet_get_main (), itp->itp_sw_if_index))
    {
      // ipsec_tun_protect_feature_set (itp, 0);
      idi->id_itp = INDEX_INVALID;

      FOR_EACH_FIB_IP_PROTOCOL (nh_proto)
	adj_nbr_walk (itp->itp_sw_if_index,
		      nh_proto, ipsec_tun_protect_adj_remove, itp);
    }
  else
    {
      adj_nbr_walk_nh (itp->itp_sw_if_index,
		       nh_proto, &nh, ipsec_tun_protect_adj_remove, itp);

      hash_unset_mem (idi->id_hash, itp->itp_key);

      if (0 == hash_elts (idi->id_hash))
	{
	  // ipsec_tun_protect_feature_set (itp, 0);
	  hash_free (idi->id_hash);
	  idi->id_hash = NULL;
	}
      ipsec_tun_unregister_nodes (FIB_PROTOCOL_IP6 == nh_proto ?
				  AF_IP6 : AF_IP4);
    }
}

static void
ipsec_tun_protect_set_crypto_addr (ipsec_tun_protect_t * itp)
{
  ipsec_sa_t *sa;

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
    if (ipsec_sa_is_set_IS_TUNNEL (sa))
      {
        itp->itp_crypto.src = sa->tunnel_dst_addr;
        itp->itp_crypto.dst = sa->tunnel_src_addr;
        if (!(itp->itp_flags & IPSEC_PROTECT_ITF))
          {
            ipsec_sa_set_IS_PROTECT (sa);
            itp->itp_flags |= IPSEC_PROTECT_ENCAPED;
          }
      }
    else
      {
        itp->itp_crypto.src = itp->itp_tun.src;
        itp->itp_crypto.dst = itp->itp_tun.dst;
        itp->itp_flags &= ~IPSEC_PROTECT_ENCAPED;
      }
  }));
  /* *INDENT-ON* */
}

static void
ipsec_tun_protect_config (ipsec_main_t * im,
			  ipsec_tun_protect_t * itp, u32 sa_out, u32 * sas_in)
{
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
  ipsec_tun_protect_set_crypto_addr(itp);
  /* *INDENT-ON* */

  /*
   * add to the DB against each SA
   */
  ipsec_tun_protect_rx_db_add (im, itp);
  ipsec_tun_protect_tx_db_add (itp);

  ITP_DBG (itp, "configured");
}

static void
ipsec_tun_protect_unconfig (ipsec_main_t * im, ipsec_tun_protect_t * itp)
{
  ipsec_sa_t *sa;
  index_t sai;

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SA(itp, sa,
  ({
    ipsec_sa_unset_IS_PROTECT (sa);
  }));

  ipsec_tun_protect_rx_db_remove (im, itp);
  ipsec_tun_protect_tx_db_remove (itp);

  ipsec_sa_unlock(itp->itp_out_sa);

  FOR_EACH_IPSEC_PROTECT_INPUT_SAI(itp, sai,
  ({
    ipsec_sa_unlock(sai);
  }));
  /* *INDENT-ON* */
  ITP_DBG (itp, "unconfigured");
}

int
ipsec_tun_protect_update_one (u32 sw_if_index,
			      const ip_address_t * nh, u32 sa_out, u32 sa_in)
{
  u32 *sas_in = NULL;
  int rv;

  vec_add1 (sas_in, sa_in);
  rv = ipsec_tun_protect_update (sw_if_index, nh, sa_out, sas_in);

  return (rv);
}

int
ipsec_tun_protect_update_out (u32 sw_if_index,
			      const ip_address_t * nh, u32 sa_out)
{
  u32 itpi, *sas_in, sai, *saip;
  ipsec_tun_protect_t *itp;
  ipsec_main_t *im;
  int rv;

  sas_in = NULL;
  rv = 0;
  im = &ipsec_main;

  itpi = ipsec_tun_protect_find (sw_if_index, nh);

  if (INDEX_INVALID == itpi)
    {
      return (VNET_API_ERROR_INVALID_INTERFACE);
    }

  itp = pool_elt_at_index (ipsec_tun_protect_pool, itpi);

  /* *INDENT-OFF* */
  FOR_EACH_IPSEC_PROTECT_INPUT_SAI (itp, sai,
  ({
    ipsec_sa_lock (sai);
    vec_add1 (sas_in, sai);
  }));
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
ipsec_tun_protect_update_in (u32 sw_if_index,
			     const ip_address_t * nh, u32 sa_in)
{
  u32 itpi, *sas_in, sa_out;
  ipsec_tun_protect_t *itp;
  ipsec_main_t *im;
  int rv;

  sas_in = NULL;
  rv = 0;
  im = &ipsec_main;
  itpi = ipsec_tun_protect_find (sw_if_index, nh);

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

  itp = pool_elt_at_index (ipsec_tun_protect_pool, itpi);
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

static void
ipsec_tun_protect_update_from_teib (ipsec_tun_protect_t * itp,
				    const teib_entry_t * ne)
{
  if (NULL != ne)
    {
      const fib_prefix_t *pfx;

      pfx = teib_entry_get_nh (ne);

      ip46_address_copy (&itp->itp_tun.dst, &pfx->fp_addr);
    }
  else
    ip46_address_reset (&itp->itp_tun.dst);
}

int
ipsec_tun_protect_update (u32 sw_if_index,
			  const ip_address_t * nh, u32 sa_out, u32 * sas_in)
{
  ipsec_tun_protect_t *itp;
  u32 itpi, ii, *saip;
  ipsec_main_t *im;
  int rv;

  ITP_DBG2 ("update: %U/%U",
	    format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
	    format_ip_address, nh);

  if (vec_len (sas_in) > ITP_MAX_N_SA_IN)
    {
      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
      goto out;
    }

  rv = 0;
  im = &ipsec_main;
  if (NULL == nh)
    nh = &IP_ADDR_ALL_0;
  itpi = ipsec_tun_protect_find (sw_if_index, nh);

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

      pool_get_zero (ipsec_tun_protect_pool, itp);

      itp->itp_sw_if_index = sw_if_index;
      itp->itp_ai = ADJ_INDEX_INVALID;

      itp->itp_n_sa_in = vec_len (sas_in);
      for (ii = 0; ii < itp->itp_n_sa_in; ii++)
	itp->itp_in_sas[ii] = sas_in[ii];
      itp->itp_out_sa = sa_out;

      itp->itp_key = clib_mem_alloc (sizeof (*itp->itp_key));
      ip_address_copy (itp->itp_key, nh);

      rv = dev_class->ip_tun_desc (sw_if_index,
				   &itp->itp_tun.src,
				   &itp->itp_tun.dst, &is_l2);

      if (rv)
	goto out;

      if (ip46_address_is_zero (&itp->itp_tun.src))
	{
	  /* must be one of thos pesky ipsec interfaces that has no encap.
	   * the encap then MUST comefrom the tunnel mode SA.
	   */
	  ipsec_sa_t *sa;

	  sa = ipsec_sa_get (itp->itp_out_sa);

	  if (!ipsec_sa_is_set_IS_TUNNEL (sa))
	    {
	      rv = VNET_API_ERROR_INVALID_DST_ADDRESS;
	      goto out;
	    }

	  itp->itp_flags |= IPSEC_PROTECT_ITF;
	}
      else if (ip46_address_is_zero (&itp->itp_tun.dst))
	{
	  /* tunnel has no destination address, presumably because it's p2mp
	     in which case we use the nh that this is protection for */
	  ip46_address_t peer;

	  ip_address_to_46 (nh, &peer);

	  ipsec_tun_protect_update_from_teib
	    (itp, teib_entry_find (sw_if_index, &peer));
	}

      if (is_l2)
	itp->itp_flags |= IPSEC_PROTECT_L2;

      /*
       * add to the tunnel DB for ingress
       *  - if the SA is in trasnport mode, then the packates will arrive
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
    }
  else
    {
      /* updating SAs only */
      itp = pool_elt_at_index (ipsec_tun_protect_pool, itpi);

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
ipsec_tun_protect_del (u32 sw_if_index, const ip_address_t * nh)
{
  ipsec_tun_protect_t *itp;
  ipsec_main_t *im;
  index_t itpi;

  ITP_DBG2 ("delete: %U/%U",
	    format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
	    format_ip_address, nh);

  im = &ipsec_main;
  if (NULL == nh)
    nh = &IP_ADDR_ALL_0;

  itpi = ipsec_tun_protect_find (sw_if_index, nh);

  if (INDEX_INVALID == itpi)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  itp = ipsec_tun_protect_get (itpi);
  ipsec_tun_protect_unconfig (im, itp);

  if (ADJ_INDEX_INVALID != itp->itp_ai)
    adj_unlock (itp->itp_ai);

  clib_mem_free (itp->itp_key);
  pool_put (ipsec_tun_protect_pool, itp);

  return (0);
}

void
ipsec_tun_protect_walk (ipsec_tun_protect_walk_cb_t fn, void *ctx)
{
  index_t itpi;

  /* *INDENT-OFF* */
  pool_foreach_index(itpi, ipsec_tun_protect_pool,
  ({
    fn (itpi, ctx);
  }));
  /* *INDENT-ON* */
}

void
ipsec_tun_protect_walk_itf (u32 sw_if_index,
			    ipsec_tun_protect_walk_cb_t fn, void *ctx)
{
  ipsec_tun_protect_itf_db_t *idi;
  ip_address_t *key;
  index_t itpi;

  if (vec_len (itp_db.id_itf) <= sw_if_index)
    return;

  idi = &itp_db.id_itf[sw_if_index];

  /* *INDENT-OFF* */
  hash_foreach(key, itpi, idi->id_hash,
  ({
    fn (itpi, ctx);
  }));
  /* *INDENT-ON* */
  if (INDEX_INVALID != idi->id_itp)
    fn (idi->id_itp, ctx);
}

static void
ipsec_tun_protect_adj_delegate_adj_deleted (adj_delegate_t * ad)
{
  /* remove our delegate */
  ipsec_tun_protect_add_adj (ad->ad_adj_index, NULL);
  adj_delegate_remove (ad->ad_adj_index, ipsec_tun_adj_delegate_type);
}

static void
ipsec_tun_protect_adj_delegate_adj_modified (adj_delegate_t * ad)
{
  ipsec_tun_protect_add_adj (ad->ad_adj_index,
			     ipsec_tun_protect_get (ad->ad_index));
}

static void
ipsec_tun_protect_adj_delegate_adj_created (adj_index_t ai)
{
  /* add our delegate if there is protection for this neighbour */
  ip_address_t ip = IP_ADDRESS_V4_ALL_0S;
  ip_adjacency_t *adj;
  index_t itpi;

  if (!adj_is_midchain (ai))
    return;

  adj = adj_get (ai);

  ip_address_from_46 (&adj->sub_type.midchain.next_hop,
		      adj->ia_nh_proto, &ip);

  itpi = ipsec_tun_protect_find (adj->rewrite_header.sw_if_index, &ip);

  if (INDEX_INVALID != itpi)
    ipsec_tun_protect_adj_add (ai, ipsec_tun_protect_get (itpi));
}

static u8 *
ipsec_tun_protect_adj_delegate_format (const adj_delegate_t * aed, u8 * s)
{
  const ipsec_tun_protect_t *itp;

  itp = ipsec_tun_protect_from_const_base (aed);
  s = format (s, "ipsec-tun-protect:\n%U", format_ipsec_tun_protect, itp);

  return (s);
}

static void
ipsec_tun_teib_entry_added (const teib_entry_t * ne)
{
  const ip46_address_t *peer46;
  ipsec_tun_protect_t *itp;
  ip_address_t peer;
  index_t itpi;

  peer46 = teib_entry_get_peer (ne);
  ip_address_from_46 (peer46,
		      (ip46_address_is_ip4 (peer46) ?
		       FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6), &peer);

  itpi = ipsec_tun_protect_find (teib_entry_get_sw_if_index (ne), &peer);

  if (INDEX_INVALID == itpi)
    return;

  itp = ipsec_tun_protect_get (itpi);
  ipsec_tun_protect_rx_db_remove (&ipsec_main, itp);
  ipsec_tun_protect_update_from_teib (itp, ne);
  ipsec_tun_protect_set_crypto_addr (itp);
  ipsec_tun_protect_rx_db_add (&ipsec_main, itp);

  ITP_DBG (itp, "teib-added");
}

static void
ipsec_tun_teib_entry_deleted (const teib_entry_t * ne)
{
  const ip46_address_t *peer46;
  ipsec_tun_protect_t *itp;
  ip_address_t peer;
  index_t itpi;

  peer46 = teib_entry_get_peer (ne);
  ip_address_from_46 (peer46,
		      (ip46_address_is_ip4 (peer46) ?
		       FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6), &peer);

  itpi = ipsec_tun_protect_find (teib_entry_get_sw_if_index (ne), &peer);

  if (INDEX_INVALID == itpi)
    return;

  itp = ipsec_tun_protect_get (itpi);
  ipsec_tun_protect_rx_db_remove (&ipsec_main, itp);
  ipsec_tun_protect_update_from_teib (itp, NULL);
  ipsec_tun_protect_set_crypto_addr (itp);

  ITP_DBG (itp, "teib-removed");
}

/**
 * VFT registered with the adjacency delegate
 */
const static adj_delegate_vft_t ipsec_tun_adj_delegate_vft = {
  .adv_adj_deleted = ipsec_tun_protect_adj_delegate_adj_deleted,
  .adv_adj_created = ipsec_tun_protect_adj_delegate_adj_created,
  .adv_adj_modified = ipsec_tun_protect_adj_delegate_adj_modified,
  .adv_format = ipsec_tun_protect_adj_delegate_format,
};

const static teib_vft_t ipsec_tun_teib_vft = {
  .nv_added = ipsec_tun_teib_entry_added,
  .nv_deleted = ipsec_tun_teib_entry_deleted,
};


clib_error_t *
ipsec_tunnel_protect_init (vlib_main_t * vm)
{
  ipsec_main_t *im;

  im = &ipsec_main;
  im->tun6_protect_by_key = hash_create_mem (0,
					     sizeof (ipsec6_tunnel_key_t),
					     sizeof (u64));
  im->tun4_protect_by_key = hash_create (0, sizeof (u64));

  /* set up feature nodes to drop outbound packets with no crypto alg set */
  im->esp4_no_crypto_tun_node_index =
    vlib_get_node_by_name (vm, (u8 *) "esp4-no-crypto")->index;
  im->esp6_no_crypto_tun_node_index =
    vlib_get_node_by_name (vm, (u8 *) "esp6-no-crypto")->index;
  im->esp6_encrypt_l2_tun_node_index =
    vlib_get_node_by_name (vm, (u8 *) "esp6-encrypt-tun")->index;
  im->esp4_encrypt_l2_tun_node_index =
    vlib_get_node_by_name (vm, (u8 *) "esp4-encrypt-tun")->index;

  ipsec_tun_adj_delegate_type =
    adj_delegate_register_new_type (&ipsec_tun_adj_delegate_vft);

  ipsec_tun_protect_logger = vlib_log_register_class ("ipsec", "tun");

  teib_register (&ipsec_tun_teib_vft);

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
