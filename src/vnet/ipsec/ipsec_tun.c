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
ipsec_tun_t *ipsec_tun_pool;

/**
 * DB of protected tunnels
 */
typedef struct ipsec_tun_db_t_
{
  u32 *tunnels;
  u32 count;
} ipsec_tun_db_t;

static ipsec_tun_db_t ipsec_tun_db;

int
ipsec_tun_protect_update (u32 sw_if_index,
                          u32 sa_in_id,
                          u32 sa_out_id)
{
    u32 sa_in, sa_out, iti;
    ipsec_tun_t *it;

    vec_validate_init_empty(ipsec_tun_db.tunnels, sw_if_index, INDEX_INVALID);
    iti = ipsec_tun_db.tunnels[sw_if_index];

    sa_in = ipsec_get_sa_index_by_sa_id(sa_in_id);
    sa_out = ipsec_get_sa_index_by_sa_id(sa_out_id);

    if (~0 == sa_in || ~0 == sa_out)
      return VNET_API_ERROR_INVALID_VALUE;

    if (INDEX_INVALID == iti)
    {
      vnet_hw_interface_class_t *hw_class;
      vnet_hw_interface_t *hi;
      ipsec_main_t *im;
      vnet_main_t *vnm;
      ipsec_sa_t *sa;
      u64 key;
      int rv;

      im = &ipsec_main;
      vnm = vnet_get_main();
      hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
      hw_class = vnet_get_hw_interface_class (vnm, hi->hw_class_index);

      if (NULL == hw_class->tun_desc)
        return (-1);

      pool_get_zero(ipsec_tun_pool, it);

      it->sw_if_index = sw_if_index;
      ipsec_tun_db.tunnels[sw_if_index] = it - ipsec_tun_pool;
      ipsec_tun_db.count++;
      it->sa[IPSEC_TUN_DIR_INBOUND] = sa_in;
      it->sa[IPSEC_TUN_DIR_OUTBOUND] = sa_out;

      rv = hw_class->tun_desc(sw_if_index, &it->src,
                              &it->dst, &it->decap_node_index);

      if (rv)
        return (-2);

      /*
       * add the arc from the IPSEC input node to the tunnel decap node 
       */
      

      /*
       * enable the encrypt feature for egress.
       */
      vnet_feature_enable_disable("ip4-output",
                                  "esp4-encrypt-tun",
                                  sw_if_index, 1,
                                  it, sizeof(*it));

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
      sa = ipsec_get_sa(sa_in);

      if (sa->is_tunnel)
        {
          key = ((u64) sa->tunnel_dst_addr.ip4.as_u32 << 32 |
                 (u64) sa->spi);
        }
      else
        {
          key = ((u64) it->dst.ip4.as_u32 << 32 |
                 (u64) sa->spi);
        }
      hash_set (im->ipsec_if_pool_index_by_key, key, it - ipsec_tun_pool);

      //if (1 == ipsec_tun_db.count) {
        ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec_tun_protect_node.index);
        //}
    }
    else
    {
        /* update TODO */
      ASSERT(0);
    }

    return (0);
}

static clib_error_t *
ipsec_tun_protect_cmd (vlib_main_t * vm,
                       unformat_input_t * input,
                       vlib_cli_command_t * cmd)
{
  u32 sw_if_index, is_del, sa_in, sa_out;
  vnet_main_t *vnm;

  is_del = 0;
  sw_if_index = ~0;
  vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "del"))
            is_del = 1;
        else if (unformat (input, "add"))
            is_del = 0;
        else if (unformat (input, " input-sa %d", &sa_in))
            ;
        else if (unformat (input, " output-sa %d", &sa_out))
            ;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (!is_del)
      ipsec_tun_protect_update(sw_if_index, sa_in, sa_out);

  return NULL;
}

/**
 * Attach an ABF policy to an interface.
 */
VLIB_CLI_COMMAND (ipsec_tun_protect_cmd_node, static) = {
  .path = "ipsec tunnel protect",
  .function = ipsec_tun_protect_cmd,
  .short_help = "ipsec tunnel protect <interface> input-sa <SA> output-sa <SA>",
  // this is not MP safe
};

clib_error_t *
ipsec_tunnel_protect_init (vlib_main_t * vm)
{
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
