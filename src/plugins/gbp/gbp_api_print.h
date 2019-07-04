/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __GBP_API_PRINT_H__
#define __GBP_API_PRINT_H__

#include <vpp/api/types.h>

/* Macro to finish up custom dump fns */
#define PRINT_S \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);

static inline void *
vl_api_gbp_bridge_domain_add_t_print (vl_api_gbp_bridge_domain_add_t * a,
				      void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_bridge_domain_add ");
  s = format (s, "bd_id %d ", ntohl (a->bd.bd_id));
  s = format (s, "rd_id %d ", ntohl (a->bd.rd_id));
  s = format (s, "flags %d ", ntohl (a->bd.flags));
  s = format (s, "uu-fwd %d ", ntohl (a->bd.uu_fwd_sw_if_index));
  s = format (s, "bvi %d ", ntohl (a->bd.bvi_sw_if_index));
  s = format (s, "bm-flood %d", ntohl (a->bd.bm_flood_sw_if_index));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_bridge_domain_del_t_print (vl_api_gbp_bridge_domain_del_t * a,
				      void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_bridge_domain_del ");
  s = format (s, "bd_id %d ", ntohl (a->bd_id));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_route_domain_add_t_print (vl_api_gbp_route_domain_add_t * a,
				     void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_route_domain_add ");
  s = format (s, "rd_id %d ", ntohl (a->rd.rd_id));
  s = format (s, "ip4_table_id %d ", ntohl (a->rd.ip4_table_id));
  s = format (s, "ip6_table_id %d ", ntohl (a->rd.ip6_table_id));
  s = format (s, "ip4_uu_sw_if_index %d ", ntohl (a->rd.ip4_uu_sw_if_index));
  s = format (s, "ip6_uu_sw_if_index %d", ntohl (a->rd.ip6_uu_sw_if_index));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_route_domain_del_t_print (vl_api_gbp_route_domain_del_t * a,
				     void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_route_domain_del ");
  s = format (s, "rd_id %d", ntohl (a->rd_id));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_endpoint_add_t_print (vl_api_gbp_endpoint_add_t * a, void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_endpoint_add ");
  s = format (s, "sw_if_index %d ", ntohl (a->endpoint.sw_if_index));
  s = format (s, "sclass %d ", ntohs (a->endpoint.sclass));
  s = format (s, "flags %x ", ntohl (a->endpoint.flags));
  s = format (s, "mac %U ", format_vl_api_mac_address, a->endpoint.mac);
  s =
    format (s, "\n\ttun\n\t\t src %U", format_vl_api_address,
	    &a->endpoint.tun.src);
  s =
    format (s, "\n\t\t dst %U ", format_vl_api_address, &a->endpoint.tun.dst);

  if (a->endpoint.n_ips)
    s = format (s, "\n\t ips");
  for (int i = 0; i < a->endpoint.n_ips; i++)
    s = format (s, "\n\t\t %U", format_vl_api_address, &a->endpoint.ips[i]);

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_endpoint_del_t_print (vl_api_gbp_endpoint_del_t * a, void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_endpoint_del ");
  s = format (s, "handle %d", ntohl (a->handle));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_endpoint_group_add_t_print (vl_api_gbp_endpoint_group_add_t * a,
				       void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_endpoint_group_add ");
  s = format (s, "vnid %d ", ntohl (a->epg.vnid));
  s = format (s, "sclass %d ", ntohs (a->epg.sclass));
  s = format (s, "bd_id %d ", ntohl (a->epg.bd_id));
  s = format (s, "rd_id %d ", ntohl (a->epg.rd_id));
  s = format (s, "uplink_sw_if_index %d ", ntohl (a->epg.uplink_sw_if_index));
  s =
    format (s, "remote_ep_timeout %d",
	    ntohl (a->epg.retention.remote_ep_timeout));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_endpoint_group_del_t_print (vl_api_gbp_endpoint_group_del_t * a,
				       void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_endpoint_group_del ");
  s = format (s, "sclass %d ", ntohs (a->sclass));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_recirc_add_del_t_print (vl_api_gbp_recirc_add_del_t * a,
				   void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_recirc_add_del ");

  if (a->is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");
  s = format (s, "sw_if_index %d ", ntohl (a->recirc.sw_if_index));
  s = format (s, "sclass %d ", ntohs (a->recirc.sclass));
  s = format (s, "is_ext %d ", a->recirc.is_ext);

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_subnet_add_del_t_print (vl_api_gbp_subnet_add_del_t * a,
				   void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_subnet_add_del ");
  if (a->is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");
  s = format (s, "rd_id %d ", ntohl (a->subnet.rd_id));
  s = format (s, "sw_if_index %d ", ntohl (a->subnet.sw_if_index));
  s = format (s, "sclass %d ", ntohs (a->subnet.sclass));
  s = format (s, "type %d ", ntohl (a->subnet.type));
  s =
    format (s, "prefix %U/%d", format_vl_api_address,
	    &a->subnet.prefix.address, a->subnet.prefix.len);

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_contract_add_del_t_print (vl_api_gbp_contract_add_del_t * a,
				     void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_contract_add_del ");
  if (a->is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");
  s = format (s, "scope %d ", ntohl (a->contract.scope));
  s = format (s, "sclass %d ", ntohs (a->contract.sclass));
  s = format (s, "dclass %d ", ntohs (a->contract.dclass));
  s = format (s, "acl_index %d \n", ntohl (a->contract.acl_index));
  for (int i = 0; i < a->contract.n_rules; i++)
    {
      s = format (s, "\t action %d\n", ntohl (a->contract.rules[i].action));
      s =
	format (s, "\t hash_mode %d",
		ntohl (a->contract.rules[i].nh_set.hash_mode));
      for (int j = 0; j < a->contract.rules[i].nh_set.n_nhs; j++)
	{
	  s =
	    format (s, "\n\t \t nhs ip %U ", format_vl_api_address,
		    &a->contract.rules[i].nh_set.nhs[j].ip);
	  s =
	    format (s, "nhs mac %U ", format_vl_api_mac_address,
		    a->contract.rules[i].nh_set.nhs[j].mac);
	  s =
	    format (s, "nhs bd_id %d ",
		    ntohl (a->contract.rules[i].nh_set.nhs[j].bd_id));
	  s =
	    format (s, "nhs rd_id %d",
		    ntohl (a->contract.rules[i].nh_set.nhs[j].rd_id));
	}
      s = format (s, "\n");
    }

  if (a->contract.n_ether_types)
    s = format (s, "\tethertypes");
  for (int i = 0; i < a->contract.n_ether_types; i++)
    {
      s = format (s, " %d ", ntohs (a->contract.allowed_ethertypes[i]));
    }

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_vxlan_tunnel_add_t_print (vl_api_gbp_vxlan_tunnel_add_t * a,
				     void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_vxlan_tunnel_add ");

  s = format (s, "vni %d ", ntohl (a->tunnel.vni));
  s = format (s, "mode %d ", ntohl (a->tunnel.mode));
  s = format (s, "bd_rd_id %d ", ntohl (a->tunnel.bd_rd_id));
  s = format (s, "src %U ", format_vl_api_ip4_address, a->tunnel.src);

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_vxlan_tunnel_del_t_print (vl_api_gbp_vxlan_tunnel_del_t * a,
				     void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_vxlan_tunnel_del ");
  s = format (s, "vni %d ", ntohl (a->vni));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

static inline void *
vl_api_gbp_ext_itf_add_del_t_print (vl_api_gbp_ext_itf_add_del_t * a,
				    void *handle)
{
  u8 *s = 0;

  s = format (s, "SCRIPT: gbp_ext_itf_add_del ");
  if (a->is_add)
    s = format (s, "add ");
  else
    s = format (s, "del ");

  s = format (s, "sw_if_index %d ", ntohl (a->ext_itf.sw_if_index));
  s = format (s, "bd_id %d ", ntohl (a->ext_itf.bd_id));
  s = format (s, "rd_id %d ", ntohl (a->ext_itf.rd_id));
  s = format (s, "flags %x ", ntohl (a->ext_itf.flags));

  s = format (s, "\n");

  PRINT_S;

  return handle;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __GBP_API_PRINT_H__ */
