/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <sys/socket.h>
#include <linux/if.h>

#include <lcp_nl.h>
#include <lcp_itf_pair.h>
#include <lcp_router.h>
#include <lcp_log.h>

#include <vc_conn.h>

#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/vlan.h>

#include <vapi/ip.api.vapi.h>
#include <vapi/ip_neighbor.api.vapi.h>
#include <vapi/interface.api.vapi.h>

VC_DECLARE_SYNC_TOKEN;
DEFINE_VAPI_MSG_IDS_IP_API_JSON;
DEFINE_VAPI_MSG_IDS_IP_NEIGHBOR_API_JSON;

#define TMP_BUFF_SIZE 256
static char TMP_BUFF[TMP_BUFF_SIZE];

typedef struct lcp_router_table_t_
{
  uint32_t nlt_id;
  vapi_enum_address_family nlt_af;
  u32 nlt_refs;
} lcp_router_table_t;

static uword *lcp_router_table_db[2];
static lcp_router_table_t *lcp_router_table_pool;

/* *INDENT-OFF* */
const static vapi_type_prefix pfx_all1s =
{
  .address = {
    .af = ADDRESS_IP4,
    .un.ip4 = { 0xff, 0xff, 0xff, 0xff },
  },
  .len = 32,
};
/* *INDENT-ON* */

/* The name of the loopback interface in linux */
/* static const char *loopback_name = "lo"; */

#define LCP_ROUTER_DBG(...)                     \
  LCP_DBG(__VA_ARGS__);
#define LCP_ROUTER_INFO(...)                    \
  LCP_INFO(__VA_ARGS__);
#define LCP_ROUTER_ERROR(...)                   \
  LCP_ERROR(__VA_ARGS__);

/* *INDENT-OFF* */
static const vapi_type_mprefix ip_mfib_specials[] =
{
  /* ALL prefixes are in network order */
  [ADDRESS_IP4] =  {
    /* (*,224.0.0.0)/24 - all local subnet */
    .af = ADDRESS_IP4,
    .grp_address = {
      .ip4 = {0xe0, 0, 0, 0},
    },
    .grp_address_length = 24,
  },
  [ADDRESS_IP6] = {
    /* (*,ff02::)/64 - all local subnet */
    .af = ADDRESS_IP6,
    .grp_address = {
      .ip6 = {0xff, 0x02, 0, 0, 0, 0, 0, 0},
    },
    .grp_address_length = 64,
  },
};
/* *INDENT-OFF* */

static vapi_enum_fib_path_nh_proto proto_v2f[] = {
  [ADDRESS_IP4] = FIB_API_PATH_NH_PROTO_IP4,
  [ADDRESS_IP6] = FIB_API_PATH_NH_PROTO_IP6,
};

static const char*
vapi_type_address_union2str (const vapi_union_address_union *un,
                             vapi_enum_address_family af,
                             char *buf, size_t n)
{
  switch (af)
    {
    case ADDRESS_IP4:
      return (inet_ntop(AF_INET, &un->ip4, buf, n));
    case ADDRESS_IP6:
      return (inet_ntop(AF_INET6, &un->ip6, buf, n));
    }
  return ("oops");
}

static const char*
vapi_type_address2str (const vapi_type_address *addr,
                       char *buf, size_t n)
{
  return (vapi_type_address_union2str (&addr->un, addr->af, buf, n));
}

static const char*
vapi_type_prefix2str (const vapi_type_prefix *pfx,
                      char *buf, size_t n)
{
  return (vapi_type_address2str (&pfx->address, buf, n));
}

lcp_itf_pair_t *
lcp_router_itf_pair_get (u32 host)
{
  index_t lipi;

  lipi = lcp_itf_pair_find_by_vif (host);

  if (INDEX_INVALID == lipi)
    return (NULL);

  return (lcp_itf_pair_get (lipi));
}

static void
lcp_router_link_del (struct rtnl_link *rl)
{
  index_t lipi;

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));

  if (INDEX_INVALID != lipi)
    {
      if (rtnl_link_is_vlan (rl))
	{
	  lcp_itf_pair_t *lip;

	  lip = lcp_itf_pair_get (lipi);

	  LCP_ROUTER_INFO ("delete vlan: %s -> %s (%d)",
			   rtnl_link_get_name (rl),
			   lip->lip_phy_name,
			   lip->lip_phy_sw_if_index);

	  lcp_itf_pair_delete (lip->lip_vif_index);
          vc_itf_sub_delete (lip->lip_phy_sw_if_index);
	}
      else
	LCP_ROUTER_INFO ("ignore non-vlan link del: %s - %s",
			 rtnl_link_get_type (rl), rtnl_link_get_name (rl));
    }
  else
    LCP_ROUTER_INFO ("ignore link del: %s - %s",
		     rtnl_link_get_type (rl), rtnl_link_get_name (rl));
}

static vapi_error_e
lcp_router_mroute_add_del_cb (vapi_ctx_t ctx,
                              void *callback_ctx,
                              vapi_error_e rv,
                              bool is_last,
                              vapi_payload_ip_mroute_add_del_reply *reply)
{
  VC_SYNC_COMPLETE();

  return (VAPI_OK);
}

static vapi_error_e
lcp_router_route_add_del_cb (vapi_ctx_t ctx,
                             void *callback_ctx,
                             vapi_error_e rv,
                             bool is_last,
                             vapi_payload_ip_route_add_del_reply *reply)
{
  VC_SYNC_COMPLETE();

  return (VAPI_OK);
}

static void
lcp_router_special_mroutes_add_del (u32 table_id,
                                    vapi_enum_address_family af,
                                    u32 sw_if_index,
                                    u8 is_add)
{
  vapi_msg_ip_mroute_add_del *msg;

  msg = vapi_alloc_ip_mroute_add_del(vc_conn_ctx(), 1);

  msg->payload.is_multipath = 1;
  msg->payload.is_add = is_add;

  msg->payload.route.table_id = table_id;
  msg->payload.route.entry_flags = 0;
  msg->payload.route.rpf_id = ~0;
  msg->payload.route.n_paths = 1;

  memcpy(&msg->payload.route.prefix,
         &ip_mfib_specials[af],
         sizeof(msg->payload.route.prefix));

  memset(&msg->payload.route.paths[0], 0,
         sizeof(msg->payload.route.paths[0]));
  msg->payload.route.paths[0].itf_flags = MFIB_API_ITF_FLAG_ACCEPT;
  msg->payload.route.paths[0].path.sw_if_index = sw_if_index;
  msg->payload.route.paths[0].path.weight = 1;
  msg->payload.route.paths[0].path.proto = proto_v2f[af];
  msg->payload.route.paths[0].path.type = FIB_API_PATH_TYPE_NORMAL;

  VC_SYNC_START();

  if (VAPI_OK == vapi_ip_mroute_add_del(vc_conn_ctx(),
                                        msg,
                                        lcp_router_mroute_add_del_cb,
                                        NULL))
    VC_SYNC_WAIT(vc_conn_ctx());
}

static void
lcp_router_link_add (struct rtnl_link *rl)
{
  index_t lipi;
  int up;

  lipi = lcp_itf_pair_find_by_vif (rtnl_link_get_ifindex (rl));
  up = IFF_UP & rtnl_link_get_flags (rl);

  if (INDEX_INVALID != lipi)
    {
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);

      if (up)
        vc_itf_set_admin_state (lip->lip_phy_sw_if_index,
                                IF_STATUS_API_FLAG_ADMIN_UP);
      else
        vc_itf_set_admin_state (lip->lip_phy_sw_if_index, 0);

      LCP_ROUTER_INFO ("link: %s (%d) -> %s/%s %s",
                       rtnl_link_get_name (rl),
                       rtnl_link_get_ifindex (rl),
                       lip->lip_phy_name,
                       lip->lip_host_name,
                       (up ? "up" : "down"));
    }
  else if (rtnl_link_is_vlan (rl))
    {
      const lcp_itf_pair_t *parent_lip;
      int parent, vlan;
      //u8 *ns = 0;		/* FIXME */

      parent = rtnl_link_get_link (rl);
      vlan = rtnl_link_vlan_get_id (rl);
      parent_lip = lcp_router_itf_pair_get (parent);

      LCP_ROUTER_INFO ("create vlan: %s",
                       rtnl_link_get_name (rl));

      if (NULL != parent_lip)
	{
	  u32 sub_sw_if_index;

	  /* create the vlan interface on the parent */
	  sub_sw_if_index = vc_itf_sub_create (parent_lip->lip_phy_sw_if_index,
                                               vlan);

          if (~0 == sub_sw_if_index)
	    {
	      LCP_ROUTER_INFO ("failed create vlan: %d on %s",
			       vlan, rtnl_link_get_name (rl));
	    }
	  else
	    {
	      LCP_ROUTER_INFO ("create vlan: %s -> (%s, %s)",
			       rtnl_link_get_name (rl),
                               parent_lip->lip_phy_name,
                               vc_itf_get_name(sub_sw_if_index));

              lcp_itf_pair_create (vc_itf_get_name(sub_sw_if_index),
                                   NULL, NULL);

              if (up)
                vc_itf_set_admin_state (sub_sw_if_index,
                                        IF_STATUS_API_FLAG_ADMIN_UP);
	    }
	}
    }
  /* else if (!strcmp (loopback_name, rtnl_link_get_name (rl))) */
  /*   { */
  /*     u32 phy_sw_if_index; */
  /*     u8 mac[6] = { }; */
  /*     u8 *ns = 0;		/\* FIXME *\/ */

  /*     LCP_ROUTER_INFO ("loopback add: %s", rtnl_link_get_name (rl)); */

  /*     vnet_create_loopback_interface (&phy_sw_if_index, mac, 0, 0); */
  /*     if (up) */
  /*       vnet_sw_interface_admin_up (vnet_get_main (), phy_sw_if_index); */

  /*     lcp_itf_pair_add (~0, phy_sw_if_index, */
  /*       		format (NULL, "%s", rtnl_link_get_name (rl)), */
  /*       		rtnl_link_get_ifindex (rl), ns); */
  /*   } */
  else
    LCP_ROUTER_INFO ("ignore link add: %s - %s",
		     rtnl_link_get_type (rl), rtnl_link_get_name (rl));
}

static vapi_enum_address_family
lcp_router_proto_h2v (uint32_t k)
{
  if (AF_INET6 == k)
    return (ADDRESS_IP6);
  return (ADDRESS_IP4);
}

static void
lcp_router_mk_addr6 (const struct nl_addr *rna,
                    vapi_type_ip6_address * ia)
{
  memcpy (ia, nl_addr_get_binary_addr (rna), nl_addr_get_len (rna));
}

static void
lcp_router_mk_addr4 (const struct nl_addr *rna,
                    vapi_type_ip4_address * ia)
{
  memcpy (ia, nl_addr_get_binary_addr (rna), nl_addr_get_len (rna));
}

static void
lcp_router_mk_addr_union (const struct nl_addr *rna,
                          vapi_enum_address_family af,
                          vapi_union_address_union * ia)
{
  if (ADDRESS_IP4 == af)
    lcp_router_mk_addr4 (rna, &ia->ip4);
  else
    lcp_router_mk_addr6 (rna, &ia->ip6);
}

static void
lcp_router_mk_addr (const struct nl_addr *rna,
                    vapi_type_address * ia)
{
  memset(ia, 0, sizeof(*ia));
  ia->af = lcp_router_proto_h2v (nl_addr_get_family (rna));

  lcp_router_mk_addr_union (rna, ia->af, &ia->un);
}

static void
lcp_router_mk_prefix (const struct nl_addr *rna,
                      u8 len,
                      vapi_type_prefix * p)
{
  p->len = len;
  lcp_router_mk_addr (rna, &p->address);
}

static vapi_error_e
lcp_router_link_addr_add_del_cb (vapi_ctx_t ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_sw_interface_add_del_address_reply *reply)
{
  VC_SYNC_COMPLETE();

  return (VAPI_OK);
}

static void
lcp_router_link_addr_add_del (struct rtnl_addr *rla, int is_add)
{
  lcp_itf_pair_t *lip;

  lip = lcp_router_itf_pair_get (rtnl_addr_get_ifindex (rla));

  if (NULL != lip)
    {
      vapi_msg_sw_interface_add_del_address *msg;

      msg = vapi_alloc_sw_interface_add_del_address (vc_conn_ctx ());

      lcp_router_mk_prefix (rtnl_addr_get_local (rla),
                            rtnl_addr_get_prefixlen (rla),
                            &msg->payload.prefix);

      if (RT_SCOPE_LINK == rtnl_addr_get_scope(rla))
        msg->payload.prefix.len = 128;

      VC_SYNC_START();

      msg->payload.is_add = is_add;
      msg->payload.sw_if_index = lip->lip_phy_sw_if_index;

      if (VAPI_OK == vapi_sw_interface_add_del_address (vc_conn_ctx (),
                                                        msg,
                                                        lcp_router_link_addr_add_del_cb,
                                                        NULL))
        VC_SYNC_WAIT(vc_conn_ctx());

      lcp_router_special_mroutes_add_del (0, msg->payload.prefix.address.af,
                                          lip->lip_phy_sw_if_index, is_add);

      LCP_ROUTER_INFO ("link-addr: %s(%s) %s",
                       lip->lip_phy_name,
                       lip->lip_host_name,
                       nl_addr2str(rtnl_addr_get_local (rla),
                                   TMP_BUFF,
                                   TMP_BUFF_SIZE));
    }
  else
    LCP_INFO ("link-addr: ignore: %s",
              rtnl_link_get_name (rtnl_addr_get_link(rla)));
}

static void
lcp_router_link_addr_del (struct rtnl_addr *la)
{
  lcp_router_link_addr_add_del (la, 0);
}

static void
lcp_router_link_addr_add (struct rtnl_addr *la)
{
  lcp_router_link_addr_add_del (la, 1);
}

static void
lcp_router_mk_mac_addr (const struct nl_addr *rna,
                        vapi_type_mac_address * mac)
{
  memcpy (mac, nl_addr_get_binary_addr (rna), 6);
}

static vapi_error_e
lcp_router_neigh_del_add_cb (vapi_ctx_t ctx,
                             void *callback_ctx,
                             vapi_error_e rv,
                             bool is_last,
                             vapi_payload_ip_neighbor_add_del_reply *reply)
{
  VC_SYNC_COMPLETE();

  return (VAPI_OK);
}

static void
lcp_router_neigh_del (struct rtnl_neigh *rn)
{
  lcp_itf_pair_t *lip;

  lip = lcp_router_itf_pair_get (rtnl_neigh_get_ifindex (rn));

  if (NULL != lip)
    {
      vapi_msg_ip_neighbor_add_del *msg;

      msg = vapi_alloc_ip_neighbor_add_del (vc_conn_ctx ());

      lcp_router_mk_addr (rtnl_neigh_get_dst (rn),
                          &msg->payload.neighbor.ip_address);

      msg->payload.is_add = 0;
      msg->payload.neighbor.sw_if_index = lip->lip_phy_sw_if_index;

      VC_SYNC_START();

      LCP_ROUTER_DBG ("neighbor del: %s %s/%s",
                      vapi_type_address2str(&msg->payload.neighbor.ip_address,
                                            TMP_BUFF, TMP_BUFF_SIZE),
                      lip->lip_phy_name,
                      lip->lip_host_name);

      if (VAPI_OK == vapi_ip_neighbor_add_del (vc_conn_ctx (),
                                               msg,
                                               lcp_router_neigh_del_add_cb,
                                               NULL))
        VC_SYNC_WAIT(vc_conn_ctx());
    }
  else
    LCP_ROUTER_INFO ("ignore neighbour del on: %d",
		     rtnl_neigh_get_ifindex (rn));
}

static void
lcp_router_neigh_add (struct rtnl_neigh *rn)
{
  lcp_itf_pair_t *lip;

  lip = lcp_router_itf_pair_get (rtnl_neigh_get_ifindex (rn));

  if (NULL != lip)
    {
      vapi_msg_ip_neighbor_add_del *msg;
      struct nl_addr *ll;

      msg = vapi_alloc_ip_neighbor_add_del (vc_conn_ctx ());

      lcp_router_mk_addr (rtnl_neigh_get_dst (rn),
                          &msg->payload.neighbor.ip_address);

      msg->payload.is_add = 1;
      msg->payload.neighbor.sw_if_index = lip->lip_phy_sw_if_index;

      ll = rtnl_neigh_get_lladdr (rn);

      if (ll)
	{
	  lcp_router_mk_mac_addr (ll, &msg->payload.neighbor.mac_address);

          VC_SYNC_START();

          LCP_ROUTER_DBG ("neighbor add: %s %s/%s",
                          vapi_type_address2str(&msg->payload.neighbor.ip_address,
                                                TMP_BUFF, TMP_BUFF_SIZE),
                          lip->lip_phy_name,
                          lip->lip_host_name);

          if (VAPI_OK == vapi_ip_neighbor_add_del (vc_conn_ctx (),
                                                   msg,
                                                   lcp_router_neigh_del_add_cb,
                                                   NULL))
            VC_SYNC_WAIT(vc_conn_ctx());
        }
    }
  else
    LCP_ROUTER_INFO ("ignore neighbour add on: %d",
		     rtnl_neigh_get_ifindex (rn));
}

static lcp_router_table_t *
lcp_router_table_find (uint32_t id, vapi_enum_address_family af)
{
  uword *p;

  p = hash_get (lcp_router_table_db[af], id);

  if (p)
    return pool_elt_at_index (lcp_router_table_pool, p[0]);

  return (NULL);
}

static uint32_t
lcp_router_table_k2v (uint32_t k)
{
  // the kernel's table ID 255 is the default table
  if (k == 255 || k == 254)
    return 0;
  return k;
}

static vapi_error_e
lcp_router_table_add_del_cb (vapi_ctx_t ctx,
                             void *callback_ctx,
                             vapi_error_e rv,
                             bool is_last,
                             vapi_payload_ip_table_add_del_reply *reply)
{
  VC_SYNC_COMPLETE();

  return (rv);
}

static vapi_error_e
lcp_router_table_flush_cb (vapi_ctx_t ctx,
                             void *callback_ctx,
                             vapi_error_e rv,
                             bool is_last,
                             vapi_payload_ip_table_flush_reply *reply)
{
  VC_SYNC_COMPLETE();

  return (rv);
}

static lcp_router_table_t *
lcp_router_table_add_or_lock (uint32_t id,
                              vapi_enum_address_family af)
{
  lcp_router_table_t *nlt;

  id = lcp_router_table_k2v (id);
  nlt = lcp_router_table_find (id, af);

  if (NULL == nlt)
    {
      vapi_msg_ip_table_add_del*msg;

      pool_get_zero (lcp_router_table_pool, nlt);

      nlt->nlt_id = id;
      nlt->nlt_af = af;

      hash_set (lcp_router_table_db[af], nlt->nlt_id,
		nlt - lcp_router_table_pool);

      msg = vapi_alloc_ip_table_add_del(vc_conn_ctx());

      msg->payload.is_add = 1;
      msg->payload.table.table_id = id;
      msg->payload.table.is_ip6 = (af == ADDRESS_IP6);
      snprintf((char*)msg->payload.table.name,
               ARRAY_LEN(msg->payload.table.name),
               "lcp-%d", id);

      VC_SYNC_START();

      if (VAPI_OK == vapi_ip_table_add_del(vc_conn_ctx(), msg,
                                           lcp_router_table_add_del_cb,
                                           NULL))
        VC_SYNC_WAIT(vc_conn_ctx());

      if (af == ADDRESS_IP4)
	{
	  /* Set the all 1s address in this table to punt */
          {
            vapi_msg_ip_route_add_del *msg;

            msg = vapi_alloc_ip_route_add_del(vc_conn_ctx(), 1);

            msg->payload.is_multipath = 1;
            msg->payload.is_add = 1;

            msg->payload.route.table_id = id;
            msg->payload.route.n_paths = 1;

            memcpy(&msg->payload.route.prefix,
                   &pfx_all1s,
                   sizeof(msg->payload.route.prefix));

            memset(&msg->payload.route.paths[0], 0,
                   sizeof(msg->payload.route.paths[0]));
            msg->payload.route.paths[0].sw_if_index = ~0;
            msg->payload.route.paths[0].weight = 1;
            msg->payload.route.paths[0].proto = proto_v2f[af];
            msg->payload.route.paths[0].type = FIB_API_PATH_TYPE_LOCAL;

            VC_SYNC_START();

            if (VAPI_OK == vapi_ip_route_add_del(vc_conn_ctx(),
                                                 msg,
                                                 lcp_router_route_add_del_cb,
                                                 NULL))
              VC_SYNC_WAIT(vc_conn_ctx());
          }
          {
            vapi_msg_ip_mroute_add_del *msg;

            msg = vapi_alloc_ip_mroute_add_del(vc_conn_ctx(), 1);

            msg->payload.is_multipath = 0;
            msg->payload.is_add = 1;

            msg->payload.route.table_id = id;
            msg->payload.route.entry_flags = 0;
            msg->payload.route.rpf_id = ~0;
            msg->payload.route.n_paths = 1;

            memcpy(&msg->payload.route.prefix,
                   &ip_mfib_specials[af],
                   sizeof(msg->payload.route.prefix));

            memset(&msg->payload.route.paths[0], 0,
                   sizeof(msg->payload.route.paths[0]));
            msg->payload.route.paths[0].itf_flags = MFIB_API_ITF_FLAG_FORWARD;
            msg->payload.route.paths[0].path.sw_if_index = ~0;
            msg->payload.route.paths[0].path.weight = 1;
            msg->payload.route.paths[0].path.proto = proto_v2f[af];
            msg->payload.route.paths[0].path.type = FIB_API_PATH_TYPE_LOCAL;

            VC_SYNC_START();

            if (VAPI_OK == vapi_ip_mroute_add_del(vc_conn_ctx(),
                                                  msg,
                                                  lcp_router_mroute_add_del_cb,
                                                  NULL))
              VC_SYNC_WAIT(vc_conn_ctx());
          }
        }
    }

  nlt->nlt_refs++;

  return (nlt);
}

static void
lcp_router_table_unlock (lcp_router_table_t * nlt)
{
  nlt->nlt_refs--;

  if (0 == nlt->nlt_refs)
    {
      {
        vapi_msg_ip_table_flush *msg;

        msg = vapi_alloc_ip_table_flush(vc_conn_ctx());

        msg->payload.table.table_id = nlt->nlt_id;
        msg->payload.table.is_ip6 = (nlt->nlt_af == ADDRESS_IP6);

        VC_SYNC_START();

        if (VAPI_OK == vapi_ip_table_flush(vc_conn_ctx(), msg,
                                           lcp_router_table_flush_cb,
                                           NULL))
          VC_SYNC_WAIT(vc_conn_ctx());
      }
      {
        vapi_msg_ip_table_add_del *msg;

        msg = vapi_alloc_ip_table_add_del(vc_conn_ctx());

        msg->payload.is_add = 0;
        msg->payload.table.table_id = nlt->nlt_id;
        msg->payload.table.is_ip6 = (nlt->nlt_af == ADDRESS_IP6);

        VC_SYNC_START();

        if (VAPI_OK == vapi_ip_table_add_del(vc_conn_ctx(), msg,
                                           lcp_router_table_add_del_cb,
                                           NULL))
          VC_SYNC_WAIT(vc_conn_ctx());
      }

      hash_unset (lcp_router_table_db[nlt->nlt_af], nlt->nlt_id);
      pool_put (lcp_router_table_pool, nlt);
    }
}

/* static void */
/* lcp_router_route_mk_mprefix (struct rtnl_route *r, */
/*                              vapi_type_mprefix * p) */
/* { */
/*   const struct nl_addr *addr; */

/*   addr = rtnl_route_get_dst (r); */

/*   p->af = lcp_router_proto_h2v (nl_addr_get_family (addr)); */
/*   p->grp_address_length = nl_addr_get_prefixlen (addr); */

/*   if (ADDRESS_IP4 == p->af) */
/*     lcp_router_mk_addr4 (addr, &p->grp_address.ip4); */
/*   else */
/*     lcp_router_mk_addr6 (addr, &p->grp_address.ip6); */

/*   addr = rtnl_route_get_src (r); */
/*   if (addr) */
/*     { */
/*       if (ADDRESS_IP4 == p->af) */
/*         lcp_router_mk_addr4 (addr, &p->src_address.ip4); */
/*       else */
/*         lcp_router_mk_addr6 (addr, &p->src_address.ip6); */
/*     } */
/* } */

typedef struct lcp_router_fib_path_parse_t_
{
  vapi_type_fib_path *paths;
  vapi_enum_address_family route_proto;
  bool is_mcast;
} lcp_router_fib_path_parse_t;

static void
lcp_router_route_path_parse (struct rtnl_nexthop *rnh, void *arg)
{
  lcp_router_fib_path_parse_t *ctx = arg;
  vapi_type_fib_path *path;
  index_t lipi;

  lipi = lcp_itf_pair_find_by_vif (rtnl_route_nh_get_ifindex (rnh));

  if (INDEX_INVALID != lipi)
    {
      struct nl_addr *addr;
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);

      vec_add2 (ctx->paths, path, 1);

      path->flags = FIB_API_PATH_FLAG_NONE;
      path->sw_if_index = lip->lip_phy_sw_if_index;
      path->weight = rtnl_route_nh_get_weight (rnh);

      addr = rtnl_route_nh_get_gateway (rnh);

      if (addr) {
        path->proto = lcp_router_proto_h2v (nl_addr_get_family (addr));
	lcp_router_mk_addr_union (rtnl_route_nh_get_gateway (rnh),
                                  path->proto,
                                  &path->nh.address);
      }
      else
        path->proto = ctx->route_proto;

      /* if (ctx->is_mcast) */
      /*   path->frp_mitf_flags = MFIB_ITF_FLAG_FORWARD; */

      LCP_ROUTER_DBG (" path:[%s, %s]", lip->lip_phy_name,
                      vapi_type_address_union2str(&path->nh.address,
                                                  path->proto,
                                                  TMP_BUFF,
                                                  TMP_BUFF_SIZE));
    }
}

static bool
rtnl_route_is_mcast (struct rtnl_route *rr)
{
  struct nl_addr *na;

  na = rtnl_route_get_dst(rr);

  if (AF_INET6 == nl_addr_get_family (na))
    {
      u8 *addr = nl_addr_get_binary_addr (na);
      if (0xff == addr[0])
        return (true);
    }

  return (rtnl_route_get_type (rr) == RTN_MULTICAST);
}

static bool
rtnl_route_is_link_local (struct rtnl_route *rr)
{
  struct nl_addr *na;

  na = rtnl_route_get_dst(rr);

  if (AF_INET6 == nl_addr_get_family (na))
    {
      u8 *addr = nl_addr_get_binary_addr (na);
      if (0xfe == addr[0])
        return (true);
    }

  return (false);
}

static void
lcp_router_route_del (struct rtnl_route *rr)
{
  lcp_router_table_t *nlt;
  vapi_type_prefix pfx;
  uint32_t table_id;
  bool is_mcast;

  is_mcast = rtnl_route_is_mcast(rr);
  lcp_router_mk_prefix (rtnl_route_get_dst(rr),
                        nl_addr_get_prefixlen(rtnl_route_get_dst(rr)),
                        &pfx);
  table_id = rtnl_route_get_table (rr);
  nlt = lcp_router_table_find (lcp_router_table_k2v (table_id),
                               pfx.address.af);

  if (NULL == nlt)
    return;

  /* link local IPv6 */
  if (rtnl_route_is_link_local(rr) ||
      RTN_LOCAL & rtnl_route_get_type (rr))
    {
      LCP_ROUTER_DBG ("route del-skip: %d:%s",
                      table_id,
                      vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));
    }
  else
    {
      lcp_router_fib_path_parse_t np = {
	.route_proto = pfx.address.af,
	.is_mcast = is_mcast,
      };

      rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);

      if (0 != vec_len (np.paths))
	{
	  if (is_mcast)
	    {
              LCP_ROUTER_DBG ("mroute del: %d:%s",
                              table_id,
                              vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));

	      /* it's not clear to me how linux expresses the RPF paramters
	       * so we'll allow from all interfaces and hope for the best */
	      /* mfib_prefix_t mpfx = { }; */

	      /* lcp_router_route_mk_mprefix (rr, &mpfx); */

	      /* mfib_table_entry_update (nlt->nlt_mfib_index, */
	      /*   		       &mpfx, */
	      /*   		       MFIB_SOURCE_PLUGIN_LOW, */
	      /*   		       MFIB_RPF_ID_NONE, */
	      /*   		       MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF); */

	      /* mfib_table_entry_paths_update (nlt->nlt_mfib_index, */
	      /*   			     &mpfx, */
	      /*   			     MFIB_SOURCE_PLUGIN_LOW, */
	      /*   			     np.paths); */
	    }
	  else
            {
              LCP_ROUTER_DBG ("route del: %d:%s",
                              table_id,
                              vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));

              vapi_msg_ip_route_add_del *msg;

              msg = vapi_alloc_ip_route_add_del(vc_conn_ctx(), vec_len(np.paths));

              msg->payload.is_multipath = 1;
              msg->payload.is_add = 0;

              msg->payload.route.table_id = nlt->nlt_id;
              msg->payload.route.n_paths = vec_len(np.paths);

              memcpy(&msg->payload.route.prefix,
                     &pfx,
                     sizeof(msg->payload.route.prefix));
              memcpy(msg->payload.route.paths,
                     np.paths,
                     sizeof(np.paths[0]) * vec_len(np.paths));

              VC_SYNC_START();

              if (VAPI_OK == vapi_ip_route_add_del(vc_conn_ctx(),
                                                   msg,
                                                   lcp_router_route_add_del_cb,
                                                   NULL))
                VC_SYNC_WAIT(vc_conn_ctx());
            }
	}
      else
      LCP_ROUTER_DBG ("route add - no-paths: %d:%s",
                      table_id,
                      vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));
      vec_free (np.paths);
    }

  lcp_router_table_unlock (nlt);
}

static void
lcp_router_route_add (struct rtnl_route *rr)
{
  lcp_router_table_t *nlt;
  vapi_type_prefix pfx;
  uint32_t table_id;
  bool is_mcast;

  is_mcast = rtnl_route_is_mcast(rr);
  lcp_router_mk_prefix (rtnl_route_get_dst(rr),
                        nl_addr_get_prefixlen(rtnl_route_get_dst(rr)),
                        &pfx);
  table_id = rtnl_route_get_table (rr);
  nlt = lcp_router_table_add_or_lock (lcp_router_table_k2v (table_id),
                                      pfx.address.af);

  /* link local IPv6 */
  if (rtnl_route_is_link_local(rr) ||
      RTN_LOCAL & rtnl_route_get_type (rr))
    {
      LCP_ROUTER_DBG ("route skip: %d:%s",
                      table_id,
                      vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));
    }
  else
    {
      lcp_router_fib_path_parse_t np = {
	.route_proto = pfx.address.af,
	.is_mcast = is_mcast,
      };

      rtnl_route_foreach_nexthop (rr, lcp_router_route_path_parse, &np);

      if (0 != vec_len (np.paths))
	{
	  if (is_mcast)
	    {
              LCP_ROUTER_DBG ("mroute add: %d:%s",
                              table_id,
                              vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));

	      /* it's not clear to me how linux expresses the RPF paramters
	       * so we'll allow from all interfaces and hope for the best */
	      /* mfib_prefix_t mpfx = { }; */

	      /* lcp_router_route_mk_mprefix (rr, &mpfx); */

	      /* mfib_table_entry_update (nlt->nlt_mfib_index, */
	      /*   		       &mpfx, */
	      /*   		       MFIB_SOURCE_PLUGIN_LOW, */
	      /*   		       MFIB_RPF_ID_NONE, */
	      /*   		       MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF); */

	      /* mfib_table_entry_paths_update (nlt->nlt_mfib_index, */
	      /*   			     &mpfx, */
	      /*   			     MFIB_SOURCE_PLUGIN_LOW, */
	      /*   			     np.paths); */
	    }
	  else
            {
              LCP_ROUTER_DBG ("route add: %d:%s",
                              table_id,
                              vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));

              vapi_msg_ip_route_add_del *msg;

              msg = vapi_alloc_ip_route_add_del(vc_conn_ctx(), vec_len(np.paths));

              msg->payload.is_multipath = 0;
              msg->payload.is_add = 1;

              msg->payload.route.table_id = nlt->nlt_id;
              msg->payload.route.n_paths = vec_len(np.paths);

              memcpy(&msg->payload.route.prefix,
                     &pfx,
                     sizeof(msg->payload.route.prefix));
              memcpy(msg->payload.route.paths,
                     np.paths,
                     sizeof(np.paths[0]) * vec_len(np.paths));

              VC_SYNC_START();

              if (VAPI_OK == vapi_ip_route_add_del(vc_conn_ctx(),
                                                   msg,
                                                   lcp_router_route_add_del_cb,
                                                   NULL))
                VC_SYNC_WAIT(vc_conn_ctx());
            }
	}
      else
      LCP_ROUTER_DBG ("route add - no-paths: %d:%s",
                      table_id,
                      vapi_type_prefix2str(&pfx, TMP_BUFF, TMP_BUFF_SIZE));
      vec_free (np.paths);
    }
}

const nl_vft_t lcp_router_vft = {
  .nvl_rt_link_add = lcp_router_link_add,
  .nvl_rt_link_del = lcp_router_link_del,
  .nvl_rt_addr_add = lcp_router_link_addr_add,
  .nvl_rt_addr_del = lcp_router_link_addr_del,
  .nvl_rt_neigh_add = lcp_router_neigh_add,
  .nvl_rt_neigh_del = lcp_router_neigh_del,
  .nvl_rt_route_add = lcp_router_route_add,
  .nvl_rt_route_del = lcp_router_route_del,
};

void
lcp_router_init (void)
{
  lcp_nl_register_vft (&lcp_router_vft);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
