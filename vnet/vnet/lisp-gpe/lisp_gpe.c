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

#include <vnet/lisp-gpe/lisp_gpe.h>

lisp_gpe_main_t lisp_gpe_main;

static int
lisp_gpe_rewrite (lisp_gpe_tunnel_t * t)
{
  u8 *rw = 0;
  lisp_gpe_header_t * lisp0;
  int len;

  if (ip_addr_version(&t->src) == IP4)
    {
      ip4_header_t * ip0;
      ip4_udp_lisp_gpe_header_t * h0;
      len = sizeof(*h0);

      vec_validate_aligned(rw, len - 1, CLIB_CACHE_LINE_BYTES);

      h0 = (ip4_udp_lisp_gpe_header_t *) rw;

      /* Fixed portion of the (outer) ip4 header */
      ip0 = &h0->ip4;
      ip0->ip_version_and_header_length = 0x45;
      ip0->ttl = 254;
      ip0->protocol = IP_PROTOCOL_UDP;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip_address_copy_addr(&ip0->src_address, &t->src);
      ip_address_copy_addr(&ip0->dst_address, &t->dst);
      ip0->checksum = ip4_header_checksum (ip0);

      /* UDP header, randomize src port on something, maybe? */
      h0->udp.src_port = clib_host_to_net_u16 (4341);
      h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

      /* LISP-gpe header */
      lisp0 = &h0->lisp;
    }
  else
    {
      ip6_header_t * ip0;
      ip6_udp_lisp_gpe_header_t * h0;
      len = sizeof(*h0);

      vec_validate_aligned(rw, len - 1, CLIB_CACHE_LINE_BYTES);

      h0 = (ip6_udp_lisp_gpe_header_t *) rw;

      /* Fixed portion of the (outer) ip6 header */
      ip0 = &h0->ip6;
      ip0->ip_version_traffic_class_and_flow_label =
          clib_host_to_net_u32 (0x6 << 28);
      ip0->hop_limit = 254;
      ip0->protocol = IP_PROTOCOL_UDP;

      /* we fix up the ip6 header length after-the-fact */
      ip_address_copy_addr(&ip0->src_address, &t->src);
      ip_address_copy_addr(&ip0->dst_address, &t->dst);

      /* UDP header, randomize src port on something, maybe? */
      h0->udp.src_port = clib_host_to_net_u16 (4341);
      h0->udp.dst_port = clib_host_to_net_u16 (UDP_DST_PORT_lisp_gpe);

      /* LISP-gpe header */
      lisp0 = &h0->lisp;
    }

  lisp0->flags = t->flags;
  lisp0->ver_res = t->ver_res;
  lisp0->res = t->res;
  lisp0->next_protocol = t->next_protocol;
  lisp0->iid = clib_host_to_net_u32 (t->vni);

  t->rewrite = rw;
  return 0;
}

#define foreach_copy_field                      \
_(encap_fib_index)                              \
_(decap_fib_index)                              \
_(decap_next_index)                             \
_(vni)

static u32
add_del_ip_tunnel (vnet_lisp_gpe_add_del_fwd_entry_args_t *a,
                   u32 * tun_index_res)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  lisp_gpe_tunnel_t *t = 0;
  uword * p;
  int rv;
  lisp_gpe_tunnel_key_t key;

  /* prepare tunnel key */
  memset(&key, 0, sizeof(key));
  ip_prefix_copy(&key.eid, &gid_address_ippref(&a->deid));
  ip_address_copy(&key.dst_loc, &a->dlocator);
  key.iid = clib_host_to_net_u32 (a->vni);

  p = mhash_get (&lgm->lisp_gpe_tunnel_by_key, &key);

  if (a->is_add)
    {
      /* adding a tunnel: tunnel must not already exist */
      if (p)
        return VNET_API_ERROR_INVALID_VALUE;

      if (a->decap_next_index >= LISP_GPE_INPUT_N_NEXT)
        return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (lgm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      ip_address_copy(&t->src, &a->slocator);
      ip_address_copy(&t->dst, &a->dlocator);

      t->flags |= LISP_GPE_FLAGS_P;
      t->next_protocol = ip_prefix_version(&key.eid) == IP4 ?
          LISP_GPE_NEXT_PROTO_IP4 : LISP_GPE_NEXT_PROTO_IP6;

      rv = lisp_gpe_rewrite (t);

      if (rv)
        {
          pool_put(lgm->tunnels, t);
          return rv;
        }

      mhash_set(&lgm->lisp_gpe_tunnel_by_key, &key, t - lgm->tunnels, 0);

      /* return tunnel index */
      if (tun_index_res)
        tun_index_res[0] = t - lgm->tunnels;
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p)
        {
          clib_warning("Tunnel for eid %U doesn't exist!", format_gid_address,
                       &a->deid);
          return VNET_API_ERROR_NO_SUCH_ENTRY;
        }

      t = pool_elt_at_index(lgm->tunnels, p[0]);

      mhash_unset(&lgm->lisp_gpe_tunnel_by_key, &key, 0);

      vec_free(t->rewrite);
      pool_put(lgm->tunnels, t);
    }

  return 0;
}

static int
add_del_negative_fwd_entry (lisp_gpe_main_t * lgm,
                            vnet_lisp_gpe_add_del_fwd_entry_args_t * a)
{
  ip_adjacency_t adj;
  /* setup adjacency for eid */
  memset (&adj, 0, sizeof(adj));
  adj.n_adj = 1;
  adj.explicit_fib_index = ~0;

  ip_prefix_t * dpref = &gid_address_ippref(&a->deid);
  ip_prefix_t * spref = &gid_address_ippref(&a->seid);

  switch (a->action)
    {
    case NO_ACTION:
      /* TODO update timers? */
    case FORWARD_NATIVE:
      /* TODO check if route/next-hop for eid exists in fib and add
       * more specific for the eid with the next-hop found */
    case SEND_MAP_REQUEST:
      /* insert tunnel that always sends map-request */
      adj.rewrite_header.sw_if_index = ~0;
      adj.lookup_next_index = (u32) (ip_prefix_version(dpref) == IP4) ?
                                     LGPE_IP4_LOOKUP_NEXT_LISP_CP_LOOKUP:
                                     LGPE_IP6_LOOKUP_NEXT_LISP_CP_LOOKUP;
      /* add/delete route for prefix */
      return ip_sd_fib_add_del_route (lgm, dpref, spref, a->table_id, &adj,
                                      a->is_add);
    case DROP:
      /* for drop fwd entries, just add route, no need to add encap tunnel */
      adj.lookup_next_index =  (u32) (ip_prefix_version(dpref) == IP4 ?
              LGPE_IP4_LOOKUP_NEXT_DROP : LGPE_IP6_LOOKUP_NEXT_DROP);

      /* add/delete route for prefix */
      return ip_sd_fib_add_del_route (lgm, dpref, spref, a->table_id, &adj,
                                      a->is_add);
    default:
      return -1;
    }
}

int
vnet_lisp_gpe_add_del_fwd_entry (vnet_lisp_gpe_add_del_fwd_entry_args_t * a,
                                 u32 * hw_if_indexp)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  ip_adjacency_t adj, * adjp;
  u32 adj_index, rv, tun_index = ~0;
  ip_prefix_t * dpref, * spref;
  uword * lookup_next_index, * lgpe_sw_if_index, * lnip;
  u8 ip_ver;

  if (vnet_lisp_gpe_enable_disable_status() == 0)
    {
      clib_warning ("LISP is disabled!");
      return VNET_API_ERROR_LISP_DISABLE;
    }

  /* treat negative fwd entries separately */
  if (a->is_negative)
    return add_del_negative_fwd_entry (lgm, a);

  dpref = &gid_address_ippref(&a->deid);
  spref = &gid_address_ippref(&a->seid);
  ip_ver = ip_prefix_version(dpref);

  /* add/del tunnel to tunnels pool and prepares rewrite */
  rv = add_del_ip_tunnel (a, &tun_index);
  if (rv)
    return rv;

  /* setup adjacency for eid */
  memset (&adj, 0, sizeof(adj));
  adj.n_adj = 1;
  adj.explicit_fib_index = ~0;

  if (a->is_add)
    {
      /* send packets that hit this adj to lisp-gpe interface output node in
       * requested vrf. */
      lnip = ip_ver == IP4 ?
              lgm->lgpe_ip4_lookup_next_index_by_table_id :
              lgm->lgpe_ip6_lookup_next_index_by_table_id;
      lookup_next_index = hash_get(lnip, a->table_id);
      lgpe_sw_if_index = hash_get(lgm->lisp_gpe_hw_if_index_by_table_id,
                                  a->table_id);

      /* the assumption is that the interface must've been created before
       * programming the dp */
      ASSERT(lookup_next_index != 0);
      ASSERT(lgpe_sw_if_index != 0);

      adj.lookup_next_index = lookup_next_index[0];
      adj.rewrite_header.node_index = tun_index;
      adj.rewrite_header.sw_if_index = lgpe_sw_if_index[0];
    }

  /* add/delete route for prefix */
  rv = ip_sd_fib_add_del_route (lgm, dpref, spref, a->table_id, &adj,
                                a->is_add);

  /* check that everything worked */
  if (CLIB_DEBUG && a->is_add)
    {
      adj_index = ip_sd_fib_get_route (lgm, dpref, spref, a->table_id);
      ASSERT(adj_index != 0);

      adjp = ip_get_adjacency ((ip_ver == IP4) ? lgm->lm4 : lgm->lm6,
                               adj_index);

      ASSERT(adjp != 0);
      ASSERT(adjp->rewrite_header.node_index == tun_index);
    }

  return rv;
}

static clib_error_t *
lisp_gpe_add_del_fwd_entry_command_fn (vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  ip_address_t slocator, dlocator, *slocators = 0, *dlocators = 0;
  ip_prefix_t * prefp;
  gid_address_t * eids = 0, eid;
  clib_error_t * error = 0;
  u32 i;
  int rv;

  prefp = &gid_address_ippref(&eid);

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "add"))
        is_add = 1;
      else if (unformat (line_input, "eid %U slocator %U dlocator %U",
                         unformat_ip_prefix, prefp,
                         unformat_ip_address, &slocator,
                         unformat_ip_address, &dlocator))
        {
          vec_add1 (eids, eid);
          vec_add1 (slocators, slocator);
          vec_add1 (dlocators, dlocator);
        }
      else
        {
          error = unformat_parse_error (line_input);
          goto done;
        }
    }
  unformat_free (line_input);

  if (vec_len (eids) + vec_len (slocators) == 0)
    {
      error = clib_error_return (0, "expected ip4/ip6 eids/locators.");
      goto done;
    }

  if (vec_len (eids) != vec_len (slocators))
    {
      error = clib_error_return (0, "number of eids not equal to that of "
          "locators.");
      goto done;
    }

  for (i = 0; i < vec_len(eids); i++)
    {
      vnet_lisp_gpe_add_del_fwd_entry_args_t a;
      memset (&a, 0, sizeof(a));

      a.is_add = is_add;
      a.deid = eids[i];
      a.slocator = slocators[i];
      a.dlocator = dlocators[i];
      rv = vnet_lisp_gpe_add_del_fwd_entry (&a, 0);
      if (0 != rv)
        {
          error = clib_error_return(0, "failed to %s gpe maptunnel!",
                                    is_add ? "add" : "delete");
          break;
        }
    }

 done:
  vec_free(eids);
  vec_free(slocators);
  vec_free(dlocators);
  return error;
}

VLIB_CLI_COMMAND (lisp_gpe_add_del_fwd_entry_command, static) = {
  .path = "lisp gpe maptunnel",
  .short_help = "lisp gpe maptunnel eid <eid> sloc <src-locator> "
      "dloc <dst-locator> [del]",
  .function = lisp_gpe_add_del_fwd_entry_command_fn,
};

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case LISP_GPE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case LISP_GPE_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case LISP_GPE_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    default:
      return format (s, "unknown %d", next_index);
    }
  return s;
}

u8 *
format_lisp_gpe_tunnel (u8 * s, va_list * args)
{
  lisp_gpe_tunnel_t * t = va_arg (*args, lisp_gpe_tunnel_t *);
  lisp_gpe_main_t * lgm = &lisp_gpe_main;

  s = format (s,
              "[%d] %U (src) %U (dst) fibs: encap %d, decap %d",
              t - lgm->tunnels,
              format_ip_address, &t->src,
              format_ip_address, &t->dst,
              t->encap_fib_index,
              t->decap_fib_index);

  s = format (s, " decap next %U\n", format_decap_next, t->decap_next_index);
  s = format (s, "lisp ver %d ", (t->ver_res>>6));

#define _(n,v) if (t->flags & v) s = format (s, "%s-bit ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

  s = format (s, "next_protocol %d ver_res %x res %x\n",
              t->next_protocol, t->ver_res, t->res);

  s = format (s, "iid %d (0x%x)\n", t->vni, t->vni);
  return s;
}

static clib_error_t *
show_lisp_gpe_tunnel_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  lisp_gpe_tunnel_t * t;
  
  if (pool_elts (lgm->tunnels) == 0)
    vlib_cli_output (vm, "No lisp-gpe tunnels configured...");

  pool_foreach (t, lgm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_lisp_gpe_tunnel, t);
  }));
  
  return 0;
}

VLIB_CLI_COMMAND (show_lisp_gpe_tunnel_command, static) = {
    .path = "show lisp gpe tunnel",
    .function = show_lisp_gpe_tunnel_command_fn,
};

u8
vnet_lisp_gpe_enable_disable_status(void)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;

  return lgm->is_en;
}

clib_error_t *
vnet_lisp_gpe_enable_disable (vnet_lisp_gpe_enable_disable_args_t * a)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  vnet_main_t * vnm = lgm->vnet_main;

  if (a->is_en)
    {
      /* add lgpe_ip4_lookup as possible next_node for ip4 lookup */
      if (lgm->ip4_lookup_next_lgpe_ip4_lookup == ~0)
        {
          lgm->ip4_lookup_next_lgpe_ip4_lookup = vlib_node_add_next (
              vnm->vlib_main, ip4_lookup_node.index,
              lgpe_ip4_lookup_node.index);
        }
      /* add lgpe_ip6_lookup as possible next_node for ip6 lookup */
      if (lgm->ip6_lookup_next_lgpe_ip6_lookup == ~0)
        {
          lgm->ip6_lookup_next_lgpe_ip6_lookup = vlib_node_add_next (
              vnm->vlib_main, ip6_lookup_node.index,
              lgpe_ip6_lookup_node.index);
        }
      else
        {
          /* ask cp to re-add ifaces and defaults */
        }

      lgm->is_en = 1;
    }
  else
    {
      CLIB_UNUSED(uword * val);
      hash_pair_t * p;
      u32 * table_ids = 0, * table_id;
      lisp_gpe_tunnel_key_t * tunnels = 0, * tunnel;
      vnet_lisp_gpe_add_del_fwd_entry_args_t _at, * at = &_at;
      vnet_lisp_gpe_add_del_iface_args_t _ai, * ai= &_ai;

      /* remove all tunnels */
      mhash_foreach(tunnel, val, &lgm->lisp_gpe_tunnel_by_key, ({
        vec_add1(tunnels, tunnel[0]);
      }));

      vec_foreach(tunnel, tunnels) {
        memset(at, 0, sizeof(at[0]));
        at->is_add = 0;
        gid_address_type(&at->deid) = GID_ADDR_IP_PREFIX;
        ip_prefix_copy(&gid_address_ippref(&at->deid), &tunnel->eid);
        ip_address_copy(&at->dlocator, &tunnel->dst_loc);
        vnet_lisp_gpe_add_del_fwd_entry (at, 0);
      }
      vec_free(tunnels);

      /* disable all ifaces */
      hash_foreach_pair(p, lgm->lisp_gpe_hw_if_index_by_table_id, ({
        vec_add1(table_ids, p->key);
      }));

      vec_foreach(table_id, table_ids) {
        ai->is_add = 0;
        ai->table_id = table_id[0];

        /* disables interface and removes defaults */
        vnet_lisp_gpe_add_del_iface(ai, 0);
      }
      vec_free(table_ids);
      lgm->is_en = 0;
    }

  return 0;
}

static clib_error_t *
lisp_gpe_enable_disable_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_en = 1;
  vnet_lisp_gpe_enable_disable_args_t _a, * a = &_a;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
        is_en = 1;
      else if (unformat (line_input, "disable"))
        is_en = 0;
      else
        {
          return clib_error_return (0, "parse error: '%U'",
                                   format_unformat_error, line_input);
        }
    }
  a->is_en = is_en;
  return vnet_lisp_gpe_enable_disable (a);
}

VLIB_CLI_COMMAND (enable_disable_lisp_gpe_command, static) = {
  .path = "lisp gpe",
  .short_help = "lisp gpe [enable|disable]",
  .function = lisp_gpe_enable_disable_command_fn,
};

static clib_error_t *
lisp_show_iface_command_fn (vlib_main_t * vm,
                            unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  hash_pair_t * p;

  vlib_cli_output (vm, "%=10s%=12s", "vrf", "hw_if_index");
  hash_foreach_pair (p, lgm->lisp_gpe_hw_if_index_by_table_id, ({
    vlib_cli_output (vm, "%=10d%=10d", p->key, p->value[0]);
  }));
  return 0;
}

VLIB_CLI_COMMAND (lisp_show_iface_command) = {
    .path = "show lisp gpe interface",
    .short_help = "show lisp gpe interface",
    .function = lisp_show_iface_command_fn,
};

clib_error_t *
lisp_gpe_init (vlib_main_t *vm)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  clib_error_t * error = 0;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  lgm->vnet_main = vnet_get_main();
  lgm->vlib_main = vm;
  lgm->im4 = &ip4_main;
  lgm->im6 = &ip6_main;
  lgm->lm4 = &ip4_main.lookup_main;
  lgm->lm6 = &ip6_main.lookup_main;
  lgm->ip4_lookup_next_lgpe_ip4_lookup = ~0;
  lgm->ip6_lookup_next_lgpe_ip6_lookup = ~0;

  mhash_init (&lgm->lisp_gpe_tunnel_by_key, sizeof(uword),
              sizeof(lisp_gpe_tunnel_key_t));

  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe, 
                         lisp_gpe_ip4_input_node.index, 1 /* is_ip4 */);
  udp_register_dst_port (vm, UDP_DST_PORT_lisp_gpe6,
                         lisp_gpe_ip6_input_node.index, 0 /* is_ip4 */);
  return 0;
}

u8 *
format_vnet_lisp_gpe_status (u8 * s, va_list * args)
{
  lisp_gpe_main_t * lgm = &lisp_gpe_main;
  return format (s, "%s", lgm->is_en ? "enabled" : "disabled");
}

VLIB_INIT_FUNCTION(lisp_gpe_init);
