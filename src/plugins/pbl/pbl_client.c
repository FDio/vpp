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

#include <vnet/fib/fib_source.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <pbl/pbl_client.h>

char *pbl_error_strings[] = {
#define pbl_error(n, s) s,
#include <pbl/pbl_error.def>
#undef pbl_error
};

pbl_client_t *pbl_client_pool;
fib_source_t pbl_fib_source;
dpo_type_t pbl_client_dpo;

static fib_node_type_t pbl_client_fib_node_type;

static_always_inline u8
pbl_client_is_clone (pbl_client_t *pc)
{
  return (FIB_NODE_INDEX_INVALID == pc->pc_fei);
}

static u8 *
format_pbl_ports (u8 *s, va_list *args)
{
  clib_bitmap_t *map = va_arg (*args, clib_bitmap_t *);
  if (NULL == map)
    {
      s = format (s, "(empty)");
      return (s);
    }
  u32 last, cur, next_set, next_clear;
  last = clib_bitmap_last_set (map);
  cur = clib_bitmap_first_set (map);

  if (cur == (u32) -1)
    {
      s = format (s, "(empty)");
      return (s);
    }

  while (cur <= last)
    {
      next_set = clib_bitmap_next_set (map, cur);
      next_clear = clib_bitmap_next_clear (map, next_set + 1);
      if (next_clear == next_set + 1)
	s = format (s, " %d", next_set);
      else
	s = format (s, " %d-%d", next_set, next_clear - 1);
      cur = next_clear;
    }

  return (s);
}

u8 *
format_pbl_client (u8 *s, va_list *args)
{
  index_t pci = va_arg (*args, index_t);
  pbl_client_t *pc = pool_elt_at_index (pbl_client_pool, pci);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%U[%d] pbl-client: %U", format_white_space, indent, pci,
	      format_ip_address, &pc->pc_addr);

  if (pc->flags & PBL_FLAG_EXCLUSIVE)
    s = format (s, " exclusive");

  if (!pbl_client_is_clone (pc) && INDEX_INVALID != pc->clone_pci)
    {
      s = format (s, " clone:%d", pc->clone_pci);
      return (s);
    }

  s = format (s, "\n%UTCP ports:%U", format_white_space, indent + 2,
	      format_pbl_ports, pc->pc_port_maps[PBL_CLIENT_PORT_MAP_TCP]);

  s = format (s, "\n%UUDP ports:%U", format_white_space, indent + 2,
	      format_pbl_ports, pc->pc_port_maps[PBL_CLIENT_PORT_MAP_UDP]);

  s = format (s, "\n%Umatched dpo\n%U%U", format_white_space, indent + 2,
	      format_white_space, indent + 4, format_dpo_id, &pc->pc_dpo,
	      indent + 4);

  if (pbl_client_is_clone (pc))
    {
      s = format (s, "\n%Udefault dpo\n%U%U", format_white_space, indent + 2,
		  format_white_space, indent + 4, format_dpo_id,
		  &pc->pc_parent, indent + 4);
    }

  return (s);
}

/**
 * Interpose a policy DPO
 */
static void
pbl_client_dpo_interpose (const dpo_id_t *original, const dpo_id_t *parent,
			  dpo_id_t *clone)
{
  pbl_client_t *pc, *pc_clone;
  int ii;

  pool_get_zero (pbl_client_pool, pc_clone);
  pc = pbl_client_get (original->dpoi_index);

  pc_clone->pc_fei = FIB_NODE_INDEX_INVALID;
  pc_clone->clone_pci = INDEX_INVALID;
  ip_address_copy (&pc_clone->pc_addr, &pc->pc_addr);
  pc_clone->flags = pc->flags;
  for (ii = 0; ii < PBL_CLIENT_PORT_MAP_N_PROTOS; ii++)
    pc_clone->pc_port_maps[ii] = pc->pc_port_maps[ii];

  dpo_copy (&pc_clone->pc_dpo, &pc->pc_dpo);

  pc->clone_pci = pc_clone - pbl_client_pool;

  /* stack the clone on the FIB provided parent */
  dpo_stack (pbl_client_dpo, original->dpoi_proto, &pc_clone->pc_parent,
	     parent);

  /* return the clone */
  dpo_set (clone, pbl_client_dpo, original->dpoi_proto,
	   pc_clone - pbl_client_pool);
}

static clib_error_t *
pbl_client_show (vlib_main_t *vm, unformat_input_t *input,
		 vlib_cli_command_t *cmd)
{
  index_t pci;

  pci = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &pci))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == pci)
    {
      pool_foreach_index (pci, pbl_client_pool)
	vlib_cli_output (vm, "%U", format_pbl_client, pci, 0);
    }

  return (NULL);
}

VLIB_CLI_COMMAND (pbl_client_show_cmd_node, static) = {
  .path = "show pbl client",
  .function = pbl_client_show,
  .short_help = "show pbl client",
  .is_mp_safe = 1,
};

const static char *const pbl_client_dpo_ip4_nodes[] = {
  "ip4-pbl-tx",
  NULL,
};

const static char *const pbl_client_dpo_ip6_nodes[] = {
  "ip6-pbl-tx",
  NULL,
};

const static char *const *const pbl_client_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = pbl_client_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = pbl_client_dpo_ip6_nodes,
};

static void
pbl_client_dpo_lock (dpo_id_t *dpo)
{
  pbl_client_t *pc;

  pc = pbl_client_get (dpo->dpoi_index);

  pc->pc_locks++;
}

static void
pbl_client_dpo_unlock (dpo_id_t *dpo)
{
  pbl_client_t *pc;

  pc = pbl_client_get (dpo->dpoi_index);

  pc->pc_locks--;

  if (0 == pc->pc_locks)
    {
      ASSERT (pbl_client_is_clone (pc));
      dpo_reset (&pc->pc_parent);
      pool_put (pbl_client_pool, pc);
    }
}

u8 *
format_pbl_client_dpo (u8 *s, va_list *ap)
{
  index_t pci = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);

  s = format (s, "\n%U", format_pbl_client, pci, indent);

  return (s);
}

const static dpo_vft_t pbl_client_dpo_vft = {
  .dv_lock = pbl_client_dpo_lock,
  .dv_unlock = pbl_client_dpo_unlock,
  .dv_format = format_pbl_client_dpo,
  .dv_mk_interpose = pbl_client_dpo_interpose,
};

static void
pbl_client_stack (pbl_client_t *pc)
{
  dpo_id_t dpo = DPO_INVALID;
  fib_protocol_t fproto;
  vlib_node_t *pnode;
  pbl_client_t *pc_clone;

  fproto = ip_address_family_to_fib_proto (pc->pc_addr.version);
  fib_path_list_contribute_forwarding (
    pc->pc_pl, fib_forw_chain_type_from_fib_proto (fproto),
    FIB_PATH_LIST_FWD_FLAG_COLLAPSE, &dpo);

  if (AF_IP4 == pc->pc_addr.version)
    pnode = vlib_get_node_by_name (vlib_get_main (), (u8 *) "ip4-pbl-tx");
  else
    pnode = vlib_get_node_by_name (vlib_get_main (), (u8 *) "ip6-pbl-tx");

  dpo_stack_from_node (pnode->index, &pc->pc_dpo, &dpo);

  if (INDEX_INVALID != pc->clone_pci)
    {
      pc_clone = pbl_client_get_if_exists (pc->clone_pci);
      if (pc_clone)
	dpo_copy (&pc_clone->pc_dpo, &pc->pc_dpo);
    }

  dpo_reset (&dpo);

  pc->flags |= PBL_CLIENT_STACKED;
}

int
pbl_client_delete (u32 id)
{
  pbl_client_t *pc;
  int ii;

  if (pool_is_free_index (pbl_client_pool, id))
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  pc = pool_elt_at_index (pbl_client_pool, id);

  fib_path_list_child_remove (pc->pc_pl, pc->pc_sibling);

  dpo_reset (&pc->pc_dpo);

  ASSERT (!pbl_client_is_clone (pc));

  ASSERT (fib_entry_is_sourced (pc->pc_fei, pbl_fib_source));
  fib_table_entry_delete_index (pc->pc_fei, pbl_fib_source);

  for (ii = 0; ii < PBL_CLIENT_PORT_MAP_N_PROTOS; ii++)
    clib_bitmap_free (pc->pc_port_maps[ii]);

  dpo_reset (&pc->pc_parent);
  pool_put (pbl_client_pool, pc);

  return (0);
}

u32
pbl_client_update (pbl_client_update_args_t *args)
{
  pbl_client_t *pc;
  dpo_id_t tmp = DPO_INVALID;
  fib_node_index_t fei;
  dpo_proto_t dproto;
  fib_prefix_t pfx;
  u32 fib_flags, fib_index;
  int ii;

  /* check again if we need this client */
  pc = pbl_client_get_if_exists (args->pci);
  if (NULL == pc)
    {
      pool_get_aligned (pbl_client_pool, pc, CLIB_CACHE_LINE_BYTES);
      pc->pc_locks = 1;
      args->pci = pc - pbl_client_pool;
      pc->pc_index = pc - pbl_client_pool;
      pc->flags = args->flags;
      pc->clone_pci = INDEX_INVALID;
      for (ii = 0; ii < PBL_CLIENT_PORT_MAP_N_PROTOS; ii++)
	pc->pc_port_maps[ii] = args->port_maps[ii];
      fib_node_init (&pc->pc_node, pbl_client_fib_node_type);

      ip_address_copy (&pc->pc_addr, &args->addr);

      ip_address_to_fib_prefix (&pc->pc_addr, &pfx);

      dproto = fib_proto_to_dpo (pfx.fp_proto);
      dpo_set (&tmp, pbl_client_dpo, dproto, args->pci);
      dpo_stack (pbl_client_dpo, dproto, &pc->pc_parent,
		 drop_dpo_get (dproto));

      fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;
      fib_flags |= (args->flags & PBL_FLAG_EXCLUSIVE) ?
		     FIB_ENTRY_FLAG_EXCLUSIVE :
		     FIB_ENTRY_FLAG_INTERPOSE;

      fib_index = fib_table_find (pfx.fp_proto, args->table_id);
      fei = fib_table_entry_special_dpo_add (fib_index, &pfx, pbl_fib_source,
					     fib_flags, &tmp);

      /* in case of interpose, pool can grow */
      pc = pool_elt_at_index (pbl_client_pool, args->pci);

      pc->pc_fei = fei;

      pc->flags = args->flags;
      pc->flags &= ~PBL_CLIENT_STACKED;

      /* Contribute in fib in fib */
      pc->pc_pl = fib_path_list_create (
	FIB_PATH_LIST_FLAG_SHARED | FIB_PATH_LIST_FLAG_NO_URPF, args->rpaths);

      /*
       * become a child of the path list so we get poked when
       * the forwarding changes.
       */
      pc->pc_sibling = fib_path_list_child_add (
	pc->pc_pl, pbl_client_fib_node_type, pc->pc_index);
      pbl_client_stack (pc);
    }
  else
    {
      /* Update unimplemented */
      clib_warning ("unimplemented");
    }

  return (pc->pc_index);
}

void
pbl_client_walk (pbl_client_walk_cb_t cb, void *ctx)
{
  u32 api;

  pool_foreach_index (api, pbl_client_pool)
    {
      if (!cb (api, ctx))
	break;
    }
}

int
pbl_client_purge (void)
{
  /* purge all the clients */
  index_t tri, *trp, *trs = NULL;

  pool_foreach_index (tri, pbl_client_pool)
    {
      vec_add1 (trs, tri);
    }

  vec_foreach (trp, trs)
    pbl_client_delete (*trp);

  ASSERT (0 == pool_elts (pbl_client_pool));

  vec_free (trs);

  return (0);
}

static fib_node_t *
pbl_client_get_node (fib_node_index_t index)
{
  pbl_client_t *pc = pbl_client_get (index);
  return (&(pc->pc_node));
}

static pbl_client_t *
pbl_client_get_from_node (fib_node_t *node)
{
  return ((pbl_client_t *) (((char *) node) -
			    STRUCT_OFFSET_OF (pbl_client_t, pc_node)));
}

static void
pbl_client_last_lock_gone (fib_node_t *node)
{
 /**/}

 /*
  * A back walk has reached this ABF policy
  */
 static fib_node_back_walk_rc_t
 pbl_client_back_walk_notify (fib_node_t *node, fib_node_back_walk_ctx_t *ctx)
 {
   /*
    * re-stack the fmask on the n-eos of the via
    */
   pbl_client_t *pc = pbl_client_get_from_node (node);

   /* If we have more than FIB_PATH_LIST_POPULAR paths
    * we might get called during path tracking */
   if (!(pc->flags & PBL_CLIENT_STACKED))
     return (FIB_NODE_BACK_WALK_CONTINUE);

   pbl_client_stack (pc);

   return (FIB_NODE_BACK_WALK_CONTINUE);
 }

 /*
  * The client's graph node virtual function table
  */
 static const fib_node_vft_t pbl_client_vft = {
   .fnv_get = pbl_client_get_node,
   .fnv_last_lock = pbl_client_last_lock_gone,
   .fnv_back_walk = pbl_client_back_walk_notify,
 };

 static clib_error_t *
 pbl_client_cli_add_del (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
 {
   pbl_client_update_args_t _args = { 0 }, *args = &_args;
   unformat_input_t _line_input, *line_input = &_line_input;
   dpo_proto_t payload_proto;
   fib_route_path_t rpath;
   clib_error_t *e = 0;
   u32 port_a, port_b;
   int is_add = 1, ii;
   u32 iproto, proto;

   args->pci = INDEX_INVALID;
   for (ii = 0; ii < PBL_CLIENT_PORT_MAP_N_PROTOS; ii++)
     {
       clib_bitmap_alloc (args->port_maps[ii], (1 << 16) - 1);
       clib_bitmap_zero (args->port_maps[ii]);
     }

   /* Get a line of input. */
   if (!unformat_user (input, unformat_line_input, line_input))
     return 0;

   while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
     {
       if (unformat (line_input, "addr %U", unformat_ip_address, &args->addr))
	 ;
       else if (unformat (line_input, "add"))
	 is_add = 1;
       else if (unformat (line_input, "del"))
	 is_add = 0;
       else if (unformat (line_input, "id %d", &args->pci))
	 ;
       else if (unformat (line_input, "table %d", &args->table_id))
	 ;
       else if (unformat (line_input, "exclusive"))
	 args->flags = PBL_FLAG_EXCLUSIVE;
       else if (unformat (line_input, "via %U", unformat_fib_route_path,
			  &rpath, &payload_proto))
	 vec_add1 (args->rpaths, rpath);
       else if (unformat (line_input, "%U %u-%u", unformat_ip_protocol,
			  &iproto, &port_a, &port_b))
	 {
	   proto = pbl_iproto_to_port_map_proto (iproto);
	   port_b = clib_max (port_a, port_b);
	   if (proto < PBL_CLIENT_PORT_MAP_N_PROTOS)
	     clib_bitmap_set_region (args->port_maps[proto], (u16) port_a, 1,
				     (u16) (port_b - port_a + 1));
	 }
       else if (unformat (line_input, "%U %u", unformat_ip_protocol, &iproto,
			  &port_a))
	 {
	   proto = pbl_iproto_to_port_map_proto (iproto);
	   if (proto < PBL_CLIENT_PORT_MAP_N_PROTOS)
	     clib_bitmap_set (args->port_maps[proto], (u16) port_a, 1);
	 }
       else
	 {
	   e = clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
	   goto done;
	 }
     }

   if (is_add)
     pbl_client_update (args);
   else
     pbl_client_delete (args->pci);

 done:
   vec_free (args->rpaths);
   unformat_free (line_input);
   return (e);
 }

 VLIB_CLI_COMMAND (pbl_client_cli_add_del_command, static) = {
   .path = "pbl client",
   .short_help = "pbl client [add|del] [addr <address>] [via <path>]"
		 "[[id <id>] [table <table-id>] [exclusive]]",
   .function = pbl_client_cli_add_del,
 };

 static clib_error_t *
 pbl_client_init (vlib_main_t *vm)
 {
   pbl_client_dpo =
     dpo_register_new_type (&pbl_client_dpo_vft, pbl_client_dpo_nodes);

   pbl_fib_source = fib_source_allocate ("pbl", PBL_FIB_SOURCE_PRIORITY,
					 FIB_SOURCE_BH_SIMPLE);

   pbl_client_fib_node_type = fib_node_register_new_type (&pbl_client_vft);

   return (NULL);
 }

 VLIB_INIT_FUNCTION (pbl_client_init);

 VLIB_PLUGIN_REGISTER () = {
   .version = VPP_BUILD_VER,
   .description = "Port based balancer (PBL)",
   .default_disabled = 0,
 };

 /*
  * fd.io coding-style-patch-verification: ON
  *
  * Local Variables:
  * eval: (c-set-style "gnu")
  * End:
  */
