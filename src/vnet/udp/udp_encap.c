/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/udp/udp_encap.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/drop_dpo.h>

/**
 * Registered DPO types for the IP header encapsulated, v4 or v6.
 */
dpo_type_t udp_encap_dpo_types[FIB_PROTOCOL_MAX];

/**
 * Pool of encaps
 */
udp_encap_t *udp_encap_pool;

/**
 * Stats for each UDP encap object
 */
vlib_combined_counter_main_t udp_encap_counters = {
  /**
   * The counter collection's name.
   */
  .name = "udp-encap",
  /**
   * Name in stat segment directory
   */
  .stat_segment_name = "/net/udp-encap",
};

static void
udp_encap_restack (udp_encap_t * ue)
{
  dpo_stack (udp_encap_dpo_types[ue->ue_ip_proto],
	     fib_proto_to_dpo (ue->ue_ip_proto),
	     &ue->ue_dpo,
	     fib_entry_contribute_ip_forwarding (ue->ue_fib_entry_index));
}

index_t
udp_encap_add_and_lock (fib_protocol_t proto,
			index_t fib_index,
			const ip46_address_t * src_ip,
			const ip46_address_t * dst_ip,
			u16 src_port,
			u16 dst_port, udp_encap_fixup_flags_t flags)
{
  udp_encap_t *ue;
  u8 pfx_len = 0;
  index_t uei;

  pool_get_aligned (udp_encap_pool, ue, CLIB_CACHE_LINE_BYTES);
  uei = ue - udp_encap_pool;

  vlib_validate_combined_counter (&(udp_encap_counters), uei);
  vlib_zero_combined_counter (&(udp_encap_counters), uei);

  fib_node_init (&ue->ue_fib_node, FIB_NODE_TYPE_UDP_ENCAP);
  fib_node_lock (&ue->ue_fib_node);
  ue->ue_fib_index = fib_index;
  ue->ue_flags = flags;
  ue->ue_ip_proto = proto;

  switch (proto)
    {
    case FIB_PROTOCOL_IP4:
      pfx_len = 32;
      ue->ue_hdrs.ip4.ue_ip4.ip_version_and_header_length = 0x45;
      ue->ue_hdrs.ip4.ue_ip4.ttl = 254;
      ue->ue_hdrs.ip4.ue_ip4.protocol = IP_PROTOCOL_UDP;
      ue->ue_hdrs.ip4.ue_ip4.src_address.as_u32 = src_ip->ip4.as_u32;
      ue->ue_hdrs.ip4.ue_ip4.dst_address.as_u32 = dst_ip->ip4.as_u32;
      ue->ue_hdrs.ip4.ue_ip4.checksum =
	ip4_header_checksum (&ue->ue_hdrs.ip4.ue_ip4);
      ue->ue_hdrs.ip4.ue_udp.src_port = clib_host_to_net_u16 (src_port);
      ue->ue_hdrs.ip4.ue_udp.dst_port = clib_host_to_net_u16 (dst_port);

      break;
    case FIB_PROTOCOL_IP6:
      pfx_len = 128;
      ue->ue_hdrs.ip6.ue_ip6.ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ue->ue_hdrs.ip6.ue_ip6.hop_limit = 255;
      ue->ue_hdrs.ip6.ue_ip6.protocol = IP_PROTOCOL_UDP;
      ue->ue_hdrs.ip6.ue_ip6.src_address.as_u64[0] = src_ip->ip6.as_u64[0];
      ue->ue_hdrs.ip6.ue_ip6.src_address.as_u64[1] = src_ip->ip6.as_u64[1];
      ue->ue_hdrs.ip6.ue_ip6.dst_address.as_u64[0] = dst_ip->ip6.as_u64[0];
      ue->ue_hdrs.ip6.ue_ip6.dst_address.as_u64[1] = dst_ip->ip6.as_u64[1];
      ue->ue_hdrs.ip6.ue_udp.src_port = clib_host_to_net_u16 (src_port);
      ue->ue_hdrs.ip6.ue_udp.dst_port = clib_host_to_net_u16 (dst_port);

      break;
    default:
      ASSERT (0);
    }

  /*
   * track the destination address
   */
  fib_prefix_t dst_pfx = {
    .fp_proto = proto,
    .fp_len = pfx_len,
    .fp_addr = *dst_ip,
  };

  ue->ue_fib_entry_index =
    fib_table_entry_special_add (fib_index,
				 &dst_pfx,
				 FIB_SOURCE_RR, FIB_ENTRY_FLAG_NONE);
  ue->ue_fib_sibling =
    fib_entry_child_add (ue->ue_fib_entry_index,
			 FIB_NODE_TYPE_UDP_ENCAP, uei);

  udp_encap_restack (ue);

  return (uei);
}

void
udp_encap_contribute_forwarding (index_t uei, dpo_proto_t proto,
				 dpo_id_t * dpo)
{
  if (INDEX_INVALID == uei)
    {
      dpo_copy (dpo, drop_dpo_get (proto));
    }
  else
    {
      udp_encap_t *ue;

      ue = udp_encap_get (uei);

      dpo_set (dpo, udp_encap_dpo_types[ue->ue_ip_proto], proto, uei);
    }
}

void
udp_encap_lock (index_t uei)
{
  udp_encap_t *ue;

  ue = udp_encap_get (uei);

  if (NULL != ue)
    {
      fib_node_lock (&ue->ue_fib_node);
    }
}

void
udp_encap_unlock (index_t uei)
{
  udp_encap_t *ue;

  if (INDEX_INVALID == uei)
    {
      return;
    }

  ue = udp_encap_get (uei);

  if (NULL != ue)
    {
      fib_node_unlock (&ue->ue_fib_node);
    }
}

static void
udp_encap_dpo_lock (dpo_id_t * dpo)
{
  udp_encap_t *ue;

  ue = udp_encap_get (dpo->dpoi_index);

  fib_node_lock (&ue->ue_fib_node);
}

static void
udp_encap_dpo_unlock (dpo_id_t * dpo)
{
  udp_encap_t *ue;

  ue = udp_encap_get (dpo->dpoi_index);

  fib_node_unlock (&ue->ue_fib_node);
}

static u8 *
format_udp_encap_i (u8 * s, va_list * args)
{
  index_t uei = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  u32 details = va_arg (*args, u32);
  vlib_counter_t to;
  udp_encap_t *ue;

  ue = udp_encap_get (uei);

  // FIXME
  s = format (s, "udp-encap:[%d]: ip-fib-index:%d ", uei, ue->ue_fib_index);
  if (FIB_PROTOCOL_IP4 == ue->ue_ip_proto)
    {
      s = format (s, "ip:[src:%U, dst:%U] udp:[src:%d, dst:%d]",
		  format_ip4_address,
		  &ue->ue_hdrs.ip4.ue_ip4.src_address,
		  format_ip4_address,
		  &ue->ue_hdrs.ip4.ue_ip4.dst_address,
		  clib_net_to_host_u16 (ue->ue_hdrs.ip4.ue_udp.src_port),
		  clib_net_to_host_u16 (ue->ue_hdrs.ip4.ue_udp.dst_port));
    }
  else
    {
      s = format (s, "ip:[src:%U, dst:%U] udp:[src:%d dst:%d]",
		  format_ip6_address,
		  &ue->ue_hdrs.ip6.ue_ip6.src_address,
		  format_ip6_address,
		  &ue->ue_hdrs.ip6.ue_ip6.dst_address,
		  clib_net_to_host_u16 (ue->ue_hdrs.ip6.ue_udp.src_port),
		  clib_net_to_host_u16 (ue->ue_hdrs.ip6.ue_udp.dst_port));
    }
  vlib_get_combined_counter (&(udp_encap_counters), uei, &to);
  s = format (s, " to:[%Ld:%Ld]]", to.packets, to.bytes);

  if (details)
    {
      s = format (s, " locks:%d", ue->ue_fib_node.fn_locks);
      s = format (s, "\n%UStacked on:", format_white_space, indent + 1);
      s = format (s, "\n%U%U",
		  format_white_space, indent + 2,
		  format_dpo_id, &ue->ue_dpo, indent + 3);
    }
  return (s);
}

void
udp_encap_get_stats (index_t uei, u64 * packets, u64 * bytes)
{
  vlib_counter_t to;

  vlib_get_combined_counter (&(udp_encap_counters), uei, &to);

  *packets = to.packets;
  *bytes = to.bytes;
}

static u8 *
format_udp_encap_dpo (u8 * s, va_list * args)
{
  index_t uei = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  return (format (s, "%U", format_udp_encap_i, uei, indent, 1));
}

u8 *
format_udp_encap (u8 * s, va_list * args)
{
  index_t uei = va_arg (*args, u32);
  u32 details = va_arg (*args, u32);

  return (format (s, "%U", format_udp_encap_i, uei, 0, details));
}

static udp_encap_t *
udp_encap_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_UDP_ENCAP == node->fn_type);
  return ((udp_encap_t *) (((char *) node) -
			   STRUCT_OFFSET_OF (udp_encap_t, ue_fib_node)));
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
udp_encap_fib_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  udp_encap_restack (udp_encap_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
udp_encap_fib_node_get (fib_node_index_t index)
{
  udp_encap_t *ue;

  ue = pool_elt_at_index (udp_encap_pool, index);

  return (&ue->ue_fib_node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
udp_encap_fib_last_lock_gone (fib_node_t * node)
{
  udp_encap_t *ue;

  ue = udp_encap_from_fib_node (node);

    /**
     * reset the stacked DPO to unlock it
     */
  dpo_reset (&ue->ue_dpo);

  fib_entry_child_remove (ue->ue_fib_entry_index, ue->ue_fib_sibling);
  fib_table_entry_delete_index (ue->ue_fib_entry_index, FIB_SOURCE_RR);


  pool_put (udp_encap_pool, ue);
}

const static char *const udp4_encap_ip4_nodes[] = {
  "udp4-encap",
  NULL,
};

const static char *const udp4_encap_ip6_nodes[] = {
  "udp4-encap",
  NULL,
};

const static char *const udp4_encap_mpls_nodes[] = {
  "udp4-encap",
  NULL,
};

const static char *const udp4_encap_bier_nodes[] = {
  "udp4-encap",
  NULL,
};

const static char *const udp6_encap_ip4_nodes[] = {
  "udp6-encap",
  NULL,
};

const static char *const udp6_encap_ip6_nodes[] = {
  "udp6-encap",
  NULL,
};

const static char *const udp6_encap_mpls_nodes[] = {
  "udp6-encap",
  NULL,
};

const static char *const udp6_encap_bier_nodes[] = {
  "udp6-encap",
  NULL,
};

const static char *const *const udp4_encap_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = udp4_encap_ip4_nodes,
  [DPO_PROTO_IP6] = udp4_encap_ip6_nodes,
  [DPO_PROTO_MPLS] = udp4_encap_mpls_nodes,
  [DPO_PROTO_BIER] = udp4_encap_bier_nodes,
};

const static char *const *const udp6_encap_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = udp6_encap_ip4_nodes,
  [DPO_PROTO_IP6] = udp6_encap_ip6_nodes,
  [DPO_PROTO_MPLS] = udp6_encap_mpls_nodes,
  [DPO_PROTO_BIER] = udp6_encap_bier_nodes,
};

/*
 * Virtual function table registered by UDP encaps
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t udp_encap_fib_vft = {
  .fnv_get = udp_encap_fib_node_get,
  .fnv_last_lock = udp_encap_fib_last_lock_gone,
  .fnv_back_walk = udp_encap_fib_back_walk,
};

const static dpo_vft_t udp_encap_dpo_vft = {
  .dv_lock = udp_encap_dpo_lock,
  .dv_unlock = udp_encap_dpo_unlock,
  .dv_format = format_udp_encap_dpo,
};

clib_error_t *
udp_encap_init (vlib_main_t * vm)
{
  fib_node_register_type (FIB_NODE_TYPE_UDP_ENCAP, &udp_encap_fib_vft);

  udp_encap_dpo_types[FIB_PROTOCOL_IP4] =
    dpo_register_new_type (&udp_encap_dpo_vft, udp4_encap_nodes);
  udp_encap_dpo_types[FIB_PROTOCOL_IP6] =
    dpo_register_new_type (&udp_encap_dpo_vft, udp6_encap_nodes);

  return (NULL);
}

VLIB_INIT_FUNCTION (udp_encap_init);

clib_error_t *
udp_encap_cli (vlib_main_t * vm,
	       unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  ip46_address_t src_ip, dst_ip;
  u32 table_id, src_port, dst_port;
  udp_encap_fixup_flags_t flags;
  fib_protocol_t fproto;
  index_t uei;
  u8 is_del;

  is_del = 0;
  table_id = 0;
  flags = UDP_ENCAP_FIXUP_NONE;
  fproto = FIB_PROTOCOL_MAX;
  dst_port = 0;
  uei = ~0;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %d", &uei))
	;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "%U %U",
			 unformat_ip4_address,
			 &src_ip.ip4, unformat_ip4_address, &dst_ip.ip4))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (line_input, "%U %U",
			 unformat_ip6_address,
			 &src_ip.ip6, unformat_ip6_address, &dst_ip.ip6))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (line_input, "%d %d", &src_port, &dst_port))
	;
      else if (unformat (line_input, "%d", &dst_port))
	;
      else if (unformat (line_input, "table-id %d", &table_id))
	;
      else if (unformat (line_input, "src-port-is-entropy"))
	flags |= UDP_ENCAP_FIXUP_UDP_SRC_PORT_ENTROPY;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (!is_del && fproto != FIB_PROTOCOL_MAX)
    {
      u32 fib_index;
      index_t uei;

      fib_index = fib_table_find (fproto, table_id);

      if (~0 == fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}

      uei = udp_encap_add_and_lock (fproto, fib_index,
				    &src_ip, &dst_ip,
				    src_port, dst_port, flags);

      vlib_cli_output (vm, "udp-encap: %d\n", uei);
    }
  else if (is_del)
    {
      if (INDEX_INVALID == uei)
	{
	  error = clib_error_return (0, "specify udp-encap object index");
	  goto done;
	}
      udp_encap_unlock (uei);
    }
  else
    {
      error = clib_error_return (0, "specify some IP addresses");
    }

done:
  unformat_free (line_input);
  return error;
}

void
udp_encap_walk (udp_encap_walk_cb_t cb, void *ctx)
{
  index_t uei;

  /* *INDENT-OFF* */
  pool_foreach_index(uei, udp_encap_pool,
  ({
    if (WALK_STOP == cb(uei, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

clib_error_t *
udp_encap_show (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t uei;

  uei = INDEX_INVALID;

  /* Get a line of input. */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &uei))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (INDEX_INVALID == uei)
    {
      /* *INDENT-OFF* */
      pool_foreach_index(uei, udp_encap_pool,
      ({
        vlib_cli_output(vm, "%U", format_udp_encap, uei, 0);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      vlib_cli_output (vm, "%U", format_udp_encap, uei, 1);
    }

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (udp_encap_add_command, static) = {
  .path = "udp encap",
  .short_help = "udp encap [add|del] <id ID> <src-ip> <dst-ip> [<src-port>] <dst-port>  [src-port-is-entropy] [table-id <table>]",
  .function = udp_encap_cli,
  .is_mp_safe = 1,
};
VLIB_CLI_COMMAND (udp_encap_show_command, static) = {
  .path = "show udp encap",
  .short_help = "show udp encap [ID]",
  .function = udp_encap_show,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
