/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/fib/ip6_fib.h>

#include <vnet/ip/ip6_ll_table.h>

/**
 * There's only one IP6 link local table
 */
static ip6_ll_table_t ip6_ll_table;

u32
ip6_ll_fib_get (u32 sw_if_index)
{
  ASSERT (vec_len (ip6_ll_table.ilt_fibs) > sw_if_index);

  return (ip6_ll_table.ilt_fibs[sw_if_index]);
}

fib_node_index_t
ip6_ll_table_lookup (const ip6_ll_prefix_t * prefix)
{
  return (ip6_fib_table_lookup (ip6_ll_fib_get (prefix->ilp_sw_if_index),
				&prefix->ilp_addr, 128));
}

fib_node_index_t
ip6_ll_table_lookup_exact_match (const ip6_ll_prefix_t * prefix)
{
  return (ip6_fib_table_lookup_exact_match
	  (ip6_ll_fib_get (prefix->ilp_sw_if_index), &prefix->ilp_addr, 128));
}

static void
ip6_ll_fib_create (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  u8 *desc;

  desc = format (NULL, "IP6-link-local:%U", format_vnet_sw_if_index_name, vnm,
		 sw_if_index);

  ip6_ll_table.ilt_fibs[sw_if_index] =
    ip6_fib_table_create_and_lock (FIB_SOURCE_IP6_ND,
				   FIB_TABLE_FLAG_IP6_LL, desc);

  /*
   * leave the default route as a drop, but fix fe::/10 to be a glean
   * via the interface.
   */
    fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_len = 10,
	.fp_addr = {
	    .ip6 = {
		.as_u8 = {
                    [0] = 0xFE,
                    [1] = 0x80,
                }
	    },
	}
    };
    fib_table_entry_update_one_path(
        ip6_ll_table.ilt_fibs[sw_if_index],
        &pfx,
        FIB_SOURCE_SPECIAL,
        (FIB_ENTRY_FLAG_ATTACHED |
         FIB_ENTRY_FLAG_NO_ATTACHED_EXPORT),
        DPO_PROTO_IP6,
        NULL,
        sw_if_index,
        ~0,
        1,
        NULL,
        FIB_ROUTE_PATH_FLAG_NONE);
}

static void
ip6_ll_prefix_to_fib (const ip6_ll_prefix_t * ilp, fib_prefix_t * fp)
{
  fp->fp_proto = FIB_PROTOCOL_IP6;
  fp->fp_len = 128;
  fp->fp_addr.ip6 = ilp->ilp_addr;
  fp->___fp___pad = 0;
}

fib_node_index_t
ip6_ll_table_entry_update (const ip6_ll_prefix_t * ilp,
			   fib_route_path_flags_t flags)
{
  fib_node_index_t ip6_ll_entry_index;
  fib_route_path_t *rpaths, rpath = {
    .frp_flags = flags,
    .frp_sw_if_index = ilp->ilp_sw_if_index,
    .frp_proto = DPO_PROTO_IP6,
    .frp_fib_index = ~0,
    .frp_weight = 1,
  };
  fib_prefix_t fp = { 0 };

  if (flags & FIB_ROUTE_PATH_LOCAL)
    rpath.frp_addr.ip6 = ilp->ilp_addr;

  vec_validate_init_empty (ip6_ll_table.ilt_fibs, ilp->ilp_sw_if_index, ~0);

  if (~0 == ip6_ll_fib_get (ilp->ilp_sw_if_index))
    {
      ip6_ll_fib_create (ilp->ilp_sw_if_index);
    }

  rpaths = NULL;
  vec_add1 (rpaths, rpath);

  ip6_ll_prefix_to_fib (ilp, &fp);
  ip6_ll_entry_index =
    fib_table_entry_update (ip6_ll_fib_get (ilp->ilp_sw_if_index), &fp,
			    FIB_SOURCE_IP6_ND,
			    (flags & FIB_ROUTE_PATH_LOCAL ?
			     FIB_ENTRY_FLAG_LOCAL : FIB_ENTRY_FLAG_NONE),
			    rpaths);
  vec_free (rpaths);

  return (ip6_ll_entry_index);
}

void
ip6_ll_table_entry_delete (const ip6_ll_prefix_t * ilp)
{
  fib_node_index_t ip6_ll_entry_index;
  u32 fib_index;

  fib_index = ip6_ll_fib_get (ilp->ilp_sw_if_index);
  if (~0 == fib_index)
    return;

  ip6_ll_entry_index = ip6_ll_table_lookup_exact_match (ilp);
  if (FIB_NODE_INDEX_INVALID == ip6_ll_entry_index)
    return;

  fib_table_entry_delete_index (ip6_ll_entry_index, FIB_SOURCE_IP6_ND);

  /*
   * if there are no ND sourced prefixes left, then we can clean up this FIB
   */
  if (0 == fib_table_get_num_entries (fib_index, FIB_PROTOCOL_IP6,
				      FIB_SOURCE_IP6_ND))
    {
      fib_table_unlock (fib_index, FIB_PROTOCOL_IP6, FIB_SOURCE_IP6_ND);
      ip6_ll_table.ilt_fibs[ilp->ilp_sw_if_index] = ~0;
    }
}

static void
ip6_ll_table_show_one (vlib_main_t * vm, ip6_ll_prefix_t * ilp, int detail)
{
  vlib_cli_output (vm, "%U",
		   format_fib_entry,
		   ip6_ll_table_lookup (ilp),
		   (detail ?
		    FIB_ENTRY_FORMAT_DETAIL2 : FIB_ENTRY_FORMAT_DETAIL));
}

typedef struct ip6_ll_show_ctx_t_
{
  fib_node_index_t *entries;
} ip6_ll_show_ctx_t;

static fib_table_walk_rc_t
ip6_ll_table_show_walk (fib_node_index_t fib_entry_index, void *arg)
{
  ip6_ll_show_ctx_t *ctx = arg;

  vec_add1 (ctx->entries, fib_entry_index);

  return (FIB_TABLE_WALK_CONTINUE);
}

static void
ip6_ll_table_show_all (vlib_main_t * vm, u32 fib_index)
{
  fib_node_index_t *fib_entry_index;
  ip6_ll_show_ctx_t ctx = {
    .entries = NULL,
  };

  fib_table_walk (fib_index, FIB_PROTOCOL_IP6, ip6_ll_table_show_walk, &ctx);
  vec_sort_with_function (ctx.entries, fib_entry_cmp_for_sort);

  vec_foreach (fib_entry_index, ctx.entries)
  {
    vlib_cli_output (vm, "%U",
		     format_fib_entry,
		     *fib_entry_index, FIB_ENTRY_FORMAT_BRIEF);
  }

  vec_free (ctx.entries);
}

static clib_error_t *
ip6_ll_show_fib (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  fib_table_t *fib_table;
  int verbose, matching;
  ip6_address_t matching_address;
  u32 mask_len = 128;
  u32 sw_if_index = ~0;
  int detail = 0;
  vnet_main_t *vnm = vnet_get_main ();
  u32 fib_index;

  verbose = 1;
  matching = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "brief") ||
	  unformat (input, "summary") || unformat (input, "sum"))
	verbose = 0;

      else if (unformat (input, "detail") || unformat (input, "det"))
	detail = 1;

      else if (unformat (input, "%U/%d",
			 unformat_ip6_address, &matching_address, &mask_len))
	matching = 1;

      else
	if (unformat (input, "%U", unformat_ip6_address, &matching_address))
	matching = 1;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  vec_foreach_index (sw_if_index, ip6_ll_table.ilt_fibs)
  {
    fib_index = ip6_ll_table.ilt_fibs[sw_if_index];
    if (~0 == fib_index)
      continue;

    fib_table = fib_table_get (fib_index, FIB_PROTOCOL_IP6);

    if (!(fib_table->ft_flags & FIB_TABLE_FLAG_IP6_LL))
      continue;

    ip6_fib_table_show (vm, fib_table, !verbose);
    if (!verbose)
      continue;

    if (!matching)
      {
	ip6_ll_table_show_all (vm, fib_index);
      }
    else
      {
	if (~0 == sw_if_index)
	  {
	    vlib_cli_output (vm, "specify the interface");
	  }
	else
	  {
	    ip6_ll_prefix_t ilp = {
	      .ilp_addr = matching_address,
	      .ilp_sw_if_index = sw_if_index,
	    };
	    ip6_ll_table_show_one (vm, &ilp, detail);
	  }
      }
  };

  return 0;
}

VLIB_CLI_COMMAND (ip6_show_fib_command, static) = {
    .path = "show ip6-ll",
    .short_help = "show ip6-ll [summary] [interface] [<ip6-addr>[/<width>]] [detail]",
    .function = ip6_ll_show_fib,
};

static clib_error_t *
ip6_ll_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  vec_validate_init_empty (ip6_ll_table.ilt_fibs, sw_if_index, ~0);

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip6_ll_sw_interface_add_del);

static clib_error_t *
ip6_ll_module_init (vlib_main_t * vm)
{
  clib_error_t *error;

  error = vlib_call_init_function (vm, ip6_lookup_init);

  return (error);
}

VLIB_INIT_FUNCTION (ip6_ll_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
