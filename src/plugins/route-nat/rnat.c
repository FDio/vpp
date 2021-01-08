/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or arnated to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/ip/format.h>
#include <vpp/app/version.h>
#include "rnat.h"

rnat_main_t rnat_main;

static void
rnat_rule_stack (adj_index_t ai)
{
  rnat_main_t *rm = &rnat_main;
  ip_adjacency_t *adj;
  rnat_rule_t *r;
  u32 sw_if_index;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len (rm->rule_index_by_sw_if_index) <= sw_if_index) ||
      (~0 == vec_elt (rm->rule_index_by_sw_if_index, sw_if_index)))
    return;

  r = pool_elt_at_index (rm->rules,
			 vec_elt (rm->rule_index_by_sw_if_index, sw_if_index));

  if ((vnet_hw_interface_get_flags (vnet_get_main (), r->hw_if_index) &
       VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    adj_midchain_delegate_unstack (ai);
  else
    adj_midchain_delegate_stack (ai, 0, &r->nh);
}

static adj_walk_rc_t
rnat_adj_walk_cb (adj_index_t ai, void *ctx)
{
  rnat_rule_stack (ai);
  return ADJ_WALK_RC_CONTINUE;
}

static void
rnat_rule_restack (rnat_rule_t *r)
{
  fib_protocol_t proto;
  FOR_EACH_FIB_IP_PROTOCOL (proto)
  adj_nbr_walk (r->sw_if_index, proto, rnat_adj_walk_cb, NULL);
}

static void
rnat_fixup_src_44 (vlib_main_t *vm, const ip_adjacency_t *adj,
		   vlib_buffer_t *b, const void *data)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  ip_csum_t ip_csum = ip4->checksum;
  u32 addr = (u64) data;

  ip_csum = ip_csum_sub_even (ip_csum, ip4->src_address.as_u32);
  ip_csum = ip_csum_add_even (ip_csum, addr);
  ip4->checksum = ip_csum_fold (ip_csum);

  ip4->src_address.as_u32 = addr;
}

static void
rnat_fixup_dst_44 (vlib_main_t *vm, const ip_adjacency_t *adj,
		   vlib_buffer_t *b, const void *data)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  ip_csum_t ip_csum = ip4->checksum;
  u32 addr = (u64) data;

  ip_csum = ip_csum_sub_even (ip_csum, ip4->dst_address.as_u32);
  ip_csum = ip_csum_add_even (ip_csum, addr);
  ip4->checksum = ip_csum_fold (ip_csum);

  ip4->dst_address.as_u32 = addr;
}

static void
rnat_fixup_src_dst_44 (vlib_main_t *vm, const ip_adjacency_t *adj,
		       vlib_buffer_t *b, const void *data)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  ip_csum_t ip_csum = ip4->checksum;
  u64 addr = (u64) data;

  ip_csum = ip_csum_sub_even (ip_csum, *(u64 *) &ip4->address_pair);
  ip_csum = ip_csum_add_even (ip_csum, addr);
  ip4->checksum = ip_csum_fold (ip_csum);

  *(u64 *) &ip4->address_pair = addr;
}

static void
rnat_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  rnat_main_t *rm = &rnat_main;
  rnat_rule_t *r;
  u32 ri;
  u8 *rw = 0;
  union
  {
    ip4_address_pair_t pair;
    void *ptr;
  } data;
  adj_midchain_fixup_t fixup;

  ri = vec_elt (rm->rule_index_by_sw_if_index, sw_if_index);
  r = pool_elt_at_index (rm->rules, ri);

  if (!ip_address_is_zero (&r->src) && !ip_address_is_zero (&r->dst))
    {
      fixup = rnat_fixup_src_dst_44;
      ip_address_copy_addr (&data.pair.src, &r->src);
      ip_address_copy_addr (&data.pair.dst, &r->dst);
    }
  else if (!ip_address_is_zero (&r->src))
    {
      fixup = rnat_fixup_src_44;
      ip_address_copy_addr (&data.pair.src, &r->src);
    }
  else
    {
      fixup = rnat_fixup_dst_44;
      ip_address_copy_addr (&data.pair.src, &r->dst);
    }

  /* ugly hack: we use a 0-byte rewrite string, so we can go through the
   * midchain node and call our fixup function which will actually do the
   * rewrite */
  vec_validate (rw, 0);
  vec_reset_length (rw);

  adj_nbr_midchain_update_rewrite (ai, fixup, data.ptr, 0, rw);

  rnat_rule_stack (ai);
}

static u8 *
format_rnat_device_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "rnat%d", dev_instance);
}

static u8 *
format_rnat_device (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "NAT rule: id %d\n", dev_instance);
  return s;
}

static clib_error_t *
rnat_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  rnat_main_t *rm = &rnat_main;
  vnet_hw_interface_t *hi;
  rnat_rule_t *r;
  u32 index;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  if (NULL == rm->rule_index_by_sw_if_index ||
      hi->sw_if_index >= vec_len (rm->rule_index_by_sw_if_index))
    return NULL;

  index = vec_elt (rm->rule_index_by_sw_if_index, hi->sw_if_index);
  if (~0 == index)
    return NULL;

  r = pool_elt_at_index (rm->rules, index);
  vnet_hw_interface_set_flags (vnm, hw_if_index,
			       (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
				 VNET_HW_INTERFACE_FLAG_LINK_UP :
				 0);
  rnat_rule_restack (r);

  return 0;
}

VNET_DEVICE_CLASS (rnat_device_class, static) = {
  .name = "route NAT device",
  .format_device_name = format_rnat_device_name,
  .format_device = format_rnat_device,
  .admin_up_down_function = rnat_interface_admin_up_down,
};

VNET_HW_INTERFACE_CLASS (rnat_hw_interface_class, static) = {
  .name = "route NAT",
  .update_adjacency = rnat_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

static u8 *
format_rnat_rule (u8 *s, va_list *args)
{
  rnat_rule_t *r = va_arg (*args, rnat_rule_t *);

  s = format (s, "[%d] src %U dst %U nh %U sw-if-idx %d ", r->dev_instance,
	      format_ip_address, &r->src, format_ip_address, &r->dst,
	      format_ip46_address, &r->nh.fp_addr, IP46_TYPE_ANY,
	      r->sw_if_index);

  return s;
}

static int
rnat_add (rnat_main_t *rm, vnet_main_t *vnm, const rnat_add_del_args_t *a,
	  u32 *sw_if_index, rnat_rule_hk_t *hk, uword *p)
{
  vnet_hw_interface_t *hi;
  u32 hw_if_index;
  rnat_rule_t *r;

  if (p)
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  if (ip_addr_version (&a->src) != ip_addr_version (&a->dst) ||
      ip_addr_version (&a->src) != ip_addr_version (&a->nh) ||
      (ip_address_is_zero (&a->src) && ip_address_is_zero (&a->dst)))
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get_aligned (rm->rules, r, CLIB_CACHE_LINE_BYTES);
  clib_memset (r, 0, sizeof (*r));

  r->dev_instance = r - rm->rules;

  hw_if_index =
    vnet_register_interface (vnm, rnat_device_class.index, r->dev_instance,
			     rnat_hw_interface_class.index, r->dev_instance);
  hi = vnet_get_hw_interface (vnm, hw_if_index);
  *sw_if_index = hi->sw_if_index;

  r->hw_if_index = hw_if_index;
  r->sw_if_index = *sw_if_index;

  vec_validate_init_empty (rm->rule_index_by_sw_if_index, *sw_if_index, ~0);
  vec_elt (rm->rule_index_by_sw_if_index, *sw_if_index) = r->dev_instance;

  ip_address_copy (&r->src, &a->src);
  ip_address_copy (&r->dst, &a->dst);
  ip_address_to_fib_prefix (&a->nh, &r->nh);

  hash_set_mem_alloc (&rm->rules_ht, hk, r->dev_instance);

  return 0;
}

static int
rnat_del (rnat_main_t *rm, vnet_main_t *vnm, const rnat_add_del_args_t *a,
	  u32 *sw_if_index, rnat_rule_hk_t *hk, uword *p)
{
  rnat_rule_t *r;

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  r = pool_elt_at_index (rm->rules, p[0]);

  *sw_if_index = r->sw_if_index;
  vnet_sw_interface_set_flags (vnm, *sw_if_index, 0 /* down */);

  vec_elt (rm->rule_index_by_sw_if_index, *sw_if_index) = ~0;

  vnet_delete_hw_interface (vnm, r->hw_if_index);

  hash_unset_mem_free (&rm->rules_ht, hk);
  pool_put (rm->rules, r);

  return 0;
}

int
rnat_add_del (const rnat_add_del_args_t *a, u32 *sw_if_index)
{
  rnat_main_t *rm = &rnat_main;
  vnet_main_t *vnm = vnet_get_main ();
  rnat_rule_hk_t hk;
  uword *p;

  ip_address_copy (&hk.src, &a->src);
  ip_address_copy (&hk.dst, &a->dst);
  ip_address_copy (&hk.nh, &a->nh);
  p = hash_get_mem (rm->rules_ht, &hk);

  if (a->is_del)
    return rnat_del (rm, vnm, a, sw_if_index, &hk, p);
  else
    return rnat_add (rm, vnm, a, sw_if_index, &hk, p);
}

static clib_error_t *
rnat_cmd_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  rnat_add_del_args_t a;
  u32 sw_if_index;
  clib_error_t *error = 0;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  memset (&a, 0, sizeof (a));

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	a.is_del = 0;
      else if (unformat (line_input, "del"))
	a.is_del = 1;
      else if (unformat (line_input, "src %U", unformat_ip_address, &a.src))
	;
      else if (unformat (line_input, "dst %U", unformat_ip_address, &a.dst))
	;
      else if (unformat (line_input, "nh %U", unformat_ip_address, &a.nh))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = rnat_add_del (&a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_IF_ALREADY_EXISTS:
      error = clib_error_return (0, "rule already exists...");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "rule doesn't exist");
      goto done;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "Instance is in use");
      goto done;
    default:
      error = clib_error_return (0, "rnat_add_del returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (rnat_cmd, static) = {
  .path = "rnat",
  .short_help = "rnat [add|del] src <addr> dst <addr> nh <next-hop>",
  .function = rnat_cmd_fn,
};

static clib_error_t *
show_rnat_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		  vlib_cli_command_t *cmd)
{
  rnat_main_t *rm = &rnat_main;
  rnat_rule_t *r;

  if (pool_elts (rm->rules) == 0)
    vlib_cli_output (vm, "No route NAT rules configured...");

  pool_foreach (r, rm->rules)
    {
      vlib_cli_output (vm, "%U", format_rnat_rule, r);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_rnat_cmd, static) = {
  .path = "show rnat",
  .function = show_rnat_cmd_fn,
};

static clib_error_t *
rnat_init (vlib_main_t *vm)
{
  rnat_main_t *rm = &rnat_main;

  clib_memset (rm, 0, sizeof (rm[0]));
  rm->rules_ht = hash_create_mem (0, sizeof (rnat_rule_hk_t), sizeof (uword));
  return 0;
}

VLIB_INIT_FUNCTION (rnat_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Route NAT plugin",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
