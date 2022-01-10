/*
 * ipsec_itf.c: IPSec dedicated interface type
 *
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

#include <vnet/ip/ip.h>
#include <vnet/ipsec/ipsec_itf.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/mpls/mpls.h>

/* bitmap of Allocated IPSEC_ITF instances */
static uword *ipsec_itf_instances;

/* pool of interfaces */
static ipsec_itf_t *ipsec_itf_pool;

static u32 *ipsec_itf_index_by_sw_if_index;

ipsec_itf_t *
ipsec_itf_get (index_t ii)
{
  return (pool_elt_at_index (ipsec_itf_pool, ii));
}

u32
ipsec_itf_count (void)
{
  return (pool_elts (ipsec_itf_pool));
}

static ipsec_itf_t *
ipsec_itf_find_by_sw_if_index (u32 sw_if_index)
{
  if (vec_len (ipsec_itf_index_by_sw_if_index) <= sw_if_index)
    return NULL;
  u32 ti = ipsec_itf_index_by_sw_if_index[sw_if_index];
  if (ti == ~0)
    return NULL;
  return pool_elt_at_index (ipsec_itf_pool, ti);
}

static u8 *
format_ipsec_itf_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ipsec%d", dev_instance);
}

void
ipsec_itf_adj_unstack (adj_index_t ai)
{
  adj_midchain_delegate_unstack (ai);
}

void
ipsec_itf_adj_stack (adj_index_t ai, u32 sai)
{
  const vnet_hw_interface_t *hw;

  hw = vnet_get_sup_hw_interface (vnet_get_main (), adj_get_sw_if_index (ai));

  if (hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
      const ipsec_sa_t *sa;
      fib_prefix_t dst;

      sa = ipsec_sa_get (sai);
      ip_address_to_fib_prefix (&sa->tunnel.t_dst, &dst);
      adj_midchain_delegate_stack (ai, sa->tunnel.t_fib_index, &dst);
    }
  else
    adj_midchain_delegate_unstack (ai);
}

static adj_walk_rc_t
ipsec_itf_adj_stack_cb (adj_index_t ai, void *arg)
{
  ipsec_tun_protect_t *itp = arg;

  ipsec_itf_adj_stack (ai, itp->itp_out_sa);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
ipsec_itf_restack (index_t itpi, const ipsec_itf_t * itf)
{
  ipsec_tun_protect_t *itp;
  fib_protocol_t proto;

  itp = ipsec_tun_protect_get (itpi);

  /*
   * walk all the adjacencies on the interface and restack them
   */
  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    adj_nbr_walk (itf->ii_sw_if_index, proto, ipsec_itf_adj_stack_cb, itp);
  }
}

static walk_rc_t
ipsec_tun_protect_walk_state_change (index_t itpi, void *arg)
{
  const ipsec_itf_t *itf = arg;

  ipsec_itf_restack (itpi, itf);

  return (WALK_CONTINUE);
}

static clib_error_t *
ipsec_itf_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  ipsec_itf_t *itf;
  u32 hw_flags;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ?
	      VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  itf = ipsec_itf_find_by_sw_if_index (hi->sw_if_index);

  if (itf)
    ipsec_tun_protect_walk_itf (itf->ii_sw_if_index,
				ipsec_tun_protect_walk_state_change, itf);

  return (NULL);
}

static int
ipsec_itf_tunnel_desc (u32 sw_if_index,
		       ip46_address_t * src, ip46_address_t * dst, u8 * is_l2)
{
  ip46_address_reset (src);
  ip46_address_reset (dst);
  *is_l2 = 0;

  return (0);
}

static u8 *
ipsec_itf_build_rewrite (void)
{
  /*
   * passing the adj code a NULL rewrite means 'i don't have one cos
   * t'other end is unresolved'. That's not the case here. For the ipsec
   * tunnel there are just no bytes of encap to apply in the adj.
   * So return a zero length rewrite. Encap will be added by a tunnel mode SA.
   */
  u8 *rewrite = NULL;

  vec_validate (rewrite, 0);
  vec_reset_length (rewrite);

  return (rewrite);
}

static u8 *
ipsec_itf_build_rewrite_i (vnet_main_t * vnm,
			   u32 sw_if_index,
			   vnet_link_t link_type, const void *dst_address)
{
  return (ipsec_itf_build_rewrite ());
}

void
ipsec_itf_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  adj_nbr_midchain_update_rewrite
    (ai, NULL, NULL, ADJ_FLAG_MIDCHAIN_IP_STACK, ipsec_itf_build_rewrite ());
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ipsec_itf_device_class) = {
  .name = "IPSEC Tunnel",
  .format_device_name = format_ipsec_itf_name,
  .admin_up_down_function = ipsec_itf_admin_up_down,
  .ip_tun_desc = ipsec_itf_tunnel_desc,
};

VNET_HW_INTERFACE_CLASS(ipsec_hw_interface_class) = {
  .name = "IPSec",
  .build_rewrite = ipsec_itf_build_rewrite_i,
  .update_adjacency = ipsec_itf_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
VNET_HW_INTERFACE_CLASS(ipsec_p2mp_hw_interface_class) = {
  .name = "IPSec",
  .build_rewrite = ipsec_itf_build_rewrite_i,
  .update_adjacency = ipsec_itf_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
};
/* *INDENT-ON* */

/*
 * Maintain a bitmap of allocated ipsec_itf instance numbers.
 */
#define IPSEC_ITF_MAX_INSTANCE		(16 * 1024)

static u32
ipsec_itf_instance_alloc (u32 want)
{
  /*
   * Check for dynamically allocated instance number.
   */
  if (~0 == want)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (ipsec_itf_instances);
      if (bit >= IPSEC_ITF_MAX_INSTANCE)
	{
	  return ~0;
	}
      ipsec_itf_instances = clib_bitmap_set (ipsec_itf_instances, bit, 1);
      return bit;
    }

  /*
   * In range?
   */
  if (want >= IPSEC_ITF_MAX_INSTANCE)
    {
      return ~0;
    }

  /*
   * Already in use?
   */
  if (clib_bitmap_get (ipsec_itf_instances, want))
    {
      return ~0;
    }

  /*
   * Grant allocation request.
   */
  ipsec_itf_instances = clib_bitmap_set (ipsec_itf_instances, want, 1);

  return want;
}

static int
ipsec_itf_instance_free (u32 instance)
{
  if (instance >= IPSEC_ITF_MAX_INSTANCE)
    {
      return -1;
    }

  if (clib_bitmap_get (ipsec_itf_instances, instance) == 0)
    {
      return -1;
    }

  ipsec_itf_instances = clib_bitmap_set (ipsec_itf_instances, instance, 0);
  return 0;
}

void
ipsec_itf_reset_tx_nodes (u32 sw_if_index)
{
  vnet_feature_modify_end_node (
    ip4_main.lookup_main.output_feature_arc_index, sw_if_index,
    vlib_get_node_by_name (vlib_get_main (), (u8 *) "ip4-drop")->index);
  vnet_feature_modify_end_node (
    ip6_main.lookup_main.output_feature_arc_index, sw_if_index,
    vlib_get_node_by_name (vlib_get_main (), (u8 *) "ip6-drop")->index);
  vnet_feature_modify_end_node (
    mpls_main.output_feature_arc_index, sw_if_index,
    vlib_get_node_by_name (vlib_get_main (), (u8 *) "mpls-drop")->index);
}

int
ipsec_itf_create (u32 user_instance, tunnel_mode_t mode, u32 * sw_if_indexp)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 instance, hw_if_index;
  vnet_hw_interface_t *hi;
  ipsec_itf_t *ipsec_itf;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~ 0;

  /*
   * Allocate a ipsec_itf instance.  Either select on dynamically
   * or try to use the desired user_instance number.
   */
  instance = ipsec_itf_instance_alloc (user_instance);
  if (instance == ~0)
    return VNET_API_ERROR_INVALID_REGISTRATION;

  pool_get (ipsec_itf_pool, ipsec_itf);

  /* tunnel index (or instance) */
  u32 t_idx = ipsec_itf - ipsec_itf_pool;

  ipsec_itf->ii_mode = mode;
  ipsec_itf->ii_user_instance = instance;

  hw_if_index = vnet_register_interface (vnm,
					 ipsec_itf_device_class.index,
					 ipsec_itf->ii_user_instance,
					 (mode == TUNNEL_MODE_P2P ?
					  ipsec_hw_interface_class.index :
					  ipsec_p2mp_hw_interface_class.index),
					 t_idx);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_sw_interface_set_mtu (vnm, hi->sw_if_index, 9000);

  vec_validate_init_empty (ipsec_itf_index_by_sw_if_index, hi->sw_if_index,
			   INDEX_INVALID);
  ipsec_itf_index_by_sw_if_index[hi->sw_if_index] = t_idx;

  ipsec_itf->ii_sw_if_index = *sw_if_indexp = hi->sw_if_index;
  ipsec_itf_reset_tx_nodes (hi->sw_if_index);

  return 0;
}

int
ipsec_itf_delete (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == 0 || hw->dev_class_index != ipsec_itf_device_class.index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  ipsec_itf_t *ipsec_itf;
  ipsec_itf = ipsec_itf_find_by_sw_if_index (sw_if_index);
  if (NULL == ipsec_itf)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (ipsec_itf_instance_free (hw->dev_instance) < 0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_reset_interface_l3_output_node (vnm->vlib_main, sw_if_index);

  vnet_delete_hw_interface (vnm, hw->hw_if_index);
  pool_put (ipsec_itf_pool, ipsec_itf);

  return 0;
}

void
ipsec_itf_walk (ipsec_itf_walk_cb_t cb, void *ctx)
{
  ipsec_itf_t *itf;

  pool_foreach (itf, ipsec_itf_pool)
    {
      if (WALK_CONTINUE != cb (itf, ctx))
	break;
    }
}

static clib_error_t *
ipsec_itf_create_cli (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 instance, sw_if_index;
  clib_error_t *error;
  mac_address_t mac;
  int rv;

  error = NULL;
  instance = sw_if_index = ~0;
  mac_address_set_zero (&mac);

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "instance %d", &instance))
	    ;
	  else
	    {
	      error = clib_error_return (0, "unknown input: %U",
					 format_unformat_error, line_input);
	      break;
	    }
	}

      unformat_free (line_input);

      if (error)
	return error;
    }

  rv = ipsec_itf_create (instance, TUNNEL_MODE_P2P, &sw_if_index);

  if (rv)
    return clib_error_return (0, "iPSec interface create failed");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
}

/*?
 * Create a IPSec interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{ipsec itf create [instance <instance>]}
 * Example of how to create a ipsec interface:
 * @cliexcmd{ipsec itf create}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_itf_create_command, static) = {
  .path = "ipsec itf create",
  .short_help = "ipsec itf create [instance <instance>]",
  .function = ipsec_itf_create_cli,
};
/* *INDENT-ON* */

static clib_error_t *
ipsec_itf_delete_cli (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm;
  u32 sw_if_index;
  int rv;

  vnm = vnet_get_main ();
  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (~0 != sw_if_index)
    {
      rv = ipsec_itf_delete (sw_if_index);

      if (rv)
	return clib_error_return (0, "ipsec interface delete failed");
    }
  else
    return clib_error_return (0, "no such interface: %U",
			      format_unformat_error, input);

  return 0;
}

/*?
 * Delete a IPSEC_ITF interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{ipsec itf delete <interface>}
 * Example of how to create a ipsec_itf interface:
 * @cliexcmd{ipsec itf delete ipsec0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_itf_delete_command, static) = {
  .path = "ipsec itf delete",
  .short_help = "ipsec itf delete <interface>",
  .function = ipsec_itf_delete_cli,
};
/* *INDENT-ON* */

static clib_error_t *
ipsec_interface_show (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t ii;

  /* *INDENT-OFF* */
  pool_foreach_index (ii, ipsec_itf_pool)
   {
    vlib_cli_output (vm, "%U", format_ipsec_itf, ii);
  }
  /* *INDENT-ON* */

  return NULL;
}

/**
 * show IPSEC tunnel protection hash tables
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipsec_interface_show_node, static) =
{
  .path = "show ipsec interface",
  .function = ipsec_interface_show,
  .short_help =  "show ipsec interface",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
