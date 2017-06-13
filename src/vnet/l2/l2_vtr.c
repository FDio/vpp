/*
 * l2_vtr.c : layer 2 vlan tag rewrite configuration
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/l2/l2_input_vtr.h>
#include <vnet/l2/l2_output.h>

#include <vppinfra/error.h>
#include <vlib/cli.h>

/**
 * @file
 * @brief Ethernet VLAN Tag Rewrite.
 *
 * VLAN tag rewrite provides the ability to change the VLAN tags on a packet.
 * Existing tags can be popped, new tags can be pushed, and existing tags can
 * be swapped with new tags. The rewrite feature is attached to a subinterface
 * as input and output operations. The input operation is explicitly configured.
 * The output operation is the symmetric opposite and is automatically derived
 * from the input operation.
 */

/** Just a placeholder; ensures file is not eliminated by linker. */
clib_error_t *
l2_vtr_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (l2_vtr_init);

u32
l2pbb_configure (vlib_main_t * vlib_main,
		 vnet_main_t * vnet_main, u32 sw_if_index, u32 vtr_op,
		 u8 * b_dmac, u8 * b_smac,
		 u16 b_vlanid, u32 i_sid, u16 vlan_outer_tag)
{
  u32 error = 0;
  u32 enable = 0;

  l2_output_config_t *config = 0;
  vnet_hw_interface_t *hi;
  hi = vnet_get_sup_hw_interface (vnet_main, sw_if_index);

  if (!hi)
    {
      error = VNET_API_ERROR_INVALID_INTERFACE;
      goto done;
    }

  // Config for this interface should be already initialized
  ptr_config_t *in_config;
  ptr_config_t *out_config;
  config = vec_elt_at_index (l2output_main.configs, sw_if_index);
  in_config = &(config->input_pbb_vtr);
  out_config = &(config->output_pbb_vtr);

  in_config->pop_bytes = 0;
  in_config->push_bytes = 0;
  out_config->pop_bytes = 0;
  out_config->push_bytes = 0;
  enable = (vtr_op != L2_VTR_DISABLED);

  if (!enable)
    goto done;

  if (vtr_op == L2_VTR_POP_2)
    {
      in_config->pop_bytes = sizeof (ethernet_pbb_header_packed_t);
    }
  else if (vtr_op == L2_VTR_PUSH_2)
    {
      clib_memcpy (in_config->macs_tags.b_dst_address, b_dmac,
		   sizeof (in_config->macs_tags.b_dst_address));
      clib_memcpy (in_config->macs_tags.b_src_address, b_smac,
		   sizeof (in_config->macs_tags.b_src_address));
      in_config->macs_tags.b_type =
	clib_net_to_host_u16 (ETHERNET_TYPE_DOT1AD);
      in_config->macs_tags.priority_dei_id =
	clib_net_to_host_u16 (b_vlanid & 0xFFF);
      in_config->macs_tags.i_type =
	clib_net_to_host_u16 (ETHERNET_TYPE_DOT1AH);
      in_config->macs_tags.priority_dei_uca_res_sid =
	clib_net_to_host_u32 (i_sid & 0xFFFFF);
      in_config->push_bytes = sizeof (ethernet_pbb_header_packed_t);
    }
  else if (vtr_op == L2_VTR_TRANSLATE_2_2)
    {
      /* TODO after PoC */
    }

  /*
   *  Construct the output tag-rewrite config
   *
   *  The push/pop values are always reversed
   */
  out_config->raw_data = in_config->raw_data;
  out_config->pop_bytes = in_config->push_bytes;
  out_config->push_bytes = in_config->pop_bytes;

done:
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_VTR, enable);
  if (config)
    config->out_vtr_flag = (u8) enable;

  /* output vtr enable is checked explicitly in l2_output */
  return error;
}

/**
 * Configure vtag tag rewrite on the given interface.
 * Return 1 if there is an error, 0 if ok
 */
u32
l2vtr_configure (vlib_main_t * vlib_main, vnet_main_t * vnet_main, u32 sw_if_index, u32 vtr_op, u32 push_dot1q,	/* ethertype of first pushed tag is dot1q/dot1ad */
		 u32 vtr_tag1,	/* first pushed tag */
		 u32 vtr_tag2)	/* second pushed tag */
{
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  u32 hw_no_tags;
  u32 error = 0;
  l2_output_config_t *config;
  vtr_config_t *in_config;
  vtr_config_t *out_config;
  u32 enable;
  u32 push_inner_et;
  u32 push_outer_et;
  u32 cfg_tags;

  hi = vnet_get_sup_hw_interface (vnet_main, sw_if_index);
  if (!hi || (hi->hw_class_index != ethernet_hw_interface_class.index))
    {
      error = VNET_API_ERROR_INVALID_INTERFACE;	/* non-ethernet interface */
      goto done;
    }

  /* Init the config for this interface */
  vec_validate (l2output_main.configs, sw_if_index);
  config = vec_elt_at_index (l2output_main.configs, sw_if_index);
  in_config = &(config->input_vtr);
  out_config = &(config->output_vtr);
  in_config->raw_tags = 0;
  out_config->raw_tags = 0;

  /* Get the configured tags for the interface */
  si = vnet_get_sw_interface (vnet_main, sw_if_index);
  hw_no_tags = (si->type == VNET_SW_INTERFACE_TYPE_HARDWARE);

  /* Construct the input tag-rewrite config */

  push_outer_et =
    clib_net_to_host_u16 (push_dot1q ? ETHERNET_TYPE_VLAN :
			  ETHERNET_TYPE_DOT1AD);
  push_inner_et = clib_net_to_host_u16 (ETHERNET_TYPE_VLAN);
  vtr_tag1 = clib_net_to_host_u16 (vtr_tag1);
  vtr_tag2 = clib_net_to_host_u16 (vtr_tag2);

  /* Determine number of vlan tags with explictly configured values */
  cfg_tags = 0;
  if (hw_no_tags || si->sub.eth.flags.no_tags)
    {
      cfg_tags = 0;
    }
  else if (si->sub.eth.flags.one_tag)
    {
      cfg_tags = 1;
      if (si->sub.eth.flags.outer_vlan_id_any)
	{
	  cfg_tags = 0;
	}
    }
  else if (si->sub.eth.flags.two_tags)
    {
      cfg_tags = 2;
      if (si->sub.eth.flags.inner_vlan_id_any)
	{
	  cfg_tags = 1;
	}
      if (si->sub.eth.flags.outer_vlan_id_any)
	{
	  cfg_tags = 0;
	}
    }

  switch (vtr_op)
    {
    case L2_VTR_DISABLED:
      in_config->push_and_pop_bytes = 0;
      break;

    case L2_VTR_POP_1:
      if (cfg_tags < 1)
	{
	  /* Need one or two tags */
	  error = VNET_API_ERROR_INVALID_VLAN_TAG_COUNT;
	  goto done;
	}
      in_config->pop_bytes = 4;
      in_config->push_bytes = 0;
      break;

    case L2_VTR_POP_2:
      if (cfg_tags < 2)
	{
	  error = VNET_API_ERROR_INVALID_VLAN_TAG_COUNT;	/* Need two tags */
	  goto done;
	}
      in_config->pop_bytes = 8;
      in_config->push_bytes = 0;
      break;

    case L2_VTR_PUSH_1:
      in_config->pop_bytes = 0;
      in_config->push_bytes = 4;
      in_config->tags[1].priority_cfi_and_id = vtr_tag1;
      in_config->tags[1].type = push_outer_et;
      break;

    case L2_VTR_PUSH_2:
      in_config->pop_bytes = 0;
      in_config->push_bytes = 8;
      in_config->tags[0].priority_cfi_and_id = vtr_tag1;
      in_config->tags[0].type = push_outer_et;
      in_config->tags[1].priority_cfi_and_id = vtr_tag2;
      in_config->tags[1].type = push_inner_et;
      break;

    case L2_VTR_TRANSLATE_1_1:
      if (cfg_tags < 1)
	{
	  error = VNET_API_ERROR_INVALID_VLAN_TAG_COUNT;	/* Need one or two tags */
	  goto done;
	}
      in_config->pop_bytes = 4;
      in_config->push_bytes = 4;
      in_config->tags[1].priority_cfi_and_id = vtr_tag1;
      in_config->tags[1].type = push_outer_et;
      break;

    case L2_VTR_TRANSLATE_1_2:
      if (cfg_tags < 1)
	{
	  error = VNET_API_ERROR_INVALID_VLAN_TAG_COUNT;	/* Need one or two tags */
	  goto done;
	}
      in_config->pop_bytes = 4;
      in_config->push_bytes = 8;
      in_config->tags[0].priority_cfi_and_id = vtr_tag1;
      in_config->tags[0].type = push_outer_et;
      in_config->tags[1].priority_cfi_and_id = vtr_tag2;
      in_config->tags[1].type = push_inner_et;
      break;

    case L2_VTR_TRANSLATE_2_1:
      if (cfg_tags < 2)
	{
	  error = VNET_API_ERROR_INVALID_VLAN_TAG_COUNT;	/* Need two tags */
	  goto done;
	}
      in_config->pop_bytes = 8;
      in_config->push_bytes = 4;
      in_config->tags[1].priority_cfi_and_id = vtr_tag1;
      in_config->tags[1].type = push_outer_et;
      break;

    case L2_VTR_TRANSLATE_2_2:
      if (cfg_tags < 2)
	{
	  error = VNET_API_ERROR_INVALID_VLAN_TAG_COUNT;	/* Need two tags */
	  goto done;
	}
      in_config->pop_bytes = 8;
      in_config->push_bytes = 8;
      in_config->tags[0].priority_cfi_and_id = vtr_tag1;
      in_config->tags[0].type = push_outer_et;
      in_config->tags[1].priority_cfi_and_id = vtr_tag2;
      in_config->tags[1].type = push_inner_et;
      break;
    }

  /*
   *  Construct the output tag-rewrite config
   *
   *  The push/pop values are always reversed
   */
  out_config->push_bytes = in_config->pop_bytes;
  out_config->pop_bytes = in_config->push_bytes;

  /* Any pushed tags are derived from the subinterface config */
  push_outer_et =
    clib_net_to_host_u16 (si->sub.eth.flags.dot1ad ? ETHERNET_TYPE_DOT1AD :
			  ETHERNET_TYPE_VLAN);
  push_inner_et = clib_net_to_host_u16 (ETHERNET_TYPE_VLAN);
  vtr_tag1 = clib_net_to_host_u16 (si->sub.eth.outer_vlan_id);
  vtr_tag2 = clib_net_to_host_u16 (si->sub.eth.inner_vlan_id);

  if (out_config->push_bytes == 4)
    {
      out_config->tags[1].priority_cfi_and_id = vtr_tag1;
      out_config->tags[1].type = push_outer_et;
    }
  else if (out_config->push_bytes == 8)
    {
      out_config->tags[0].priority_cfi_and_id = vtr_tag1;
      out_config->tags[0].type = push_outer_et;
      out_config->tags[1].priority_cfi_and_id = vtr_tag2;
      out_config->tags[1].type = push_inner_et;
    }

  /* set the interface enable flags */
  enable = (vtr_op != L2_VTR_DISABLED);
  config->out_vtr_flag = (u8) enable;
  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_VTR, enable);
  /* output vtr enable is checked explicitly in l2_output */

done:
  return error;
}

/**
 * Get vtag tag rewrite on the given interface.
 * Return 1 if there is an error, 0 if ok
 */
u32
l2vtr_get (vlib_main_t * vlib_main, vnet_main_t * vnet_main, u32 sw_if_index, u32 * vtr_op, u32 * push_dot1q,	/* ethertype of first pushed tag is dot1q/dot1ad */
	   u32 * vtr_tag1,	/* first pushed tag */
	   u32 * vtr_tag2)	/* second pushed tag */
{
  vnet_hw_interface_t *hi;
  u32 error = 0;
  vtr_config_t *in_config;

  if (!vtr_op || !push_dot1q || !vtr_tag1 || !vtr_tag2)
    {
      clib_warning ("invalid arguments");
      error = VNET_API_ERROR_INVALID_ARGUMENT;
      goto done;
    }

  *vtr_op = L2_VTR_DISABLED;
  *vtr_tag1 = 0;
  *vtr_tag2 = 0;
  *push_dot1q = 0;

  hi = vnet_get_sup_hw_interface (vnet_main, sw_if_index);
  if (!hi || (hi->hw_class_index != ethernet_hw_interface_class.index))
    {
      /* non-ethernet interface */
      goto done;
    }

  if (sw_if_index >= vec_len (l2output_main.configs))
    {
      /* no specific config (return disabled) */
      goto done;
    }

  /* Get the config for this interface */
  in_config =
    &(vec_elt_at_index (l2output_main.configs, sw_if_index)->input_vtr);

  /* DISABLED */
  if (in_config->push_and_pop_bytes == 0)
    {
      goto done;
    }

  /* find out vtr_op */
  switch (in_config->pop_bytes)
    {
    case 0:
      switch (in_config->push_bytes)
	{
	case 0:
	  /* DISABLED */
	  goto done;
	case 4:
	  *vtr_op = L2_VTR_PUSH_1;
	  *vtr_tag1 =
	    clib_host_to_net_u16 (in_config->tags[1].priority_cfi_and_id);
	  *push_dot1q =
	    (ETHERNET_TYPE_VLAN ==
	     clib_host_to_net_u16 (in_config->tags[1].type));
	  break;
	case 8:
	  *vtr_op = L2_VTR_PUSH_2;
	  *vtr_tag1 =
	    clib_host_to_net_u16 (in_config->tags[0].priority_cfi_and_id);
	  *vtr_tag2 =
	    clib_host_to_net_u16 (in_config->tags[1].priority_cfi_and_id);
	  *push_dot1q =
	    (ETHERNET_TYPE_VLAN ==
	     clib_host_to_net_u16 (in_config->tags[0].type));
	  break;
	default:
	  clib_warning ("invalid push_bytes count: %d",
			in_config->push_bytes);
	  error = VNET_API_ERROR_UNEXPECTED_INTF_STATE;
	  goto done;
	}
      break;

    case 4:
      switch (in_config->push_bytes)
	{
	case 0:
	  *vtr_op = L2_VTR_POP_1;
	  break;
	case 4:
	  *vtr_op = L2_VTR_TRANSLATE_1_1;
	  *vtr_tag1 =
	    clib_host_to_net_u16 (in_config->tags[1].priority_cfi_and_id);
	  *push_dot1q =
	    (ETHERNET_TYPE_VLAN ==
	     clib_host_to_net_u16 (in_config->tags[1].type));
	  break;
	case 8:
	  *vtr_op = L2_VTR_TRANSLATE_1_2;
	  *vtr_tag1 =
	    clib_host_to_net_u16 (in_config->tags[0].priority_cfi_and_id);
	  *vtr_tag2 =
	    clib_host_to_net_u16 (in_config->tags[1].priority_cfi_and_id);
	  *push_dot1q =
	    (ETHERNET_TYPE_VLAN ==
	     clib_host_to_net_u16 (in_config->tags[0].type));
	  break;
	default:
	  clib_warning ("invalid push_bytes count: %d",
			in_config->push_bytes);
	  error = VNET_API_ERROR_UNEXPECTED_INTF_STATE;
	  goto done;
	}
      break;

    case 8:
      switch (in_config->push_bytes)
	{
	case 0:
	  *vtr_op = L2_VTR_POP_2;
	  break;
	case 4:
	  *vtr_op = L2_VTR_TRANSLATE_2_1;
	  *vtr_tag1 =
	    clib_host_to_net_u16 (in_config->tags[1].priority_cfi_and_id);
	  *push_dot1q =
	    (ETHERNET_TYPE_VLAN ==
	     clib_host_to_net_u16 (in_config->tags[1].type));
	  break;
	case 8:
	  *vtr_op = L2_VTR_TRANSLATE_2_2;
	  *vtr_tag1 =
	    clib_host_to_net_u16 (in_config->tags[0].priority_cfi_and_id);
	  *vtr_tag2 =
	    clib_host_to_net_u16 (in_config->tags[1].priority_cfi_and_id);
	  *push_dot1q =
	    (ETHERNET_TYPE_VLAN ==
	     clib_host_to_net_u16 (in_config->tags[0].type));
	  break;
	default:
	  clib_warning ("invalid push_bytes count: %d",
			in_config->push_bytes);
	  error = VNET_API_ERROR_UNEXPECTED_INTF_STATE;
	  goto done;
	}
      break;

    default:
      clib_warning ("invalid pop_bytes count: %d", in_config->pop_bytes);
      error = VNET_API_ERROR_UNEXPECTED_INTF_STATE;
      goto done;
    }

done:
  return error;
}

/**
 * Set subinterface vtr enable/disable.
 * The CLI format is:
 *    set interface l2 tag-rewrite <interface> [disable | pop 1 | pop 2 | push {dot1q|dot1ad} <tag> [<tag>]]
 *
 *  "push" can also be replaced by "translate-{1|2}-{1|2}"
 */
static clib_error_t *
int_l2_vtr (vlib_main_t * vm,
	    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 vtr_op;
  u32 push_dot1q = 0;
  u32 tag1 = 0, tag2 = 0;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  vtr_op = L2_VTR_DISABLED;

  if (unformat (input, "disable"))
    {
      vtr_op = L2_VTR_DISABLED;
    }
  else if (unformat (input, "pop 1"))
    {
      vtr_op = L2_VTR_POP_1;
    }
  else if (unformat (input, "pop 2"))
    {
      vtr_op = L2_VTR_POP_2;

    }
  else if (unformat (input, "push dot1q %d %d", &tag1, &tag2))
    {
      vtr_op = L2_VTR_PUSH_2;
      push_dot1q = 1;
    }
  else if (unformat (input, "push dot1ad %d %d", &tag1, &tag2))
    {
      vtr_op = L2_VTR_PUSH_2;

    }
  else if (unformat (input, "push dot1q %d", &tag1))
    {
      vtr_op = L2_VTR_PUSH_1;
      push_dot1q = 1;
    }
  else if (unformat (input, "push dot1ad %d", &tag1))
    {
      vtr_op = L2_VTR_PUSH_1;

    }
  else if (unformat (input, "translate 1-1 dot1q %d", &tag1))
    {
      vtr_op = L2_VTR_TRANSLATE_1_1;
      push_dot1q = 1;
    }
  else if (unformat (input, "translate 1-1 dot1ad %d", &tag1))
    {
      vtr_op = L2_VTR_TRANSLATE_1_1;

    }
  else if (unformat (input, "translate 2-1 dot1q %d", &tag1))
    {
      vtr_op = L2_VTR_TRANSLATE_2_1;
      push_dot1q = 1;
    }
  else if (unformat (input, "translate 2-1 dot1ad %d", &tag1))
    {
      vtr_op = L2_VTR_TRANSLATE_2_1;

    }
  else if (unformat (input, "translate 2-2 dot1q %d %d", &tag1, &tag2))
    {
      vtr_op = L2_VTR_TRANSLATE_2_2;
      push_dot1q = 1;
    }
  else if (unformat (input, "translate 2-2 dot1ad %d %d", &tag1, &tag2))
    {
      vtr_op = L2_VTR_TRANSLATE_2_2;

    }
  else if (unformat (input, "translate 1-2 dot1q %d %d", &tag1, &tag2))
    {
      vtr_op = L2_VTR_TRANSLATE_1_2;
      push_dot1q = 1;
    }
  else if (unformat (input, "translate 1-2 dot1ad %d %d", &tag1, &tag2))
    {
      vtr_op = L2_VTR_TRANSLATE_1_2;

    }
  else
    {
      error =
	clib_error_return (0,
			   "expecting [disable | pop 1 | pop 2 | push {dot1q|dot1ah} <tag> [<tag>]\n"
			   " | translate {1|2}-{1|2} {dot1q|dot1ah} <tag> [<tag>]] but got `%U'",
			   format_unformat_error, input);
      goto done;
    }

  if (l2vtr_configure (vm, vnm, sw_if_index, vtr_op, push_dot1q, tag1, tag2))
    {
      error =
	clib_error_return (0,
			   "vlan tag rewrite is not compatible with interface");
      goto done;
    }

done:
  return error;
}

/*?
 * VLAN tag rewrite provides the ability to change the VLAN tags on a packet.
 * Existing tags can be popped, new tags can be pushed, and existing tags can
 * be swapped with new tags. The rewrite feature is attached to a subinterface
 * as input and output operations. The input operation is explicitly configured.
 * The output operation is the symmetric opposite and is automatically derived
 * from the input operation.
 *
 * <b>POP:</b> For pop operations, the subinterface encapsulation (the vlan
 * tags specified when it was created) must have at least the number of popped
 * tags. e.g. the \"pop 2\" operation would be rejected on a single-vlan interface.
 * The output tag-rewrite operation for pops is to push the specified number of
 * vlan tags onto the packet. The pushed tag values are the ones in the
 * subinterface encapsulation.
 *
 * <b>PUSH:</b> For push operations, the ethertype is also specified. The
 * output tag-rewrite operation for pushes is to pop the same number of tags
 * off the packet. If the packet doesn't have enough tags it is dropped.
 *
 *
 * @cliexpar
 * @parblock
 * By default a subinterface has no tag-rewrite. To return a subinterface to
 * this state use:
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 disable}
 *
 * To pop vlan tags off packets received from a subinterface, use:
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 pop 1}
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 pop 2}
 *
 * To push one or two vlan tags onto packets received from an interface, use:
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 push dot1q 100}
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 push dot1ad 100 150}
 *
 * Tags can also be translated, which is basically a combination of a pop and push.
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 translate 1-1 dot1ad 100}
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 translate 2-2 dot1ad 100 150}
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 translate 1-2 dot1q 100}
 * @cliexcmd{set interface l2 tag-rewrite GigabitEthernet0/8/0.200 translate 2-1 dot1q 100 150}
 *
 * To display the VLAN Tag settings, show the associate bridge-domain:
 * @cliexstart{show bridge-domain 200 detail}
 *  ID   Index   Learning   U-Forwrd   UU-Flood   Flooding   ARP-Term     BVI-Intf
 * 200     1        on         on         on         on         off          N/A
 *
 *          Interface           Index  SHG  BVI        VLAN-Tag-Rewrite
 *  GigabitEthernet0/8/0.200      5     0    -       trans-1-1 dot1ad 100
 *  GigabitEthernet0/9/0.200      4     0    -               none
 *  GigabitEthernet0/a/0.200      6     0    -               none
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_vtr_cli, static) = {
  .path = "set interface l2 tag-rewrite",
  .short_help = "set interface l2 tag-rewrite <interface> [disable | pop {1|2} | push {dot1q|dot1ad} <tag> <tag>]",
  .function = int_l2_vtr,
};
/* *INDENT-ON* */

/**
 * Get pbb tag rewrite on the given interface.
 * Return 1 if there is an error, 0 if ok
 */
u32
l2pbb_get (vlib_main_t * vlib_main, vnet_main_t * vnet_main, u32 sw_if_index,
	   u32 * vtr_op, u16 * outer_tag, ethernet_header_t * eth_hdr,
	   u16 * b_vlanid, u32 * i_sid)
{
  u32 error = 1;
  ptr_config_t *in_config;

  if (!vtr_op || !outer_tag || !b_vlanid || !i_sid)
    {
      clib_warning ("invalid arguments");
      error = VNET_API_ERROR_INVALID_ARGUMENT;
      goto done;
    }

  *vtr_op = L2_VTR_DISABLED;
  *outer_tag = 0;
  *b_vlanid = 0;
  *i_sid = 0;

  if (sw_if_index >= vec_len (l2output_main.configs))
    {
      /* no specific config (return disabled) */
      goto done;
    }

  /* Get the config for this interface */
  in_config =
    &(vec_elt_at_index (l2output_main.configs, sw_if_index)->input_pbb_vtr);

  if (in_config->push_and_pop_bytes == 0)
    {
      /* DISABLED */
      goto done;
    }
  else
    {
      if (in_config->pop_bytes && in_config->push_bytes)
	*vtr_op = L2_VTR_TRANSLATE_2_1;
      else if (in_config->pop_bytes)
	*vtr_op = L2_VTR_POP_2;
      else if (in_config->push_bytes)
	*vtr_op = L2_VTR_PUSH_2;

      clib_memcpy (&eth_hdr->dst_address, in_config->macs_tags.b_dst_address,
		   sizeof (eth_hdr->dst_address));
      clib_memcpy (&eth_hdr->src_address, in_config->macs_tags.b_src_address,
		   sizeof (eth_hdr->src_address));

      *b_vlanid =
	clib_host_to_net_u16 (in_config->macs_tags.priority_dei_id) & 0xFFF;
      *i_sid =
	clib_host_to_net_u32 (in_config->macs_tags.
			      priority_dei_uca_res_sid) & 0xFFFFF;
      error = 0;
    }
done:
  return error;
}

/**
 * Set subinterface pbb vtr enable/disable.
 * The CLI format is:
 *    set interface l2 pbb-tag-rewrite <interface> [disable | pop | push | translate_pbb_stag <outer_tag> dmac <address> smac <address> s_id <nn> [b_vlanid <nn>]]
 */
static clib_error_t *
int_l2_pbb_vtr (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index, tmp;
  u32 vtr_op = L2_VTR_DISABLED;
  u32 outer_tag = 0;
  u8 dmac[6];
  u8 smac[6];
  u8 dmac_set = 0, smac_set = 0;
  u16 b_vlanid = 0;
  u32 s_id = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user
	  (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (input, "disable"))
	vtr_op = L2_VTR_DISABLED;
      else if (vtr_op == L2_VTR_DISABLED && unformat (input, "pop"))
	vtr_op = L2_VTR_POP_2;
      else if (vtr_op == L2_VTR_DISABLED && unformat (input, "push"))
	vtr_op = L2_VTR_PUSH_2;
      else if (vtr_op == L2_VTR_DISABLED
	       && unformat (input, "translate_pbb_stag %d", &outer_tag))
	vtr_op = L2_VTR_TRANSLATE_2_1;
      else if (unformat (input, "dmac %U", unformat_ethernet_address, dmac))
	dmac_set = 1;
      else if (unformat (input, "smac %U", unformat_ethernet_address, smac))
	smac_set = 1;
      else if (unformat (input, "b_vlanid %d", &tmp))
	b_vlanid = tmp;
      else if (unformat (input, "s_id %d", &s_id))
	;
      else
	{
	  error = clib_error_return (0,
				     "expecting [disable | pop | push | translate_pbb_stag <outer_tag>\n"
				     "dmac <address> smac <address> s_id <nn> [b_vlanid <nn>]]");
	  goto done;
	}
    }

  if ((vtr_op == L2_VTR_PUSH_2 || vtr_op == L2_VTR_TRANSLATE_2_1)
      && (!dmac_set || !smac_set || s_id == ~0))
    {
      error = clib_error_return (0,
				 "expecting dmac <address> smac <address> s_id <nn> [b_vlanid <nn>]");
      goto done;
    }

  if (l2pbb_configure
      (vm, vnm, sw_if_index, vtr_op, dmac, smac, b_vlanid, s_id, outer_tag))
    {
      error =
	clib_error_return (0,
			   "pbb tag rewrite is not compatible with interface");
      goto done;
    }

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_pbb_vtr_cli, static) = {
  .path = "set interface l2 pbb-tag-rewrite",
  .short_help = "set interface l2 pbb-tag-rewrite <interface> [disable | pop | push | translate_pbb_stag <outer_tag> dmac <address> smac <address> s_id <nn> [b_vlanid <nn>]]",
  .function = int_l2_pbb_vtr,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
