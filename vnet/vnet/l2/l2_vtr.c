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


/** Just a placeholder; ensures file is not eliminated by linker. */
clib_error_t *
l2_vtr_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (l2_vtr_init);


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
  in_config =
    &(vec_elt_at_index (l2output_main.configs, sw_if_index)->input_vtr);
  out_config =
    &(vec_elt_at_index (l2output_main.configs, sw_if_index)->output_vtr);
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

      out_config->push_bytes = in_config->pop_bytes;
      out_config->pop_bytes = in_config->push_bytes;
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_vtr_cli, static) = {
  .path = "set interface l2 tag-rewrite",
  .short_help = "set interface l2 tag-rewrite <interface> [disable | pop {1|2} | push {dot1q|dot1ad} <tag> <tag>]",
  .function = int_l2_vtr,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
