/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

/**
 * @file
 * @brief SR Path Tracing (PT)
 *
 * SR PT CLI
 *
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/srv6/sr.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj.h>
#include <vnet/srv6/sr_pt.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

sr_pt_main_t sr_pt_main;

void *
sr_pt_find_iface (u32 iface)
{
  sr_pt_main_t *sr_pt = &sr_pt_main;
  uword *p;

  /* Search for the item */
  p = mhash_get (&sr_pt->sr_pt_iface_index_hash, &iface);
  if (p)
    {
      /* Retrieve sr_pt_iface */
      return pool_elt_at_index (sr_pt->sr_pt_iface, p[0]);
    }
  return NULL;
}

int
sr_pt_add_iface (u32 iface, u16 id, u8 ingress_load, u8 egress_load,
		 u8 tts_template)
{
  sr_pt_main_t *sr_pt = &sr_pt_main;
  uword *p;

  sr_pt_iface_t *ls = 0;

  if (iface == (u32) ~0)
    return SR_PT_ERR_IFACE_INVALID;

  /* Search for the item */
  p = mhash_get (&sr_pt->sr_pt_iface_index_hash, &iface);

  if (p)
    return SR_PT_ERR_EXIST;

  if (id > SR_PT_ID_MAX)
    return SR_PT_ERR_ID_INVALID;

  if (ingress_load > SR_PT_LOAD_MAX || egress_load > SR_PT_LOAD_MAX)
    return SR_PT_ERR_LOAD_INVALID;

  if (tts_template > SR_PT_TTS_TEMPLATE_MAX)
    return SR_PT_ERR_TTS_TEMPLATE_INVALID;

  vnet_feature_enable_disable ("ip6-output", "pt", iface, 1, 0, 0);

  /* Create a new sr_pt_iface */
  pool_get_zero (sr_pt->sr_pt_iface, ls);
  ls->iface = iface;
  ls->id = id;
  ls->ingress_load = ingress_load;
  ls->egress_load = egress_load;
  ls->tts_template = tts_template;

  /* Set hash key for searching sr_pt_iface by iface */
  mhash_set (&sr_pt->sr_pt_iface_index_hash, &iface, ls - sr_pt->sr_pt_iface,
	     NULL);
  return 0;
}

int
sr_pt_del_iface (u32 iface)
{
  sr_pt_main_t *sr_pt = &sr_pt_main;
  uword *p;

  sr_pt_iface_t *ls = 0;

  if (iface == (u32) ~0)
    return SR_PT_ERR_IFACE_INVALID;

  /* Search for the item */
  p = mhash_get (&sr_pt->sr_pt_iface_index_hash, &iface);

  if (p)
    {
      /* Retrieve sr_pt_iface */
      ls = pool_elt_at_index (sr_pt->sr_pt_iface, p[0]);
      vnet_feature_enable_disable ("ip6-output", "pt", iface, 0, 0, 0);
      /* Delete sr_pt_iface */
      pool_put (sr_pt->sr_pt_iface, ls);
      mhash_unset (&sr_pt->sr_pt_iface_index_hash, &iface, NULL);
    }
  else
    {
      return SR_PT_ERR_NOENT;
    }
  return 0;
}

void *
sr_pt_find_probe_inject_iface (u32 iface)
{
  sr_pt_main_t *sr_pt = &sr_pt_main;
  uword *p;

  /* Search for the item */
  p = mhash_get (&sr_pt->sr_pt_probe_inject_iface_index_hash, &iface);
  if (p)
    {
      /* Retrieve sr_pt_probe_inject_iface */
      return pool_elt_at_index (sr_pt->sr_pt_probe_inject_iface, p[0]);
    }
  return NULL;
}

int
sr_pt_add_probe_inject_iface (u32 iface)
{
  sr_pt_main_t *sr_pt = &sr_pt_main;
  uword *p;

  sr_pt_probe_inject_iface_t *ls = 0;

  if (iface == (u32) ~0)
    return SR_PT_ERR_IFACE_INVALID;

  /* Search for the item */
  p = mhash_get (&sr_pt->sr_pt_probe_inject_iface_index_hash, &iface);

  if (p)
    return SR_PT_ERR_EXIST;

  /* Create a new pt probe-inject iface */
  pool_get_zero (sr_pt->sr_pt_probe_inject_iface, ls);
  clib_memset (ls, 0, sizeof (*ls));
  ls->iface = iface;

  /* Set hash key for searching sr_pt_iface by iface */
  mhash_set (&sr_pt->sr_pt_probe_inject_iface_index_hash, &iface,
       ls - sr_pt->sr_pt_probe_inject_iface, NULL);

  return 0;
}

int
sr_pt_del_probe_inject_iface (u32 iface)
{
  sr_pt_main_t *sr_pt = &sr_pt_main;
  uword *p;

  sr_pt_probe_inject_iface_t *ls = 0;

  if (iface == (u32) ~0)
    return SR_PT_ERR_IFACE_INVALID;
  
  /* Search for the item */
  p = mhash_get (&sr_pt->sr_pt_probe_inject_iface_index_hash, &iface);

  if (p)
  {
    /* Retrieve sr_pt_iface */
    ls = pool_elt_at_index (sr_pt->sr_pt_probe_inject_iface, p[0]);
    /* Delete sr_pt_iface */
    pool_put (sr_pt->sr_pt_probe_inject_iface, ls);
    mhash_unset (&sr_pt->sr_pt_probe_inject_iface_index_hash, &iface, NULL);
  }
  else
  {
    return SR_PT_ERR_NOENT;
  }
  return 0;
}

/**
 * @brief "sr pt add iface" CLI function.
 *
 * @see sr_pt_add_iface
 */
static clib_error_t *
sr_pt_add_iface_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 iface = (u32) ~0;
  u32 id = (u32) ~0;
  u32 ingress_load = 0;
  u32 egress_load = 0;
  u32 tts_template = SR_PT_TTS_TEMPLATE_DEFAULT;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &iface))
	;
      else if (unformat (input, "id %u", &id))
	;
      else if (unformat (input, "ingress-load %u", &ingress_load))
	;
      else if (unformat (input, "egress-load %u", &egress_load))
	;
      else if (unformat (input, "tts-template %u", &tts_template))
	;
      else
	break;
    }

  rv = sr_pt_add_iface (iface, id, ingress_load, egress_load, tts_template);

  switch (rv)
    {
    case 0:
      break;
    case SR_PT_ERR_EXIST:
      return clib_error_return (0, "Error: Identical iface already exists.");
    case SR_PT_ERR_IFACE_INVALID:
      return clib_error_return (0, "Error: The iface name invalid.");
    case SR_PT_ERR_ID_INVALID:
      return clib_error_return (0, "Error: The iface id value invalid.");
    case SR_PT_ERR_LOAD_INVALID:
      return clib_error_return (
	0, "Error: The iface ingress or egress load value invalid.");
    case SR_PT_ERR_TTS_TEMPLATE_INVALID:
      return clib_error_return (
	0, "Error: The iface TTS Template value invalid.");
    default:
      return clib_error_return (0, "Error: unknown error.");
    }
  return 0;
}

/**
 * @brief "sr pt del iface" CLI function.
 *
 * @see sr_pt_del_iface
 */
static clib_error_t *
sr_pt_del_iface_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 iface = (u32) ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &iface))
	;
      else
	break;
    }

  rv = sr_pt_del_iface (iface);

  switch (rv)
    {
    case 0:
      break;
    case SR_PT_ERR_NOENT:
      return clib_error_return (0, "Error: No such iface.");
    case SR_PT_ERR_IFACE_INVALID:
      return clib_error_return (0, "Error: The iface name is not valid.");
    default:
      return clib_error_return (0, "Error: unknown error.");
    }
  return 0;
}

/**
 * @brief CLI function to show all SR PT interfcaes
 */
static clib_error_t *
sr_pt_show_iface_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  sr_pt_main_t *sr_pt = &sr_pt_main;
  sr_pt_iface_t **sr_pt_iface_list = 0;
  sr_pt_iface_t *ls;
  int i;

  vlib_cli_output (vm, "SR PT Interfaces");
  vlib_cli_output (vm, "==================================");

  pool_foreach (ls, sr_pt->sr_pt_iface)
    {
      vec_add1 (sr_pt_iface_list, ls);
    };

  for (i = 0; i < vec_len (sr_pt_iface_list); i++)
    {
      ls = sr_pt_iface_list[i];
      vlib_cli_output (
	vm,
	"\tiface       : \t%U\n\tid          : \t%d\n\tingress-load: "
	"\t%d\n\tegress-load : \t%d\n\ttts-template: \t%d  ",
	format_vnet_sw_if_index_name, vnm, ls->iface, ls->id, ls->ingress_load,
	ls->egress_load, ls->tts_template);
      vlib_cli_output (vm, "--------------------------------");
    }

  return 0;
}

/**
  * @brief "sr pt add probe-inject-iface" CLI function.
  *
  * @see sr_pt_add_probe_inject_iface
*/
static clib_error_t *
sr_pt_add_probe_inject_iface_command_fn (vlib_main_t *vm,
            unformat_input_t *input,
            vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 iface = (u32) ~ 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &iface))
	;
      else
	break;
    }

  rv = sr_pt_add_probe_inject_iface (iface);

  switch (rv)
    {
    case 0:
      break;
    case SR_PT_ERR_EXIST:
      return clib_error_return (0, "Error: Identical iface already exists.");
    case SR_PT_ERR_IFACE_INVALID:
      return clib_error_return (0,"Error: The iface name is not valid.");
    default:
      return clib_error_return (0, "Error: unknown error.");
    }

  return 0;
}

/**
 * @brief "sr pt del probe-inject-iface" CLI function.
 *
 */
static clib_error_t *
sr_pt_del_probe_inject_iface_command_fn (vlib_main_t *vm,
            unformat_input_t *input,
            vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 iface = (u32) ~ 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iface %U",
       unformat_vnet_sw_interface, vnm, &iface))
  ;
      else
  break;
    }

  rv = sr_pt_del_probe_inject_iface (iface);

  switch (rv)
    {
    case 0:
      break;
    case SR_PT_ERR_NOENT:
      return clib_error_return (0, "Error: No such iface.");
    case SR_PT_ERR_IFACE_INVALID:
      return clib_error_return (0, "Error: The iface name is not valid.");
    default:
      return clib_error_return (0, "Error: unknown error.");
    }

  return 0;
}

/**
 * @brief CLI function to show SR PT probe-inject interfaces
 *
*/
static clib_error_t *
sr_pt_show_probe_inject_iface_command_fn (vlib_main_t *vm,
            unformat_input_t *input,
            vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  sr_pt_main_t *sr_pt = &sr_pt_main;
  sr_pt_probe_inject_iface_t **sr_pt_probe_inject_iface_list = 0;
  sr_pt_probe_inject_iface_t *ls;
  int i;

  vlib_cli_output (vm, "SR PT probe-inject interfaces:");
  vlib_cli_output (vm, "==================================");

  /* *INDENT-OFF* */
  pool_foreach (ls, sr_pt->sr_pt_probe_inject_iface) { vec_add1 (sr_pt_probe_inject_iface_list, ls); };
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (sr_pt_probe_inject_iface_list); i++)
    {
      ls = sr_pt_probe_inject_iface_list[i];
      vlib_cli_output (vm, "\tiface   : \t%U",
		       format_vnet_sw_if_index_name, vnm, ls->iface);
      vlib_cli_output (vm, "----------------------------------");
    }

  return 0;
}

VLIB_CLI_COMMAND (sr_pt_add_iface_command, static) = {
  .path = "sr pt add iface",
  .short_help = "sr pt add iface <iface-name> id <pt-iface-id> ingress-load "
		"<ingress-load-value> egress-load <egress-load-value> "
		"tts-template <tts-template-value>",
  .function = sr_pt_add_iface_command_fn,
};

VLIB_CLI_COMMAND (sr_pt_del_iface_command, static) = {
  .path = "sr pt del iface",
  .short_help = "sr pt del iface <iface-name>",
  .function = sr_pt_del_iface_command_fn,
};

VLIB_CLI_COMMAND (sr_pt_show_iface_command, static) = {
  .path = "sr pt show iface",
  .short_help = "sr pt show iface",
  .function = sr_pt_show_iface_command_fn,
};

VLIB_CLI_COMMAND (sr_pt_add_probe_inject_iface_command, static) = {
  .path = "sr pt add probe-inject-iface",
  .short_help = "sr pt add probe-inject-iface <iface-name>",
  .function = sr_pt_add_probe_inject_iface_command_fn,
};

VLIB_CLI_COMMAND (sr_pt_del_probe_inject_iface_command, static) = {
  .path = "sr pt del probe-inject-iface",
  .short_help = "sr pt del probe-inject-iface <iface-name>",
  .function = sr_pt_del_probe_inject_iface_command_fn,
};

VLIB_CLI_COMMAND (sr_pt_show_probe_inject_iface_command, static) = {
  .path = "sr pt show probe-inject-iface",
  .short_help = "sr pt show probe-inject-iface",
  .function = sr_pt_show_probe_inject_iface_command_fn,
};

/**
 *  * @brief SR PT initialization
 *   */
clib_error_t *
sr_pt_init (vlib_main_t *vm)
{
  sr_pt_main_t *pt = &sr_pt_main;
  mhash_init (&pt->sr_pt_iface_index_hash, sizeof (uword), sizeof (u32));
  mhash_init (&pt->sr_pt_probe_inject_iface_index_hash, sizeof (uword),
        sizeof (u32));
  return 0;
}

VLIB_INIT_FUNCTION (sr_pt_init);