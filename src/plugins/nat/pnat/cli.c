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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/pool.h>
#include "pnat.h"
#include <vnet/ip/ip4.h>

/*
 * This file contains the handlers for the (unsupported) VPP debug CLI.
 */
u8 *
format_pnat_5tuple (u8 * s, va_list * args)
{
  pnat_5tuple_t *t = va_arg (*args, pnat_5tuple_t *);
  s = format(s, "{");
  if (t->mask & PNAT_SA)
    s = format(s, "%U", format_ip4_address, &t->src);
  else
    s = format(s, "*");
  if (t->mask & PNAT_SPORT)
    s = format(s, ":%u,", t->sport);
  else
    s = format(s, ":*,");
  if (t->proto > 0)
    s = format(s, "%U,", format_ip_protocol, t->proto);
  else
    s = format(s, "*,");
  if (t->mask & PNAT_DA)
    s = format(s, "%U", format_ip4_address, &t->dst);
  else
    s = format(s, "*");
  if (t->mask & PNAT_DPORT)
    s = format(s, ":%u", t->dport);
  else
    s = format(s, ":*");
  s = format(s, "}");
  return s;
}

u8 *
format_pnat_key (u8 * s, va_list * args)
{
  pnat_key_t *k = va_arg (*args, pnat_key_t *);
  s = format(s, "[%u] %s %U:%u -> %U:%u, proto: %U",
             k->sw_if_index,
             k->input ? "input" : "output",
             format_ip4_address, &k->sa, k->sp,
             format_ip4_address, &k->da, k->dp,
             format_ip_protocol, k->proto);
  return s;
}

static u8 *
format_pnat_translation (u8 * s, va_list * args)
{
  u32 index = va_arg (*args, u32);
  pnat_translation_t *t = va_arg (*args, pnat_translation_t *);
  s = format (s, "[%d, %d, %d] %s match: %U rewrite: %U",
              index, t->fib_index, t->key.sw_if_index,
              t->key.input ? "input" : "output",
              format_pnat_5tuple, &t->match,
              format_pnat_5tuple, &t->rewrite);
  return s;
}

static u8 *
format_pnat_mask (u8 * s, va_list * args)
{
  pnat_mask_t t = va_arg (*args, pnat_mask_t);
  if (t & PNAT_SA)
    s = format(s, "SA ");
  if (t & PNAT_SPORT)
    s = format(s, "SP ");
  if (t & PNAT_DA)
    s = format(s, "DA ");
  if (t & PNAT_DPORT)
    s = format(s, "DP");
  return s;
}

static u8 *
format_pnat_interface (u8 * s, va_list * args)
{
  pnat_interface_t *interface = va_arg (*args, pnat_interface_t *);
  s = format (s, "sw_if_index: %d",
              interface->sw_if_index);
  if (interface->input_enabled) {
    s = format (s, " input mask: %U",
                format_pnat_mask, interface->input_lookup_mask);
  }
  if (interface->output_enabled) {
    s = format (s, " output mask: %U",
                format_pnat_mask, interface->output_lookup_mask);
  }
  return s;
}

uword
unformat_pnat_5tuple (unformat_input_t *input, va_list *args)
{
  pnat_5tuple_t *t = va_arg (*args, pnat_5tuple_t *);
  u32 dport, sport;
  while (1) {
    if (unformat(input, "src %U", unformat_ip4_address, &t->src))
      t->mask |= PNAT_SA;
    else if (unformat(input, "dst %U", unformat_ip4_address, &t->dst))
      t->mask |= PNAT_DA;
    else if (unformat(input, "sport %d", &sport)) {
      if (sport < 0 || sport > 65535) return 0;
      t->mask |= PNAT_SPORT;
      t->sport = sport;
    } else if (unformat(input, "dport %d", &dport)) {
      if (dport < 0 || dport > 65535) return 0;
      t->mask |= PNAT_DPORT;
      t->dport = dport;
    } else if (unformat(input, "proto %U", unformat_ip_protocol, &t->proto))
      ;
    else
      break;
  }
  return 1;
}

int pnat_add_translation (u32 sw_if_index, pnat_5tuple_t *match, pnat_5tuple_t *rewrite, bool input, u32 *index);

static clib_error_t *
set_pnat_translation_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  bool in = false, out = false;
  bool match_set = false, rewrite_set = false;
  u32 sw_if_index = ~0;
  pnat_5tuple_t match = {0};
  pnat_5tuple_t rewrite = {0};

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "match %U", unformat_pnat_5tuple, &match))
      match_set = true;
    else if (unformat(line_input, "rewrite %U", unformat_pnat_5tuple, &rewrite))
      rewrite_set = true;
    else if (unformat(line_input, "interface %U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
      ;
    else if (unformat(line_input, "in")) {
      in = true;
    } else if (unformat(line_input, "out")) {
      out = true;
    } else {
        error = clib_error_return (0, "unknown input `%U'",
                                   format_unformat_error, line_input);
        goto done;
    }
  }
  if (sw_if_index == ~0) {
    error = clib_error_return (0, "interface is required `%U'",
                               format_unformat_error, line_input);
    goto done;
  }
  if ((in && out) || (!in && !out)) {
    error = clib_error_return (0, "in or out is required `%U'",
                               format_unformat_error, line_input);
    goto done;
  }
  if (!match_set) {
    error = clib_error_return (0, "missing parameter: match `%U'",
                               format_unformat_error, line_input);
    goto done;
  }
  if (!rewrite_set) {
    error = clib_error_return (0, "missing parameter: rewrite `%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  if ((match.dport || match.sport) &&
      (match.proto != 17 && match.proto != 6)) {
    error = clib_error_return (0, "missing protocol (TCP|UDP): match `%U'",
                               format_unformat_error, line_input);
    goto done;
  }

  u32 index;
  int rv = pnat_add_translation(sw_if_index, &match, &rewrite, in, &index);
  if (rv) {
    error = clib_error_return (0, "pnat_add_translation failed %d", rv);
  }

done:
  unformat_free(line_input);

  return error;
}

VLIB_CLI_COMMAND(set_pnat_translation_command, static) = {
  .path = "set pnat translation",
  .short_help = "set pnat translation interface <name> match <5-tuple> rewrite <5-tuple> [in|out]",
  .function = set_pnat_translation_command_fn,
};

int pnat_del_translation (u32 index);

static clib_error_t *
unset_pnat_translation_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 index;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "%u", &index))
      ;
    else {
        error = clib_error_return (0, "unknown input `%U'",
                                   format_unformat_error, line_input);
        goto done;
    }
  }

done:
  unformat_free(line_input);

  int rv = pnat_del_translation(index);
  if (rv) {
    error = clib_error_return (0, "pnat_del_translation failed %d", rv);
  }
  return error;
}

VLIB_CLI_COMMAND(unset_pnat_translation_command, static) = {
  .path = "unset pnat translation",
  .short_help = "unset pnat translation <index>",
  .function = unset_pnat_translation_command_fn,
};

static clib_error_t *
show_pnat_translations_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  pnat_main_t *pm = &pnat_main;
  pnat_translation_t *s;
  clib_error_t *error = 0;

  /* Get a line of input. */
  pool_foreach(s, pm->translations) {
    vlib_cli_output(vm, "%U", format_pnat_translation,
                    s - pm->translations, s);
  }
  return error;
}

VLIB_CLI_COMMAND(show_pnat_translations_command, static) = {
  .path = "show pnat translations",
  .short_help = "show pnat translations",
  .function = show_pnat_translations_command_fn,
};

static clib_error_t *
show_pnat_interfaces_command_fn (vlib_main_t * vm, unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  pnat_main_t *pm = &pnat_main;
  pnat_interface_t *interface;
  clib_error_t *error = 0;

  /* Get a line of input. */
  pool_foreach(interface, pm->interfaces) {
    vlib_cli_output(vm, "%U", format_pnat_interface,
                    interface);
  }
  return error;
}

VLIB_CLI_COMMAND(show_pnat_interfaces_command, static) = {
  .path = "show pnat interfaces",
  .short_help = "show pnat interfaces",
  .function = show_pnat_interfaces_command_fn,
};
