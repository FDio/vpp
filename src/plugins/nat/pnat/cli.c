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

VLIB_CLI_COMMAND(show_pnat_translations_command, static) = {
  .path = "show pnat translations",
  .short_help = "show pnat translations",
  .function = show_pnat_translations_command_fn,
};

VLIB_CLI_COMMAND(show_pnat_interfaces_command, static) = {
  .path = "show pnat interfaces",
  .short_help = "show pnat interfaces",
  .function = show_pnat_interfaces_command_fn,
};
