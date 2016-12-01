/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/ip/ip6_hop_by_hop.h>
#include "ip6_ioam_e2e.h"

ioam_e2e_main_t ioam_e2e_main;

static u8 * ioam_e2e_trace_handler (u8 * s,
                                    ip6_hop_by_hop_option_t *opt)
{
  ioam_e2e_option_t * e2e = (ioam_e2e_option_t *)opt;
  u32 seqno = 0;

  if (e2e)
    {
      seqno = clib_net_to_host_u32 (e2e->e2e_hdr.e2e_data);
    }

  s = format (s, "SeqNo = 0x%Lx", seqno);
  return s;
}

int 
ioam_e2e_config_handler (void *data, u8 disable)
{
  int *analyse = data;

  /* Register hanlders if enabled */
  if (!disable)
    {
      /* If encap node register for encap handler */
      if (0 == *analyse)
        {
          if (ip6_hbh_register_option(HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE,
                                      ioam_seqno_encap_handler,
                                      ioam_e2e_trace_handler) < 0)
            {
              return (-1);
            }
        }
      /* If analyze node then register for decap handler */
      else
        {
          if (ip6_hbh_pop_register_option(HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE,
                                          ioam_seqno_decap_handler) < 0)
            {
              return (-1);
            }
        }
      return 0;
    }

  /* UnRegister handlers */
  (void) ip6_hbh_unregister_option(HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE);
  (void) ip6_hbh_pop_unregister_option(HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE);
  return 0;
}

int
ioam_e2e_rewrite_handler (u8 *rewrite_string,
                          u8 *rewrite_size)
{
  ioam_e2e_option_t *e2e_option;

  if (rewrite_string && *rewrite_size == sizeof(ioam_e2e_option_t))
    {
      e2e_option = (ioam_e2e_option_t *)rewrite_string;
      e2e_option->hdr.type = HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE
          | HBH_OPTION_TYPE_SKIP_UNKNOWN;
      e2e_option->hdr.length = sizeof (ioam_e2e_option_t) -
          sizeof (ip6_hop_by_hop_option_t);
      return(0);
    }
  return(-1);
}

u32
ioam_e2e_flow_handler (u32 ctx, u8 add)
{
  ioam_e2e_data_t *data;
  u16 i;

  if (add)
    {
      pool_get(ioam_e2e_main.e2e_data, data);
      data->flow_ctx =  ctx;
      ioam_seqno_init_data(&data->seqno_data);
      return ((u32) (data - ioam_e2e_main.e2e_data));
    }

  /* Delete case */
  for (i = 0; i < vec_len(ioam_e2e_main.e2e_data); i++)
    {
      if (pool_is_free_index(ioam_e2e_main.e2e_data, i))
        continue;

      data = pool_elt_at_index(ioam_e2e_main.e2e_data, i);
      if (data && (data->flow_ctx == ctx))
        {
          pool_put_index(ioam_e2e_main.e2e_data, i);
          return (0);
        }
    }
  return 0;
}

static clib_error_t *
ioam_show_e2e_cmd_fn (vlib_main_t * vm,
                      unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  ioam_e2e_data_t *e2e_data;
  u8 *s = 0;
  int i;

  vec_reset_length(s);

  s = format(0, "IOAM E2E information: \n");
  for (i = 0; i < vec_len(ioam_e2e_main.e2e_data); i++)
    {
      if (pool_is_free_index(ioam_e2e_main.e2e_data, i))
        continue;

      e2e_data = pool_elt_at_index(ioam_e2e_main.e2e_data, i);
      s = format(s, "Flow name: %s\n", get_flow_name_from_flow_ctx(e2e_data->flow_ctx));

      s = show_ioam_seqno_cmd_fn(s,
                                 &e2e_data->seqno_data,
                                 !IOAM_DEAP_ENABLED(e2e_data->flow_ctx));
    }

  vlib_cli_output(vm, "%v", s);
  return 0;
}


VLIB_CLI_COMMAND (ioam_show_e2e_cmd, static) = {
    .path = "show ioam e2e ",
    .short_help = "show ioam e2e information",
    .function = ioam_show_e2e_cmd_fn,
};

/*
 * Init handler E2E headet handling.
 * Init hanlder registers encap, decap, trace and Rewrite handlers.
 */
static clib_error_t *
ioam_e2e_init (vlib_main_t * vm)
{
  clib_error_t * error;

  if ((error = vlib_call_init_function (vm, ip6_hop_by_hop_ioam_init)))
    {
      return(error);
    }

  /*
   * As of now we have only PPC under E2E header.
   */
  if (ip6_hbh_config_handler_register(HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE,
                                      ioam_e2e_config_handler) < 0)
    {
      return (clib_error_create("Registration of "
          "HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE for rewrite failed"));
    }

  if (ip6_hbh_add_register_option(HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE,
                                  sizeof(ioam_e2e_option_t),
                                  ioam_e2e_rewrite_handler) < 0)
    {
      return (clib_error_create("Registration of "
          "HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE for rewrite failed"));
    }

  if (ip6_hbh_flow_handler_register(HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE,
                                    ioam_e2e_flow_handler) < 0)
    {
      return (clib_error_create("Registration of "
          "HBH_OPTION_TYPE_IOAM_EDGE_TO_EDGE Flow handler failed"));
    }

  ioam_e2e_main.vlib_main = vm;
  ioam_e2e_main.vnet_main = vnet_get_main();

  return (0);
}

/*
 * Init function for the E2E lib.
 * ip6_hop_by_hop_ioam_e2e_init gets called during init.
 */
VLIB_INIT_FUNCTION (ioam_e2e_init);
