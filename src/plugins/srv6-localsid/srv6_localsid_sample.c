/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 *------------------------------------------------------------------
 * srv6_localsid_sample.c - Simple SRv6 LocalSID
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <srv6-localsid/srv6_localsid_sample.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

unsigned char srv6_localsid_name[32] = "Sample-SRv6-LocalSID-plugin";

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static void
srv6_localsid_creation_fn (ip6_sr_localsid_t *localsid)
{
  /* Do you want to do anything fancy upon localsid instantiation?
   * You can do it here
   */
  /* For example you might want to setup your graph node parameters..
   * Notice that you can use localsid->plugin_mem to store your useful bytes
   */
}

static void
srv6_localsid_removal_fn (ip6_sr_localsid_t *localsid)
{
  /* Do you want to do anything fancy upon localsid removal?
   * You can do it here
   */
  /* 
   * BTW if you stored something in localsid->plugin_mem you should clean it now
   */
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "table 5"
 */
u8 *
format_srv6_localsid_sample (u8 * s, va_list * args)
{
  u32 table_id = va_arg (*args, u32);
  return (format (s, "Table: %d", table_id));
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior table 5
 * everything from behavior on... so in this case 'behavior table 5'
 */
uword
unformat_srv6_localsid_sample (unformat_input_t * input, va_list * args)
{
  u32 table_id = va_arg (*args, u32);

  if (unformat (input, "behavior table %d", &table_id))
      return 1;
  return 0;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_localsid_sample_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: localsid_sample_index:[%d]", index));
}

void
srv6_localsid_sample_dpo_lock (dpo_id_t * dpo)
{
}

void
srv6_localsid_sample_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t srv6_localsid_sample_vft = {
  .dv_lock = srv6_localsid_sample_dpo_lock,
  .dv_unlock = srv6_localsid_sample_dpo_unlock,
  .dv_format = format_srv6_localsid_sample_dpo,
};

const static char *const srv6_localsid_sample_ip6_nodes[] = {
  "srv6-localsid-sample",
  NULL,
};

const static char *const *const srv6_localsid_sample_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_localsid_sample_ip6_nodes,
};

/**********************/
static clib_error_t * srv6_localsid_sample_init (vlib_main_t * vm)
{
  srv6_localsid_sample_main_t * sm = &srv6_localsid_sample_main;

  /* Create DPO */
  sm->srv6_localsid_sample_dpo_type = dpo_register_new_type (
    &srv6_localsid_sample_vft, srv6_localsid_sample_nodes);

  /* Register SRv6 LocalSID */
  sr_localsid_register_function (vm, 
    srv6_localsid_name, 
    &sm->srv6_localsid_sample_dpo_type,
    format_srv6_localsid_sample, 
    unformat_srv6_localsid_sample, 
    srv6_localsid_creation_fn, 
    srv6_localsid_removal_fn);

  return 0;
}

VLIB_INIT_FUNCTION (srv6_localsid_sample_init);

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0",
  .version_required = "17.04-rc0~237-gcba73ac",
  .default_disabled = 0,
};
