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
unsigned char keyword_str[32] = "new_srv6_localsid";
unsigned char def_str[64] = "This is a definition of a sample new_srv6_localsid";
unsigned char params_str[32] = "<fib_table>";

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int
srv6_localsid_creation_fn (ip6_sr_localsid_t *localsid)
{
  /* 
   * Do you want to do anything fancy upon localsid instantiation?
   * You can do it here
   * (If return != 0 the localsid creation will be cancelled.)
   */
  /* As an example Im going to do a +1 to the fib table inserted by the user */
  srv6_localsid_sample_per_sid_memory_t *ls_mem = localsid->plugin_mem;
  ls_mem->fib_table += 1;
  return 0;
}

static int
srv6_localsid_removal_fn (ip6_sr_localsid_t *localsid)
{
  /* Do you want to do anything fancy upon localsid removal?
   * You can do it here
   * (If return != 0 the localsid removal will be cancelled.)
   */
  /* 
   * BTW if you stored something in localsid->plugin_mem you should clean it now
   */

  //In this example we are only cleaning the memory allocated per localsid
  clib_mem_free(localsid->plugin_mem);
  return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "Table 5"
 */
u8 *
format_srv6_localsid_sample (u8 * s, va_list * args)
{
  srv6_localsid_sample_per_sid_memory_t *ls_mem = va_arg (*args, void *);
  return (format (s, "Table: %u", ls_mem->fib_table));
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior new_srv6_localsid 5
 * everything from behavior on... so in this case 'new_srv6_localsid 5'
 * Notice that it MUST match the keyword_str and params_str defined above.
 */
uword
unformat_srv6_localsid_sample (unformat_input_t * input, va_list * args)
{
  void **plugin_mem = va_arg (*args, void **);
  srv6_localsid_sample_per_sid_memory_t *ls_mem;
  u32 table_id;
  if (unformat (input, "new_srv6_localsid %u", &table_id))
    {
      /* Allocate a portion of memory */
      ls_mem = clib_mem_alloc_aligned_at_offset (
        sizeof(srv6_localsid_sample_per_sid_memory_t), 0, 0, 1);

      /* Set to zero the memory */
      memset (ls_mem, 0, sizeof(srv6_localsid_sample_per_sid_memory_t));

      /* Our brand-new car is ready */
      ls_mem->fib_table = table_id;

      /* Dont forget to add it to the localsid */
      *plugin_mem = ls_mem;
      return 1;
    }
  return 0;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_localsid_sample_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: localsid_sample_index:[%u]", index));
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
  int rv = 0;
  /* Create DPO */
  sm->srv6_localsid_sample_dpo_type = dpo_register_new_type (
    &srv6_localsid_sample_vft, srv6_localsid_sample_nodes);

  /* Register SRv6 LocalSID */
  rv = sr_localsid_register_function (vm, 
                                  srv6_localsid_name,
                                  keyword_str,
                                  def_str,
                                  params_str,
                                  &sm->srv6_localsid_sample_dpo_type,
                                  format_srv6_localsid_sample, 
                                  unformat_srv6_localsid_sample, 
                                  srv6_localsid_creation_fn, 
                                  srv6_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;

  return 0;
}

VLIB_INIT_FUNCTION (srv6_localsid_sample_init);

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0",
};
