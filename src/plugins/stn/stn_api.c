/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <plugins/stn/stn.h>
#include <vnet/ip/format.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vppinfra/byte_order.h>

/* define message IDs */
#include <stn/stn.api_enum.h>
#include <stn/stn.api_types.h>

#define REPLY_MSG_ID_BASE stn_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

/**
 * @brief API message custom-dump function
 * @param mp vl_api_stn_add_del_rule_t * mp the api message
 * @param handle void * print function handle
 * @returns u8 * output string
 */
static void *vl_api_stn_add_del_rule_t_print
  (vl_api_stn_add_del_rule_t * mp, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: stn_add_del_rule ");
  s = format (s, "address %U ", format_ip46_address, mp->ip_address);
  s = format (s, "sw_if_index %d is_add %d", mp->sw_if_index, mp->is_add);

  FINISH;
}

static void
vl_api_stn_add_del_rule_t_handler (vl_api_stn_add_del_rule_t * mp)
{
  stn_rule_add_del_args_t args;
  vl_api_stn_add_del_rule_reply_t *rmp;
  int rv = 0;

  ip_address_decode (&mp->ip_address, &args.address);
  args.sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  args.del = !mp->is_add;

  rv = stn_rule_add_del (&args);

  REPLY_MACRO (VL_API_STN_ADD_DEL_RULE_REPLY);
}

static void
send_stn_rules_details (stn_rule_t * r, vl_api_registration_t * reg,
			u32 context)
{
  vl_api_stn_rules_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_STN_RULES_DETAILS + stn_main.msg_id_base);

  ip_address_encode (&r->address,
		     ip46_address_is_ip4 (&r->address) ? IP46_TYPE_IP4 :
		     IP46_TYPE_IP6, &rmp->ip_address);
  rmp->context = context;
  rmp->sw_if_index = clib_host_to_net_u32 (r->sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_stn_rules_dump_t_handler (vl_api_stn_rules_dump_t * mp)
{
  vl_api_registration_t *reg;
  stn_main_t *stn = &stn_main;
  stn_rule_t *r;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (r, stn->rules,({
    send_stn_rules_details (r, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

#include <stn/stn.api.c>
clib_error_t *
stn_api_init (vlib_main_t * vm, stn_main_t * sm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = setup_message_id_table ();

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
