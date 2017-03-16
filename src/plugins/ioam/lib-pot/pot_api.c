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
/*
 *------------------------------------------------------------------
 * pot_api.c - Proof of Transit related APIs to create 
 *             and maintain profiles
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ioam/lib-pot/pot_util.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <ioam/lib-pot/pot_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */
#define foreach_pot_plugin_api_msg                                      \
_(POT_PROFILE_ADD, pot_profile_add)                                     \
_(POT_PROFILE_ACTIVATE, pot_profile_activate)                           \
_(POT_PROFILE_DEL, pot_profile_del)                                     \
_(POT_PROFILE_SHOW_CONFIG_DUMP, pot_profile_show_config_dump)                                     \

static void vl_api_pot_profile_add_t_handler
(vl_api_pot_profile_add_t *mp)
{
    pot_main_t * sm = &pot_main;
    int rv = 0;
    vl_api_pot_profile_add_reply_t * rmp;
    u8 id;
    pot_profile *profile = NULL;
    u8 *name = 0;

    if (mp->list_name_len)
        name = format(0, "%s", mp->list_name);

    pot_profile_list_init(name);
    id = mp->id;
    profile = pot_profile_find(id);
    if (profile) {
	rv = pot_profile_create(profile,
				clib_net_to_host_u64(mp->prime),
				clib_net_to_host_u64(mp->polynomial_public),
				clib_net_to_host_u64(mp->lpc),
				clib_net_to_host_u64(mp->secret_share));
	if (rv != 0)
            goto ERROROUT;
	if (1 == mp->validator)
	  (void)pot_set_validator(profile, clib_net_to_host_u64(mp->secret_key));
        (void)pot_profile_set_bit_mask(profile, mp->max_bits);
    } else {
        rv = -3;
    }  
 ERROROUT:
    vec_free(name);
    REPLY_MACRO(VL_API_POT_PROFILE_ADD_REPLY);
}

static void send_pot_profile_details(vl_api_pot_profile_show_config_dump_t *mp, u8 id)
{
    vl_api_pot_profile_show_config_details_t * rmp;
    pot_main_t * sm = &pot_main;
    pot_profile *profile = pot_profile_find(id);
    int rv = 0;
    if(profile){
        REPLY_MACRO2(VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS,
			rmp->id=id;
			rmp->validator=profile->validator;
			rmp->secret_key=clib_host_to_net_u64(profile->secret_key);
			rmp->secret_share=clib_host_to_net_u64(profile->secret_share);
			rmp->prime=clib_host_to_net_u64(profile->prime);
			rmp->bit_mask=clib_host_to_net_u64(profile->bit_mask);
			rmp->lpc=clib_host_to_net_u64(profile->lpc);
			rmp->polynomial_public=clib_host_to_net_u64(profile->poly_pre_eval);
			);
    }
    else{
        REPLY_MACRO2(VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS,
			rmp->id=id;
			rmp->validator=0;
			rmp->secret_key=0;
			rmp->secret_share=0;
			rmp->prime=0;
			rmp->bit_mask=0;
			rmp->lpc=0;
			rmp->polynomial_public=0;
			);
    }
}

static void vl_api_pot_profile_show_config_dump_t_handler
(vl_api_pot_profile_show_config_dump_t *mp)
{
    u8 id = mp->id;
    u8 dump_call_id = ~0;
    if(dump_call_id==id){
        for(id=0;id<MAX_POT_PROFILES;id++)
	    send_pot_profile_details(mp,id);
    }
    else
        send_pot_profile_details(mp,id);
}

static void vl_api_pot_profile_activate_t_handler
(vl_api_pot_profile_activate_t *mp)
{
    pot_main_t * sm = &pot_main;
    int rv = 0;
    vl_api_pot_profile_add_reply_t * rmp;
    u8 id;
    u8 *name = NULL;

    if (mp->list_name_len)
        name = format(0, "%s", mp->list_name);
    if (!pot_profile_list_is_enabled(name)) {
        rv = -1;
    } else {
        id = mp->id;
	rv = pot_profile_set_active(id);
    }
     
    vec_free(name);
    REPLY_MACRO(VL_API_POT_PROFILE_ACTIVATE_REPLY);
}


static void vl_api_pot_profile_del_t_handler
(vl_api_pot_profile_del_t *mp)
{
    pot_main_t * sm = &pot_main;
    int rv = 0;
    vl_api_pot_profile_del_reply_t * rmp;

    clear_pot_profiles();

    REPLY_MACRO(VL_API_POT_PROFILE_DEL_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
pot_plugin_api_hookup (vlib_main_t *vm)
{
  pot_main_t * sm = &pot_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_pot_plugin_api_msg;
#undef _

    return 0;
}

#define vl_msg_name_crc_list
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (pot_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_pot;
#undef _
}

static clib_error_t * pot_init (vlib_main_t * vm)
{
  pot_main_t * sm = &pot_main;
  clib_error_t * error = 0;
  u8 * name;

  bzero(sm, sizeof(pot_main));
  (void)pot_util_init();

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main();

  name = format (0, "ioam_pot_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = pot_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (pot_init);
