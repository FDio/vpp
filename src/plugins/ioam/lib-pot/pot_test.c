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
 * pot_test.c - test harness for pot plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>

#define __plugin_msg_base pot_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <ioam/lib-pot/pot_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/lib-pot/pot_all_api_h.h>
#undef vl_api_version


typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} pot_test_main_t;

pot_test_main_t pot_test_main;

#define foreach_standard_reply_retval_handler     \
_(pot_profile_add_reply)                          \
_(pot_profile_activate_reply)                     \
_(pot_profile_del_reply)

#define foreach_custom_reply_retval_handler     		\
_(pot_profile_show_config_details,				\
    errmsg("		ID:%d\n",mp->id);			\
    errmsg("	 Validator:%d\n",mp->validator);		\
    errmsg("	secret_key:%Lx\n",clib_net_to_host_u64(mp->secret_key));		\
    errmsg("  secret_share:%Lx\n",clib_net_to_host_u64(mp->secret_share));		\
    errmsg("  	     prime:%Lx\n",clib_net_to_host_u64(mp->prime));			\
    errmsg("  	   bitmask:%Lx\n",clib_net_to_host_u64(mp->bit_mask));		\
    errmsg("  	       lpc:%Lx\n",clib_net_to_host_u64(mp->lpc));			\
    errmsg("   public poly:%Lx\n",clib_net_to_host_u64(mp->polynomial_public));	\
		)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = pot_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

#define _(n,body)                                       \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = pot_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
	do{body;}while(0);				\
    }
foreach_custom_reply_retval_handler;
#undef _

/* 
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(POT_PROFILE_ADD_REPLY, pot_profile_add_reply)                         \
_(POT_PROFILE_ACTIVATE_REPLY, pot_profile_activate_reply)               \
_(POT_PROFILE_DEL_REPLY, pot_profile_del_reply)                         \
_(POT_PROFILE_SHOW_CONFIG_DETAILS, pot_profile_show_config_details)

static int api_pot_profile_add (vat_main_t *vam)
{
#define MAX_BITS 64
    unformat_input_t *input = vam->input;
    vl_api_pot_profile_add_t *mp;
    u8 *name = NULL;
    u64 prime = 0;
    u64 secret_share = 0;
    u64 secret_key = 0;
    u32  bits = MAX_BITS;
    u64 lpc = 0, poly2 = 0;
    u8 id = 0;
    int rv = 0;
    int ret;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat(input, "name %s", &name))
	  ;
	else if(unformat(input, "id %d", &id))
	  ;
        else if (unformat(input, "validator-key 0x%Lx", &secret_key))
          ;
        else if (unformat(input, "prime-number 0x%Lx", &prime))
          ;
        else if (unformat(input, "secret-share 0x%Lx", &secret_share))
          ;
        else if (unformat(input, "polynomial-public 0x%Lx", &poly2))
          ;
        else if (unformat(input, "lpc 0x%Lx", &lpc))
          ;
        else if (unformat(input, "bits-in-random %u", &bits))
	  {
	    if (bits > MAX_BITS)
	      bits = MAX_BITS;
	  }
        else
  	break;
      }

    if (!name)
      {
        errmsg ("name required\n");
        rv = -99;
        goto OUT;
      }
    
    M2(POT_PROFILE_ADD, mp, vec_len(name));

    mp->list_name_len = vec_len(name);
    clib_memcpy(mp->list_name, name, mp->list_name_len);
    mp->secret_share = clib_host_to_net_u64(secret_share);
    mp->polynomial_public = clib_host_to_net_u64(poly2);
    mp->lpc = clib_host_to_net_u64(lpc);
    mp->prime = clib_host_to_net_u64(prime);
    if (secret_key != 0)
      {
        mp->secret_key = clib_host_to_net_u64(secret_key);
        mp->validator = 1;
      }
    else
      {
	mp->validator = 0;
      }
    mp->id = id;
    mp->max_bits = bits;
      
    S(mp);
    W (ret);
    return ret;
  
OUT:
    vec_free(name);
    return(rv);
}

static int api_pot_profile_activate (vat_main_t *vam)
{
#define MAX_BITS 64
    unformat_input_t *input = vam->input;
    vl_api_pot_profile_activate_t *mp;
    u8 *name = NULL;
    u8 id = 0;
    int rv = 0;
    int ret;
    
    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
      {
        if (unformat(input, "name %s", &name))
	  ;
	else if(unformat(input, "id %d", &id))
	  ;
        else
  	break;
      }

    if (!name)
      {
        errmsg ("name required\n");
        rv = -99;
        goto OUT;
      }
    
    M2(POT_PROFILE_ACTIVATE, mp, vec_len(name));

    mp->list_name_len = vec_len(name);
    clib_memcpy(mp->list_name, name, mp->list_name_len);
    mp->id = id;
      
    S(mp);
    W (ret);
    return ret;
  
OUT:
    vec_free(name);
    return(rv);
}


static int api_pot_profile_del (vat_main_t *vam)
{
    vl_api_pot_profile_del_t *mp;
    int ret;
   
    M(POT_PROFILE_DEL, mp);
    mp->list_name_len = 0;
    S(mp);
    W (ret);
    return ret;
}

static int api_pot_profile_show_config_dump (vat_main_t *vam)
{
    unformat_input_t *input = vam->input;
    vl_api_pot_profile_show_config_dump_t *mp;
    u8 id = 0;
    int ret;

    while(unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      if(unformat(input,"id %d",&id));
      else
        break;
    }
    M(POT_PROFILE_SHOW_CONFIG_DUMP, mp);

    mp->id = id;

    S(mp);
    W (ret);
    return ret;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(pot_profile_add, "name <name> id [0-1] "                              \
  "prime-number <0xu64> bits-in-random [0-64] "                         \
  "secret-share <0xu64> lpc <0xu64> polynomial-public <0xu64> "         \
  "[validator-key <0xu64>] [validity <0xu64>]")                         \
_(pot_profile_activate, "name <name> id [0-1] ")    			\
_(pot_profile_del, "[id <nn>]")                                         \
_(pot_profile_show_config_dump, "id [0-1]")

static void 
pot_vat_api_hookup (vat_main_t *vam)
{
    pot_test_main_t * sm = &pot_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
    foreach_vpe_api_msg;
#undef _    
    
    /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
    foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  pot_test_main_t * sm = &pot_test_main;
  u8 * name;

  sm->vat_main = vam;

  name = format (0, "ioam_pot_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    pot_vat_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
