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

#include <vppinfra/error.h>

#define __plugin_msg_base pot_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <ioam/lib-pot/pot.api_enum.h>
#include <ioam/lib-pot/pot.api_types.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} pot_test_main_t;

pot_test_main_t pot_test_main;

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

    M2(POT_PROFILE_ADD, mp, sizeof(vl_api_string_t) + vec_len(name));

    vl_api_to_api_string(vec_len(name), (const char *)name, &mp->list_name);
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

    M2(POT_PROFILE_ACTIVATE, mp, sizeof(vl_api_string_t) + vec_len(name));
    vl_api_to_api_string(vec_len(name), (const char *)name, &mp->list_name);
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
static int vl_api_pot_profile_show_config_details_t_handler (vat_main_t *vam)
{
  return -1;
}

/* Override generated plugin register symbol */
#define vat_plugin_register pot_vat_plugin_register
#include <ioam/lib-pot/pot.api_test.c>
