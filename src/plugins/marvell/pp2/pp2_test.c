/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Arm Limited.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <marvell/pp2/pp2.h>

#define __plugin_msg_base mrvl_pp2_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <marvell/pp2/pp2_msg_enum.h>

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <marvell/pp2/pp2_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */
#define vl_endianfun
#include <marvell/pp2/pp2_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <marvell/pp2/pp2_all_api_h.h>
#undef vl_printfun

/* get API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <marvell/pp2/pp2_all_api_h.h>
#undef vp_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} mrvl_pp2_test_main_t;

mrvl_pp2_test_main_t mrvl_pp2_test_main;

#define foreach_standard_reply_retval_handler           \
_(mrvl_pp2_delete_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = mrvl_pp2_test_main.vat_main; \
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

#define foreach_vpe_api_reply_msg                       \
_(MRVL_PP2_CREATE_REPLY, mrvl_pp2_create_reply)         \
_(MRVL_PP2_DELETE_REPLY, mrvl_pp2_delete_reply)

/* mrvl_pp2 create API */
static int
api_mrvl_pp2_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mrvl_pp2_create_t *mp;
  mrvl_pp2_create_if_args_t args;
  int ret;
  u16 size;

  clib_memset (&args, 0, sizeof (mrvl_pp2_create_if_args_t));
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %s", &args.name))
	;
      else if (unformat (i, "rx-queue-size %u", &size))
	args.rx_q_sz = size;
      else if (unformat (i, "tx-queue-size %u", &size))
	args.tx_q_sz = size;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (MRVL_PP2_CREATE, mp);

  strncpy_s ((char *) mp->if_name, ARRAY_LEN (mp->if_name),
	     (char *) (args.name), ARRAY_LEN (args.name));
  mp->rx_q_sz = clib_host_to_net_u16 (args.rx_q_sz);
  mp->tx_q_sz = clib_host_to_net_u16 (args.tx_q_sz);

  S (mp);
  W (ret);

  vec_free (args.name);

  return ret;
}

/* mrvl_pp2 create reply handler */
static void
vl_api_mrvl_pp2_create_reply_t_handler (vl_api_mrvl_pp2_create_reply_t * mp)
{
  vat_main_t *vam = mrvl_pp2_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created mrvl_pp2 with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
  vam->regenerate_interface_table = 1;
}


/* mrvl_pp2 delete API */
static int
api_mrvl_pp2_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  //vnet_main_t *vnm = vnet_get_main ();
  vl_api_mrvl_pp2_delete_t *mp;
  u32 sw_if_index = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (MRVL_PP2_DELETE, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);

  S (mp);
  W (ret);

  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                     \
_(mrvl_pp2_create, "[name <ifname>] [rx-queue-size <size>]"     \
  "[tx-queue-size <size>]")                                     \
_(mrvl_pp2_delete, "[sw_if_index <sw_if_index>]")

static void
mrvl_pp2_vat_api_hookup (vat_main_t * vam)
{
  mrvl_pp2_test_main_t *pp2 __attribute__ ((unused)) = &mrvl_pp2_test_main;
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + pp2->msg_id_base),      \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

#define _(n,h)    \
  hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  mrvl_pp2_test_main_t *pp2 = &mrvl_pp2_test_main;
  u8 *name;

  pp2->vat_main = vam;

  name = format (0, "mrvl_pp2_%08x%c", api_version, 0);
  pp2->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);
  vec_free (name);

  if (pp2->msg_id_base == (u16) ~ 0)
    return clib_error_return (0, "mrvl_pp2 plugin not loaded...");

  mrvl_pp2_vat_api_hookup (vam);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
