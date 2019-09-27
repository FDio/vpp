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

#define __plugin_msg_base pp2_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <marvell/pp2/pp2.api_enum.h>
#include <marvell/pp2/pp2.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} pp2_test_main_t;

pp2_test_main_t pp2_test_main;

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
	     (char *) (args.name), strlen ((char *) args.name));
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
  vat_main_t *vam = pp2_test_main.vat_main;
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

#include <marvell/pp2/pp2.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
