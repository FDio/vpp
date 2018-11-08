/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <avf/avf.h>

#define __plugin_msg_base avf_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <avf/avf_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <avf/avf_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */
#define vl_endianfun
#include <avf/avf_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <avf/avf_all_api_h.h>
#undef vl_printfun

/* get API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <avf/avf_all_api_h.h>
#undef vp_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} avf_test_main_t;

avf_test_main_t avf_test_main;

#define foreach_standard_reply_retval_handler		\
_(avf_delete_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = avf_test_main.vat_main;    	\
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

#define foreach_vpe_api_reply_msg			\
_(AVF_CREATE_REPLY, avf_create_reply)			\
_(AVF_DELETE_REPLY, avf_delete_reply)

/* avf create API */
static int
api_avf_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_avf_create_t *mp;
  avf_create_if_args_t args;
  uint32_t tmp;
  int ret;
  u32 x[4];

  clib_memset (&args, 0, sizeof (avf_create_if_args_t));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%x:%x:%x.%x", &x[0], &x[1], &x[2], &x[3]))
	{
	  args.addr.domain = x[0];
	  args.addr.bus = x[1];
	  args.addr.slot = x[2];
	  args.addr.function = x[3];
	}
      else if (unformat (i, "elog"))
	args.enable_elog = 1;
      else if (unformat (i, "rx-queue-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (i, "tx-queue-size %u", &tmp))
	args.txq_size = tmp;
      else if (unformat (i, "num-rx-queues %u", &tmp))
	args.rxq_num = tmp;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (AVF_CREATE, mp);

  mp->pci_addr = clib_host_to_net_u32 (args.addr.as_u32);
  mp->enable_elog = clib_host_to_net_u16 (args.enable_elog);
  mp->rxq_num = clib_host_to_net_u16 (args.rxq_num);
  mp->rxq_size = clib_host_to_net_u16 (args.rxq_size);
  mp->txq_size = clib_host_to_net_u16 (args.txq_size);

  S (mp);
  W (ret);

  return ret;
}

/* avf-create reply handler */
static void
vl_api_avf_create_reply_t_handler (vl_api_avf_create_reply_t * mp)
{
  vat_main_t *vam = avf_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created avf with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
  vam->regenerate_interface_table = 1;
}

/* avf delete API */
static int
api_avf_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_avf_delete_t *mp;
  u32 sw_if_index = 0;
  u8 index_defined = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %u", &sw_if_index))
	index_defined = 1;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!index_defined)
    {
      errmsg ("missing sw_if_index\n");
      return -99;
    }

  M (AVF_DELETE, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);

  S (mp);
  W (ret);

  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg					\
_(avf_create, "<pci-address> [rx-queue-size <size>] "		\
              "[tx-queue-size <size>] [num-rx-queues <size>]")	\
_(avf_delete, "<sw_if_index>")

static void
avf_vat_api_hookup (vat_main_t * vam)
{
  avf_test_main_t *avm __attribute__ ((unused)) = &avf_test_main;
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + avm->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

#define _(n,h)							\
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
  avf_test_main_t *avm = &avf_test_main;
  u8 *name;

  avm->vat_main = vam;

  name = format (0, "avf_%08x%c", api_version, 0);
  avm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (avm->msg_id_base != (u16) ~ 0)
    avf_vat_api_hookup (vam);

  vec_free (name);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
