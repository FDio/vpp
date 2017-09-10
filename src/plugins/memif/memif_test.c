/*
 * memif VAT support
 *
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

#include <inttypes.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <memif/memif.h>
#include <memif/private.h>

#define __plugin_msg_base memif_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <memif/memif_msg_enum.h>

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <memif/memif_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <memif/memif_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <memif/memif_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <memif/memif_all_api_h.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} memif_test_main_t;

memif_test_main_t memif_test_main;

/* standard reply handlers */
#define foreach_standard_reply_retval_handler           \
_(memif_delete_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = memif_test_main.vat_main;    \
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

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                       \
_(MEMIF_CREATE_REPLY, memif_create_reply)               \
_(MEMIF_DELETE_REPLY, memif_delete_reply)               \
_(MEMIF_DETAILS, memif_details)

static uword
unformat_memif_queues (unformat_input_t * input, va_list * args)
{
  u32 *rx_queues = va_arg (*args, u32 *);
  u32 *tx_queues = va_arg (*args, u32 *);

  if (unformat (input, "rx-queues %u", rx_queues))
    ;
  if (unformat (input, "tx-queues %u", tx_queues))
    ;

  return 1;
}

/* memif-create API */
static int
api_memif_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_memif_create_t *mp;
  u32 id = 0;
  u8 *socket_filename = 0;
  u8 *secret = 0;
  u8 role = 1;
  u32 ring_size = 0;
  u32 buffer_size = 0;
  u8 hw_addr[6] = { 0 };
  u32 rx_queues = MEMIF_DEFAULT_RX_QUEUES;
  u32 tx_queues = MEMIF_DEFAULT_TX_QUEUES;
  int ret;
  u8 mode = MEMIF_INTERFACE_MODE_ETHERNET;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "id %u", &id))
	;
      else if (unformat (i, "socket %s", &socket_filename))
	;
      else if (unformat (i, "secret %s", &secret))
	;
      else if (unformat (i, "ring_size %u", &ring_size))
	;
      else if (unformat (i, "buffer_size %u", &buffer_size))
	;
      else if (unformat (i, "master"))
	role = 0;
      else if (unformat (i, "slave %U",
			 unformat_memif_queues, &rx_queues, &tx_queues))
	role = 1;
      else if (unformat (i, "mode ip"))
	mode = MEMIF_INTERFACE_MODE_IP;
      else if (unformat (i, "hw_addr %U", unformat_ethernet_address, hw_addr))
	;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!is_pow2 (ring_size))
    {
      errmsg ("ring size must be power of 2\n");
      return -99;
    }

  if (rx_queues > 255 || rx_queues < 1)
    {
      errmsg ("rx queue must be between 1 - 255\n");
      return -99;
    }

  if (tx_queues > 255 || tx_queues < 1)
    {
      errmsg ("tx queue must be between 1 - 255\n");
      return -99;
    }

  M (MEMIF_CREATE, mp);

  mp->mode = mode;
  mp->id = clib_host_to_net_u32 (id);
  mp->role = role;
  mp->ring_size = clib_host_to_net_u32 (ring_size);
  mp->buffer_size = clib_host_to_net_u16 (buffer_size & 0xffff);
  if (socket_filename != 0)
    {
      strncpy ((char *) mp->socket_filename, (char *) socket_filename, 127);
      vec_free (socket_filename);
    }
  if (secret != 0)
    {
      strncpy ((char *) mp->secret, (char *) secret, 16);
      vec_free (secret);
    }
  memcpy (mp->hw_addr, hw_addr, 6);
  mp->rx_queues = rx_queues;
  mp->tx_queues = tx_queues;

  S (mp);
  W (ret);
  return ret;
}

/* memif-create reply handler */
static void vl_api_memif_create_reply_t_handler
  (vl_api_memif_create_reply_t * mp)
{
  vat_main_t *vam = memif_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created memif with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

/* memif-delete API */
static int
api_memif_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_memif_delete_t *mp;
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

  M (MEMIF_DELETE, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

/* memif-dump API */
static int
api_memif_dump (vat_main_t * vam)
{
  memif_test_main_t *mm = &memif_test_main;
  vl_api_memif_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for memif_dump");
      return -99;
    }

  M (MEMIF_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (mm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", mm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

/* memif-details message handler */
static void vl_api_memif_details_t_handler (vl_api_memif_details_t * mp)
{
  vat_main_t *vam = memif_test_main.vat_main;

  fformat (vam->ofp, "%s: sw_if_index %u mac %U\n"
	   "   id %u socket %s role %s\n"
	   "   ring_size %u buffer_size %u\n"
	   "   state %s link %s\n",
	   mp->if_name, ntohl (mp->sw_if_index), format_ethernet_address,
	   mp->hw_addr, clib_net_to_host_u32 (mp->id), mp->socket_filename,
	   mp->role ? "slave" : "master",
	   ntohl (mp->ring_size), ntohs (mp->buffer_size),
	   mp->admin_up_down ? "up" : "down",
	   mp->link_up_down ? "up" : "down");
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg					  \
_(memif_create, "[id <id>] [socket <path>] [ring_size <size>] " \
		"[buffer_size <size>] [hw_addr <mac_address>] "   \
		"[secret <string>] [mode ip] <master|slave>")	  \
_(memif_delete, "<sw_if_index>")                                  \
_(memif_dump, "")

static void
memif_vat_api_hookup (vat_main_t * vam)
{
  memif_test_main_t *mm __attribute__ ((unused)) = &memif_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h)                                          \
  hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  memif_test_main_t *mm = &memif_test_main;
  u8 *name;

  mm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "memif_%08x%c", api_version, 0);
  mm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  mm->ping_id = vl_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (mm->msg_id_base != (u16) ~0)
    memif_vat_api_hookup (vam);

  vec_free (name);

  return 0;
}
