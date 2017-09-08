/*
 *------------------------------------------------------------------
 * memif_api.c - memif api
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/unix/unix.h>
#include <memif/memif.h>
#include <memif/private.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <memif/memif_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <memif/memif_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <memif/memif_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <memif/memif_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <memif/memif_all_api_h.h>
#undef vl_api_version

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */
#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = htons ((t)+mm->msg_id_base);              \
    rmp->context = mp->context;                                 \
    rmp->retval = htonl (rv);                                   \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO2(t, body)                                   \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = htons ((t)+mm->msg_id_base);              \
    rmp->context = mp->context;                                 \
    rmp->retval = htonl (rv);                                   \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define foreach_memif_plugin_api_msg                     \
_(MEMIF_CREATE, memif_create)                            \
_(MEMIF_DELETE, memif_delete)                            \
_(MEMIF_DUMP, memif_dump)                                \

/**
 * @brief Message handler for memif_create API.
 * @param mp vl_api_memif_create_t * mp the api message
 */
void
vl_api_memif_create_t_handler (vl_api_memif_create_t * mp)
{
  memif_main_t *mm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  vl_api_memif_create_reply_t *rmp;
  memif_create_if_args_t args = { 0 };
  u32 ring_size = MEMIF_DEFAULT_RING_SIZE;
  static const u8 empty_hw_addr[6];
  int rv = 0;

  /* id */
  args.id = clib_net_to_host_u32 (mp->id);

  /* socket filename */
  mp->socket_filename[ARRAY_LEN (mp->socket_filename) - 1] = 0;
  if (strlen ((char *) mp->socket_filename) > 0)
    {
      vec_validate (args.socket_filename,
		    strlen ((char *) mp->socket_filename));
      strncpy ((char *) args.socket_filename, (char *) mp->socket_filename,
	       vec_len (args.socket_filename));
    }

  /* secret */
  mp->secret[ARRAY_LEN (mp->secret) - 1] = 0;
  if (strlen ((char *) mp->secret) > 0)
    {
      vec_validate (args.secret, strlen ((char *) mp->secret));
      strncpy ((char *) args.secret, (char *) mp->secret,
	       vec_len (args.secret));
    }

  /* role */
  args.is_master = (mp->role == 0);

  /* mode */
  args.mode = mp->mode;

  /* rx/tx queues */
  if (args.is_master == 0)
    {
      args.rx_queues = MEMIF_DEFAULT_RX_QUEUES;
      args.tx_queues = MEMIF_DEFAULT_TX_QUEUES;
      if (mp->rx_queues)
	{
	  args.rx_queues = mp->rx_queues;
	}
      if (mp->tx_queues)
	{
	  args.tx_queues = mp->tx_queues;
	}
    }

  /* ring size */
  if (mp->ring_size)
    {
      ring_size = ntohl (mp->ring_size);
    }
  if (!is_pow2 (ring_size))
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }
  args.log2_ring_size = min_log2 (ring_size);

  /* buffer size */
  args.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;
  if (mp->buffer_size)
    {
      args.buffer_size = ntohs (mp->buffer_size);
    }

  /* MAC address */
  if (memcmp (mp->hw_addr, empty_hw_addr, 6) != 0)
    {
      memcpy (args.hw_addr, mp->hw_addr, 6);
      args.hw_addr_set = 1;
    }

  rv = memif_create_if (vm, &args);

  vec_free (args.socket_filename);
  vec_free (args.secret);

reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_MEMIF_CREATE_REPLY,
    ({
       rmp->sw_if_index = htonl (args.sw_if_index);
    }));
  /* *INDENT-ON* */
}

/**
 * @brief Message handler for memif_delete API.
 * @param mp vl_api_memif_delete_t * mp the api message
 */
void
vl_api_memif_delete_t_handler (vl_api_memif_delete_t * mp)
{
  memif_main_t *mm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_memif_delete_reply_t *rmp;
  vnet_hw_interface_t *hi =
    vnet_get_sup_hw_interface (vnm, ntohl (mp->sw_if_index));
  memif_if_t *mif;
  int rv = 0;

  if (hi == NULL || memif_device_class.index != hi->dev_class_index)
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      mif = pool_elt_at_index (mm->interfaces, hi->dev_instance);
      rv = memif_delete_if (vm, mif);
    }

  REPLY_MACRO (VL_API_MEMIF_DELETE_REPLY);
}

static void
send_memif_details (unix_shared_memory_queue_t * q,
		    memif_if_t * mif,
		    vnet_sw_interface_t * swif,
		    u8 * interface_name, u32 context)
{
  vl_api_memif_details_t *mp;
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf = vec_elt_at_index (mm->socket_files,
					       mif->socket_file_index);
  vnet_hw_interface_t *hwif;

  hwif = vnet_get_sup_hw_interface (vnm, swif->sw_if_index);

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_MEMIF_DETAILS + mm->msg_id_base);
  mp->context = context;

  mp->sw_if_index = htonl (swif->sw_if_index);
  strncpy ((char *) mp->if_name,
	   (char *) interface_name, ARRAY_LEN (mp->if_name) - 1);
  memcpy (mp->hw_addr, hwif->hw_address, ARRAY_LEN (mp->hw_addr));

  mp->id = clib_host_to_net_u32 (mif->id);
  mp->role = (mif->flags & MEMIF_IF_FLAG_IS_SLAVE) ? 1 : 0;
  strncpy ((char *) mp->socket_filename,
	   (char *) msf->filename, ARRAY_LEN (mp->socket_filename) - 1);

  mp->ring_size = htonl (1 << mif->run.log2_ring_size);
  mp->buffer_size = htons (mif->run.buffer_size);

  mp->admin_up_down = (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;
  mp->link_up_down = (hwif->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ? 1 : 0;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

/**
 * @brief Message handler for memif_dump API.
 * @param mp vl_api_memif_dump_t * mp the api message
 */
void
vl_api_memif_dump_t_handler (vl_api_memif_dump_t * mp)
{
  memif_main_t *mm = &memif_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *swif;
  memif_if_t *mif;
  u8 *if_name = 0;
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (mif, mm->interfaces,
    ({
      swif = vnet_get_sw_interface (vnm, mif->sw_if_index);

      if_name = format (if_name, "%U%c",
			format_vnet_sw_interface_name,
			vnm, swif, 0);

      send_memif_details (q, mif, swif, if_name, mp->context);
      _vec_len (if_name) = 0;
    }));
  /* *INDENT-ON* */

  vec_free (if_name);
}

#define vl_msg_name_crc_list
#include <memif/memif_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (memif_main_t * mm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + mm->msg_id_base);
  foreach_vl_msg_name_crc_memif;
#undef _
}

/* Set up the API message handling tables */
clib_error_t *
memif_plugin_api_hookup (vlib_main_t * vm)
{
  memif_main_t *mm = &memif_main;
  api_main_t *am = &api_main;
  u8 *name;

  /* Construct the API name */
  name = format (0, "memif_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_memif_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (mm, am);

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
