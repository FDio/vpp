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

#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <memif/memif.api_enum.h>
#include <memif/memif.api_types.h>

#define REPLY_MSG_ID_BASE mm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/**
 * @brief Message handler for memif_socket_filename_add_del API.
 * @param mp the vl_api_memif_socket_filename_add_del_t API message
 */
void
  vl_api_memif_socket_filename_add_del_t_handler
  (vl_api_memif_socket_filename_add_del_t * mp)
{
  memif_main_t *mm = &memif_main;
  u8 is_add;
  u32 socket_id;
  vl_api_memif_socket_filename_add_del_reply_t *rmp;
  int rv;

  /* is_add */
  is_add = mp->is_add;

  /* socket_id */
  socket_id = clib_net_to_host_u32 (mp->socket_id);
  if (socket_id == 0 || socket_id == ~0)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  /* socket filename */
  mp->socket_filename[ARRAY_LEN (mp->socket_filename) - 1] = 0;

  rv = vnet_api_error (memif_socket_filename_add_del (
    is_add, socket_id, (char *) mp->socket_filename));

reply:
  REPLY_MACRO (VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_REPLY);
}

/**
 * @brief Message handler for memif_socket_filename_add_del API.
 * @param mp the vl_api_memif_socket_filename_add_del_t API message
 */
void
vl_api_memif_socket_filename_add_del_v2_t_handler (
  vl_api_memif_socket_filename_add_del_v2_t *mp)
{
  vl_api_memif_socket_filename_add_del_v2_reply_t *rmp;
  memif_main_t *mm = &memif_main;
  char *socket_filename = 0;
  u32 socket_id;
  int rv;

  /* socket_id */
  socket_id = clib_net_to_host_u32 (mp->socket_id);
  if (socket_id == 0)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  /* socket filename */
  socket_filename = vl_api_from_api_to_new_c_string (&mp->socket_filename);
  if (mp->is_add && socket_id == (u32) ~0)
    socket_id = memif_get_unused_socket_id ();

  rv = vnet_api_error (
    memif_socket_filename_add_del (mp->is_add, socket_id, socket_filename));

  vec_free (socket_filename);

reply:
  REPLY_MACRO2 (VL_API_MEMIF_SOCKET_FILENAME_ADD_DEL_V2_REPLY,
		({ rmp->socket_id = htonl (socket_id); }));
}

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
  mac_address_t mac;

  /* id */
  args.id = clib_net_to_host_u32 (mp->id);

  /* socket-id */
  args.socket_id = clib_net_to_host_u32 (mp->socket_id);

  /* secret */
  mp->secret[ARRAY_LEN (mp->secret) - 1] = 0;
  if (strlen ((char *) mp->secret) > 0)
    {
      vec_validate (args.secret, strlen ((char *) mp->secret));
      strncpy ((char *) args.secret, (char *) mp->secret,
	       vec_len (args.secret));
    }

  /* role */
  args.is_master = (ntohl (mp->role) == MEMIF_ROLE_API_MASTER);

  /* mode */
  args.mode = ntohl (mp->mode);

  args.is_zero_copy = mp->no_zero_copy ? 0 : 1;

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
  mac_address_decode (mp->hw_addr, &mac);
  if (memcmp (&mac, empty_hw_addr, 6) != 0)
    {
      memcpy (args.hw_addr, &mac, 6);
      args.hw_addr_set = 1;
    }

  rv = vnet_api_error (memif_create_if (vm, &args));

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
  vnet_hw_interface_t *hi;
  memif_if_t *mif;
  int rv = 0;

  hi =
    vnet_get_sup_hw_interface_api_visible_or_null (vnm,
						   ntohl (mp->sw_if_index));

  if (hi == NULL || memif_device_class.index != hi->dev_class_index)
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      mif = pool_elt_at_index (mm->interfaces, hi->dev_instance);
      rv = vnet_api_error (memif_delete_if (vm, mif));
    }

  REPLY_MACRO (VL_API_MEMIF_DELETE_REPLY);
}

static void
send_memif_details (vl_api_registration_t * reg,
		    memif_if_t * mif,
		    vnet_sw_interface_t * swif,
		    u8 * interface_name, u32 context)
{
  vl_api_memif_details_t *mp;
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  vnet_hw_interface_t *hwif;
  memif_socket_file_t *msf;

  hwif = vnet_get_sup_hw_interface (vnm, swif->sw_if_index);

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_MEMIF_DETAILS + mm->msg_id_base);
  mp->context = context;

  mp->sw_if_index = htonl (swif->sw_if_index);
  strncpy ((char *) mp->if_name,
	   (char *) interface_name, ARRAY_LEN (mp->if_name) - 1);

  if (hwif->hw_address)
    {
      mac_address_encode ((mac_address_t *) hwif->hw_address, mp->hw_addr);
    }

  mp->id = clib_host_to_net_u32 (mif->id);

  msf = pool_elt_at_index (mm->socket_files, mif->socket_file_index);
  mp->socket_id = clib_host_to_net_u32 (msf->socket_id);

  mp->role =
    (mif->flags & MEMIF_IF_FLAG_IS_SLAVE) ? MEMIF_ROLE_API_SLAVE :
    MEMIF_ROLE_API_MASTER;
  mp->role = htonl (mp->role);
  mp->mode = htonl (mif->mode);
  mp->ring_size = htonl (1 << mif->run.log2_ring_size);
  mp->buffer_size = htons (mif->run.buffer_size);
  mp->zero_copy = (mif->flags & MEMIF_IF_FLAG_ZERO_COPY) ? 1 : 0;

  mp->flags = 0;
  mp->flags |= (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    IF_STATUS_API_FLAG_ADMIN_UP : 0;
  mp->flags |= (hwif->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ?
    IF_STATUS_API_FLAG_LINK_UP : 0;
  mp->flags = htonl (mp->flags);


  vl_api_send_msg (reg, (u8 *) mp);
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
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (mif, mm->interfaces)
     {
      swif = vnet_get_sw_interface (vnm, mif->sw_if_index);

      if_name = format (if_name, "%U%c",
			format_vnet_sw_interface_name,
			vnm, swif, 0);

      send_memif_details (reg, mif, swif, if_name, mp->context);
      vec_set_len (if_name, 0);
    }
  /* *INDENT-ON* */

  vec_free (if_name);
}

static void
send_memif_socket_filename_details (vl_api_registration_t * reg,
				    u32 socket_id,
				    u8 * socket_filename, u32 context)
{
  vl_api_memif_socket_filename_details_t *mp;
  memif_main_t *mm = &memif_main;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_MEMIF_SOCKET_FILENAME_DETAILS
			  + mm->msg_id_base);
  mp->context = context;

  mp->socket_id = clib_host_to_net_u32 (socket_id);
  strncpy ((char *) mp->socket_filename,
	   (char *) socket_filename, ARRAY_LEN (mp->socket_filename) - 1);

  vl_api_send_msg (reg, (u8 *) mp);
}

/**
 * @brief Message handler for memif_socket_filename_dump API.
 * @param mp vl_api_memif_socket_filename_dump_t api message
 */
void
  vl_api_memif_socket_filename_dump_t_handler
  (vl_api_memif_socket_filename_dump_t * mp)
{
  memif_main_t *mm = &memif_main;
  vl_api_registration_t *reg;
  u32 sock_id;
  u32 msf_idx;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  hash_foreach (sock_id, msf_idx, mm->socket_file_index_by_sock_id,
    ({
      memif_socket_file_t *msf;
      u8 *filename;

      msf = pool_elt_at_index(mm->socket_files, msf_idx);
      filename = msf->filename;
      send_memif_socket_filename_details(reg, sock_id, filename, mp->context);
    }));
  /* *INDENT-ON* */
}

/* Set up the API message handling tables */
#include <memif/memif.api.c>
clib_error_t *
memif_plugin_api_hookup (vlib_main_t * vm)
{
  memif_main_t *mm = &memif_main;

  /* Ask for a correctly-sized block of API message decode slots */
  mm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
