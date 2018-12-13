/*
 *------------------------------------------------------------------
 * bond_api.c - vnet bonding device driver API support
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>
#include <vnet/bonding/node.h>

#define foreach_bond_api_msg                     \
_(BOND_CREATE, bond_create)                      \
_(BOND_DELETE, bond_delete)                      \
_(BOND_ENSLAVE, bond_enslave)                    \
_(BOND_DETACH_SLAVE, bond_detach_slave)          \
_(SW_INTERFACE_BOND_DUMP, sw_interface_bond_dump)\
_(SW_INTERFACE_SLAVE_DUMP, sw_interface_slave_dump)

static void
bond_send_sw_interface_event_deleted (vpe_api_main_t * am,
				      unix_shared_memory_queue_t * q,
				      u32 sw_if_index)
{
  vl_api_sw_interface_event_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_EVENT);
  mp->sw_if_index = ntohl (sw_if_index);

  mp->admin_up_down = 0;
  mp->link_up_down = 0;
  mp->deleted = 1;
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_bond_delete_t_handler (vl_api_bond_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  int rv;
  vpe_api_main_t *vam = &vpe_api_main;
  vl_api_bond_delete_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = bond_delete_if (vm, sw_if_index);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_BOND_DELETE_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);

  if (!rv)
    bond_send_sw_interface_event_deleted (vam, q, sw_if_index);
}

static void
vl_api_bond_create_t_handler (vl_api_bond_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_create_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  bond_create_if_args_t _a, *ap = &_a;

  clib_memset (ap, 0, sizeof (*ap));

  ap->id = ntohl (mp->id);

  if (mp->use_custom_mac)
    {
      clib_memcpy (ap->hw_addr, mp->mac_address, 6);
      ap->hw_addr_set = 1;
    }

  ap->mode = mp->mode;
  ap->lb = mp->lb;
  bond_create_if (vm, ap);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  if (ap->rv != 0)
    return;
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_BOND_CREATE_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (ap->rv);
  rmp->sw_if_index = ntohl (ap->sw_if_index);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_bond_enslave_t_handler (vl_api_bond_enslave_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_enslave_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  bond_enslave_args_t _a, *ap = &_a;

  clib_memset (ap, 0, sizeof (*ap));

  ap->group = ntohl (mp->bond_sw_if_index);
  ap->slave = ntohl (mp->sw_if_index);
  ap->is_passive = mp->is_passive;
  ap->is_long_timeout = mp->is_long_timeout;

  bond_enslave (vm, ap);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_BOND_ENSLAVE_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (ap->rv);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_bond_detach_slave_t_handler (vl_api_bond_detach_slave_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_bond_detach_slave_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  bond_detach_slave_args_t _a, *ap = &_a;

  clib_memset (ap, 0, sizeof (*ap));

  ap->slave = ntohl (mp->sw_if_index);
  bond_detach_slave (vm, ap);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_BOND_DETACH_SLAVE_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (ap->rv);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
bond_send_sw_interface_details (vpe_api_main_t * am,
				vl_api_registration_t * reg,
				bond_interface_details_t * bond_if,
				u32 context)
{
  vl_api_sw_interface_bond_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_SW_INTERFACE_BOND_DETAILS);
  mp->sw_if_index = htonl (bond_if->sw_if_index);
  mp->id = htonl (bond_if->id);
  clib_memcpy (mp->interface_name, bond_if->interface_name,
	       MIN (ARRAY_LEN (mp->interface_name) - 1,
		    strlen ((const char *) bond_if->interface_name)));
  mp->mode = bond_if->mode;
  mp->lb = bond_if->lb;
  mp->active_slaves = htonl (bond_if->active_slaves);
  mp->slaves = htonl (bond_if->slaves);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_interface_bond_dump_t_handler (vl_api_sw_interface_bond_dump_t * mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  bond_interface_details_t *bondifs = NULL;
  bond_interface_details_t *bond_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = bond_dump_ifs (&bondifs);
  if (rv)
    return;

  vec_foreach (bond_if, bondifs)
  {
    bond_send_sw_interface_details (am, reg, bond_if, mp->context);
  }

  vec_free (bondifs);
}

static void
bond_send_sw_interface_slave_details (vpe_api_main_t * am,
				      vl_api_registration_t * reg,
				      slave_interface_details_t * slave_if,
				      u32 context)
{
  vl_api_sw_interface_slave_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_SW_INTERFACE_SLAVE_DETAILS);
  mp->sw_if_index = htonl (slave_if->sw_if_index);
  clib_memcpy (mp->interface_name, slave_if->interface_name,
	       MIN (ARRAY_LEN (mp->interface_name) - 1,
		    strlen ((const char *) slave_if->interface_name)));
  mp->is_passive = slave_if->is_passive;
  mp->is_long_timeout = slave_if->is_long_timeout;

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_interface_slave_dump_t_handler (vl_api_sw_interface_slave_dump_t *
					  mp)
{
  int rv;
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  slave_interface_details_t *slaveifs = NULL;
  slave_interface_details_t *slave_if = NULL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rv = bond_dump_slave_ifs (&slaveifs, ntohl (mp->sw_if_index));
  if (rv)
    return;

  vec_foreach (slave_if, slaveifs)
  {
    bond_send_sw_interface_slave_details (am, reg, slave_if, mp->context);
  }

  vec_free (slaveifs);
}

#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
bond_setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_bond;
#undef _
}

static clib_error_t *
bond_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_bond_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  bond_setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (bond_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
