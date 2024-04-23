#include <stddef.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/tm/tm.api_enum.h>
#include <vnet/tm/tm.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 tm_base_msg_id;
#define REPLY_MSG_ID_BASE tm_base_msg_id

#include <vlibapi/api_helper_macros.h>

void
vl_api_tm_sys_node_create_t_handler (vl_api_tm_sys_node_create_t *mp)
{
  vl_api_tm_sys_node_create_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  tm_node_params_t n_p;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill tm_node_params_t n_p from mp
   *  post conversion from network to host endian
   */

  rv = tm_sys_node_create (sw->hw_if_index, &n_p);

  REPLY_MACRO2 (VL_API_TM_SYS_NODE_CREATE_REPLY, ({
		  if (rv > 0)
		    mp->node_id = htonl (rv);
		}));
}

void
vl_api_tm_sys_node_delete_t_handler (vl_api_tm_sys_node_delete_t *mp)
{
  vl_api_tm_sys_node_delete_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_idx = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill n_idx from mp
   *  post conversion from network to host endian
   */

  rv = tm_sys_node_delete (sw->hw_if_index, n_idx);
  REPLY_MACRO (VL_API_TM_SYS_NODE_DELETE_REPLY);
}

void
vl_api_tm_sys_node_connect_t_handler (vl_api_tm_sys_node_connect_t *mp)
{
  vl_api_tm_sys_node_connect_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  tm_node_connect_params_t n_p = { 0 };
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill tm_node_connect_t n_p from mp
   *  post conversion from network to host endian
   */

  rv = tm_sys_node_connect (sw->hw_if_index, &n_p);
  REPLY_MACRO (VL_API_TM_SYS_NODE_CONNECT_REPLY);
}

void
vl_api_tm_sys_node_disconnect_t_handler (vl_api_tm_sys_node_disconnect_t *mp)
{
  vl_api_tm_sys_node_disconnect_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_idx = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill n_idx from mp
   *  post conversion from network to host endian
   */

  rv = tm_sys_node_disconnect (sw->hw_if_index, n_idx);
  REPLY_MACRO (VL_API_TM_SYS_NODE_DISCONNECT_REPLY);
}

void
vl_api_tm_sys_sched_create_t_handler (vl_api_tm_sys_sched_create_t *mp)
{
  vl_api_tm_sys_sched_create_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  tm_sched_params_t s_p;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill tm_sched_params_t n_p from mp
   *  post conversion from network to host endian
   */
  sw->hw_if_index = 1;
  printf ("sw->hw_if_index:%d\n", sw->hw_if_index);

  rv = tm_sys_sched_create (sw->hw_if_index, &s_p);

  REPLY_MACRO2 (VL_API_TM_SYS_SCHED_CREATE_REPLY, ({
		  if (rv > 0)
		    rmp->sched_id = htonl (rv);
		}));
}

void
vl_api_tm_sys_sched_delete_t_handler (vl_api_tm_sys_sched_delete_t *mp)
{
  vl_api_tm_sys_sched_delete_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 s_idx = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill s_idx from mp
   *  post conversion from network to host endian
   */

  sw->hw_if_index = 1;
  rv = tm_sys_node_delete (sw->hw_if_index, s_idx);
  REPLY_MACRO (VL_API_TM_SYS_SCHED_DELETE_REPLY);
}

void
vl_api_tm_sys_shaper_create_t_handler (vl_api_tm_sys_shaper_create_t *mp)
{
  vl_api_tm_sys_shaper_create_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  tm_shaper_params_t s_p;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill tm_shaper_params_t s_p from mp
   *  post conversion from network to host endian
   */

  rv = tm_sys_shaper_create (sw->hw_if_index, &s_p);

  REPLY_MACRO2 (VL_API_TM_SYS_SCHED_CREATE_REPLY, ({
		  if (rv > 0)
		    rmp->shaper_id = htonl (rv);
		}));

  REPLY_MACRO (VL_API_TM_SYS_SHAPER_CREATE_REPLY);
}

void
vl_api_tm_sys_shaper_delete_t_handler (vl_api_tm_sys_shaper_delete_t *mp)
{
  vl_api_tm_sys_shaper_delete_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 s_idx = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, mp->sw_if_idx);
  /**
   *  Place holder to add code to fill s_idx from mp
   *  post conversion from network to host endian
   */

  rv = tm_sys_node_delete (sw->hw_if_index, s_idx);
  REPLY_MACRO (VL_API_TM_SYS_SCHED_DELETE_REPLY);
}

#include <vnet/tm/tm.api.c>

static clib_error_t *
tm_api_init (vlib_main_t *vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  tm_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (tm_api_init);
