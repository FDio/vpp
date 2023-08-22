/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/srv6/sr_pt.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>

#include <vnet/srv6/sr_pt.api_enum.h>
#include <vnet/srv6/sr_pt.api_types.h>

#define REPLY_MSG_ID_BASE sr_pt_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
send_sr_pt_iface_details (sr_pt_iface_t *t, vl_api_registration_t *reg,
			  u32 context)
{
  vl_api_sr_pt_iface_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SR_PT_IFACE_DETAILS);

  rmp->sw_if_index = ntohl (t->iface);
  rmp->id = ntohs (t->id);
  rmp->ingress_load = t->ingress_load;
  rmp->egress_load = t->egress_load;
  rmp->tts_template = t->tts_template;

  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_sr_pt_iface_dump_t_handler (vl_api_sr_pt_iface_dump_t *mp)
{
  vl_api_registration_t *reg;
  sr_pt_main_t *pt = &sr_pt_main;
  sr_pt_iface_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (t, pt->sr_pt_iface)
    {
      send_sr_pt_iface_details (t, reg, mp->context);
    }
}

static void
vl_api_sr_pt_iface_add_t_handler (vl_api_sr_pt_iface_add_t *mp)
{
  vl_api_sr_pt_iface_add_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = sr_pt_add_iface (ntohl (mp->sw_if_index), ntohs (mp->id),
			mp->ingress_load, mp->egress_load, mp->tts_template);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_PT_IFACE_ADD_REPLY);
}

static void
vl_api_sr_pt_iface_del_t_handler (vl_api_sr_pt_iface_del_t *mp)
{
  vl_api_sr_pt_iface_del_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = sr_pt_del_iface (ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_PT_IFACE_DEL_REPLY);
}

static void
send_sr_pt_probe_inject_iface_details (sr_pt_probe_inject_iface_t *t,
				       vl_api_registration_t *reg, u32 context)
{
  vl_api_sr_pt_probe_inject_iface_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_SR_PT_PROBE_INJECT_IFACE_DETAILS);
  rmp->sw_if_index = ntohl (t->iface);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_sr_pt_probe_inject_iface_dump_t_handler (
  vl_api_sr_pt_probe_inject_iface_dump_t *mp)
{
  vl_api_registration_t *reg;
  sr_pt_main_t *pt = &sr_pt_main;
  sr_pt_probe_inject_iface_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (t, pt->sr_pt_probe_inject_iface)
    {
      send_sr_pt_probe_inject_iface_details (t, reg, mp->context);
    }
}

static void
vl_api_sr_pt_probe_inject_iface_add_t_handler (
  vl_api_sr_pt_probe_inject_iface_add_t *mp)
{
  vl_api_sr_pt_probe_inject_iface_add_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = sr_pt_add_probe_inject_iface (ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_PT_PROBE_INJECT_IFACE_ADD_REPLY);
}

static void
vl_api_sr_pt_probe_inject_iface_del_t_handler (
  vl_api_sr_pt_probe_inject_iface_del_t *mp)
{
  vl_api_sr_pt_probe_inject_iface_del_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = sr_pt_del_probe_inject_iface (ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_PT_PROBE_INJECT_IFACE_DEL_REPLY);
}

#include <vnet/srv6/sr_pt.api.c>
static clib_error_t *
sr_pt_api_hookup (vlib_main_t *vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (sr_pt_api_hookup);