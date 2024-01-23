
#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vlibapi/api.h>

#include <pvti/pvti.api_enum.h>
#include <pvti/pvti.api_types.h>

#include <pvti/pvti.h>
#include <pvti/pvti_if.h>

#define REPLY_MSG_ID_BASE pvm->msg_id_base
#include <vlibapi/api_helper_macros.h>

typedef struct
{
  vl_api_registration_t *reg;
  u32 context;
} pvti_if_details_ctx_t;

typedef struct
{

} pvti_interface_dump_ctx_t;

static walk_rc_t
pvti_if_send_details (index_t pvtii, void *data)
{
  vl_api_pvti_interface_details_t *rmp;
  pvti_if_details_ctx_t *ctx = data;
  const pvti_if_t *pvi;

  pvi = pvti_if_get (pvtii);

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (VL_API_PVTI_INTERFACE_DETAILS + pvti_main.msg_id_base);

  rmp->interface.sw_if_index = htonl (pvi->sw_if_index);
  rmp->interface.local_port = htons (pvi->local_port);
  rmp->interface.remote_port = htons (pvi->remote_port);
  ip_address_encode2 (&pvi->local_ip, &rmp->interface.local_ip);
  ip_address_encode2 (&pvi->remote_ip, &rmp->interface.remote_ip);

  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return (WALK_CONTINUE);
}

static void
vl_api_pvti_interface_dump_t_handler (vl_api_pvti_interface_dump_t *mp)
{
  vl_api_registration_t *reg;
  // pvti_main_t *pvm = &pvti_main;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    return;

  pvti_if_details_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  u32 sw_if_index = ntohl (mp->sw_if_index);
  if (sw_if_index == ~0)
    pvti_if_walk (pvti_if_send_details, &ctx);
  else
    {
      index_t pvtii = pvti_if_find_by_sw_if_index (sw_if_index);
      if (pvtii != INDEX_INVALID)
	pvti_if_send_details (pvtii, &ctx);
    }
}

static void
vl_api_pvti_enable_disable_t_handler (vl_api_pvti_enable_disable_t *mp)
{
  vl_api_pvti_enable_disable_reply_t *rmp;
  pvti_main_t *pvm = &pvti_main;
  int rv;

  rv = 0;

  REPLY_MACRO (VL_API_PVTI_ENABLE_DISABLE_REPLY);
}

static void
vl_api_pvti_interface_create_t_handler (vl_api_pvti_interface_create_t *mp)
{
  vl_api_pvti_interface_create_reply_t *rmp;
  pvti_main_t *pvm = &pvti_main;
  int rv = ~0;
  u32 sw_if_index = ~0;
  ip_address_t local_ip;
  ip_address_t remote_ip;

  ip_address_decode2 (&mp->interface.local_ip, &local_ip);
  ip_address_decode2 (&mp->interface.remote_ip, &remote_ip);

  rv = pvti_if_create (&local_ip, mp->interface.local_port, &remote_ip,
		       mp->interface.remote_port, &sw_if_index);

  REPLY_MACRO2 (VL_API_PVTI_INTERFACE_CREATE_REPLY,
		{ rmp->sw_if_index = htonl (sw_if_index); });
}

static void
vl_api_pvti_interface_delete_t_handler (vl_api_pvti_interface_delete_t *mp)
{
  vl_api_pvti_interface_delete_reply_t *rmp;
  pvti_main_t *pvm = &pvti_main;
  int rv = 0;

  /* rv = pvti_enable_disable (pvm, ntohl(mp->sw_if_index),
				      (int) (mp->enable_disable));
*/
  REPLY_MACRO (VL_API_PVTI_INTERFACE_DELETE_REPLY);
}

/* API definitions */
#include <pvti/pvti.api.c>

void
pvti_api_init ()
{
  pvti_main_t *pvm = &pvti_main;
  /* Add our API messages to the global name_crc hash table */
  pvm->msg_id_base = setup_message_id_table ();
}
