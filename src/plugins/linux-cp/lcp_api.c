/*
 * Copyright 2020 Rubicon Communications, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>
#include <linux/if.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>

#include <linux-cp/lcp_interface.h>
#include <linux-cp/lcp.api_enum.h>
#include <linux-cp/lcp.api_types.h>

static u16 lcp_msg_id_base;
#define REPLY_MSG_ID_BASE lcp_msg_id_base
#include <vlibapi/api_helper_macros.h>

static lip_host_type_t
api_decode_host_type (vl_api_lcp_itf_host_type_t type)
{
  if (type == LCP_API_ITF_HOST_TUN)
    return LCP_ITF_HOST_TUN;

  return LCP_ITF_HOST_TAP;
}

static vl_api_lcp_itf_host_type_t
api_encode_host_type (lip_host_type_t type)
{
  if (type == LCP_ITF_HOST_TUN)
    return LCP_API_ITF_HOST_TUN;

  return LCP_API_ITF_HOST_TAP;
}

static int
vl_api_lcp_itf_pair_add (u32 phy_sw_if_index, lip_host_type_t lip_host_type,
			 u8 *mp_host_if_name, size_t sizeof_host_if_name,
			 u8 *mp_namespace, size_t sizeof_mp_namespace,
			 u32 *host_sw_if_index_p)
{
  u8 *host_if_name, *netns;
  int host_len, netns_len, rv;

  host_if_name = netns = 0;

  /* lcp_itf_pair_create expects vec of u8 */
  host_len = clib_strnlen ((char *) mp_host_if_name, sizeof_host_if_name - 1);
  vec_add (host_if_name, mp_host_if_name, host_len);
  vec_add1 (host_if_name, 0);

  netns_len = clib_strnlen ((char *) mp_namespace, sizeof_mp_namespace - 1);
  vec_add (netns, mp_namespace, netns_len);
  vec_add1 (netns, 0);

  rv = lcp_itf_pair_create (phy_sw_if_index, host_if_name, lip_host_type,
			    netns, host_sw_if_index_p);

  vec_free (host_if_name);
  vec_free (netns);

  return rv;
}

static void
vl_api_lcp_itf_pair_add_del_t_handler (vl_api_lcp_itf_pair_add_del_t *mp)
{
  u32 phy_sw_if_index;
  vl_api_lcp_itf_pair_add_del_reply_t *rmp;
  lip_host_type_t lip_host_type;
  int rv;

  VALIDATE_SW_IF_INDEX_END (mp);

  phy_sw_if_index = mp->sw_if_index;
  lip_host_type = api_decode_host_type (mp->host_if_type);
  if (mp->is_add)
    {
      rv =
	vl_api_lcp_itf_pair_add (phy_sw_if_index, lip_host_type,
				 mp->host_if_name, sizeof (mp->host_if_name),
				 mp->namespace, sizeof (mp->namespace), NULL);
    }
  else
    {
      rv = lcp_itf_pair_delete (phy_sw_if_index);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY);
}

static void
vl_api_lcp_itf_pair_add_del_v2_t_handler (vl_api_lcp_itf_pair_add_del_v2_t *mp)
{
  u32 phy_sw_if_index, host_sw_if_index = ~0;
  vl_api_lcp_itf_pair_add_del_v2_reply_t *rmp;
  lip_host_type_t lip_host_type;
  int rv;

  VALIDATE_SW_IF_INDEX_END (mp);

  phy_sw_if_index = mp->sw_if_index;
  lip_host_type = api_decode_host_type (mp->host_if_type);
  if (mp->is_add)
    {
      rv = vl_api_lcp_itf_pair_add (phy_sw_if_index, lip_host_type,
				    mp->host_if_name,
				    sizeof (mp->host_if_name), mp->namespace,
				    sizeof (mp->namespace), &host_sw_if_index);
    }
  else
    {
      rv = lcp_itf_pair_delete (phy_sw_if_index);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO2 (VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY,
		{ rmp->host_sw_if_index = ntohl (host_sw_if_index); });
}

static void
send_lcp_itf_pair_details (index_t lipi, vl_api_registration_t *rp,
			   u32 context)
{
  vl_api_lcp_itf_pair_details_t *rmp;
  lcp_itf_pair_t *lcp_pair = lcp_itf_pair_get (lipi);

  REPLY_MACRO_DETAILS4 (
    VL_API_LCP_ITF_PAIR_DETAILS, rp, context, ({
      rmp->phy_sw_if_index = lcp_pair->lip_phy_sw_if_index;
      rmp->host_sw_if_index = lcp_pair->lip_host_sw_if_index;
      rmp->vif_index = lcp_pair->lip_vif_index;
      rmp->host_if_type = api_encode_host_type (lcp_pair->lip_host_type);

      memcpy_s (rmp->host_if_name, sizeof (rmp->host_if_name),
		lcp_pair->lip_host_name, vec_len (lcp_pair->lip_host_name));

      clib_strncpy ((char *) rmp->namespace, (char *) lcp_pair->lip_namespace,
		    vec_len (lcp_pair->lip_namespace));
    }));
}

static void
vl_api_lcp_itf_pair_get_t_handler (vl_api_lcp_itf_pair_get_t *mp)
{
  vl_api_lcp_itf_pair_get_reply_t *rmp;
  i32 rv = 0;

  REPLY_AND_DETAILS_MACRO (
    VL_API_LCP_ITF_PAIR_GET_REPLY, lcp_itf_pair_pool,
    ({ send_lcp_itf_pair_details (cursor, rp, mp->context); }));
}

static void
vl_api_lcp_default_ns_set_t_handler (vl_api_lcp_default_ns_set_t *mp)
{
  vl_api_lcp_default_ns_set_reply_t *rmp;
  int rv;

  mp->namespace[LCP_NS_LEN - 1] = 0;
  rv = lcp_set_default_ns (mp->namespace);

  REPLY_MACRO (VL_API_LCP_DEFAULT_NS_SET_REPLY);
}

static void
vl_api_lcp_default_ns_get_t_handler (vl_api_lcp_default_ns_get_t *mp)
{
  vl_api_lcp_default_ns_get_reply_t *rmp;
  vl_api_registration_t *reg;
  char *ns;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = (VL_API_LCP_DEFAULT_NS_GET_REPLY);
  rmp->context = mp->context;

  ns = (char *) lcp_get_default_ns ();
  if (ns)
    clib_strncpy ((char *) rmp->namespace, ns, LCP_NS_LEN - 1);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lcp_itf_pair_replace_begin_t_handler (
  vl_api_lcp_itf_pair_replace_begin_t *mp)
{
  vl_api_lcp_itf_pair_replace_begin_reply_t *rmp;
  int rv;

  rv = lcp_itf_pair_replace_begin ();

  REPLY_MACRO (VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY);
}

static void
vl_api_lcp_itf_pair_replace_end_t_handler (
  vl_api_lcp_itf_pair_replace_end_t *mp)
{
  vl_api_lcp_itf_pair_replace_end_reply_t *rmp;
  int rv = 0;

  rv = lcp_itf_pair_replace_end ();

  REPLY_MACRO (VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY);
}

/*
 * Set up the API message handling tables
 */
#include <linux-cp/lcp.api.c>

static clib_error_t *
lcp_api_init (vlib_main_t *vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  lcp_msg_id_base = setup_message_id_table ();

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_api_init);

#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Linux Control Plane - Interface Mirror",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
