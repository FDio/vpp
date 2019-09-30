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


typedef struct lcp_main_s
{
  u16 msg_id_base;		/* API message ID base */
  u8 default_namespace[LCP_NS_LEN];	/* default namespace if set */
  int default_ns_fd;
  u8 auto_intf;
} lcp_main_t;

#define REPLY_MSG_ID_BASE lcpm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static lcp_main_t lcp_main;

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

void
lcp_set_auto_intf (u8 is_auto)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->auto_intf = (is_auto != 0);
}

int
lcp_auto_intf (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->auto_intf;
}

static void
vl_api_lcp_itf_pair_add_del_t_handler (vl_api_lcp_itf_pair_add_del_t * mp)
{
  lcp_main_t *lcpm = &lcp_main;
  u32 phy_sw_if_index;
  vl_api_lcp_itf_pair_add_del_reply_t *rmp;
  lip_host_type_t lip_host_type;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  phy_sw_if_index = ntohl (mp->sw_if_index);
  lip_host_type = api_decode_host_type (mp->host_if_type);
  if (mp->is_add)
    {
      u8 *host_if_name, *netns;
      int host_len, netns_len;

      host_if_name = netns = 0;

      /* lcp_itf_pair_create expects vec of u8 */
      host_len = clib_strnlen ((char *) mp->host_if_name,
			       sizeof (mp->host_if_name) - 1);
      vec_add (host_if_name, mp->host_if_name, host_len);
      vec_add1 (host_if_name, 0);

      netns_len = clib_strnlen ((char *) mp->namespace,
				sizeof (mp->namespace) - 1);
      vec_add (netns, mp->namespace, netns_len);
      vec_add1 (netns, 0);

      rv = lcp_itf_pair_create (phy_sw_if_index, host_if_name,
				lip_host_type, netns);

      vec_free (host_if_name);
      vec_free (netns);
    }
  else
    {
      rv = lcp_itf_pair_delete (phy_sw_if_index);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY);
}


static void
send_lcp_itf_pair_details (vl_api_registration_t * reg,
			   u32 context, lcp_itf_pair_t * lcp_pair)
{
  lcp_main_t *lcpm = &lcp_main;
  vl_api_lcp_itf_pair_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return;
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_LCP_ITF_PAIR_DETAILS + lcpm->msg_id_base);
  mp->context = context;

  mp->phy_sw_if_index = htonl (lcp_pair->lip_phy_sw_if_index);
  mp->host_sw_if_index = htonl (lcp_pair->lip_host_sw_if_index);
  mp->vif_index = htonl (lcp_pair->lip_vif_index);
  mp->host_if_type = api_encode_host_type (lcp_pair->lip_host_type);

  clib_strncpy ((char *) mp->host_if_name,
		(char *) lcp_pair->lip_host_name,
		vec_len (lcp_pair->lip_host_name) - 1);

  clib_strncpy ((char *) mp->namespace,
		(char *) lcp_pair->lip_namespace,
		vec_len (lcp_pair->lip_namespace));

  vl_api_send_msg (reg, (u8 *) mp);
}


walk_rc_t
lcp_itf_pair_walk_send_cb (index_t api, void *ctx)
{
  vl_api_lcp_itf_pair_dump_t *mp = ctx;
  vl_api_registration_t *reg;
  lcp_itf_pair_t *lcp_pair;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return WALK_STOP;

  lcp_pair = lcp_itf_pair_get (api);
  if (!lcp_pair)
    return WALK_STOP;

  send_lcp_itf_pair_details (reg, mp->context, lcp_pair);
  return WALK_CONTINUE;
}


static void
vl_api_lcp_itf_pair_dump_t_handler (vl_api_lcp_itf_pair_dump_t * mp)
{
  u32 sw_if_index;
  index_t api;

  sw_if_index = ntohl (mp->sw_if_index);
  if (sw_if_index == ~0)
    {
      lcp_itf_pair_walk (lcp_itf_pair_walk_send_cb, (void *) mp);
    }
  else
    {
      api = lcp_itf_pair_find_by_phy (sw_if_index);
      lcp_itf_pair_walk_send_cb (api, (void *) mp);
    }
}


u8 *
lcp_get_default_ns (void)
{
  lcp_main_t *lcpm = &lcp_main;

  if (lcpm->default_namespace[0] == 0)
    return 0;
  return lcpm->default_namespace;
}


int
lcp_get_default_ns_fd (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->default_ns_fd;
}


/*
 * ns is expected to be or look like a NUL-terminated C string.
 */
int
lcp_set_default_ns (u8 * ns)
{
  lcp_main_t *lcpm = &lcp_main;
  char *p;
  int len;
  u8 *s;

  p = (char *) ns;
  len = clib_strnlen (p, LCP_NS_LEN);
  if (len >= LCP_NS_LEN)
    return -1;

  if (!p || *p == 0)
    {
      clib_memset (lcpm->default_namespace,
		   0, sizeof (lcpm->default_namespace));
      if (lcpm->default_ns_fd > 0)
	close (lcpm->default_ns_fd);
      lcpm->default_ns_fd = 0;
      return 0;
    }

  clib_strncpy ((char *) lcpm->default_namespace, p, LCP_NS_LEN - 1);

  s = format (0, "/var/run/netns/%s%c", (char *) lcpm->default_namespace, 0);
  lcpm->default_ns_fd = open ((char *) s, O_RDONLY);
  vec_free (s);

  return 0;
}


static void
vl_api_lcp_default_ns_set_t_handler (vl_api_lcp_default_ns_set_t * mp)
{
  lcp_main_t *lcpm = &lcp_main;
  vl_api_lcp_default_ns_set_reply_t *rmp;
  int rv;

  mp->namespace[LCP_NS_LEN - 1] = 0;
  rv = lcp_set_default_ns (mp->namespace);

  REPLY_MACRO (VL_API_LCP_DEFAULT_NS_SET_REPLY);
}


static void
vl_api_lcp_default_ns_get_t_handler (vl_api_lcp_default_ns_get_t * mp)
{
  lcp_main_t *lcpm = &lcp_main;
  vl_api_lcp_default_ns_get_reply_t *rmp;
  vl_api_registration_t *reg;
  char *ns;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_LCP_DEFAULT_NS_GET_REPLY + lcpm->msg_id_base);
  rmp->context = mp->context;

  ns = (char *) lcp_get_default_ns ();
  if (ns)
    clib_strncpy ((char *) rmp->namespace, ns, LCP_NS_LEN - 1);

  vl_api_send_msg (reg, (u8 *) rmp);
}


/*
 * Set up the API message handling tables
 */
#include <linux-cp/lcp.api.c>

static clib_error_t *
lcp_plugin_api_hookup (vlib_main_t * vm)
{
  lcp_main_t *lcpm = &lcp_main;

  /* Ask for a correctly-sized block of API message decode slots */
  lcpm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (lcp_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
