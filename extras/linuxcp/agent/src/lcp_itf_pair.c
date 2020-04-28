/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <lcp_log.h>
#include <lcp_itf_pair.h>

#include <lcp.api.vapi.h>

#include <vc_conn.h>

DEFINE_VAPI_MSG_IDS_LCP_API_JSON;

/** pool of interface pairs */
lcp_itf_pair_t *lcp_pair_pool;

/** DB of pairs by VIF */
uword *lcp_pairs_by_vif;

/** DB of pairs by phy */
uword *lcp_pairs_by_phy;

VC_DECLARE_SYNC_TOKEN;

/**
 * Get an interface-pair object from its VPP index
 */
lcp_itf_pair_t *
lcp_itf_pair_get (index_t index)
{
  return (pool_elt_at_index (lcp_pair_pool, index));
}

index_t
lcp_itf_pair_find_by_phy (u32 phy_sw_if_index)
{
  uword *p;

  p = hash_get (lcp_pairs_by_phy, phy_sw_if_index);

  if (p)
    return p[0];

  return (INDEX_INVALID);
}

index_t
lcp_itf_pair_find_by_vif (u32 vif_index)
{
  uword *p;

  p = hash_get (lcp_pairs_by_vif, vif_index);

  if (p)
    return p[0];

  return (INDEX_INVALID);
}

static vapi_error_e
lcp_itf_pair_create_cb (vapi_ctx_t vctx,
			void *cctx,
			vapi_error_e rv,
			bool is_last,
			vapi_payload_lcp_itf_pair_add_del_reply * reply)
{
  index_t lipi;

  lipi = pointer_to_uword (cctx);

  if (VAPI_OK == rv)
    {
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);

      lip->lip_vif_index = reply->host_vif;

      hash_set (lcp_pairs_by_phy, lip->lip_phy_sw_if_index, lipi);
      hash_set (lcp_pairs_by_vif, lip->lip_vif_index, lipi);

      LCP_INFO ("pair-install: phy:%d vif:%d",
		lip->lip_phy_sw_if_index, lip->lip_vif_index);
    }
  else
    pool_put_index (lcp_pair_pool, lipi);

  VC_SYNC_COMPLETE ();

  return (rv);
}

int
lcp_itf_pair_create (const char *phy_name,
		     const char *host_name, const char *ns)
{
  vapi_msg_lcp_itf_pair_add_del *msg;
  const vc_itf_t *itf;
  lcp_itf_pair_t *lip;
  index_t lipi;

  LCP_INFO ("pair-create: %s, %s, %s", phy_name, host_name, (ns ? ns : ""));

  /* find the phy/VPP interface to pair */
  itf = vc_itf_find_by_name (phy_name);

  if (NULL == itf)
    {
      LCP_ERROR ("VPP does not have interface: %s", phy_name);
      return (1);
    }

  pool_get (lcp_pair_pool, lip);
  lipi = lip - lcp_pair_pool;

  lip->lip_phy_name = strdup (phy_name);
  if (host_name)
    lip->lip_host_name = strdup (host_name);
  if (ns)
    lip->lip_ns = strdup (ns);

  msg = vapi_alloc_lcp_itf_pair_add_del (vc_conn_ctx ());

  msg->payload.is_add = 1;
  lip->lip_phy_sw_if_index = msg->payload.sw_if_index = itf->sw_if_index;

  if (host_name)
    strncpy ((char *) msg->payload.host_if_name, host_name,
	     clib_min (ARRAY_LEN (msg->payload.host_if_name),
		       strlen (host_name)));
  if (ns)
    strncpy ((char *) msg->payload.namespace, ns,
	     clib_min (ARRAY_LEN (msg->payload.namespace), strlen (ns)));

  VC_SYNC_START ();

  if (VAPI_OK == vapi_lcp_itf_pair_add_del (vc_conn_ctx (), msg,
					    lcp_itf_pair_create_cb,
					    uword_to_pointer (lipi, void *)))
    {
      VC_SYNC_WAIT (vc_conn_ctx ());
      return (0);
    }

  return (2);
}

static vapi_error_e
lcp_itf_pair_delete_cb (vapi_ctx_t vctx,
			void *cctx,
			vapi_error_e rv,
			bool is_last,
			vapi_payload_lcp_itf_pair_add_del_reply * reply)
{
  index_t lipi;

  lipi = pointer_to_uword (cctx);

  if (VAPI_OK == rv)
    {
      lcp_itf_pair_t *lip;

      lip = lcp_itf_pair_get (lipi);

      hash_unset (lcp_pairs_by_phy, lip->lip_phy_sw_if_index);
      hash_unset (lcp_pairs_by_vif, lip->lip_vif_index);

      LCP_INFO ("pair-install: phy:%d vif:%d",
		lip->lip_phy_sw_if_index, lip->lip_vif_index);
      pool_put (lcp_pair_pool, lip);
    }

  VC_SYNC_COMPLETE ();

  return (rv);
}

/**
 * Delete a LCP_ITF_PAIR
 */
int
lcp_itf_pair_delete (u32 vif_index)
{
  vapi_msg_lcp_itf_pair_add_del *msg;
  lcp_itf_pair_t *lip;
  index_t lipi;

  lipi = lcp_itf_pair_find_by_vif (vif_index);

  if (INDEX_INVALID != lipi)
    {
      lip = lcp_itf_pair_get (lipi);

      LCP_INFO ("pair-delete: %s, %s, %s",
		lip->lip_phy_name,
		lip->lip_host_name, (lip->lip_ns ? lip->lip_ns : ""));

      msg = vapi_alloc_lcp_itf_pair_add_del (vc_conn_ctx ());

      msg->payload.is_add = 0;
      msg->payload.sw_if_index = lip->lip_phy_sw_if_index;

      VC_SYNC_START ();

      if (VAPI_OK == vapi_lcp_itf_pair_add_del (vc_conn_ctx (), msg,
						lcp_itf_pair_delete_cb,
						uword_to_pointer (lipi,
								  void *)))
	  VC_SYNC_WAIT (vc_conn_ctx ());
      return (0);
    }
  return (2);
}

/**
 * Callback for when the state of an interface in VPP changes
 */
void
lcp_itf_pair_state_change (u32 phy_sw_if_index,
			   vapi_enum_if_status_flags flags)
{
  LCP_INFO ("itf-pair-state-change: %d", phy_sw_if_index);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
