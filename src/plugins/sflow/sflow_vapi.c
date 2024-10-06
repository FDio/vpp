/*
 * Copyright (c) 2024 InMon Corp.
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

#include <sflow/sflow_vapi.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <vapi/vapi.h>
#include <vapi/memclnt.api.vapi.h>
#include <vapi/vlib.api.vapi.h>

#ifdef included_interface_types_api_types_h
#define defined_vapi_enum_if_status_flags
#define defined_vapi_enum_mtu_proto
#define defined_vapi_enum_link_duplex
#define defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_rx_mode
#define defined_vapi_enum_if_type
#define defined_vapi_enum_direction
#endif
#include <vapi/lcp.api.vapi.h>

DEFINE_VAPI_MSG_IDS_LCP_API_JSON;

static vapi_error_e
my_pair_get_cb (struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv,
		bool is_last, vapi_payload_lcp_itf_pair_get_v2_reply *reply)
{
  // this is a no-op, but it seems like it's presence is still required.  For
  // example, it is called if the pair lookup does not find anything.
  return VAPI_OK;
}

static vapi_error_e
my_pair_details_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
		    vapi_error_e rv, bool is_last,
		    vapi_payload_lcp_itf_pair_details *details)
{
  sflow_per_interface_data_t *sfif =
    (sflow_per_interface_data_t *) callback_ctx;
  // Setting this here will mean it is sent to hsflowd with the interface
  // counters.
  sfif->linux_if_index = details->vif_index;
  return VAPI_OK;
}

static vapi_error_e
sflow_vapi_connect (sflow_vapi_client_t *vac)
{
  vapi_error_e rv = VAPI_OK;
  vapi_ctx_t ctx = vac->vapi_ctx;
  if (ctx == NULL)
    {
      // first time - open and connect.
      if ((rv = vapi_ctx_alloc (&ctx)) != VAPI_OK)
	{
	  SFLOW_ERR ("vap_ctx_alloc() returned %d", rv);
	}
      else
	{
	  vac->vapi_ctx = ctx;
	  if ((rv = vapi_connect_from_vpp (
		 ctx, "api_from_sflow_plugin", SFLOW_VAPI_MAX_REQUEST_Q,
		 SFLOW_VAPI_MAX_RESPONSE_Q, VAPI_MODE_BLOCKING, true)) !=
	      VAPI_OK)
	    {
	      SFLOW_ERR ("vapi_connect_from_vpp() returned %d", rv);
	    }
	  else
	    {
	      // Connected - but is there a handler for the request we want to
	      // send?
	      if (!vapi_is_msg_available (ctx,
					  vapi_msg_id_lcp_itf_pair_add_del_v2))
		{
		  SFLOW_WARN ("vapi_is_msg_available() returned false => "
			      "linux-cp plugin not loaded");
		  rv = VAPI_EUSER;
		}
	    }
	}
    }
  return rv;
}

// in forked thread
static void *
get_lcp_itf_pairs (void *magic)
{
  sflow_vapi_client_t *vac = magic;
  vapi_error_e rv = VAPI_OK;

  sflow_per_interface_data_t *intfs = vac->vapi_itfs;
  vlib_set_thread_name (SFLOW_VAPI_THREAD_NAME);
  if ((rv = sflow_vapi_connect (vac)) != VAPI_OK)
    {
      vac->vapi_unavailable = true;
    }
  else
    {
      vapi_ctx_t ctx = vac->vapi_ctx;

      for (int ii = 1; ii < vec_len (intfs); ii++)
	{
	  sflow_per_interface_data_t *sfif = vec_elt_at_index (intfs, ii);
	  if (sfif && sfif->sflow_enabled)
	    {
	      // TODO: if we try non-blocking we might not be able to just pour
	      // all the requests in here. Might be better to do them one at a
	      // time - e.g. when we poll for counters.
	      vapi_msg_lcp_itf_pair_get_v2 *msg =
		vapi_alloc_lcp_itf_pair_get_v2 (ctx);
	      if (msg)
		{
		  msg->payload.sw_if_index = sfif->sw_if_index;
		  if ((rv = vapi_lcp_itf_pair_get_v2 (ctx, msg, my_pair_get_cb,
						      sfif, my_pair_details_cb,
						      sfif)) != VAPI_OK)
		    {
		      SFLOW_ERR ("vapi_lcp_itf_pair_get_v2 returned %d", rv);
		      // vapi.h: "message must be freed by vapi_msg_free if not
		      // consumed by vapi_send"
		      vapi_msg_free (ctx, msg);
		    }
		}
	    }
	}
      // We no longer disconnect or free the client structures
      // vapi_disconnect_from_vpp (ctx);
      // vapi_ctx_free (ctx);
    }
  // indicate that we are done - more portable that using pthread_tryjoin_np()
  vac->vapi_request_status = (int) rv;
  clib_atomic_store_rel_n (&vac->vapi_request_active, false);
  // TODO: how to tell if heap-allocated data is stored separately per thread?
  // And if so, how to tell the allocator to GC all data for the thread when it
  // exits?
  return (void *) rv;
}

int
sflow_vapi_read_linux_if_index_numbers (sflow_vapi_client_t *vac,
					sflow_per_interface_data_t *itfs)
{

#ifdef SFLOW_VAPI_TEST_PLUGIN_SYMBOL
  // don't even fork the query thread if the symbol is not there
  if (!vlib_get_plugin_symbol ("linux_cp_plugin.so", "lcp_itf_pair_get"))
    {
      return false;
    }
#endif
  // previous query is done and results extracted?
  int req_active = clib_atomic_load_acq_n (&vac->vapi_request_active);
  if (req_active == false && vac->vapi_itfs == NULL)
    {
      // make a copy of the current interfaces vector for the lookup thread to
      // write into
      vac->vapi_itfs = vec_dup (itfs);
      pthread_attr_t attr;
      pthread_attr_init (&attr);
      pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
      pthread_attr_setstacksize (&attr, VLIB_THREAD_STACK_SIZE);
      vac->vapi_request_active = true;
      pthread_create (&vac->vapi_thread, &attr, get_lcp_itf_pairs, vac);
      pthread_attr_destroy (&attr);
      return true;
    }
  return false;
}

int
sflow_vapi_check_for_linux_if_index_results (sflow_vapi_client_t *vac,
					     sflow_per_interface_data_t *itfs)
{
  // request completed?
  // TODO: if we use non-blocking mode do we have to call something here to
  // receive results?
  int req_active = clib_atomic_load_acq_n (&vac->vapi_request_active);
  if (req_active == false && vac->vapi_itfs != NULL)
    {
      // yes, extract what we learned
      // TODO: would not have to do this if vector were array of pointers
      // to sflow_per_interface_data_t rather than an actual array, but
      // it does mean we have very clear separation between the threads.
      for (int ii = 1; ii < vec_len (vac->vapi_itfs); ii++)
	{
	  sflow_per_interface_data_t *sfif1 =
	    vec_elt_at_index (vac->vapi_itfs, ii);
	  sflow_per_interface_data_t *sfif2 = vec_elt_at_index (itfs, ii);
	  if (sfif1 && sfif2 && sfif1->sflow_enabled && sfif2->sflow_enabled)
	    sfif2->linux_if_index = sfif1->linux_if_index;
	}
      vec_free (vac->vapi_itfs);
      vac->vapi_itfs = NULL;
      return true;
    }
  return false;
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
