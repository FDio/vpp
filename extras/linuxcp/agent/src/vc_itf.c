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

#include <vppinfra/hash.h>
#include <vppinfra/mhash.h>
#include <vppinfra/pool.h>

#include <vc_itf.h>
#include <vc_types.h>
#include <vc_log.h>
#include <vc_conn.h>

DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON;
VC_DECLARE_SYNC_TOKEN;

static mhash_t itf_by_name;
static mhash_t itf_by_tag;
static uword *itf_by_sw_if_index;

static vapi_payload_sw_interface_details *itf_pool;

static int sync_dump_complete;


static vc_itf_event_cb_t client_itf_ev_cb;

vc_itf_t *
vc_itf_get (index_t itfi)
{
  return (pool_elt_at_index (itf_pool, itfi));
}

index_t
vc_itf_find_by_sw_if_index (u32 sw_if_index)
{
  uword *p;

  p = hash_get (itf_by_sw_if_index, sw_if_index);

  if (p)
    return (p[0]);

  return (INDEX_INVALID);
}

const char *
vc_itf_get_name (u32 phy_sw_if_index)
{
  index_t itfi;

  itfi = vc_itf_find_by_sw_if_index (phy_sw_if_index);

  if (INDEX_INVALID == itfi)
    return (NULL);

  vc_itf_t *itf;

  itf = vc_itf_get (itfi);

  return ((const char *) itf->interface_name);
}

const vc_itf_t *
vc_itf_find_by_name (const char *name)
{
  uword *p;

  p = mhash_get (&itf_by_name, name);

  if (p)
    return vc_itf_get (p[0]);

  return (NULL);
}

static void
vc_itf_add (vapi_payload_sw_interface_details * reply)
{
  vc_itf_t *itf;
  index_t itfi;

  pool_get (itf_pool, itf);
  itfi = itf - itf_pool;

  VC_INFO ("itf-add: %s", reply->interface_name);

  clib_memcpy (itf, reply, sizeof (*itf));

  mhash_set (&itf_by_name, itf->interface_name, itfi, NULL);
  mhash_set (&itf_by_tag, itf->tag, itfi, NULL);
  hash_set (itf_by_sw_if_index, itf->sw_if_index, itfi);
}

static void
vc_itf_del (vc_itf_t * itf)
{
  VC_INFO ("itf-del: %s", itf->interface_name);

  mhash_unset (&itf_by_name, itf->interface_name, NULL);
  mhash_unset (&itf_by_tag, itf->tag, NULL);
  hash_unset (itf_by_sw_if_index, itf->sw_if_index);

  pool_put (itf_pool, itf);
}

static vapi_error_e
vc_itf_populate_cb (vapi_ctx_t ctx,
		    void *callback_ctx,
		    vapi_error_e rv,
		    bool is_last, vapi_payload_sw_interface_details * reply)
{
  if (is_last)
    {
      sync_dump_complete = 1;
      return (VAPI_OK);
    }

  VC_INFO ("itf-populate: %s", reply->interface_name);
  vc_itf_add (reply);

  return (VAPI_OK);
}

bool
vc_itf_populate (vapi_ctx_t vapi_ctx)
{
  vapi_msg_sw_interface_dump *msg = vapi_alloc_sw_interface_dump (vapi_ctx);

  sync_dump_complete = 0;

  if (VAPI_OK == vapi_sw_interface_dump (vapi_ctx,
					 msg, vc_itf_populate_cb, NULL))
    {
      while (!sync_dump_complete)
	{
	  vapi_dispatch (vapi_ctx);
	}
    }

  return (true);
}

static vapi_error_e
vc_itf_event_reply_cb (vapi_ctx_t ctx,
		       void *callback_ctx,
		       vapi_error_e rv,
		       bool is_last,
		       vapi_payload_want_interface_events_reply * reply)
{
  return (VAPI_OK);
}

static vapi_error_e
vc_itf_event_cb (vapi_ctx_t ctx, void *callback_ctx, void *payload)
{
  vapi_payload_sw_interface_event *event = payload;
  vc_itf_t *itf;
  index_t itfi;

  itfi = vc_itf_find_by_sw_if_index (event->sw_if_index);

  if (INDEX_INVALID != itfi)
    {
      itf = vc_itf_get (itfi);

      itf->flags = event->flags;

      if (client_itf_ev_cb)
	client_itf_ev_cb (event->sw_if_index, itf->flags);
    }
  else
    VC_ERROR ("Event for unknown interface:%d", event->sw_if_index);

  return (VAPI_OK);
}

bool
vc_itf_reg_events (vapi_ctx_t vapi_ctx, vc_itf_event_cb_t cb, void *ctx)
{
  vapi_msg_want_interface_events *msg =
    vapi_alloc_want_interface_events (vapi_ctx);

  client_itf_ev_cb = cb;
  vapi_set_event_cb (vapi_ctx,
		     vapi_msg_id_sw_interface_event, vc_itf_event_cb, NULL);

  msg->payload.enable_disable = 1;

  return (VAPI_OK == vapi_want_interface_events (vapi_ctx, msg,
						 vc_itf_event_reply_cb, ctx));
}

static vapi_error_e
vc_itf_set_admin_state_reply_cb (vapi_ctx_t ctx,
				 void *callback_ctx,
				 vapi_error_e rv,
				 bool is_last,
				 vapi_payload_sw_interface_set_flags_reply *
				 reply)
{
  return (VAPI_OK);
}

void
vc_itf_set_admin_state (u32 sw_if_index, vapi_enum_if_status_flags flags)
{
  vapi_msg_sw_interface_set_flags *msg =
    vapi_alloc_sw_interface_set_flags (vc_conn_ctx ());

  msg->payload.sw_if_index = sw_if_index;
  msg->payload.flags = flags;

  if (VAPI_OK == vapi_sw_interface_set_flags (vc_conn_ctx (),
					      msg,
					      vc_itf_set_admin_state_reply_cb,
					      NULL))
    {
      vapi_dispatch (vc_conn_ctx ());
    }
}

static vapi_error_e
vc_itf_sub_create_reply_cb (vapi_ctx_t ctx,
			    void *callback_ctx,
			    vapi_error_e rv,
			    bool is_last,
			    vapi_payload_create_subif_reply * reply)
{
  u32 *sub_sw_if_index = callback_ctx;

  if (reply)
    *sub_sw_if_index = reply->sw_if_index;
  else
    *sub_sw_if_index = 0;

  return (rv);
}

u32
vc_itf_sub_create (u32 parent_sw_if_index, u16 vlan)
{
  vapi_msg_create_subif *msg = vapi_alloc_create_subif (vc_conn_ctx ());
  u32 sub_sw_if_index = ~0;

  msg->payload.sw_if_index = parent_sw_if_index;
  msg->payload.sub_id = vlan;
  msg->payload.sub_if_flags = (SUB_IF_API_FLAG_EXACT_MATCH |
			       SUB_IF_API_FLAG_ONE_TAG);

  if (VAPI_OK == vapi_create_subif (vc_conn_ctx (),
				    msg,
				    vc_itf_sub_create_reply_cb,
				    &sub_sw_if_index))
    {
      while (~0 == sub_sw_if_index)
	vapi_dispatch (vc_conn_ctx ());
    }

  {
    vapi_msg_sw_interface_dump *msg;

    msg = vapi_alloc_sw_interface_dump (vc_conn_ctx ());

    msg->payload.sw_if_index = sub_sw_if_index;
    sync_dump_complete = 0;

    if (VAPI_OK == vapi_sw_interface_dump (vc_conn_ctx (),
					   msg, vc_itf_populate_cb, NULL))
      {
	while (!sync_dump_complete)
	  {
	    vapi_dispatch (vc_conn_ctx ());
	  }
      }
  }

  return (sub_sw_if_index);
}

static vapi_error_e
vc_itf_sub_delete_reply_cb (vapi_ctx_t ctx,
			    void *callback_ctx,
			    vapi_error_e rv,
			    bool is_last,
			    vapi_payload_delete_subif_reply * reply)
{
  VC_SYNC_COMPLETE ();

  return (rv);
}

void
vc_itf_sub_delete (u32 sub_sw_if_index)
{
  vapi_msg_delete_subif *msg = vapi_alloc_delete_subif (vc_conn_ctx ());

  msg->payload.sw_if_index = sub_sw_if_index;

  VC_SYNC_START ();

  if (VAPI_OK == vapi_delete_subif (vc_conn_ctx (),
				    msg,
				    vc_itf_sub_delete_reply_cb,
				    &sub_sw_if_index))
    VC_SYNC_WAIT (vc_conn_ctx ());

  index_t itfi;

  itfi = vc_itf_find_by_sw_if_index (sub_sw_if_index);

  if (INDEX_INVALID != itfi)
    {
      vc_itf_t *itf;

      itf = vc_itf_get (itfi);

      vc_itf_del (itf);
    }
}

void
vc_itf_init (void)
{
  mhash_init_c_string (&itf_by_name, sizeof (index_t));
  mhash_init_c_string (&itf_by_tag, sizeof (index_t));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
