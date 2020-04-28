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

#include <vc_log.h>
#include <vc_keepalive.h>

DEFINE_VAPI_MSG_IDS_VPE_API_JSON;

static vapi_error_e
vc_keepalive_cb (vapi_ctx_t ctx,
		 void *callback_ctx,
		 vapi_error_e rv,
		 bool is_last, vapi_payload_control_ping_reply * reply)
{
  // VC_DBG("alive");
  return (VAPI_OK);
}

void
vc_keepalive (vapi_ctx_t ctx)
{
  // VC_DBG("poll");
  vapi_msg_control_ping *p = vapi_alloc_control_ping (ctx);

  vapi_control_ping (ctx, p, vc_keepalive_cb, NULL);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
