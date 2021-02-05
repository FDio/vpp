/*
 * esp_decrypt.c : IPSec ESP decrypt node
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_punt.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ip/punt.h>

static vlib_punt_hdl_t punt_hdl;

vlib_punt_reason_t ipsec_punt_reason[IPSEC_PUNT_N_REASONS];

static void
ipsec_punt_interested_listener (vlib_enable_or_disable_t action, void *data)
{
  if (action == VLIB_ENABLE)
    {
      ipsec_tun_register_nodes (AF_IP4);
      ipsec_tun_register_nodes (AF_IP6);
    }
  else
    {
      ipsec_tun_unregister_nodes (AF_IP4);
      ipsec_tun_unregister_nodes (AF_IP6);
    }
}

static clib_error_t *
ipsec_punt_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, punt_init)))
    return (error);

  punt_hdl = vlib_punt_client_register ("ipsec");

#define _(s, v, f)                                                            \
  vlib_punt_reason_alloc (punt_hdl, v, ipsec_punt_interested_listener, NULL,  \
			  &ipsec_punt_reason[IPSEC_PUNT_##s],                 \
			  VNET_PUNT_REASON_F_##f,                             \
			  format_vnet_punt_reason_flags);
  foreach_ipsec_punt_reason
#undef _
    return (error);
}

VLIB_INIT_FUNCTION (ipsec_punt_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
