/*
 * ip_neighboor.h: ip neighbor generic services
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>

#include <vnet/ip-neighbor/ip_neighbor_dp.h>
#include <vnet/ip-neighbor/ip_neighbor.h>

/**
 * APIs invoked by neighbor implementation (i.s. ARP and ND) that can be
 * called from the DP when the protocol has resolved a neighbor
 */
void
ip_neighbor_learn_dp (const ip_neighbor_learn_t * l)
{
  vl_api_rpc_call_main_thread (ip_neighbor_learn, (u8 *) l, sizeof (*l));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
