/*
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

#include <vnet/feature/feature.h>

char *device_input_feature_start_nodes[] = {
#if DPDK > 0
  "dpdk-input",
#endif
  "tuntap-rx",
  "vhost-user-input",
  "af-packet-input",
  "netmap-input",
};
int device_input_feature_num_start_nodes = ARRAY_LEN (device_input_feature_start_nodes);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (DEVICE_INPUT, l2_patch, static) = {
  .node_name = "l2_patch",
  .runs_before = ORDER_CONSTRAINTS {"ethernet-input", 0},
};

VNET_FEATURE_INIT (DEVICE_INPUT, worker_handoff, static) = {
  .node_name = "worker-handoff",
  .runs_before = ORDER_CONSTRAINTS {"ethernet-input", 0},
};

VNET_FEATURE_INIT (DEVICE_INPUT, ethernet_input, static) = {
  .node_name = "ethernet-input",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
