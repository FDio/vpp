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

char *mpls_input_feature_start_nodes[] = {
  "mpls-input",
};

int mpls_input_feature_num_start_nodes = ARRAY_LEN (mpls_input_feature_start_nodes);

char *mpls_output_feature_start_nodes[] = {
  "mpls-output",
  "mpls-midchain",
};

int mpls_out_feature_num_start_nodes = ARRAY_LEN (mpls_output_feature_start_nodes);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (MPLS_INPUT, mpls_lookup, static) = {
  .node_name = "mpls-lookup",
  .runs_before = ORDER_CONSTRAINTS {"mpls-not-enabled", 0},
};

VNET_FEATURE_INIT (MPLS_INPUT, mpls_not_enabled, static) = {
  .node_name = "mpls-not-enabled",
  .runs_before = ORDER_CONSTRAINTS {0},
};

VNET_FEATURE_INIT (MPLS_OUTPUT, interface_output, static) = {
  .node_name = "interface-output",
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
