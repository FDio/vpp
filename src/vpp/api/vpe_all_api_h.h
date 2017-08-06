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
/*
 * Add to the bottom of the #include list, or elves will steal your
 * keyboard in the middle of the night!
 */

/* Include the (first) vlib-api API definition layer */
#include <vlibmemory/vl_memory_api_h.h>

/* Include the (second) vnet API definition layer */
#define included_from_layer_3
#include <vnet/vnet_all_api_h.h>
#undef included_from_layer_3

/* Include the current layer (third) vpp API definition layer */
#include <vpp/api/vpe.api.h>

/* Include stats APIs */
#include <vpp/stats/stats.api.h>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
