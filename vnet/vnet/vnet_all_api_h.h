/*
 *------------------------------------------------------------------
 * vl_memory_api_h.h - memory API headers, in a specific order.
 *
 * Copyright (c) 2009-2010 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

/*
 * Add to the bottom of the #include list, or elves will steal your
 * keyboard in the middle of the night!
 *
 * Include current layer (2) last, or an artistic disagreement
 * about message numbering will occur
 */

#ifndef included_from_layer_3
#include <vlibmemory/vl_memory_api_h.h>
#endif /* included_from_layer_3 */

#include <vnet/interface.api.h>
#include <vnet/map/map.api.h>
#include <vnet/l2/l2.api.h>
#include <vnet/span/span.api.h>
#include <vnet/ip/ip.api.h>
#include <vnet/unix/tap.api.h>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
