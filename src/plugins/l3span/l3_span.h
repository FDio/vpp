/*
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

#ifndef __L3_SPAN_H__
#define __L3_SPAN_H__

#include <vnet/fib/fib_types.h>

extern void l3_span_path_add (u32 fib_index,
                              const fib_prefix_t * pfx,
                              const fib_route_path_t * rpath);

extern void l3_span_path_remove (u32 fib_index,
                                 const fib_prefix_t * pfx,
                                 const fib_route_path_t * rpath);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
