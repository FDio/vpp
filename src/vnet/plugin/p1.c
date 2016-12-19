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
 * This file and in fact the entire directory shouldn't even exist.
 *
 * Unfortunately, various things malfunction when we try to go there. 
 * Plugin DLL's end up with their own copies of critical
 * data structures. No one of these problems would be tough to fix, 
 * but there are quite a number of them.
 */

/* 
 * Make certain that plugin .dll's which reference the following functions
 * can find them...
 */

#if DPDK > 0
#define foreach_dpdk_plugin_reference		\
_(rte_calloc)                                   \
_(rte_free)                                     \
_(rte_malloc)                                   \
_(rte_zmalloc)                                  \
_(rte_malloc_virt2phy)                          \
_(rte_eal_get_configuration)
#else
#define foreach_dpdk_plugin_reference
#endif

#define _(a) void a (void);
foreach_dpdk_plugin_reference
#undef _

void *vnet_library_plugin_references[] =
  {
#define _(a) &a,
    foreach_dpdk_plugin_reference
#undef _
  };

void vnet_library_plugin_reference(void) { }
