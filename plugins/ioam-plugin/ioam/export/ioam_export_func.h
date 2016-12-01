/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_EXPORT_IOAM_EXPORT_FUNC_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_EXPORT_IOAM_EXPORT_FUNC_H_

#include <ioam/export-common/ioam_export.h>

inline static void ioam_export_set_next_node (u8 *next_node_name)
{
  vlib_node_t *next_node;

  next_node = vlib_get_node_by_name (ioam_export_main.vlib_main,
                                     next_node_name);
  ioam_export_main.next_node_index = next_node->index;
}

inline static void ioam_export_reset_next_node (void)
{
  vlib_node_t *next_node;

  next_node = vlib_get_node_by_name (ioam_export_main.vlib_main,
                                     (u8 *) "ip4-lookup");
  ioam_export_main.next_node_index = next_node->index;
}

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_EXPORT_IOAM_EXPORT_FUNC_H_ */
