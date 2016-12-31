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
/*
 * ioam_export_thread.c
 */
#include <vnet/api_errno.h>
#include <vppinfra/pool.h>
#include <ioam/export-common/ioam_export.h>

static vlib_node_registration_t ioam_export_process_node;

static uword
ioam_export_process (vlib_main_t * vm,
		     vlib_node_runtime_t * rt, vlib_frame_t * f)
{
   return (ioam_export_process_common(&ioam_export_main,
                                      vm, rt, f,
                                      ioam_export_process_node.index));
}

VLIB_REGISTER_NODE (ioam_export_process_node, static) =
{
 .function = ioam_export_process,
 .type = VLIB_NODE_TYPE_PROCESS,
 .name = "ioam-export-process",
};
