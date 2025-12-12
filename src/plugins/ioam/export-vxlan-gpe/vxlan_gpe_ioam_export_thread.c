/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/*
 * ioam_export_thread.c
 */
#include <vnet/api_errno.h>
#include <vppinfra/pool.h>
#include <vnet/ethernet/ethernet.h>
#include <ioam/export-common/ioam_export.h>

static vlib_node_registration_t vxlan_gpe_ioam_export_process_node;
extern ioam_export_main_t vxlan_gpe_ioam_export_main;

static uword
vxlan_gpe_ioam_export_process (vlib_main_t * vm,
			       vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  return (ioam_export_process_common (&vxlan_gpe_ioam_export_main,
				      vm, rt, f,
				      vxlan_gpe_ioam_export_process_node.index));
}

VLIB_REGISTER_NODE (vxlan_gpe_ioam_export_process_node, static) = {
  .function = vxlan_gpe_ioam_export_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "vxlan-gpe-ioam-export-process",
};
