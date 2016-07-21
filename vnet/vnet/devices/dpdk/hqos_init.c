/*
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
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
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>
#include <vlib/unix/physmem.h>
#include <vlib/pci/pci.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>

#include "dpdk_priv.h"

dpdk_main_t dpdk_main;

static struct rte_sched_subport_params hqos_subport_params_default = {
  .tb_rate = 1250000000,
  .tb_size = 1000000,
  .tc_rate = {1250000000, 1250000000, 1250000000, 1250000000},
  .tc_period = 10,
};

static struct rte_sched_pipe_params hqos_pipe_params_default = {
  .tb_rate = 305175,
  .tb_size = 1000000,
  .tc_rate = {305175, 305175, 305175, 305175},
  .tc_period = 40,
#ifdef RTE_SCHED_SUBPORT_TC_OV
  .tc_ov_weight = 1,
#endif
  .wrr_weights = {1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1},
};

static struct rte_sched_port_params hqos_port_params_default = {
  .name = NULL, /* Set at init */
  .socket = 0,  /* Set at init */
  .rate = 1250000000, /* Assuming 10GbE port */
  .mtu = 6 + 6 + 2 + 1500, /* Assuming Ethernet/IPv4 pkt (Ethernet FCS not included) */
  .frame_overhead = RTE_SCHED_FRAME_OVERHEAD_DEFAULT,
  .n_subports_per_port = 1,
  .n_pipes_per_subport = 4096,
  .qsize = {64, 64, 64, 64},
  .pipe_profiles = NULL, /* Set at config */
  .n_pipe_profiles = 1,

#ifdef RTE_SCHED_RED
  .red_params = {
    /* Traffic Class 0 Colors Green / Yellow / Red */
    [0][0] = {.min_th = 48, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [0][1] = {.min_th = 40, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [0][2] = {.min_th = 32, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},

    /* Traffic Class 1 - Colors Green / Yellow / Red */
    [1][0] = {.min_th = 48, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [1][1] = {.min_th = 40, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [1][2] = {.min_th = 32, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},

    /* Traffic Class 2 - Colors Green / Yellow / Red */
    [2][0] = {.min_th = 48, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [2][1] = {.min_th = 40, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [2][2] = {.min_th = 32, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},

    /* Traffic Class 3 - Colors Green / Yellow / Red */
    [3][0] = {.min_th = 48, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [3][1] = {.min_th = 40, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9},
    [3][2] = {.min_th = 32, .max_th = 64, .maxp_inv = 10, .wq_log2 = 9}
}
#endif /* RTE_SCHED_RED */
};

static u32 hqos_tc_table_default[] = {
    0, 1 , 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1 , 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1 , 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1 , 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
};

static dpdk_device_config_hqos_t hqos_params_default = {
  .config_file = NULL,
  .iotx_valid = 0,

  .swq_size = 4096,
  .burst_enq = 256,
  .burst_deq = 220,

  /* Assuming Ethernet/IPv4/UDP packet: payload bits 0 .. 11 */
  .pktfield0_slabpos = 40,
  .pktfield0_slabmask = 0x0000FFF000000000LLU,

  /* Assuming Ethernet/IPv4/UDP packet: payload bits 12 .. 23  */
  .pktfield1_slabpos = 40,
  .pktfield1_slabmask = 0x0000000FFF000000LLU,

  /* Assuming Ethernet/IPv4/UDP packet: IPv4 DSCP field */
  .pktfield2_slabpos = 8,
  .pktfield2_slabmask = 0x00000000000000FCLLU,
};

void
dpdk_device_config_hqos_pipe_profile_default(dpdk_device_config_hqos_t * hqos, u32 pipe_profile_id)
{
    memcpy(&hqos->pipe[pipe_profile_id], &hqos_pipe_params_default, sizeof(hqos_pipe_params_default));
}

void
dpdk_device_config_hqos_default(dpdk_device_config_hqos_t * hqos)
{
  struct rte_sched_subport_params *subport_params;
  struct rte_sched_pipe_params *pipe_params;
  u32 *pipe_map;
  u32 i;

  memcpy(hqos, &hqos_params_default, sizeof(hqos_params_default));

  memcpy(hqos->tc_table, hqos_tc_table_default, sizeof(hqos_tc_table_default));

  /* port */
  memcpy(&hqos->port,
    &hqos_port_params_default,
    sizeof(hqos_port_params_default));

  /* pipe */
  vec_add2(hqos->pipe,
    pipe_params,
    hqos->port.n_pipe_profiles);

  for (i = 0; i < vec_len(hqos->pipe); i++)
    memcpy(&pipe_params[i],
      &hqos_pipe_params_default,
      sizeof(hqos_pipe_params_default));

  hqos->port.pipe_profiles = hqos->pipe;

  /* subport */
  vec_add2(hqos->subport,
    subport_params,
    hqos->port.n_subports_per_port);

  for (i = 0; i < vec_len(hqos->subport); i++)
    memcpy(&subport_params[i],
      &hqos_subport_params_default,
      sizeof(hqos_subport_params_default));

  /* pipe profile */
  vec_add2(hqos->pipe_map,
    pipe_map,
    hqos->port.n_subports_per_port * hqos->port.n_pipes_per_subport);

  for (i = 0; i < vec_len(hqos->pipe_map); i++)
    pipe_map[i] = 0;
}

clib_error_t *
dpdk_port_setup_hqos (dpdk_device_t * xd, dpdk_device_config_hqos_t *hqos)
{
  vlib_thread_main_t * tm = vlib_get_thread_main();
  char name[32];
  u32 subport_id, i;
  int rv;

  /* Detect the set of worker threads */
  int worker_thread_first = 0;
  int worker_thread_count = 0;

  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  vlib_thread_registration_t *tr = p ? (vlib_thread_registration_t *) p[0] : 0;

  if (tr && tr->count > 0) {
    worker_thread_first = tr->first_index;
    worker_thread_count = tr->count;
  }

  /* Allocate the per-thread device data array */
  vec_validate_aligned (xd->hqos_worker, tm->n_vlib_mains - 1, CLIB_CACHE_LINE_BYTES);
  memset(xd->hqos_worker, 0, tm->n_vlib_mains * sizeof(xd->hqos_worker[0]));

  vec_validate_aligned (xd->hqos_iotx, 0, CLIB_CACHE_LINE_BYTES);
  memset(xd->hqos_iotx, 0, sizeof(xd->hqos_iotx[0]));

  /* Allocate space for one SWQ per worker thread in the I/O TX thread data structure */
  vec_validate(xd->hqos_iotx->swq, worker_thread_count - 1);

  /* SWQ */
  for (i = 0; i < worker_thread_count; i++) {
    u32 swq_flags = RING_F_SP_ENQ | RING_F_SC_DEQ;

    snprintf(name, sizeof(name), "SWQ-worker%u-to-device%u", i, xd->device_index);
    xd->hqos_iotx->swq[i] = rte_ring_create(name, hqos->swq_size, xd->cpu_socket, swq_flags);
    if (xd->hqos_iotx->swq[i] == NULL)
      return clib_error_return (0, "SWQ-worker%u-to-device%u: rte_ring_create err", i, xd->device_index);
  }

  /*
   * HQoS
   */

  /* HQoS port */
  snprintf(name, sizeof(name), "HQoS%u", xd->device_index);
  hqos->port.name = strdup(name);
  if (hqos->port.name == NULL)
    return clib_error_return (0, "HQoS%u: strdup err", xd->device_index);

  hqos->port.socket = rte_eth_dev_socket_id(xd->device_index);
  if (hqos->port.socket == SOCKET_ID_ANY)
    hqos->port.socket = 0;

  xd->hqos_iotx->hqos = rte_sched_port_config(&hqos->port);
  if (xd->hqos_iotx->hqos == NULL)
    return clib_error_return (0, "HQoS%u: rte_sched_port_config err", xd->device_index);

  /* HQoS subport */
  for (subport_id = 0; subport_id < hqos->port.n_subports_per_port; subport_id ++) {
    u32 pipe_id;

    rv = rte_sched_subport_config(xd->hqos_iotx->hqos, subport_id, &hqos->subport[subport_id]);
    if (rv)
      return clib_error_return (0, "HQoS%u subport %u: rte_sched_subport_config err (%d)", xd->device_index, subport_id, rv);

    /* HQoS pipe */
    for (pipe_id = 0; pipe_id < hqos->port.n_pipes_per_subport; pipe_id ++) {
      u32 pos = subport_id * hqos->port.n_pipes_per_subport + pipe_id;
      u32 profile_id = hqos->pipe_map[pos];

      rv = rte_sched_pipe_config(xd->hqos_iotx->hqos, subport_id, pipe_id, profile_id);
      if (rv)
        return clib_error_return (0, "HQoS%u subport %u pipe %u: rte_sched_pipe_config err (%d)", xd->device_index, subport_id, pipe_id, rv);
    }
  }

  /* Set up per-thread device data for the I/O TX thread */
  xd->hqos_iotx->hqos_burst_enq = hqos->burst_enq;
  xd->hqos_iotx->hqos_burst_deq = hqos->burst_deq;
  vec_validate(xd->hqos_iotx->pkts_enq, 2 * hqos->burst_enq - 1);
  vec_validate(xd->hqos_iotx->pkts_deq, hqos->burst_deq - 1);
  xd->hqos_iotx->pkts_enq_len = 0;
  xd->hqos_iotx->swq_pos = 0;

  /* Set up per-thread device data for each worker thread */
  for (i = 0; i < worker_thread_count; i++) {
    u32 tid = worker_thread_first + i;

    xd->hqos_worker[tid].swq = xd->hqos_iotx->swq[i];
    xd->hqos_worker[tid].hqos_field0_slabpos = hqos->pktfield0_slabpos;
    xd->hqos_worker[tid].hqos_field0_slabmask = hqos->pktfield0_slabmask;
    xd->hqos_worker[tid].hqos_field0_slabshr = __builtin_ctzll(hqos->pktfield0_slabmask);
    xd->hqos_worker[tid].hqos_field1_slabpos = hqos->pktfield1_slabpos;
    xd->hqos_worker[tid].hqos_field1_slabmask = hqos->pktfield1_slabmask;
    xd->hqos_worker[tid].hqos_field1_slabshr = __builtin_ctzll(hqos->pktfield1_slabmask);
    xd->hqos_worker[tid].hqos_field2_slabpos = hqos->pktfield2_slabpos;
    xd->hqos_worker[tid].hqos_field2_slabmask = hqos->pktfield2_slabmask;
    xd->hqos_worker[tid].hqos_field2_slabshr = __builtin_ctzll(hqos->pktfield2_slabmask);
    memcpy(xd->hqos_worker[tid].hqos_tc_table, hqos->tc_table, sizeof(hqos->tc_table));
  }

  return 0;
}
