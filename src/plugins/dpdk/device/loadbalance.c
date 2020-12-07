/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vppinfra/linux/sysfs.h>
#include <vlib/unix/unix.h>
#include <vlib/log.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <vlib/pci/pci.h>
#include <vlib/vmbus/vmbus.h>

#include <rte_ring.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>

#include <dpdk/device/dpdk_priv.h>

static int dpdk_lb_debug = 0;

static void
dpdk_device_reta_dump (dpdk_device_t * xd)
{
  int i, j;

  dpdk_log_notice ("LB: reta size %d, group size %d",
                 xd->reta_size, RTE_RETA_GROUP_SIZE);
  for (i = 0; i < (xd->reta_size/RTE_RETA_GROUP_SIZE); i++) {
      for (j = 0; j < RTE_RETA_GROUP_SIZE;) {
          dpdk_log_notice ("LB: [%d] %x %x %x %x %x %x %x %x", i,
                     xd->reta_conf[i].reta[j],
                     xd->reta_conf[i].reta[j+1],
                     xd->reta_conf[i].reta[j+2],
                     xd->reta_conf[i].reta[j+3],
                     xd->reta_conf[i].reta[j+4],
                     xd->reta_conf[i].reta[j+5],
                     xd->reta_conf[i].reta[j+6],
                     xd->reta_conf[i].reta[j+7]);
          j +=8;
      }
  }
}

/*
 * Modify the RSS reta table, replace the src id with dest id every 'ratio'.
 */
static void
dpdk_device_balance_handler (dpdk_device_t * xd, u16 src_q_id, u16 dest_q_id, u16 ratio)
{
  int i, j, rc;
  u32 total = 0;;

  dpdk_log_notice ("LB: Loadbalance handling for port %d, src_q_id %d, dest_q_id %d, ratio %d",
                 xd->port_id, src_q_id, dest_q_id, ratio);

  clib_memset (&xd->reta_conf[0], 0,
               (xd->reta_size/RTE_RETA_GROUP_SIZE) * sizeof(xd->reta_conf[0]));
  for (i = 0; i < (xd->reta_size/RTE_RETA_GROUP_SIZE); i++) {
      xd->reta_conf[i].mask = UINT64_MAX;
  }
  rc = rte_eth_dev_rss_reta_query(xd->port_id, &xd->reta_conf[0], xd->reta_size);
  if (rc) {
      dpdk_log_warn ("LB: Failed to get reta config for port %d, rc %d",
                     xd->port_id, rc);
      return;
  }

  if (dpdk_lb_debug) {
      dpdk_device_reta_dump (xd);
  }

  for (i = 0; i < (xd->reta_size/RTE_RETA_GROUP_SIZE); i++) {
      xd->reta_conf[i].mask = UINT64_MAX;
      for (j = 0; j < RTE_RETA_GROUP_SIZE; j++) {
          if (xd->reta_conf[i].reta[j] == src_q_id) {
              if (total++ % ratio == 0) {
                  xd->reta_conf[i].reta[j] = dest_q_id;
              }
          }
      }
  }
  rc = rte_eth_dev_rss_reta_update(xd->port_id, &xd->reta_conf[0], xd->reta_size);
  if (rc) {
      dpdk_log_warn ("LB: Failed to update reta config for port %d, rc %d",
                     xd->port_id, rc);
      return;
  }
  dpdk_log_notice ("LB: Changed reta config for port %d, orignal total src q total %d",
                 xd->port_id, total);

  if (dpdk_lb_debug) {
      dpdk_device_reta_dump (xd);
  }
}

static int
dpdk_load_cmp (void *a1, void *a2)
{
  dpdk_loadbalance_worker_t *w1 = a1;
  dpdk_loadbalance_worker_t *w2 = a2;

  return (w1->load - w2->load);
}

/*
 * Get the worker list and LB info.
 */
void
dpdk_loadbalance_init (void)
{
    dpdk_main_t *dm = &dpdk_main;
    vnet_device_main_t *vdm = &vnet_device_main;

    vlib_node_t **nodes;
    uword i, j;
    vlib_main_t **stat_vms = 0, *stat_vm;
    dpdk_loadbalance_worker_t *lb_worker;

    /* skip the main */
    for (i = 1; i < vec_len (vlib_mains); i++)
    {
        stat_vm = vlib_mains[i];
        if (stat_vm) {
            vec_add1 (stat_vms, stat_vm);
        }
    }

    for (i = 0; i < vec_len (stat_vms); i++)
    {
        stat_vm = stat_vms[i];
        nodes = stat_vm->node_main.nodes;
        for (j = 0; j < vec_len (nodes); j++)
        {
            if (!strcmp((const char *)nodes[j]->name, "dpdk-input")) {
                vec_add2_aligned (dm->loadbalance.lb_workers, lb_worker, 1, CLIB_CACHE_LINE_BYTES);
                lb_worker->stat_vm = stat_vm;
                lb_worker->dpdk_node_index = j;
                lb_worker->thread_index = vdm->first_worker_thread_index + i;
                lb_worker->ratio = DPDK_LB_BALANCE_RATIO;
                dpdk_log_notice ("LB: added LB worker thread %d",
                                 lb_worker->thread_index);
                break;
            }
        }
    }
    vec_free (stat_vms);

    return;
}

/*
 * Periodicall called.
 * Caculate the DPDK input loads of workers, get the highest and lowest workers.
 */
void
dpdk_loadbalance_update (f64 now)
{
    vlib_main_t *vm = vlib_get_main ();
    dpdk_main_t *dm = &dpdk_main;
    dpdk_device_t *xd;
    dpdk_loadbalance_worker_t *lb_worker;
    dpdk_loadbalance_worker_t *lb_worker_high;
    vlib_node_t *dpdk_node;
    u64 v_diff, c_diff;
    u16 highs = 0;
    u16 lows = 0;
    int i, j;
    vnet_hw_interface_t *hw;
    u16 high_q_id;
    u16 low_q_id;

    if (dpdk_lb_debug) {
        dpdk_log_warn ("LB: ---lb_update called");
    }
    dm->loadbalance.time_last_lb_update = now ? now : dm->loadbalance.time_last_lb_update;

    /*
     * Barrier sync across stats scraping.
     * Otherwise, the counts will be grossly inaccurate.
     */

    vlib_worker_thread_barrier_sync (vm);

    vec_foreach (lb_worker, dm->loadbalance.lb_workers)
    {
        dpdk_node = lb_worker->stat_vm->node_main.nodes[lb_worker->dpdk_node_index];
        if (!dpdk_node) {
            dpdk_log_warn ("LB: lb_update NULL dpdk_node found!!!");
            continue;
        }
        vlib_node_sync_stats (lb_worker->stat_vm, dpdk_node);
        lb_worker->vectors = dpdk_node->stats_total.vectors;
        lb_worker->calls = dpdk_node->stats_total.calls;
    }
    vlib_worker_thread_barrier_release (vm);

    vec_foreach (lb_worker, dm->loadbalance.lb_workers)
    {
        v_diff = lb_worker->vectors - lb_worker->old_vectors;
        c_diff = lb_worker->calls - lb_worker->old_calls;
        lb_worker->old_vectors = lb_worker->vectors;
        lb_worker->old_calls = lb_worker->calls;
        if (!c_diff) {
            dpdk_log_info ("LB: thread %d, no changed, calls %llu, vectors %llu, load %d",
                       lb_worker->thread_index,
                       lb_worker->calls, lb_worker->vectors, lb_worker->load);
            /* Give a medium value, then it will not join the balancing. */
            lb_worker->load = (DPDK_LB_LOAD_HIGH_TH+DPDK_LB_LOAD_LOW_TH)/2;
        } else {
            lb_worker->load = v_diff/c_diff;
        }
        if (lb_worker->load > DPDK_LB_LOAD_HIGH_TH) {
            if (lb_worker->ratio) {
                highs++;
            }
        } else if (lb_worker->load < DPDK_LB_LOAD_LOW_TH) {
            lows++;
            lb_worker->ratio = DPDK_LB_BALANCE_RATIO;
        }

        if (dpdk_lb_debug) {
            dpdk_log_warn ("LB: thread %d, c_diff %llu, v_diff %llu, load %d",
                       lb_worker->thread_index,
                       c_diff, v_diff, lb_worker->load);
        }
    }

    if (!highs || !lows) {
        /* no high or no low, doesn't balance. */
        return;
    }
    /*
     * Need balance.
     */
    vec_sort_with_function (dm->loadbalance.lb_workers, dpdk_load_cmp);
    if (dpdk_lb_debug) {
        for (i = 0; i < vec_len(dm->loadbalance.lb_workers); i++) {
            lb_worker =  &dm->loadbalance.lb_workers[i];
             dpdk_log_notice ("LB: thread %d, calls %llu, vectors %llu, load %d, ratio %d",
                       lb_worker->thread_index, lb_worker->calls,
                       lb_worker->vectors, lb_worker->load, lb_worker->ratio);
        }
    }
    for (i = 0; i < highs; i++) {
        lb_worker_high =
            &dm->loadbalance.lb_workers[vec_len(dm->loadbalance.lb_workers) - i - 1];
        if (lb_worker_high->ratio) {
            break;
        }
    }
    if (i == highs) {
        return;
    }
    if (dpdk_lb_debug) {
        dpdk_log_notice ("LB: high worker, thread %d, ratio %d, load %d",
                   lb_worker_high->thread_index, lb_worker_high->ratio,
                   lb_worker_high->load);
    }

    vec_foreach (xd, dm->devices)
    {
        if (xd->loadbalance_enabled) {
            dpdk_log_info ("LB: xd port id %d, no loadbalance enabled",
                   xd->port_id);
            continue;
        }
        hw = vnet_get_hw_interface (dm->vnet_main, xd->hw_if_index);
        if (!hw) {
            dpdk_log_warn ("LB: xd port id %d, no hw",
                   xd->port_id);
            continue;
        }
        for (high_q_id = 0; high_q_id < xd->rx_q_used; high_q_id++) {
            if (hw->input_node_thread_index_by_queue[high_q_id] ==
                lb_worker_high->thread_index) {
                break;
            }
        }
        if (high_q_id == xd->rx_q_used) {
            continue;
        }

        for (j = 0; j < lows; j++)
        {
            for (low_q_id = 0; low_q_id < xd->rx_q_used; low_q_id++) {
                if (hw->input_node_thread_index_by_queue[low_q_id] ==
                    dm->loadbalance.lb_workers[j].thread_index) {
                    break;
                }
            }
            if (low_q_id != xd->rx_q_used) {
                /*
                 * blance from high queue to low queue;
                 */
                dpdk_log_notice ("LB: Need balance low worker %d, high q %d, low q %d",
                       j, high_q_id, low_q_id);
                dpdk_device_balance_handler(xd, high_q_id, low_q_id, lb_worker_high->ratio);
                break;
            }
        }
    }
    if (lb_worker_high->ratio) {
        lb_worker_high->ratio--;
    }
}
