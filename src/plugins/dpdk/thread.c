/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <rte_config.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>

static clib_error_t *
dpdk_launch_thread (void *fp, vlib_worker_thread_t * w, unsigned lcore_id)
{
  int r;
  r = rte_eal_remote_launch (fp, (void *) w, lcore_id);
  if (r)
    return clib_error_return (0, "Failed to launch thread %u", lcore_id);
  return 0;
}

static clib_error_t *
dpdk_thread_set_lcore (u32 thread, u16 lcore)
{
  return 0;
}

static vlib_thread_callbacks_t callbacks = {
  .vlib_launch_thread_cb = &dpdk_launch_thread,
  .vlib_thread_set_lcore_cb = &dpdk_thread_set_lcore,
};

static clib_error_t *
dpdk_thread_init (vlib_main_t * vm)
{
  vlib_thread_cb_register (vm, &callbacks);
  return 0;
}

VLIB_INIT_FUNCTION (dpdk_thread_init);

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
