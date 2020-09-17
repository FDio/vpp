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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/vfio.h>
#include <sys/ioctl.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <dpdk/device/dpdk.h>
#include <vpp/app/version.h>

/*
 * Called by the dpdk driver's rte_delay_us() function.
 * Return 0 to have the dpdk do a regular delay loop.
 * Return 1 if to skip the delay loop because we are suspending
 * the calling vlib process instead.
 */
static int
rte_delay_us_override (unsigned us)
{
  vlib_main_t *vm;

  /* Don't bother intercepting for short delays */
  if (us < 10)
    return 0;

  /*
   * Only intercept if we are in a vlib process.
   * If we are called from a vlib worker thread or the vlib main
   * thread then do not intercept. (Must not be called from an
   * independent pthread).
   */
  if (vlib_get_thread_index () == 0)
    {
      /*
       * We're in the vlib main thread or a vlib process. Make sure
       * the process is running and we're not still initializing.
       */
      vm = vlib_get_main ();
      if (vlib_in_process_context (vm))
	{
	  /* Only suspend for the admin_down_process */
	  vlib_process_t *proc = vlib_get_current_process (vm);
	  if (!(proc->flags & VLIB_PROCESS_IS_RUNNING) ||
	      (proc->node_runtime.node_index !=
	       admin_up_down_process_node.index))
	    return 0;

	  f64 delay = 1e-6 * us;
	  vlib_process_suspend (vm, delay);
	  return 1;
	}
    }
  return 0;			// no override
}

static void
rte_delay_us_override_cb (unsigned us)
{
  if (rte_delay_us_override (us) == 0)
    rte_delay_us_block (us);
}

static clib_error_t * dpdk_main_init (vlib_main_t * vm)
{
  dpdk_main_t * dm = &dpdk_main;
  clib_error_t * error = 0;

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main ();

  /* register custom delay function */
  rte_delay_us_callback_register (rte_delay_us_override_cb);

  return error;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (dpdk_main_init) =
{
    .runs_after = VLIB_INITS("dpdk_init"),
};
/* *INDENT-ON* */


clib_error_t *
dpdk_early_init (vlib_main_t *vm)
{
  int fd = -1;
  u64 *pt = 0;
  clib_error_t *err = 0;

  /* check if pagemap is accessible - if we get zero result
     dpdk will not be able to get physical memory address and game is over
     unless we have IOMMU */
  pt = clib_mem_vm_get_paddr (&pt, CLIB_MEM_PAGE_SZ_DEFAULT, 1);
  if (pt && pt[0])
    goto check_hugetlb;

  if ((fd = open ("/dev/vfio/vfio", O_RDWR)) == -1)
      goto error;

  if (ioctl (fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION)
      goto error;

  /* if we have type 1 IOMMU page map is not needed */
  if (ioctl (fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU) != 1)
    goto error;

check_hugetlb:
  fd = clib_mem_vm_create_fd (CLIB_MEM_PAGE_SZ_DEFAULT_HUGE,
			      "dpdk early init");

  if (fd != -1)
    {
      u8 *page = clib_mem_vm_map_shared (0, 1, fd, 0, "dpdk_early_init");
      if (page != CLIB_MEM_VM_MAP_FAILED)
	{
	  clib_mem_vm_unmap (page);
	  goto done;
	}
    }

error:
  err = clib_error_return (0, "access to physical devices is not allowed");

done:
  if (fd != -1)
    close (fd);
  vec_free (pt);
  return err;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Data Plane Development Kit (DPDK)",
    .early_init = "dpdk_early_init",
};
/* *INDENT-ON* */
