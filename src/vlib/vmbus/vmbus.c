/*
 * Copyright (c) 2018, Microsoft Corporation.
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

#include <vlib/vlib.h>
#include <vlib/vmbus/vmbus.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* this is a stub replaced by the Linux specfic version */
vlib_vmbus_addr_t * __attribute__ ((weak)) vlib_vmbus_get_all_dev_addrs ()
{
  return NULL;
}

clib_error_t *
vmbus_bus_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vmbus_bus_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
