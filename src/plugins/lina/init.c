/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */


#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <inttypes.h>
#include <limits.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/linux/syscall.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <lina/shared.h>
#include <lina/lina.h>

lina_main_t lina_main;

void
lina_create_instance (vlib_main_t * vm, lina_create_instance_args_t * a)
{
  lina_main_t *lm = &lina_main;
  clib_mem_vm_alloc_t alloc = { 0 };
  lina_instance_t *lin;

  pool_get_aligned_zero (lm->instances, lin, CLIB_CACHE_LINE_BYTES);
  lin->index = lin - lm->instances;
  lin->listener_filename = format (0, "%s%c", a->filename, 0);

  /* allocate shared memory */
  lin->shm_size = 4096;
  alloc.name = "lina region";
  alloc.size = lin->shm_size;
  alloc.flags = CLIB_MEM_VM_F_SHARED;

  a->error = clib_mem_vm_ext_alloc (&alloc);
  if (a->error)
    goto error;

  lin->fd = alloc.fd;
  lin->shm_hdr = alloc.addr;

  lin->shm_hdr->cookie = LINA_SHM_HDR_COOKIE;
  if ((a->error = lina_socket_listener_create (vm, lin)))
    goto error;

  return;

error:
  pool_put (lm->instances, lin);
}

static clib_error_t *
lina_init (vlib_main_t * vm)
{
  lina_main_t *mm = &lina_main;

  clib_memset (mm, 0, sizeof (lina_main_t));

  mm->log_class = vlib_log_register_class ("lina", 0);

  return 0;
}

VLIB_INIT_FUNCTION (lina_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = "1.0",
    .description = "lina enqueue/dequeue plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
