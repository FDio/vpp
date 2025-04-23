/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <limits.h>

clib_file_main_t file_main;

void
vlib_file_poll_init (vlib_main_t *vm)
{
  vm->epoll_fd = epoll_create (1);

  if (vm->epoll_fd < 0)
    clib_panic ("failed to initialize epoll for thread %u", vm->thread_index);
}
