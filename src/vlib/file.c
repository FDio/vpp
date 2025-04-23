/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <limits.h>

VLIB_REGISTER_LOG_CLASS (vlib_file_log, static) = {
  .class_name = "vlib",
  .subclass_name = "file",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (vlib_file_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (vlib_file_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...) vlib_log_err (vlib_file_log.class, fmt, __VA_ARGS__)

clib_file_main_t file_main;

static void
vlib_file_update (clib_file_t *f, clib_file_update_type_t update_type)
{
  vlib_main_t *vm = vlib_get_main_by_index (f->polling_thread_index);
  int op = -1, add_del = 0;

  struct epoll_event e = {
    .events = EPOLLIN,
    .data.u32 = f->index,
  };

  if (f->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE)
    e.events |= EPOLLOUT;
  if (f->flags & UNIX_FILE_EVENT_EDGE_TRIGGERED)
    e.events |= EPOLLET;

  switch (update_type)
    {
    case UNIX_FILE_UPDATE_ADD:
      op = EPOLL_CTL_ADD;
      add_del = 1;
      break;

    case UNIX_FILE_UPDATE_MODIFY:
      op = EPOLL_CTL_MOD;
      break;

    case UNIX_FILE_UPDATE_DELETE:
      op = EPOLL_CTL_DEL;
      add_del = -1;
      break;

    default:
      log_err ("%s: unknown update_type %d", __func__, update_type);
      return;
    }

  if (epoll_ctl (vm->epoll_fd, op, (int) f->file_descriptor, &e) < 0)
    {
      log_err ("%s: epoll_ctl() failed, errno %d", __func__, errno);
      return;
    }

  vm->n_epoll_fds += add_del;
}

void
vlib_file_poll_init (vlib_main_t *vm)
{
  vm->epoll_fd = epoll_create (1);

  if (vm->epoll_fd < 0)
    clib_panic ("failed to initialize epoll for thread %u", vm->thread_index);

  if (!file_main.file_update)
    file_main.file_update = vlib_file_update;
}
