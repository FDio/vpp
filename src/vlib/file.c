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
    .data.ptr = f,
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

static clib_error_t *
wake_read_fn (struct clib_file *f)
{
  u64 val, __clib_unused rv;
  rv = read ((int) f->file_descriptor, &val, sizeof (u64));
  return 0;
}

void
vlib_file_poll_init (vlib_main_t *vm)
{
  vm->epoll_fd = epoll_create (1);

  if (vm->epoll_fd < 0)
    clib_panic ("failed to initialize epoll for thread %u", vm->thread_index);

  vm->wakeup_fd = eventfd (0, EFD_NONBLOCK);

  if (vm->wakeup_fd < 0)
    clib_panic ("failed to initialize wakeup event for thread %u",
		vm->thread_index);

  if (!file_main.file_update)
    file_main.file_update = vlib_file_update;

  clib_file_add (&file_main, &(clib_file_t){
			       .polling_thread_index = vm->thread_index,
			       .file_descriptor = vm->wakeup_fd,
			       .description = format (0, "wakeup thread %u",
						      vm->thread_index),
			       .read_function = wake_read_fn,
			     });
}

void
vlib_file_poll (vlib_main_t *vm)
{
  unix_main_t *um = &unix_main;
  struct epoll_event *e, epoll_events[256];
  int n_fds_ready;
  int is_main = (vm->thread_index == 0);

  vlib_node_main_t *nm = &vm->node_main;
  u32 ticks_until_expiration;
  f64 timeout;
  f64 now;
  int timeout_ms = 0, max_timeout_ms = 10;
  f64 vector_rate = vlib_last_vectors_per_main_loop (vm);

  if (is_main == 0)
    now = vlib_time_now (vm);

  /*
   * If we've been asked for a fixed-sleep between main loop polls,
   * do so right away.
   */
  if (PREDICT_FALSE (is_main && um->poll_sleep_usec))
    {
      struct timespec ts, tsrem;
      timeout = 0;
      timeout_ms = 0;
      vm->file_poll_skip_loops = 0;
      ts.tv_sec = 0;
      ts.tv_nsec = 1000L * um->poll_sleep_usec;

      while (nanosleep (&ts, &tsrem) < 0)
	{
	  ts = tsrem;
	}
    }
  /* If we're not working very hard, decide how long to sleep */
  else if (is_main && vector_rate < 2 && vm->api_queue_nonempty == 0 &&
	   nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] == 0)
    {
      ticks_until_expiration = vlib_tw_timer_first_expires_in_ticks (vm);

      /* Nothing on the fast wheel, sleep 10ms */
      if (ticks_until_expiration == TW_SLOTS_PER_RING)
	{
	  timeout = 10e-3;
	  timeout_ms = max_timeout_ms;
	}
      else
	{
	  timeout = (f64) ticks_until_expiration * 1e-5;
	  if (timeout < 1e-3)
	    timeout_ms = 0;
	  else
	    {
	      timeout_ms = timeout * 1e3;
	      /* Must be between 1 and 10 ms. */
	      timeout_ms = clib_max (1, timeout_ms);
	      timeout_ms = clib_min (max_timeout_ms, timeout_ms);
	    }
	}
      vm->file_poll_skip_loops = 0;
    }
  else if (is_main == 0 && vector_rate < 2 &&
	   (vlib_get_first_main ()->time_last_barrier_release + 0.5 < now) &&
	   nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING] == 0)
    {
      timeout = 10e-3;
      timeout_ms = max_timeout_ms;
      vm->file_poll_skip_loops = 0;
    }
  else /* busy */
    {
      /* Don't come back for a respectable number of dispatch cycles */
      vm->file_poll_skip_loops = 1024;
    }

  n_fds_ready = epoll_wait (vm->epoll_fd, epoll_events,
			    ARRAY_LEN (epoll_events), timeout_ms);

  if (n_fds_ready < 0)
    {
      if (unix_error_is_fatal (errno))
	vlib_panic_with_error (vm, clib_error_return_unix (0, "epoll_wait"));

      /* non fatal error (e.g. EINTR). */
      return;
    }

  vm->epoll_waits += 1;
  vm->epoll_files_ready += n_fds_ready;

  for (e = epoll_events; e < epoll_events + n_fds_ready; e++)
    {
      clib_file_t *f = e->data.ptr;
      clib_error_t *errors[4];
      int n_errors = 0;

      if (PREDICT_FALSE (!f->active))
	{
	  if (e->events & EPOLLIN)
	    {
	      errors[n_errors] =
		clib_error_return (0,
				   "epoll event EPOLLIN dropped due "
				   "to free index %u",
				   f->index);
	      n_errors++;
	    }
	  if (e->events & EPOLLOUT)
	    {
	      errors[n_errors] =
		clib_error_return (0,
				   "epoll event EPOLLOUT dropped due "
				   "to free index %u",
				   f->index);
	      n_errors++;
	    }
	  if (e->events & EPOLLERR)
	    {
	      errors[n_errors] =
		clib_error_return (0,
				   "epoll event EPOLLERR dropped due "
				   "to free index %u",
				   f->index);
	      n_errors++;
	    }
	}
      else if (PREDICT_TRUE (!(e->events & EPOLLERR)))
	{
	  if (e->events & EPOLLIN)
	    {
	      f->read_events++;
	      errors[n_errors] = f->read_function (f);
	      n_errors += errors[n_errors] != 0;
	    }
	  if (e->events & EPOLLOUT)
	    {
	      f->write_events++;
	      errors[n_errors] = f->write_function (f);
	      n_errors += errors[n_errors] != 0;
	    }
	}
      else
	{
	  if (f->error_function)
	    {
	      f->error_events++;
	      errors[n_errors] = f->error_function (f);
	      n_errors += errors[n_errors] != 0;
	    }
	  else if (f->dont_close == 0)
	    close ((int) f->file_descriptor);
	}

      ASSERT (n_errors < ARRAY_LEN (errors));
      for (u32 i = 0; i < n_errors; i++)
	{
	  unix_save_error (um, errors[i]);
	}
    }

  /* removing fd from epoll instance doesn't remove event from epoll queue
   * so we need to be sure epoll queue is empty before freeing */

  if (n_fds_ready < ARRAY_LEN (epoll_events))
    clib_file_free_deleted (&file_main, vm->thread_index);
}

static clib_error_t *
show_files (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  clib_file_main_t *fm = &file_main;
  char path[PATH_MAX];
  u8 *s = 0;

  vlib_cli_output (vm, "%3s %6s %12s %12s %12s %-32s %s", "FD", "Thread",
		   "Read", "Write", "Error", "File Name", "Description");

  pool_foreach_pointer (f, fm->file_pool)
    {
      ssize_t rv;
      s = format (s, "/proc/self/fd/%d%c", f->file_descriptor, 0);
      rv = readlink ((char *) s, path, PATH_MAX - 1);

      path[rv < 0 ? 0 : rv] = 0;

      vlib_cli_output (vm, "%3d %6d %12d %12d %12d %-32s %v",
		       f->file_descriptor, f->polling_thread_index,
		       f->read_events, f->write_events, f->error_events, path,
		       f->description);
      vec_reset_length (s);
    }
  vec_free (s);

  return error;
}

VLIB_CLI_COMMAND (cli_show_files, static) = {
  .path = "show files",
  .short_help = "Show files in use",
  .function = show_files,
};
