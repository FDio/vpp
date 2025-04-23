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
  vlib_node_main_t *nm = &vm->node_main;
  unix_main_t *um = &unix_main;
  struct epoll_event *e, epoll_events[16];
  int n_fds_ready;
  int is_main = (vm->thread_index == 0);
  int timeout_ms = 0, max_timeout_ms = 10;
  u32 ticks;

  /*
   * If we've been asked for a fixed-sleep between main loop polls,
   * do so right away.
   */
  if (PREDICT_FALSE (is_main && um->poll_sleep_usec))
    {
      struct timespec ts, tsrem;
      ts.tv_sec = 0;
      ts.tv_nsec = 1000L * um->poll_sleep_usec;

      while (nanosleep (&ts, &tsrem) < 0)
	ts = tsrem;

      goto epoll;
    }

  /* we are busy, skip some loops before polling again */
  if (vlib_last_vectors_per_main_loop (vm) >= 2)
    goto skip_loops;

  /* at least one node is polling */
  if (nm->input_node_counts_by_state[VLIB_NODE_STATE_POLLING])
    goto skip_loops;

  /* pending APIs in the queue */
  if (is_main && vm->api_queue_nonempty)
    goto skip_loops;

  if (is_main == 0)
    {
      if (*vlib_worker_threads->wait_at_barrier)
	goto epoll;

      if (vlib_get_first_main ()->time_last_barrier_release + 0.5 >=
	  vlib_time_now (vm))
	goto skip_loops;
    }

  /* check for pending interrupts */
  for (int nt = 0; nt < VLIB_N_NODE_TYPE; nt++)
    if (nm->node_interrupts[nt] &&
	clib_interrupt_is_any_pending (nm->node_interrupts[nt]))
      goto epoll;

  /* at this point we know that thread is going to sleep, so let's annonce
   * to other threads that they need to wakeup us if they need our attention */
  __atomic_store_n (&vm->thread_sleeps, 1, __ATOMIC_RELAXED);

  ticks = vlib_tw_timer_first_expires_in_ticks (vm);

  if (ticks != TW_SLOTS_PER_RING)
    {
      timeout_ms = (int) (ticks / ((u32) VLIB_TW_TICKS_PER_SECOND / 1000));
      timeout_ms = clib_min (timeout_ms, max_timeout_ms);
    }
  else
    timeout_ms = max_timeout_ms;

  goto epoll;

skip_loops:
  /* Don't come back for a respectable number of dispatch cycles */
  vm->file_poll_skip_loops = 1024;

epoll:
  n_fds_ready = epoll_wait (vm->epoll_fd, epoll_events,
			    ARRAY_LEN (epoll_events), timeout_ms);

  __atomic_store_n (&vm->thread_sleeps, 0, __ATOMIC_RELAXED);
  __atomic_store_n (&vm->wakeup_pending, 0, __ATOMIC_RELAXED);

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
      clib_error_t *err;

      if (PREDICT_FALSE (!f->active))
	{
	  foreach_int (flag, EPOLLIN, EPOLLOUT, EPOLLERR)
	    if (e->events & flag)
	      {
		const char *str[] = {
		  [EPOLLIN] = "EPOLLIN",
		  [EPOLLOUT] = "EPOLLOUT",
		  [EPOLLERR] = "EPOLLERR",
		};
		log_debug ("epoll event %s dropped due to inactive file",
			   str[flag]);
	      }
	  continue;
	}
      else if (PREDICT_TRUE (!(e->events & EPOLLERR)))
	{
	  if (e->events & EPOLLIN)
	    {
	      f->read_events++;
	      err = f->read_function (f);
	      if (err)
		{
		  log_err ("file read error: %U", format_clib_error, err);
		  clib_error_free (err);
		}
	    }
	  if (e->events & EPOLLOUT)
	    {
	      f->write_events++;
	      err = f->write_function (f);
	      if (err)
		{
		  log_err ("file write error: %U", format_clib_error, err);
		  clib_error_free (err);
		}
	    }
	}
      else
	{
	  if (f->error_function)
	    {
	      f->error_events++;
	      err = f->error_function (f);
	      if (err)
		{
		  log_err ("file error: %U", format_clib_error, err);
		  clib_error_free (err);
		}
	    }
	  else if (f->dont_close == 0)
	    close ((int) f->file_descriptor);
	}
    }

  /* maximum epoll events received, there may be more ... */
  if (n_fds_ready == ARRAY_LEN (epoll_events))
    {
      timeout_ms = 0;
      goto epoll;
    }

  /* removing fd from epoll instance doesn't remove event from epoll queue
   * so we need to be sure epoll queue is empty before freeing */
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
