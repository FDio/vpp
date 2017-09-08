/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * unix.h: Unix specific main state
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_unix_unix_h
#define included_unix_unix_h

#include <vppinfra/socket.h>
#include <termios.h>


struct unix_file;
typedef clib_error_t *(unix_file_function_t) (struct unix_file * f);

typedef struct unix_file
{
  /* Unix file descriptor from open/socket. */
  u32 file_descriptor;

  u32 flags;
#define UNIX_FILE_DATA_AVAILABLE_TO_WRITE (1 << 0)
#define UNIX_FILE_EVENT_EDGE_TRIGGERED   (1 << 1)

  /* Data available for function's use. */
  uword private_data;

  /* Functions to be called when read/write data becomes ready. */
  unix_file_function_t *read_function, *write_function, *error_function;
} unix_file_t;

typedef struct
{
  f64 time;
  clib_error_t *error;
} unix_error_history_t;

typedef enum
{
  UNIX_FILE_UPDATE_ADD,
  UNIX_FILE_UPDATE_MODIFY,
  UNIX_FILE_UPDATE_DELETE,
} unix_file_update_type_t;

typedef struct
{
  /* Back pointer to main structure. */
  vlib_main_t *vlib_main;

  u32 flags;
  /* Run interactively or as daemon (background process). */
#define UNIX_FLAG_INTERACTIVE (1 << 0)
#define UNIX_FLAG_NODAEMON (1 << 1)

  /* Pool of files to poll for input/output. */
  unix_file_t *file_pool;

  /* CLI listen socket. */
  clib_socket_t cli_listen_socket;

  void (*file_update) (unix_file_t * file,
		       unix_file_update_type_t update_type);

  /* Circular buffer of last unix errors. */
  unix_error_history_t error_history[128];
  u32 error_history_index;
  u64 n_total_errors;

  /* startup-config filename */
  u8 *startup_config_filename;

  /* runtime directory path */
  u8 *runtime_dir;

  /* pidfile filename */
  u8 *pidfile;

  /* unix config complete */
  volatile int unix_config_complete;

  /* CLI log file. GIGO. */
  u8 *log_filename;
  int log_fd;

  /* Don't put CLI connections into character mode */
  int cli_line_mode;

  /* Maximum amount of command line history to keep per session */
  u32 cli_history_limit;

  /* Suppress the welcome banner at CLI session start */
  int cli_no_banner;

  /* Maximum pager buffer size */
  u32 cli_pager_buffer_limit;

  /* Suppress the pager */
  int cli_no_pager;

  /* Store the original state of stdin when it's a tty */
  struct termios tio_stdin;
  int tio_isset;
} unix_main_t;

/* Global main structure. */
extern unix_main_t unix_main;

always_inline uword
unix_file_add (unix_main_t * um, unix_file_t * template)
{
  unix_file_t *f;
  pool_get (um->file_pool, f);
  f[0] = template[0];
  um->file_update (f, UNIX_FILE_UPDATE_ADD);
  return f - um->file_pool;
}

always_inline void
unix_file_del (unix_main_t * um, unix_file_t * f)
{
  um->file_update (f, UNIX_FILE_UPDATE_DELETE);
  close (f->file_descriptor);
  f->file_descriptor = ~0;
  pool_put (um->file_pool, f);
}

always_inline void
unix_file_del_by_index (unix_main_t * um, uword index)
{
  unix_file_t *uf;
  uf = pool_elt_at_index (um->file_pool, index);
  unix_file_del (um, uf);
}

always_inline uword
unix_file_set_data_available_to_write (u32 unix_file_index,
				       uword is_available)
{
  unix_file_t *uf = pool_elt_at_index (unix_main.file_pool, unix_file_index);
  uword was_available = (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
  if ((was_available != 0) != (is_available != 0))
    {
      uf->flags ^= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      unix_main.file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
  return was_available != 0;
}

always_inline void
unix_save_error (unix_main_t * um, clib_error_t * error)
{
  unix_error_history_t *eh = um->error_history + um->error_history_index;
  clib_error_free_vector (eh->error);
  eh->error = error;
  eh->time = vlib_time_now (um->vlib_main);
  um->n_total_errors += 1;
  if (++um->error_history_index >= ARRAY_LEN (um->error_history))
    um->error_history_index = 0;
}

/* Main function for Unix VLIB. */
int vlib_unix_main (int argc, char *argv[]);

clib_error_t *unix_physmem_init (vlib_main_t * vm);

/* Set prompt for CLI. */
void vlib_unix_cli_set_prompt (char *prompt);

static inline unix_main_t *
vlib_unix_get_main (void)
{
  return &unix_main;
}

static inline char *
vlib_unix_get_runtime_dir (void)
{
  return (char *) unix_main.runtime_dir;
}

/* thread stack array; vec_len = max number of threads */
extern u8 **vlib_thread_stacks;

/* utils */

clib_error_t *foreach_directory_file (char *dir_name,
				      clib_error_t * (*f) (void *arg,
							   u8 * path_name,
							   u8 * file_name),
				      void *arg, int scan_dirs);

clib_error_t *vlib_unix_recursive_mkdir (char *path);

clib_error_t *vlib_unix_validate_runtime_file (unix_main_t * um,
					       const char *path,
					       u8 ** full_path);

#endif /* included_unix_unix_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
