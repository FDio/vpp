/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

/* Copyright (c) 2019 Marvell International Ltd. */

#include <unistd.h>
#include <fcntl.h>

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/linux/sysfs.c>

#include <vnet/ethernet/ethernet.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/mpls/packet.h>

#include <octeontx2/buffer.h>
#include <octeontx2/device/octeontx2.h>
#include <octeontx2/device/otx2_priv.h>

static clib_error_t *
show_otx2_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, bm->buffer_pools)
  {
    struct rte_mempool *rmp = otx2_mempool_by_buffer_pool_index[bp->index];
    if (rmp)
      {
	unsigned count = rte_mempool_avail_count (rmp);
	unsigned free_count = rte_mempool_in_use_count (rmp);

	vlib_cli_output (vm,
			 "name=\"%s\"  available = %7d allocated = %7d total = %7d\n",
			 rmp->name, (u32) count, (u32) free_count,
			 (u32) (count + free_count));
      }
    else
      {
	vlib_cli_output (vm, "rte_mempool is NULL (!)\n");
      }
  }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_otx2_buffer,static) = {
    .path = "show octeontx2 mempool",
    .short_help = "show DPDK mempool buffers managed by hardware aka NPA",
    .function = show_otx2_buffer,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
show_otx2_physmem (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  clib_error_t *err = 0;
  u32 pipe_max_size;
  int fds[2];
  u8 *s = 0;
  int n, n_try;
  FILE *f;

  err = clib_sysfs_read ("/proc/sys/fs/pipe-max-size", "%u", &pipe_max_size);

  if (err)
    return err;

  if (pipe (fds) == -1)
    return clib_error_return_unix (0, "pipe");

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	(1024 + 7)
#endif

  if (fcntl (fds[1], F_SETPIPE_SZ, pipe_max_size) == -1)
    {
      err = clib_error_return_unix (0, "fcntl(F_SETPIPE_SZ)");
      goto error;
    }

  if (fcntl (fds[0], F_SETFL, O_NONBLOCK) == -1)
    {
      err = clib_error_return_unix (0, "fcntl(F_SETFL)");
      goto error;
    }

  if ((f = fdopen (fds[1], "a")) == 0)
    {
      err = clib_error_return_unix (0, "fdopen");
      goto error;
    }

  rte_dump_physmem_layout (f);
  fflush (f);

  n = n_try = 4096;
  while (n == n_try)
    {
      uword len = vec_len (s);
      vec_resize (s, len + n_try);

      n = read (fds[0], s + len, n_try);
      if (n < 0 && errno != EAGAIN)
	{
	  err = clib_error_return_unix (0, "read");
	  goto error;
	}
      _vec_len (s) = len + (n < 0 ? 0 : n);
    }

  vlib_cli_output (vm, "%v", s);

error:
  close (fds[0]);
  close (fds[1]);
  vec_free (s);
  return err;
}

/*?
 * This command displays Marvell OCTEONTX2 DPDK physmem layout
 *
 * @cliexpar
 * Example of how to display physmem layout:
 * @cliexstart{show octeontx2 physmem}
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_octeontx2_physmem,static) = {
    .path = "show octeontx2 physmem",
    .short_help = "show octeontx2 physmem",
    .function = show_otx2_physmem,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
show_otx2_version_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
#define _(a,b,c) vlib_cli_output (vm, "%-25s " b, a ":", c);
  _("Marvell DPDK Version", "%s", rte_version ());
  _("Marvell DPDK EAL init args", "%s", otx2_config_main.eal_init_args_str);
#undef _
  return 0;
}

/*?
 * This command is used to display the current Marvell OCTEONTX2 DPDK version and
 * the list of arguments passed to it when started.
 *
 * @cliexpar
 * Show version
 * @cliexstart{show octeontx2 version}
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_octeontx2_version_command, static) = {
  .path = "show octeontx2 version",
  .short_help = "show octeontx2 version - Marvell custom DPDK version",
  .function = show_otx2_version_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
