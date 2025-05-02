/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 * Copyright (c) 2022 Intel and/or its affiliates.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/dma/dma.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vppinfra/linux/sysfs.h>
#include <dma_intel/dsa_intel.h>

VLIB_REGISTER_LOG_CLASS (intel_dsa_log, static) = {
  .class_name = "intel_dsa",
};

intel_dsa_main_t intel_dsa_main;

void
intel_dsa_assign_channels (vlib_main_t *vm)
{
  intel_dsa_main_t *idm = &intel_dsa_main;
  intel_dsa_channel_t *ch, **chv = 0;
  u16 n_threads;
  int n;

  vec_foreach_index (n, idm->channels)
    vec_append (chv, idm->channels[n]);

  vec_validate (idm->dsa_threads, vlib_get_n_threads () - 1);

  if (vec_len (chv) == 0)
    {
      dsa_log_debug ("No DSA channels found");
      goto done;
    }

  if (vec_len (chv) >= vlib_get_n_threads ())
    n_threads = 1;
  else
    n_threads = vlib_get_n_threads () % vec_len (chv) ?
			vlib_get_n_threads () / vec_len (chv) + 1 :
			vlib_get_n_threads () / vec_len (chv);

  for (int i = 0; i < vlib_get_n_threads (); i++)
    {
      vlib_main_t *tvm = vlib_get_main_by_index (i);
      ch = *vec_elt_at_index (chv, i / n_threads);
      idm->dsa_threads[i].ch = ch;
      ch->n_threads = n_threads;
      dsa_log_debug ("Assigning channel %u/%u to thread %u (numa %u)", ch->did,
		     ch->qid, i, tvm->numa_node);
    }

done:
  /* free */
  vec_free (chv);
}

static clib_error_t *
intel_dsa_map_region (intel_dsa_channel_t *ch)
{
  /* map one page */
  uword size = 0x1000;
  uword offset = 0;
  char path[256] = { 0 };

  snprintf (path, sizeof (path), "%s/wq%d.%d", DSA_DEV_PATH, ch->did, ch->qid);
  ch->fd = open (path, O_RDWR);
  if (ch->fd < 0)
    return clib_error_return (0, "failed to open dsa device %s", path);

  ch->portal =
    clib_mem_vm_map_shared (0, size, ch->fd, offset, "%s", (char *) path);
  if (ch->portal == CLIB_MEM_VM_MAP_FAILED)
    {
      /* direct access is unavailable, submit work using write syscall */
      dsa_log_debug ("mmap portal %s failed", path);
      ch->portal = NULL;
    }

  return NULL;
}

static clib_error_t *
intel_dsa_get_info (intel_dsa_channel_t *ch, clib_error_t **error)
{
  clib_error_t *err;
  u8 *tmpstr;
  u8 *dev_dir_name = 0, *wq_dir_name = 0;

  u8 *f = 0;
  dev_dir_name = format (0, "%s/dsa%d", SYS_DSA_PATH, ch->did);

  vec_reset_length (f);
  f = format (f, "%v/numa_node%c", dev_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  ch->numa = atoi ((char *) tmpstr);

  /* Version 1 devices cannot use batch descriptors for work submitted
   * using the write syscall.
   */
  vec_reset_length (f);
  f = format (f, "%v/version%c", dev_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  if (tmpstr)
    if (!clib_strcmp ((char *) tmpstr, "0x100"))
      ch->no_batch = ch->portal ? 0 : 1;

  wq_dir_name = format (0, "%s/%U", SYS_DSA_PATH, format_intel_dsa_addr, ch);

  vec_reset_length (f);
  f = format (f, "%v/max_transfer_size%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  ch->max_transfer_size = atoi ((char *) tmpstr);

  vec_reset_length (f);
  f = format (f, "%v/max_batch_size%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  ch->max_transfers = atoi ((char *) tmpstr);

  vec_reset_length (f);
  f = format (f, "%v/size%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  ch->size = atoi ((char *) tmpstr);

  vec_reset_length (f);
  f = format (f, "%v/type%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  if (tmpstr)
    {
      if (!clib_strcmp ((char *) tmpstr, "enabled"))
	ch->type = INTEL_DSA_DEVICE_TYPE_UNKNOWN;
      else if (!clib_strcmp ((char *) tmpstr, "user"))
	ch->type = INTEL_DSA_DEVICE_TYPE_USER;
      else if (!clib_strcmp ((char *) tmpstr, "mdev"))
	ch->type = INTEL_DSA_DEVICE_TYPE_KERNEL;
      else
	ch->type = INTEL_DSA_DEVICE_TYPE_UNKNOWN;
      vec_free (tmpstr);
    }

  vec_reset_length (f);
  f = format (f, "%v/state%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  if (tmpstr)
    {
      if (!clib_strcmp ((char *) tmpstr, "enabled"))
	ch->state = 1;
      else
	ch->state = 0;
      vec_free (tmpstr);
    }

  vec_reset_length (f);
  f = format (f, "%v/ats_disable%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  ch->ats_disable = atoi ((char *) tmpstr);

  vec_reset_length (f);
  f = format (f, "%v/block_on_fault%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  ch->block_on_fault = atoi ((char *) tmpstr);

  vec_reset_length (f);
  f = format (f, "%v/mode%c", wq_dir_name, 0);
  err = clib_sysfs_read ((char *) f, "%s", &tmpstr);
  if (err)
    goto error;
  if (tmpstr)
    {
      if (!clib_strcmp ((char *) tmpstr, "dedicated"))
	ch->mode = 1;
      else
	ch->mode = 0;
      vec_free (tmpstr);
    }

  vec_free (f);
  vec_free (dev_dir_name);
  vec_free (wq_dir_name);
  return NULL;

error:
  vec_free (f);
  vec_free (dev_dir_name);
  vec_free (wq_dir_name);

  return err;
}

clib_error_t *
intel_dsa_add_channel (vlib_main_t *vm, intel_dsa_channel_t *ch)
{
  intel_dsa_main_t *dm = &intel_dsa_main;
  clib_error_t *err = 0;

  if (intel_dsa_map_region (ch))
    return clib_error_return (0, "dsa open device failed");

  if (intel_dsa_get_info (ch, &err))
    return clib_error_return (err, "dsa info not scanned");

  vec_validate (dm->channels, ch->numa);
  vec_add1 (dm->channels[ch->numa], ch);

  return err;
}

static clib_error_t *
dsa_config (vlib_main_t *vm, unformat_input_t *input)
{
  clib_error_t *error = 0;
  intel_dsa_channel_t *ch;
  u32 did, qid;

  if (intel_dsa_main.lock == 0)
    clib_spinlock_init (&(intel_dsa_main.lock));

  if ((error = vlib_dma_register_backend (vm, &intel_dsa_backend)))
    goto done;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dev wq%d.%d", &did, &qid))
	{
	  ch = clib_mem_alloc_aligned (sizeof (*ch), CLIB_CACHE_LINE_BYTES);
	  clib_memset (ch, 0, sizeof (*ch));
	  ch->did = did;
	  ch->qid = qid;
	  if (intel_dsa_add_channel (vm, ch))
	    clib_mem_free (ch);
	}
      else if (unformat_skip_white_space (input))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

done:
  return error;
}

VLIB_CONFIG_FUNCTION (dsa_config, "dsa");

clib_error_t *
intel_dsa_num_workers_change (vlib_main_t *vm)
{
  intel_dsa_assign_channels (vm);
  return 0;
}

VLIB_NUM_WORKERS_CHANGE_FN (intel_dsa_num_workers_change);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Intel DSA Backend",
};
