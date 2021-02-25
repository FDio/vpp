/*
 * Copyright (c) 2017 Intel and/or its affiliates.
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

#include <vnet/vnet.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/ipsec/ipsec.h>

static u8 *
format_crypto_resource (u8 * s, va_list * args)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  u32 indent = va_arg (*args, u32);
  u32 res_idx = va_arg (*args, u32);

  crypto_resource_t *res = vec_elt_at_index (dcm->resource, res_idx);


  s = format (s, "%U thr_id %3d qp %2u dec_inflight %u, enc_inflights %u\n",
	      format_white_space, indent, (i16) res->thread_idx,
	      res->qp_id, res->inflights[0], res->inflights[1]);

  return s;
}

static u8 *
format_crypto (u8 * s, va_list * args)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_dev_t *dev = va_arg (*args, crypto_dev_t *);
  crypto_drv_t *drv = vec_elt_at_index (dcm->drv, dev->drv_id);
  u64 feat, mask;
  u32 i;
  char *pre = "  ";

  s = format (s, "%-25s%-20s%-10s\n", dev->name, drv->name,
	      rte_cryptodevs[dev->id].data->dev_started ? "up" : "down");
  s = format (s, "  numa_node %u, max_queues %u\n", dev->numa, dev->max_qp);

  if (dev->features)
    {
      for (mask = 1; mask != 0; mask <<= 1)
	{
	  feat = dev->features & mask;
	  if (feat)
	    {
	      s =
		format (s, "%s%s", pre,
			rte_cryptodev_get_feature_name (feat));
	      pre = ", ";
	    }
	}
      s = format (s, "\n");
    }

  s = format (s, "  Cipher:");
  pre = " ";
  for (i = 0; i < IPSEC_CRYPTO_N_ALG; i++)
    if (dev->cipher_support[i])
      {
	s = format (s, "%s%s", pre, dcm->cipher_algs[i].name);
	pre = ", ";
      }
  s = format (s, "\n");

  s = format (s, "  Auth:");
  pre = " ";
  for (i = 0; i < IPSEC_INTEG_N_ALG; i++)
    if (dev->auth_support[i])
      {
	s = format (s, "%s%s", pre, dcm->auth_algs[i].name);
	pre = ", ";
      }
  s = format (s, "\n");

  struct rte_cryptodev_stats stats;
  rte_cryptodev_stats_get (dev->id, &stats);

  s =
    format (s,
	    "  enqueue %-10lu dequeue %-10lu enqueue_err %-10lu dequeue_err %-10lu \n",
	    stats.enqueued_count, stats.dequeued_count,
	    stats.enqueue_err_count, stats.dequeue_err_count);

  u16 *res_idx;
  s = format (s, "  free_resources %u :", vec_len (dev->free_resources));

  u32 indent = format_get_indent (s);
  s = format (s, "\n");

  /* *INDENT-OFF* */
  vec_foreach (res_idx, dev->free_resources)
    s = format (s, "%U", format_crypto_resource, indent, res_idx[0]);
  /* *INDENT-ON* */

  s = format (s, "  used_resources %u :", vec_len (dev->used_resources));
  indent = format_get_indent (s);

  s = format (s, "\n");

  /* *INDENT-OFF* */
  vec_foreach (res_idx, dev->used_resources)
    s = format (s, "%U", format_crypto_resource, indent, res_idx[0]);
  /* *INDENT-ON* */

  s = format (s, "\n");

  return s;
}


static clib_error_t *
clear_crypto_stats_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_dev_t *dev;

  /* *INDENT-OFF* */
  vec_foreach (dev, dcm->dev)
    rte_cryptodev_stats_reset (dev->id);
  /* *INDENT-ON* */

  return NULL;
}

/*?
 * This command is used to clear the DPDK Crypto device statistics.
 *
 * @cliexpar
 * Example of how to clear the DPDK Crypto device statistics:
 * @cliexsart{clear dpdk crypto devices statistics}
 * vpp# clear dpdk crypto devices statistics
 * @cliexend
 * Example of clearing the DPDK Crypto device statistic data:
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_dpdk_crypto_stats, static) = {
    .path = "clear dpdk crypto devices statistics",
    .short_help = "clear dpdk crypto devices statistics",
    .function = clear_crypto_stats_fn,
};
/* *INDENT-ON* */


static clib_error_t *
show_dpdk_crypto_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_dev_t *dev;

  /* *INDENT-OFF* */
  vec_foreach (dev, dcm->dev)
    vlib_cli_output (vm, "%U", format_crypto, dev);
  /* *INDENT-ON* */

  return NULL;
}

/*?
 * This command is used to display the DPDK Crypto device information.
 *
 * @cliexpar
 * Example of how to display the DPDK Crypto device information:
 * @cliexsart{show dpdk crypto devices}
 * vpp# show dpdk crypto devices
 *  aesni_mb0		  crypto_aesni_mb     up
 *  numa_node 0, max_queues 4
 *  SYMMETRIC_CRYPTO, SYM_OPERATION_CHAINING, CPU_AVX2, CPU_AESNI
 *  Cipher: aes-cbc-128, aes-cbc-192, aes-cbc-256, aes-ctr-128, aes-ctr-192, aes-ctr-256, aes-gcm-128, aes-gcm-192, aes-gcm-256
 *  Auth: md5-96, sha1-96, sha-256-128, sha-384-192, sha-512-256
 *  enqueue 2	      dequeue 2 	 enqueue_err 0		dequeue_err 0
 *  free_resources 3 :
 *		      thr_id  -1 qp  3 inflight 0
 *		      thr_id  -1 qp  2 inflight 0
 *		      thr_id  -1 qp  1 inflight 0
 *  used_resources 1 :
 *		      thr_id   1 qp  0 inflight 0
 * @cliexend
 * Example of displaying the DPDK Crypto device data when enabled:
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_dpdk_crypto, static) = {
    .path = "show dpdk crypto devices",
    .short_help = "show dpdk crypto devices",
    .function = show_dpdk_crypto_fn,
};

/* *INDENT-ON* */
static u8 *
format_crypto_worker (u8 * s, va_list * args)
{
  u32 thread_idx = va_arg (*args, u32);
  u8 verbose = (u8) va_arg (*args, u32);
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm;
  crypto_resource_t *res;
  u16 *res_idx;
  char *pre, *ind;
  u32 i;

  cwm = vec_elt_at_index (dcm->workers_main, thread_idx);

  s = format (s, "Thread %u (%v):\n", thread_idx,
	      vlib_worker_threads[thread_idx].name);

  /* *INDENT-OFF* */
  vec_foreach (res_idx, cwm->resource_idx)
    {
      ind = "  ";
      res = vec_elt_at_index (dcm->resource, res_idx[0]);
      s = format (s, "%s%-20s dev-id %2u queue-pair %2u\n",
		  ind, vec_elt_at_index (dcm->dev, res->dev_id)->name,
		  res->dev_id, res->qp_id);

      ind = "    ";
      if (verbose)
	{
	  s = format (s, "%sCipher:", ind);
	  pre = " ";
	  for (i = 0; i < IPSEC_CRYPTO_N_ALG; i++)
	    if (cwm->cipher_resource_idx[i] == res_idx[0])
	      {
		s = format (s, "%s%s", pre, dcm->cipher_algs[i].name);
		pre = ", ";
	      }
	  s = format (s, "\n");

	  s = format (s, "%sAuth:", ind);
	  pre = " ";
	  for (i = 0; i < IPSEC_INTEG_N_ALG; i++)
	    if (cwm->auth_resource_idx[i] == res_idx[0])
	      {
		s = format (s, "%s%s", pre, dcm->auth_algs[i].name);
		pre = ", ";
	      }
	  s = format (s, "\n");
	}
    }
  /* *INDENT-ON* */

  return s;
}

static clib_error_t *
common_crypto_placement_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd, u8 verbose)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  clib_error_t *error = NULL;
  u32 i;
  u8 skip_master;

  if (!dcm->enabled)
    {
      vlib_cli_output (vm, "\nDPDK Cryptodev support is disabled\n");
      return error;
    }

  skip_master = vlib_num_workers () > 0;

  /* *INDENT-OFF* */
  vec_foreach_index (i, dcm->workers_main)
    {
      if (i < skip_master)
	continue;

      vlib_cli_output (vm, "%U\n", format_crypto_worker, i, verbose);
    }
  /* *INDENT-ON* */

  return error;
}

static clib_error_t *
show_dpdk_crypto_placement_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  return common_crypto_placement_fn (vm, input, cmd, 0);
}

static clib_error_t *
show_dpdk_crypto_placement_v_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  return common_crypto_placement_fn (vm, input, cmd, 1);
}

/*?
 * This command is used to display the DPDK Crypto device placement.
 *
 * @cliexpar
 * Example of displaying the DPDK Crypto device placement:
 * @cliexstart{show dpdk crypto placement}
 * vpp# show dpdk crypto placement
 * Thread 1 (vpp_wk_0):
 *   cryptodev_aesni_mb_p dev-id  0 queue-pair  0
 *   cryptodev_aesni_gcm_ dev-id  1 queue-pair  0
 *
 * Thread 2 (vpp_wk_1):
 *   cryptodev_aesni_mb_p dev-id  0 queue-pair  1
 *   cryptodev_aesni_gcm_ dev-id  1 queue-pair  1
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_dpdk_crypto_placement, static) = {
    .path = "show dpdk crypto placement",
    .short_help = "show dpdk crypto placement",
    .function = show_dpdk_crypto_placement_fn,
};
/* *INDENT-ON* */

/*?
 * This command is used to display the DPDK Crypto device placement
 * with verbose output.
 *
 * @cliexpar
 * Example of displaying the DPDK Crypto device placement verbose:
 * @cliexstart{show dpdk crypto placement verbose}
 * vpp# show dpdk crypto placement verbose
 * Thread 1 (vpp_wk_0):
 *   cryptodev_aesni_mb_p dev-id  0 queue-pair  0
 *     Cipher: aes-cbc-128, aes-cbc-192, aes-cbc-256, aes-ctr-128, aes-ctr-192, aes-ctr-256
 *     Auth: md5-96, sha1-96, sha-256-128, sha-384-192, sha-512-256
 *     cryptodev_aesni_gcm_ dev-id  1 queue-pair  0
 *     Cipher: aes-gcm-128, aes-gcm-192, aes-gcm-256
 *     Auth:
 *
 * Thread 2 (vpp_wk_1):
 *   cryptodev_aesni_mb_p dev-id  0 queue-pair  1
 *     Cipher: aes-cbc-128, aes-cbc-192, aes-cbc-256, aes-ctr-128, aes-ctr-192, aes-ctr-256
 *     Auth: md5-96, sha1-96, sha-256-128, sha-384-192, sha-512-256
 *     cryptodev_aesni_gcm_ dev-id  1 queue-pair  1
 *     Cipher: aes-gcm-128, aes-gcm-192, aes-gcm-256
 *     Auth:
 *
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_dpdk_crypto_placement_v, static) = {
    .path = "show dpdk crypto placement verbose",
    .short_help = "show dpdk crypto placement verbose",
    .function = show_dpdk_crypto_placement_v_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_crypto_placement_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_worker_main_t *cwm;
  crypto_dev_t *dev;
  u32 thread_idx, i;
  u16 res_idx, *idx;
  u8 dev_idx, auto_en = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "invalid syntax");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u %u", &dev_idx, &thread_idx))
	;
      else if (unformat (line_input, "auto"))
	auto_en = 1;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);

  if (auto_en)
    {
      crypto_auto_placement ();
      return 0;
    }

  /* TODO support device name */

  if (!(dev_idx < vec_len (dcm->dev)))
    return clib_error_return (0, "please specify valid device index");

  if (thread_idx != (u32) ~ 0 && !(thread_idx < vec_len (dcm->workers_main)))
    return clib_error_return (0, "invalid thread index");

  dev = vec_elt_at_index (dcm->dev, dev_idx);
  if (!(vec_len (dev->free_resources)))
    return clib_error_return (0, "all device resources are being used");

  /* Check thread is not already using the device */
  /* *INDENT-OFF* */
  vec_foreach (idx, dev->used_resources)
    if (dcm->resource[idx[0]].thread_idx == thread_idx)
      return clib_error_return (0, "thread %u already using device %u",
				thread_idx, dev_idx);
  /* *INDENT-ON* */

  res_idx = vec_pop (dev->free_resources);
  vec_add1 (dev->used_resources, res_idx);

  cwm = vec_elt_at_index (dcm->workers_main, thread_idx);

  ASSERT (dcm->resource[res_idx].thread_idx == (u16) ~ 0);
  dcm->resource[res_idx].thread_idx = thread_idx;

  /* Add device to vector of polling resources */
  vec_add1 (cwm->resource_idx, res_idx);

  /* Set device as default for all supported algos */
  for (i = 0; i < IPSEC_CRYPTO_N_ALG; i++)
    if (dev->cipher_support[i])
      {
	if (cwm->cipher_resource_idx[i] == (u16) ~ 0)
	  dcm->cipher_algs[i].disabled--;
	cwm->cipher_resource_idx[i] = res_idx;
      }

  for (i = 0; i < IPSEC_INTEG_N_ALG; i++)
    if (dev->auth_support[i])
      {
	if (cwm->auth_resource_idx[i] == (u16) ~ 0)
	  dcm->auth_algs[i].disabled--;
	cwm->auth_resource_idx[i] = res_idx;
      }

  /* Check if any unused resource */

  u8 used = 0;
  /* *INDENT-OFF* */
  vec_foreach (idx, cwm->resource_idx)
    {
      if (idx[0] == res_idx)
	continue;

      for (i = 0; i < IPSEC_CRYPTO_N_ALG; i++)
	used |= cwm->cipher_resource_idx[i] == idx[0];

      for (i = 0; i < IPSEC_INTEG_N_ALG; i++)
	used |= cwm->auth_resource_idx[i] == idx[0];

      vec_elt_at_index (dcm->resource, idx[0])->remove = !used;
    }
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_dpdk_crypto_placement, static) = {
    .path = "set dpdk crypto placement",
    .short_help = "set dpdk crypto placement (<device> <thread> | auto)",
    .function = set_dpdk_crypto_placement_fn,
};
/* *INDENT-ON* */

/*
 * The thread will not enqueue more operations to the device but will poll
 * from it until there are no more inflight operations.
*/
static void
dpdk_crypto_clear_resource (u16 res_idx)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_resource_t *res = vec_elt_at_index (dcm->resource, res_idx);
  crypto_worker_main_t *cwm = &dcm->workers_main[res->thread_idx];
  u32 i;

  for (i = 0; i < IPSEC_CRYPTO_N_ALG; i++)
    if (cwm->cipher_resource_idx[i] == res_idx)
      {
	cwm->cipher_resource_idx[i] = (u16) ~ 0;
	dcm->cipher_algs[i].disabled++;
      }

  for (i = 0; i < IPSEC_INTEG_N_ALG; i++)
    if (cwm->auth_resource_idx[i] == res_idx)
      {
	cwm->auth_resource_idx[i] = (u16) ~ 0;
	dcm->auth_algs[i].disabled++;
      }

  /* Fully remove device on crypto_node once there are no inflights */
  res->remove = 1;
}

static clib_error_t *
clear_dpdk_crypto_placement_fn (vlib_main_t * vm,
				unformat_input_t *
				input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_dev_t *dev;
  u32 thread_idx = (u32) ~ 0;
  u16 *res_idx;
  u8 dev_idx = (u8) ~ 0;
  u8 free_all = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "invalid syntax");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u %u", &dev_idx, &thread_idx))
	;
      else if (unformat (line_input, "%u", &dev_idx))
	free_all = 1;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);

  if (!(dev_idx < vec_len (dcm->dev)))
    return clib_error_return (0, "invalid device index");

  dev = vec_elt_at_index (dcm->dev, dev_idx);

  /* Clear all resources placements */
  if (free_all)
    {
    /* *INDENT-OFF* */
    vec_foreach (res_idx, dev->used_resources)
      dpdk_crypto_clear_resource (res_idx[0]);
    /* *INDENT-ON* */

      return 0;
    }

  if (!(thread_idx < vec_len (dcm->workers_main)))
    return clib_error_return (0, "invalid thread index");

  /* Clear placement of device for given thread index */
  /* *INDENT-OFF* */
  vec_foreach (res_idx, dev->used_resources)
    if (dcm->resource[res_idx[0]].thread_idx == thread_idx)
      break;
  /* *INDENT-ON* */

  if (!(res_idx < vec_end (dev->used_resources)))
    return clib_error_return (0, "thread %u is not using device %u",
			      thread_idx, dev_idx);

  dpdk_crypto_clear_resource (res_idx[0]);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_dpdk_crypto_placement, static) = {
    .path = "clear dpdk crypto placement",
    .short_help = "clear dpdk crypto placement <device> [<thread>]",
    .function = clear_dpdk_crypto_placement_fn,
};
/* *INDENT-ON* */

u8 *
format_dpdk_mempool (u8 * s, va_list * args)
{
  struct rte_mempool *mp = va_arg (*args, struct rte_mempool *);
  u32 indent = format_get_indent (s);
  u32 count = rte_mempool_avail_count (mp);

  s = format (s, "%s\n%Uavailable %7d, allocated %7d total %7d\n",
	      mp->name, format_white_space, indent + 2,
	      count, mp->size - count, mp->size);
  s = format (s, "%Uphys_addr %p, flags %08x, nb_mem_chunks %u\n",
	      format_white_space, indent + 2,
	      mp->mz->iova, mp->flags, mp->nb_mem_chunks);
  s = format (s, "%Uelt_size %4u, header_size %3u, trailer_size %u\n",
	      format_white_space, indent + 2,
	      mp->elt_size, mp->header_size, mp->trailer_size);
  s = format (s, "%Uprivate_data_size %3u, total_elt_size %u\n",
	      format_white_space, indent + 2,
	      mp->private_data_size,
	      mp->elt_size + mp->header_size + mp->trailer_size);
  return s;
}

static clib_error_t *
show_dpdk_crypto_pools_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;

  /* *INDENT-OFF* */
  vec_foreach (data, dcm->data)
  {
    if (data->crypto_op)
      vlib_cli_output (vm, "%U\n", format_dpdk_mempool, data->crypto_op);
    if (data->session_h)
      vlib_cli_output (vm, "%U\n", format_dpdk_mempool, data->session_h);

    struct rte_mempool **mp;
    vec_foreach (mp, data->session_drv)
      if (mp[0])
        vlib_cli_output (vm, "%U\n", format_dpdk_mempool, mp[0]);
  }
  /* *INDENT-ON* */

  return NULL;
}

/*?
 * This command is used to display the DPDK Crypto pools information.
 *
 * @cliexpar
 * Example of how to display the DPDK Crypto pools information:
 * @cliexstart{show crypto device mapping}
 * vpp# show dpdk crypto pools
 * crypto_pool_numa1
 * available   15872, allocated     512 total   16384
 * phys_addr 0xf3d2086c0, flags 00000010, nb_mem_chunks 1
 * elt_size  160, header_size  64, trailer_size 96
 * private_data_size  64, total_elt_size 320
 *
 * session_h_pool_numa1
 * available   19998, allocated       2 total   20000
 * phys_addr 0xf3c9c4380, flags 00000010, nb_mem_chunks 1
 * elt_size   40, header_size  64, trailer_size 88
 * private_data_size   0, total_elt_size 192
 *
 * session_drv0_pool_numa1
 * available   19998, allocated       2 total   20000
 * phys_addr 0xf3ad42d80, flags 00000010, nb_mem_chunks 1
 * elt_size  512, header_size  64, trailer_size 0
 * private_data_size   0, total_elt_size 576
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_dpdk_crypto_pools, static) = {
    .path = "show dpdk crypto pools",
    .short_help = "show dpdk crypto pools",
    .function = show_dpdk_crypto_pools_fn,
};
/* *INDENT-ON* */

/* TODO Allow user define number of sessions supported */
/* TODO Allow user define descriptor queue size */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
