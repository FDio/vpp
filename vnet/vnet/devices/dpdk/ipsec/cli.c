/*
 * Copyright (c) 2016 Intel and/or its affiliates.
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
#include <vnet/devices/dpdk/ipsec/ipsec.h>

static void
dpdk_ipsec_show_mapping (vlib_main_t * vm, u16 detail_display)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 i, skip_master;

  if (detail_display)
    vlib_cli_output (vm, "worker\t%10s\t%15s\tdir\tdev\tqp\n",
		     "cipher", "auth");
  else
    vlib_cli_output (vm, "worker\tcrypto device id(type)\n");

  skip_master = vlib_num_workers () > 0;

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      uword key, data;
      u32 cpu_index = vlib_mains[i]->cpu_index;
      crypto_worker_main_t *cwm = &dcm->workers_main[cpu_index];
      u8 *s = 0;

      if (skip_master)
	{
	  skip_master = 0;
	  continue;
	}

      if (!detail_display)
	{
	  i32 last_cdev = -1;
	  crypto_qp_data_t *qpd;

	  s = format (s, "%u\t", cpu_index);

	  /* *INDENT-OFF* */
	  vec_foreach (qpd, cwm->qp_data)
	    {
	      u32 dev_id = qpd->dev_id;

	      if ((u16) last_cdev != dev_id)
		{
		  struct rte_cryptodev_info cdev_info;

		  rte_cryptodev_info_get (dev_id, &cdev_info);

		  s = format(s, "%u(%s)\t", dev_id, cdev_info.feature_flags &
			     RTE_CRYPTODEV_FF_HW_ACCELERATED ? "HW" : "SW");
		}
	      last_cdev = dev_id;
	    }
	  /* *INDENT-ON* */
	  vlib_cli_output (vm, "%s", s);
	}
      else
	{
	  char cipher_str[15], auth_str[15];
	  struct rte_cryptodev_capabilities cap;
	  crypto_worker_qp_key_t *p_key = (crypto_worker_qp_key_t *) & key;
	  /* *INDENT-OFF* */
	  hash_foreach (key, data, cwm->algo_qp_map,
	  ({
	    cap.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	    cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	    cap.sym.cipher.algo = p_key->cipher_algo;
	    check_algo_is_supported (&cap, cipher_str);
	    cap.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	    cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH;
	    cap.sym.auth.algo = p_key->auth_algo;
	    check_algo_is_supported (&cap, auth_str);
	    vlib_cli_output (vm, "%u\t%10s\t%15s\t%3s\t%u\t%u\n",
			     vlib_mains[i]->cpu_index, cipher_str, auth_str,
			     p_key->is_outbound ? "out" : "in",
			     cwm->qp_data[data].dev_id,
			     cwm->qp_data[data].qp_id);
	  }));
	  /* *INDENT-ON* */
	}
    }
}

static clib_error_t *
lcore_cryptodev_map_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 detail = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "verbose"))
	detail = 1;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  dpdk_ipsec_show_mapping (vm, detail);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lcore_cryptodev_map, static) = {
    .path = "show crypto device mapping",
    .short_help =
    "show cryptodev device mapping <verbose>",
    .function = lcore_cryptodev_map_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
