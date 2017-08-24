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
#include <dpdk/device/dpdk.h>
#include <dpdk/ipsec/ipsec.h>

static void
dpdk_ipsec_show_mapping (vlib_main_t * vm, u16 detail_display)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 i, skip_master;

  if (!dcm->enabled)
    {
      vlib_cli_output (vm, "DPDK Cryptodev support is disabled\n");
      return;
    }

  if (detail_display)
    vlib_cli_output (vm, "worker\t%10s\t%15s\tdir\tdev\tqp\n",
		     "cipher", "auth");
  else
    vlib_cli_output (vm, "worker\tcrypto device id(type)\n");

  skip_master = vlib_num_workers () > 0;

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      uword key, data;
      u32 thread_index = vlib_mains[i]->thread_index;
      crypto_worker_main_t *cwm = &dcm->workers_main[thread_index];
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

	  s = format (s, "%u\t", thread_index);

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
#if DPDK_NO_AEAD
	    cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	    cap.sym.cipher.algo = p_key->cipher_algo;
#else
	    if (p_key->is_aead)
	      {
		cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_AEAD;
		cap.sym.aead.algo = p_key->cipher_algo;
	      }
	    else
	      {
		cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		cap.sym.cipher.algo = p_key->cipher_algo;
	      }
#endif
	    check_algo_is_supported (&cap, cipher_str);

	    cap.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
	    cap.sym.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH;
	    cap.sym.auth.algo = p_key->auth_algo;
	    check_algo_is_supported (&cap, auth_str);

	    vlib_cli_output (vm, "%u\t%10s\t%15s\t%3s\t%u\t%u\n",
			     vlib_mains[i]->thread_index, cipher_str, auth_str,
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
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "verbose"))
	detail = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  dpdk_ipsec_show_mapping (vm, detail);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to display the DPDK Crypto device data. See
 * @ref dpdk_crypto_ipsec_doc for more details on initializing the
 * DPDK Crypto device.
 *
 * @cliexpar
 * Example of displaying the DPDK Crypto device data when disabled:
 * @cliexstart{show crypto device mapping}
 * DPDK Cryptodev support is disabled
 * @cliexend
 * Example of displaying the DPDK Crypto device data when enabled:
 * @cliexstart{show crypto device mapping}
 * worker  crypto device id(type)
 * 1       1(SW)
 * 2       1(SW)
 * @cliexend
 * Example of displaying the DPDK Crypto device data when enabled with verbose:
 * @cliexstart{show crypto device mapping verbose}
 * worker      cipher                 auth dir     dev     qp
 * 1          AES_CTR         AES-XCBC-MAC  in     1       0
 * 1          AES_CTR          HMAC-SHA384  in     1       0
 * 1          AES_CTR          HMAC-SHA384 out     1       1
 * 1          AES_CBC          HMAC-SHA512  in     1       0
 * 1          AES_CBC          HMAC-SHA256  in     1       0
 * 1          AES_CBC         AES-XCBC-MAC out     1       1
 * 1          AES_CTR         AES-XCBC-MAC out     1       1
 * 1          AES_CBC          HMAC-SHA256 out     1       1
 * 1          AES_CTR          HMAC-SHA512 out     1       1
 * 1          AES_CTR          HMAC-SHA256  in     1       0
 * 1          AES_CTR            HMAC-SHA1  in     1       0
 * 1          AES_CBC          HMAC-SHA512 out     1       1
 * 1          AES_CBC          HMAC-SHA384 out     1       1
 * 1          AES_CTR            HMAC-SHA1 out     1       1
 * 1          AES_CTR          HMAC-SHA256 out     1       1
 * 1          AES_CBC            HMAC-SHA1  in     1       0
 * 1          AES_CBC         AES-XCBC-MAC  in     1       0
 * 1          AES_CTR          HMAC-SHA512  in     1       0
 * 1          AES_CBC            HMAC-SHA1 out     1       1
 * 1          AES_CBC          HMAC-SHA384  in     1       0
 * 2          AES_CTR         AES-XCBC-MAC  in     1       2
 * 2          AES_CTR          HMAC-SHA384  in     1       2
 * 2          AES_CTR          HMAC-SHA384 out     1       3
 * 2          AES_CBC          HMAC-SHA512  in     1       2
 * 2          AES_CBC          HMAC-SHA256  in     1       2
 * 2          AES_CBC         AES-XCBC-MAC out     1       3
 * 2          AES_CTR         AES-XCBC-MAC out     1       3
 * 2          AES_CBC          HMAC-SHA256 out     1       3
 * 2          AES_CTR          HMAC-SHA512 out     1       3
 * 2          AES_CTR          HMAC-SHA256  in     1       2
 * 2          AES_CTR            HMAC-SHA1  in     1       2
 * 2          AES_CBC          HMAC-SHA512 out     1       3
 * 2          AES_CBC          HMAC-SHA384 out     1       3
 * 2          AES_CTR            HMAC-SHA1 out     1       3
 * 2          AES_CTR          HMAC-SHA256 out     1       3
 * 2          AES_CBC            HMAC-SHA1  in     1       2
 * 2          AES_CBC         AES-XCBC-MAC  in     1       2
 * 2          AES_CTR          HMAC-SHA512  in     1       2
 * 2          AES_CBC            HMAC-SHA1 out     1       3
 * 2          AES_CBC          HMAC-SHA384  in     1       2
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lcore_cryptodev_map, static) = {
    .path = "show crypto device mapping",
    .short_help =
    "show cryptodev device mapping [verbose]",
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
