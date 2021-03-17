/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <rdma/rdma.h>

uword
unformat_rdma_create_if_args (unformat_input_t * input, va_list * vargs)
{
  rdma_create_if_args_t *args = va_arg (*vargs, rdma_create_if_args_t *);
  unformat_input_t _line_input, *line_input = &_line_input;
  uword ret = 1;
  u32 tmp;
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  clib_memset (args, 0, sizeof (*args));

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "host-if %s", &args->ifname))
	;
      else if (unformat (line_input, "name %s", &args->name))
	;
      else if (unformat (line_input, "rx-queue-size %u", &args->rxq_size))
	;
      else if (unformat (line_input, "tx-queue-size %u", &args->txq_size))
	;
      else if (unformat (line_input, "num-rx-queues %u", &args->rxq_num))
	;
      else if (unformat (line_input, "mode auto"))
	args->mode = RDMA_MODE_AUTO;
      else if (unformat (line_input, "mode ibv"))
	args->mode = RDMA_MODE_IBV;
      else if (unformat (line_input, "mode dv"))
	args->mode = RDMA_MODE_DV;
      else if (unformat (line_input, "no-striding"))
	args->disable_striding_rq = 1;
      else if (unformat (line_input, "no-multi-seg"))
	args->no_multi_seg = 1;
      else if (unformat (line_input, "max-pktlen %u", &tmp))
	args->max_pktlen = tmp;
      else if (unformat (line_input, "rss ipv4"))
	args->rss4 = RDMA_RSS4_IP;
      else if (unformat (line_input, "rss ipv4-udp"))
	args->rss4 = RDMA_RSS4_IP_UDP;
      else if (unformat (line_input, "rss ipv4-tcp"))
	args->rss4 = RDMA_RSS4_IP_TCP;
      else if (unformat (line_input, "rss ipv6"))
	args->rss6 = RDMA_RSS6_IP;
      else if (unformat (line_input, "rss ipv6-udp"))
	args->rss6 = RDMA_RSS6_IP_UDP;
      else if (unformat (line_input, "rss ipv6-tcp"))
	args->rss6 = RDMA_RSS6_IP_TCP;
      else
	{
	  /* return failure on unknown input */
	  ret = 0;
	  break;
	}
    }

  unformat_free (line_input);
  return ret;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
