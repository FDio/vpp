/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <af_xdp/af_xdp.h>

uword
unformat_af_xdp_create_if_args (unformat_input_t * input, va_list * vargs)
{
  af_xdp_create_if_args_t *args = va_arg (*vargs, af_xdp_create_if_args_t *);
  unformat_input_t _line_input, *line_input = &_line_input;
  uword ret = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  clib_memset (args, 0, sizeof (*args));

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "host-if %s", &args->linux_ifname))
	;
      else if (unformat (line_input, "name %s", &args->name))
	;
      else if (unformat (line_input, "rx-queue-size %u", &args->rxq_size))
	;
      else if (unformat (line_input, "tx-queue-size %u", &args->txq_size))
	;
      else if (unformat (line_input, "num-rx-queues all"))
	args->rxq_num = AF_XDP_NUM_RX_QUEUES_ALL;
      else if (unformat (line_input, "num-rx-queues %u", &args->rxq_num))
	;
      else if (unformat (line_input, "prog %s", &args->prog))
	;
      else if (unformat (line_input, "no-zero-copy"))
	args->mode = AF_XDP_MODE_COPY;
      else if (unformat (line_input, "zero-copy"))
	args->mode = AF_XDP_MODE_ZERO_COPY;
      else if (unformat (line_input, "no-syscall-lock"))
	args->flags |= AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK;
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
