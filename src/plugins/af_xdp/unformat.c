/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
      else if (unformat (line_input, "netns %s", &args->netns))
	;
      else if (unformat (line_input, "no-zero-copy"))
	args->mode = AF_XDP_MODE_COPY;
      else if (unformat (line_input, "zero-copy"))
	args->mode = AF_XDP_MODE_ZERO_COPY;
      else if (unformat (line_input, "no-syscall-lock"))
	args->flags |= AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK;
      else if (unformat (line_input, "multi-buffer"))
	args->flags |= AF_XDP_CREATE_FLAGS_MULTI_BUFFER;
      else if (unformat (line_input, "no-multi-buffer"))
	args->flags &= ~AF_XDP_CREATE_FLAGS_MULTI_BUFFER;
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
