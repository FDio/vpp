/*
 * Copyright (c) 2019 Intel and/or its affiliates.
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

#include <dpdk/cryptodev/cryptodev.h>

static clib_error_t *
enable_disable_cryptodev_engine_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  clib_error_t *error;

  error = dpdk_enable_cryptodev_engine (vm);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_dpdk_cryptodev_engine, static) = {
    .path = "set dpdk cryptodev engine enable",
    .short_help = "set dpdk cryptodev engine enable)",
    .function = enable_disable_cryptodev_engine_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
