/*
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
 */

#include <calico/calico_types.h>

calico_main_t calico_main;
fib_source_t calico_fib_source;
f64 *calico_timestamps;

u8 *
format_calico_endpoint (u8 * s, va_list * args)
{
  calico_endpoint_t *cep = va_arg (*args, calico_endpoint_t *);

  s = format (s, "%U;%d", format_ip_address, &cep->ce_ip, cep->ce_port);

  return (s);
}

static clib_error_t *
calico_types_init (vlib_main_t * vm)
{
  calico_fib_source = fib_source_allocate ("calico",
					   FIB_SOURCE_PRIORITY_HI,
					   FIB_SOURCE_BH_SIMPLE);

  return (NULL);
}

static clib_error_t *
calico_config (vlib_main_t * vm, unformat_input_t * input)
{
  calico_main_t *cm = &calico_main;
  cm->session_hash_memory = CALICO_DEFAULT_SESSION_MEMORY;
  cm->session_hash_buckets = CALICO_DEFAULT_SESSION_BUCKETS;
  cm->scanner_timeout = CALICO_DEFAULT_SCANNER_TIMEOUT;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "session-db-buckets %u", &cm->session_hash_buckets))
	;
      else if (unformat (input, "session-db-memory %U",
			 unformat_memory_size, &cm->session_hash_memory))
	;
      else
	if (unformat
	    (input, "session-cleanup-timeout %f", &cm->scanner_timeout))
	;
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (calico_config, "calico");
VLIB_INIT_FUNCTION (calico_types_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
