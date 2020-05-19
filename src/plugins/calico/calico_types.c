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

fib_source_t calico_fib_source;

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

VLIB_INIT_FUNCTION (calico_types_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
