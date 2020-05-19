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
calico_timestamp_t *calico_timestamps;
throttle_t calico_throttle;

char *calico_error_strings[] = {
#define calico_error(n,s) s,
#include <calico/calico_error.def>
#undef calico_error
};

uword
unformat_calico_ep (unformat_input_t * input, va_list * args)
{
  calico_endpoint_t *a = va_arg (*args, calico_endpoint_t *);
  int port = 0;

  clib_memset (a, 0, sizeof (*a));
  if (unformat (input, "%U %d", unformat_ip_address, &a->ce_ip, &port))
    ;
  else if (unformat_user (input, unformat_ip_address, &a->ce_ip))
    ;
  else if (unformat (input, "%d", &port))
    ;
  else
    return 0;
  a->ce_port = (u16) port;
  return 1;
}

uword
unformat_calico_ep_tuple (unformat_input_t * input, va_list * args)
{
  calico_endpoint_tuple_t *a = va_arg (*args, calico_endpoint_tuple_t *);
  if (unformat (input, "%U->%U", unformat_calico_ep, &a->src_ep,
		unformat_calico_ep, &a->dst_ep))
    ;
  else if (unformat (input, "->%U", unformat_calico_ep, &a->dst_ep))
    ;
  else if (unformat (input, "%U->", unformat_calico_ep, &a->src_ep))
    ;
  else
    return 0;
  return 1;
}

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
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;
  calico_fib_source = fib_source_allocate ("calico",
					   CALICO_FIB_SOURCE_PRIORITY,
					   FIB_SOURCE_BH_SIMPLE);

  clib_rwlock_init (&calico_main.ts_lock);
  clib_spinlock_init (&calico_main.src_ports_lock);
  clib_bitmap_validate (calico_main.src_ports, UINT16_MAX);
  throttle_init (&calico_throttle, n_vlib_mains, 1e-3);

  return (NULL);
}

static clib_error_t *
calico_config (vlib_main_t * vm, unformat_input_t * input)
{
  calico_main_t *cm = &calico_main;

  cm->session_hash_memory = CALICO_DEFAULT_SESSION_MEMORY;
  cm->session_hash_buckets = CALICO_DEFAULT_SESSION_BUCKETS;
  cm->translation_hash_memory = CALICO_DEFAULT_TRANSLATION_MEMORY;
  cm->translation_hash_buckets = CALICO_DEFAULT_TRANSLATION_BUCKETS;
  cm->snat_hash_memory = CALICO_DEFAULT_SNAT_MEMORY;
  cm->snat_hash_buckets = CALICO_DEFAULT_SNAT_BUCKETS;
  cm->scanner_timeout = CALICO_DEFAULT_SCANNER_TIMEOUT;
  cm->session_max_age = CALICO_DEFAULT_SESSION_MAX_AGE;
  cm->tcp_max_age = CALICO_DEFAULT_TCP_MAX_AGE;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "session-db-buckets %u", &cm->session_hash_buckets))
	;
      else if (unformat (input, "session-db-memory %U",
			 unformat_memory_size, &cm->session_hash_memory))
	;
      else if (unformat (input, "translation-db-buckets %u",
			 &cm->translation_hash_buckets))
	;
      else if (unformat (input, "translation-db-memory %U",
			 unformat_memory_size, &cm->translation_hash_memory))
	;
      else if (unformat (input, "snat-db-buckets %u", &cm->snat_hash_buckets))
	;
      else if (unformat (input, "snat-db-memory %U",
			 unformat_memory_size, &cm->snat_hash_memory))
	;
      else if (unformat (input, "session-cleanup-timeout %f",
			 &cm->scanner_timeout))
	;
      else if (unformat (input, "session-max-age %u", &cm->session_max_age))
	;
      else if (unformat (input, "tcp-max-age %u", &cm->tcp_max_age))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
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
