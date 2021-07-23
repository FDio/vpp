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

#ifndef included_json_convert_h
#define included_json_convert_h

#include <stdbool.h>
#include <vppinfra/cJSON.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>

#define foreach_type_fromjson                                                 \
  _ (i8)                                                                      \
  _ (u8)                                                                      \
  _ (i16)                                                                     \
  _ (u16)                                                                     \
  _ (i32)                                                                     \
  _ (u32)                                                                     \
  _ (u64)                                                                     \
  _ (f64)

#define _(T) CJSON_PUBLIC (int) vl_api_##T##_fromjson (cJSON *o, T *d);
foreach_type_fromjson
#undef _

/* Prototypes */
CJSON_PUBLIC (int) vl_api_bool_fromjson (cJSON *o, bool *d);
CJSON_PUBLIC (int)
vl_api_ip4_address_t_fromjson (void **mp, int *len, cJSON *o,
			       vl_api_ip4_address_t *a);
CJSON_PUBLIC (int)
vl_api_ip4_prefix_t_fromjson (void **mp, int *len, cJSON *o,
			      vl_api_ip4_prefix_t *a);
CJSON_PUBLIC (int)
vl_api_ip4_address_with_prefix_t_fromjson (void **mp, int *len, cJSON *o,
					   vl_api_ip4_prefix_t *a);
CJSON_PUBLIC (int)
vl_api_ip6_address_t_fromjson (void **mp, int *len, cJSON *o,
			       vl_api_ip6_address_t *a);
CJSON_PUBLIC (int)
vl_api_ip6_prefix_t_fromjson (void **mp, int *len, cJSON *o,
			      vl_api_ip6_prefix_t *a);
CJSON_PUBLIC (int)
vl_api_ip6_address_with_prefix_t_fromjson (void **mp, int *len, cJSON *o,
					   vl_api_ip6_prefix_t *a);
CJSON_PUBLIC (int)
vl_api_address_t_fromjson (void **mp, int *len, cJSON *o, vl_api_address_t *a);
CJSON_PUBLIC (int)
vl_api_prefix_t_fromjson (void **mp, int *len, cJSON *o, vl_api_prefix_t *a);
CJSON_PUBLIC (int)
vl_api_address_with_prefix_t_fromjson (void **mp, int *len, cJSON *o,
				       vl_api_prefix_t *a);
CJSON_PUBLIC (int)
vl_api_mac_address_t_fromjson (void **mp, int *len, cJSON *o,
			       vl_api_mac_address_t *a);

CJSON_PUBLIC (uword)
unformat_ip4_address (unformat_input_t *input, va_list *args);
CJSON_PUBLIC (uword)
unformat_ip6_address (unformat_input_t *input, va_list *args);
CJSON_PUBLIC (u8 *) format_ip6_address (u8 *s, va_list *args);
CJSON_PUBLIC (uword)
unformat_mac_address (unformat_input_t *input, va_list *args);
CJSON_PUBLIC (u8 *) format_ip4_address (u8 *s, va_list *args);
CJSON_PUBLIC (uword)
unformat_vl_api_timedelta_t (unformat_input_t *input, va_list *args);
CJSON_PUBLIC (uword)
unformat_vl_api_timestamp_t (unformat_input_t *input, va_list *args);
CJSON_PUBLIC (uword)
unformat_vl_api_gbp_scope_t (unformat_input_t *input, va_list *args);

CJSON_PUBLIC (int)
vl_api_c_string_to_api_string (const char *buf, vl_api_string_t *str);
CJSON_PUBLIC (void)
vl_api_string_cJSON_AddToObject (cJSON *const object, const char *const name,
				 vl_api_string_t *astr);

CJSON_PUBLIC (u8 *) u8string_fromjson (cJSON *o, char *fieldname);
CJSON_PUBLIC (int) u8string_fromjson2 (cJSON *o, char *fieldname, u8 *data);
CJSON_PUBLIC (int) vl_api_u8_string_fromjson (cJSON *o, u8 *s, int len);

#define foreach_type_tojson                                                   \
  _ (ip4_address)                                                             \
  _ (ip4_prefix)                                                              \
  _ (ip6_address)                                                             \
  _ (ip6_prefix)                                                              \
  _ (address)                                                                 \
  _ (prefix)                                                                  \
  _ (mac_address)

#define _(T) CJSON_PUBLIC (cJSON *) vl_api_##T##_t_tojson (vl_api_##T##_t *);
foreach_type_tojson
#undef _

CJSON_PUBLIC (cJSON *)
  vl_api_ip4_address_with_prefix_t_tojson (vl_api_ip4_prefix_t *a);
CJSON_PUBLIC (cJSON *)
vl_api_ip6_address_with_prefix_t_tojson (vl_api_ip6_prefix_t *a);
CJSON_PUBLIC (cJSON *)
vl_api_address_with_prefix_t_tojson (vl_api_prefix_t *a);

#endif
