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

#include <vppinfra/cJSON.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_format_fns.h>
#include <vpp/api/types.h>
#include "jsonconvert.h"

#define _(T)                                    \
int vl_api_ ##T## _fromjson(cJSON *o, T *d)     \
{                                               \
    if (!cJSON_IsNumber(o)) return -1;          \
    memcpy(d, &o->valueint, sizeof(T));         \
    return 0;                                   \
}
  foreach_vat2_fromjson
#undef _

int vl_api_bool_fromjson(cJSON *o, bool *d)
{
    if (!cJSON_IsBool(o)) return -1;
    *d = o->valueint ? true : false;
    return 0;
}

int vl_api_u8_string_fromjson(cJSON *o, u8 *s, int len)
{
    unformat_input_t input;
    char *p = cJSON_GetStringValue(o);
    unformat_init_string (&input, p, strlen(p));
    unformat(&input, "0x%U", unformat_hex_string, s);
    return 0;
}

u8 *
u8string_fromjson(cJSON *o, char *fieldname)
{
    u8 *s = 0;
    unformat_input_t input;
    cJSON *item = cJSON_GetObjectItem(o, fieldname);
    if (!item) {
        printf("Illegal JSON, no such fieldname %s\n", fieldname);
        return 0;
    }

    char *p = cJSON_GetStringValue(item);
    unformat_init_string (&input, p, strlen(p));
    unformat(&input, "0x%U", unformat_hex_string, &s);
    return s;
}

int
u8string_fromjson2(cJSON *o, char *fieldname, u8 *data)
{
    u8 *s = u8string_fromjson(o, fieldname);
    if (!s) return 0;
    memcpy(data, s, vec_len(s));
    vec_free(s);
    return 0;
}

/* Parse an IP4 address %d.%d.%d.%d. */
uword
unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  unsigned a[4];

  if (!unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}

/* Parse an IP6 address. */
uword
unformat_ip6_address (unformat_input_t * input, va_list * args)
{
  ip6_address_t *result = va_arg (*args, ip6_address_t *);
  u16 hex_quads[8];
  uword hex_quad, n_hex_quads, hex_digit, n_hex_digits;
  uword c, n_colon, double_colon_index;

  n_hex_quads = hex_quad = n_hex_digits = n_colon = 0;
  double_colon_index = ARRAY_LEN (hex_quads);
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      hex_digit = 16;
      if (c >= '0' && c <= '9')
        hex_digit = c - '0';
      else if (c >= 'a' && c <= 'f')
        hex_digit = c + 10 - 'a';
      else if (c >= 'A' && c <= 'F')
        hex_digit = c + 10 - 'A';
      else if (c == ':' && n_colon < 2)
        n_colon++;
      else
        {
          unformat_put_input (input);
          break;
        }

      /* Too many hex quads. */
      if (n_hex_quads >= ARRAY_LEN (hex_quads))
        return 0;

      if (hex_digit < 16)
        {
          hex_quad = (hex_quad << 4) | hex_digit;

          /* Hex quad must fit in 16 bits. */
          if (n_hex_digits >= 4)
            return 0;

          n_colon = 0;
          n_hex_digits++;
        }

      /* Save position of :: */
      if (n_colon == 2)
        {
          /* More than one :: ? */
          if (double_colon_index < ARRAY_LEN (hex_quads))
            return 0;
          double_colon_index = n_hex_quads;
        }

      if (n_colon > 0 && n_hex_digits > 0)
        {
          hex_quads[n_hex_quads++] = hex_quad;
          hex_quad = 0;
          n_hex_digits = 0;
        }
    }

  if (n_hex_digits > 0)
    hex_quads[n_hex_quads++] = hex_quad;


  {
    word i;

    /* Expand :: to appropriate number of zero hex quads. */
    if (double_colon_index < ARRAY_LEN (hex_quads))
      {
        word n_zero = ARRAY_LEN (hex_quads) - n_hex_quads;

        for (i = n_hex_quads - 1; i >= (signed) double_colon_index; i--)
          hex_quads[n_zero + i] = hex_quads[i];

        for (i = 0; i < n_zero; i++)
          {
            ASSERT ((double_colon_index + i) < ARRAY_LEN (hex_quads));
            hex_quads[double_colon_index + i] = 0;
          }

        n_hex_quads = ARRAY_LEN (hex_quads);
      }

    /* Too few hex quads given. */
    if (n_hex_quads < ARRAY_LEN (hex_quads))
      return 0;

    for (i = 0; i < ARRAY_LEN (hex_quads); i++)
      result->as_u16[i] = clib_host_to_net_u16 (hex_quads[i]);

    return 1;
  }
}

u8 *
format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 max_zero_run = 0, this_zero_run = 0;
  int max_zero_run_index = -1, this_zero_run_index = 0;
  int in_zero_run = 0, i;
  int last_double_colon = 0;

  /* Ugh, this is a pain. Scan forward looking for runs of 0's */
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (a->as_u16[i] == 0)
        {
          if (in_zero_run)
            this_zero_run++;
          else
            {
              in_zero_run = 1;
              this_zero_run = 1;
              this_zero_run_index = i;
            }
        }
      else
        {
          if (in_zero_run)
            {
              /* offer to compress the biggest run of > 1 zero */
              if (this_zero_run > max_zero_run && this_zero_run > 1)
                {
                  max_zero_run_index = this_zero_run_index;
                  max_zero_run = this_zero_run;
                }
            }
          in_zero_run = 0;
          this_zero_run = 0;
        }
    }

  if (in_zero_run)
    {
      if (this_zero_run > max_zero_run && this_zero_run > 1)
        {
          max_zero_run_index = this_zero_run_index;
          max_zero_run = this_zero_run;
        }
    }

  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == max_zero_run_index)
        {
          s = format (s, "::");
          i += max_zero_run - 1;
          last_double_colon = 1;
        }
      else
        {
          s = format (s, "%s%x",
                      (last_double_colon || i == 0) ? "" : ":",
                      clib_net_to_host_u16 (a->as_u16[i]));
          last_double_colon = 0;
        }
    }

  return s;
}

void *vl_api_ip4_address_t_fromjson(void *mp, int *len, cJSON *o, vl_api_ip4_address_t *a)
{
    unformat_input_t input;
    char *p = cJSON_GetStringValue(o);
    if (!p) return 0;
    unformat_init_string (&input, p, strlen(p));
    unformat(&input, "%U", unformat_ip4_address, a);
    return mp;
}

void *vl_api_ip4_prefix_t_fromjson(void *mp, int *len, cJSON *o, vl_api_ip4_prefix_t *a)
{
    unformat_input_t input;
    char *p = cJSON_GetStringValue(o);
    if (!p) return 0;
    unformat_init_string (&input, p, strlen(p));
    unformat(&input, "%U/%d", unformat_ip4_address, &a->address, &a->len);
    return mp;
}

void *vl_api_ip4_address_with_prefix_t_fromjson(void *mp, int *len, cJSON *o, vl_api_ip4_prefix_t *a)
{
  return vl_api_ip4_prefix_t_fromjson(mp, len, o, a);
}
void *vl_api_ip6_address_t_fromjson(void *mp, int *len, cJSON *o, vl_api_ip6_address_t *a)
{
    unformat_input_t input;
    char *p = cJSON_GetStringValue(o);
    if (!p) return 0;
    unformat_init_string (&input, p, strlen(p));
    unformat(&input, "%U", unformat_ip6_address, a);
    return mp;
}

void *vl_api_ip6_prefix_t_fromjson(void *mp, int *len, cJSON *o, vl_api_ip6_prefix_t *a)
{
  unformat_input_t input;
  char *p = cJSON_GetStringValue(o);
  if (!p) return 0;
  unformat_init_string (&input, p, strlen(p));
  unformat(&input, "%U/%d", unformat_ip6_address, &a->address, &a->len);
  return mp;
}

void *vl_api_ip6_address_with_prefix_t_fromjson(void *mp, int *len, cJSON *o, vl_api_ip6_prefix_t *a)
{
  return vl_api_ip6_prefix_t_fromjson(mp, len, o, a);
}

void *vl_api_address_t_fromjson(void *mp, int *len, cJSON *o, vl_api_address_t *a)
{
  unformat_input_t input;

  char *p = cJSON_GetStringValue(o);
  if (!p) return 0;
  unformat_init_string (&input, p, strlen(p));
  if (a->af == ADDRESS_IP4)
    unformat(&input, "%U", unformat_ip4_address, &a->un.ip4);
  else if (a->af == ADDRESS_IP6)
    unformat(&input, "%U", unformat_ip6_address, &a->un.ip6);
  else
    return 0;
  return mp;
}

void *vl_api_prefix_t_fromjson(void *mp, int *len, cJSON *o, vl_api_prefix_t *a)
{
  unformat_input_t input;

  char *p = cJSON_GetStringValue(o);
  if (!p) return 0;
  unformat_init_string (&input, p, strlen(p));
  if (a->address.af == ADDRESS_IP4)
    unformat(&input, "%U/%d", unformat_ip4_address, &a->address.un.ip4, &a->len);
  else if (a->address.af == ADDRESS_IP6)
    unformat(&input, "%U/%d", unformat_ip6_address, &a->address.un.ip6, &a->len);
  else
    return 0;
  return mp;
}

void *vl_api_address_with_prefix_t_fromjson(void *mp, int *len, cJSON *o, vl_api_prefix_t *a)
{
  return vl_api_prefix_t_fromjson(mp, len, o, a);
}

uword
unformat_mac_address (unformat_input_t * input, va_list * args)
{
  mac_address_t *mac = va_arg (*args, mac_address_t *);
  u32 i, a[3];

  if (unformat (input, "%_%X:%X:%X:%X:%X:%X%_",
                1, &mac->bytes[0], 1, &mac->bytes[1], 1, &mac->bytes[2],
                1, &mac->bytes[3], 1, &mac->bytes[4], 1, &mac->bytes[5]))
    return (1);
  else if (unformat (input, "%_%x.%x.%x%_", &a[0], &a[1], &a[2]))
    {
      for (i = 0; i < ARRAY_LEN (a); i++)
        if (a[i] >= (1 << 16))
          return 0;

      mac->bytes[0] = (a[0] >> 8) & 0xff;
      mac->bytes[1] = (a[0] >> 0) & 0xff;
      mac->bytes[2] = (a[1] >> 8) & 0xff;
      mac->bytes[3] = (a[1] >> 0) & 0xff;
      mac->bytes[4] = (a[2] >> 8) & 0xff;
      mac->bytes[5] = (a[2] >> 0) & 0xff;

      return (1);
    }
  return (0);
}

void *vl_api_mac_address_t_fromjson(void *mp, int *len, cJSON *o, vl_api_mac_address_t *a)
{
  unformat_input_t input;

  char *p = cJSON_GetStringValue(o);
  unformat_init_string (&input, p, strlen(p));
  unformat(&input, "%U", unformat_mac_address, a);
  return mp;
}

/* Format an IP4 address. */
u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

int
vl_api_c_string_to_api_string (const char *buf, vl_api_string_t * str)
{
  /* copy without nul terminator */
  u32 len = strlen (buf);
  if (len > 0)
    clib_memcpy_fast (str->buf, buf, len);
  str->length = htonl (len);
  return len + sizeof (u32);
}

u8 *
format_vl_api_interface_index_t (u8 *s, va_list *args)
{
  u32 *a = va_arg (*args, u32 *);
  return format (s, "%u", *a);
}

uword
unformat_vl_api_interface_index_t (unformat_input_t * input, va_list * args)
{
    u32 *a = va_arg (*args, u32 *);

    if (!unformat (input, "%u", a))
        return 0;
    return 1;
}

void
vl_api_string_cJSON_AddToObject(cJSON * const object, const char * const name, vl_api_string_t *astr)
{

    if (astr == 0) return;
    u32 length = clib_net_to_host_u32 (astr->length);

    char *cstr = malloc(length + 1);
    memcpy(cstr, astr->buf, length);
    cstr[length] = '\0';
    cJSON_AddStringToObject(object, name, cstr);
    free(cstr);
}

u8 *
format_vl_api_timestamp_t(u8 * s, va_list * args)
{
    f64 timestamp = va_arg (*args, f64);
    struct tm *tm;
    word msec;

    time_t t = timestamp;
    tm = gmtime (&t);
    msec = 1e6 * (timestamp - t);
    return format (s, "%4d-%02d-%02dT%02d:%02d:%02d.%06dZ", 1900 + tm->tm_year,
                   1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min,
                   tm->tm_sec, msec);
}

u8 *
format_vl_api_timedelta_t(u8 * s, va_list * args)
{
    return format_vl_api_timestamp_t(s, args);
}

uword
unformat_vl_api_timedelta_t(unformat_input_t * input, va_list * args)
{
    return 0;
}

uword
unformat_vl_api_timestamp_t(unformat_input_t * input, va_list * args)
{
    return 0;
}
u8 *format_vl_api_gbp_scope_t(u8 * s, va_list * args)
{
    return 0;
}
uword unformat_vl_api_gbp_scope_t(unformat_input_t * input, va_list * args)
{
    return 0;
}

cJSON *
vl_api_ip4_address_with_prefix_t_tojson (vl_api_ip4_prefix_t *a) {
  u8 *s = format(0, "%U", format_vl_api_ip4_address_t, a);
  cJSON *o = cJSON_CreateString((char *)s);
  vec_free(s);
  return o;
}
cJSON *
vl_api_ip6_address_with_prefix_t_tojson (vl_api_ip6_prefix_t *a) {
  u8 *s = format(0, "%U", format_vl_api_ip6_address_t, a);
  cJSON *o = cJSON_CreateString((char *)s);
  vec_free(s);
  return o;
}
cJSON *
vl_api_address_with_prefix_t_tojson (vl_api_prefix_t *a) {
  u8 *s = format(0, "%U", format_vl_api_address_t, a);
  cJSON *o = cJSON_CreateString((char *)s);
  vec_free(s);
  return o;
}
u8 *
format_vl_api_mac_address_t (u8 * s, va_list * args)
{
  const mac_address_t *mac = va_arg (*args, mac_address_t *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac->bytes[0], mac->bytes[1], mac->bytes[2],
                 mac->bytes[3], mac->bytes[4], mac->bytes[5]);
}
#define _(T)                                                \
  cJSON *vl_api_ ##T## _t_tojson (vl_api_ ##T## _t *a) {   \
  u8 *s = format(0, "%U", format_vl_api_ ##T## _t, a);      \
  cJSON *o = cJSON_CreateString((char *)s);                 \
  vec_free(s);                                              \
  return o;                                                 \
  }
foreach_vat2_tojson
#undef _
