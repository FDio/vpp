/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/*
 * api_types.h
 */

#ifndef included_api_types_h
#define included_api_types_h

#include <stdbool.h>
#include <stdarg.h>
#include <vppinfra/types.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* VPP API string type */
typedef struct
{
  u32 length;
  u8 buf[0];
} __attribute__ ((packed)) vl_api_string_t;

/* Nul terminated string to vl_api_string_t */
extern int vl_api_c_string_to_api_string (const char *buf, vl_api_string_t * str);
/* NON nul terminated vector to vl_api_string_t */
extern int vl_api_vec_to_api_string (const u8 *vec, vl_api_string_t * str);

extern u32 vl_api_string_len (vl_api_string_t * astr);

/* Returns new vector. NON nul terminated */
extern u8 * vl_api_from_api_to_new_vec (void *mp, vl_api_string_t *astr);
/* Returns new vector. Nul terminated */
extern char * vl_api_from_api_to_new_c_string (vl_api_string_t *astr);

extern u8 *vl_api_format_string (u8 *s, va_list *args);

#ifdef __cplusplus
}
#endif

#endif
