/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef included_vppinfra_json_h
#define included_vppinfra_json_h

#include <vppinfra/clib.h>
#include <vppinfra/format.h>

typedef enum
{
  CLIB_JSON_VALUE_NULL = 0,
  CLIB_JSON_VALUE_TRUE,
  CLIB_JSON_VALUE_FALSE,
  CLIB_JSON_VALUE_NUMBER,
  CLIB_JSON_VALUE_STRING,
  CLIB_JSON_VALUE_OBJECT,
  CLIB_JSON_VALUE_ARRAY,
} clib_json_value_type_t;

typedef struct
{
  u8 *name;
  u32 value_index;
} clib_json_nvpair_t;

typedef struct clib_json_value_t
{
  clib_json_value_type_t type;
  int parent_value_index;
  union
  {
    u64 value;
    u8 *string;
    u32 *array_val_indices;
    clib_json_nvpair_t *nvpairs;
  };
} clib_json_value_t;

typedef struct
{
  clib_json_value_t *values;
  int root_value;
  int current_value;
  u8 *next_nvpair_name;
  u32 indent;
  u32 current_indent;
} clib_json_text_t;

void clib_json_init (clib_json_text_t *j);
clib_error_t *clib_json_init_from_file (clib_json_text_t *j, int fd);
clib_error_t *clib_json_init_from_string (clib_json_text_t *j, char *str,
					  int len);
void clib_json_free (clib_json_text_t *j);
int clib_json_add_null (clib_json_text_t *j);
int clib_json_add_true (clib_json_text_t *j);
int clib_json_add_false (clib_json_text_t *j);
int clib_json_add_string (clib_json_text_t *j, char *fmt, ...);
int clib_json_add_array (clib_json_text_t *j);
int clib_json_add_object (clib_json_text_t *j);
int clib_json_parent (clib_json_text_t *j);
int clib_json_append (clib_json_text_t *to, clib_json_text_t *from);
void clib_json_set_next_nvpair_name (clib_json_text_t *j, char *fmt, ...);

format_function_t format_clib_json;
unformat_function_t unformat_clib_json_string;
unformat_function_t unformat_clib_json_value;
#endif
