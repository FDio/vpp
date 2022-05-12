/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef included_vppinfra_json_h
#define included_vppinfra_json_h

#include <vppinfra/clib.h>
#include <vppinfra/format.h>

#define foreach_clib_json_value_type                                          \
  _ (null, NULL)                                                              \
  _ (true, TRUE)                                                              \
  _ (false, FALSE)                                                            \
  _ (number, NUMBER)                                                          \
  _ (string, STRING)                                                          \
  _ (array, ARRAY)                                                            \
  _ (object, OBJECT)

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

typedef enum
{
  CLIB_JSON_ERR_INVALID_VALUE_INDEX = -1,
  CLIB_JSON_ERR_INVALID_VALUE_TYPE = -2,
  CLIB_JSON_ERR_OBJECT_NAME_NOT_FOUND = -3,
} clib_json_err_t;

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
    f64 number;
    u8 *string;
    int *array_val_indices;
    clib_json_nvpair_t *nvpairs;
  };
} clib_json_value_t;

typedef struct
{
  clib_json_value_t *values;
  int root_value;
  int current_value;
  u32 indent;
  u32 current_indent;
} clib_json_text_t;

void clib_json_init (clib_json_text_t *j);
clib_error_t *clib_json_init_from_file (clib_json_text_t *j, int fd);
clib_error_t *clib_json_init_from_string (clib_json_text_t *j, char *str,
					  int len);
void clib_json_free (clib_json_text_t *j);
int clib_json_add_null (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_true (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_false (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_string (clib_json_text_t *j, char *nfmt, char *sfmt, ...);
int clib_json_add_number (clib_json_text_t *j, char *nfmt, f64 num, ...);
int clib_json_add_array (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_object (clib_json_text_t *j, char *nfmt, ...);
int clib_json_parent (clib_json_text_t *j);
int clib_json_append (clib_json_text_t *to, clib_json_text_t *from, char *nfmt,
		      ...);

int clib_json_get_top_value_index (clib_json_text_t *j);
int clib_json_value_is_type (clib_json_text_t *j, int value_index,
			     clib_json_value_type_t type);
int clib_json_find_object_value_by_name (clib_json_text_t *j,
					 int object_value_index, char *fmt,
					 ...);
int *clib_json_get_array_value_indices (clib_json_text_t *j,
					int array_value_index);
uword clib_json_unformat_string (clib_json_text_t *j, int value_index,
				 char *fmt, ...);

/* format and unformat functions */
format_function_t format_clib_json_text;
format_function_t format_clib_json_value;
unformat_function_t unformat_clib_json_string;
unformat_function_t unformat_clib_json_value;

#define _(n, N)                                                               \
  static_always_inline int clib_json_value_is_##n (clib_json_text_t *j,       \
						   int value_index)           \
  {                                                                           \
    return clib_json_value_is_type (j, value_index, CLIB_JSON_VALUE_##N);     \
  }
foreach_clib_json_value_type
#undef _

#define foreach_clib_json_array_value(j, idx, v)                              \
  for (int *__vec = clib_json_get_array_value_indices (j, idx),               \
	   *__elt = __vec,                                                    \
	   __clib_unused __unused = ((v) = __vec ? *__elt : 0);               \
       __vec != 0 && __elt < vec_end (__vec); __elt++, (v) = *__elt)

#endif
