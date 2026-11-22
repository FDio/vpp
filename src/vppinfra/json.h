/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/format.h>

#define foreach_clib_json_value_type                                                               \
  _ (null, NULL)                                                                                   \
  _ (true, TRUE)                                                                                   \
  _ (false, FALSE)                                                                                 \
  _ (number, NUMBER)                                                                               \
  _ (string, STRING)                                                                               \
  _ (array, ARRAY)                                                                                 \
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

/* JSON text. Values are stored in a pool and referenced by index. The
 * add functions build the text in place: add_object/add_array make the new
 * value the current one, clib_json_parent () moves back to its parent. */
typedef struct
{
  clib_json_value_t *values;
  int root_value;
  int current_value;
  u32 indent;
  u32 current_indent;
  /* output style, see the clib_json_set_* functions, 0 is the default */
  const char *key_separator;
  u8 indent_spaces;
  u8 array_lines;
  u8 compact_empty;
  u8 number_exact;
  u8 number_digits;
} clib_json_text_t;

void clib_json_init (clib_json_text_t *j);
/* Parses a whole JSON text, trailing characters are an error. */
clib_error_t *clib_json_init_from_file (clib_json_text_t *j, int fd);
clib_error_t *clib_json_init_from_string (clib_json_text_t *j, char *str, int len);
void clib_json_free (clib_json_text_t *j);
/* The style of the text which format_clib_json_text () creates. The text
 * starts at the indentation of the last line of the vector it is formatted
 * into. The default is a tab per nesting level, ":\t" between the name and the
 * value of a member, arrays on one line, an empty object over two lines and
 * numbers which are not integers with 15 significant digits, which is what
 * the JSON text of VPP has always been. The setters change it. */

/* Number of indentation characters of a nesting level, 0 makes the text
 * without white space. */
void clib_json_set_indent (clib_json_text_t *j, u32 indent);
/* The indentation characters are tabs, which is the default, or spaces. */
void clib_json_set_indent_tabs (clib_json_text_t *j, int tabs);
/* Text between the name and the value of a member. The string has to be
 * valid as long as the text is formatted, 0 is the default. */
void clib_json_set_key_separator (clib_json_text_t *j, const char *separator);
/* The elements of an array are on one line, separated by ", ", which is the
 * default, or on a line each. */
void clib_json_set_inline_arrays (clib_json_text_t *j, int inline_arrays);
/* An empty object is the bracket, a new line and the closing bracket, which is
 * the default, or {}. */
void clib_json_set_expand_empty (clib_json_text_t *j, int expand);
/* A number which is not an integer is printed with this many significant
 * digits if that is the same value within the precision of a double, and with
 * 17 digits if it is not. The default is 15, 0 prints the shortest number of
 * digits which gives the same value. */
void clib_json_set_number_digits (clib_json_text_t *j, u32 digits);
int clib_json_add_null (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_true (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_false (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_string (clib_json_text_t *j, char *nfmt, char *sfmt, ...);
int clib_json_add_number (clib_json_text_t *j, char *nfmt, f64 num, ...);
int clib_json_add_array (clib_json_text_t *j, char *nfmt, ...);
int clib_json_add_object (clib_json_text_t *j, char *nfmt, ...);
int clib_json_parent (clib_json_text_t *j);
int clib_json_append (clib_json_text_t *to, clib_json_text_t *from, char *nfmt, ...);

int clib_json_get_top_value_index (clib_json_text_t *j);
int clib_json_value_is_type (clib_json_text_t *j, int value_index, clib_json_value_type_t type);
int clib_json_find_object_value_by_name (clib_json_text_t *j, int object_value_index, char *fmt,
					 ...);
int *clib_json_get_array_value_indices (clib_json_text_t *j, int array_value_index);
uword clib_json_unformat_string (clib_json_text_t *j, int value_index, char *fmt, ...);

/* format and unformat functions */
format_function_t format_clib_json_text;
format_function_t format_clib_json_value;
unformat_function_t unformat_clib_json_string;
unformat_function_t unformat_clib_json_value;

#define _(n, N)                                                                                    \
  static_always_inline int clib_json_value_is_##n (clib_json_text_t *j, int value_index)           \
  {                                                                                                \
    return clib_json_value_is_type (j, value_index, CLIB_JSON_VALUE_##N);                          \
  }
foreach_clib_json_value_type
#undef _

#define foreach_clib_json_array_value(j, idx, v)                                                   \
  for (int *__vec = clib_json_get_array_value_indices (j, idx), *__elt = __vec;                    \
       __vec != 0 && __elt < vec_end (__vec) && ((v) = *__elt, 1); __elt++)
