/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

typedef struct vlua_handle_t *vlua_handle_t;
typedef struct vlua_table_handle *vlua_table_handle_t;
typedef struct vlua_ns_t *vlua_ns_handle_t;
typedef struct vlua_method_t *vlua_method_handle_t;

typedef struct
{
  vlua_table_handle_t *table_handles;
} vlua_init_fn_args_t;

typedef clib_error_t *(*vlua_init_fn_t) (vlua_handle_t h,
					 vlua_init_fn_args_t *a);

typedef struct vlua_init_fn_registration_t
{
  vlua_init_fn_t init_fn;
  const char *name;
  const char *const *paths;
  struct vlua_init_fn_registration_t *next;
  vlua_table_handle_t *table_handles_by_path;
} vlua_init_fn_registration_t;

typedef enum
{
  VLUA_LOG_LEVEL_DEBUG,
  VLUA_LOG_LEVEL_INFO,
  VLUA_LOG_LEVEL_WARN,
  VLUA_LOG_LEVEL_ERR,
} vlua_log_level_t;

typedef void (*vlua_log_callback_t) (vlua_handle_t h, vlua_log_level_t level,
				     const char *fmt, va_list *va);

typedef void (*vlua_hook_fn_t) (vlua_handle_t h);

typedef struct
{
  vlua_log_callback_t log_cb;
  char *path_prefix;
  vlua_hook_fn_t hook_fn;
  u32 hook_inst_count;
} vlua_create_args_t;

clib_error_t *vlua_run_init_functions (vlua_handle_t h);
void vlua_log_message (vlua_handle_t h, vlua_log_level_t level,
		       const char *fmt, ...);
void vlua_log_debug (vlua_handle_t h, const char *fmt, ...);
void vlua_log_info (vlua_handle_t h, const char *fmt, ...);
void vlua_log_warn (vlua_handle_t h, const char *fmt, ...);
void vlua_log_err (vlua_handle_t h, const char *fmt, ...);

extern vlua_init_fn_registration_t *vlua_init_registrations;
static_always_inline void
vlua_register_init_fn (const vlua_init_fn_registration_t *entry)
{
  ((vlua_init_fn_registration_t *) entry)->next = vlua_init_registrations;
  vlua_init_registrations = (vlua_init_fn_registration_t *) entry;
}

#define VLUA_REGISTER_INIT_FN(name)                                           \
  static vlua_init_fn_registration_t __vlua_init_entry_##name;                \
  static void __vlua_init_ctor_##name (void) __attribute__ ((constructor));   \
  static void __vlua_init_ctor_##name (void)                                  \
  {                                                                           \
    vlua_register_init_fn (&__vlua_init_entry_##name);                        \
  }                                                                           \
  static vlua_init_fn_registration_t __vlua_init_entry_##name

#define VLUA_PATHS(...)                                                       \
  (const char *const[])                                                       \
  {                                                                           \
    __VA_ARGS__, NULL                                                         \
  }

typedef enum
{
  VLUA_T_STRING,
  VLUA_T_NUMBER,
  VLUA_T_INTEGER,
  VLUA_T_BOOL,
  VLUA_T_TABLE,
  VLUA_T_NIL,
} vlua_type_t;

typedef struct vlua_table_entry_t vlua_table_entry_t;

typedef struct
{
  vlua_type_t type;
  union
  {
    u8 *string_value;
    double number_value;
    i64 integer_value;
    bool bool_value;
    vlua_table_entry_t *table_entries;
  };
} vlua_val_t;

struct vlua_table_entry_t
{
  u8 *key;
  vlua_val_t value;
};

typedef struct
{
  vlua_handle_t handle;
  const void *context;
  size_t context_size;
  vlua_val_t *args;
  vlua_val_t *returns;
} vlua_method_fn_args_t;

typedef clib_error_t *(*vlua_method_fn_t) (vlua_method_fn_args_t *args);

void vlua_val_vec_add_nil (vlua_val_t **vec);
void vlua_val_vec_add_bool (vlua_val_t **vec, bool value);
void vlua_val_vec_add_number (vlua_val_t **vec, i64 number);
void vlua_val_vec_add_integer (vlua_val_t **vec, i64 value);
void vlua_val_vec_add_string (vlua_val_t **vec, const char *fmt, ...);
vlua_val_t *vlua_val_vec_add_table (vlua_val_t **vec);
void vlua_val_vec_free (vlua_val_t **vec);

bool vlua_val_is_string (const vlua_val_t *v, const char *fmt, ...);
bool vlua_val_is_bool (const vlua_val_t *v, bool expected);
bool vlua_val_is_integer (const vlua_val_t *v, i64 expected);
bool vlua_val_is_number (const vlua_val_t *v, double expected);
bool vlua_val_is_nil (const vlua_val_t *v);

bool vlua_val_type_is_string (const vlua_val_t *v);
bool vlua_val_type_is_number (const vlua_val_t *v);
bool vlua_val_type_is_integer (const vlua_val_t *v);
bool vlua_val_type_is_bool (const vlua_val_t *v);
bool vlua_val_type_is_table (const vlua_val_t *v);
bool vlua_val_type_is_nil (const vlua_val_t *v);

bool vlua_val_vec_type_is_string (const vlua_val_t *vec, u32 index);
bool vlua_val_vec_type_is_number (const vlua_val_t *vec, u32 index);
bool vlua_val_vec_type_is_integer (const vlua_val_t *vec, u32 index);
bool vlua_val_vec_type_is_bool (const vlua_val_t *vec, u32 index);
bool vlua_val_vec_type_is_table (const vlua_val_t *vec, u32 index);
bool vlua_val_vec_type_is_nil (const vlua_val_t *vec, u32 index);

const u8 *vlua_val_get_string (const vlua_val_t *v, u32 *len);
const u8 *vlua_val_vec_get_string (const vlua_val_t *vec, u32 index, u32 *len);
void vlua_val_set_string (vlua_val_t *v, const char *fmt, ...);

double vlua_val_get_number (const vlua_val_t *v);
double vlua_val_vec_get_number (const vlua_val_t *vec, u32 index);
void vlua_val_set_number (vlua_val_t *v, double value);

i64 vlua_val_get_integer (const vlua_val_t *v);
i64 vlua_val_vec_get_integer (const vlua_val_t *vec, u32 index);
void vlua_val_set_integer (vlua_val_t *v, i64 value);

bool vlua_val_get_bool (const vlua_val_t *v);
bool vlua_val_vec_get_bool (const vlua_val_t *vec, u32 index);
void vlua_val_set_bool (vlua_val_t *v, bool value);

void vlua_val_set_nil (vlua_val_t *v);
void vlua_val_table_add_string (vlua_val_t *table, const char *key,
				const char *fmt, ...);
void vlua_val_table_add_integer (vlua_val_t *table, const char *key,
				 i64 value);
void vlua_val_table_add_number (vlua_val_t *table, const char *key,
				double value);
void vlua_val_table_add_bool (vlua_val_t *table, const char *key, bool value);
void vlua_val_table_add_nil (vlua_val_t *table, const char *key);
const vlua_val_t *vlua_val_table_get_entry (const vlua_val_t *table,
					    const char *key);

format_function_t format_vlua_value;

void vlua_stub_dump (vlua_handle_t h, const char *stub_path);

f64 vlua_scheduler_run_cycle (vlua_handle_t h);
clib_error_t *vlua_scheduler_kill_task (vlua_handle_t h, u32 task_index);
void vlua_yield (vlua_handle_t h);
void vlua_sleep (vlua_handle_t h, f64 seconds);

typedef struct vlua_ns_resolver_fn_args_t_
{
  vlua_handle_t handle;
  void *context;
  const vlua_val_t *args;
} vlua_ns_resolver_fn_args_t;

typedef clib_error_t *(*vlua_ns_resolver_fn_t) (
  vlua_ns_resolver_fn_args_t *args);

vlua_handle_t vlua_create (vlua_create_args_t *args);
void vlua_destroy (vlua_handle_t h);
vlua_table_handle_t vlua_table_add (vlua_handle_t h, const char *name,
				    vlua_table_handle_t parent);

vlua_method_handle_t vlua_method_add (vlua_handle_t h,
				      vlua_table_handle_t table,
				      const char *fmt, ...);

void vlua_method_add_call_args (vlua_method_handle_t mh, vlua_method_fn_t func,
				u32 n_args, ...);

clib_error_t *vlua_run_string (vlua_handle_t h, const char *code);
clib_error_t *vlua_run_file (vlua_handle_t h, const char *fmt, ...);

vlua_ns_handle_t vlua_ns_create (vlua_handle_t h, vlua_table_handle_t table,
				 size_t context_size);

void vlua_ns_add_call_args (vlua_ns_handle_t nh, vlua_ns_resolver_fn_t fn,
			    u32 n_args, ...);

format_function_t vlua_format_stats;
